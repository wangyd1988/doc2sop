"""页面上配置主机与数据源（工具服务这一层）：连接、远程 MCP server、对外开放、远程主机。

两条硬规矩各有专门的用例：页面加的连接引用不了服务器上的凭据（${名字} / OPS_SECRET_*）；去向一变，存好的凭据就作废。
另外：凭据只写不读（接口、日志、错误信息、/tools/full 里都没有值），扩大能力的要审批口令（和批准共用输错计数、锁定），
sqlite、服务器文件路径、stdio MCP 一律不收，不能把外部改标成内部，和主配置重名的不收，host key 不核对就不登记，
私钥不出工具服务，安装包和 push --print 一样，旁路文件坏了照常启动，什么都没在页面上配时输出和以前一样。
"""
import base64
import contextlib
import io
import json
import os
import queue
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import threading
import time
import types
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

import tests.support  # noqa: F401  OPS_APPROVAL_FILE 等环境变量先固定下来

REPO = Path(__file__).resolve().parent.parent

if "ops_readonly" in sys.modules:
    ops = sys.modules["ops_readonly"]
else:
    import importlib.util
    _SPEC = importlib.util.spec_from_file_location("ops_readonly", REPO / "deploy" / "ops_readonly.py")
    ops = importlib.util.module_from_spec(_SPEC)
    sys.modules["ops_readonly"] = ops
    _SPEC.loader.exec_module(ops)

try:     # 真的 psycopg（带 libpq）：装进 OPS_VENDOR_DIR 才有，平时的测试环境没有，用它的用例跳过
    import psycopg as PSYCOPG
except Exception:
    PSYCOPG = None

POSIX = os.name == "posix"
PASS = "correct horse battery staple"
WRONG = "not the passphrase at all"
DB_SECRET = "page-db-Pass#2026"            # 页面上输入的数据库密码
TOKEN = "page-token-0123456789abcdef"       # 页面上输入的接口令牌
SERVER_SECRET = "server-side-litellm-password"  # 服务器上已有的凭据（OPS_SECRET_LITELLM_DB_PASSWORD）
FAKE_PRIVATE = ("-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEPRIVATEKEYMATERIAL-do-not-leak-0123456789\n"
                "-----END OPENSSH PRIVATE KEY-----\n")
FAKE_PUBLIC = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPAGEKEYPUBLICPART0123456789abcdefghijklmnop"
HOST_BLOB = base64.b64encode(b"host-key-of-web01-" + bytes(range(40))).decode()
OTHER_BLOB = base64.b64encode(b"someone-in-the-middle-" + bytes(range(40))).decode()

CONFIG = textwrap.dedent("""\
    connections:
      - {name: litellm_db, type: postgres, host: 127.0.0.1, port: 15432, database: litellm, user: doc2sop_ro,
         password: "${litellm_db_password}"}
    tools:
      - {name: one, desc: 看内存, binary: free, argv: [free, -m], params: {}}
      - {name: usage, desc: 用量, impl: {type: sql, conn: litellm_db, query: "SELECT 1 AS x"}, params: {}}
      - {name: cmdb_count, desc: 资产数, impl: {type: sql, conn: cmdb, query: "SELECT count(*) AS n FROM assets"},
         params: {}}
      - {name: prom_up, desc: 看 up, http: {conn: prom, url: /api/v1/query, query: {query: up}}, params: {}}
    """)


def quiet(fn, *args, **kwargs):
    """调用并收起它打印的东西：(结果或异常, 打印的内容)。"""
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        try:
            return fn(*args, **kwargs), out.getvalue()
        except Exception as exc:   # 让调用方断言异常和日志
            return exc, out.getvalue()


def status_of(exc):
    """异常 → 工具服务会回的 HTTP 状态码（和 Handler._page 一样）。"""
    if isinstance(exc, ops.ApprovalRefused):
        return exc.status
    for kind, code in ((ops.NotFound, 404), (ops.Conflict, 409), (ops.RateLimited, 429), (ops.Forbidden, 403)):
        if isinstance(exc, kind):
            return code
    return 400 if isinstance(exc, ops.ConfigError) else 500


class FakeSsh:
    """假的 ssh-keygen / ssh-keyscan：生成假私钥（内容是 FAKE_PRIVATE），扫描时报上 host_blob。"""

    def __init__(self):
        self.host_blob = HOST_BLOB
        self.calls = []

    def run(self, argv, **kwargs):
        name = os.path.basename(str(argv[0]))
        self.calls.append([str(part) for part in argv])
        if "ssh-keygen" in name and "-t" in argv:
            path = argv[argv.index("-f") + 1]
            comment = argv[argv.index("-C") + 1]
            Path(path).write_text(FAKE_PRIVATE, encoding="utf-8")
            Path(path + ".pub").write_text(f"{FAKE_PUBLIC} {comment}\n", encoding="utf-8")
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        if "ssh-keygen" in name and "-y" in argv:
            return subprocess.CompletedProcess(argv, 0, (FAKE_PUBLIC + "\n").encode(), b"")
        if "ssh-keyscan" in name:
            address = argv[-1]
            return subprocess.CompletedProcess(argv, 0, f"{address} ssh-ed25519 {self.host_blob}\n".encode(), b"")
        raise AssertionError(f"没想到会跑 {argv}")


class FakeCursor:
    description = [("x",)]

    def __init__(self, db):
        self.db = db

    def execute(self, sql, params=None):
        self.db.statements.append(sql)

    def fetchall(self):
        return [(1,)]

    def fetchmany(self, n):
        return [(1,)]


class FakeDb:
    def __init__(self):
        self.statements = []
        self.read_only = False

    def cursor(self, name=None):
        return FakeCursor(self)

    def rollback(self):
        pass

    def close(self):
        pass


class FakeDriver:
    """假的 psycopg / pymysql：记下每次 connect 的参数（看凭据到底发给了谁），可以设成连接时抛错。"""

    def __init__(self):
        self.connects = []
        self.fail = None
        self.errors = types.SimpleNamespace(QueryCanceled=type("QueryCanceled", (Exception,), {}))
        self.cursors = types.SimpleNamespace(SSCursor=object)
        self.Error = Exception

    def connect(self, **kwargs):
        self.connects.append(kwargs)
        if self.fail is not None:
            raise self.fail
        return FakeDb()


class _Config(unittest.TestCase):
    CONFIG = CONFIG

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.main = self.dir / "ops_tools.yaml"
        self.main.write_text(self.CONFIG, encoding="utf-8")
        (self.dir / "scripts").mkdir()
        self.private = self.dir / "private"
        self.passfile = self.private / "approval.hash"
        self.ssh = FakeSsh()
        self.driver = FakeDriver()
        self.sent = []
        patchers = [
            patch.dict(ops._state, {"path": self.main, "mtime": None, "omtime": None, "tmtime": None, "imtime": None,
                                    "mmtime": None, "pmtime": None, "includes": [], "tools": {}, "problems": [],
                                    "mcp_servers": {}, "connections": {}, "hosts": None, "held": [], "page": {}}),
            patch.dict(ops._approval, {"failures": 0, "locked_until": 0.0, "logged": None}),
            patch.dict(ops.SCRYPT_PARAMS, {"p": 1}),
            patch.dict(os.environ, {"OPS_APPROVAL_FILE": str(self.passfile), "OPS_CLI": "",
                                    "OPS_SECRET_LITELLM_DB_PASSWORD": SERVER_SECRET,
                                    "OPS_SECRET_SSH_KEY": str(self.dir / "main-key")}),
            patch.dict(ops._page_tests, clear=True),
            patch.dict(ops._page_bundle_times, clear=True),
            patch.object(ops.shutil, "which", lambda name: f"/usr/bin/{name}"),
            patch.object(ops._monitor, "wake", lambda: None),
            patch.object(ops.subprocess, "run", self.ssh.run),
            patch.object(ops, "_driver", lambda kind: (self.driver, "")),
            patch.object(ops, "_http_get", self.fake_get),
            # 试探同步做（真正的后台名额由 _page_probe 的用例单独测）
            patch.object(ops, "_page_probe", lambda label, caller, probe, wait=None: ops._precheck_run(label, caller, probe)),
            patch.object(ops, "_page_net_checks", lambda url, auth, done: [ops._check("tcp", "ok", "TCP", "通")]),
        ]
        os.environ.pop("OPS_PAGE_CONFIG", None)
        os.environ.pop("OPS_PRIVATE_DIR", None)
        if POSIX:
            patchers.append(patch.object(ops, "APPROVAL_OWNER", os.geteuid()))
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.printed = io.StringIO()
        redirect = contextlib.redirect_stdout(self.printed)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)
        ops.refresh(force=True)

    def fake_get(self, url, headers, context=None):
        self.sent.append((url, dict(headers)))
        return 200, json.dumps({"echo": headers.get("Authorization", ""), "data": "ok"}).encode()

    def set_passphrase(self, text=PASS):
        ops._write_private(str(self.passfile), json.dumps(ops.new_approval_record(text)))

    def do(self, fn, payload):
        """调一个页面动作，返回 (结果或异常, 打印的内容)；打印的内容也收进 self.printed，最后统一查有没有泄露。"""
        result, printed = quiet(fn, payload, "web user=admin ip=10.1.2.3")
        self.printed.write(printed)
        return result, printed

    def ok(self, fn, payload):
        result, printed = self.do(fn, payload)
        self.assertNotIsInstance(result, Exception, f"{result!r}\n{printed}")
        return result

    def refused(self, fn, payload, status=None):
        result, printed = self.do(fn, payload)
        self.assertIsInstance(result, Exception, f"应当被拒绝，却返回了 {result!r}")
        if status is not None:
            self.assertEqual(status_of(result), status, f"{result}")
        return result

    def page_doc(self):
        return ops._read_yaml(ops._page_file())

    def secrets(self):
        return ops._page_secret_records()[0]

    def add_pg(self, name="cmdb", secret=DB_SECRET, **fields):
        connection = {"name": name, "type": "postgres", "host": "db.example.internal", "database": "cmdb",
                      "user": "doc2sop_ro", "tls": "require", **fields}
        payload = {"connection": connection, "passphrase": PASS}
        if secret is not None:
            payload["secret"] = secret
        return self.ok(ops.page_connection_save, payload)

    def add_http(self, name="prom", secret=TOKEN, **fields):
        connection = {"name": name, "type": "http", "base": "https://prom.example.internal:9090", "auth": "bearer",
                      **fields}
        payload = {"connection": connection, "passphrase": PASS}
        if secret is not None:
            payload["secret"] = secret
        return self.ok(ops.page_connection_save, payload)

    def everything_said(self):
        """工具服务对外说过的一切：日志、旁路文件、变更记录、/tools、/tools/full、/tools/pending、/tools/config。"""
        texts = [self.printed.getvalue(), json.dumps(ops.available_tools(), ensure_ascii=False),
                 json.dumps({"tools": ops.describe_tools(), "mcp_servers": ops.mcp_status(),
                             "connections": ops.describe_connections(), "hosts": ops.describe_hosts()},
                            ensure_ascii=False),
                 json.dumps(ops.list_pending(), ensure_ascii=False),
                 json.dumps(ops.config_view(), ensure_ascii=False)]
        for path in (ops._page_file(), ops._page_log_file(), ops._page_known_hosts()):
            if Path(path).exists():
                texts.append(Path(path).read_text(encoding="utf-8"))
        return "\n".join(texts)

    def assertNothingLeaks(self, *texts, values=(DB_SECRET, TOKEN, SERVER_SECRET, "FAKEPRIVATEKEYMATERIAL")):
        said = self.everything_said() + "\n".join(str(text) for text in texts)
        for value in values:
            self.assertNotIn(value, said)


class ConnectionTests(_Config):
    def setUp(self):
        super().setUp()
        self.set_passphrase()

    def test_add_a_database_connection_the_password_is_write_only(self):
        result = self.add_pg()
        self.assertEqual(result["saved"], "cmdb")
        self.assertEqual(result["note"], "凭据已设置")
        self.assertEqual(result["test"]["verdict"], "ok")
        # 主配置里引用 cmdb 的工具这下能加载了：它们用的是页面上加的连接
        self.assertIn("cmdb_count", ops.all_tools())
        item = ops.describe_connections()["cmdb"]
        self.assertEqual((item["origin"], item["secret"]["state"]), ("page", "set"))
        # 测试和真正的查询都只带页面上输入的密码，连的是页面上写的地址
        self.assertEqual(self.driver.connects[-1]["password"], DB_SECRET)
        self.assertEqual(self.driver.connects[-1]["host"], "db.example.internal")
        run = ops.run_tool("cmdb_count", {})
        self.assertTrue(run["ok"], run)
        self.assertEqual(self.driver.connects[-1]["password"], DB_SECRET)
        # 凭据只在凭据文件里（0600）；主配置一个字节都没动
        self.assertEqual(self.secrets()["connection:cmdb"]["value"], DB_SECRET)
        self.assertEqual(self.main.read_text(encoding="utf-8"), self.CONFIG)
        if POSIX:
            self.assertEqual(stat.S_IMODE(os.stat(ops._page_secrets_file()).st_mode), 0o600)
        self.assertNothingLeaks(json.dumps(result, ensure_ascii=False))

    def test_wrong_or_missing_passphrase_changes_nothing(self):
        payload = {"connection": {"name": "cmdb", "type": "postgres", "host": "db", "database": "cmdb",
                                  "user": "ro"}, "secret": DB_SECRET}
        self.refused(ops.page_connection_save, payload, 400)
        self.refused(ops.page_connection_save, {**payload, "passphrase": WRONG}, 403)
        self.assertFalse(ops._page_file().exists())
        self.assertEqual(self.secrets(), {})
        self.assertNothingLeaks()

    def test_page_connections_cannot_reference_server_credentials(self):
        base = {"name": "evil", "type": "postgres", "host": "evil.example.com", "database": "x", "user": "ro"}
        for field, value in (("host", "${litellm_db_password}"), ("user", "${OPS_SECRET_LITELLM_DB_PASSWORD}"),
                             ("database", "${litellm_db_password}")):
            with self.subTest(field=field):
                error = self.refused(ops.page_connection_save,
                                     {"connection": {**base, field: value}, "passphrase": PASS}, 400)
                self.assertIn("不能引用服务器上的凭据", str(error))
        error = self.refused(ops.page_connection_save, {"connection": base, "secret": "${litellm_db_password}",
                                                        "passphrase": PASS}, 400)
        self.assertIn("不能引用服务器上的凭据", str(error))
        for field in ("password", "bearer", "headers"):
            with self.subTest(field=field):
                self.refused(ops.page_connection_save,
                             {"connection": {**base, field: "${litellm_db_password}"}, "passphrase": PASS}, 400)
        http = {"name": "evil", "type": "http", "base": "${litellm_db_password}/x", "auth": "none"}
        self.refused(ops.page_connection_save, {"connection": http, "passphrase": PASS}, 400)
        self.assertFalse(ops._page_file().exists())
        # 手改旁路文件塞进去的也一样：整条跳过，什么都不连
        ops._page_write({"connections": [{**base, "password": "${litellm_db_password}"},
                                          {**base, "name": "evil2", "host": "${litellm_db_password}"}],
                         "mcp_servers": [], "export": [], "hosts": []})
        ops.refresh(force=True)
        self.assertNotIn("evil", ops.describe_connections())
        self.assertNotIn("evil2", ops.describe_connections())
        self.assertTrue(any("页面配置，这一条已跳过" in problem for problem in ops._state["problems"]))
        self.assertNothingLeaks()

    def test_a_page_connection_without_a_password_never_borrows_one(self):
        self.add_pg(secret=None)
        self.assertTrue(ops.run_tool("cmdb_count", {})["ok"])
        sent = self.driver.connects[-1]
        self.assertEqual((sent["password"], sent["passfile"]), ("", ops.PG_NO_FILE))   # 显式的空密码，不让 libpq 自己找
        self.assertNotIn(SERVER_SECRET, json.dumps(self.driver.connects))

    def test_page_postgres_never_lets_libpq_look_for_server_credentials(self):
        """参数里没给的密码、密码文件、客户端证书，libpq 会自己去找服务器上的（PGPASSWORD、~/.pgpass、service 文件、
        ~/.postgresql/postgresql.crt）。页面连接走的每一条路——保存后的测试、查询、测试草稿、自动检查的 EXPLAIN——都显式给出；
        主配置的连接参数和以前一样。"""
        isolated = {"passfile": ops.PG_NO_FILE, "sslcert": ops.PG_NO_FILE, "sslkey": ops.PG_NO_FILE}

        def sent_with(password):
            sent = self.driver.connects[-1]
            self.assertEqual({key: sent.get(key) for key in ("password", *isolated)}, {"password": password, **isolated})

        fields = {"name": "cmdb", "type": "postgres", "host": "db.example.internal", "database": "cmdb",
                  "user": "doc2sop_ro", "tls": "require"}
        self.add_pg(secret=None)
        sent_with("")                                               # 保存之后的测试，没有密码
        self.assertTrue(ops.run_tool("cmdb_count", {})["ok"])
        sent_with("")                                               # 真正的查询
        self.ok(ops.page_connection_test, {"connection": fields, "passphrase": PASS})
        sent_with("")                                               # 测试草稿，没输密码
        self.ok(ops.page_connection_test, {"connection": fields, "secret": "typed-in-the-dialog", "passphrase": PASS})
        sent_with("typed-in-the-dialog")                            # 测试草稿，输了
        self.ok(ops.page_connection_save, {"original": "cmdb", "connection": fields, "secret": DB_SECRET,
                                           "confirm": ["cmdb_count"], "passphrase": PASS})
        sent_with(DB_SECRET)                                        # 存了密码之后的测试
        self.assertTrue(ops.run_tool("cmdb_count", {})["ok"])
        sent_with(DB_SECRET)
        item = ops.propose_tool({"name": "cmdb_status", "desc": "按状态数资产", "params": {},
                                 "impl": {"type": "sql", "conn": "cmdb", "query": "SELECT status FROM assets"}})
        state = ops.review_pending(item, caller="web user=admin ip=10.1.2.3", deadline=time.monotonic() + 30,
                                   fresh=True)["precheck"]
        self.assertEqual(state["state"], "done", state)
        sent_with(DB_SECRET)                                        # 自动检查的 EXPLAIN
        # 主配置的连接：一个参数都没多（服务器上的连接照旧由管理员决定）
        self.assertTrue(ops.run_tool("usage", {})["ok"])
        self.assertEqual(self.driver.connects[-1], {
            "autocommit": False, "host": "127.0.0.1", "port": 15432, "dbname": "litellm", "user": "doc2sop_ro",
            "connect_timeout": 8, "application_name": "doc2sop-ops-readonly", "sslmode": "prefer",
            "options": "-c default_transaction_read_only=on -c statement_timeout=5000 "
                       "-c idle_in_transaction_session_timeout=10000", "password": SERVER_SECRET})

    def test_newer_libpq_also_keeps_kerberos_and_sspi_out(self):
        """libpq 12 起不拿 Kerberos 票据建加密通道，16 起服务器要 Kerberos / SSPI 认证就不连；更老的不认识这两个参数，不加。"""
        self.add_pg(secret=None)
        page, main = ops._state["connections"]["cmdb"], ops._state["connections"]["litellm_db"]
        for version, extra in ((110000, {}), (150004, {"gssencmode": "disable"}),
                               (180004, {"gssencmode": "disable", "require_auth": "!gss,!sspi"})):
            with self.subTest(version=version):
                driver = types.SimpleNamespace(pq=types.SimpleNamespace(version=lambda version=version: version))
                kwargs = ops._postgres_kwargs(page, [], driver)
                self.assertEqual({key: kwargs[key] for key in ("gssencmode", "require_auth") if key in kwargs}, extra)
                self.assertFalse({"passfile", "sslcert", "sslkey", "gssencmode", "require_auth"}
                                 & set(ops._postgres_kwargs(main, [], driver)))

    @unittest.skipUnless(PSYCOPG, "没有 psycopg：把 psycopg[binary] 装进 OPS_VENDOR_DIR 才跑")
    def test_psycopg_hands_the_empty_password_to_libpq(self):
        """None 会被 psycopg 丢掉（等于没给），空串才真的进连接串。"""
        self.add_pg(secret=None)
        kwargs = ops._postgres_kwargs(ops._state["connections"]["cmdb"], [], PSYCOPG)
        conninfo = PSYCOPG.conninfo.make_conninfo(**kwargs)
        self.assertIn("password=''", conninfo)
        parsed = PSYCOPG.conninfo.conninfo_to_dict(conninfo)
        self.assertEqual([parsed[key] for key in ("password", "passfile", "sslcert", "sslkey")],
                         ["", ops.PG_NO_FILE, ops.PG_NO_FILE, ops.PG_NO_FILE])
        if PSYCOPG.pq.version() >= 160000:
            self.assertEqual(parsed["require_auth"], "!gss,!sspi")

    def test_ports_must_be_1_to_65535(self):
        """地址里的端口保存时就查（连接和 MCP 都是），免得存下来、到测试和调用时才出错；手改旁路文件写错的照样跳过。"""
        for base in ("https://prom.example.internal:abc", "https://prom.example.internal:99999",
                     "https://prom.example.internal:0", "https://prom.example.internal:", "https://prom.example.internal:+80",
                     "https://prom.example.internal:\u0668\u0660", "https://[::1]:abc", "https://a:b:c"):
            with self.subTest(base=base):
                error = self.refused(ops.page_connection_save, {"connection": {"name": "prom", "type": "http",
                                                                               "base": base, "auth": "none"},
                                                                "passphrase": PASS}, 400)
                self.assertIn("端口", str(error))
        error = self.refused(ops.page_mcp_save, {"server": {"id": "itsm", "url": "https://mcp.example.com:99999/mcp"},
                                                 "passphrase": PASS}, 400)
        self.assertIn("端口", str(error))
        self.assertEqual(ops._approval["failures"], 0)          # 请求本身不对，不消耗口令次数
        self.assertFalse(ops._page_file().exists())
        for index, base in enumerate(("https://prom.example.internal:9090", "http://[::1]:8080", "https://[2001:db8::1]",
                                      "https://prom.example.internal:65535/api")):
            with self.subTest(base=base):
                self.add_http(name=f"ok{index}", base=base, auth="none", secret=None)
        ops._page_write({"connections": [{"name": "bad", "type": "http", "base": "https://x.example.com:99999",
                                          "auth": "none"}], "mcp_servers": [], "export": [], "hosts": []})
        ops.refresh(force=True)
        self.assertNotIn("bad", ops.describe_connections())
        self.assertTrue(any("端口" in problem for problem in ops._state["problems"]))

    def test_a_tool_on_a_page_connection_cannot_carry_its_own_server_credential(self):
        # 管理员删掉了主配置里的连接 prom 之后，有人在页面上建一个同名的指向自己：手写工具自带的 ${…} 不能跟过去
        self.main.write_text(self.CONFIG + '  - {name: leaky, desc: 带凭据的手写工具, http: {conn: prom, url: /x, '
                             'headers: {X-Key: "${litellm_db_password}"}}, params: {}}\n', encoding="utf-8")
        self.add_http(base="https://attacker.example.com")
        tools = ops.all_tools()
        self.assertIn("prom_up", tools)
        self.assertNotIn("leaky", tools)
        self.assertTrue(any("leaky 用的是页面上加的连接 prom，自己就不能再引用凭据" in p for p in ops._state["problems"]))
        self.assertTrue(ops.run_tool("prom_up", {})["ok"])
        self.assertEqual(self.sent[-1][1]["Authorization"], "Bearer " + TOKEN)
        self.assertNotIn(SERVER_SECRET, json.dumps(self.sent))

    def test_http_token_is_sent_only_to_its_base_and_scrubbed_from_echoes(self):
        self.add_http()
        result = ops.run_tool("prom_up", {})
        self.assertTrue(result["ok"], result)
        url, headers = self.sent[-1]
        self.assertTrue(url.startswith("https://prom.example.internal:9090/api/v1/query"))
        self.assertEqual(headers["Authorization"], "Bearer " + TOKEN)
        self.assertNotIn(TOKEN, result["output"])          # 接口把令牌回显了，也被换成 ***
        self.assertIn("***", result["output"])
        self.add_http(name="itsm", base="https://itsm.example.com/api", auth="header", auth_header="X-Api-Key",
                      secret="Token " + TOKEN)
        self.assertIn("X-Api-Key", ops.describe_connections()["itsm"]["headers"])

    def test_changing_the_destination_voids_the_stored_password(self):
        self.add_pg()
        fields = {"name": "cmdb", "type": "postgres", "host": "other.example.internal", "database": "cmdb",
                  "user": "doc2sop_ro", "tls": "require"}
        result = self.ok(ops.page_connection_save, {"original": "cmdb", "connection": fields,
                                                    "confirm": ["cmdb_count"], "passphrase": PASS})
        self.assertIn("原来存的凭据已作废", result["note"])
        self.assertNotIn("connection:cmdb", self.secrets())
        self.assertEqual(ops.describe_connections()["cmdb"]["secret"]["state"], "missing")
        self.driver.connects.clear()
        self.assertTrue(ops.run_tool("cmdb_count", {})["ok"])
        self.assertEqual(self.driver.connects[-1]["host"], "other.example.internal")
        self.assertEqual(self.driver.connects[-1]["password"], "")

    def test_every_part_of_the_destination_counts(self):
        for field, value in (("port", 6543), ("database", "other"), ("user", "someone"), ("tls", "disable")):
            with self.subTest(field=field):
                self.add_pg(name="db_" + field)
                fields = {"name": "db_" + field, "type": "postgres", "host": "db.example.internal",
                          "database": "cmdb", "user": "doc2sop_ro", "tls": "require", field: value}
                result = self.ok(ops.page_connection_save, {"original": "db_" + field, "connection": fields,
                                                            "passphrase": PASS})
                self.assertIn("作废", result["note"])
                self.assertNotIn("connection:db_" + field, self.secrets())
        # 只改显示名、超时：去向没变，密码不动
        self.add_pg(name="keep")
        fields = {"name": "keep", "type": "postgres", "host": "db.example.internal", "database": "cmdb",
                  "user": "doc2sop_ro", "tls": "require", "label": "改个名字", "timeout": 9}
        result = self.ok(ops.page_connection_save, {"original": "keep", "connection": fields, "passphrase": PASS})
        self.assertEqual(result["note"], "凭据没改")
        self.assertEqual(self.secrets()["connection:keep"]["value"], DB_SECRET)

    def test_a_hand_edited_destination_never_receives_the_password(self):
        self.add_pg()
        document = self.page_doc()
        document["connections"][0]["host"] = "attacker.example.com"
        ops._page_write({kind: document.get(kind) or [] for kind in ops.PAGE_KINDS})
        ops.refresh(force=True)
        self.assertEqual(ops.describe_connections()["cmdb"]["secret"]["state"], "stale")
        self.driver.connects.clear()
        result = ops.run_tool("cmdb_count", {})
        self.assertFalse(result["ok"])
        self.assertIn("原来存的凭据已作废", result["error"])
        self.assertEqual(self.driver.connects, [])           # 根本没去连
        # 测试也一样：去向变了的草稿不会拿存着的密码去试
        draft = {**document["connections"][0]}
        test = self.ok(ops.page_connection_test, {"original": "cmdb", "connection": draft, "passphrase": PASS})
        self.assertFalse(test["used_saved_secret"])
        self.assertTrue(all(sent["password"] == "" for sent in self.driver.connects))
        self.assertNothingLeaks()

    def test_testing_uses_the_saved_password_only_for_the_same_destination(self):
        self.add_pg()
        same = {"name": "cmdb", "type": "postgres", "host": "db.example.internal", "database": "cmdb",
                "user": "doc2sop_ro", "tls": "require"}
        self.driver.connects.clear()
        test = self.ok(ops.page_connection_test, {"original": "cmdb", "connection": same, "passphrase": PASS})
        self.assertTrue(test["used_saved_secret"])
        self.assertEqual(self.driver.connects[-1]["password"], DB_SECRET)
        self.assertIn("SELECT 1", test["test"]["checks"][-1]["title"])
        # 测试要口令，口令不对什么都不连
        self.driver.connects.clear()
        self.refused(ops.page_connection_test, {"original": "cmdb", "connection": same, "passphrase": WRONG}, 403)
        self.assertEqual(self.driver.connects, [])

    def test_connection_failures_are_classified_without_echoing_the_driver(self):
        self.add_pg(secret=None)
        error = Exception(f'connection failed: FATAL:  password authentication failed for user "doc2sop_ro" {DB_SECRET}')
        self.driver.fail = error
        test = self.ok(ops.page_connection_test, {"connection": {"name": "cmdb", "type": "postgres", "host": "db",
                                                                 "database": "cmdb", "user": "doc2sop_ro"},
                                                  "secret": DB_SECRET, "passphrase": PASS})
        check = test["test"]["checks"][-1]
        self.assertEqual(check["status"], "fail")
        self.assertIn("账号或密码不对", check["text"])
        self.assertNotIn(DB_SECRET, json.dumps(test, ensure_ascii=False))

    def test_sqlite_server_paths_and_stdio_are_refused(self):
        cases = [({"name": "assets", "type": "sqlite", "path": "/opt/kb-app/data/chat.db"}, "sqlite"),
                 ({"name": "assets", "type": "sqlite"}, "sqlite"),
                 ({"name": "k8s", "type": "http", "base": "https://k8s:6443", "ca": "/etc/ops-readonly/k8s-ca.pem"}, "ca"),
                 ({"name": "k8s", "type": "http", "base": "https://k8s:6443", "bearer_file": "/etc/ops-readonly/t"},
                  "bearer_file"),
                 ({"name": "pg", "type": "postgres", "host": "db", "database": "x", "user": "u", "ca": "/etc/x.pem"},
                  "ca")]
        for connection, word in cases:
            with self.subTest(word=word):
                error = self.refused(ops.page_connection_save, {"connection": connection, "passphrase": PASS}, 400)
                self.assertIn(word, str(error))
        error = self.refused(ops.page_mcp_save, {"server": {"id": "local", "command": "/usr/bin/python3",
                                                            "args": ["server.py"]}, "passphrase": PASS}, 400)
        self.assertIn("stdio", str(error))
        self.assertFalse(ops._page_file().exists())
        self.assertEqual(ops._approval["failures"], 0)        # 请求本身不对，不消耗口令次数
        # 手改旁路文件写进去的也照样跳过
        ops._page_write({"connections": [{"name": "assets", "type": "sqlite", "path": "/opt/kb-app/data/chat.db"}],
                         "mcp_servers": [{"id": "local", "command": "/bin/sh"}], "export": [], "hosts": []})
        ops.refresh(force=True)
        self.assertNotIn("assets", ops.describe_connections())
        self.assertNotIn("local", ops.mcp_status())

    def test_the_page_cannot_mark_an_external_address_internal(self):
        result = self.add_http(name="public_api", base="https://api.example.com", external=False, secret=None,
                               auth="none")
        self.assertTrue(ops.describe_connections()["public_api"]["external"])
        self.assertNotIn("external", self.page_doc()["connections"][0])   # 没勾「标为外部」就是按地址判断
        # 内部地址可以改标成外部（更严）
        self.add_http(name="inner", base="http://10.0.0.5:9090", external=True, secret=None, auth="none")
        self.assertTrue(ops.describe_connections()["inner"]["external"])
        self.assertEqual(ops.describe_connections()["inner"]["external_why"], "页面上标为外部")
        # 手改成 external: false 的条目整条跳过
        document = self.page_doc()
        document["connections"].append({"name": "sneaky", "type": "http", "base": "https://api.example.com",
                                        "external": False})
        ops._page_write({kind: document.get(kind) or [] for kind in ops.PAGE_KINDS})
        ops.refresh(force=True)
        self.assertNotIn("sneaky", ops.describe_connections())
        self.assertTrue(any("不能把它标成内部" in p for p in ops._state["problems"]))
        self.assertTrue(result["saved"])

    def test_names_taken_by_the_main_config_are_refused(self):
        error = self.refused(ops.page_connection_save, {"connection": {"name": "litellm_db", "type": "postgres",
                                                                       "host": "evil", "database": "x", "user": "u"},
                                                        "secret": DB_SECRET, "passphrase": PASS}, 409)
        self.assertIn("主配置里已经有叫 litellm_db 的连接", str(error))
        self.assertEqual(ops._approval["failures"], 0)
        # 手改旁路文件塞一个同名的：主配置优先，页面那条不加载，主配置的连接照旧
        ops._page_write({"connections": [{"name": "litellm_db", "type": "postgres", "host": "evil.example.com",
                                          "database": "x", "user": "u"}], "mcp_servers": [], "export": [], "hosts": []})
        ops.refresh(force=True)
        self.assertNotIn("origin", ops.describe_connections()["litellm_db"])
        self.assertTrue(any("和主配置里的同名，已忽略（主配置优先）" in p for p in ops._state["problems"]))
        self.add_pg()
        self.refused(ops.page_connection_save, {"connection": {"name": "cmdb", "type": "postgres", "host": "db",
                                                               "database": "x", "user": "u"}, "passphrase": PASS}, 409)

    def test_editing_asks_to_confirm_the_tools_that_use_it(self):
        self.add_pg()
        fields = {"name": "cmdb", "type": "postgres", "host": "db.example.internal", "database": "cmdb",
                  "user": "doc2sop_ro", "tls": "require", "label": "CMDB"}
        error = self.refused(ops.page_connection_save, {"original": "cmdb", "connection": fields, "passphrase": PASS},
                             409)
        self.assertEqual(error.extra, {"confirm": ["cmdb_count"]})
        self.assertEqual(ops._approval["failures"], 0)
        self.refused(ops.page_connection_save, {"original": "cmdb", "connection": fields, "confirm": ["other"],
                                                "passphrase": PASS}, 409)
        self.ok(ops.page_connection_save, {"original": "cmdb", "connection": fields, "confirm": ["cmdb_count"],
                                           "passphrase": PASS})

    def test_delete_takes_the_password_with_it(self):
        self.add_pg()
        self.refused(ops.page_connection_delete, {"name": "cmdb", "passphrase": PASS}, 409)   # 没确认在用它的工具
        self.refused(ops.page_connection_delete, {"name": "cmdb", "confirm": ["cmdb_count"]}, 400)
        result = self.ok(ops.page_connection_delete, {"name": "cmdb", "confirm": ["cmdb_count"], "passphrase": PASS})
        self.assertEqual(result["affected"], ["cmdb_count"])
        self.assertNotIn("connection:cmdb", self.secrets())
        self.assertNotIn("cmdb", ops.describe_connections())
        self.assertNotIn("cmdb_count", ops.all_tools())
        self.assertTrue(any("引用了未声明的连接 cmdb" in p for p in ops._state["problems"]))

    def test_wrong_passphrases_share_the_approval_lockout(self):
        payload = {"connection": {"name": "cmdb", "type": "postgres", "host": "db", "database": "x", "user": "u"},
                   "passphrase": WRONG}
        for _ in range(3):
            self.refused(ops.page_connection_save, payload, 403)
        self.refused(ops.page_export, {"tool": "one", "on": True, "passphrase": WRONG}, 403)
        # 第 5 次从批准那个入口输错：同一个计数，锁定
        result, _ = quiet(ops.check_passphrase, WRONG, "批准", "x")
        self.assertEqual(status_of(result), 423)
        # 锁定中：口令对了也不行，回 423
        self.refused(ops.page_connection_save, {**payload, "passphrase": PASS}, 423)
        self.assertFalse(ops._page_file().exists())

    def test_the_secrets_file_is_checked_on_every_use(self):
        if not POSIX:
            self.skipTest("权限位只在 POSIX 上有意义")
        self.add_pg()
        os.chmod(ops._page_secrets_file(), 0o644)
        self.driver.connects.clear()
        result = ops.run_tool("cmdb_count", {})
        self.assertFalse(result["ok"])
        self.assertIn("chmod 600", result["error"])
        self.assertEqual(self.driver.connects, [])
        ops.refresh(force=True)
        self.assertEqual(ops.describe_connections()["cmdb"]["secret"]["state"], "unreadable")
        self.refused(ops.page_connection_save, {"connection": {"name": "other", "type": "postgres", "host": "db",
                                                               "database": "x", "user": "u"},
                                                "secret": DB_SECRET, "passphrase": PASS}, 409)


class FakePostgres:
    """假的 PostgreSQL：收下启动包（SSL、GSS 加密一律回「不支持」），要明文密码，记下客户端发来的密码，然后拒绝。
    客户端手里没有密码时，libpq 根本不发（「no password supplied」）就断开：记 None。"""

    def __init__(self):
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.results = queue.Queue()
        threading.Thread(target=self.serve, daemon=True).start()

    def close(self):
        self.listener.close()

    def serve(self):
        while True:
            try:
                client, _ = self.listener.accept()
            except OSError:
                return
            with client:
                client.settimeout(15)
                try:
                    self.results.put(self.handle(client))
                except (OSError, EOFError, struct.error) as exc:
                    self.results.put(f"broken: {exc!r}")

    @staticmethod
    def read(client, size):
        data = b""
        while len(data) < size:
            chunk = client.recv(size - len(data))
            if not chunk:
                raise EOFError("closed")
            data += chunk
        return data

    def handle(self, client):
        while True:
            length, code = struct.unpack("!ii", self.read(client, 8))
            self.read(client, length - 8)
            if code not in (80877103, 80877104):       # SSLRequest、GSSENCRequest：回 N（不支持），客户端接着发启动包
                break
            client.sendall(b"N")
        client.sendall(b"R" + struct.pack("!ii", 8, 3))  # AuthenticationCleartextPassword
        try:
            kind = self.read(client, 1)
        except (EOFError, ConnectionError):
            return None
        payload = self.read(client, struct.unpack("!i", self.read(client, 4))[0] - 4)
        error = b"SFATAL\0VFATAL\0C28P01\0Mpassword authentication failed\0\0"
        client.sendall(b"E" + struct.pack("!i", len(error) + 4) + error)
        return payload.rstrip(b"\0").decode("utf-8") if kind == b"p" else f"unexpected {kind!r}"

    def next(self):
        return self.results.get(timeout=20)


@unittest.skipUnless(PSYCOPG, "没有 psycopg：把 psycopg[binary] 装进 OPS_VENDOR_DIR 才跑")
class LibpqTests(_Config):
    """真的 libpq 连一个假的 PostgreSQL：服务器上的 PGPASSWORD、密码文件、service 文件里的密码，页面上的连接一个都带不过去，
    页面上输入的照常送到。每种来源先用以前的参数（不给密码）连一次，确认这台机器上它真的会被 libpq 带过去。"""

    def setUp(self):
        super().setUp()
        self.set_passphrase()
        self.server = FakePostgres()
        self.addCleanup(self.server.close)
        clean = patch.dict(os.environ)
        clean.start()
        self.addCleanup(clean.stop)
        for name in ("PGPASSWORD", "PGPASSFILE", "PGSERVICE", "PGSERVICEFILE", "PGSYSCONFDIR"):
            os.environ.pop(name, None)                  # 跑测试的机器上本来就有的先拿掉
        passfile, services = self.dir / "pgpass", self.dir / "pg_service.conf"
        passfile.write_text("*:*:*:*:from-passfile\n", encoding="utf-8")
        services.write_text("[doc2sop]\npassword=from-service-file\n", encoding="utf-8")
        if POSIX:
            passfile.chmod(0o600)                       # 组或其他用户能读的密码文件 libpq 不用
        self.sources = {"from-PGPASSWORD": {"PGPASSWORD": "from-PGPASSWORD"},
                        "from-passfile": {"PGPASSFILE": str(passfile)},
                        "from-service-file": {"PGSERVICEFILE": str(services), "PGSERVICE": "doc2sop"}}
        real = patch.object(ops, "_driver", lambda kind: (PSYCOPG, "") if kind == "postgres" else (self.driver, ""))
        real.start()
        self.addCleanup(real.stop)
        self.fields = {"name": "cmdb", "type": "postgres", "host": "127.0.0.1", "port": self.server.port,
                       "database": "cmdb", "user": "doc2sop_ro", "tls": "prefer"}

    def connect(self, kwargs):
        with contextlib.suppress(PSYCOPG.Error):
            PSYCOPG.connect(autocommit=False, **kwargs).close()
        return self.server.next()

    def test_server_credentials_never_reach_a_page_connection(self):
        self.ok(ops.page_connection_save, {"connection": self.fields, "passphrase": PASS})
        self.assertIsNone(self.server.next())                        # 保存之后的测试：没有密码
        conn = ops._state["connections"]["cmdb"]
        for source, env in self.sources.items():
            with self.subTest(source=source), patch.dict(os.environ, env):
                before = {key: value for key, value in ops._postgres_kwargs(conn, [], PSYCOPG).items()
                          if key not in ("password", "passfile")}
                self.assertEqual(self.connect(before), source)       # 以前的参数：libpq 把服务器上的凭据带过去了
                self.assertIsNone(self.connect(ops._postgres_kwargs(conn, [], PSYCOPG)))
                self.assertFalse(ops.run_tool("cmdb_count", {})["ok"])
                self.assertIsNone(self.server.next())                # 真正的查询
                self.ok(ops.page_connection_test, {"connection": self.fields, "passphrase": PASS})
                self.assertIsNone(self.server.next())                # 测试草稿，没输密码
                self.ok(ops.page_connection_test, {"connection": self.fields, "secret": "typed-in-the-dialog",
                                                   "passphrase": PASS})
                self.assertEqual(self.server.next(), "typed-in-the-dialog")
        everything = {key: value for env in self.sources.values() for key, value in env.items()}
        with patch.dict(os.environ, everything):
            self.ok(ops.page_connection_save, {"original": "cmdb", "connection": self.fields, "secret": DB_SECRET,
                                               "confirm": ["cmdb_count"], "passphrase": PASS})
            self.assertEqual(self.server.next(), DB_SECRET)          # 存了密码之后的测试
            self.assertFalse(ops.run_tool("cmdb_count", {})["ok"])
            self.assertEqual(self.server.next(), DB_SECRET)
            item = ops.propose_tool({"name": "cmdb_status", "desc": "按状态数资产", "params": {},
                                     "impl": {"type": "sql", "conn": "cmdb", "query": "SELECT status FROM assets"}})
            ops.review_pending(item, caller="web user=admin ip=10.1.2.3", deadline=time.monotonic() + 30, fresh=True)
            self.assertEqual(self.server.next(), DB_SECRET)          # 自动检查的 EXPLAIN
        self.assertTrue(self.server.results.empty())


class McpServerTests(_Config):
    def setUp(self):
        super().setUp()
        self.set_passphrase()

    def add(self, **fields):
        server = {"id": "itsm", "url": "https://mcp.example.com/mcp", "auth": "bearer", **fields}
        return self.ok(ops.page_mcp_save, {"server": server, "secret": TOKEN, "passphrase": PASS})

    def test_a_remote_server_gets_only_its_own_token(self):
        self.add()
        server = ops._mcp.get("itsm")
        self.assertIsInstance(server, ops.McpHttpServer)
        url, headers, _ = server._endpoint()
        self.assertEqual(url, "https://mcp.example.com/mcp")
        self.assertEqual(headers, {"Authorization": "Bearer " + TOKEN})
        self.assertIn(TOKEN, server.secrets)                  # 输出脱敏要用
        status = ops.mcp_status()["itsm"]
        self.assertEqual((status["origin"], status["secret"]["state"]), ("page", "set"))
        self.assertTrue(status["external"])                   # 公网地址按外部算
        self.assertNothingLeaks()

    def test_moving_the_server_voids_its_token(self):
        self.add()
        result = self.ok(ops.page_mcp_save, {"original": "itsm", "server": {"id": "itsm", "url": "https://evil.example.com/mcp",
                                                                          "auth": "bearer"}, "passphrase": PASS})
        self.assertIn("作废", result["note"])
        with self.assertRaises(ops.McpError) as caught:
            ops._mcp.get("itsm")._endpoint()
        self.assertIn("还没有在页面上输入凭据", str(caught.exception))

    def test_deleting_a_page_server_removes_its_approvals_and_requests(self):
        self.add()
        approved = {"name": "itsm__lookup", "label": "查", "group": "ITSM", "desc": "查工单",
                    "mcp": {"server": "itsm", "tool": "lookup"}, "input_schema": {"type": "object", "properties": {}},
                    "schema_hash": "", "readonly_declared": True}
        ops._write_yaml(ops._mcp_file(), {"tools": [approved]})
        ops._write_yaml(ops._sibling("pending"), {"pending": [
            {"id": "p1", "author": "mcp:itsm", "tool": {**approved, "name": "itsm__other"}},
            {"id": "p2", "author": "web", "tool": {"name": "keep_me"}}]})
        ops.refresh(force=True)
        self.ok(ops.page_export, {"tool": "itsm__lookup", "on": True, "passphrase": PASS})
        self.refused(ops.page_mcp_delete, {"id": "itsm", "passphrase": PASS}, 409)   # 要确认在用它的工具
        result = self.ok(ops.page_mcp_delete, {"id": "itsm", "confirm": ["itsm__lookup"], "passphrase": PASS})
        self.assertEqual(result["removed_tools"], ["itsm__lookup"])
        self.assertEqual(ops._read_yaml(ops._mcp_file()).get("tools"), [])
        self.assertEqual([item["id"] for item in ops.list_pending()], ["p2"])
        self.assertEqual(self.page_doc().get("export") or [], [])
        self.assertNotIn("mcp:itsm", self.secrets())
        self.assertIsNone(ops._mcp.get("itsm"))

    def test_main_config_server_ids_are_reserved(self):
        self.main.write_text(self.CONFIG.replace("tools:", 'mcp_servers:\n  holiday: {url: "https://holiday.example.com/mcp"}\ntools:'),
                             encoding="utf-8")
        ops.refresh(force=True)
        error = self.refused(ops.page_mcp_save, {"server": {"id": "holiday", "url": "https://evil.example.com/mcp"},
                                                 "passphrase": PASS}, 409)
        self.assertIn("主配置里已经有叫 holiday 的", str(error))


class ExportTests(_Config):
    def setUp(self):
        super().setUp()
        self.set_passphrase()

    def exported(self, name):
        return ops.available_tools()[name]["_meta"]["doc2sop"]["export"]

    def test_turning_on_needs_the_passphrase_turning_off_does_not(self):
        self.refused(ops.page_export, {"tool": "one", "on": True}, 400)
        self.refused(ops.page_export, {"tool": "one", "on": True, "passphrase": WRONG}, 403)
        self.assertFalse(self.exported("one"))
        self.ok(ops.page_export, {"tool": "one", "on": True, "passphrase": PASS})
        self.assertTrue(self.exported("one"))
        self.ok(ops.page_export, {"tool": "one", "on": False})
        self.assertFalse(self.exported("one"))
        self.assertEqual(self.page_doc().get("export") or [], [])    # 和主配置一样了，不留记录
        self.assertEqual(self.main.read_text(encoding="utf-8"), self.CONFIG)

    def test_the_page_can_close_what_the_main_config_opened(self):
        self.main.write_text(self.CONFIG + "export: [one]\n", encoding="utf-8")
        ops.refresh(force=True)
        self.assertTrue(self.exported("one"))
        self.ok(ops.page_export, {"tool": "one", "on": False})
        self.assertFalse(self.exported("one"))
        self.assertEqual(self.page_doc()["export"], [{"tool": "one", "on": False}])
        self.assertIn("export: [one]", self.main.read_text(encoding="utf-8"))   # 主配置不动
        self.ok(ops.page_export, {"tool": "one", "on": True, "passphrase": PASS})
        self.assertTrue(self.exported("one"))
        self.assertEqual(self.page_doc().get("export") or [], [])

    def test_an_opened_tool_pauses_when_its_definition_changes(self):
        self.ok(ops.page_export, {"tool": "one", "on": True, "passphrase": PASS})
        self.main.write_text(self.CONFIG.replace("argv: [free, -m]", "argv: [free, -g]"), encoding="utf-8")
        ops.refresh(force=True)
        self.assertFalse(self.exported("one"))
        item = next(entry for entry in ops.config_view()["export"] if entry["tool"] == "one")
        self.assertEqual(item["page"], "stale")
        self.assertTrue(any("定义后来变了" in p for p in ops._state["problems"]))
        # 只改说明不算定义变了
        self.main.write_text(self.CONFIG.replace("desc: 看内存", "desc: 看看内存"), encoding="utf-8")
        ops.refresh(force=True)
        self.assertTrue(self.exported("one"))


class NothingConfiguredTests(_Config):
    """页面上什么都没配：/tools、/tools/full、/tools/pending 和没有这个功能时一样，页面条目才有的字段一个都不出现。"""

    def outputs(self):
        ops.refresh(force=True)
        return (json.dumps({"tools": ops.available_tools()}, ensure_ascii=False, sort_keys=True),
                json.dumps({"tools": ops.describe_tools(), "pending": len(ops.list_pending()),
                            "mcp_servers": ops.mcp_status(), "connections": ops.describe_connections(),
                            "hosts": ops.describe_hosts(), "host": {"os": ops.HOST_OS}}, ensure_ascii=False, sort_keys=True),
                json.dumps({"pending": ops.list_pending()}, ensure_ascii=False, sort_keys=True))

    def test_no_side_file_and_an_empty_one_look_the_same(self):
        before = self.outputs()
        for word in ('"origin"', '"secret"', "export_page", "export_main", "page_secret"):
            self.assertNotIn(word, before[0] + before[1] + before[2])
        ops._page_write({kind: [] for kind in ops.PAGE_KINDS})
        self.assertEqual(self.outputs(), before)
        # 关掉一个本来就没开放的工具：不留记录，输出照旧
        self.set_passphrase()
        self.ok(ops.page_export, {"tool": "one", "on": False})
        self.assertEqual(self.outputs(), before)


class BrokenAndOldTests(_Config):
    def setUp(self):
        super().setUp()
        self.set_passphrase()

    def test_a_broken_side_file_does_not_stop_the_service(self):
        ops._page_file().write_text("connections:\n  - {name: x, type: postgres\n", encoding="utf-8")
        ops.refresh(force=True)
        self.assertIn("one", ops.all_tools())
        self.assertTrue(any("页面配置文件读不了" in p for p in ops._state["problems"]))
        view = ops.config_view()
        self.assertFalse(view["readable"])
        error = self.refused(ops.page_connection_save, {"connection": {"name": "cmdb", "type": "postgres", "host": "db",
                                                                       "database": "x", "user": "u"},
                                                        "passphrase": PASS}, 409)
        self.assertIn("暂时不能改", str(error))
        self.assertEqual(ops._approval["failures"], 0)
        # 一条写坏只跳过这一条
        ops._page_write({"connections": [{"name": "good", "type": "http", "base": "https://a.example.internal"},
                                         {"name": "Bad Name", "type": "http", "base": "https://b"}],
                         "mcp_servers": "oops", "export": [], "hosts": []})
        ops.refresh(force=True)
        self.assertIn("good", ops.describe_connections())
        self.assertTrue(any("连接名不合法" in p for p in ops._state["problems"]))
        self.assertTrue(any("mcp_servers 必须是列表" in p for p in ops._state["problems"]))

    def test_without_the_side_file_dependent_tools_drop_out_but_nothing_breaks(self):
        """旧版工具服务不认识旁路文件：和旁路文件不见了一样——依赖页面连接的工具加载不了，别的照常。"""
        self.add_pg()
        self.assertIn("cmdb_count", ops.all_tools())
        ops._page_file().unlink()
        ops.refresh(force=True)
        tools = ops.all_tools()
        self.assertNotIn("cmdb_count", tools)
        self.assertIn("one", tools)
        self.assertIn("usage", tools)
        self.assertTrue(any("cmdb_count 引用了未声明的连接 cmdb" in p for p in ops._state["problems"]))

    def test_the_switch_off_makes_the_page_read_only(self):
        with patch.dict(os.environ, {"OPS_PAGE_CONFIG": "off"}):
            error = self.refused(ops.page_connection_save, {"connection": {"name": "cmdb", "type": "postgres",
                                                                           "host": "db", "database": "x", "user": "u"},
                                                            "passphrase": PASS}, 403)
            self.assertIn("OPS_PAGE_CONFIG=off", str(error))
            self.refused(ops.page_export, {"tool": "one", "on": False}, 403)
            self.assertFalse(ops.config_view()["enabled"])
        self.assertTrue(ops.config_view()["enabled"])
        self.assertEqual(ops._approval["failures"], 0)

    def test_changes_are_logged_without_values(self):
        self.add_pg()
        self.ok(ops.page_connection_save, {"original": "cmdb", "connection": {
            "name": "cmdb", "type": "postgres", "host": "db2.example.internal", "database": "cmdb", "user": "doc2sop_ro",
            "tls": "require"}, "confirm": ["cmdb_count"], "passphrase": PASS})
        changes = ops._page_changes()
        self.assertEqual([change["action"] for change in changes][:2], ["修改连接", "新增连接"])
        self.assertIn("原来存的凭据已作废", changes[0]["detail"])
        self.assertIn("ip=10.1.2.3", changes[0]["caller"])
        self.assertIn("[page-config] 新增连接 cmdb", self.printed.getvalue())
        self.assertNothingLeaks()

    def test_the_real_probe_shares_the_precheck_budget(self):
        result = REAL_PROBE("测试连接 x", "web", lambda done: ([ops._check("tcp", "ok", "TCP", "通")], ""), wait=10)
        self.assertEqual((result["state"], result["verdict"]), ("done", "ok"))
        self.assertNotIn("key", result)


REAL_PROBE = ops._page_probe


HOSTS_CONFIG = textwrap.dedent("""\
    hosts:
      defaults: {via: ssh, user: opsread, key: "${ssh_key}", os: linux, mode: guarded}
      list:
        - {name: gateway-b, address: 150.109.244.82, groups: [gateway]}
    tools:
      - {name: host_uptime, desc: 开机时长, binary: uptime, argv: [uptime], params: {}}
      - {name: gw_disk, desc: 网关磁盘, binary: df, argv: [df, -h], params: {}, groups: [gateway]}
    """)
WEB01 = {"name": "web01", "address": "10.0.1.11", "user": "opsread", "groups": ["gateway"], "from": ["117.72.91.19"]}


class HostTests(_Config):
    CONFIG = HOSTS_CONFIG

    def setUp(self):
        super().setUp()
        self.set_passphrase()

    def add(self, **fields):
        return self.ok(ops.page_host_save, {"host": {**WEB01, **fields}, "passphrase": PASS})

    def fingerprint(self, blob=HOST_BLOB):
        return ops.key_fingerprint(blob)

    def trust(self, **extra):
        payload = {"name": "web01", "fingerprint": self.fingerprint(), "confirm_impact": ["gw_disk"],
                   "passphrase": PASS, **extra}
        return self.ok(ops.page_host_trust, payload)

    def test_adding_a_host_generates_its_own_key_and_does_not_trust_anything_yet(self):
        result = self.add()
        key = Path(ops._page_key_path("web01"))
        self.assertTrue(key.is_file())
        if POSIX:
            self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
        scanned = result["scan"]["checks"][0]["keys"]
        self.assertEqual(scanned[0]["fingerprint"], self.fingerprint())
        self.assertFalse(ops._page_known_hosts().exists())          # 扫到了也不登记
        self.assertNotIn("web01", ops.describe_hosts()["list"])     # 没核对之前不进主机清单，模型看不到
        self.assertEqual([item["tool"] for item in result["projected_impact"]], ["gw_disk"])
        install = result["item"]["install"]
        self.assertEqual(install["authorized_keys"],
                         'restrict,from="117.72.91.19",command="/usr/bin/python3 -I /opt/ops-readonly/ops_exec.py --stdio" '
                         f"{FAKE_PUBLIC} doc2sop-ops:web01")
        self.assertEqual(result["item"]["step"], "verify")
        # 不继承主配置 hosts.defaults 里的 key：私钥是页面主机自己的那一把
        self.assertEqual(ops._key_file(ops._page_host("web01")), str(key))
        self.assertNothingLeaks(json.dumps(result, ensure_ascii=False))

    def test_the_host_key_is_registered_only_after_a_matching_confirmation(self):
        self.add()
        error = self.refused(ops.page_host_trust, {"name": "web01", "fingerprint": self.fingerprint(),
                                                   "passphrase": PASS}, 409)
        self.assertEqual([item["tool"] for item in error.extra["confirm_impact"]], ["gw_disk"])
        self.refused(ops.page_host_trust, {"name": "web01", "fingerprint": self.fingerprint(OTHER_BLOB),
                                           "confirm_impact": ["gw_disk"], "passphrase": PASS}, 409)
        self.refused(ops.page_host_trust, {"name": "web01", "fingerprint": self.fingerprint(),
                                           "confirm_impact": ["gw_disk"]}, 400)
        self.assertEqual(ops._pinned_keys("web01", ops._page_known_hosts()), [])
        # 中间有人冒充：重新扫到的 key 和用户核对的对不上，不登记
        self.ssh.host_blob = OTHER_BLOB
        self.refused(ops.page_host_trust, {"name": "web01", "fingerprint": self.fingerprint(),
                                           "confirm_impact": ["gw_disk"], "passphrase": PASS}, 409)
        self.assertEqual(ops._pinned_keys("web01", ops._page_known_hosts()), [])
        self.ssh.host_blob = HOST_BLOB
        result = self.trust()
        self.assertEqual(result["fingerprint"], self.fingerprint())
        self.assertEqual(ops._pinned_keys("web01", ops._page_known_hosts()), [("ssh-ed25519", HOST_BLOB)])
        self.assertEqual(ops._pinned_keys("web01"), [])             # 主配置的 known_hosts 不动
        self.assertEqual(ops.describe_hosts()["list"]["web01"]["origin"], "page")
        target = ops.available_tools()["gw_disk"]["inputSchema"]["properties"]["target"]
        self.assertNotIn("x-default", target)                        # 两台能跑：没有默认值了
        self.assertIn("web01", target["enum"])

    def test_page_and_main_hosts_use_the_same_ssh_options(self):
        main_key = self.dir / "main-key"
        main_key.write_text("main private key", encoding="utf-8")
        main_key.chmod(0o600)
        ops._write_known_hosts("gateway-b", "ssh-ed25519", HOST_BLOB)
        twin = {**ops._hosts()["hosts"]["gateway-b"], "origin": "page", "key": None}
        Path(ops._page_key_path("gateway-b")).parent.mkdir(parents=True, exist_ok=True)
        Path(ops._page_key_path("gateway-b")).write_text("page private key", encoding="utf-8")
        os.chmod(ops._page_key_path("gateway-b"), 0o600)
        ops._write_known_hosts("gateway-b", "ssh-ed25519", HOST_BLOB, ops._page_known_hosts())
        seen = []
        with patch.object(ops, "_communicate", lambda argv, *rest, **kw: (seen.append(argv), (0, b"", b""))[1]):
            ops._transport.run(ops._hosts()["hosts"]["gateway-b"], "doc2sop-ops-exec")
            ops._transport.run(twin, "doc2sop-ops-exec")

        def without_key_and_known_hosts(argv):
            out, skip = [], False
            for part in argv:
                if skip:
                    skip = False
                    continue
                if part == "-i":
                    skip = True
                    continue
                if part.startswith("UserKnownHostsFile="):
                    continue
                out.append(part)
            return out

        main_argv, page_argv = seen
        self.assertNotEqual(main_argv, page_argv)
        self.assertEqual(without_key_and_known_hosts(main_argv), without_key_and_known_hosts(page_argv))
        self.assertIn(str(main_key), main_argv)
        self.assertIn(ops._page_key_path("gateway-b"), page_argv)
        self.assertIn(f"UserKnownHostsFile={ops._page_known_hosts()}", page_argv)

    def test_the_install_bundle_matches_push_print(self):
        self.add()
        self.trust()
        result = self.ok(ops.page_host_bundle, {"name": "web01"})
        info = result["bundle"]
        path = Path(info["file"])
        self.assertEqual(path, Path(ops._page_bundles_dir()) / "web01.tgz")
        if POSIX:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
        with tarfile.open(path, "r:gz") as archive:
            names = sorted(archive.getnames())
            files = {name: archive.extractfile(name).read() for name in names}
        self.assertEqual(names, ["web01/allowlist.json", "web01/install.sh", "web01/ops_exec.py"])
        self.assertEqual(files["web01/ops_exec.py"], (REPO / "deploy" / "ops_exec.py").read_bytes())
        allowlist = files["web01/allowlist.json"].decode("utf-8")
        self.assertEqual(files["web01/install.sh"].decode("utf-8"), ops.install_script(allowlist))
        out = self.dir / "push"
        quiet(ops.push, None, "web01", str(out))
        pushed = json.loads((out / "web01" / "allowlist.json").read_text(encoding="utf-8"))
        bundled = json.loads(allowlist)
        self.assertEqual({**pushed, "generated_at": ""}, {**bundled, "generated_at": ""})
        self.assertEqual((out / "web01" / "ops_exec.py").read_bytes(), files["web01/ops_exec.py"])
        # 下载的就是 A 上这个文件，sha256 一致
        download = ops.page_bundle_download("web01")
        data = base64.b64decode(download["data"])
        self.assertEqual(data, path.read_bytes())
        self.assertEqual(download["sha256"], info["sha256"])
        self.assertEqual(info["version"], ops._allowlist_state(ops._page_host("web01"))["expected"])
        self.refused(ops.page_host_bundle, {"name": "web01"}, 429)  # 连点
        self.assertNothingLeaks(json.dumps(result), json.dumps(download)[:2000])

    def test_host_info_prints_the_same_lines_as_the_page(self):
        self.add()
        self.trust()
        self.ok(ops.page_host_bundle, {"name": "web01"})
        item = next(host for host in ops.config_view()["hosts"] if host["name"] == "web01")
        code, printed = quiet(ops.host_info, "web01")
        self.assertEqual(code, 0, printed)
        self.assertIn(item["install"]["authorized_keys"], printed)
        for line in item["install"]["account"]:
            self.assertIn(line, printed)
        self.assertIn(item["bundle"]["sha256"], printed)
        self.assertIn(f"sha256sum {item['bundle']['file']}", printed)
        self.assertNotIn("FAKEPRIVATEKEYMATERIAL", printed)
        self.assertIsInstance(quiet(ops.host_info, "gateway-b")[0], ops.ConfigError)

    def test_a_changed_host_key_is_replaced_only_when_asked(self):
        self.add()
        self.trust()
        self.ssh.host_blob = OTHER_BLOB          # 目标主机重装了（或者有人冒充）
        error = self.refused(ops.page_host_trust, {"name": "web01", "fingerprint": self.fingerprint(OTHER_BLOB),
                                                   "passphrase": PASS}, 409)
        self.assertIn("替换", str(error))
        self.assertEqual(ops._approval["failures"], 0)
        self.assertEqual(ops._pinned_keys("web01", ops._page_known_hosts()), [("ssh-ed25519", HOST_BLOB)])
        self.ok(ops.page_host_trust, {"name": "web01", "fingerprint": self.fingerprint(OTHER_BLOB), "replace": True,
                                      "passphrase": PASS})
        self.assertEqual(ops._pinned_keys("web01", ops._page_known_hosts()), [("ssh-ed25519", OTHER_BLOB)])
        self.assertIn("替换了原来的", ops._page_changes()[0]["detail"])

    def test_moving_a_host_voids_its_host_key_and_delete_cleans_up(self):
        self.add()
        self.trust()
        dry = self.ok(ops.page_host_save, {"original": "web01", "host": {**WEB01, "address": "10.0.1.12"},
                                           "dry_run": True})
        self.assertEqual([item["tool"] for item in dry["impact"]], ["gw_disk"])
        self.refused(ops.page_host_save, {"original": "web01", "host": {**WEB01, "address": "10.0.1.12"},
                                          "passphrase": PASS}, 409)
        result = self.ok(ops.page_host_save, {"original": "web01", "host": {**WEB01, "address": "10.0.1.12"},
                                              "confirm_impact": ["gw_disk"], "passphrase": PASS})
        self.assertEqual(ops._pinned_keys("web01", ops._page_known_hosts()), [])
        self.assertNotIn("web01", ops.describe_hosts()["list"])
        self.assertEqual(result["item"]["step"], "verify")
        self.ok(ops.page_host_bundle, {"name": "web01"})
        result = self.ok(ops.page_host_delete, {"name": "web01", "passphrase": PASS})
        self.assertEqual(result["revoke"], ["rm -r ~opsread /opt/ops-readonly && userdel opsread"])
        for path in (ops._page_key_path("web01"), ops._page_key_path("web01") + ".pub", ops._page_bundle_path("web01")):
            self.assertFalse(os.path.exists(path), path)
        self.assertEqual(self.page_doc().get("hosts") or [], [])

    def test_host_requests_cannot_reach_server_keys_or_names(self):
        error = self.refused(ops.page_host_save, {"host": {**WEB01, "key": "${ssh_key}"}, "passphrase": PASS}, 400)
        self.assertIn("只用工具服务为它生成的私钥", str(error))
        self.refused(ops.page_host_save, {"host": {**WEB01, "name": "gateway-b"}, "passphrase": PASS}, 409)
        self.refused(ops.page_host_save, {"host": {**WEB01, "name": "local"}, "passphrase": PASS}, 400)
        self.refused(ops.page_host_save, {"host": {**WEB01, "name": "../etc"}, "passphrase": PASS}, 400)
        self.refused(ops.page_host_save, {"host": {**WEB01, "from": ["*"]}, "passphrase": PASS}, 400)
        self.refused(ops.page_host_save, {"host": {**WEB01, "from": ["0.0.0.0/0"]}, "passphrase": PASS}, 400)
        self.refused(ops.page_host_save, {"host": {**WEB01, "address": "${evil}"}, "passphrase": PASS}, 400)
        self.assertEqual(ops._approval["failures"], 0)
        self.assertFalse(ops._page_file().exists())

    def test_a_hand_edited_bad_host_name_can_still_be_deleted(self):
        """手改旁路文件写出来的非法主机名拼不出私钥、安装包的路径：删的时候不能删了条目又回 400，变更记录照记。"""
        outside = self.dir / "evil"
        outside.write_text("not ours", encoding="utf-8")
        ops._page_write({"connections": [], "mcp_servers": [], "export": [],
                         "hosts": [{**WEB01, "name": "../evil"}, {**WEB01, "name": "Web02"}]})
        ops.refresh(force=True)
        self.assertEqual(len([item for item in ops.config_view()["skipped"] if item["kind"] == "hosts"]), 2)
        for name in ("../evil", "Web02"):
            with self.subTest(name=name):
                result = self.ok(ops.page_host_delete, {"name": name, "passphrase": PASS})
                self.assertEqual(result["deleted"], name)
                self.assertEqual(ops._page_changes()[0]["target"], name)
        self.assertEqual(self.page_doc().get("hosts") or [], [])
        self.assertEqual(outside.read_text(encoding="utf-8"), "not ours")

    def test_names_never_escape_their_folder(self):
        folder = self.dir / "keys"
        folder.mkdir()
        for name in ("../evil", "a/b", "a\\b", "x y", "bad\x00", "", ".hidden", ".."):
            with self.subTest(name=name):
                with self.assertRaises(ops.ConfigError):
                    ops._named_path(str(folder), name)
        self.assertEqual(ops._named_path(str(folder), "web01"), os.path.realpath(str(folder / "web01")))
        if POSIX:
            (folder / "link").symlink_to(self.dir / "outside")
            with self.assertRaises(ops.ConfigError):
                ops._named_path(str(folder), "link")


class FirstHostTests(_Config):
    """主配置没有 hosts 段：页面上加的第一台主机核对之后打开主机模式，本机算一台（不填 target 就在本机跑），页面上也列出来。"""

    def test_the_first_page_host_lists_the_implicit_local_host(self):
        self.set_passphrase()
        self.assertEqual(ops.config_view()["hosts"], [])
        self.ok(ops.page_host_save, {"host": WEB01, "passphrase": PASS})
        self.assertEqual([host["name"] for host in ops.config_view()["hosts"]], ["web01"])   # 没核对：主机模式还没开
        dry = self.ok(ops.page_host_trust, {"name": "web01", "dry_run": True})
        self.ok(ops.page_host_trust, {"name": "web01", "fingerprint": ops.key_fingerprint(HOST_BLOB),
                                      "confirm_impact": [item["tool"] for item in dry["impact"]], "passphrase": PASS})
        view = ops.config_view()
        self.assertEqual([(host["name"], host["origin"], host.get("implicit", False)) for host in view["hosts"]],
                         [("local", "main", True), ("web01", "page", False)])
        self.assertEqual(view["host_mode"], {"configured": True, "default": "local", "local": "local"})


class HttpTests(_Config):
    """经 HTTP：令牌、状态码，回复和日志里没有口令、凭据、私钥。"""

    def setUp(self):
        super().setUp()
        self.set_passphrase()
        server = ops.ThreadingHTTPServer(("127.0.0.1", 0), ops.Handler)
        self.addCleanup(server.server_close)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        self.url = f"http://127.0.0.1:{server.server_address[1]}"
        token = patch.object(ops.Handler, "token", "t0k")
        token.start()
        self.addCleanup(token.stop)

    def http(self, path, payload=None, token="t0k"):
        request = urllib.request.Request(self.url + path, json.dumps(payload).encode() if payload is not None else None,
                                         {"X-Ops-Token": token, "Content-Type": "application/json",
                                          "X-Ops-Caller": "web user=admin ip=10.1.2.3"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            return exc.code, json.load(exc)

    def test_config_endpoints_over_http(self):
        connection = {"name": "cmdb", "type": "postgres", "host": "db.example.internal", "database": "cmdb",
                      "user": "doc2sop_ro"}
        self.assertEqual(self.http("/tools/config/connection-save", {"connection": connection}, token="bad")[0], 401)
        self.assertEqual(self.http("/tools/config/nope", {"x": 1})[0], 404)
        status, body = self.http("/tools/config/connection-save", {"connection": connection, "secret": DB_SECRET,
                                                                    "passphrase": WRONG})
        self.assertEqual(status, 403)
        status, body = self.http("/tools/config/connection-save", {"connection": connection, "secret": DB_SECRET,
                                                                    "passphrase": PASS})
        self.assertEqual(status, 200, body)
        status, view = self.http("/tools/config")
        self.assertEqual(status, 200)
        self.assertEqual(next(c for c in view["connections"] if c["name"] == "cmdb")["secret"]["state"], "set")
        status, body = self.http("/tools/config/connection-save", {"original": "cmdb", "connection": connection,
                                                                    "passphrase": PASS})
        self.assertEqual((status, body.get("confirm")), (409, ["cmdb_count"]))
        with patch.dict(os.environ, {"OPS_PAGE_CONFIG": "off"}):
            self.assertEqual(self.http("/tools/config/export", {"tool": "one", "on": False})[0], 403)
        self.assertEqual(self.http("/tools/config/bundle/..%2Fetc")[0], 404)
        self.assertNothingLeaks(json.dumps(view, ensure_ascii=False), json.dumps(body, ensure_ascii=False))
        self.assertNotIn(PASS, self.printed.getvalue())

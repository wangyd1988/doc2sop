"""页面上的 K8s 集群（工具服务这一层）。

名字、https 地址、CA（必填，没有跳过证书校验）存旁路文件，只读令牌存 page-secrets.json（只写不读，去向是名字、地址、CA）；
贴 kubeconfig 只认令牌认证，exec、auth-provider、客户端证书、用户名密码、文件路径、跳过校验、代理一律拒绝；要口令（加、改、删、测试），
共用输错计数；测试连接直连 API Server：/version、列命名空间、SelfSubjectAccessReview 问能不能读 Secret、能不能写，能就标红。
kubectl 型工具多一个 cluster 参数（没有页面集群时不出现，/tools 逐字节不变）：填了就用只含这个集群的临时 kubeconfig 跑，
令牌不进 argv、环境变量、日志，输出里遮掉（含 JWT 的每一段），临时文件用完一定删（含超时、出错）。
"""
import base64
import json
import os
import shutil
import ssl
import subprocess
import tempfile
import textwrap
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from tests.test_page_config import PASS, POSIX, WRONG, _Config, ops, quiet, tls_files

REAL_RUN = subprocess.run
REAL_WHICH = shutil.which


def jwt(sub="system:serviceaccount:doc2sop:ops-readonly", days=90, tag="ro"):
    part = lambda data: base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")  # noqa: E731
    return ".".join((part({"alg": "RS256", "kid": f"kid-{tag}-0123456789"}),
                     part({"sub": sub, "exp": int(time.time() + days * 86400), "iss": "https://kubernetes.default.svc",
                           "tag": tag}),
                     base64.urlsafe_b64encode(f"signature-{tag}-".encode() * 4).decode().rstrip("=")))


RO = jwt()
ADMIN = jwt(sub="system:serviceaccount:kube-system:admin", tag="admin")
CONFIG = textwrap.dedent("""\
    tools:
      - name: kube_list
        desc: 列资源
        binary: kubectl
        argv: [kubectl, get, "{resource}", -n, "{namespace}", -o, wide]
        params:
          resource: {type: str, pattern: resource, required: true}
          namespace: {type: str, pattern: k8s_name, default: default}
      - {name: kube_ctx, desc: 写死了 context, binary: kubectl, argv: [kubectl, --context, prod, get, pods], params: {}}
      - {name: one, desc: 看内存, binary: free, argv: [free, -m], params: {}}
    """)


class FakeApi(BaseHTTPRequestHandler):
    """假的 API Server：RO 令牌读不了 Secret、不能写；ADMIN 什么都能；别的 401。记下收到的请求。"""
    seen = []

    def reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def who(self):
        auth = self.headers.get("Authorization", "")
        return {f"Bearer {RO}": "ro", f"Bearer {ADMIN}": "admin"}.get(auth)

    def do_GET(self):
        FakeApi.seen.append(("GET", self.path, self.who()))
        if self.path == "/version":
            return self.reply(200, {"gitVersion": "v1.31.4+k3s1"})
        if not self.who():
            return self.reply(401, {"kind": "Status"})
        if self.path.startswith("/api/v1/namespaces"):
            return self.reply(200, {"kind": "NamespaceList", "items": [{"metadata": {"name": "default"}}]})
        self.reply(404, {})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        FakeApi.seen.append(("POST", self.path, self.who(), body))
        if not self.who():
            return self.reply(401, {"kind": "Status"})
        if self.path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
            return self.reply(201, {**body, "status": {"allowed": self.who() == "admin"}})
        self.reply(404, {})

    def log_message(self, *args):
        pass


class _Clusters(_Config):
    CONFIG = CONFIG

    def setUp(self):
        super().setUp()
        self.set_passphrase()
        self.tls = tls_files(self, self.dir / "tls")
        self.ca = self.tls["ca"].read_text()
        self.server = "https://127.0.0.1:6443"
        for patcher in (patch.object(ops, "_server_kubeconfig", lambda: True),
                        patch.object(ops, "_cluster_checks", lambda cluster, token, use_saved, done: [
                            ops._check("tls", "ok", "TLS", "通")])):
            patcher.start()
            self.addCleanup(patcher.stop)

    def cluster(self, **fields):
        return {"name": "prod", "label": "生产", "server": self.server, "ca": self.ca, **fields}

    def add(self, token=RO, **fields):
        payload = {"cluster": self.cluster(**fields), "passphrase": PASS}
        if token is not None:
            payload["token"] = token
        return self.ok(ops.page_cluster_save, payload)

    def kubeconfig(self, user=None, cluster=None, extra=""):
        cluster = cluster or {"server": self.server,
                              "certificate-authority-data": base64.b64encode(self.ca.encode()).decode()}
        user = {"token": RO} if user is None else user
        return json.dumps({"apiVersion": "v1", "kind": "Config", "current-context": "c",
                           "clusters": [{"name": "k", "cluster": cluster}], "users": [{"name": "u", "user": user}],
                           "contexts": [{"name": "c", "context": {"cluster": "k", "user": "u"}}]}) + extra

    def assertNoToken(self, *texts):
        said = self.everything_said() + json.dumps(ops.clusters_view(), ensure_ascii=False) + "\n".join(map(str, texts))
        for value in ops._token_forms(RO) + ops._token_forms(ADMIN):
            self.assertNotIn(value, said)


class SaveTests(_Clusters):
    def test_no_cluster_no_parameter_and_tools_unchanged(self):
        before = json.dumps(ops.available_tools(), ensure_ascii=False, sort_keys=True)
        full = json.dumps(ops.describe_tools(), ensure_ascii=False, sort_keys=True)
        self.assertNotIn('"cluster"', before)
        self.add()
        self.ok(ops.page_cluster_delete, {"name": "prod", "passphrase": PASS})
        self.assertEqual(json.dumps(ops.available_tools(), ensure_ascii=False, sort_keys=True), before)
        self.assertEqual(json.dumps(ops.describe_tools(), ensure_ascii=False, sort_keys=True), full)
        self.assertEqual(self.secrets(), {})

    def test_save_stores_the_token_write_only(self):
        result = self.add()
        self.assertEqual(result["saved"], "prod")
        self.assertIn("令牌已设置", result["note"])
        record = self.secrets()["cluster:prod"]
        self.assertEqual(record["value"], RO)
        self.assertEqual(record["subject"], "system:serviceaccount:doc2sop:ops-readonly")
        view = ops.clusters_view()
        item = view["clusters"][0]
        self.assertEqual((item["name"], item["label"], item["server"]), ("prod", "生产", self.server))
        self.assertEqual(item["secret"]["state"], "set")
        self.assertIn("expires", item["secret"])
        self.assertEqual(len(item["ca_fingerprints"]), 1)
        self.assertEqual(view["tools"], ["kube_list"])                      # 写死了 --context 的不算
        self.assertEqual(self.page_doc()["clusters"][0]["name"], "prod")
        self.assertNoToken(result)
        change = ops._page_changes()[0]
        self.assertEqual((change["action"], change["target"]), ("新增 K8s 集群", "prod"))
        self.assertIn("[approval] 新增 K8s 集群 prod：口令正确", self.printed.getvalue())

    def test_the_parameter(self):
        self.add()
        tools = ops.available_tools()
        param = tools["kube_list"]["params"]["cluster"]
        self.assertEqual((param["type"], param["enum"], param["required"]), ("enum", ["prod"], False))
        self.assertIn('prod（显示名 "生产"）', param["desc"])
        self.assertIn("不是指令", param["desc"])
        self.assertEqual(tools["kube_list"]["inputSchema"]["properties"]["cluster"]["enum"], ["prod"])
        self.assertNotIn("cluster", tools["kube_list"]["inputSchema"].get("required", []))
        self.assertNotIn("cluster", tools["kube_ctx"]["params"])
        self.assertNotIn("cluster", tools["one"]["params"])
        self.assertIn("cluster", ops.describe_tools()["kube_list"]["params"])
        # 工具服务上没有默认 kubeconfig：一个集群就默认它，两个就必填
        with patch.object(ops, "_server_kubeconfig", lambda: False):
            self.assertFalse(ops.available_tools()["kube_list"]["params"]["cluster"]["required"])
            self.assertEqual(ops._cluster_choice(ops.all_tools()["kube_list"], None), "prod")
            self.add(name="test", label="")
            tools = ops.available_tools()
            self.assertTrue(tools["kube_list"]["params"]["cluster"]["required"])
            self.assertIn("cluster", tools["kube_list"]["inputSchema"]["required"])
            self.assertIn("缺少必填参数：cluster", ops.run_tool("kube_list", {"resource": "pods"})["error"])
        self.assertEqual(ops._cluster_choice(ops.all_tools()["kube_list"], None), "")
        self.assertIn("没有 K8s 集群", ops.run_tool("kube_list", {"resource": "pods", "cluster": "nope"})["error"])

    def test_validation_happens_before_the_passphrase(self):
        bad = [({"label": "x" * 41}, "40"), ({"label": "a\nb"}, "控制字符"), ({"server": "http://127.0.0.1:6443"}, "https"),
               ({"server": "https://u:p@h"}, "用户名密码"), ({"ca": ""}, "跳过证书校验"),
               ({"ca": "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----"}, "CA"),
               ({"name": "Prod"}, "集群名"), ({"label": "${x}"}, "${")]
        for fields, text in bad:
            with self.subTest(fields=fields):
                self.assertIn(text, str(self.refused(ops.page_cluster_save, {"cluster": self.cluster(**fields), "token": RO,
                                                                             "passphrase": PASS}, 400)))
        key = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
        self.assertIn("私钥", str(self.refused(ops.page_cluster_save, {"cluster": self.cluster(ca=self.ca + key),
                                                                       "token": RO, "passphrase": PASS}, 400)))
        for token in ("short", "has space in it", "${ops_token}"):
            self.refused(ops.page_cluster_save, {"cluster": self.cluster(), "token": token, "passphrase": PASS}, 400)
        self.refused(ops.page_cluster_save, {"cluster": self.cluster(), "passphrase": PASS}, 400)       # 新加的要令牌
        self.refused(ops.page_cluster_save, {"cluster": {**self.cluster(), "insecure": True}, "token": RO,
                                             "passphrase": PASS}, 400)
        self.assertNotIn("[approval]", self.printed.getvalue())
        self.assertEqual(ops._approval["failures"], 0)
        self.refused(ops.page_cluster_save, {"cluster": self.cluster(), "token": RO, "passphrase": WRONG}, 403)
        self.assertEqual(ops._approval["failures"], 1)
        self.assertFalse(ops._page_file().exists())
        self.assertNoToken()

    def test_destination_bound(self):
        self.add()
        result = self.ok(ops.page_cluster_save, {"cluster": self.cluster(label="生产集群"), "original": "prod", "passphrase": PASS})
        self.assertEqual(result["note"], "令牌没改")
        self.assertEqual(self.secrets()["cluster:prod"]["value"], RO)
        # 改地址或 CA 不带新令牌：拒绝（不会悄悄留下作废的令牌，也不会拿旧令牌去连新地址）
        error = self.refused(ops.page_cluster_save, {"cluster": self.cluster(server="https://10.0.0.9:6443"),
                                                     "original": "prod", "passphrase": PASS}, 400)
        self.assertIn("作废", str(error))
        self.refused(ops.page_cluster_test, {"cluster": self.cluster(server="https://10.0.0.9:6443"), "original": "prod",
                                             "passphrase": PASS}, 400)
        self.ok(ops.page_cluster_save, {"cluster": self.cluster(server="https://10.0.0.9:6443"), "original": "prod",
                                        "token": ADMIN, "passphrase": PASS})
        self.assertEqual(self.secrets()["cluster:prod"]["value"], ADMIN)
        # 手改旁路文件换了地址：去向对不上，令牌不发
        document = self.page_doc()
        document["clusters"][0]["server"] = "https://evil.example:6443"
        ops._write_yaml(ops._page_file(), document)
        ops.refresh(force=True)
        self.assertEqual(ops.clusters_view()["clusters"][0]["secret"]["state"], "stale")
        error = ops.run_tool("kube_list", {"resource": "pods", "cluster": "prod"})
        self.assertIn("去向变过", error["error"])
        self.refused(ops.page_cluster_save, {"cluster": self.cluster(name="prod2"), "original": "prod", "token": RO,
                                             "passphrase": PASS}, 400)          # 不能改名

    def test_delete(self):
        self.add()
        self.refused(ops.page_cluster_delete, {"name": "prod"}, 400)
        self.refused(ops.page_cluster_delete, {"name": "nope", "passphrase": PASS}, 404)
        self.ok(ops.page_cluster_delete, {"name": "prod", "passphrase": PASS})
        self.assertNotIn("cluster:prod", self.secrets())
        self.assertNotIn("clusters", self.page_doc())
        self.assertEqual(ops._page_changes()[0]["action"], "删除 K8s 集群")

    def test_page_config_off(self):
        self.add()
        with patch.dict(os.environ, {"OPS_PAGE_CONFIG": "off"}):
            for fn, payload in ((ops.page_cluster_save, {"cluster": self.cluster(name="x"), "token": RO, "passphrase": PASS}),
                                (ops.page_cluster_delete, {"name": "prod", "passphrase": PASS}),
                                (ops.page_cluster_test, {"cluster": self.cluster(), "token": RO, "passphrase": PASS})):
                self.refused(fn, payload, 403)

    def test_old_service_style_broken_entries_are_skipped(self):
        ops._write_yaml(ops._page_file(), {"format": 1, "clusters": [{"name": "prod", "server": "http://x", "ca": self.ca},
                                                                      {"name": "ok1", "server": self.server, "ca": self.ca}]})
        ops.refresh(force=True)
        view = ops.config_view()
        self.assertEqual([item["name"] for item in view["skipped"]], ["prod"])
        self.assertEqual([item["name"] for item in ops.clusters_view()["clusters"]], ["ok1"])
        self.assertEqual(ops.clusters_view()["clusters"][0]["secret"]["state"], "missing")


class KubeconfigTests(_Clusters):
    def setUp(self):
        super().setUp()
        import collections
        for patcher in (patch.object(ops, "_probe_times", collections.deque()), patch.object(ops, "PRECHECK_RATE", (100, 60))):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_token_kubeconfig(self):
        parsed = self.ok(ops.page_cluster_parse, {"kubeconfig": self.kubeconfig()})
        self.assertEqual((parsed["server"], parsed["context"], parsed["has_token"]), (self.server, "c", True))
        self.assertEqual(parsed["subject"], "system:serviceaccount:doc2sop:ops-readonly")
        self.assertNotIn("token", parsed)
        self.assertNoToken(parsed)
        result = self.ok(ops.page_cluster_save, {"cluster": {"name": "prod", "server": "https://ignored:1", "ca": "x"},
                                                 "kubeconfig": self.kubeconfig(), "passphrase": PASS})
        self.assertEqual(result["item"]["server"], self.server)
        self.assertEqual(self.secrets()["cluster:prod"]["value"], RO)
        self.refused(ops.page_cluster_save, {"cluster": {"name": "p2"}, "kubeconfig": self.kubeconfig(), "token": RO,
                                             "passphrase": PASS}, 400)

    def test_refused_styles(self):
        ca = base64.b64encode(self.ca.encode()).decode()
        cases = [({"exec": {"command": "aws"}}, None, "exec 插件"), ({"auth-provider": {"name": "oidc"}}, None, "auth-provider"),
                 ({"client-certificate-data": "QQ==", "client-key-data": "QQ=="}, None, "客户端证书"),
                 ({"username": "admin", "password": "x"}, None, "用户名和密码"), ({"tokenFile": "/var/run/token"}, None, "tokenFile"),
                 ({"token": RO, "as": "system:admin"}, None, "身份模拟"), ({}, None, "没有令牌"),
                 (None, {"server": self.server, "insecure-skip-tls-verify": True}, "跳过证书校验"),
                 (None, {"server": self.server, "certificate-authority": "/etc/k.pem"}, "文件路径"),
                 (None, {"server": "http://10.0.0.1:8080", "certificate-authority-data": ca}, "https"),
                 (None, {"server": self.server, "certificate-authority-data": ca, "proxy-url": "http://p:3128"}, "代理"),
                 (None, {"server": self.server}, "certificate-authority-data")]
        for user, cluster, text in cases:
            with self.subTest(text=text):
                error = self.refused(ops.page_cluster_parse, {"kubeconfig": self.kubeconfig(user=user, cluster=cluster)}, 400)
                self.assertIn(text, str(error))
                self.assertNotIn(RO, str(error))
        error = self.refused(ops.page_cluster_parse, {"kubeconfig": self.kubeconfig(user={"client-certificate-data": "QQ=="})})
        self.assertIn("kubectl -n doc2sop create token ops-readonly", str(error))
        for text in ("", "a: [", "- 1", "x" * (ops.KUBECONFIG_MAX + 1)):
            self.refused(ops.page_cluster_parse, {"kubeconfig": text}, 400)

    def test_several_contexts(self):
        document = json.loads(self.kubeconfig())
        document["contexts"].append({"name": "d", "context": {"cluster": "k", "user": "u"}})
        del document["current-context"]
        error = self.refused(ops.page_cluster_parse, {"kubeconfig": json.dumps(document)}, 409)
        self.assertEqual(error.extra["contexts"], ["c", "d"])
        self.assertEqual(self.ok(ops.page_cluster_parse, {"kubeconfig": json.dumps(document), "context": "d"})["context"], "d")


class _ApiServer(_Clusters):
    def setUp(self):
        super().setUp()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.tls["cert"], self.tls["key"])
        server = ThreadingHTTPServer(("127.0.0.1", 0), FakeApi)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.server = f"https://127.0.0.1:{server.server_address[1]}"
        FakeApi.seen = []
        patcher = patch.object(ops, "_cluster_checks", REAL_CHECKS)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test(self, token=RO, **extra):
        return self.ok(ops.page_cluster_test, {"cluster": self.cluster(), "token": token, "passphrase": PASS, **extra})["test"]


REAL_CHECKS = ops._cluster_checks


class ConnectionTestTests(_ApiServer):
    def test_read_only_token(self):
        result = self.test()
        self.assertEqual(result["verdict"], "ok", result)
        keys = [check["key"] for check in result["checks"]]
        self.assertEqual(keys, ["expiry", "tls", "list", "secrets", "write"])
        self.assertIn("v1.31.4+k3s1", result["checks"][1]["text"])
        self.assertIn("只问权限、不读任何数据", result["checks"][3]["text"])
        asked = [seen[3]["spec"]["resourceAttributes"] for seen in FakeApi.seen if seen[0] == "POST"]
        self.assertIn({"verb": "list", "resource": "secrets", "namespace": "kube-system"}, asked)
        self.assertIn({"verb": "create", "resource": "pods", "subresource": "exec", "namespace": "default"}, asked)
        self.assertTrue(all(seen[2] == "ro" for seen in FakeApi.seen if seen[1] != "/version"))
        self.assertNoToken(result)

    def test_admin_token_is_red(self):
        result = self.test(token=ADMIN)
        self.assertEqual(result["verdict"], "blocked")
        secrets_check = next(check for check in result["checks"] if check["key"] == "secrets")
        self.assertEqual((secrets_check["status"], secrets_check.get("danger")), ("fail", True))
        self.assertIn("能读 Secret", secrets_check["text"])
        self.assertTrue(next(check for check in result["checks"] if check["key"] == "write").get("danger"))

    def test_bad_token_and_wrong_ca(self):
        result = self.test(token=jwt(tag="other"))
        self.assertIn("401", json.dumps(result, ensure_ascii=False))
        other = tls_files(self, self.dir / "other")
        result = self.ok(ops.page_cluster_test, {"cluster": self.cluster(ca=other["ca"].read_text()), "token": RO,
                                                 "passphrase": PASS})["test"]
        self.assertIn("证书校验不过", json.dumps(result, ensure_ascii=False))
        self.assertEqual([seen for seen in FakeApi.seen if seen[2]], [])        # CA 不对时令牌一次都没发出去

    def test_expired_and_soon(self):
        self.assertIn("已经过期", self.test(token=jwt(days=-1))["checks"][0]["text"])
        self.assertEqual(self.test(token=jwt(days=3))["checks"][0]["status"], "warn")

    def test_saved_token_only_for_its_own_destination(self):
        self.add()
        self.assertEqual(ops._page_last_test("cluster", ops._page_clusters()["prod"], "prod")["verdict"], "ok")
        result = self.ok(ops.page_cluster_test, {"cluster": self.cluster(), "original": "prod", "passphrase": PASS})
        self.assertTrue(result["used_saved_secret"])
        self.refused(ops.page_cluster_test, {"cluster": self.cluster(server="https://127.0.0.1:1"), "original": "prod",
                                             "passphrase": PASS}, 400)
        self.refused(ops.page_cluster_test, {"cluster": self.cluster(), "token": RO}, 400)       # 测试要口令


FAKE_KUBECTL = """#!/bin/sh
echo "ARGS $*"
echo "ENV ${KUBECONFIG-unset}"
prev=
for a in "$@"; do
  if [ "$prev" = "--kubeconfig" ]; then echo "FILE $a"; echo "MODE $(stat -c %a "$a") $(stat -c %a "$(dirname "$a")")"; cat "$a"; echo; fi
  prev=$a
done
case "$*" in *sleep*) sleep 5;; esac
"""


@unittest.skipUnless(POSIX, "假的 kubectl 是 sh 脚本")
class RunTests(_Clusters):
    def setUp(self):
        super().setUp()
        self.add()
        bin_dir = self.dir / "bin"
        bin_dir.mkdir()
        kubectl = bin_dir / "kubectl"
        kubectl.write_text(FAKE_KUBECTL)
        kubectl.chmod(0o755)
        for patcher in (patch.object(ops.subprocess, "run", REAL_RUN),
                        patch.object(ops.shutil, "which", lambda name: str(kubectl) if name == "kubectl" else REAL_WHICH(name)),
                        patch.dict(os.environ, {"KUBECONFIG": "/etc/server-kubeconfig"})):
            patcher.start()
            self.addCleanup(patcher.stop)

    def files(self, output):
        return [line.split(" ", 1)[1] for line in output.splitlines() if line.startswith("FILE ")]

    def test_runs_with_a_temporary_kubeconfig(self):
        result = ops.run_tool("kube_list", {"resource": "pods", "namespace": "biz", "cluster": "prod"})
        self.assertTrue(result["ok"], result)
        output = result["output"]
        self.assertIn("get pods -n biz -o wide", output)
        self.assertIn("ENV unset", output)                                  # 服务器的 KUBECONFIG 不传给它
        self.assertIn("MODE 600 700", output)
        self.assertIn("***", output)                                         # kubeconfig 里的令牌遮掉了
        self.assertEqual(result["command"], "kubectl get pods -n biz -o wide（K8s 集群 prod）")
        path = self.files(output)[0]
        self.assertTrue(path.startswith("/dev/shm/doc2sop-kube-") or "kube-tmp" in path, path)
        self.assertFalse(os.path.exists(path))
        self.assertFalse(os.path.exists(os.path.dirname(path)))
        self.assertNoToken(json.dumps(result, ensure_ascii=False))

    def test_jwt_segments_are_masked_too(self):
        segments = RO.split(".")
        with patch.object(ops, "_kubeconfig_text", lambda cluster, token: "\n".join(segments)):
            output = ops.run_tool("kube_list", {"resource": "pods", "cluster": "prod"})["output"]
        for part in segments:
            self.assertNotIn(part, output)

    def test_without_cluster_runs_as_before(self):
        with patch.object(ops, "_run_local", lambda spec, args: {"ok": True, "output": f"local {sorted(args)}"}):
            self.assertEqual(ops.run_tool("kube_list", {"resource": "pods"})["output"], "local ['resource']")
        self.assertIn("target", ops.run_tool("kube_list", {"resource": "pods", "cluster": "prod", "target": "b"})["error"])

    def test_timeout_and_errors_still_delete_the_file(self):
        seen = []

        def boom(argv, **kwargs):
            path = argv[argv.index("--kubeconfig") + 1]
            seen.append(path)
            self.assertTrue(os.path.exists(path))
            raise OSError("exec failed " + RO)

        with patch.object(ops.subprocess, "run", boom):
            result = ops.run_tool("kube_list", {"resource": "pods", "cluster": "prod"})
        self.assertFalse(result["ok"])
        self.assertNotIn(RO, result["error"])
        self.assertFalse(os.path.exists(seen[0]))

        def slow(argv, **kwargs):
            seen.append(argv[argv.index("--kubeconfig") + 1])
            raise subprocess.TimeoutExpired(argv, 1)

        with patch.object(ops.subprocess, "run", slow):
            self.assertIn("超时", ops.run_tool("kube_list", {"resource": "pods", "cluster": "prod"})["error"])
        self.assertFalse(os.path.exists(seen[1]))
        with patch.object(ops, "TIMEOUT", 1):
            result = ops.run_tool("kube_list", {"resource": "sleep", "cluster": "prod"})
        self.assertIn("超时", result["error"])
        self.assertEqual([p for p in os.listdir("/dev/shm") if p.startswith("doc2sop-kube-")] if os.path.isdir("/dev/shm") else [], [])

    def test_token_never_in_argv_or_environment(self):
        captured = {}

        def spy(argv, **kwargs):
            captured.update(argv=argv, env=kwargs.get("env"))
            return REAL_RUN(argv, **kwargs)

        with patch.object(ops.subprocess, "run", spy):
            ops.run_tool("kube_list", {"resource": "pods", "cluster": "prod"})
        self.assertNotIn(RO, json.dumps(captured))
        self.assertNotIn("KUBECONFIG", captured["env"])


class HttpTests(_Clusters):
    def test_endpoints(self):
        import urllib.error
        import urllib.request
        server = ops.ThreadingHTTPServer(("127.0.0.1", 0), ops.Handler)
        self.addCleanup(server.server_close)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        url = f"http://127.0.0.1:{server.server_address[1]}"
        token = patch.object(ops.Handler, "token", "t0k")
        token.start()
        self.addCleanup(token.stop)

        def http(path, payload=None, key="t0k"):
            request = urllib.request.Request(url + path, json.dumps(payload).encode() if payload is not None else None,
                                             {"X-Ops-Token": key, "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    return response.status, json.loads(response.read())
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read())

        self.assertEqual(http("/tools/config/clusters", key="bad")[0], 401)
        self.assertEqual(http("/tools/config/clusters"), (200, ops.clusters_view()))
        status, body = http("/tools/config/cluster-save", {"cluster": self.cluster(), "token": RO, "passphrase": PASS})
        self.assertEqual(status, 200, body)
        status, body = http("/tools/config/cluster-parse", {"kubeconfig": self.kubeconfig(user={"exec": {"command": "x"}})})
        self.assertEqual(status, 400)
        status, body = http("/tools/config/clusters")
        self.assertEqual(body["clusters"][0]["secret"]["state"], "set")
        self.assertNoToken(body)


if __name__ == "__main__":
    unittest.main()

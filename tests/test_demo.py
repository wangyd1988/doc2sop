"""一键演示的静态校验：compose 文件、.env.example、sidecar 和演示主机的入口脚本。

本机没有 Docker 也能跑：只解析文件、不起容器。真机验证见 docs/五分钟演示.md。
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

REPO = Path(__file__).resolve().parent.parent
DEMO = ("leave-planning", "model-selfcheck")

_SPEC = importlib.util.spec_from_file_location("demo_entrypoint", REPO / "deploy" / "demo" / "entrypoint.py")
entrypoint = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(entrypoint)

if "ops_readonly" in sys.modules:
    ops = sys.modules["ops_readonly"]
else:
    _OPS = importlib.util.spec_from_file_location("ops_readonly", REPO / "deploy" / "ops_readonly.py")
    ops = importlib.util.module_from_spec(_OPS)
    sys.modules["ops_readonly"] = ops
    _OPS.loader.exec_module(ops)


def env_example():
    text = (REPO / ".env.example").read_text(encoding="utf-8")
    values = {}
    for line in text.splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()
    return text, values


class ComposeTests(unittest.TestCase):
    def setUp(self):
        self.doc = yaml.safe_load((REPO / "docker-compose.yml").read_text(encoding="utf-8"))
        self.app = self.doc["services"]["kb-app"]
        self.ops = self.doc["services"]["kb-ops"]
        self.host = self.doc["services"]["kb-host"]

    def test_sidecar_only_runs_under_the_demo_profile(self):
        self.assertEqual(self.ops["profiles"], ["demo"])
        self.assertEqual(self.host["profiles"], ["demo"])
        self.assertNotIn("profiles", self.app)
        # profile 外的服务不能 depends_on profile 内的服务，否则不带 --profile 的 up 会报错
        self.assertNotIn("depends_on", self.app)

    def test_demo_host_is_small_unpublished_and_has_no_docker_socket(self):
        """演示主机：sshd + 执行器，内存设上限，不发布端口，不挂 docker.sock；sidecar 经服务名连它。"""
        self.assertNotIn("ports", self.host)
        self.assertEqual((self.host["mem_limit"], self.host["cpus"]), ("64m", 0.25))
        self.assertEqual(self.host["build"]["dockerfile"], "demo/Dockerfile.host")
        self.assertEqual(self.host["build"]["context"], "deploy")
        self.assertFalse([v for v in self.host.get("volumes", []) if "docker.sock" in v])
        self.assertEqual(sorted(self.host["volumes"]), ["host-exchange:/exchange", "host-keys:/etc/ssh/keys"])
        self.assertEqual(self.host["container_name"], "${HOST_CONTAINER:-kb-host}")
        self.assertEqual(self.host["image"], "${HOST_IMAGE:-kb-host:latest}")
        env = self.ops["environment"]
        self.assertEqual((env["DEMO_HOST"], env["DEMO_HOST_PACKS"]), ("kb-host", "${DEMO_HOST_PACKS-ops-inspection}"))
        self.assertIn("host-exchange:/exchange", self.ops["volumes"])
        self.assertEqual(self.ops["depends_on"], ["kb-host"])
        self.assertLessEqual({"host-exchange", "host-keys"}, set(self.doc["volumes"]))

    def test_dockerfiles_keep_the_pip_cache_and_ship_the_executor(self):
        ops_file = (REPO / "deploy" / "demo" / "Dockerfile.ops").read_text(encoding="utf-8")
        self.assertLess(ops_file.index("pip install"), ops_file.index("ARG DEBIAN_MIRROR"),
                        "apt 那一层要放在 pip 之后，改它不让 pip 的缓存失效")
        self.assertIn("COPY ops_readonly.py ops_exec.py demo/entrypoint.py /srv/", ops_file)
        self.assertIn("openssh-client", ops_file)
        host_file = (REPO / "deploy" / "demo" / "Dockerfile.host").read_text(encoding="utf-8")
        for needle in ("openssh-server", "COPY ops_exec.py /opt/ops-readonly/ops_exec.py",
                       "COPY demo/host-allowlist.json /opt/ops-readonly/allowlist.json", "usermod -p '*' opsread"):
            self.assertIn(needle, host_file)

    def test_sidecar_is_not_published_and_is_small(self):
        self.assertNotIn("ports", self.ops)
        self.assertEqual(self.ops["mem_limit"], "128m")
        self.assertEqual(self.app["mem_limit"], "${APP_MEM_LIMIT:-900m}")
        self.assertEqual(self.app["cpus"], "${APP_CPUS:-1.5}")
        self.assertEqual(self.ops["build"]["context"], "deploy")
        self.assertEqual(self.ops["build"]["dockerfile"], "demo/Dockerfile.ops")

    def test_names_ports_and_limits_come_from_env_with_defaults(self):
        """一台机器跑两套只改 .env：容器名、镜像名、宿主机端口都是带默认值的变量，默认值就是原来的字面量。"""
        self.assertEqual(self.app["container_name"], "${APP_CONTAINER:-kb-app}")
        self.assertEqual(self.app["image"], "${APP_IMAGE:-kb-app:latest}")
        self.assertEqual(self.app["ports"], ["127.0.0.1:${APP_PORT:-8765}:8765"])
        self.assertEqual(self.ops["container_name"], "${OPS_CONTAINER:-kb-ops}")
        self.assertEqual(self.ops["image"], "${OPS_IMAGE:-kb-ops:latest}")
        # 容器访问宿主机服务（本机网关、宿主机工具）靠这一条；Linux 上没有它 host.docker.internal 解析不了
        for service in (self.app, self.ops):
            self.assertIn("host.docker.internal:host-gateway", service["extra_hosts"])
        text, _ = env_example()
        for name in ("APP_CONTAINER", "OPS_CONTAINER", "HOST_CONTAINER", "APP_IMAGE", "OPS_IMAGE", "HOST_IMAGE",
                     "APP_PORT", "APP_MEM_LIMIT", "APP_CPUS", "DEBIAN_MIRROR", "DEMO_HOST_PACKS"):
            self.assertIn(f"# {name}=", text, f".env.example 应说明 {name}")

    def test_base_image_is_overridable_from_the_env_file(self):
        """国内拉不动 Docker Hub 时只改 .env 的 BASE_IMAGE：三个镜像都要吃到同一个值，默认仍是官方镜像。"""
        for service in (self.app, self.ops, self.host):
            self.assertEqual(service["build"]["args"]["BASE_IMAGE"], "${BASE_IMAGE:-python:3.12-slim}")
        for service in (self.ops, self.host):
            self.assertEqual(service["build"]["args"]["DEBIAN_MIRROR"], "${DEBIAN_MIRROR:-}")
        for dockerfile in ("Dockerfile", "deploy/demo/Dockerfile.ops", "deploy/demo/Dockerfile.host"):
            text = (REPO / dockerfile).read_text(encoding="utf-8")
            self.assertIn("ARG BASE_IMAGE=python:3.12-slim", text, dockerfile)
            self.assertIn("FROM ${BASE_IMAGE}", text, dockerfile)
            self.assertNotIn("FROM python:", text, dockerfile)

    def test_token_and_gateway_credentials_come_from_the_single_env_file(self):
        env = self.ops["environment"]
        self.assertTrue(env["OPS_TOKEN"].startswith("${OPS_TOKEN:?"))
        self.assertEqual(env["OPS_SECRET_GATEWAY_URL"], "${LLM_BASE_URL:-}")
        self.assertEqual(env["OPS_SECRET_GATEWAY_KEY"], "${LLM_API_KEY:-}")
        self.assertEqual(env["DEMO_PACKS"], "${DEMO_PACKS:-}")
        self.assertEqual(self.app["env_file"], ".env")

    def test_both_containers_see_the_packs_directory(self):
        self.assertIn("./packs:/packs:ro", self.ops["volumes"])
        self.assertIn("ops-state:/ops", self.ops["volumes"])
        self.assertIn("./packs:/srv/packs:ro", self.app["volumes"])
        self.assertIn("ops-state", self.doc["volumes"])

    def test_sidecar_healthcheck_hits_the_unauthenticated_health_route(self):
        self.assertIn("/health", self.ops["healthcheck"]["test"][-1])
        self.assertIn("('127.0.0.1',22)", self.host["healthcheck"]["test"][-1])


class EnvExampleTests(unittest.TestCase):
    def test_demo_defaults_are_consistent_with_compose_and_packs(self):
        text, values = env_example()
        self.assertNotIn("\r", text, ".env.example 必须是 LF")
        self.assertEqual(values["COMPOSE_PROFILES"], "demo")
        self.assertEqual(values["OPS_URL"], "http://kb-ops:8799")
        self.assertTrue(values["OPS_TOKEN"])
        self.assertEqual(values["LLM_BASE_URL"], "https://api.siliconflow.cn/v1")
        self.assertEqual(values["LLM_API_KEY"], "", "key 留给用户自己填")
        self.assertEqual(values["EMBED_MODEL"], "BAAI/bge-m3")
        packs = [p.strip() for p in values["DEMO_PACKS"].split(",")]
        self.assertEqual(tuple(packs), DEMO)
        for pack_id in packs:
            self.assertTrue((REPO / "packs" / pack_id / "pack.yaml").is_file(), pack_id)

    def test_dockerfile_ships_the_packs(self):
        self.assertIn("COPY packs /srv/packs", (REPO / "Dockerfile").read_text(encoding="utf-8"))


class EntrypointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.packs = Path(self.tmp.name) / "packs"
        for pack_id in ("a", "b"):
            (self.packs / pack_id).mkdir(parents=True)
            (self.packs / pack_id / "tools.yaml").write_text(
                f"tools:\n  - {{name: t_{pack_id}, binary: free, argv: [free, -m], params: {{}}}}\n",
                encoding="utf-8")
        self.config = Path(self.tmp.name) / "ops" / "ops_tools.yaml"

    def test_gateway_root_strips_the_v1_suffix(self):
        for raw, want in [("https://api.siliconflow.cn/v1", "https://api.siliconflow.cn"),
                          ("https://api.siliconflow.cn/v1/", "https://api.siliconflow.cn"),
                          (" http://127.0.0.1:4000/v1 ", "http://127.0.0.1:4000"),
                          ("https://api.deepseek.com", "https://api.deepseek.com"),
                          ("", ""), (None, "")]:
            with self.subTest(raw=raw):
                self.assertEqual(entrypoint.gateway_root(raw), want)

    def test_include_list_reports_packs_without_tools(self):
        files, missing = entrypoint.include_list(["a", "nope", "b"], self.packs)
        self.assertEqual(files, [str(self.packs / "a" / "tools.yaml"), str(self.packs / "b" / "tools.yaml")])
        self.assertEqual(missing, ["nope"])
        self.assertEqual(entrypoint.pack_ids(" a, ,b "), ["a", "b"])

    def test_generated_config_loads_in_ops_readonly_and_keeps_approved_tools(self):
        files, _ = entrypoint.include_list(["a"], self.packs)
        entrypoint.write_config(self.config, files)
        tools, problems = ops.load_tools(self.config)
        self.assertEqual((sorted(tools), problems), (["t_a"], []))
        # 容器里批准过一个工具后重启：include 按新的 DEMO_PACKS 重算，tools 保留
        document = yaml.safe_load(self.config.read_text(encoding="utf-8"))
        document["tools"] = [{"name": "approved", "binary": "df", "argv": ["df", "-h"], "params": {}}]
        self.config.write_text(yaml.safe_dump(document, allow_unicode=True), encoding="utf-8")
        files, _ = entrypoint.include_list(["a", "b"], self.packs)
        entrypoint.write_config(self.config, files)
        tools, problems = ops.load_tools(self.config)
        self.assertEqual((sorted(tools), problems), (["approved", "t_a", "t_b"], []))

    def test_prepare_normalises_secrets_and_writes_the_config(self):
        environ = {"OPS_SECRET_GATEWAY_URL": "https://api.siliconflow.cn/v1/",
                   "OPS_SECRET_GATEWAY_KEY": " sk-demo ", "DEMO_PACKS": "a,b"}
        with patch.object(entrypoint, "CONFIG", self.config), \
                patch.object(entrypoint, "PACKS_DIR", self.packs):
            path = entrypoint.prepare(environ)
        self.assertEqual(path, self.config)
        self.assertEqual(environ["OPS_SECRET_GATEWAY_URL"], "https://api.siliconflow.cn")
        self.assertEqual(environ["OPS_SECRET_GATEWAY_KEY"], "sk-demo")
        document = yaml.safe_load(self.config.read_text(encoding="utf-8"))
        self.assertEqual(len(document["include"]), 2)

    def test_prepare_without_model_credentials_drops_the_secret_variables(self):
        environ = {"OPS_SECRET_GATEWAY_URL": "", "OPS_SECRET_GATEWAY_KEY": "", "DEMO_PACKS": ""}
        with patch.object(entrypoint, "CONFIG", self.config), \
                patch.object(entrypoint, "PACKS_DIR", self.packs):
            entrypoint.prepare(environ)
        self.assertNotIn("OPS_SECRET_GATEWAY_URL", environ)
        self.assertNotIn("OPS_SECRET_GATEWAY_KEY", environ)
        self.assertEqual(yaml.safe_load(self.config.read_text(encoding="utf-8"))["include"], [])


@unittest.skipUnless(os.name == "posix" and shutil.which("ssh-keygen"), "演示 sidecar 跑在 Linux 容器里：需要类 Unix 的 ssh-keygen")
class DemoHostTests(unittest.TestCase):
    """演示主机：sidecar 生成自己的私钥、经交换目录给出公钥，登记演示主机的 host 公钥；主机清单只开放三个工具。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.state, self.exchange = root / "ops", root / "exchange"
        self.state.mkdir()
        self.exchange.mkdir()
        self.config = self.state / "ops_tools.yaml"
        self.host_pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl demo-host\n"

    def prepare(self, environ):
        with patch.object(entrypoint, "CONFIG", self.config), patch.object(entrypoint, "STATE_DIR", self.state), \
                patch.object(entrypoint, "EXCHANGE_DIR", self.exchange), \
                patch.object(entrypoint, "PACKS_DIR", REPO / "packs"), patch.object(entrypoint, "HOST_WAIT", 0):
            return entrypoint.prepare(environ)

    def test_keys_go_through_the_exchange_and_the_host_list_is_written(self):
        (self.exchange / "host_ed25519.pub").write_text(self.host_pub, encoding="utf-8")
        environ = {"DEMO_PACKS": "leave-planning", "DEMO_HOST": "kb-host", "DEMO_HOST_PACKS": "ops-inspection"}
        self.prepare(environ)
        key = self.state / "demo_host_key"
        self.assertEqual(environ["OPS_SECRET_DEMO_HOST_KEY"], str(key))
        self.assertTrue((self.exchange / "client.pub").read_text(encoding="utf-8").startswith("ssh-ed25519 "))
        self.assertFalse((self.exchange / "demo_host_key").exists())       # 私钥不进交换目录
        self.assertEqual((self.state / "ops_tools.known_hosts").read_text(encoding="utf-8"),
                         "demo-host " + " ".join(self.host_pub.split()[:2]) + "\n")
        document = yaml.safe_load(self.config.read_text(encoding="utf-8"))
        self.assertEqual(len(document["include"]), 2)
        self.assertEqual(document["hosts"], entrypoint.host_section("kb-host"))
        with patch.dict(ops._state, {"path": self.config}), patch.object(ops, "HOST_OS", "linux"), \
                patch.object(ops.shutil, "which", lambda name: None if name == "docker" else f"/usr/bin/{name}"), \
                patch.dict(ops._host_status, {}, clear=True), patch.object(ops._monitor, "wake", lambda: None):
            ops.refresh(force=True)
            self.assertEqual(ops._state["problems"], [])
            tools = ops.available_tools()
            # 容器状态两个工具要读 docker：sidecar 里没有 docker，演示主机没开放，所以不下发
            self.assertEqual(sorted(tools), ["date_info", "holiday_calendar", "host_disk", "host_resources",
                                             "host_uptime"])
            target = tools["host_disk"]["inputSchema"]["properties"]["target"]
            self.assertEqual((target["enum"], target["x-default"]), (["local", "demo-host", "@demo", "@all"], "local"))
            self.assertNotIn("target", tools["date_info"]["inputSchema"]["properties"])

    def test_restarts_reuse_the_key_and_a_missing_host_key_is_not_fatal(self):
        environ = {"DEMO_PACKS": "", "DEMO_HOST": "kb-host", "DEMO_HOST_PACKS": "ops-inspection"}
        self.prepare(environ)
        first = (self.state / "demo_host_key.pub").read_text(encoding="utf-8")
        self.assertFalse((self.state / "ops_tools.known_hosts").exists())
        self.assertIsNotNone(yaml.safe_load(self.config.read_text(encoding="utf-8")).get("hosts"))
        self.prepare({"DEMO_PACKS": "", "DEMO_HOST": "kb-host", "DEMO_HOST_PACKS": "ops-inspection"})
        self.assertEqual((self.state / "demo_host_key.pub").read_text(encoding="utf-8"), first)
        # DEMO_HOST_PACKS 写成空的：不演示多机巡检，主机清单从配置里拿掉
        self.prepare({"DEMO_PACKS": "", "DEMO_HOST": "kb-host", "DEMO_HOST_PACKS": ""})
        self.assertNotIn("hosts", yaml.safe_load(self.config.read_text(encoding="utf-8")))


class DemoHostFilesTests(unittest.TestCase):
    """演示主机镜像里的文件：白名单和工具服务生成的一致，入口脚本只放强制命令的公钥。Windows 上也能跑。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = Path(self.tmp.name) / "ops_tools.yaml"

    def test_the_static_allowlist_matches_what_push_would_generate(self):
        """演示主机镜像里的白名单是 push --print 生成的：包里的工具定义一改，这里就要重新生成。"""
        shipped = json.loads((REPO / "deploy" / "demo" / "host-allowlist.json").read_text(encoding="utf-8"))
        self.config.write_text(yaml.safe_dump({"include": [str(REPO / "packs" / "ops-inspection" / "tools.yaml")],
                                               "hosts": entrypoint.host_section("kb-host"), "tools": []}),
                               encoding="utf-8")
        with patch.dict(ops._state, {"path": self.config}), patch.object(ops._monitor, "wake", lambda: None):
            ops.refresh(force=True)
            generated = json.loads(ops.allowlist_for(ops._state["hosts"]["hosts"][entrypoint.HOST_NAME]))
        self.assertEqual(shipped["tools"], generated["tools"])
        self.assertEqual([tool["name"] for tool in shipped["tools"]], entrypoint.HOST_TOOLS)
        tools, info, problems = ops.ops_exec.parse_allowlist(shipped)
        self.assertEqual((sorted(tools), problems, info["host"]), (entrypoint.HOST_TOOLS, [], "demo-host"))

    def test_the_host_entrypoint_installs_a_forced_command_key(self):
        script = (REPO / "deploy" / "demo" / "host-entrypoint.sh").read_text(encoding="utf-8")
        self.assertNotIn("\r", script)
        self.assertIn('restrict,command="/usr/local/bin/python3 /opt/ops-readonly/ops_exec.py --stdio"', script)
        self.assertIn("exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_demo.conf", script)
        sshd = (REPO / "deploy" / "demo" / "host-sshd.conf").read_text(encoding="utf-8")
        for line in ("AllowUsers opsread", "PasswordAuthentication no", "PermitRootLogin no", "PermitTTY no",
                     "AllowTcpForwarding no", "AuthorizedKeysFile /etc/ssh/authorized_keys/%u"):
            self.assertIn(line, sshd)
        if shutil.which("sh") and os.name == "posix":
            done = subprocess.run(["sh", "-n", str(REPO / "deploy" / "demo" / "host-entrypoint.sh")],
                                  stderr=subprocess.PIPE)
            self.assertEqual(done.returncode, 0, done.stderr)

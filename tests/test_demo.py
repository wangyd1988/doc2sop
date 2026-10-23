"""一键演示的静态校验：compose 文件、.env.example、sidecar 入口脚本。

本机没有 Docker 也能跑：只解析文件、不起容器。真机验证见 docs/五分钟演示.md。
"""
import importlib.util
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

    def test_sidecar_only_runs_under_the_demo_profile(self):
        self.assertEqual(self.ops["profiles"], ["demo"])
        self.assertNotIn("profiles", self.app)
        # profile 外的服务不能 depends_on profile 内的服务，否则不带 --profile 的 up 会报错
        self.assertNotIn("depends_on", self.app)

    def test_sidecar_is_not_published_and_is_small(self):
        self.assertNotIn("ports", self.ops)
        self.assertEqual(self.ops["mem_limit"], "128m")
        self.assertEqual(self.app["mem_limit"], "900m")
        self.assertEqual(self.ops["build"], {"context": "deploy", "dockerfile": "demo/Dockerfile.ops"})

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

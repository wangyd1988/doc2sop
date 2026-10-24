"""正式部署脚本 deploy/release.sh 与两段式 Dockerfile 的静态校验。

本机没有 Docker 也能跑：只检查文件形状；有 bash（Linux / macOS / Git for Windows）时再做语法检查，
并用 --print-config、--parse-chunks 这两个不碰 docker 的入口验证参数解析和片段计数。真机流程见 docs/正式部署.md。
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "deploy" / "release.sh"
DOCKERFILE = (REPO / "Dockerfile").read_text(encoding="utf-8")
RELEASE_DOCKERFILE = (REPO / "deploy" / "Dockerfile.release").read_text(encoding="utf-8")
SCRIPT_TEXT = SCRIPT.read_text(encoding="utf-8")


def find_bash():
    found = shutil.which("bash")
    if found and "System32" not in found:      # WSL 的垫片不是我们要的
        return found
    for candidate in (r"C:\Program Files\Git\bin\bash.exe", r"F:\Program Files\Git\bin\bash.exe",
                      os.path.expandvars(r"%LOCALAPPDATA%\Programs\Git\bin\bash.exe")):
        if Path(candidate).is_file():
            return candidate
    return None


BASH = find_bash()


def posix(path):
    """Git Bash 认得 C:/x/y 这种写法，反斜杠不行。"""
    return str(path).replace("\\", "/")


def run(*args, env=None, stdin=None):
    merged = {k: v for k, v in os.environ.items()
              if not k.startswith(("APP_", "ENV_FILE", "DATA_DIR", "BASE_IMAGE", "PIP_INDEX_URL", "KEEP_IMAGES"))}
    merged.update(env or {})
    return subprocess.run([BASH, posix(SCRIPT), *args], capture_output=True, text=True, encoding="utf-8",
                          env=merged, input=stdin, cwd=str(REPO))


def stages(text):
    """Dockerfile 按 FROM 切成 {阶段名: 指令行}。"""
    out, current = {}, None
    for line in text.splitlines():
        found = re.match(r"^FROM\s+(\S+)(?:\s+AS\s+(\S+))?\s*$", line, re.IGNORECASE)
        if found:
            current = found.group(2) or found.group(1)
            out[current] = []
        elif current and line.strip() and not line.lstrip().startswith("#"):
            out[current].append(line.strip())
    return out


class DockerfileTests(unittest.TestCase):
    def test_base_stage_installs_dependencies_and_app_stage_only_copies_code(self):
        """base 只装依赖、app 只拷代码：发版脚本单独打 base，之后每次只 COPY，不再等 pip。"""
        parts = stages(DOCKERFILE)
        self.assertEqual(list(parts), ["base", "app"], "app 必须是最后一个阶段：compose 不指定 target 时构建的就是它")
        base, app = parts["base"], parts["app"]
        self.assertTrue(any(line.startswith("RUN pip install") and "requirements.txt" in line for line in base))
        self.assertTrue(any(line.startswith("CMD ") for line in base), "CMD 放在 base 里，release 镜像直接继承")
        self.assertTrue(any(line.startswith("ARG PIP_INDEX_URL") for line in base))
        self.assertEqual(app, ["COPY app /srv/app", "COPY packs /srv/packs"])
        # BASE_IMAGE 仍然是第一条指令，compose / release.sh 都靠它换国内镜像站
        first = next(line for line in DOCKERFILE.splitlines() if line.strip() and not line.startswith("#"))
        self.assertEqual(first, "ARG BASE_IMAGE=python:3.12-slim")
        self.assertIn("FROM ${BASE_IMAGE} AS base", DOCKERFILE)

    def test_release_dockerfile_only_copies_code_onto_the_base_image(self):
        parts = stages(RELEASE_DOCKERFILE)
        self.assertEqual(list(parts), ["${RUNTIME_IMAGE}"])
        self.assertEqual(parts["${RUNTIME_IMAGE}"], ["COPY app /srv/app", "COPY packs /srv/packs"])
        self.assertIn("ARG RUNTIME_IMAGE=", RELEASE_DOCKERFILE)
        self.assertNotIn("pip", RELEASE_DOCKERFILE)

    def test_compose_passes_the_pip_index_through(self):
        compose = (REPO / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertEqual(compose.count("PIP_INDEX_URL: ${PIP_INDEX_URL:-}"), 2)
        self.assertIn("ARG PIP_INDEX_URL", (REPO / "deploy" / "demo" / "Dockerfile.ops").read_text(encoding="utf-8"))
        self.assertIn("# PIP_INDEX_URL=", (REPO / ".env.example").read_text(encoding="utf-8"))


class ReleaseScriptStaticTests(unittest.TestCase):
    def test_script_is_strict_and_never_prints_secrets(self):
        self.assertTrue(SCRIPT_TEXT.startswith("#!/bin/bash\n"))
        self.assertNotIn("\r", SCRIPT_TEXT, "脚本必须是 LF，CRLF 在 Linux 上第一行就挂")
        self.assertNotIn("\r", RELEASE_DOCKERFILE)
        self.assertIn("set -euo pipefail", SCRIPT_TEXT)
        for secret in ("WEB_PASSWORD", "LLM_API_KEY", "OPS_TOKEN", "EMBED_API_KEY"):
            for line in SCRIPT_TEXT.splitlines():
                if re.search(rf"\b(echo|log|printf)\b.*\${secret}", line) and not re.search(r"\| *(curl|base64)", line):
                    self.fail(f"疑似把 {secret} 打印出来了：{line.strip()}")
        # 凭据 base64 后经 curl 的 stdin 配置传入，不进命令行
        self.assertIn("curl -s -K -", SCRIPT_TEXT)
        self.assertIn("Authorization: Basic %s", SCRIPT_TEXT)
        self.assertNotIn("-u \"$WEB_USER", SCRIPT_TEXT)
        self.assertNotIn(". \"$ENV_FILE\"", SCRIPT_TEXT, "不能 source 环境文件")

    def test_switch_flow_has_rollback_and_chunk_comparison(self):
        for needle in ("docker stop -t 60", "docker rename", "--network host", "--env-file", "--restart unless-stopped",
                       "rollback \"片段总数不一致", "rollback \"新容器启动失败", "docker rm -f \"$PREV_CONTAINER\"",
                       "--target base", "Dockerfile.release", "KEEP_IMAGES"):
            self.assertIn(needle, SCRIPT_TEXT, needle)

    def test_docs_point_at_the_script(self):
        readme = (REPO / "README.md").read_text(encoding="utf-8")
        self.assertIn("docs/正式部署.md", readme)
        self.assertLessEqual(len([l for l in readme.splitlines() if l.strip()]), 103, "README 只改不增")
        guide = (REPO / "docs" / "正式部署.md").read_text(encoding="utf-8")
        for needle in ("deploy/release.sh", "git pull", "--image", "backup.sh", "ops_readonly", "container-guard",
                       "APP_CONTAINER", "--network host"):
            self.assertIn(needle, guide, needle)
        self.assertIn("release.sh", (REPO / "docs" / "architecture.md").read_text(encoding="utf-8"))


@unittest.skipUnless(BASH, "没有 bash")
class ReleaseScriptBashTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env_file = Path(self.tmp.name) / "prod.env"
        self.env_file.write_text("# 注释\nWEB_USER=admin\nWEB_PASSWORD=s3cret-\"quoted\"\nPORT=9000\n"
                                 "LLM_API_KEY=sk-top-secret\nAPP_MEM_LIMIT=700m\nAPP_IMAGE=demo-app:latest\n",
                                 encoding="utf-8")

    def test_syntax(self):
        done = subprocess.run([BASH, "-n", posix(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_help_exits_zero(self):
        done = run("--help")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("ENV_FILE", done.stdout)
        self.assertEqual(run("--bogus").returncode, 2)

    def test_parse_chunks_sums_the_documents(self):
        done = run("--parse-chunks", stdin='{"documents": [{"chunks": 3}, {"chunks": 4}, {"name": "x"}]}')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.strip(), "7")
        self.assertNotEqual(run("--parse-chunks", stdin="not json").returncode, 0)

    def test_print_config_resolves_precedence_without_leaking_secrets(self):
        """环境变量 > 环境文件 > 默认；探活端口跟环境文件的 PORT 走；密钥一个字都不出现。"""
        done = run("--print-config", env={"ENV_FILE": posix(self.env_file), "APP_CONTAINER": "demo-app"})
        self.assertEqual(done.returncode, 0, done.stderr)
        got = dict(line.split("=", 1) for line in done.stdout.splitlines() if "=" in line)
        self.assertEqual(got["APP_CONTAINER"], "demo-app")           # 环境变量
        self.assertEqual(got["APP_MEM_LIMIT"], "700m")               # 环境文件
        self.assertEqual(got["APP_IMAGE"], "demo-app:latest")
        self.assertEqual(got["REPO_NAME"], "demo-app")
        self.assertEqual(got["APP_PORT"], "9000")                    # 环境文件的 PORT
        self.assertEqual(got["APP_CPUS"], "1.5")                     # 默认
        self.assertEqual(got["KEEP_IMAGES"], "2")
        self.assertTrue(got["DATA_DIR"].endswith("/data"))
        self.assertRegex(got["BASE_TAG"], r"^demo-app:base-[0-9a-f]{12}$")
        for secret in ("s3cret", "sk-top-secret", "WEB_PASSWORD", "LLM_API_KEY"):
            self.assertNotIn(secret, done.stdout)
        # 显式 APP_PORT 盖过环境文件的 PORT；--image 原样带出
        done = run("--print-config", "--image", "demo-app:20261024195031",
                   env={"ENV_FILE": posix(self.env_file), "APP_PORT": "8766"})
        got = dict(line.split("=", 1) for line in done.stdout.splitlines() if "=" in line)
        self.assertEqual(got["APP_PORT"], "8766")
        self.assertEqual(got["IMAGE"], "demo-app:20261024195031")

    def test_base_tag_changes_with_requirements_pip_index_and_base_image(self):
        base = dict(line.split("=", 1) for line in run("--print-config").stdout.splitlines() if "=" in line)["BASE_TAG"]
        mirror = dict(line.split("=", 1) for line in run(
            "--print-config", env={"PIP_INDEX_URL": "https://pypi.tuna.tsinghua.edu.cn/simple"}).stdout.splitlines()
            if "=" in line)["BASE_TAG"]
        other_base = dict(line.split("=", 1) for line in run(
            "--print-config", env={"BASE_IMAGE": "docker.m.daocloud.io/library/python:3.12-slim"}).stdout.splitlines()
            if "=" in line)["BASE_TAG"]
        self.assertEqual(len({base, mirror, other_base}), 3, "pip 源或基础镜像变了也要重建 base")
        # 同样的输入永远算出同一个 tag：机器重启、换目录都能命中已有的 base 镜像
        self.assertEqual(base, dict(line.split("=", 1) for line in run("--print-config").stdout.splitlines()
                                    if "=" in line)["BASE_TAG"])

    def test_missing_env_file_is_a_clear_error_before_touching_docker(self):
        done = run(env={"ENV_FILE": posix(Path(self.tmp.name) / "nope.env"), "PATH": os.environ["PATH"]})
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
        self.assertTrue("环境文件不存在" in done.stderr or "缺少命令" in done.stderr, done.stderr)

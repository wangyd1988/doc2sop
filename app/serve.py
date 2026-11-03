"""启动应用：镜像的 CMD 是 `python -m app.serve`（老镜像是 `uvicorn app.main:app --host 0.0.0.0 --port $PORT --workers 1`）。

什么都不配时和老命令一样：单进程，0.0.0.0:PORT 上的明文 HTTP。唯一的不同是关掉了 uvicorn 自己的转发头处理
（proxy_headers）：来源地址统一由 app/peer.py 算，可信代理写在 TRUSTED_PROXIES 里。

    TLS_CERT_FILE / TLS_KEY_FILE   两个都填：PORT 说 HTTPS（容器里的路径，正式部署挂在 /tls，见 docs/正式部署.md）。
                                   证书文件可以带中间证书链。私钥对 group / other 可读、证书和私钥不配对、读不了 → 拒绝启动；
                                   证书过期、还没生效、快到期只告警（不能让经隧道的人也一起断）。换证书要重启。
    LISTEN_HOST                    PORT 监听哪个地址：0.0.0.0（默认）或 127.0.0.1（只给本机的反向代理用）。
    LOCAL_HTTP_PORT                开了 TLS 时，另在 127.0.0.1 上留一个明文端口（给 SSH 隧道、本机探活和脚本用）。
                                   明文端口只能在回环地址上，这一点不能配。
    FORWARDED_ALLOW_IPS            不再起作用；有值时拒绝启动，提示改用 TRUSTED_PROXIES。

    python -m app.serve --check    只检查上面这些（release.sh 在停旧容器之前跑），有问题时退出码 2
    python -m app.serve --probe    在本机连一次自己（compose 的健康检查）：回了任何 HTTP 状态就算活着
"""
import asyncio
import contextlib
import http.client
import os
import ssl
import stat
import sys
import time

APP = "app.main:app"
LISTEN_HOSTS = ("0.0.0.0", "127.0.0.1")
CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20"        # TLS 1.2 的套件；TLS 1.3 的不受它影响
WARN_DAYS = 30
FORWARDED_TEXT = ("设了 FORWARDED_ALLOW_IPS：应用不再用 uvicorn 的转发头处理，这一项不起作用了。前面有反向代理就改成 "
                  "TRUSTED_PROXIES=代理的地址（不能写 *），再删掉 FORWARDED_ALLOW_IPS；没有反向代理就直接删掉它")


def _port(text, name):
    try:
        value = int(str(text).strip())
    except ValueError:
        return None, f"{name} 要是端口号（1-65535），现在是 {str(text)[:40]!r}"
    if not 1 <= value <= 65535:
        return None, f"{name} 要是端口号（1-65535），现在是 {value}"
    return value, ""


def settings(environ=None) -> dict:
    """读环境变量：{port, host, cert, key, local_port, problems}。problems 非空就不能启动。"""
    environ = os.environ if environ is None else environ
    problems = []
    port, problem = _port(environ.get("PORT", "8765") or "8765", "PORT")
    problems += [problem] if problem else []
    host = str(environ.get("LISTEN_HOST", "") or "0.0.0.0").strip()
    if host not in LISTEN_HOSTS:
        problems.append(f"LISTEN_HOST 只能是 0.0.0.0 或 127.0.0.1，现在是 {host[:60]!r}")
    cert = str(environ.get("TLS_CERT_FILE", "") or "").strip()
    key = str(environ.get("TLS_KEY_FILE", "") or "").strip()
    if bool(cert) != bool(key):
        problems.append("TLS_CERT_FILE 和 TLS_KEY_FILE 要一起填（证书和私钥），只填了一个")
    local_port = None
    if str(environ.get("LOCAL_HTTP_PORT", "") or "").strip():
        local_port, problem = _port(environ["LOCAL_HTTP_PORT"], "LOCAL_HTTP_PORT")
        if problem:
            problems.append(problem)
        elif not (cert and key):
            problems.append("LOCAL_HTTP_PORT 只在开了 TLS 时用（没开 TLS 时 PORT 本身就是明文）：删掉它，或者配上 TLS_CERT_FILE、TLS_KEY_FILE")
        elif local_port == port:
            problems.append("LOCAL_HTTP_PORT 不能和 PORT 相同")
    if str(environ.get("FORWARDED_ALLOW_IPS", "") or "").strip():
        problems.append(FORWARDED_TEXT)
    return {"port": port, "host": host, "cert": cert, "key": key, "local_port": local_port, "problems": problems}


# --- 证书 -------------------------------------------------------------------------------------

def decode_cert(path) -> dict:
    """证书文件里第一张证书（服务器证书）：{not_after, not_before（时间戳）, names}。认不出时抛 ValueError。"""
    try:
        info = ssl._ssl._test_decode_cert(str(path))       # 标准库自带、不另装依赖；只读文件里的第一张
    except (ssl.SSLError, OSError, AttributeError) as exc:
        raise ValueError(f"读不出证书：{exc.__class__.__name__}") from None
    names = [value for kind, value in info.get("subjectAltName", ()) if kind in ("DNS", "IP Address")]
    if not names:
        names = [value for rdn in info.get("subject", ()) for key, value in rdn if key == "commonName"]
    return {"not_after": ssl.cert_time_to_seconds(info["notAfter"]),
            "not_before": ssl.cert_time_to_seconds(info["notBefore"]), "names": names}


def check_tls(cert, key, now=None) -> tuple:
    """(problems, warnings, info)。problems 非空就不能启动。"""
    problems, warnings, info = [], [], {}
    for name, path in (("TLS_CERT_FILE", cert), ("TLS_KEY_FILE", key)):
        if not os.path.isfile(path):
            problems.append(f"{name}={path} 不存在或不是文件（容器里的路径；正式部署要把证书目录挂到容器里，见 docs/正式部署.md）")
        elif not os.access(path, os.R_OK):
            problems.append(f"{name}={path} 读不了（权限）")
    if problems:
        return problems, warnings, info
    if os.name == "posix":
        mode = os.stat(key).st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            problems.append(f"私钥 {key} 的权限是 {stat.filemode(mode)}，别的账号也能读：在宿主机上 chmod 600（属主 root）")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(cert, key)
    except ssl.SSLError as exc:
        problems.append(f"证书和私钥用不了（不配对、格式不对或私钥有口令）：{exc.reason or exc.__class__.__name__}")
    except OSError as exc:
        problems.append(f"证书或私钥读不了：{exc.__class__.__name__}")
    try:
        info = decode_cert(cert)
    except ValueError as exc:
        problems.append(f"{cert}：{exc}")
        return problems, warnings, info
    warning = expiry_warning(info, now)
    if warning:
        warnings.append(warning)
    return problems, warnings, info


def expiry_warning(info, now=None) -> str:
    now = time.time() if now is None else now
    days = int((info["not_after"] - now) // 86400)
    if info["not_after"] <= now:
        return f"服务器证书已经过期（{_date(info['not_after'])}）：客户端会拒绝连接，请换证书后重启"
    if info["not_before"] > now:
        return f"服务器证书还没生效（从 {_date(info['not_before'])} 起）：先核对服务器时间"
    if days < WARN_DAYS:
        return f"服务器证书 {days} 天后过期（{_date(info['not_after'])}）：请尽快换证书，换完重启"
    return ""


def _date(seconds) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(seconds))


_status_cache = {}


def tls_status(environ=None, now=None) -> dict:
    """页面用：这个进程是不是自己说 HTTPS（内置 TLS）、服务器证书到哪天、给哪些名字签的、还剩几天。"""
    config = settings(environ)
    base = {"port": config["port"], "listen_host": config["host"], "local_port": config["local_port"]}
    if not (config["cert"] and config["key"]):
        return {"builtin": False, **base}
    out = {"builtin": True, **base}
    try:
        stamp = os.stat(config["cert"]).st_mtime
        cached = _status_cache.get(config["cert"])
        if not cached or cached[0] != stamp:
            cached = (stamp, decode_cert(config["cert"]))
            _status_cache[config["cert"]] = cached
        info = cached[1]
    except (OSError, ValueError) as exc:
        return {**out, "problem": f"读不出服务器证书：{exc.__class__.__name__}"}
    now = time.time() if now is None else now
    return {**out, "not_after": _date(info["not_after"]), "days_left": int((info["not_after"] - now) // 86400),
            "names": info["names"][:20], "warning": expiry_warning(info, now)}


def problems_and_warnings(environ=None) -> tuple:
    """启动前的全部检查：(settings, problems, warnings, info)。"""
    config = settings(environ)
    problems, warnings, info = list(config["problems"]), [], {}
    try:
        from app import peer       # 导入时解析 TRUSTED_PROXIES，写错了抛 ValueError
        del peer
    except ValueError as exc:
        problems.append(str(exc))
    if config["cert"] and config["key"]:
        more, warnings, info = check_tls(config["cert"], config["key"])
        problems += more
    return config, problems, warnings, info


def describe(config) -> list:
    scheme = "https" if config["cert"] else "http"
    out = [f"{scheme}://{config['host']}:{config['port']}"]
    if config["local_port"]:
        out.append(f"http://127.0.0.1:{config['local_port']}（只给本机）")
    return out


# --- 启动 -------------------------------------------------------------------------------------

def _uvicorn_config(config, port=None, host=None, tls=True, lifespan="auto"):
    import uvicorn
    kwargs = {"host": host or config["host"], "port": port or config["port"], "workers": 1, "proxy_headers": False,
              "lifespan": lifespan}
    if tls and config["cert"]:
        kwargs.update(ssl_certfile=config["cert"], ssl_keyfile=config["key"], ssl_ciphers=CIPHERS)
    server_config = uvicorn.Config(APP, **kwargs)
    server_config.load()
    if server_config.ssl is not None:
        server_config.ssl.minimum_version = ssl.TLSVersion.TLSv1_2
    return server_config


def _servers(config):
    """主服务（PORT，跑 lifespan、收信号）和可选的本机明文服务（LOCAL_HTTP_PORT，不跑 lifespan、不另装信号处理）。"""
    import uvicorn

    class Quiet(uvicorn.Server):
        """跟着主服务停：自己不装信号处理（两个都装会互相覆盖，docker stop 时只停一半）。"""

        @contextlib.contextmanager
        def capture_signals(self):
            yield

        def install_signal_handlers(self):     # 老版本 uvicorn 用这个名字
            pass

    class Main(uvicorn.Server):
        others = []

        def handle_exit(self, sig, frame):
            super().handle_exit(sig, frame)
            for other in self.others:
                other.should_exit, other.force_exit = self.should_exit, self.force_exit

    main = Main(_uvicorn_config(config))
    if not config["local_port"]:
        return main, None
    local = Quiet(_uvicorn_config(config, port=config["local_port"], host="127.0.0.1", tls=False, lifespan="off"))
    main.others = [local]
    return main, local


async def _serve_both(main, local):
    """先起主服务，等它的 lifespan 跑完（定时线程、/mcp 都就绪）再开本机明文端口；任何一个停了，另一个也停。"""
    first = asyncio.ensure_future(main.serve())
    while not main.started and not first.done():
        await asyncio.sleep(0.05)
    if first.done():
        return await first
    second = asyncio.ensure_future(local.serve())
    await asyncio.wait({first, second}, return_when=asyncio.FIRST_COMPLETED)
    main.should_exit = local.should_exit = True
    await asyncio.gather(first, second)


def run(environ=None) -> int:
    config, problems, warnings, _ = problems_and_warnings(environ)
    for warning in warnings:
        print(f"serve: 警告：{warning}", file=sys.stderr, flush=True)
    if problems:
        for problem in problems:
            print(f"serve: 不能启动：{problem}", file=sys.stderr, flush=True)
        return 2
    main, local = _servers(config)
    if local is None:
        main.run()
    else:
        asyncio.run(_serve_both(main, local))
    return 0 if main.started else 3        # 和 uvicorn 命令行一样：没起来就非 0 退出


# --- 检查与探活 -------------------------------------------------------------------------------

def check(environ=None) -> int:
    config, problems, warnings, info = problems_and_warnings(environ)
    print("serve: 将监听 " + "、".join(describe(config)) if config["port"] else "serve: 端口配置不对")
    if info:
        print(f"serve: 服务器证书给 {'、'.join(info['names'][:10]) or '（没有名字）'} 签发，到 {_date(info['not_after'])}")
    for warning in warnings:
        print(f"serve: 警告：{warning}")
    for problem in problems:
        print(f"serve: 不能启动：{problem}")
    return 2 if problems else 0


def probe(environ=None, timeout=5) -> int:
    """连本机的自己一次：有本机明文端口就连它；否则按 PORT 的协议连（HTTPS 不校验证书：只连回环，没有中间人可防）。"""
    config = settings(environ)
    if config["local_port"]:
        connection = http.client.HTTPConnection("127.0.0.1", config["local_port"], timeout=timeout)
    elif config["cert"]:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        connection = http.client.HTTPSConnection("127.0.0.1", config["port"], timeout=timeout, context=context)
    else:
        connection = http.client.HTTPConnection("127.0.0.1", config["port"], timeout=timeout)
    try:
        connection.request("GET", "/")
        status = connection.getresponse().status
    except OSError as exc:
        print(f"serve: 连不上自己：{exc.__class__.__name__}", file=sys.stderr)
        return 1
    finally:
        connection.close()
    return 0 if 100 <= status < 600 else 1


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--check"]:
        return check()
    if argv == ["--probe"]:
        return probe()
    if argv:
        print("用法：python -m app.serve [--check | --probe]", file=sys.stderr)
        return 2
    return run()


if __name__ == "__main__":
    sys.exit(main())

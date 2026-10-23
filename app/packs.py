"""场景包：文档 + 工具定义 + SOP，是「小知」可复用、可贡献的最小单元。

一个包就是一个目录（格式见 docs/场景包.md）：

    packs/<id>/
    ├── pack.yaml    名称、一句话说明、适用岗位、前提、入库分类、示例问题
    ├── docs/        要入库的文档
    ├── tools.yaml   与 deploy/ops_tools.yaml 同格式的工具定义子集
    └── sops.json    预先整理好的 SOP，不用再现场抽取

应用对三样东西的态度不一样：
  - 文档：导入时走和上传完全相同的 ingest()。
  - 工具：**只读、不执行、不上传**。工具由管理员在宿主机（或演示 sidecar）用 include 启用；
    这里只拿它的名字做校验，一个包需要的工具没在线，就一直等，状态里写明缺哪些。
  - SOP：必经 playbooks.save() → validate()，步骤只能引用此刻真实可用的工具。所以导入一个包
    不会凭空多出任何执行权限，这条线和「从文档抽取」「从实践沉淀」是同一条。

自动导入：DEMO_PACKS 列出的包，在模型配好、工具在线后由后台线程导入一次。data/packs.json 记录
导入过的包和版本，重启不重导；包升级了也不自动重导（会重置人改过的启停），接口 force 才重导。
"""
import hashlib
import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

from fastapi import HTTPException

from app import config, playbooks, settings
from app.config import ALLOWED_SUFFIXES, DATA_DIR, log, why

STATE_PATH = DATA_DIR / "packs.json"
PACK_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
TOOL_NAME = re.compile(r"^[a-z][a-z0-9_]{0,40}$")
EXAMPLES_MAX = 6

_lock = threading.Lock()          # 状态文件读写 + 一次只导一个包
_wake = threading.Event()
_thread = None
# 正在导入哪个包、到哪一步了，给欢迎页的引导卡看；最近一次没导成的原因，给 /api/packs 看
_progress = {"importing": "", "stage": ""}
_notes: dict = {}
_failed: set = set()


class PackWaiting(RuntimeError):
    """条件还没就绪（模型没配、工具没上线、向量服务暂时不通）：稍后重试，不算失败。"""


class PackError(ValueError):
    """包内容本身不合法，重试也没用；附带能直接展示的原因。"""


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _yaml(path):
    import yaml
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(document, dict):
        raise PackError(f"{path.name} 的顶层必须是映射")
    return document


def _strings(value):
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [str(value).strip()] if value not in (None, "") else []


def _read_pack(folder: Path) -> dict:
    """解析一个包目录。格式问题收进 problems 而不是抛出：列表页要能把坏包连同原因一起显示。"""
    pack = {"id": folder.name, "dir": str(folder), "name": folder.name, "version": 1, "summary": "",
            "roles": [], "requires": [], "category": "", "examples": [], "docs": [], "tools": [],
            "sops": [], "problems": []}
    problems = pack["problems"]
    if not PACK_ID.match(folder.name):
        problems.append("目录名只能用小写字母、数字和连字符")

    meta_path = folder / "pack.yaml"
    if not meta_path.is_file():
        problems.append("缺少 pack.yaml")
    else:
        try:
            meta = _yaml(meta_path)
        except Exception as exc:
            meta = {}
            problems.append(f"pack.yaml 读取失败：{why(exc)}")
        if meta.get("id") and str(meta["id"]) != folder.name:
            problems.append(f"pack.yaml 里的 id「{meta['id']}」和目录名不一致")
        pack["name"] = str(meta.get("name") or folder.name).strip()[:60]
        try:
            pack["version"] = int(meta.get("version", 1))
        except (TypeError, ValueError):
            problems.append("version 必须是整数")
        pack["summary"] = str(meta.get("summary") or "").strip()[:300]
        pack["roles"] = _strings(meta.get("roles"))
        pack["requires"] = _strings(meta.get("requires"))
        pack["category"] = str(meta.get("category") or "").strip()[:config.CATEGORY_MAX]
        pack["examples"] = _strings(meta.get("examples"))[:EXAMPLES_MAX]
        if not pack["summary"]:
            problems.append("pack.yaml 缺少 summary（一句话说明）")

    docs_dir = folder / "docs"
    docs = sorted(p for p in docs_dir.iterdir() if p.is_file() and not p.name.startswith(".")) \
        if docs_dir.is_dir() else []
    for path in docs:
        if path.suffix.lower() not in ALLOWED_SUFFIXES:
            problems.append(f"docs/{path.name} 不是支持的文档格式")
    pack["docs"] = [p.name for p in docs]
    if not docs:
        problems.append("docs/ 里没有文档")

    tools_path = folder / "tools.yaml"
    if tools_path.is_file():
        try:
            entries = _yaml(tools_path).get("tools")
            if not isinstance(entries, list):
                raise PackError("tools.yaml 缺少 tools 列表")
            for entry in entries:
                name = str((entry or {}).get("name", "")).strip() if isinstance(entry, dict) else ""
                if not TOOL_NAME.match(name):
                    problems.append(f"tools.yaml 里有工具名不合法：{name[:40]!r}")
                    continue
                if entry.get("script"):
                    # 脚本要宿主机 root 放进 scripts/ 并 trust，不是一个目录能自带的东西
                    problems.append(f"tools.yaml 里的 {name} 是脚本型工具，场景包不支持")
                    continue
                pack["tools"].append(name)
        except Exception as exc:
            problems.append(f"tools.yaml 读取失败：{why(exc)}")

    sops_path = folder / "sops.json"
    if sops_path.is_file():
        try:
            items = json.loads(sops_path.read_text(encoding="utf-8"))
            if not isinstance(items, list):
                raise PackError("sops.json 的顶层必须是数组")
            for index, item in enumerate(items, 1):
                sop = _read_sop(item, index, pack)
                if sop:
                    pack["sops"].append(sop)
        except Exception as exc:
            problems.append(f"sops.json 读取失败：{why(exc)}")
    return pack


def _read_sop(item, index, pack):
    problems = pack["problems"]
    if not isinstance(item, dict):
        problems.append(f"sops.json 第 {index} 条不是对象")
        return None
    name = str(item.get("name") or "").strip()[:playbooks.NAME_MAX]
    steps = item.get("steps")
    if not name or not isinstance(steps, list) or not steps:
        problems.append(f"sops.json 第 {index} 条缺少 name 或 steps")
        return None
    clean = []
    for position, step in enumerate(steps, 1):
        tool = str((step or {}).get("tool") or "").strip() if isinstance(step, dict) else ""
        if tool not in pack["tools"]:
            # 包必须自洽：SOP 只能用本包 tools.yaml 里的工具，别人装了这个包才跑得起来
            problems.append(f"SOP《{name}》第 {position} 步引用了本包 tools.yaml 里没有的工具「{tool}」")
            continue
        clean.append({"tool": tool, "args": step.get("args") or {},
                      "checkpoint": str(step.get("checkpoint") or ""),
                      "evidence": str(step.get("evidence") or "")})
    return {"name": name, "trigger": str(item.get("trigger") or "").strip()[:playbooks.TRIGGER_MAX],
            "source": str(item.get("source") or (pack["docs"][0] if pack["docs"] else pack["name"])).strip(),
            "enabled": bool(item.get("enabled", True)), "steps": clean}


def discover(root=None) -> dict:
    """目录下的所有包，id -> 解析结果（含 problems）。目录不存在就是没有包。"""
    root = Path(root or config.PACKS_DIR)
    if not root.is_dir():
        return {}
    return {folder.name: _read_pack(folder)
            for folder in sorted(p for p in root.iterdir() if p.is_dir() and not p.name.startswith("."))}


def _state() -> dict:
    try:
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except ValueError:
        log.warning("packs.json unreadable, treating every pack as not imported")
        return {}


def _save_state(state: dict):
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, STATE_PATH)


def imported(pack_id) -> dict | None:
    return _state().get(pack_id)


def stable_id(pack_id, sop_name) -> str:
    """同一个包里同名 SOP 永远是同一个 id：重导是覆盖，不是再长一份。"""
    return hashlib.sha1(f"pack:{pack_id}:{sop_name}".encode("utf-8")).hexdigest()[:32]


def status(known_tools=None) -> list:
    """给管理接口：每个包的元信息、导入记录、还缺什么。known_tools 为 None 表示不判断工具。"""
    state = _state()
    out = []
    for pack_id, pack in discover().items():
        record = state.get(pack_id)
        missing = sorted(t for t in pack["tools"] if t not in known_tools) if known_tools is not None else []
        if pack["problems"]:
            phase = "invalid"
        elif record:
            phase = "imported" if record.get("version") == pack["version"] else "outdated"
        elif pack_id in _failed:
            phase = "failed"
        else:
            phase = "pending"
        out.append({"id": pack_id, "name": pack["name"], "version": pack["version"],
                    "summary": pack["summary"], "roles": pack["roles"], "requires": pack["requires"],
                    "category": pack["category"], "examples": pack["examples"], "docs": pack["docs"],
                    "tools": pack["tools"],
                    "sops": [{"name": s["name"], "enabled": s["enabled"], "steps": len(s["steps"])}
                             for s in pack["sops"]],
                    "problems": pack["problems"], "imported": record, "missing_tools": missing,
                    "auto": pack_id in config.DEMO_PACKS, "phase": phase,
                    "note": _notes.get(pack_id, "")})
    return out


def overview(known_tools=None) -> dict:
    """管理接口一次要的全部：包列表、目录、自动导入名单与进度。"""
    return {"packs": status(known_tools), "dir": str(config.PACKS_DIR),
            "auto": list(config.DEMO_PACKS), "progress": progress()}


def import_pack(pack_id, ingest, known_tools, force=False) -> dict:
    """导入一个包：文档入库 → SOP 入库 → 记状态。幂等：同版本已导入且不 force 时什么都不做。

    ingest(name, data, category, report) 就是上传用的那一个；known_tools 是此刻真实可用的工具名。
    """
    pack = discover().get(pack_id)
    if not pack:
        raise PackError(f"没有这个场景包：{pack_id}")
    if pack["problems"]:
        raise PackError("；".join(pack["problems"]))
    with _lock:
        record = _state().get(pack_id)
        if record and record.get("version") == pack["version"] and not force:
            return {"skipped": True, **record}
        if not settings.configured():
            raise PackWaiting(settings.NOT_CONFIGURED)
        missing = sorted(t for t in pack["tools"] if t not in set(known_tools))
        if missing:
            raise PackWaiting(f"等待工具上线：{'、'.join(missing)}")

        _progress.update(importing=pack_id, stage="")
        try:
            docs = []
            for name in pack["docs"]:
                path = Path(pack["dir"]) / "docs" / name
                try:
                    ingest(name, path.read_bytes(), pack["category"],
                           lambda stage, _n=name: _progress.update(stage=f"{_n}：{stage}"))
                except HTTPException as exc:
                    # 4xx 是文档本身的问题；5xx 是向量服务暂时不通，等会儿再来
                    if exc.status_code < 500:
                        raise PackError(f"{name} 入库失败：{exc.detail}") from exc
                    raise PackWaiting(f"{name} 入库失败：{exc.detail}") from exc
                docs.append(name)
            sops = []
            for sop in pack["sops"]:
                try:
                    playbooks.save(stable_id(pack_id, sop["name"]), sop["name"], sop["trigger"],
                                   sop["steps"], set(known_tools), source=sop["source"],
                                   enabled=sop["enabled"])
                except playbooks.InvalidPlaybook as exc:
                    raise PackError(f"SOP《{sop['name']}》不合法：{exc}") from exc
                sops.append(sop["name"])
            record = {"version": pack["version"], "imported_at": now_iso(), "docs": docs, "sops": sops}
            state = _state()
            state[pack_id] = record
            _save_state(state)
            _notes.pop(pack_id, None)
            _failed.discard(pack_id)
            log.info("scenario pack %s imported: %d docs, %d SOPs", pack_id, len(docs), len(sops))
            return {"skipped": False, **record}
        finally:
            _progress.update(importing="", stage="")


def export_sops(source="") -> list:
    """库里的 SOP 按 sops.json 的形状导出；source 为空导全部。现场长出来的 SOP 就这样进包。"""
    items = playbooks.list_all()
    if source:
        items = [p for p in items if (p["source"] or "手工创建") == source]
    return [{"name": p["name"], "trigger": p["trigger"], "source": p["source"], "enabled": p["enabled"],
             "steps": [{"tool": s["tool"], "args": s["args"], "checkpoint": s["checkpoint"],
                        "evidence": s["evidence"]} for s in p["steps"]]}
            for p in items]


def examples() -> list:
    """已导入的包的示例问题，给欢迎页当「点一下就问」的 chips。自动导入的包排前面。"""
    state, packs, out, seen = _state(), discover(), [], set()
    for pack_id in list(config.DEMO_PACKS) + sorted(packs):
        if pack_id in seen or pack_id not in packs or pack_id not in state:
            continue
        seen.add(pack_id)
        out.extend(packs[pack_id]["examples"])
    return out[:EXAMPLES_MAX]


def progress() -> dict:
    """引导卡用：在导哪个包、到哪一步；自动导入还有哪些包没完成、卡在什么上。"""
    state = _state()
    pending = [p for p in config.DEMO_PACKS if p not in state and p not in _failed]
    return {"importing": _progress["importing"], "stage": _progress["stage"], "pending": pending,
            "notes": {p: _notes[p] for p in pending if p in _notes},
            "failed": {p: _notes.get(p, "") for p in config.DEMO_PACKS if p in _failed}}


def poke():
    """模型设置刚保存：别等退避计时，马上再试一次。"""
    _wake.set()


def start_autoimport(ingest, tools_fn):
    """DEMO_PACKS 非空时起后台线程：等模型配好、工具在线，把包导进来，然后退出。"""
    global _thread
    if not config.DEMO_PACKS or _thread is not None:
        return None
    _thread = threading.Thread(target=_run, args=(ingest, tools_fn), name="packs", daemon=True)
    _thread.start()
    return _thread


def _run(ingest, tools_fn):
    delay = 5
    while True:
        packs = discover()
        todo = []
        for pack_id in config.DEMO_PACKS:
            if pack_id in _failed or imported(pack_id):
                continue
            if pack_id not in packs:
                _notes[pack_id] = f"{config.PACKS_DIR} 下没有这个包"
                _failed.add(pack_id)
                log.warning("demo pack %s not found under %s", pack_id, config.PACKS_DIR)
                continue
            todo.append(pack_id)
        if not todo:
            log.info("demo packs: nothing left to import")
            return
        if settings.configured():
            try:
                known = set(tools_fn())
            except Exception as exc:
                known = set()
                log.info("demo packs: tool list unavailable: %s", why(exc))
            for pack_id in todo:
                try:
                    import_pack(pack_id, ingest, known)
                except PackWaiting as exc:
                    if _notes.get(pack_id) != str(exc):
                        log.info("demo pack %s waiting: %s", pack_id, exc)
                    _notes[pack_id] = str(exc)
                except Exception as exc:
                    _notes[pack_id] = f"导入失败：{why(exc)}"
                    _failed.add(pack_id)
                    log.warning("demo pack %s failed", pack_id, exc_info=True)
        else:
            for pack_id in todo:
                _notes[pack_id] = settings.NOT_CONFIGURED
        if all(imported(p) or p in _failed for p in todo):
            continue    # 这一轮全导完了，回到开头收尾，不白等一次退避
        # 被 poke（刚保存了模型设置）就从头快速重试；自然超时则继续退避
        woken = _wake.wait(delay)
        _wake.clear()
        delay = 5 if woken else min(delay * 2, 60)

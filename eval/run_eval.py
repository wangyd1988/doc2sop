#!/usr/bin/env python3
"""Run the evaluation set against a running knowledge base and print the metrics.

    python eval/run_eval.py --url http://127.0.0.1:8765 --user admin --password ...

Measures four things, deliberately kept separate so a bad score points at one stage:

  召回命中率  did retrieval surface the expected source documents?
  要点覆盖率  did the answer contain the expected facts?
  拒答正确率  did it refuse when the knowledge base has nothing?
  延迟        TTFT and total, P50 / P95

Point coverage is scored by an LLM judge when --judge-model is given, otherwise by
keyword overlap. Keyword scoring is strict and will under-report; treat it as a
lower bound.

--mode prefetch|forced|agentic 按请求打开知识类工具（KB_TOOLS）并指定检索模式，三种模式跑同一套题对比。
这要带评测令牌（--eval-token / --eval-token-file，默认读 EVAL_TOKEN 环境变量），令牌在应用的
DATA_DIR/eval_token 里，只有宿主机上读得到。打开后多三个指标：

  补查率          第一次检索之后模型又查了知识库（kb_search / kb_read）的题占比
  补查后命中率    补查过的题里，最终来源（预检索 + 补查）命中期望文档的比例；同时给出补查前的命中率对照
  平均模型轮次    每题调用模型的次数（服务端 stats 事件给出）
"""
import argparse
import json
import os
import re
import statistics
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REFUSAL_MARKERS = ["没有找到", "未找到", "没有相关", "无法找到", "知识库中没有",
                   "没有收录", "不包含", "没有相关内容"]
MODES = ("prefetch", "forced", "agentic")
KB_TOOLS = ("kb_search", "kb_read", "kb_catalog")


def percentile(values, pct):
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(int(len(ordered) * pct / 100), len(ordered) - 1)
    return ordered[index]


def request_body(question, web=False, mode=None):
    """/api/ask 的请求体：--mode 时按请求打开知识类工具并指定检索模式。"""
    body = {"question": question, "web": web}
    if mode:
        body.update(retrieval_mode=mode, kb_tools=True)
    return body


def read_events(lines, started, clock=time.time):
    """把 /api/ask 的 NDJSON 事件收拢成一条结果：答案、来源、首字时间，以及知识类工具的补查情况。"""
    ttft, answer, conversation_id, error, stats, mode = None, "", None, None, None, None
    sources, kb_sources, prefetched, kb_calls = [], [], False, []
    for line in lines:
        if not line.strip():
            continue
        event = json.loads(line)
        if "conversation" in event:
            conversation_id = event["conversation"]["id"]
            mode = event.get("retrieval_mode")
        elif "stage" in event:
            prefetched = prefetched or event["stage"] == "retrieve"
        elif "sources" in event:
            sources = event["sources"]
        elif "kb_sources" in event:
            kb_sources.extend(event["kb_sources"])
            if kb_calls:
                kb_calls[-1]["sources"].extend(event["kb_sources"])
        elif "tool_call" in event:
            call = event["tool_call"]
            if call.get("category") == "knowledge" or call.get("tool") in KB_TOOLS:
                kb_calls.append({"tool": call.get("tool"), "args": call.get("args") or {}, "sources": []})
        elif "stats" in event:
            stats = event["stats"]
        elif "delta" in event:
            if ttft is None:
                ttft = clock() - started
            answer += event["delta"]
        elif "error" in event:
            error = event["error"]
    return {"answer": answer, "sources": sources + kb_sources, "prefetch_sources": sources,
            "prefetched": prefetched, "kb_calls": kb_calls, "stats": stats, "error": error,
            "conversation_id": conversation_id, "mode": mode,
            "ttft": ttft if ttft is not None else clock() - started, "total": clock() - started}


def ask(base_url, auth_header, question, timeout, web=False, mode=None, eval_token=""):
    """Call /api/ask and collect sources, answer and timings.

    Web search is off by default: search results change over time, which would
    make the numbers impossible to reproduce. Pass --web to measure it anyway.
    """
    headers = {"Authorization": auth_header, "Content-Type": "application/json"}
    if mode:
        headers["X-Eval-Token"] = eval_token
    request = urllib.request.Request(
        base_url.rstrip("/") + "/api/ask",
        json.dumps(request_body(question, web, mode)).encode("utf-8"), headers)
    started = time.time()
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return read_events(response, started)


def cleanup(base_url, auth_header, conversation_id, timeout):
    """Eval runs would otherwise pile up in the conversation list."""
    if not conversation_id:
        return
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/api/conversations/{conversation_id}",
        headers={"Authorization": auth_header}, method="DELETE")
    try:
        urllib.request.urlopen(request, timeout=timeout).read()
    except urllib.error.URLError:
        pass


def recall_hit(expected_sources, sources):
    """True when every expected document appears among the retrieved snippets."""
    if not expected_sources:
        return None  # refusal cases have nothing to recall
    found = {s["location"].split(" 第 ")[0] for s in sources}
    return all(expected in found for expected in expected_sources)


def requeried(outcome):
    """第一次检索之后模型又查了知识库：预检索过的，有一次 kb_search / kb_read 就算；没预检索的要有第二次。"""
    looks = [c for c in outcome.get("kb_calls") or [] if c["tool"] in ("kb_search", "kb_read")]
    return len(looks) >= (1 if outcome.get("prefetched") else 2)


def first_sources(outcome):
    """第一次检索拿到的来源：预检索的片段；没预检索就是模型第一次 kb_search 拿到的。"""
    if outcome.get("prefetched"):
        return outcome.get("prefetch_sources") or []
    for call in outcome.get("kb_calls") or []:
        if call["tool"] == "kb_search":
            return call["sources"]
    return []


def kb_metrics(records):
    """--mode 时多出的三个指标。records 里每条有 requeried、recall、first_recall、model_calls。"""
    done = [r for r in records if not r.get("failed")]
    again = [r for r in done if r.get("requeried")]
    after = [r["recall"] for r in again if r.get("recall") is not None]
    before = [r["first_recall"] for r in again if r.get("first_recall") is not None]
    calls = [r["model_calls"] for r in done if r.get("model_calls") is not None]
    return {"requery_rate": len(again) / len(done) if done else 0.0, "requeried": len(again),
            "answered": len(done),
            "hit_after": sum(after) / len(after) if after else None,
            "hit_before": sum(before) / len(before) if before else None, "hit_cases": len(after),
            "model_calls": statistics.mean(calls) if calls else None, "call_cases": len(calls)}


def covered_by_keywords(point, answer):
    """Lower-bound check: do the point's distinctive tokens appear in the answer?"""
    tokens = [t for t in re.split(r"[\s，。、；：,.;:()（）]+", point) if len(t) >= 2]
    if not tokens:
        return False
    hits = sum(1 for token in tokens if token in answer)
    return hits / len(tokens) >= 0.5


def covered_by_judge(judge, point, question, answer):
    """Ask a model whether the answer contains the point. None means 'could not judge'."""
    prompt = ("判断「回答」是否包含了「要点」所表达的信息。\n"
              "只输出 是 或 否，不要解释。\n\n"
              f"问题：{question}\n\n要点：{point}\n\n回答：{answer[:2000]}")
    try:
        verdict = (judge.invoke([("human", prompt)]).content or "").strip()
    except Exception:
        return None
    # A thinking model may emit reasoning first, so take the last verdict token,
    # and fall back to keyword scoring when no verdict is found at all.
    tokens = re.findall(r"[是否]", verdict)
    if not tokens:
        return None
    return tokens[-1] == "是"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8765")
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--dataset", default=str(Path(__file__).parent / "dataset.jsonl"))
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument("--web", action="store_true",
                        help="Allow web search (results are not reproducible over time).")
    parser.add_argument("--judge-model", default="",
                        help="Model alias for LLM-as-judge scoring; falls back to keywords.")
    parser.add_argument("--judge-base-url", default="")
    parser.add_argument("--judge-api-key", default="")
    parser.add_argument("--out", default="", help="Write per-case results to this JSON file.")
    parser.add_argument("--mode", choices=MODES, default="",
                        help="打开知识类工具并指定检索模式（要评测令牌）；不给则按服务端配置跑。")
    parser.add_argument("--eval-token", default=os.environ.get("EVAL_TOKEN", ""),
                        help="评测令牌，默认取 EVAL_TOKEN 环境变量")
    parser.add_argument("--eval-token-file", default="",
                        help="从文件读评测令牌，如宿主机上的 /opt/kb-app/data/eval_token")
    args = parser.parse_args()

    eval_token = args.eval_token
    if args.mode and not eval_token and args.eval_token_file:
        eval_token = Path(args.eval_token_file).read_text(encoding="utf-8").strip()
    if args.mode and not eval_token:
        print("--mode 需要评测令牌：--eval-token、--eval-token-file 或 EVAL_TOKEN 环境变量")
        return 2

    import base64
    auth_header = "Basic " + base64.b64encode(
        f"{args.user}:{args.password}".encode()).decode()

    judge = None
    if args.judge_model:
        from langchain_openai import ChatOpenAI
        # Generous max_tokens on purpose: a thinking model spends its budget on
        # reasoning first and would otherwise return an empty verdict.
        judge = ChatOpenAI(model=args.judge_model, base_url=args.judge_base_url or None,
                           api_key=args.judge_api_key or "not-needed",
                           temperature=0, timeout=90, max_retries=1, max_tokens=2000)

    cases = [json.loads(line) for line in
             Path(args.dataset).read_text(encoding="utf-8").splitlines() if line.strip()]
    print(f"数据集 {args.dataset}：{len(cases)} 条" + (f"；检索模式 {args.mode}（KB_TOOLS 打开）" if args.mode else "")
          + "\n")

    results = []
    for i, case in enumerate(cases, 1):
        print(f"[{i}/{len(cases)}] {case['id']}  {case['question'][:38]}", flush=True)
        try:
            outcome = ask(args.url, auth_header, case["question"], args.timeout, web=args.web,
                          mode=args.mode or None, eval_token=eval_token)
        except Exception as exc:
            print(f"    请求失败：{exc.__class__.__name__}")
            results.append({**case, "failed": True})
            continue
        cleanup(args.url, auth_header, outcome["conversation_id"], args.timeout)

        answer = outcome["answer"]
        is_refusal = case["type"] == "refusal"
        refused = any(marker in answer for marker in REFUSAL_MARKERS)

        points = []
        for point in case["expected_points"]:
            verdict = covered_by_judge(judge, point, case["question"], answer) if judge else None
            if verdict is None:
                verdict = covered_by_keywords(point, answer)
            points.append(verdict)

        record = {**case, "failed": False, "answer": answer, "mode": args.mode or None,
                  "retrieved": [s["location"] for s in outcome["sources"]],
                  "recall": recall_hit(case["expected_sources"], outcome["sources"]),
                  "coverage": sum(points) / len(points) if points else 0.0,
                  "refused_correctly": refused if is_refusal else None,
                  "ttft": outcome["ttft"], "total": outcome["total"],
                  "error": outcome["error"],
                  "requeried": requeried(outcome),
                  "first_recall": recall_hit(case["expected_sources"], first_sources(outcome)),
                  "model_calls": (outcome["stats"] or {}).get("model_calls"),
                  "effective_mode": outcome["mode"],
                  "fallback": bool((outcome["stats"] or {}).get("fallback")),
                  "kb_calls": [{"tool": c["tool"], "args": c["args"]} for c in outcome["kb_calls"]]}
        results.append(record)

        mark = "✓" if (record["recall"] is not False and record["coverage"] >= 0.5) else "✗"
        extra = ""
        if args.mode:
            extra = (f"  补查 {'是' if record['requeried'] else '否'}"
                     f"  轮次 {record['model_calls'] if record['model_calls'] is not None else '-'}")
        print(f"    {mark} 召回 {record['recall']}  要点 {record['coverage']:.0%}  "
              f"首字 {record['ttft']:.1f}s  总 {record['total']:.1f}s{extra}")

    ok = [r for r in results if not r["failed"]]
    if not ok:
        print("\n全部请求失败，无法统计")
        return 1

    recalls = [r["recall"] for r in ok if r["recall"] is not None]
    refusals = [r["refused_correctly"] for r in ok if r["refused_correctly"] is not None]
    coverages = [r["coverage"] for r in ok if r["type"] != "refusal"]
    ttfts = [r["ttft"] for r in ok]
    totals = [r["total"] for r in ok]

    print("\n" + "=" * 54)
    print(f"{'指标':<16}{'结果':>12}   样本")
    print("-" * 54)
    if recalls:
        print(f"{'召回命中率':<14}{sum(recalls) / len(recalls):>12.0%}   {len(recalls)} 条")
    if coverages:
        print(f"{'要点覆盖率':<14}{statistics.mean(coverages):>12.0%}   {len(coverages)} 条"
              + ("" if judge else "（关键词法，偏低）"))
    if refusals:
        print(f"{'拒答正确率':<14}{sum(refusals) / len(refusals):>12.0%}   {len(refusals)} 条")
    print(f"{'首字 P50 / P95':<14}{percentile(ttfts, 50):>7.1f}s /{percentile(ttfts, 95):>5.1f}s")
    print(f"{'总耗时 P50 / P95':<14}{percentile(totals, 50):>7.1f}s /{percentile(totals, 95):>5.1f}s")
    if args.mode:
        kb = kb_metrics(ok)
        print(f"{'补查率':<15}{kb['requery_rate']:>12.0%}   {kb['requeried']}/{kb['answered']} 条")
        if kb["hit_after"] is not None:
            print(f"{'补查后命中率':<13}{kb['hit_after']:>12.0%}   {kb['hit_cases']} 条，补查前 "
                  + (f"{kb['hit_before']:.0%}" if kb["hit_before"] is not None else "-"))
        if kb["model_calls"] is not None:
            print(f"{'平均模型轮次':<13}{kb['model_calls']:>12.1f}   {kb['call_cases']} 条")
    print("=" * 54)
    if args.mode:
        # forced 遇到不支持 tool_choice 的模型会退回 prefetch：这些题量的其实不是要的模式，单独说出来
        other = [r for r in ok if r.get("effective_mode") and r["effective_mode"] != args.mode]
        fell = [r for r in ok if r.get("fallback")]
        if other or fell:
            print(f"\n⚠ 有 {len(other)} 题实际按其他模式跑、{len(fell)} 题在本轮退回 prefetch："
                  + "、".join(r["id"] for r in other + fell))

    by_type = {}
    for r in ok:
        by_type.setdefault(r["type"], []).append(r)
    print("\n分类型要点覆盖率：")
    for kind, items in sorted(by_type.items()):
        if kind == "refusal":
            rate = sum(1 for x in items if x["refused_correctly"]) / len(items)
            print(f"  {kind:<10} 拒答 {rate:.0%}  ({len(items)} 条)")
        else:
            print(f"  {kind:<10} {statistics.mean(x['coverage'] for x in items):.0%}"
                  f"  ({len(items)} 条)")

    missed = [r for r in ok if r["recall"] is False]
    if missed:
        print("\n召回未命中：")
        for r in missed:
            print(f"  {r['id']}  期望 {r['expected_sources']}")
            print(f"        实际 {r['retrieved'][:3]}")

    if args.out:
        Path(args.out).write_text(json.dumps(results, ensure_ascii=False, indent=2),
                                  encoding="utf-8")
        print(f"\n明细已写入 {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

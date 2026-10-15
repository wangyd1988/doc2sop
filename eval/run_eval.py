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
"""
import argparse
import json
import re
import statistics
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REFUSAL_MARKERS = ["没有找到", "未找到", "没有相关", "无法找到", "知识库中没有",
                   "没有收录", "不包含", "没有相关内容"]


def percentile(values, pct):
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(int(len(ordered) * pct / 100), len(ordered) - 1)
    return ordered[index]


def ask(base_url, auth_header, question, timeout):
    """Call /api/ask and collect sources, answer and timings."""
    request = urllib.request.Request(
        base_url.rstrip("/") + "/api/ask",
        json.dumps({"question": question}).encode("utf-8"),
        {"Authorization": auth_header, "Content-Type": "application/json"})

    started = time.time()
    ttft, answer, sources, conversation_id, error = None, "", [], None, None
    with urllib.request.urlopen(request, timeout=timeout) as response:
        for line in response:
            if not line.strip():
                continue
            event = json.loads(line)
            if "conversation" in event:
                conversation_id = event["conversation"]["id"]
            elif "sources" in event:
                sources = event["sources"]
            elif "delta" in event:
                if ttft is None:
                    ttft = time.time() - started
                answer += event["delta"]
            elif "error" in event:
                error = event["error"]
    return {"answer": answer, "sources": sources, "error": error,
            "conversation_id": conversation_id,
            "ttft": ttft if ttft is not None else time.time() - started,
            "total": time.time() - started}


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
    parser.add_argument("--judge-model", default="",
                        help="Model alias for LLM-as-judge scoring; falls back to keywords.")
    parser.add_argument("--judge-base-url", default="")
    parser.add_argument("--judge-api-key", default="")
    parser.add_argument("--out", default="", help="Write per-case results to this JSON file.")
    args = parser.parse_args()

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
    print(f"数据集 {args.dataset}：{len(cases)} 条\n")

    results = []
    for i, case in enumerate(cases, 1):
        print(f"[{i}/{len(cases)}] {case['id']}  {case['question'][:38]}", flush=True)
        try:
            outcome = ask(args.url, auth_header, case["question"], args.timeout)
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

        record = {**case, "failed": False, "answer": answer,
                  "retrieved": [s["location"] for s in outcome["sources"]],
                  "recall": recall_hit(case["expected_sources"], outcome["sources"]),
                  "coverage": sum(points) / len(points) if points else 0.0,
                  "refused_correctly": refused if is_refusal else None,
                  "ttft": outcome["ttft"], "total": outcome["total"],
                  "error": outcome["error"]}
        results.append(record)

        mark = "✓" if (record["recall"] is not False and record["coverage"] >= 0.5) else "✗"
        print(f"    {mark} 召回 {record['recall']}  要点 {record['coverage']:.0%}  "
              f"首字 {record['ttft']:.1f}s  总 {record['total']:.1f}s")

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
    print("=" * 54)

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

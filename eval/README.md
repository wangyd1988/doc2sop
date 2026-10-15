# 评测集

把「这套系统效果怎么样」变成可复现的数字，而不是凭感觉。

## 两套评测集

| | 文件 | 对应语料 | 是否进仓库 |
|---|---|---|---|
| 公开 | `dataset.jsonl` | `sample_kb/` 的 6 篇示例文档 | 是，任何人 clone 都能复现 |
| 私有 | `dataset.local.jsonl` | 你自己的真实文档 | 否，已在 `.gitignore` 中 |

公开这套不依赖任何私有数据：上传 `sample_kb/` 下的文档即可跑出相同结果。
如果你的知识库装的是工作资料，把题目写进 `dataset.local.jsonl`，它不会被提交。

## 怎么跑

```bash
# 1. 准备语料：把 sample_kb/ 下 6 个文件上传到知识库
# 2. 跑评测
python eval/run_eval.py --url http://127.0.0.1:8765 --user admin --password '你的密码'
```

要点覆盖率默认用关键词匹配打分，结果偏保守。接入模型评判更准：

```bash
python eval/run_eval.py --user admin --password '...' \
  --judge-model kb-chat \
  --judge-base-url http://127.0.0.1:4000/v1 \
  --judge-api-key "$LLM_API_KEY" \
  --out eval/result.json
```

## 数据格式

一行一条 JSON：

| 字段 | 说明 |
|---|---|
| `id` | 唯一编号 |
| `question` | 提问原文 |
| `expected_points` | 答案里应当出现的关键信息点 |
| `expected_sources` | 期望命中的来源文件名；空数组表示「知识库里本就没有」 |
| `type` | `fact` / `concept` / `multi_hop` / `refusal` |

## 题目构成

当前 20 条：

| 类型 | 条数 | 考什么 |
|---|---|---|
| `fact` | 7 | 能否准确取回具体数值和定义 |
| `concept` | 7 | 能否解释清楚原理，不只是复读原文 |
| `multi_hop` | 4 | 需要综合多处内容或跨文档 |
| `refusal` | 2 | 知识库里没有时能否老实说没有 |

**`refusal` 是最重要的一类。** RAG 最危险的失败不是答不出，而是知识库里没有却编造一个。
建议保持 10%–20% 的占比。

## 指标说明

| 指标 | 怎么算 | 看什么 |
|---|---|---|
| 召回命中率 | `expected_sources` 是否都出现在检索结果里 | 检索环节是否可靠 |
| 要点覆盖率 | `expected_points` 被答案覆盖的比例 | 生成环节是否完整 |
| 拒答正确率 | `refusal` 类是否正确拒答 | 是否会编造 |
| 首字 / 总耗时 P50、P95 | 端到端计时 | 体验是否可接受 |

**先拆开看检索和生成。** 召回命中率低，调提示词没用，要先解决检索（切分、`TOP_K`、重排序）；
召回正常但要点覆盖率低，问题才在提示词或模型。

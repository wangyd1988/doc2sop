# 评测集

把「这套系统效果怎么样」变成可复现的数字，而不是凭感觉。

## 两套评测集

| | 文件 | 对应语料 | 是否进仓库 |
|---|---|---|---|
| 公开 | `dataset.jsonl` | `sample_kb/` 下的示例文档 | 是，任何人 clone 都能复现 |
| 私有 | `dataset.local.jsonl` | 你自己的真实文档 | 否，已在 `.gitignore` 中 |

公开这套不依赖任何私有数据：上传 `sample_kb/` 下的文档即可跑出相同结果。
如果你的知识库装的是工作资料，把题目写进 `dataset.local.jsonl`，它不会被提交。

**公开这套测不出检索改动。** 它只有十几个片段，`TOP_K=8` 等于每次返回半个库；比较检索模式、补查效果要用私有真实语料。

## 怎么跑

```bash
# 1. 准备语料：把 sample_kb/ 下的文件上传到知识库
# 2. 跑评测。凭据走环境变量：写在命令行上的密码谁都能用 ps 看到
export EVAL_USER=admin
read -rsp '登录密码：' EVAL_PASSWORD && export EVAL_PASSWORD
python eval/run_eval.py --url http://127.0.0.1:8765
```

| 环境变量 | 对应参数 | 用途 |
|---|---|---|
| `EVAL_USER` / `EVAL_PASSWORD` | `--user` / `--password` | 页面的登录账号 |
| `EVAL_JUDGE_API_KEY` | `--judge-api-key` | 评判模型的 key |
| `EVAL_TOKEN` | `--eval-token` | `--mode` 用的评测令牌（也可以 `--eval-token-file`） |

在部署机上可以直接从应用的配置里取（和 `deploy/release.sh` 读法一样），不打印、不进命令行：

```bash
envget() { sed -n "s/^[[:space:]]*$1=//p" /opt/kb-app/.env | tail -n 1 | tr -d '\r'; }
export EVAL_USER=$(envget WEB_USER) EVAL_PASSWORD=$(envget WEB_PASSWORD) EVAL_JUDGE_API_KEY=$(envget LLM_API_KEY)
```

要点覆盖率默认用关键词匹配打分，结果偏保守。接入模型评判更准：

```bash
python eval/run_eval.py --judge-model kb-chat --judge-base-url http://127.0.0.1:4000/v1 --out eval/result.json
```

### 对比三种检索模式

`--mode prefetch|forced|agentic` 按请求打开知识类工具（`KB_TOOLS`）并指定检索模式，服务端配置不用改。
这要带评测令牌：应用启动时生成在 `DATA_DIR/eval_token`（权限 600），只有宿主机上读得到；也可以在 `.env` 里配 `EVAL_TOKEN`。

```bash
for mode in prefetch forced agentic; do
  python eval/run_eval.py --dataset eval/dataset.local.jsonl \
    --mode $mode --eval-token-file /opt/kb-app/data/eval_token --out eval/result.$mode.json
done
```

`--mode` 时多三个指标：

| 指标 | 怎么算 |
|---|---|
| 补查率 | 第一次检索之后模型又调了 `kb_search` / `kb_read` 的题占比（`prefetch` 下第一次是代码预检索，其余模式是模型的第一次 `kb_search`） |
| 补查后命中率 | 补查过的题里，最终来源（预检索 + 补查）命中期望文档的比例；同时给出这些题补查前的命中率 |
| 平均模型轮次 | 每题调用模型的次数（服务端在回答末尾的 `stats` 事件里给出） |

## 数据格式

一行一条 JSON：

| 字段 | 说明 |
|---|---|
| `id` | 唯一编号 |
| `question` | 提问原文 |
| `expected_points` | 答案里应当出现的关键信息点 |
| `expected_sources` | 期望命中的来源文件名；空数组表示「知识库里本就没有」 |
| `type` | `fact` / `concept` / `multi_hop` / `rephrase` / `context` / `refusal` |

## 题目构成

当前 27 条：

| 类型 | 条数 | 考什么 |
|---|---|---|
| `fact` | 7 | 能否准确取回具体数值和定义 |
| `concept` | 7 | 能否解释清楚原理，不只是复读原文 |
| `multi_hop` | 5 | 需要综合多处内容或跨文档 |
| `rephrase` | 3 | 提问的说法和文档不一样，第一次检索可能查不到，要换个说法再查 |
| `context` | 3 | 答案散在相邻几段里，只拿到一个片段答不全，要读前后文 |
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

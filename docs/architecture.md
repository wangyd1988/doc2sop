# 架构说明

## 部署拓扑

三台 2 核小规格云主机，按职责拆分。云 A 与云 C 之间网络不通，
所有跨区流量经由云 B 中转。

```mermaid
flowchart LR
    U([浏览器]) -->|HTTP Basic| A

    subgraph A["云 A · 应用"]
        APP[FastAPI 应用]
        CH[(Chroma<br/>向量库)]
        DB[(SQLite<br/>对话记忆)]
        FS[(原文件)]
        APP --- CH
        APP --- DB
        APP --- FS
    end

    subgraph B["云 B · 网关"]
        LL[LiteLLM<br/>统一模型入口]
    end

    subgraph C["云 C · 向量模型"]
        EMB[bge-base-zh-v1.5<br/>ONNX CPU]
    end

    EXT([外部大模型<br/>对话 / 多模态]):::ext

    APP -->|OpenAI 兼容| LL
    LL -->|SSH 隧道| EMB
    LL --> EXT

    classDef ext fill:#f3f4f6,stroke:#9ca3af,stroke-dasharray:4 3
```

## 为什么这样拆

| 决策 | 原因 |
|---|---|
| 向量模型独立一台 | 模型常驻约 800 MB，应用机只有 2 GB，放一起会互相挤占 |
| 所有模型调用走 LiteLLM | 换模型、换供应商只改网关配置，应用代码不动 |
| 跨主机走 SSH 隧道 | 向量服务只监听 `127.0.0.1`，不暴露公网；密钥限制为仅允许单端口转发 |
| 向量库和原文件留在应用机 | 文档和索引不出自己的服务器，只有待识别图片和检索片段会发给模型 |

## 单机演示拓扑（compose `demo` profile）

上面是生产拓扑；给陌生人五分钟跑通用的是同一份代码的单机形态（`docs/五分钟演示.md`）：

```mermaid
flowchart LR
    U([浏览器]) -->|127.0.0.1:8765| APP
    subgraph H["一台机器 · docker compose"]
        APP[kb-app<br/>应用 · 900 MB]
        OPS[kb-ops<br/>ops_readonly.py · 128 MB<br/>端口不发布]
        PK[(packs/<br/>场景包)]
        APP -->|OPS_URL + 令牌| OPS
        OPS -. include tools.yaml .-> PK
        APP -. 导入 docs/ 与 sops.json .-> PK
    end
    V([模型服务商<br/>对话 + 向量，一把 key]):::ext
    CDN([节假日数据 CDN]):::ext
    APP -->|OpenAI 兼容| V
    OPS -->|/v1/models /v1/user/info| V
    OPS --> CDN
    classDef ext fill:#f3f4f6,stroke:#9ca3af,stroke-dasharray:4 3
```

- 没有网关、没有自托管模型：对话和向量都走一家 OpenAI 兼容服务商（推荐硅基流动，一把 key）。
- 工具不是另一套实现：sidecar 跑的就是宿主机上那个 `ops_readonly.py`，只是工具定义通过 `include:` 来自场景包，
  凭据（`OPS_TOKEN`、`OPS_SECRET_GATEWAY_*`）由 compose 从同一个 `.env` 映射进去，页面依旧碰不到。
- 应用启动后在后台导入 `DEMO_PACKS` 列出的场景包：文档走入库链路，SOP 走 `playbooks.validate`——和手工操作完全相同的两条路径。

## 问答链路

```
提问
 └─ 问题改写      多轮时补全指代，首轮直接跳过
 └─ 向量化        云 A → 云 B → 云 C
 └─ 混合检索      向量 + 关键词融合、低分过滤、重排，取 TOP_K
 └─ 生成回答      系统提示 + 历史 + 片段，流式返回；有工具可绑时走 Agent（模型 ⇄ 工具循环）
 └─ 写入记忆      答案与引用一起存库
```

每一步都是 LangSmith 里的一个节点，耗时自动拆分。

**知识检索工具化（`KB_TOOLS`，默认关）。** 打开后知识库检索也是工具：`kb_search`（复用上面的混合检索，可按分类、文档过滤）、
`kb_read`（按片段 id「文档键:序号」读前后各几段，或按文档 + 页码读整页，拼接时去掉切分留的重叠）、`kb_catalog`（目录）。
没有工具服务、也没开联网的部署也会因此走 Agent 分支。`KB_RETRIEVAL_MODE` 决定首轮：`prefetch` 照上面先检索一次、不够时模型补查；
`forced` 不预检索，第一轮强制调 `kb_search`（模型不支持 `tool_choice` 时当场退回 `prefetch`）；`agentic` 全由模型决定。
补查的片段接着预检索的 `[1]…[k]` 编号，经 `kb_sources` 事件追加卡片、随回答落库；结构化结果放在工具消息的 `artifact` 里，
往后几轮回放只给文档名。知识类、流程类工具绑上时一轮最多 8 次工具调用（只有数据类、外网类时仍是 4 次）。

**待办清单（`PLAN_TOOL`，默认关）。** 流程类工具 `plan`：模型维护整张清单（每次整体替换），经 `plan` 事件画成勾选列表；
点「▶ 执行」时代码先按 SOP 步骤预填。流程类调用不算观察到系统、不进 SOP、不记进图谱。

**联网与出网规则。** 联网打开时绑 `web_search`，再打开 `WEB_FETCH` 时多绑 `web_fetch`（读本轮搜索结果或用户给的链接的正文，
作为 `[W]` 来源接着编号）。两条出网通道——搜索词和链接——发出去之前都过 `egress.py` 的同一套规则：静态拦截、
本轮数据类调用留下的污点、链接来源、可选的严格模式（`WEB_AFTER_DATA=deny`），见 `docs/工具.md`「出网规则」。

## 组织运行图谱（graph.db）

文档 → SOP → 工具 原本是一条单向流，工具查到的真实数据和人对一次回答的判断答完就丢。
图谱把它们留下来，SOP 和文档从「源头」变成图谱的「生成物」；模块在 `app/graph.py`，
一个 SQLite 文件、六张表，不引入图数据库：

| 表 | 存什么 |
|---|---|
| `executions` | 一次提问 / 一次「▶ 执行」：会话、对应的回答消息、按哪个 SOP 跑的、结论质量（ok / anomaly / failed / unknown） |
| `tool_calls` | 每次工具调用的参数、**完整返回**（页面和模型看到的都是截断 / 压缩过的）、成功与否、耗时 |
| `entities` | 容器、命名空间、K8s 对象、工具、SOP、文档、阈值、执行……`(kind, name)` 唯一，记首次 / 最近见到的时间 |
| `facts` | 主语 → 谓语 → 宾语（实体或字面量），带 `source_kind`（tool / doc / human / sop）和 `source_ref`（`tool_call:<id>` / `sop:<id>` / `feedback:<id>`） |
| `proposals` | 图谱提出的建议（长出 SOP、补充 SOP、调阈值……），`evidence_refs` 指向工具调用，状态 pending / approved / rejected |
| `feedback` | 人对一次执行的判断：correct / false_alarm / wrong_threshold / missing_step |

两条铁律：**没有出处的事实、没有证据的提议不进图谱**（Python 层校验 + 表上 CHECK）；
**事实只追加不覆盖**，同一主语同一谓语的多条记录就是时间线，撤回只把状态改成 retracted。

第一期不用模型抽实体，只在三处零成本播种：

```
保存 SOP      sop —checks→ tool；sop —defined_in→ doc；检查点里可靠解析出的「80%」「3 次」→ threshold 实体
调用工具      execution —called→ tool；调用成功时，工具声明了 x-entity 的实参成为实体并刷新 last_seen
             （老写法由工具服务按 name / k8s_name 预置正则推出，见 docs/工具.md「工具契约」）
人工反馈      execution —judged→ verdict（按 SOP 执行的，SOP 也记一笔）
```

工具调用在 `loop.py` 的 `tools` 节点里落盘（`run(..., execution_id=)`），对外事件仍只发预览，
前端协议不变；`/api/ask` 首行多一个 `execution_id`，`POST /api/feedback` 用它打反馈。

## 自由排查 → 长出 SOP

文档抽取是「人写过的做法 → SOP」；这条链路是「Agent 刚做过的事 → SOP」。模块在 `app/agent/grow.py`，
回答落库后在后台单线程里跑，不拖慢流式回答：

```
回答结束
 └─ 该不该提      自动提议开着 ∧ 当日未达上限 ∧ 不是「▶ 执行」∧ outcome ∈ {ok, anomaly}
                 ∧ ≥2 个不同数据类工具（联网搜索这类不算）∧ 回答有结论（≥40 字且开头不是「没查到 / 请提供…」）
                 ∧ 没套用启用中的 SOP（回答未写「按 SOP《」、工具序列也不按顺序覆盖某个 SOP 的步骤）
                 ∧ 同样的轨迹签名 30 天内没被忽略、也没有待确认的提议
 └─ 生成          把本轮轨迹（问题 + 第 n 次调用 xxx 的参数与返回摘要 + 结论）喂给模型，
                 复用文档抽取的 JSON 形状：具体对象泛化为空参数，checkpoint 写实际判断依据，
                 evidence 写「第 n 次调用 xxx 的返回：…」——序号、工具名对不上的加 ⚠ 留给人看
 └─ 门禁          猜错的参数键丢掉；过 playbooks.validate：只能引用已有工具，否则整条丢弃
 └─ 去重          候选步骤序列与某个已有 SOP（含停用）相似度 ≥ 0.7 → 改提「补充到《X》」，只带 X 没有的步骤；
                 X 已全覆盖则不提
 └─ 入 proposals  evidence_refs 指向本轮的 tool_call，signature 是工具序列签名
```

页面在回答结束后按 2/4/8…s 退避轮询 `GET /api/proposals?execution_id=`，拿到就在回答末尾画卡片；
SOP 面板顶部有「待确认提议 N」，回放对话时卡片也会补画。批准（`POST /api/proposals/{id}/approve`）
新建来源为「从实践沉淀」、默认停用的 SOP，或把步骤追加到目标 SOP 末尾；忽略则同签名 30 天静默。
开关 `AUTO_SOP_PROPOSALS`，每日上限 `SOP_PROPOSALS_PER_DAY`。

## 入库链路

```
上传文件
 └─ 解析          PDF / DOCX / PPTX / 图片 / 文本
 └─ 图片识别      抽出内嵌图片 → 多模态模型 → 结果插回原位
 └─ 自动分类      模型给出简短分类，可手工覆盖
 └─ 切分          约 400 字，重叠 50 字
 └─ 向量化入库    文本 + 向量 + 来源页码一起写入 Chroma
```

## 代码结构

```
app/
├── main.py            HTTP API 与鉴权
├── config.py          环境变量配置
├── clients.py         模型客户端（经网关）
├── conversations.py   会话列表与界面回放（SQLite）
├── jobs.py            后台入库任务与进度
├── playbooks.py       SOP：存储与校验（只能引用已有工具）
├── packs.py           场景包：发现、校验、导入（文档 + SOP）、导出、首次运行自动导入
├── graph.py           组织运行图谱：执行、工具完整返回、实体与带出处的事实、提议、反馈（SQLite）
├── models.py          网关可用模型列表与校验
├── tracing.py         LangSmith 追踪
├── agent/
│   ├── loop.py        LangGraph Agent：模型 ⇄ 工具循环，检查点记住每轮完整过程；三种检索模式、forced 的退回
│   ├── registry.py    工具注册表：统一契约（MCP 的 Tool 格式）与类别策略，合并工具服务和应用内的工具
│   ├── kb_tools.py    知识类工具 kb_search / kb_read / kb_catalog：补查、读前后文、目录，片段续编号
│   ├── plan.py        流程类工具 plan：本轮的待办清单，「▶ 执行」时按 SOP 步骤预填
│   ├── tools.py       按 JSON Schema 生成工具签名（契约里的 inputSchema；老工具服务按 params 推）
│   ├── extract.py     从文档抽取 SOP
│   ├── grow.py        从一次自由排查长出 SOP 提议（回答后后台判断、生成、去重）
│   ├── web_search.py  联网搜索（经网关）
│   ├── web_fetch.py   读网页正文（WEB_FETCH）：只读搜索结果和用户给的链接，防 SSRF、限大小和类型、HTML 转正文
│   ├── egress.py      统一出网规则：搜索词和链接的静态拦截、污点拦截、链接来源、严格模式
│   └── ops_client.py  只读接口客户端
├── rag/
│   ├── chunking.py    切分
│   ├── embedding.py   向量化
│   ├── store.py       Chroma 读写
│   ├── lexical.py     BM25 关键词索引（内存，随写入重建）
│   ├── retrieval.py   向量 + 关键词融合召回 → 重排
│   ├── rerank.py      交叉编码器重排（经网关 /rerank，best-effort）
│   └── answer.py      提示词与生成
└── ingest/
    ├── extract.py     文档解析
    └── vision.py      多模态 OCR

deploy/
├── release.sh         正式发版：base 镜像按依赖哈希预烘焙 → 只 COPY 代码 → 停旧起新 → 比对片段数 → 不一致回滚（docs/正式部署.md）
├── Dockerfile.release 发版用的应用镜像：FROM base 只 COPY app/ packs/（根 Dockerfile 的 base 阶段装依赖，app 阶段给 compose）
├── ops_readonly.py    宿主机上的只读运维接口（白名单 + 令牌），支持 include 场景包的工具定义；
│                      /tools 按统一契约多回 inputSchema 等字段；
│                      内置标准库手写的 MCP stdio 客户端，发现的工具进待审、批准后写 ops_tools.mcp.yaml
├── ops_tools.yaml     工具定义的唯一真相源，改完即时生效；顶层 mcp_servers 声明 MCP server
├── mcp/               玩具 MCP server holiday_mcp.py（测试 + 演示）与把拼假工具换成 MCP 来源的 holiday_tools.yaml
├── demo/              一键演示用的工具 sidecar：Dockerfile.ops + entrypoint.py（按 DEMO_PACKS 生成 include）
├── backup.sh          每日备份
├── container-guard.sh 内存超阈值才重启容器，配 systemd timer 每天跑一次
└── embedding/
    ├── server.py          向量服务（FastEmbed ONNX，OpenAI 兼容 /v1/embeddings）
    └── rerank_server.py   重排服务（onnxruntime，Infinity/Cohere 兼容 /rerank），LiteLLM 用 infinity/ 接

packs/                 场景包：每个目录 = pack.yaml + docs/ + tools.yaml + sops.json（docs/场景包.md）
├── leave-planning     行政-请假拼假
├── model-selfcheck    研发-模型调用自查
└── ops-inspection     运维-日常巡检（需宿主机 docker）
```

## 关键取舍

**手写解析器，而不是用现成 Loader。** 标准加载器会丢掉内嵌图片、演讲者备注、
组合图形和表格顺序——这些恰恰是真实笔记里信息密度最高的部分。
代价是解析代码需要自己维护。

**片段 ID 按文件名生成，不按内容哈希。** 否则两个内容相同、文件名不同的文档
会互相覆盖，先传的那份会静默消失。

**不默认下发 `reasoning_effort`。** 部分网关对该参数的处理是把思考内容并入正文，
反而污染回答。只在确认模型支持时才开启。

**对话记忆用 SQLite 而非 LangGraph Checkpointer。** 只需要存消息本身，
不需要图状态；少一层依赖，在小内存机器上更省。

**MCP 工具不直连应用，仍经宿主机工具服务。** 应用侧只认 `/tools` 和 `/exec`，SOP 校验「只能引用
当前存在的工具」这条线不用动；审批、只读确认、schema 指纹、输出脱敏也全部复用同一个地方。
MCP 客户端用标准库手写而不引入 SDK，是为了保住 `ops_readonly.py`「单文件、零依赖、扔到任何主机就能跑」。

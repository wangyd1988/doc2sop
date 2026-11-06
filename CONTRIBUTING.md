# 参与贡献

欢迎新加入的同事和外部贡献者。先读 [`README.md`](README.md) 了解它做什么，代码结构和链路见
[`docs/architecture.md`](docs/architecture.md)，设计决策见 [`docs/设计与取舍.md`](docs/设计与取舍.md)，
工具的安全约定见 [`docs/工具.md`](docs/工具.md)，贡献场景包见 [`docs/场景包.md`](docs/场景包.md)。

## 分支与 PR

- **组织成员**：直接在本仓库从最新的 `main` 拉分支开发，推到同名分支后提 PR。
- **外部贡献者**：fork 本仓库，在 fork 里开分支，向 `Inspur-Data/doc2sop` 的 `main` 提 PR。
- `main` 受保护：只能经 PR 合入，至少 1 位维护者批准，所有评论解决后才能合并；禁止强推和删除。
  [`.github/CODEOWNERS`](.github/CODEOWNERS) 会自动请 @Inspur-Data/doc2sop-maintainers 评审。
- 一个 PR 只做一件事；改动较大的先开 Issue 讨论方向。按 PR 模板写清改了什么、怎么验证、是否涉及安全 / 部署 / 配置变更。

## 本地跑测试

```bash
pip install -r requirements.txt
python -m unittest discover -s tests -t .    # 全量
python -m unittest tests.test_packs          # 只跑一个模块
node tests/page.test.js                      # 改了 app/web/index.html 时；不需要浏览器和依赖
node tests/picker.test.js
```

- 部分测试要 Linux 上的 bash、POSIX 权限或可选依赖（`cryptography`、`paho-mqtt==1.6.1`），没有时会跳过；
  在 Windows 上建议用 WSL 跑全量。
- `tests/test_ask_golden.py` 和 `tests/fixtures/ask_transcripts.json` 逐字节固定了问答接口的行为，
  除非有意改变行为，否则不要改；真要改，单独一个提交并写明原因。
- README 有行数上限（`tests/test_release.py`：非空行不超过 103），新内容并进现有行或写进 `docs/`。

## 提交信息与代码风格

- 提交信息用中文，首行「范围：一句话说明」，范围如 `页面`、`测试`、`文档`、`工具服务`、`应用`；
  需要时空一行写正文，说明为什么这么改、影响和取舍。
- 代码风格跟随所在文件：应用跑在 Python 3.12；远程执行器 `deploy/ops_exec.py` 只用标准库、兼容 Python 3.6。
  注释只写需要解释的地方，用中文。不随手引入新依赖。
- 文本文件一律 LF（见 [`.gitattributes`](.gitattributes)）。
- 行为、配置或部署步骤变了，同一个 PR 里同步 README / `docs/`。

## 安全

- 不要提交密钥、令牌、证书、kubeconfig 或生产 `.env`；`.env.example` 里只放占位值。不小心提交了，立即告诉维护者轮换凭据，
  仅删掉文件不够。
- 发现安全问题**不要公开提 Issue**，请私下联系维护者（@Inspur-Data/doc2sop-maintainers）。

## 许可

提交的贡献按本仓库的 [MIT](LICENSE) 协议发布。

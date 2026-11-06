## 改了什么、为什么

<!-- 一两句话说明改动和动机；有关联的 Issue 写 Closes #编号 -->

## 怎么验证的

<!-- 跑了哪些测试、手动点了哪些页面；没跑全量的说明原因 -->

- [ ] `python -m unittest discover -s tests -t .`
- [ ] 改了页面（app/web/index.html）：`node tests/page.test.js`、`node tests/picker.test.js`

## 是否涉及以下变更

<!-- 勾选并简要说明影响和回滚方式；都不涉及就写「无」 -->

- [ ] 安全边界：认证、审批口令、工具只读约束、出网规则、凭据
- [ ] 部署：Dockerfile、deploy/ 下的脚本或服务、发版和回滚步骤
- [ ] 配置：新增或改名的环境变量、`.env.example`、默认值

## 文档

- [ ] 已同步 README / docs/（或无需修改）

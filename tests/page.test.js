// 页面（app/web/index.html）的检查：内联脚本能编译；几个纯函数的行为（风险提示的措辞、主机原因去重、参数范围转义、
// 审批口令卡片在各个状态下给的表单和说明、工作台「待处理」里的「还没设审批口令」、执行记录 / 自动执行 / 知识库缺口里服务端文字的转义）。
// 用法：node tests/page.test.js（和 picker.test.js 一样，不需要浏览器和依赖）
const fs = require('fs');

const html = fs.readFileSync('app/web/index.html', 'utf8');
const scripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]);

let pass = 0, fail = 0;
const check = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  console.log(`${ok ? 'OK  ' : 'FAIL'} ${label}  got=${JSON.stringify(got)}`);
  ok ? pass++ : fail++;
};

check('有内联脚本', scripts.length > 0, true);
scripts.forEach((code, i) => {
  let error = null;
  try { new Function(code); } catch (e) { error = e.message; }
  check(`第 ${i + 1} 段脚本能编译`, error, null);
});

// 按名字取出一个顶层函数的源码（花括号配对，跳过字符串和模板里的括号不必：这几个函数里没有）
function extract(name) {
  const code = scripts.join('\n');
  const start = code.indexOf(`function ${name}(`);
  if (start < 0) throw new Error('找不到函数 ' + name);
  let depth = 0, i = code.indexOf('{', start);
  for (; i < code.length; i++) {
    if (code[i] === '{') depth++;
    if (code[i] === '}' && --depth === 0) break;
  }
  return code.slice(start, i + 1);
}
const load = (...names) => new Function(names.map(extract).join('\n') + `\nreturn {${names.join(',')}};`)();

const {hostReason} = load('hostReason');
check('主机原因去掉重复的主机名', hostReason('gateway-b', '主机 gateway-b：主机 gateway-b 的 host key 还没登记'), 'host key 还没登记');
check('没有前缀的原样保留', hostReason('gw', '连不上：超时'), '连不上：超时');
check('空原因写「连不上」', hostReason('gw', ''), '连不上');

const {riskMark} = load('riskMark');
check('有高风险报条数', riskMark([{level: 'high'}, {level: 'warn'}]), ['high', '⛔ 1 项高风险']);
check('只有注意', riskMark([{level: 'warn'}, {level: 'info'}]), ['warn', '⚠ 1 项注意']);
check('没检测到问题不说成没有风险', riskMark([{level: 'info'}]), ['', '没有检测到风险']);
check('页面里没有「无风险」的说法', html.includes('无风险'), false);

// 参数的类型和范围：min / max 可能来自 MCP server 的 schema，必须转义后再进 HTML
const escLine = scripts.join('\n').match(/^const esc = .*$/m)[0];
const {paramType} = new Function(`${escLine}\n${extract('paramType')}\nreturn {paramType};`)();
const evil = '<img src=x onerror=alert(1)>';
const shown = paramType({type: 'integer', min: evil, max: `${evil}"'`});
check('min/max 里的 < 被转义', shown.includes('<img'), false);
check('转义后的文字照常显示', shown.includes('&lt;img src=x onerror=alert(1)&gt;'), true);
check('正常的整数范围不变', paramType({type: 'int', min: 1, max: 10000}), '整数，1–10000');
check('只有一头的范围', paramType({type: 'integer', min: 0}), '整数，0–…');

// 左侧导航：七个页面，对话下面常驻最近 5 条
for (const path of ['/', '/chat', '/tools', '/sop', '/docs', '/access', '/settings']) {
  check(`导航有 ${path}`, html.includes(`<a href="${path}" data-page=`), true);
}
check('对话下面有最近的对话', html.includes('id="navRecent"') && /convList\.slice\(0, 5\)/.test(html), true);
// 口令只在这次请求里用：不进 localStorage、地址栏
check('口令不进 localStorage', /localStorage\.setItem\([^)]*pass/i.test(html), false);
check('手机上的占位文字是短的', html.includes("NARROW.matches ? '问点什么…'"), true);

// 审批口令的卡片（设置页、主机与数据源）：每种状态给对的表单，每种状态都写上忘了怎么重设
const lineOf = re => scripts.join('\n').match(re)[0];
const passCode = [/^const esc = .*$/m, /^const setCmd = .*$/m, /^const unlockIn = .*$/m, /^const LOCAL_HOSTS = .*$/m].map(lineOf)
  .concat(['plainHint', 'setAtText', 'passWho', 'passFormHtml', 'passCard', 'passUnset', 'todoCounts'].map(extract)).join('\n');
const passFns = host => new Function('location', `${passCode}\nreturn {passCard, passFormHtml, passWho, setAtText, passUnset, todoCounts};`)(
  {hostname: host, host: `${host}:8765`});
const P = passFns('127.0.0.1');
const base = {max_failures: 5, lock_minutes: 15, min_length: 12, page_set: true, problem: '',
              command: 'python3 /opt/ops/ops_readonly.py set-approval-passphrase'};
const count = (text, re) => (text.match(re) || []).length;
const unset = P.passCard({...base, configured: false});
check('没设：设置表单', unset.includes('data-passform="set"'), true);
check('没设：新口令输两遍（new-password）', count(unset, /autocomplete="new-password"/g), 2);
check('没设：不要旧口令', unset.includes('current-password'), false);
check('没设：写明抢先设的风险', unset.includes('抢先设'), true);
const done = P.passCard({...base, configured: true, set_at: '2026-11-01 11:30:00', set_by: 'page', set_from: '10.0.0.9'});
check('已设：修改表单', done.includes('data-passform="change"'), true);
check('已设：旧口令（current-password）', count(done, /autocomplete="current-password"/g), 1);
check('已设：新口令输两遍（new-password）', count(done, /autocomplete="new-password"/g), 2);
check('已设：写明设置时间和来源', done.includes(`已设置：${P.setAtText('2026-11-01 11:30:00')}，在页面上设置（来自 10.0.0.9）`), true);
const locked = P.passCard({...base, configured: true, locked: true, unlock_minutes: 12, set_by: 'cli'});
check('锁定：三个输入框和按钮都灰掉', count(locked, / disabled/g), 4);
check('锁定：写明几分钟解锁', locked.includes('12 分钟后解锁'), true);
check('命令行设的写明', locked.includes('在宿主机上用命令行设置'), true);
const broken = P.passCard({...base, configured: false, problem: '口令文件 /etc/x 不属于 root：<b>'});
check('口令文件有问题：不给表单', broken.includes('<form'), false);
check('口令文件有问题：原因转义后显示', broken.includes('不属于 root：&lt;b&gt;'), true);
const old = P.passCard({configured: false, problem: '', command: base.command});
check('工具服务较旧：不给表单', old.includes('<form'), false);
check('工具服务较旧：写明', old.includes('工具服务版本较旧'), true);
for (const [label, card] of [['没设', unset], ['已设', done], ['锁定', locked], ['文件有问题', broken], ['较旧', old]]) {
  check(`${label}：附「忘了口令」和宿主机命令`, card.includes('忘了口令') && card.includes(base.command), true);
}
check('输入框没有 name：表单不会把口令带进地址栏', /\bname=/.test(unset + done), false);
check('来源地址转义', P.passWho({set_by: 'page', set_from: '<img src=x>'}).includes('<img'), false);
check('从本机打开不提示明文', unset.includes('明文连接'), false);
check('不是从本机打开时提示明文', passFns('10.0.0.5').passFormHtml({...base, configured: false}).includes('明文连接（10.0.0.5:8765）'), true);
check('今年的设置时间只写月日时分', P.setAtText(`${new Date().getFullYear()}-11-01 11:30:00`), '11-01 11:30');
check('往年的带上年份', P.setAtText('2020-03-04 05:06:07'), '2020-03-04 05:06');
check('没有设置时间', P.setAtText(''), '');
// 工作台「待处理」：还没设口令时多一项；口令文件有问题、工具服务没给状态时不算
check('没设口令算一项待处理', P.todoCounts({approval: {configured: false, problem: ''}, pending: {}}).all, 1);
check('口令文件有问题不算', P.passUnset({approval: {configured: false, problem: 'x'}}), false);
check('已经设了不算', P.passUnset({approval: {configured: true}}), false);
check('工具服务没给状态不算', P.passUnset({approval: {}}), false);
// 回答模式：智能模式里的 [💡] 渲染成「💡 通用知识」标签；智能模式不可用时 tab 灰着、写明原因，发出去的是知识库模式
const gk = new Function(`${escLine}\n${lineOf(/^const GK_MARK = .*$/m)}\n${lineOf(/^const GK_TIP = .*$/m)}\n`
  + `${lineOf(/^const usesGeneral = .*$/m)}\n${lineOf(/^const GK_WITH_PUNCT = .*$/m)}\n${lineOf(/^const gkBadge = .*$/m)}\n`
  + `${extract('inline')}\nreturn {inline, usesGeneral, GK_MARK};`)();
check('[💡] 渲染成通用知识标签', gk.inline('调休按通用做法折算 [💡]').includes('<span class="gk"'), true);
check('标签上写「💡 通用知识」', gk.inline('x [💡]').includes('>💡 通用知识</span>'), true);
check('句号和标签连在一起，不单独折行', gk.inline('x [💡]。').includes('💡 通用知识</span>。</span>'), true);
check('模型写成 [💡通用知识] 也认', gk.inline('x [💡通用知识]').includes('class="gk"'), true);
check('全角括号【💡】也认', gk.usesGeneral('x 【💡】'), true);
check('知识库引用不当成通用知识', gk.usesGeneral('年假 5 天 [1]，网上说法 [W2]'), false);
check('[1] 照旧是引用', gk.inline('x [1]').includes('class="cite"'), true);
check('标签不吞掉后面的句子', gk.inline('甲 [💡] 乙 [1]').includes('乙 <span class="cite"'), true);
check('正则不带状态：连着判断两次结果一样', [gk.usesGeneral('a [💡]'), gk.usesGeneral('a [💡]')], [true, true]);
const modeInfo = lineOf(/^const MODE_INFO = \{[\s\S]*?^\};$/m);
const modes = (mode, info) => new Function(`${escLine}\n${modeInfo}\nlet answerMode = ${JSON.stringify(mode)};\n`
  + `let smartInfo = ${JSON.stringify(info)};\n${lineOf(/^const sendMode = .*$/m)}\n${extract('modesHtml')}\n`
  + 'return {html: modesHtml(), send: sendMode()};')();
const off = modes('smart', {available: false, reason: '管理员没有打开智能模式（SMART_MODE）'});
check('智能模式不可用时发知识库模式', off.send, 'kb');
check('不可用时选中的是知识库模式', /data-amode="kb" class="on"/.test(off.html), true);
check('不可用的 tab 灰着', /data-amode="smart" class=" off"/.test(off.html), true);
check('写明原因', off.html.includes('智能模式不可用：管理员没有打开智能模式（SMART_MODE）'), true);
const on = modes('smart', {available: true, reason: ''});
check('可用时按选择发', on.send, 'smart');
check('可用时选中智能模式', /data-amode="smart" class="on"/.test(on.html), true);
check('原因里的 HTML 被转义', modes('kb', {available: false, reason: '<b>x</b>'}).html.includes('<b>x'), false);
check('选择记在 localStorage', /localStorage\.setItem\('kb-answer-mode'/.test(html), true);
check('请求里带 answer_mode', /answer_mode: mode/.test(html), true);
check('工作台的输入框也有模式 tab', /<div class="ask-wrap"><div class="modes">\$\{modesHtml\(\)\}/.test(html), true);

// 执行记录、自动执行、知识库缺口：服务端来的文字（SOP 名、告警标题和标签、用户的问题）都转义后再进 HTML
const runCode = [/^const esc = .*$/m, /^const LEVEL = .*$/m, /^const RUN_STATUS = .*$/m, /^const TRIGGER = .*$/m, /^const MARK = .*$/m,
  /^const NOTIFY_WHEN = .*$/m, /^const NOTIFY_REPEAT = .*$/m, /^const GAP_KIND = .*$/m, /^const shortTime = .*$/m,
  /^const paramsText = .*$/m, /^const isRunning = .*$/m, /^const triggerLabel = .*$/m].map(lineOf)
  .concat(['levelPill', 'runRow', 'compareHtml', 'mailHtml', 'notifyText', 'lastRunHtml', 'scheduleRows', 'eventRows', 'gapRow'].map(extract)).join('\n');
const R = new Function(`const mCache = {}; let mItem = null; const ago = t => '刚刚';\n${runCode}\n`
  + 'return {levelPill, runRow, compareHtml, mailHtml, scheduleRows, eventRows, gapRow};')();
const raw = /<(img|svg|script|q|i|u|em)[\s>]/;
check('结论：有异常', R.levelPill({status: 'done', level: 'anomaly'}), '<span class="pill warn">⚠️ 有异常</span>');
check('结论：没跑成', R.levelPill({status: 'done', level: 'failed'}, true), '<span class="lv bad">❌ 没跑成</span>');
check('不认识的结论按没法判断', R.levelPill({status: 'done', level: '<b>'}), '<span class="pill unk">❓ 没法判断</span>');
check('错过的写「错过」', R.levelPill({status: 'missed', level: 'failed'}), '<span class="pill off">错过</span>');
check('在跑的写「执行中」', R.levelPill({status: 'running', level: ''}).includes('⏳ 执行中'), true);
const row = R.runRow({id: 'r"1', playbook_name: '<img src=x onerror=alert(1)>', trigger: 'alert', note: '<q>磁盘</q>',
                      summary: '<script>x</script>', started_at: '2026-11-01T01:00:00+00:00', status: 'done', level: 'anomaly'});
check('执行记录一行：SOP 名、告警标题、摘要都转义', raw.test(row), false);
check('执行记录一行：id 进属性也转义', row.includes('data-mitem="r&quot;1"'), true);
check('不认识的触发方式也转义', raw.test(R.runRow({id: 'x', playbook_name: 'p', trigger: '<svg onload=1>', status: 'done', level: 'ok'})), false);
const cmp = R.compareHtml({previous: {started_at: '2026-10-31T01:00:00+00:00', status: 'done', level: 'ok'}, note: '<em>注意</em>',
  new: [{step: '<q>第 1 步</q>', value: '<i>92%</i>', before: '<u>86%</u>'}], still: [], recovered: [],
  changed: [{step: '第 2 步', deltas: ['<img src=x>']}], gone: []});
check('和上次比：异常项、数值变化、说明都转义', raw.test(cmp), false);
check('和上次比：新出现的写上次的值', cmp.includes('（上次 &lt;u&gt;86%&lt;/u&gt;）'), true);
check('第一次执行：没有可比的', R.compareHtml(null).includes('第一次完成的执行'), true);
check('邮件没发出去：组名和原因转义', raw.test(R.mailHtml({mail: {status: 'failed', group: '<q>值班</q>', error: '<i>535</i>', attempts: 3}})), false);
check('没有邮件状态就不显示', R.mailHtml({mail: {}}), '');
const sched = R.scheduleRows([{id: 's"1', playbook_name: '<img src=x>', describe: '<q>每天</q>', enabled: false, params: {'<i>': '<u>'},
  notify: {group: '<script>g</script>', when: 'problems', repeat: 'daily'}, next_at: null, last: null}]);
check('定时计划：SOP 名、参数、收件组都转义', raw.test(sched), false);
check('定时计划：手机上每格有列名', ['时间', '邮件', '下次', '上次'].every(l => sched.includes(`data-l="${l}"`)), true);
const evs = R.eventRows([{received_at: '2026-11-01T01:00:00+00:00', name: '<q>DiskFull</q>', title: '<img src=x>',
  labels: {'<i>k': '<u>v'}, action_name: '<em>已触发</em>', run_id: 'r1', peer: '<q>10.0.0.1'}]);
check('最近收到的告警：标题、标签、来源都转义', raw.test(evs), false);
const gap = R.gapRow({id: 'g"1', count: 3, example: '<img src=x onerror=alert(1)>', questions: ['<img src=x onerror=alert(1)>', '<svg onload=1>'],
  last_at: '2026-11-01T01:00:00+00:00', detail: '<q>没有</q>', kinds: {'<i>': 1, feedback: 2}});
check('知识库缺口：问题、其他问法、线索都转义', raw.test(gap), false);
check('知识库缺口：线索写成中文', gap.includes('有人工反馈 2'), true);
check('知识库缺口：id 进属性也转义', gap.includes('data-gapopen="g&quot;1"'), true);
// 问题标题不能用工作台示例问题的全局 .ex（4 列网格）：长问题会被挤在四分之一宽里折行
check('知识库缺口：标题不用全局的 .ex', /class="ex"/.test(gap) || !gap.includes('class="gq"'), false);
// 自动执行的设置：地址和账号现在看得到（要改就得看得见），服务端来的文字一律转义；授权码、令牌只画状态，值就算混进了回复也不画出来。
// 什么都不能改时按钮全灰；口令用不了时只灰掉要口令的，缩小能力的照常能点；在服务器上配置的没有按钮
const autoCode = [/^const esc = .*$/m, /^const unlockIn = .*$/m, /^const AS_SRV = .*$/m, /^const AS_SEC = .*$/m, /^const AS_PW = .*$/m,
  /^const AS_KIND = .*$/m, /^const AS_SKIP = .*$/m].map(lineOf)
  .concat(['setAtText', 'icCopy', 'asBtn', 'autoLocks', 'asPwHtml', 'autoMailHtml', 'autoSiteHtml', 'autoGroupRow', 'autoHookHtml',
           'autoChangeRow', 'autoSkipRow', 'autoSettingsHtml', 'autoTokenHtml', 'asUsedHtml'].map(extract)).join('\n');
const A = new Function(`${autoCode}\nreturn {autoSettingsHtml, autoTokenHtml, autoLocks, asUsedHtml};`)();
const autoS = (over = {}) => ({
  version: 'v1', writable: {ok: true, reason: ''}, approval: {configured: true, locked: false, problem: ''},
  mail: {source: 'page', configured: false, host: '<img src=x onerror=alert(1)>', port: 465, security: 'ssl', user: '<q>u@x.com', from: '<i>f@x.com',
         password: {state: 'set', set_at: '<u>2026', value: 'SECRET-AUTH-CODE'}, problem: '<em>授权码要重新输入</em>'},
  site_url: {source: 'page', value: 'http://<svg onload=1>', plain: true},
  groups: [{name: '<script>g</script>', addresses: ['<q>a@x.com'], source: 'page'}, {name: '手写组', addresses: ['b@x.com'], source: 'server'}],
  alerts: {enabled: true, token: {source: 'page', state: 'set', set_at: '2026-11-02T01:00:00+00:00', value: 'SECRET-TOKEN'},
           clients: {source: 'page', values: ['<i>10.0.0.0/8']}},
  skipped: [{kind: 'group', name: '<q>坏组', reason: '<img src=y>'}], problems: [],
  server: {file: '<u>/data/automation.yaml', exists: true, keys: ['<i>mail'], groups: ['<q>手写组']},
  page: {file: '/data/automation.page.json', secrets_file: '/data/automation.page-secrets.json'},
  used_by: {'<script>g</script>': [{kind: 'schedule', id: 's1', name: '<img src=z>'}]},
  changes: [{at: '<q>t', user: '<i>u', ip: '<u>1.2.3.4', kind: '<svg>', detail: '<img src=w>'}], limits: {groups: 20}, ...over});
const asButtons = h => [...h.matchAll(/<button[^>]*data-as="([^"]+)"[^>]*>/g)].map(m => [m[1], /\bdisabled\b/.test(m[0])]);
const asHtml = A.autoSettingsHtml({settings: autoS(), mail: {configured: true}, groups: [{name: '<q>组'}], file: ''}, 'http://kb/<svg>');
check('自动执行的设置：地址、组名、原因、变更、文件名都转义', raw.test(asHtml), false);
check('自动执行的设置：授权码、令牌的值就算混进回复也不画出来', /SECRET-AUTH-CODE|SECRET-TOKEN/.test(asHtml), false);
check('自动执行的设置：收件地址、发件账号看得到', asHtml.includes('&lt;q&gt;a@x.com') && asHtml.includes('&lt;q&gt;u@x.com'), true);
check('自动执行的设置：在服务器上配置的收件组没有按钮，标出来',
  asHtml.includes('<b>手写组</b>') && !asHtml.includes('data-name="手写组"') && asHtml.includes('在服务器上配置'), true);
check('能改时：按钮都能点', asButtons(asHtml).every(([, off]) => !off), true);
const asLocked = A.autoSettingsHtml({settings: autoS({approval: {configured: true, locked: true, unlock_minutes: 9}})}, 'h');
const asOff = Object.fromEntries(asButtons(asLocked));
check('口令锁定时：要口令的灰掉', [asOff['mail-edit'], asOff['site-edit'], asOff['group-add'], asOff['token-new']], [true, true, true, true]);
check('口令锁定时：缩小能力的照常能点', [asOff['mail-clear'], asOff['site-clear'], asOff['group-del'], asOff['token-del'], asOff['skip-del']],
  [false, false, false, false, false]);
check('口令锁定时：写明原因', asLocked.includes('页面审批锁定中，9 分钟后解锁'), true);
const asReadOnly = A.autoSettingsHtml({settings: autoS({writable: {ok: false, reason: '工具服务较旧：<b>升级</b>'}})}, 'h');
check('工具服务较旧：按钮全灰，原因转义', asButtons(asReadOnly).every(([, off]) => off) && asReadOnly.includes('工具服务较旧：&lt;b&gt;升级'), true);
check('没读到设置：只能看', A.autoLocks(undefined).all, '读不到自动执行的设置');
const asToken = A.autoTokenHtml('ab'.repeat(32), 'http://kb/<svg onload=1>');
check('新令牌：地址转义', raw.test(asToken), false);
check('新令牌：令牌在复制块里', asToken.includes('<pre>' + 'ab'.repeat(32) + '</pre>'), true);
check('删收件组：选了它的计划和规则转义', raw.test(A.asUsedHtml([{name: '<img src=x>'}])), false);

// 自动检查与模型预审：检查结果、模型说的话一律转义；模型预审的标题固定；开关关着（没有 prereview）时这一块整个不出现
const checkCode = [/^const esc = .*$/m, /^const PC_ICON = .*$/m, /^const PC_VERDICT_ICON = .*$/m, /^const PRE_DISCLAIMER = .*$/m,
  /^const PRE_BUSY = .*$/m, /^const apMrHtml = .*$/m].map(lineOf)
  .concat(['precheckMark', 'precheckHtml', 'prereviewHtml', 'apPcHtml'].map(extract)).join('\n');
const C = new Function(`${checkCode}\nreturn {precheckMark, precheckHtml, prereviewHtml, apPcHtml, apMrHtml, PRE_DISCLAIMER};`)();
check('模型预审的标题固定', C.PRE_DISCLAIMER, '模型预审：仅供参考，可能出错，也可能被申请内容误导');
check('开关关着：没有模型预审这一块', C.apMrHtml(undefined), '');
check('开关开着：标题写在块上', C.apMrHtml({status: 'queued'}).includes('<h4>模型预审：仅供参考，可能出错，也可能被申请内容误导</h4>'), true);
const pc = C.precheckHtml({state: 'done', verdict: 'blocked', label: '跑不了', note: evil, at: evil,
                           checks: [{status: 'fail', title: evil, text: `${evil}"'`}, {status: 'skip', title: '/etc/shadow', text: '敏感位置，不检查'}]});
check('自动检查：标题、文字、说明都转义', pc.includes('<img'), false);
check('自动检查：结论在最上面', pc.startsWith('<div class="pc-verdict blocked">⛔ 跑不了'), true);
check('自动检查：每项一行', (pc.match(/<li /g) || []).length, 2);
check('自动检查还在做', C.precheckHtml({state: 'checking', key: 'k'}).includes('自动检查进行中'), true);
check('草稿的检查还在排队：请人过一会儿再点，不说会自动刷新',
  [C.precheckHtml({state: 'checking', key: 'k'}, '', true)].map(h => h.includes('还在排队') && h.includes('再点「检查一下」')
    && !h.includes('自动刷新'))[0], true);
check('老工具服务：写明没有自动检查', C.precheckHtml(undefined).includes('工具服务版本较旧'), true);
check('申请本身不合法：不说成老版本', C.precheckHtml(undefined, '缺少 binary').includes('批不了'), true);
check('列表上的标记', C.precheckMark({state: 'done', verdict: 'ok', label: '能用'}), ['ok', '能用']);
check('列表上：检查中', C.precheckMark({state: 'checking'}), ['checking', '检查中']);
check('列表上：老版本没有标记', C.precheckMark(undefined), null);
check('重新检查按钮只在有结果时给', C.apPcHtml({}, 'data-recheck="a"').includes('重新检查'), false);
check('重新检查按钮', C.apPcHtml({precheck: {state: 'done', verdict: 'ok', label: '能用', checks: []}}, 'data-recheck="a"')
  .includes('data-recheck="a">重新检查</button>'), true);
const mr = C.prereviewHtml({status: 'done', what: evil, model: evil, notes: [evil],
  findings: [{level: '注意', type: evil, text: evil}, {level: '提示', type: '其他', text: '小问题'}],
  duplicates: [{name: evil, label: evil}], suggestions: [evil]});
check('模型预审：模型说的每一处都转义', mr.includes('<img'), false);
check('模型预审：注意、提示分级', (mr.match(/class="lv attn"/g) || []).length + (mr.match(/class="lv tip"/g) || []).length, 2);
check('模型预审：生成中', C.prereviewHtml({status: 'queued', ahead: 2}).includes('生成中…') && C.prereviewHtml({status: 'queued', ahead: 2}).includes('前面还有 2 条'), true);
check('模型预审：在跑', C.prereviewHtml({status: 'running'}).includes('生成中…'), true);
check('模型预审：没做成写原因（转义）', C.prereviewHtml({status: 'failed', reason: evil}).includes('模型预审没做成：&lt;img'), true);
check('模型预审：跳过写原因', C.prereviewHtml({status: 'skipped', reason: '没做'}).includes('没做'), true);
check('模型预审：没有问题也不说成没有风险', C.prereviewHtml({status: 'done', findings: []}).includes('没有指出问题'), true);
check('页面上有「检查一下」和重新检查、撤回的入口', ['/api/tools/check', 'id="tlDoCheck"', '/recheck', 'data-withdraw'].every(x => html.includes(x)), true);

// 工具页「主机与数据源」：页面上加的条目能改，主配置的只读；工具服务给的每一段文字都转义；凭据只有状态，永远不显示值
const icCode = [/^const esc = .*$/m, /^const unlockIn = .*$/m, /^const TL_CONN_TYPE = .*$/m, /^const IC_SRV = .*$/m,
  /^const IC_STEP = .*$/m, /^const IC_SECRET = .*$/m, /^const IC_MODE = .*$/m, /^const IC_MODE_SHORT = .*$/m,
  /^const IC_PW_STEP = .*$/m].map(lineOf)
  .concat(['setAtText', 'hostReason', 'icSecretPill', 'icBlocked', 'icUsers', 'icHostRow', 'icConnRow', 'icMcpRow', 'icExportRow',
    'icChangeRow', 'icImpactHtml', 'icUsersBox', 'icCopy', 'icInstallHtml', 'icToolStates', 'icScanKeys',
    'icPwInstallBlocked', 'icPwResultHtml'].map(extract)).join('\n');
const IC = new Function(`${icCode}\nreturn {icSecretPill, icBlocked, icHostRow, icConnRow, icMcpRow, icExportRow, icChangeRow,
  icImpactHtml, icUsersBox, icInstallHtml, icToolStates, icScanKeys, icPwInstallBlocked, icPwResultHtml};`)();
const SECRET = 'page-db-Pass#2026-never-shown';
const cells = row => (row.match(/<td[\s>]/g) || []).length;
const labelled = row => (row.match(/<td data-l="/g) || []).length;
const pgConn = {name: 'cmdb', origin: 'page', type: 'postgres', label: evil, address: `db.example.internal:5432/${evil}`, user: evil,
  external: true, external_why: evil, driver: evil, used_by: ['cmdb_count', evil], sops: [{id: 's1', name: evil}],
  secret: {state: 'set', set_at: '2026-11-01 11:30:00', value: SECRET}, test: {label: evil}};
const connRow = IC.icConnRow(pgConn);
check('连接：服务端文字全部转义', connRow.includes('<img'), false);
check('连接：凭据只有状态，没有值', connRow.includes(SECRET), false);
check('连接：已设置', connRow.includes('已设置'), true);
check('连接：页面上加的能改、能测、能删', ['data-ic="conn"', 'data-ic="conn-test"', 'data-ic="conn-del"'].every(x => connRow.includes(x)), true);
check('连接：用到它的 SOP 也列出来', connRow.includes('SOP：&lt;img'), true);
check('连接：手机上每格都有列名（操作那格除外）', labelled(connRow), cells(connRow) - 1);
check('连接：现在不能改时修改、测试、删除灰掉并写明原因', (IC.icConnRow(pgConn, '还没设审批口令').match(/ disabled title="还没设审批口令"/g) || []).length, 3);
const mainConn = IC.icConnRow({name: 'litellm_db', origin: 'main', type: 'postgres', address: '127.0.0.1:15432/litellm', used_by: []});
check('主配置的连接：只读，标「在服务器上配置」', mainConn.includes('在服务器上配置') && !mainConn.includes('data-ic='), true);
check('凭据作废了要重新输入', IC.icSecretPill({state: 'stale'}).includes('要重新输入'), true);
check('不带凭据', IC.icSecretPill({state: 'none'}).includes('不带凭据'), true);
check('没有状态当作未设置', IC.icSecretPill(undefined).includes('未设置'), true);
const mcpRow = IC.icMcpRow({id: 'ext', origin: 'page', label: evil, transport: 'http', url: evil, online: false, reason: evil,
  discovered: evil, approved: 1, secret: {state: 'missing', value: SECRET}, external: true});
check('MCP server：转义、没有令牌的值', mcpRow.includes('<img') || mcpRow.includes(SECRET), false);
check('MCP server：页面上加的能改', mcpRow.includes('data-ic="mcp"') && mcpRow.includes('data-ic="mcp-del"'), true);
check('本机 MCP server：只读', IC.icMcpRow({id: 'local_fs', origin: 'main', transport: 'stdio', online: true}).includes('data-ic='), false);
const pageHost = {name: 'web01', origin: 'page', via: 'ssh', user: evil, address: '10.0.1.11', port: 22, mode: 'guarded', groups: [evil],
  status: {reachable: false, error: `主机 web01：${evil}`}, step: 'install', allowlist: {stale: true}};
const hostRow = IC.icHostRow(pageHost, 'local', true);
check('主机：转义（账号、分组、连不上的原因）', hostRow.includes('<img'), false);
check('主机：停在哪一步', hostRow.includes('待在目标主机上安装'), true);
check('主机：白名单变了要重新生成安装包', hostRow.includes('重新生成安装包'), true);
check('主机：页面上加的能打开', hostRow.includes('data-ic="host"'), true);
const mainHost = IC.icHostRow({name: 'gateway-b', origin: 'main', via: 'ssh', user: 'opsread', address: '150.109.244.82', port: 22,
  mode: 'guarded', groups: [], status: null}, 'gateway-b', true);
check('主配置的主机：只读、能检查连通、是默认', mainHost.includes('在服务器上配置') && mainHost.includes('data-ic="host-check"')
  && mainHost.includes('默认') && !mainHost.includes('data-ic="host"'), true);
check('老工具服务：主机一个按钮都没有', IC.icHostRow({name: 'gw', via: 'ssh', user: 'u', address: 'a', groups: []}, '', false).includes('data-ic='), false);
check('隐含的本机不标「在服务器上配置」', IC.icHostRow({name: 'local', via: 'local', groups: [], implicit: true}, 'local', true).includes('在服务器上配置'), false);
const install = IC.icInstallHtml({name: 'web01', mode: 'guarded', install: {authorized_keys: `restrict,from="1.2.3.4" ${evil}`,
  account: ['useradd -M opsread', evil], install: 'tar -xzf x.tgz && sh web01/install.sh'},
  bundle: {file: '/opt/ops/page-bundles/web01.tgz', sha256: 'ab'.repeat(32), version: 'sha256:' + 'c'.repeat(64), generated_at: '2026-11-01 11:30:00'},
  allowlist: {expected: 'sha256:' + 'd'.repeat(64)}}, 'python3 /opt/ops/ops_readonly.py host-info');
check('安装：authorized_keys、建账号的命令转义后显示', install.includes('<img') || !install.includes('restrict,from=&quot;1.2.3.4&quot;'), false);
check('安装：写明在 A 上 sha256sum 对照', install.includes('sha256sum /opt/ops/page-bundles/web01.tgz'), true);
check('安装：写明命令行 host-info 对照', install.includes('python3 /opt/ops/ops_readonly.py host-info web01'), true);
check('安装：安装包的白名单旧了要重新生成', install.includes('和现在的不一致'), true);
const direct = IC.icInstallHtml({name: 'db01', mode: 'direct', install: {authorized_keys: 'restrict x', account: []}}, '');
check('直连模式：没有安装包', direct.includes('安装包'), false);
const exportOn = IC.icExportRow({tool: 'prom_up', label: evil, group: evil, export: true, page: 'on', enabled: true}, true);
check('对外开放：转义、开着', !exportOn.includes('<img') && exportOn.includes(' checked') && exportOn.includes('页面上打开的'), true);
check('对外开放：页面配置关了时开关灰掉', IC.icExportRow({tool: 'x', export: false}, false).includes(' disabled'), true);
check('对外开放：定义变了，已暂停', IC.icExportRow({tool: 'x', page: 'stale'}, true).includes('已暂停'), true);
check('变更记录转义', IC.icChangeRow({action: evil, target: evil, detail: evil, at: evil, caller: evil}).includes('<img'), false);
check('target 会变的工具和 SOP 转义', IC.icImpactHtml([{tool: evil, label: evil, text: evil, sops: [{name: evil}]}], evil).includes('<img'), false);
check('没有要确认的就什么都不显示', IC.icImpactHtml([], 'x') + IC.icUsersBox([], [], 'x'), '');
check('检查连通：逐个工具转义', IC.icToolStates({checks: [{tools: {[evil]: {state: 'no', reason: evil}}}]}).includes('<img'), false);
const grouped = IC.icToolStates({checks: [{tools: {a: {state: 'unknown', reason: '主机 web03：连不上'},
  b: {state: 'unknown', reason: '主机 web03：连不上'}, c: {state: 'ok', reason: ''}}}]}, 'web03');
check('检查连通：原因一样的并成一行，去掉重复的主机名', [(grouped.match(/<li>/g) || []).length, grouped.includes('a、b：连不上')], [2, true]);
check('扫到的 host key', IC.icScanKeys({checks: [{status: 'ok'}, {keys: [{type: 'ssh-ed25519', fingerprint: 'SHA256:x'}]}]}).length, 1);
const ap = {configured: true, max_failures: 5, lock_minutes: 15};
const live = {supported: true, enabled: true, readable: true};
check('能改', IC.icBlocked(live, ap), '');
check('老工具服务', IC.icBlocked({supported: false, error: '工具服务较旧'}, ap), '工具服务较旧');
check('宿主机上关了', IC.icBlocked({...live, enabled: false}, ap).includes('OPS_PAGE_CONFIG=off'), true);
check('旁路文件读不了', IC.icBlocked({...live, readable: false}, ap).includes('读不了'), true);
check('没设口令', IC.icBlocked(live, {configured: false}).includes('还没设审批口令'), true);
check('锁定中', IC.icBlocked(live, {...ap, locked: true, unlock_minutes: 7}).includes('7 分钟后解锁'), true);
check('页面上的动作都走 /api/tools/config', ['connection-save', 'connection-test', 'mcp-save', 'mcp-test', 'export', 'host-save',
  'host-trust', 'host-delete', 'host-scan', 'host-check', 'host-bundle', 'host-install'].every(a => html.includes(`'/api/tools/config/${a}'`))
  && html.includes("`/api/tools/config/${kind === 'conn' ? 'connection' : 'mcp'}-delete`"), true);
check('口令、凭据不进 localStorage', /localStorage\.setItem\([^)]*(secret|token|password)/i.test(html), false);
// 用密码自动安装：不是本机打开的页面、没核对 host key、工具服务不支持时按钮灰掉并写原因；结果里服务端来的文字一律转义
const pwHost = {os: 'linux', install: {authorized_keys: 'restrict ssh-ed25519 AAAA'}};
const pwLive = {password_install: {supported: true, local: true}};
check('用密码安装：本机打开、已核对时可用', IC.icPwInstallBlocked(pwLive, pwHost, '', true), '');
check('用密码安装：不是本机打开的页面不能用', IC.icPwInstallBlocked({password_install: {supported: true, local: false, local_why: '请经 SSH 隧道打开页面'}}, pwHost, '', true),
  '请经 SSH 隧道打开页面');
check('用密码安装：老工具服务', IC.icPwInstallBlocked({}, pwHost, '', true), '工具服务较旧，没有这个功能');
check('用密码安装：没核对 host key 不能用', IC.icPwInstallBlocked(pwLive, pwHost, '', false).includes('host key'), true);
check('用密码安装：只支持 Linux', IC.icPwInstallBlocked(pwLive, {...pwHost, os: 'darwin'}, '', true).includes('Linux'), true);
check('用密码安装：没设口令时跟着灰掉', IC.icPwInstallBlocked(pwLive, pwHost, '还没设审批口令', true), '还没设审批口令');
const pwr = IC.icPwResultHtml({ok: false, login: evil, error: evil, password_sent: false, steps: [
  {status: 'ok', title: evil, command: evil, output: evil, code: 0}, {status: 'fail', title: 'x', text: evil, hidden: true}]});
check('用密码安装：结果逐步转义', pwr.includes('<img'), false);
check('用密码安装：密码没发出去要说', pwr.includes('密码没有发出去'), true);
check('用密码安装：输出可能带密码时不显示', pwr.includes('不显示，只给退出码'), true);
check('用密码安装：密码框不让浏览器记住，提交时立即取出清空',
  [html.includes('<input type="password" data-f="password" autocomplete="new-password"'),
   /const password = icTake\(wrap, '\[data-f="password"\]'\);[\s\S]{0,400}postJson\('\/api\/tools\/config\/host-install'/.test(html)], [true, true]);
check('不拿「口令一泄露」当理由：审批口令本来就等同 root，页面上照实写', [html.includes('口令一泄露'),
  html.includes('审批口令等同工具服务那台机器的 root')], [false, true]);
check('MySQL 的 disable 写「不要求加密」（服务器支持时 PyMySQL 会顺带加密），TLS 下面说清 require 不防冒充',
  [html.includes("['disable', 'disable（不要求加密）'], ['require'"), html.includes('require 只防窃听，不防冒充；跨公网请用 verify')],
  [true, true]);

// 云上协同：对外接入页的卡片、计划和告警规则表单里的推送下拉、对话列表的来源。服务端来的名字、粘贴行、问题一律转义；
// 没打开时（/api/chat/notify 是 404）表单里没有推送这一项，对话列表没有筛选（由 /api/conversations 带不带 chat 决定）
const chatCode = [/^const esc = .*$/m, /^const shortTime = .*$/m, /^const NOTIFY_WHEN = .*$/m, /^const NOTIFY_REPEAT = .*$/m,
  /^const CHAT_STATE = .*$/m, /^const CHAT_TYPE = .*$/m, /^const PUSH_STATUS = .*$/m].map(lineOf)
  .concat(['chatScopes', 'chatCardHtml', 'chatNotifyRows'].map(extract)).join('\n');
const CH = state => new Function('autoState', `${chatCode}\nreturn {chatCardHtml, chatNotifyRows};`)(state);
const at = '2026-11-02T01:00:00Z';
const chatCard = CH({}).chatCardHtml({problem: '', problems: [evil],
  bridge: {reachable: true, state: 'connected', since: at, tls: true, send: true, robot: '…8765', targets: [evil],
           target_kinds: {[evil]: 'chat'}, problems: [evil]},
  channel: {state: 'ok', last_poll: at, inflight: 0},
  config: {groups: [{name: evil, tools: [evil], categories: [evil], mode: 'kb', web: false}], people: [], contact: evil,
           limits: {person_per_hour: 20}, digest: [{target: evil}], file: evil, exists: true},
  unknown: [{last_at: at, chat_type: 'group', chat_name: evil, sender_name: evil, count: 2, paste: {chat_yaml: evil, targets_yaml: evil}}],
  pushes: [{created_at: at, kind: 'run', target: evil, status: 'failed', detail: evil}]});
check('云上协同卡片：名字、工具、问题、粘贴行、推送结果都转义', chatCard.includes('<img'), false);
check('云上协同卡片：连着、能发时测试按钮可点', [chatCard.includes('已连接'), /data-chattest\s*>/.test(chatCard)], [true, true]);
const chatDown = CH({}).chatCardHtml({bridge: {reachable: false, error: '连不上转接程序：ConnectionRefusedError'}, config: {},
  unknown: [], pushes: []});
check('转接程序连不上：写明原因，测试按钮灰掉', [chatDown.includes('ConnectionRefusedError'), /data-chattest disabled>/.test(chatDown)],
  [true, true]);
check('没打开云上协同：表单里没有推送这一项', CH({chat: null}).chatNotifyRows('schedule', 's1'), '');
const chatRows = CH({chat: {targets: [evil, '王某某'], target_kinds: {'王某某': 'user'}, error: evil,
  items: [{kind: 'schedule', id: 's1', target: '已删的目标', when: 'always', repeat: 'never'}]}}).chatNotifyRows('schedule', 's1');
check('推送下拉：目标名转义、配置里删掉的目标照样显示、个人标出来',
  [chatRows.includes('<img'), chatRows.includes('value="已删的目标" selected'), chatRows.includes('王某某（个人）')], [false, true, true]);
check('推送下拉：沿用邮件那一套 when / repeat', [chatRows.includes('value="always" selected'), chatRows.includes('value="never" selected')],
  [true, true]);
check('对话列表：群聊对话的来源名转义', html.includes('💬 ${esc(c.source.chat_name)}'), true);
check('群聊的对话网页上只读：不显示输入框和「重新回答」，发送也挡住', [html.includes('#pg-chat.readonly .composer, #pg-chat.readonly [data-retry] { display: none; }'),
  html.includes("$('askBtn').disabled || $('pg-chat').classList.contains('readonly')")], [true, true]);
check('执行记录：触发方式有「💬 群聊」', lineOf(/^const TRIGGER = .*$/m).includes("chat: ['💬', '群聊']"), true);
check('云上协同的卡片和下拉不用全局的 .box、.ex', /class="(box|ex)"/.test(chatCard + chatRows), false);

// ---------- 搜索框：输入法组字期间不搜，组字结束后防抖搜一次；所有搜索框都经 searchInput 接 ----------
{
  const {searchInput} = load('searchInput');
  // 假的事件源 + 假的定时器：按顺序派发事件，手动推进时间
  const makeRoot = () => { const ls = {}; return {ls, addEventListener: (type, fn) => (ls[type] ||= []).push(fn),
    fire(type, ev) { (ls[type] || []).forEach(fn => fn({type, ...ev})); }}; };
  let now = 0, timers = [];
  const realSet = global.setTimeout, realClear = global.clearTimeout;
  global.setTimeout = (fn, ms) => { const t = {fn, at: now + ms}; timers.push(t); return t; };
  global.clearTimeout = t => { timers = timers.filter(x => x !== t); };
  const tick = ms => { now += ms; const due = timers.filter(t => t.at <= now); timers = timers.filter(t => t.at > now); due.forEach(t => t.fn()); };
  const el = {id: 'mSearch', value: ''};
  const setup = () => { const root = makeRoot(), runs = []; now = 0; timers = [];
    searchInput(root, x => x.id === 'mSearch', x => runs.push(x.value), 250); return {root, runs}; };
  const typePinyin = (root, finalValue, chromeOrder) => {
    root.fire('compositionstart', {target: el});
    for (const v of ['n', 'ni', 'nih', 'niha', 'nihao']) { el.value = v; root.fire('input', {target: el, isComposing: true}); tick(300); }
    el.value = finalValue;
    if (chromeOrder) { root.fire('input', {target: el, isComposing: true}); root.fire('compositionend', {target: el}); }
    else { root.fire('compositionend', {target: el}); root.fire('input', {target: el, isComposing: false}); }
  };
  for (const [label, chrome] of [['Chrome 顺序（input 在 compositionend 之前）', true], ['Firefox 顺序（compositionend 在 input 之前）', false]]) {
    const {root, runs} = setup();
    typePinyin(root, '你好', chrome);
    check(`${label}：组字期间一次都不搜`, runs, []);
    tick(300);
    check(`${label}：组字结束后只搜一次，搜的是选好的汉字`, runs, ['你好']);
  }
  {
    const {root, runs} = setup();
    el.value = 'disk'; root.fire('input', {target: el}); tick(100);
    root.fire('compositionstart', {target: el});               // 防抖还没到，开始打中文：取消这一次
    tick(500);
    check('开始组字时取消还没跑的那次搜索', runs, []);
    el.value = 'disk 磁盘'; root.fire('compositionend', {target: el}); tick(300);
    check('组字结束后搜完整的内容', runs, ['disk 磁盘']);
  }
  {
    const {root, runs} = setup();
    for (const v of ['d', 'di', 'dis', 'disk']) { el.value = v; root.fire('input', {target: el}); tick(100); }
    tick(300);
    check('英文照常防抖：连着打只搜最后一次', runs, ['disk']);
    root.fire('compositionstart', {target: el}); el.value = 'diskc';
    root.fire('keydown', {target: el, key: 'Enter', isComposing: true});
    check('组字时按回车（选字）不搜', runs, ['disk']);
    root.fire('focusout', {target: el});                       // 组字中途输入框没了：不会从此再也不搜
    el.value = 'cpu'; root.fire('keydown', {target: el, key: 'Enter'});
    check('回车立即搜；失焦清掉组字标记', runs, ['disk', 'cpu']);
    root.fire('input', {target: {id: 'other', value: 'x'}}); tick(300);
    check('别的输入框不触发', runs, ['disk', 'cpu']);
  }
  global.setTimeout = realSet; global.clearTimeout = realClear;

  // 静态检查：页面上每个搜索 / 筛选框都经 searchInput 接上，没有直接挂 input 监听去搜的
  const code = scripts.join('\n');
  const boxes = [...html.matchAll(/<input\b[^>]*>/g)].map(m => m[0])
    .filter(tag => /type="search"|placeholder="[^"]*(搜索|筛选|过滤|查找)/.test(tag))
    .map(tag => (tag.match(/id="([^"]+)"/) || [])[1]);
  check('页面上的搜索框都有 id', boxes.every(Boolean) && boxes.length >= 2, true);
  for (const id of boxes) {
    check(`搜索框 #${id} 经 searchInput 接上`, new RegExp(`searchInput\\([^;]*el\\.id === '${id}'`).test(code), true);
    check(`搜索框 #${id} 没有另挂 input 监听`, new RegExp(`addEventListener\\('input'[^]{0,120}${id}`).test(code), false);
  }
  check('文档 / SOP / 工具的搜索不再重建输入框', code.includes("kept.dataset.tab === mTab"), true);
  check('选文档的筛选框按回车时不在组字', code.includes("e.target.id === 'pbDocFilter' && e.key === 'Enter' && !e.isComposing"), true);
}

// ---------- 对外接入：总开关、删令牌、清除调用记录、操作记录；分类维护的影响预览 ----------
{
  const AX = new Function([/^const esc = .*$/m, /^const axTime = .*$/m, /^const AX_CHANGE = .*$/m, /^const TOKEN_STATE = .*$/m].map(lineOf)
    .concat(['axCats', 'axSwitchHtml', 'axChangesHtml', 'catImpactHtml', 'catListHtml'].map(extract)).join('\n')
    + `\nconst CAT_NOTE = '网络补充', CAT_DEFAULT = '未分类';\nreturn {axCats, axSwitchHtml, axChangesHtml, catImpactHtml, catListHtml};`)();
  check('白名单：null 是全部、空的是一篇都看不到', [AX.axCats(null), AX.axCats([]).includes('无（分类已删除）'), AX.axCats([evil]).includes('<img')],
    ['全部', true, false]);
  const on = AX.axSwitchHtml({on: true, at: null});
  check('开着：有「关闭」按钮，不要口令', [on.includes('id="axOff"'), on.includes('axOn')], [true, false]);
  const off = AX.axSwitchHtml({on: false, at: '2026-11-02T08:00:00+00:00', ip: evil, user: 'tester', reopen: ''});
  check('关着：「重新打开…」可点，来源地址转义，写了宿主机上的逃生口',
    [/id="axOn" class="pri" >/.test(off), off.includes('<img'), off.includes('python -m app.access open')], [true, false, true]);
  const oldSvc = AX.axSwitchHtml({on: false, at: null, reopen: evil});
  check('工具服务较旧：「重新打开」灰掉、原因转义', [/id="axOn" class="pri" disabled>/.test(oldSvc), oldSvc.includes('<img')], [true, false]);
  const changes = AX.axChangesHtml([{at: '2026-11-02T08:00:00+00:00', kind: 'calls-purge', detail: evil, count: 3, user: evil, ip: evil}]);
  check('操作记录：内容、人、地址都转义；写着页面上删不掉', [changes.includes('<img'), changes.includes('清除调用记录'), changes.includes('删不掉'),
    /data-\w*del|删除<\/button>/.test(changes)], [false, true, true, false]);
  const impact = AX.catImpactHtml({action: 'rename', from: evil, to: evil, merge: true, documents: [evil], needs_passphrase: true, chat_file: evil,
    tokens: [{name: evil, status: 'revoked', before: [evil], after: [], gained: 2, lost: 0}],
    chat: [{name: evil, categories: [evil], gained: 1, lost: 0}]});
  check('分类预览：名字、文档、令牌、群都转义', impact.includes('<img'), false);
  check('分类预览：多看到的标红、白名单去空写明、要口令时说清楚', [impact.includes('多看到 2 篇'), impact.includes('一篇都看不到'),
    impact.includes('要输审批口令'), impact.includes('合并到已有的')], [true, true, true, true]);
  const list = AX.catListHtml([['网络补充', 2], ['未分类', 1], [evil, 3]]);
  check('分类列表：网络补充不能改、未分类不能删、名字转义', [/data-catren="网络补充"/.test(list), /data-catdel="未分类"/.test(list),
    list.includes('<img')], [false, false, false]);
  const GRP = new Function(`${lineOf(/^const esc = .*$/m)}\n${extract('grpListHtml')}\nreturn grpListHtml;`)();
  check('工具分组列表：分组名转义', GRP([{name: evil, total: 2}]).includes('<img'), false);
  check('工具卡片：分组的输入框和下拉提示都转义', /value="\$\{esc\(t\.group \|\| ''\)\}"/.test(html) && html.includes('`<option value="${esc(g)}">`'), true);
  check('工具卡片：主配置里的分组转义', html.includes("主配置里是「${esc(t.group_base || '其他')}」"), true);
}

console.log(`\n${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);

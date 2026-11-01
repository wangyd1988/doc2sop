// 页面（app/web/index.html）的检查：内联脚本能编译；几个纯函数的行为（风险提示的措辞、主机原因去重、参数范围转义、
// 审批口令卡片在各个状态下给的表单和说明、工作台「待处理」里的「还没设审批口令」）。
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

console.log(`\n${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);

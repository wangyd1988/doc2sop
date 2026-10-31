// 页面（app/web/index.html）的检查：内联脚本能编译；几个纯函数的行为（风险提示的措辞、主机原因去重）。
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

console.log(`\n${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);

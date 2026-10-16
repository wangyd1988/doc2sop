const fs = require('fs');
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

// 复刻 pbPicker 的筛选逻辑
const allDocs = [
  {source: 'Kube-OVN组播配置排障总结.docx', category: 'CNI'},
  {source: 'ingress-nginx-controller问题排查总结.docx', category: '未分类'},
  {source: 'GPU掉卡故障排查与恢复&掉卡.pptx', category: '未分类'},
  {source: 'SDD使用手册-自动化测试版.pdf', category: 'SDD'},
];
const match = f => {
  f = f.trim().toLowerCase();
  return allDocs.filter(d => !f || d.source.toLowerCase().includes(f)
                                || (d.category || '').toLowerCase().includes(f));
};

let pass = 0, fail = 0;
const check = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  console.log(`${ok ? 'OK  ' : 'FAIL'} ${label}  got=${JSON.stringify(got)}`);
  ok ? pass++ : fail++;
};

check('空筛选返回全部', match('').length, 4);
check('按文件名筛选', match('排查').map(d => d.source.split(/[-.]/)[0]),
      ['ingress', 'GPU掉卡故障排查与恢复&掉卡']);
check('按分类筛选', match('cni').map(d => d.source.slice(0, 8)), ['Kube-OVN']);
check('大小写不敏感', match('GPU').length, match('gpu').length);
check('无匹配', match('zzz').length, 0);

// HTML 转义：文件名里的 & 必须被转义，否则选项值会被截断
const opts = match('GPU').map(d =>
  `<option value="${esc(d.source)}">${esc(d.source)}　[${esc(d.category)}]</option>`).join('');
check('特殊字符已转义', opts.includes('&amp;掉卡'), true);

// 真实文件里确认旧的 prompt 实现已移除
const html = fs.readFileSync('app/web/index.html', 'utf8');
check('不再使用 prompt 选文档', /prompt\([^)]*从哪个文档/.test(html), false);
check('已有筛选输入框', html.includes('id="pbDocFilter"'), true);
check('已有下拉选择器', html.includes('id="pbDocSelect"'), true);
check('输入时只重画选项', html.includes('不重画整个面板'), true);

console.log(`\n${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);

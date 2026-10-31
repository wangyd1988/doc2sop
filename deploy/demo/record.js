#!/usr/bin/env node
/* 演示 GIF 无头录制（见 docs/五分钟演示.md「录制 GIF」）。

   对着跑起来的演示站走两幕。画面用 Chromium 的 Page.startScreencast 抓无损 PNG 帧（和 Playwright 自带录像
   同一机制，只是不经过它那路 1 Mbps 的 VP8 有损编码——有损噪点会让 GIF 体积翻倍、文字发糊），脚本一边操作
   一边记关键时刻，录完用 ffmpeg 按这些时刻裁剪、变速、结尾定格，再两遍法（palettegen → paletteuse）转 GIF，
   按「1280@12 → 1280@10 → 960@12 → 960@10 → 960@10/128 色」的阶梯保证每个 GIF ≤ 4 MB。

   用法  node deploy/demo/record.js [--scene sop|grow|all] [--out docs/media] [--sidebar] [--reuse]
         --sidebar  录进左侧导航（默认用注入的 CSS 隐藏它，让对话区在 720p 里更大）
         --reuse    不重录，用 <out>/raw/ 里上次的素材和时刻记录只重做剪辑与 GIF（调时长 / 体积参数用）
   环境  DEMO_URL / DEMO_USER / DEMO_PASSWORD   演示站地址与 Basic 登录；只从环境变量读，不进日志
         PWCORE                                 可选，playwright-core 的安装目录；不设就 require('playwright-core')
   依赖  Node ≥ 18、playwright-core + Chromium、PATH 里的 ffmpeg 与 ffprobe
   退出  0 成功；1 录制断言不满足（不出 GIF，素材留在 <out>/raw/）；2 参数 / 环境 / 预检问题

   第二幕要从「还没有从实践沉淀的 SOP」的状态开始：保存过一次后同样的问题不会再出 💡 卡片，
   每次完整重录前先重置演示数据（docker compose down → 删 data → up，等场景包重新导入）。 */
'use strict';
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const REPO = path.resolve(__dirname, '..', '..');
const argv = process.argv.slice(2);
const opt = (name, dflt) => { const i = argv.indexOf(name); return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : dflt; };
const SCENE = opt('--scene', 'all');
const OUT = path.resolve(opt('--out', path.join(REPO, 'docs', 'media')));
const SIDEBAR = argv.includes('--sidebar');
const REUSE = argv.includes('--reuse');
if (argv.includes('--help') || argv.includes('-h') || !['sop', 'grow', 'all'].includes(SCENE)) {
  console.error('用法：node deploy/demo/record.js [--scene sop|grow|all] [--out docs/media] [--sidebar] [--reuse]\n'
              + '环境：DEMO_URL DEMO_USER DEMO_PASSWORD，可选 PWCORE');
  process.exit(argv.includes('--help') || argv.includes('-h') ? 0 : 2);
}

class PreflightError extends Error {}   // 环境 / 参数 / 演示站状态问题 → exit 2
class RecordError extends Error {}      // 录到的内容不满足断言 → exit 1，不出 GIF

const BASE = (process.env.DEMO_URL || '').trim().replace(/\/+$/, '');
const USER = process.env.DEMO_USER || '';
const PASS = process.env.DEMO_PASSWORD || '';
if (!BASE || !USER || !PASS) {
  console.error('缺少环境变量：DEMO_URL / DEMO_USER / DEMO_PASSWORD 都要设置');
  process.exit(2);
}
let pw;
try { pw = require(process.env.PWCORE || 'playwright-core'); }
catch (e) {
  console.error('加载不到 playwright-core：npm i --no-save playwright-core && npx playwright-core install chromium，'
              + '或把 PWCORE 指向已有的 playwright-core 目录。原始错误：' + e.message);
  process.exit(2);
}
for (const bin of ['ffmpeg', 'ffprobe']) {
  const r = spawnSync(bin, ['-version'], { encoding: 'utf8' });
  if (r.error || r.status !== 0) { console.error(`PATH 里找不到 ${bin}`); process.exit(2); }
}

const VIEW = { width: 1280, height: 720 };
const ZOOM = SIDEBAR ? 1.15 : 1.25;          // 相当于浏览器缩放：抓帧按 CSS 像素，放大内容让 720p 里的字看得清
const CAP_FPS = 15;                          // 抓帧上限；GIF 最多 12 fps，再多只是占磁盘
const TARGET = 19, MAX_LEN = 20, HOLD = 3.5;  // 秒：目标总长、上限、结尾定格
const MAX_BYTES = 4_000_000;                  // 「≤ 4 MB」按十进制算，MiB 口径下更宽松
const LADDER = [[1280, 12, 256], [1280, 10, 256], [960, 12, 256], [960, 10, 256], [960, 10, 128]];
const LOSSLESS = ['-c:v', 'libx264rgb', '-qp', '0', '-preset', 'ultrafast'];   // 中间片全程无损，GIF 前不引入任何噪点
const RAW = path.join(OUT, 'raw');
const GIF_NAME = { sop: 'demo-sop.gif', grow: 'demo-grow.gif' };

const T0 = Date.now();
const log = (...a) => console.log(`[${((Date.now() - T0) / 1000).toFixed(1).padStart(6)}s]`, ...a);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const safeBase = (() => { try { const u = new URL(BASE); return u.origin + u.pathname.replace(/\/$/, ''); } catch { return '(DEMO_URL 不是合法 URL)'; } })();

/* ---------- 演示站接口（预检与诊断用） ---------- */
const AUTH = 'Basic ' + Buffer.from(`${USER}:${PASS}`).toString('base64');
class Unreachable extends PreflightError {}
async function api(p) {
  let r;
  try { r = await fetch(BASE + p, { headers: { Authorization: AUTH } }); }
  catch (e) { throw new Unreachable(`连不上演示站 ${safeBase}：${e.message}`); }
  if (r.status === 401) throw new PreflightError('演示站返回 401：DEMO_USER / DEMO_PASSWORD 不对');
  if (r.status >= 500) throw new Unreachable(`演示站返回 ${r.status}（可能还在启动）`);
  if (!r.ok) throw new PreflightError(`GET ${p} 返回 ${r.status}`);
  return r.json();
}
/* 自动导入的场景包都 imported 了才有首屏示例问题可点；刚重置完容器还在起、包还在导，这里都等。 */
async function waitPacks(timeoutMs = 180000) {
  const t = Date.now();
  let last = '';
  for (;;) {
    let d;
    try { d = await api('/api/packs'); }
    catch (e) {
      if (!(e instanceof Unreachable) || Date.now() - t > timeoutMs) throw e;
      if (last !== 'down') { log('演示站还没起来，等它…'); last = 'down'; }
      await sleep(3000);
      continue;
    }
    const auto = (d.packs || []).filter(p => p.auto);
    const bad = auto.find(p => p.phase === 'failed' || p.phase === 'invalid');
    if (bad) throw new PreflightError(`场景包 ${bad.id} ${bad.phase === 'failed' ? '导入失败' : '无效'}：${bad.note || (bad.problems || []).join('；')}`);
    const line = auto.map(p => `${p.id}=${p.phase}`).join(' ') || '（没有自动导入的场景包）';
    if (line !== last) { log('场景包：' + line); last = line; }
    if (auto.length && auto.every(p => p.phase === 'imported')) return;
    if (!auto.length) throw new PreflightError('演示站没有配置自动导入的场景包（DEMO_PACKS），首屏不会有示例问题');
    if (Date.now() - t > timeoutMs) throw new PreflightError('等场景包导入超时');
    await sleep(3000);
  }
}
async function checkGrowReady() {
  const d = await api('/api/playbooks');
  const practice = (d.origins || {}).practice || 0;
  if (practice) throw new PreflightError(`第二幕要从没有「从实践沉淀」SOP 的状态开始，现在已有 ${practice} 个：先重置演示数据再录`);
  if (d.pending) log(`提示：还有 ${d.pending} 条待确认提议，SOP 页的「待确认提议」里会多出几条`);
}

/* ---------- 注进页面的字幕层 / 侧栏隐藏 / 收尾裁剪 ---------- */
const OVERLAY_CSS = `
#__cap{position:fixed;left:50%;bottom:46px;transform:translateX(-50%);max-width:94vw;padding:9px 20px;border-radius:12px;
  background:rgba(17,24,39,.86);color:#fff;font:600 21px/1.5 "Microsoft YaHei","PingFang SC",system-ui,sans-serif;letter-spacing:.3px;
  text-align:center;z-index:2147483647;opacity:0;transition:opacity .3s;pointer-events:none;box-shadow:0 8px 24px rgba(0,0,0,.3);white-space:nowrap}
#__cap.on{opacity:1}
#__cap b{color:#fbbf24}
#chat{scroll-behavior:auto !important}`;   /* 平滑滚动的每一帧都是整幅重绘，GIF 里最费字节；录制时改成瞬时滚动 */
const HIDE_ASIDE_CSS = `#side,#scrim{display:none !important}`;

function initScript({ css, zoom }) {
  const ensure = () => {
    if (!document.documentElement || document.getElementById('__cap')) return;
    document.documentElement.style.zoom = String(zoom);
    const st = document.createElement('style'); st.textContent = css;
    const cap = document.createElement('div'); cap.id = '__cap';
    document.documentElement.append(st, cap);
  };
  window.__cap = html => {
    ensure();
    const c = document.getElementById('__cap');
    if (!html) return c.classList.remove('on');
    c.innerHTML = html; c.classList.add('on');
  };
  // 第一幕收尾：结论粗体出现后，把最后一条回答里结论段之后的块隐藏掉（只影响画面；回答每次重绘后再套一遍）
  window.__clampAfter = pattern => {
    const re = new RegExp(pattern);
    const apply = () => {
      const bots = document.querySelectorAll('.bot');
      const ans = bots.length && bots[bots.length - 1].querySelector('.answer');
      if (!ans) return;
      const hit = [...ans.querySelectorAll('strong')].find(s => !s.closest('table') && re.test(s.textContent));
      if (!hit) return;
      let node = hit;
      while (node.parentElement && node.parentElement !== ans) node = node.parentElement;
      for (let sib = node.nextElementSibling; sib; sib = sib.nextElementSibling) sib.style.display = 'none';
    };
    apply();
    new MutationObserver(apply).observe(document.getElementById('thread'), { childList: true, subtree: true });
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', ensure); else ensure();
}

/* ---------- 一幕 = 一个 context，一段抓帧 ---------- */
async function record(browser, name, scene) {
  const framesDir = path.join(RAW, `${name}.frames`);
  fs.rmSync(framesDir, { recursive: true, force: true });
  fs.mkdirSync(framesDir, { recursive: true });
  const ctx = await browser.newContext({
    viewport: VIEW, deviceScaleFactor: 1, colorScheme: 'light', locale: 'zh-CN', timezoneId: 'Asia/Shanghai',
    httpCredentials: { username: USER, password: PASS },
  });
  await ctx.addInitScript(initScript, { css: OVERLAY_CSS + (SIDEBAR ? '' : HIDE_ASIDE_CSS), zoom: ZOOM });
  const page = await ctx.newPage();
  page.setDefaultTimeout(30000);
  const t0 = Date.now();
  // 抓帧：页面有重绘才来一帧，附带的 timestamp 是墙钟，和下面 mark 记的时刻天然对齐
  const frames = [], writes = [];
  let lastKept = -Infinity;
  const cdp = await ctx.newCDPSession(page);
  cdp.on('Page.screencastFrame', ({ data, metadata, sessionId }) => {
    cdp.send('Page.screencastFrameAck', { sessionId }).catch(() => {});
    const ms = metadata && metadata.timestamp > 1e9 ? metadata.timestamp * 1000 : Date.now();
    const t = (ms - t0) / 1000;
    if (t - lastKept < 1 / CAP_FPS) return;
    lastKept = t;
    const file = path.join(framesDir, `f${String(frames.length).padStart(5, '0')}.png`);
    frames.push({ t, file });
    writes.push(fs.promises.writeFile(file, Buffer.from(data, 'base64')));
  });
  await cdp.send('Page.startScreencast', { format: 'png', everyNthFrame: 1 });
  const marks = {};
  const h = {
    page, marks,
    mark: k => { marks[k] = (Date.now() - t0) / 1000; log('  ·', k, marks[k].toFixed(1) + 's'); },
    cap: html => page.evaluate(x => window.__cap(x), html),
    toBottom: () => page.evaluate(() => { const c = document.getElementById('chat'); c.scrollTop = c.scrollHeight; }),
    // 把最后一条回答的卡片顶到聊天区顶部：标题、表格、结论一屏看全
    toCard: () => page.evaluate(() => {
      const cards = document.querySelectorAll('.bot .card');
      const card = cards[cards.length - 1], c = document.getElementById('chat');
      if (card) c.scrollTop += card.getBoundingClientRect().top - c.getBoundingClientRect().top - 14;
    }),
    // 观察最后一条回答：工具卡数、正文（含被隐藏的部分）、表格外的粗体、是否结束
    state: () => page.evaluate(() => {
      const bots = document.querySelectorAll('.bot');
      const bot = bots[bots.length - 1];
      const ans = bot && bot.querySelector('.answer');
      return {
        steps: bot ? bot.querySelectorAll('.step').length : 0,
        text: ans ? ans.textContent : '',
        strongs: ans ? [...ans.querySelectorAll('strong')].filter(s => !s.closest('table')).map(s => s.textContent) : [],
        done: !document.getElementById('askBtn').disabled,
        exec: bot ? bot.dataset.exec || '' : '',
      };
    }),
  };
  let err;
  try { await scene(h); }
  catch (e) {
    err = e;
    try { await page.screenshot({ path: path.join(RAW, `${name}.error.png`) }); } catch (_) { /* 页面可能已经没了 */ }
  }
  const wall = (Date.now() - t0) / 1000;
  await cdp.send('Page.stopScreencast').catch(() => {});
  await Promise.all(writes);
  await ctx.close();
  if (frames.length < 2) throw new RecordError(`${name}: 没抓到画面帧`);
  // 帧序列 → 25 fps 无损视频：每帧停留到下一帧为止，最后一帧停留到收尾
  const q = p => `'${p.replace(/\\/g, '/').replace(/'/g, "'\\''")}'`;
  const list = frames.map((f, i) => `file ${q(f.file)}\nduration ${((i + 1 < frames.length ? frames[i + 1].t : wall) - f.t).toFixed(4)}`)
    .concat([`file ${q(frames[frames.length - 1].file)}`]).join('\n');
  const listFile = path.join(RAW, `${name}.frames.txt`);
  fs.writeFileSync(listFile, list);
  const full = path.join(RAW, `${name}.full.mkv`);
  run('ffmpeg', ['-y', '-v', 'error', '-f', 'concat', '-safe', '0', '-i', listFile, '-vf', 'fps=25', ...LOSSLESS, full]);
  fs.rmSync(framesDir, { recursive: true, force: true });
  fs.rmSync(listFile, { force: true });
  const rec = { name, full, marks, wall, videoStart: frames[0].t, frames: frames.length };
  fs.writeFileSync(path.join(RAW, `${name}.marks.json`), JSON.stringify({ ...rec, error: err ? err.message : null }, null, 2));
  log(`${name}: 抓到 ${frames.length} 帧，${(wall - frames[0].t).toFixed(1)} s`);
  if (err) throw err;
  return rec;
}

/* 等一条回答走完，顺手记下：每张工具卡、第一个字、（第一幕）结论粗体与后续提醒出现的时刻。 */
async function watchAnswer(h, { conclusion, follow, caption } = {}, timeoutMs = 180000) {
  const deadline = Date.now() + timeoutMs;
  const onConclusion = async () => {
    h.mark('strong');
    await h.page.evaluate(p => window.__clampAfter(p), conclusion.source);
    await h.toCard();
    if (caption) await h.cap(caption);
  };
  let st, steps = 0;
  while (Date.now() < deadline) {
    st = await h.state();
    while (steps < st.steps) h.mark(`step${++steps}`);
    if (st.text && !h.marks.firstDelta) h.mark('firstDelta');
    if (conclusion && !h.marks.strong && st.strongs.some(s => conclusion.test(s))) await onConclusion();
    if (follow && !h.marks.follow && follow.test(st.text)) h.mark('follow');
    if (st.done) {
      // 模型没把结论加粗时退一步：正文里有结论就按回答结束算
      if (conclusion && !h.marks.strong && conclusion.test(st.text)) await onConclusion();
      h.mark('done');
      return st;
    }
    await sleep(100);
  }
  throw new RecordError(`回答 ${timeoutMs / 1000} s 还没结束`);
}
/* 两幕开头一样：首屏与示例问题（点击前 1.6 s）→ 点击、气泡出现、「正在检索」（点击后 2.2 s）；
   检索 / 模型思考的空档都剪掉，每张工具卡只留它冒出来前后的一小段（卡片出现 → 结果行数填上），然后接回答。 */
function opening(m) {
  const segs = [{ from: m.click - 1.6, to: m.click + 2.2, speed: 1 }];
  for (let i = 1; m[`step${i}`] !== undefined; i++) segs.push({ from: m[`step${i}`] - 0.4, to: m[`step${i}`] + 2.2, flex: [1, 2] });
  return segs;
}

async function openAndAsk(h, chipText, caption) {
  // 「对话」页的欢迎语下面就是按用途分组的示例问题（和工作台同一份），点一个就问
  await h.page.goto(BASE + '/chat');
  const chip = h.page.locator('.welcome .ex button', { hasText: chipText }).first();
  await chip.waitFor({ timeout: 60000 });
  await sleep(900);
  await h.cap(caption);
  await sleep(800);
  h.mark('click');
  await chip.click();
  await h.page.waitForSelector('#askBtn[disabled]', { timeout: 15000 });
}

/* 第一幕：照着 SOP 办事。止于粗体结论「请 N 天年假」，后面的「需要跟进」提醒不入镜。
   N 不钉死：问题不带年份，Agent 查的是下一个国庆所在的年份，要请几天取决于那一年的补班安排。 */
const LEAVE_DAYS = /请假?\s*[0-9一二两三四五六七八九十]+\s*天/;
async function sceneSop(h) {
  await openAndAsk(h, '国庆', '照着 SOP 办事：问一句，它按《请假拼假核对》查节假日和补班日');
  const st = await watchAnswer(h, {
    conclusion: LEAVE_DAYS, follow: /需要跟进|已过去|已经过去/,
    caption: '补班日也要算：周末里的补班日照样要请假，按 SOP 查数据才不会少算',
  });
  if (!LEAVE_DAYS.test(st.text) || !/SOP/.test(st.text))
    throw new RecordError('第一幕：回答里没有同时出现「请 N 天」和「SOP」。回答开头：' + st.text.slice(0, 120));
  if (!h.marks.strong) throw new RecordError('第一幕：没等到含「请 N 天」的结论');
  if (st.steps < 2) throw new RecordError(`第一幕：只调用了 ${st.steps} 个工具，不像是按 SOP 执行`);
  await sleep(3000);
}
/* 第一幕时间线。切点：结论出现后至少看 2.6 s（滚动到位、字幕淡入），若回答随即结束就再带上来源出现的一下，
   最多到结论后 4 s；结论之后的「需要跟进」提醒已被 __clampAfter 隐藏，不会入镜。 */
function timelineSop(m) {
  const cut = Math.min(Math.max(m.strong + 2.6, m.done + 0.8), m.strong + 4.0);
  return opening(m).concat([
    { from: (m.firstDelta || m.strong) - 0.3, to: cut, flex: [1, 3], cutMiddle: true },   // 回答
  ]);
}

/* 第二幕：SOP 从实践里长出来。自由排查 → 💡 提议 → 查看步骤 → 保存 → SOP 面板「从实践沉淀」里出现它。 */
async function sceneGrow(h) {
  const { page } = h;
  await openAndAsk(h, '余额', '研发包没带 SOP：它自由排查，调了 2 个工具');
  const st = await watchAnswer(h);
  if (st.steps < 2) throw new RecordError(`第二幕：只调用了 ${st.steps} 个工具，不会有 SOP 提议`);
  await h.cap('回答完了，后台在整理这次的排查轨迹…');
  const prop = page.locator('.bot .proposal').first();
  try { await prop.waitFor({ timeout: 90000 }); }
  catch (_) {
    let why;
    try {
      const d = await api('/api/proposals?execution_id=' + encodeURIComponent(st.exec));
      why = (d.proposals || []).length
        ? '服务端已经有这条提议，但页面没取到（前端只轮询约 54 s，提议生成得太晚）'
        : '服务端没有生成提议：看 kb-app 日志里的「no SOP proposal for …」；同样的路径保存 / 忽略过要先重置演示数据';
    } catch (e) { why = '查 /api/proposals 也失败：' + e.message; }
    throw new RecordError('第二幕：90 s 内没有出现 💡 卡片。' + why);
  }
  h.mark('proposal');
  await h.cap('它提议把这条路径沉淀成 SOP，人点一下「<b>保存</b>」');
  await sleep(1500);
  await prop.locator('details > summary').first().click();
  h.mark('steps');
  await h.toBottom();
  await sleep(2200);
  await prop.locator('[data-papprove]').click();
  await prop.locator('.hd', { hasText: '已保存' }).waitFor({ timeout: 20000 });
  h.mark('saved');
  await sleep(1400);
  await page.evaluate(() => window.go('sop'));   // 左侧导航默认被隐藏了，直接切到 SOP 页
  const grp = page.locator('#mgroups .mg[data-mgroup="从实践沉淀"]');
  await grp.waitFor({ timeout: 15000 });
  await grp.click();
  await page.locator('#mrows .mrow').first().waitFor({ timeout: 15000 });
  h.mark('panel');
  const head = await page.locator('#topSub').innerText();
  if (!/实践\s*1/.test(head)) throw new RecordError('第二幕：SOP 页顶栏没有「实践 1」：' + head.replace(/\s+/g, ' '));
  await h.cap('SOP 页：来源 文档 1 / 实践 1 —— 默认停用，人核对后再启用');
  await sleep(1600);
  h.mark('end');
}
function timelineGrow(m) {
  return opening(m).concat([
    { from: (m.firstDelta || m.done) - 0.3, to: m.done, flex: [1, 3], cutMiddle: true }, // 回答
    { from: m.proposal - 1.0, to: m.end, speed: 1 },                                     // 等提议的空档剪掉，只留它冒出来前的 1 s
  ]);
}
const SCENES = { sop: { run: sceneSop, timeline: timelineSop }, grow: { run: sceneGrow, timeline: timelineGrow } };

/* ---------- 后期：按时刻裁剪变速 → 无损中间片 → 两遍法 GIF ---------- */
function run(bin, args) {
  const r = spawnSync(bin, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (r.error) throw new Error(`${bin} 启动失败：${r.error.message}`);
  if (r.status !== 0) throw new Error(`${bin} 失败（exit ${r.status}）：${(r.stderr || '').trim().split('\n').slice(-6).join('\n')}`);
  return r;
}
function probe(file, entries) {
  return run('ffprobe', ['-v', 'error', '-select_streams', 'v:0', '-show_entries', entries, '-of', 'default=nw=1:nk=1', file])
    .stdout.trim().split(/\r?\n/);
}
function duration(file) {
  const d = parseFloat(probe(file, 'format=duration')[0]);
  if (!(d > 0)) throw new Error('读不出时长：' + file);
  return d;
}

/* 把墙钟时刻换成素材时刻（素材从第一帧算起），相邻段不重叠；再给可变速的段定速度：
   先尽量凑到 TARGET，超过 MAX_LEN 就在允许跳切的段中间剪一刀。 */
function fit(segments, videoStart, videoLen) {
  const toV = t => Math.min(videoLen, Math.max(0, t - videoStart));
  const segs = [];
  for (const s of segments) {
    const from = Math.max(toV(s.from), segs.length ? segs[segs.length - 1].to : 0), to = toV(s.to);
    if (to - from > 0.3) segs.push({ ...s, from, to });
  }
  if (!segs.length) throw new RecordError('时间线为空：关键时刻没有记全');
  const hold = HOLD;
  const fixed = segs.filter(s => !s.flex).reduce((a, s) => a + (s.to - s.from) / (s.speed || 1), 0) + hold;
  const flexReal = segs.filter(s => s.flex).reduce((a, s) => a + (s.to - s.from), 0);
  const k = TARGET - fixed > 0 ? flexReal / (TARGET - fixed) : Infinity;
  for (const s of segs) s.speed = s.flex ? Math.min(s.flex[1], Math.max(s.flex[0], k)) : (s.speed || 1);
  const total = () => segs.reduce((a, s) => a + (s.to - s.from) / s.speed, 0) + hold;
  if (total() > MAX_LEN) {
    const i = segs.findIndex(s => s.cutMiddle);
    if (i >= 0) {
      const s = segs[i];
      const keep = (s.to - s.from) - (total() - TARGET) * s.speed;   // 这段还能留多少真实秒
      if (keep > 1) segs.splice(i, 1, { ...s, to: s.from + keep * 0.4 }, { ...s, from: s.to - keep * 0.6 });
    }
  }
  return { segs, hold, total: total() };
}
function cutFilter(segs, hold) {
  const n = segs.length;
  const seg = (s, i) => `trim=start=${s.from.toFixed(3)}:end=${s.to.toFixed(3)},setpts=(PTS-STARTPTS)/${s.speed.toFixed(3)}`;
  const tail = `tpad=stop_mode=clone:stop_duration=${hold}[out]`;
  if (n === 1) return `[0:v]${seg(segs[0], 0)},${tail}`;
  return `[0:v]split=${n}${segs.map((_, i) => `[v${i}]`).join('')};`
       + segs.map((s, i) => `[v${i}]${seg(s, i)}[s${i}]`).join(';') + ';'
       + segs.map((_, i) => `[s${i}]`).join('') + `concat=n=${n}:v=1:a=0,${tail}`;
}
function produce(rec) {
  const videoLen = duration(rec.full);
  const { segs, hold, total } = fit(SCENES[rec.name].timeline(rec.marks), rec.videoStart, videoLen);
  log(`${rec.name}: 素材 ${videoLen.toFixed(1)} s，剪成 ${total.toFixed(1)} s：`
      + segs.map(s => ` [${s.from.toFixed(1)}→${s.to.toFixed(1)} ×${s.speed.toFixed(2)}]`).join('') + ` +定格 ${hold} s`);
  const cut = path.join(RAW, `${rec.name}.cut.mkv`);
  run('ffmpeg', ['-y', '-v', 'error', '-i', rec.full, '-filter_complex', cutFilter(segs, hold), '-map', '[out]', '-r', '25', ...LOSSLESS, cut]);
  const palette = path.join(RAW, `${rec.name}.palette.png`);
  const gif = path.join(OUT, GIF_NAME[rec.name]);
  for (const [w, fps, colors] of LADDER) {
    const vf = `fps=${fps},scale=${w}:-2:flags=lanczos`;
    run('ffmpeg', ['-y', '-v', 'error', '-i', cut, '-vf', `${vf},palettegen=stats_mode=diff:max_colors=${colors}`, palette]);
    run('ffmpeg', ['-y', '-v', 'error', '-i', cut, '-i', palette,
                   '-lavfi', `${vf}[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle`, '-loop', '0', gif]);
    const size = fs.statSync(gif).size;
    log(`${rec.name}: ${w}p @ ${fps} fps / ${colors} 色 → ${(size / 1e6).toFixed(2)} MB`);
    if (size <= MAX_BYTES) {
      const [width, height] = probe(gif, 'stream=width,height').map(Number);
      return { path: gif, size, width, height, fps, len: duration(gif) };
    }
  }
  fs.rmSync(gif, { force: true });
  throw new RecordError(`${rec.name}: 体积阶梯用尽仍超过 4 MB，没有输出 GIF；缩短幕长或降低 TARGET 再试`);
}

/* ---------- 主流程 ---------- */
function reuse(name) {
  const file = path.join(RAW, `${name}.marks.json`);
  if (!fs.existsSync(file)) throw new PreflightError(`--reuse：没有 ${file}`);
  const saved = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (saved.error || !saved.marks || !saved.full) throw new PreflightError(`--reuse：上次 ${name} 没录成（${saved.error || '没有可用素材'}），先重录`);
  return saved;
}
(async () => {
  const names = SCENE === 'all' ? ['sop', 'grow'] : [SCENE];
  log(`演示站 ${safeBase}  场景 ${SCENE}  输出 ${OUT}  侧栏 ${SIDEBAR ? '显示' : '隐藏'}${REUSE ? '  （--reuse：只重做后期）' : ''}`);
  if (REUSE) {
    const done = names.map(n => produce(reuse(n)));
    for (const g of done) log(`✓ ${g.path}  ${g.width}×${g.height}  ${g.fps} fps  ${g.len.toFixed(1)} s  ${(g.size / 1e6).toFixed(2)} MB`);
    return;
  }
  await waitPacks();
  const browser = await pw.chromium.launch({ headless: true });
  const done = [];
  try {
    for (const name of names) {
      if (name === 'grow') await checkGrowReady();
      log(`== 第${name === 'sop' ? '一' : '二'}幕 ${name}`);
      const rec = await record(browser, name, SCENES[name].run);
      done.push(produce(rec));
    }
  } finally { await browser.close(); }
  for (const g of done) log(`✓ ${g.path}  ${g.width}×${g.height}  ${g.fps} fps  ${g.len.toFixed(1)} s  ${(g.size / 1e6).toFixed(2)} MB`);
})().catch(e => {
  console.error('!!', e instanceof PreflightError || e instanceof RecordError ? e.message : (e.stack || e.message));
  process.exit(e instanceof PreflightError ? 2 : 1);
});

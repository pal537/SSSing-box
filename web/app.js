let CUR_PROTO = 'vless';
let NODES = [];       // /api/inbounds flat list (with links)
let USAGE = {};       // id -> usage node from /api/usage
let CHAINS = [];
let BNODES = [];
let POLL = null;
let PING_POLL = null;

function $(id){ return document.getElementById(id); }
function toast(msg, isErr){
  const t = $('toast');
  t.textContent = msg;
  t.className = 'toast on' + (isErr ? ' err' : '');
  clearTimeout(t._h);
  t._h = setTimeout(()=>{ t.className = 'toast'; }, 3200);
}
async function api(path, method, body){
  const opt = { method: method || 'GET', headers: {'Content-Type':'application/json'} };
  if (body !== undefined) opt.body = JSON.stringify(body);
  const r = await fetch(path, opt);
  let j = {};
  try { j = await r.json(); } catch(e){}
  if (r.status === 401){ showLogin(); throw new Error('未登录'); }
  if (!j.ok) throw new Error(j.error || ('请求失败 ' + r.status));
  return j.data;
}
function fmtBytes(n){
  if (n == null) return '-';
  const u = ['B','KB','MB','GB','TB'];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length-1){ v /= 1024; i++; }
  return v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2) + ' ' + u[i];
}
function fmtRate(n){ return fmtBytes(n) + '/s'; }
function fmtDur(sec){
  if (!sec) return '-';
  const d = Math.floor(sec/86400), h = Math.floor(sec%86400/3600), m = Math.floor(sec%3600/60);
  if (d > 0) return d + '天' + h + '小时';
  if (h > 0) return h + '小时' + m + '分';
  return m + '分';
}
function fmtPct(p){ return (p == null ? 0 : p).toFixed(p >= 10 ? 0 : 2) + '%'; }
function uuidv4(){
  const b = new Uint8Array(16); crypto.getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map(x => x.toString(16).padStart(2,'0')).join('');
  return h.slice(0,8)+'-'+h.slice(8,12)+'-'+h.slice(12,16)+'-'+h.slice(16,20)+'-'+h.slice(20);
}
function escHtml(s){ return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function copyText(idOrVal, val){
  const text = val !== undefined ? val : $(idOrVal).value;
  const done = ()=> toast('已复制');
  if (navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(text).then(done).catch(()=>fallbackCopy(text, done));
  } else fallbackCopy(text, done);
}
function fallbackCopy(text, done){
  const ta = document.createElement('textarea');
  ta.value = text; document.body.appendChild(ta); ta.select();
  try { document.execCommand('copy'); done(); } catch(e){ toast('复制失败，请手动复制', true); }
  document.body.removeChild(ta);
}
function effAddr(n){
  return panelCertDomain(PANEL_CERT_ID) || n.address;
}

// ---------- modal ----------
function openModal(html, wide){
  $('modalBox').innerHTML = html;
  $('modalBox').className = 'modal' + (wide ? ' wide' : '');
  $('overlay').className = 'overlay on';
}
function closeModal(){ $('overlay').className = 'overlay'; }
$('overlay').addEventListener('click', e => { if (e.target.id === 'overlay') closeModal(); });
function confirmModal(title, bodyHtml, okText, onOk){
  openModal(`<h4>${title}</h4><div style="color:var(--mut)">${bodyHtml}</div>
    <div class="foot"><button class="btn ghost" onclick="closeModal()">取消</button><button class="btn red" id="cfmOk">${okText}</button></div>
    <div class="msg" id="cfmMsg"></div>`);
  $('cfmOk').onclick = async ()=>{
    $('cfmOk').disabled = true;
    try { await onOk(); closeModal(); } catch(e){ $('cfmMsg').className = 'msg err'; $('cfmMsg').textContent = e.message; $('cfmOk').disabled = false; }
  };
}

// ---------- views / auth ----------
function showView(name){
  document.querySelectorAll('.view').forEach(v => v.classList.remove('on'));
  document.querySelectorAll('.nav button').forEach(b => b.classList.toggle('on', b.dataset.view === name));
  $('view-' + name).classList.add('on');
  if (name === 'status') refreshStatus();
  if (name === 'inbounds'){ refreshStatus(); loadChains(); }
  if (name === 'settings') loadSettings();
}
function hideAllAuth(){
  $('setupView').style.display = 'none';
  $('loginView').style.display = 'none';
  $('appView').style.display = 'none';
}
// 随机账号：首位字母，后 7 位字母数字（不含易混的 0/1/o/l），绝不默认 admin。
function randomUsername(){
  const first = 'abcdefghjkmnpqrstuvwxyz', rest = first + '23456789';
  let s = first[Math.floor(Math.random() * first.length)];
  for (let i = 0; i < 7; i++) s += rest[Math.floor(Math.random() * rest.length)];
  return s;
}
function showSetup(){
  hideAllAuth();
  if ($('setupUser') && !$('setupUser').value) $('setupUser').value = randomUsername();
  $('setupView').style.display = 'flex';
  if (POLL){ clearInterval(POLL); POLL = null; }
}
function showLogin(){
  hideAllAuth();
  $('loginView').style.display = 'flex';
  if (POLL){ clearInterval(POLL); POLL = null; }
}
function showApp(){
  hideAllAuth();
  $('appView').style.display = 'block';
  refreshAll();
  if (!POLL) POLL = setInterval(()=>{ if ($('view-status').classList.contains('on')) refreshStatus(); }, 5000);
  if (!PING_POLL) PING_POLL = setInterval(refreshBNodePing, 3000);
}
async function doSetup(){
  $('setupErr').textContent = '';
  let u = $('setupUser').value.trim();
  if (!u){ u = randomUsername(); $('setupUser').value = u; }
  const p = $('setupPass').value, p2 = $('setupPass2').value;
  if (p !== p2){ $('setupErr').textContent = '两次输入的密码不一致'; return; }
  try {
    await api('/api/setup', 'POST', { username: u, password: p, password2: p2 });
    showApp();
  } catch(e){ $('setupErr').textContent = e.message; }
}
async function doLogin(){
  $('loginErr').textContent = '';
  try {
    await api('/api/login', 'POST', { username: $('loginUser').value.trim(), password: $('loginPass').value, remember: $('loginRemember').checked });
    showApp();
  } catch(e){ $('loginErr').textContent = e.message; }
}
async function doLogout(){
  try { await api('/api/logout', 'POST', {}); } catch(e){}
  showLogin();
}
$('loginPass').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
$('loginUser').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
$('setupPass2').addEventListener('keydown', e => { if (e.key === 'Enter') doSetup(); });

// ---------- rings (compact) ----------
function ringHTML(pct, cls){
  const C = 201.1;
  const off = C * (1 - Math.min(100, Math.max(0, pct)) / 100);
  const color = pct >= 90 ? 'bad' : pct >= 75 ? 'warn' : '';
  return `<svg width="76" height="76" viewBox="0 0 76 76">
    <circle class="bg" cx="38" cy="38" r="32" fill="none" stroke-width="9"/>
    <circle class="fg ${cls || color}" cx="38" cy="38" r="32" fill="none" stroke-width="9"
      stroke-dasharray="${C}" stroke-dashoffset="${off}"/>
  </svg><div class="num">${fmtPct(pct)}</div>`;
}
function renderSystem(d){
  const s = d.system;
  $('ringCpu').innerHTML = ringHTML(s.cpu_percent);
  $('ringMem').innerHTML = ringHTML(s.mem_percent);
  $('ringSwap').innerHTML = ringHTML(s.swap_percent);
  $('ringDisk').innerHTML = ringHTML(s.disk_percent);
  $('capCpu').textContent = s.cpu_cores + ' Cores';
  $('capMem').textContent = fmtBytes(s.mem_used) + ' / ' + fmtBytes(s.mem_total);
  $('capSwap').textContent = fmtBytes(s.swap_used) + ' / ' + fmtBytes(s.swap_total);
  $('capDisk').textContent = fmtBytes(s.disk_used) + ' / ' + fmtBytes(s.disk_total);
  $('kvLoad').textContent = s.load1.toFixed(2) + ' | ' + s.load5.toFixed(2) + ' | ' + s.load15.toFixed(2);
  $('kvUptime').textContent = fmtDur(s.uptime_sec);
  $('kvPanelMem').textContent = fmtBytes(s.panel_mem);
  $('kvPubIp').textContent = d.public_ip || '-';
  $('kvPubIp6').textContent = d.public_ipv6 || '-';
  $('kvPubIp6Row').style.display = d.public_ipv6 ? '' : 'none';
  $('sysSub').textContent = '面板已运行 ' + fmtDur(d.panel_uptime_sec);
}

// ---------- cores ----------
// 安装中的内核：名字 -> 当前阶段文案。状态页每 5 秒重绘内核卡片，
// 以前重绘会把进行中的“下载中…”按钮整个换回“下载”，等于没反馈；
// 现在重绘按这张表渲染，按钮状态在安装结束前不会被刷新抹掉。
let CORE_LIST = [];
const CORE_INSTALL = {};
async function refreshCores(){
  const list = await api('/api/cores');
  CORE_LIST = list;
  const el = $('coreRows');
  if (!list.length){ el.innerHTML = '<div class="empty">暂无内核信息</div>'; return; }
  el.innerHTML = list.map(c => `
    <div class="row core-row">
      <span class="dot ${c.running ? 'on' : 'off'}"></span>
      <div class="grow"><div class="t">${c.title}</div>
        <div class="s">${c.installed ? ('已安装 ' + c.version + (c.has_update ? ' · 有新版本 ' + c.latest : '')) : '未下载，不占空间'}${c.note ? ' · ' + c.note : ''}${c.name === 'sing-box' ? ' · 通用代理内核' : ''}${c.name === 'mtg' ? ' · Telegram 专用代理内核' : ''}</div></div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end">
        ${CORE_INSTALL[c.name]
          ? `<button class="btn small" data-install-core="${c.name}" disabled>${CORE_INSTALL[c.name]}</button>`
          : (c.installed
            ? `${c.no_update ? '' : `<button class="btn ghost small" onclick="openVerDialog('${c.name}','${c.title}')">更新</button>`}
               <button class="btn ghost small" onclick="restartCore('${c.name}')">重启</button>
               <button class="btn ghost small" onclick="showCoreLog('${c.name}','${c.title}')">日志</button>`
            : `<button class="btn small" data-install-core="${c.name}" onclick="installCore('${c.name}','')">下载</button>`)}
      </div>
    </div>`).join('');
}
// 安装进度轮询：服务端在下载阶段报 downloading，解压写入阶段报 installing；
// 前端按真实阶段改按钮文案，不用假计时。轮询只改按钮文案，不重绘整张卡。
function pollCoreProgress(name, setText){
  return setInterval(async () => {
    try {
      const p = await api('/api/cores/progress');
      const phase = p && p[name];
      if (phase === 'installing'){ CORE_INSTALL[name] = '安装中…'; setText('安装中…'); }
      else if (phase === 'downloading'){ CORE_INSTALL[name] = '下载中…'; setText('下载中…'); }
    } catch(_){}
  }, 800);
}
function coreInstallBtn(name){
  return document.querySelector('[data-install-core="' + name + '"]');
}
async function installCore(name, version){
  if (CORE_INSTALL[name]) return;
  CORE_INSTALL[name] = '下载中…';
  const btn = event.target;
  btn.disabled = true; btn.textContent = '下载中…';
  const timer = pollCoreProgress(name, t => { const b = coreInstallBtn(name) || btn; b.textContent = t; });
  try {
    const r = await api('/api/cores/' + name + '/install', 'POST', { version: version || '' });
    toast(name + ' 已安装 ' + r.version);
  } catch(e){ toast(e.message, true); }
  clearInterval(timer);
  delete CORE_INSTALL[name];
  refreshCores(); refreshStatus();
}
async function openVerDialog(name, title){
  openModal(`<h4>${title} · 选择版本安装</h4><div class="ver-list" id="verList"><div class="muted" style="padding:14px">正在获取版本…</div></div>
    <div class="foot"><button class="btn ghost" onclick="closeModal()">关闭</button></div><div class="msg" id="verMsg"></div>`);
  try {
    const vers = await api('/api/cores/' + name + '/versions');
    if (!vers.length){ $('verList').innerHTML = '<div class="muted" style="padding:14px">没有可用版本</div>'; return; }
    $('verList').innerHTML = vers.map(v =>
      `<button onclick="installCoreVer('${name}','${v}',this)">${v}</button>`).join('');
  } catch(e){ $('verMsg').className = 'msg err'; $('verMsg').textContent = e.message; }
}
async function installCoreVer(name, ver, btn){
  if (CORE_INSTALL[name]) return;
  CORE_INSTALL[name] = '下载中…';
  btn.disabled = true; btn.textContent = '下载中…';
  const timer = pollCoreProgress(name, t => { btn.textContent = t; });
  try {
    const r = await api('/api/cores/' + name + '/install', 'POST', { version: ver });
    toast(name + ' 已安装 ' + r.version);
    closeModal(); refreshCores(); refreshStatus();
  } catch(e){
    $('verMsg').className = 'msg err'; $('verMsg').textContent = e.message;
    btn.disabled = false; btn.textContent = ver;
  }
  clearInterval(timer);
  delete CORE_INSTALL[name];
}
async function restartCore(name){
  try { await api('/api/cores/' + name + '/restart', 'POST', {}); toast(name + ' 已重启'); refreshStatus(); }
  catch(e){ toast(e.message, true); }
}
async function showCoreLog(name, title){
  try {
    const log = await api('/api/cores/' + name + '/log');
    openModal(`<h4>${title} · 日志（最近 100 行）</h4><div class="muted" style="padding:4px 0 10px">日志文件在面板数据目录 cores/ 下；单个文件超 10MB 自动只留最新 2000 行，不会一直堆。</div><pre class="log">${escHtml(log || '(暂无日志)')}</pre>
      <div class="foot"><button class="btn ghost" onclick="clearCoreLog('${name}','${title}')">清理日志</button><button class="btn ghost" onclick="closeModal()">关闭</button></div>`, true);
  } catch(e){ toast(e.message, true); }
}
async function clearCoreLog(name, title){
  try { await api('/api/cores/' + name + '/clear-log', 'POST', {}); toast('日志已清理'); showCoreLog(name, title); }
  catch(e){ toast(e.message, true); }
}

// ---------- usage: status view (view-only) + inbound list rows ----------
async function refreshStatus(){
  try {
    const sys = await api('/api/system');
    renderSystem(sys);
  } catch(e){}
  try {
    const u = await api('/api/usage');
    renderUsage(u);
  } catch(e){}
  try { await refreshCores(); } catch(e){}
}
function protoBadge(p){
  if (p === 'vless') return '<span class="badge">VLESS</span>';
  if (p === 'hy2') return '<span class="badge hy2">HY2</span>';
  if (p === 'mtg') return '<span class="badge mtg">MTProto</span>';
  if (p === 'vmess') return '<span class="badge">VMess</span>';
  if (p === 'trojan') return '<span class="badge">Trojan</span>';
  if (p === 'wireguard') return '<span class="badge">WG</span>';
  if (p === 'dokodemo') return '<span class="badge">DOKO</span>';
  if (p === 'ss') return '<span class="badge">SS</span>';
  if (p === 'socks') return '<span class="badge">SOCKS</span>';
  if (p === 'http') return '<span class="badge">HTTP</span>';
  if (p === 'tuic') return '<span class="badge">TUIC</span>';
  if (p === 'anytls') return '<span class="badge">AnyTLS</span>';
  if (p === 'naive') return '<span class="badge">Naive</span>';
  if (p === 'hysteria2') return '<span class="badge hy2">HY2</span>';
  return '<span class="badge">' + escHtml(p) + '</span>';
}
// 完整协议栈：徽章只写简称，第二行写全——
// VLESS 是 sing-box 的 VLESS + Reality + TCP + 流控；
// Hy2 是 QUIC/UDP + 真 TLS；MTG 是 TCP + Fake-TLS。
function nodeCfg(id){
  const n = NODES.find(x => x.id === id);
  if (!n || !n.config) return null;
  try { return JSON.parse(n.config); } catch(e){ return null; }
}
function protoFull(p, cfg){
  if (p === 'vless'){
    const mode = (cfg && cfg.mode) || 'reality';
    let s = mode === 'reality' ? 'sing-box · VLESS + Reality + TCP' :
      mode === 'ws' ? 'sing-box · VLESS + WS + TLS' :
      mode === 'h2' ? 'sing-box · VLESS + H2 + TLS' :
      mode === 'httpupgrade' ? 'sing-box · VLESS + HTTPUpgrade + TLS' : 'sing-box · VLESS';
    if (mode === 'reality' && cfg && cfg.flow) s += ' + ' + cfg.flow;
    return s;
  }
  if (p === 'hy2'){
    let s = 'sing-box · Hysteria2 + QUIC/UDP + TLS';
    if (cfg && cfg.obfs_type) s += ' + ' + cfg.obfs_type;
    return s;
  }
  if (p === 'mtg') return 'mtg · MTProto + TCP + Fake-TLS · Telegram专用';
  if (p === 'vmess'){
    const mode = (cfg && cfg.mode) || 'tcp';
    return mode === 'cf' ? 'sing-box · VMess + WS + TLS（Cloudflare）' :
      mode === 'http' ? 'sing-box · VMess + HTTP' :
      mode === 'quic' ? 'sing-box · VMess + QUIC + TLS' :
      mode === 'h2' ? 'sing-box · VMess + H2 + TLS' :
      mode === 'httpupgrade' ? 'sing-box · VMess + HTTPUpgrade + TLS' : 'sing-box · VMess + TCP';
  }
  if (p === 'trojan'){
    const mode = (cfg && cfg.mode) || 'reality';
    return mode === 'cf' ? 'sing-box · Trojan + WS + TLS（Cloudflare）' :
      mode === 'h2' ? 'sing-box · Trojan + H2 + TLS' :
      mode === 'httpupgrade' ? 'sing-box · Trojan + HTTPUpgrade + TLS' : 'sing-box · Trojan + Reality + TCP';
  }
  if (p === 'wireguard') return 'sing-box · WireGuard + UDP';
  if (p === 'dokodemo') return 'Dokodemo-door（已退役，sing-box 不支持）';
  if (p === 'ss') return 'sing-box · Shadowsocks + ' + (cfg && cfg.method ? cfg.method : '');
  if (p === 'socks') return 'sing-box · SOCKS5 + 账号密码';
  if (p === 'http') return 'sing-box · HTTP + 账号密码';
  if (p === 'tuic') return 'sing-box · TUIC + QUIC/UDP + TLS';
  if (p === 'anytls') return 'sing-box · AnyTLS + TCP + TLS';
  if (p === 'naive') return 'sing-box · Naive + TCP + TLS（需 CA 证书）';
  if (p === 'hysteria2') return 'Hysteria2';
  return p || '';
}
function quotaText(n){
  if (!n.quota_mode || !n.quota_bytes) return '';
  const used = n.quota_mode === 'down' ? n.total_down : (n.total_up + n.total_down);
  const pct = Math.round(used / n.quota_bytes * 100);
  return ' · 限额 ' + fmtBytes(n.quota_bytes) + (n.quota_mode === 'down' ? '（下行）' : '（合计）') + '，已用 ' + pct + '%';
}
function scrollTraffic(){
  const sc = $('trafficScroll');
  if (sc) sc.scrollBy({ top: 120, behavior: 'smooth' });
}
function renderUsage(u){
  const nodes = u.nodes || [];
  USAGE = {};
  nodes.forEach(n => { USAGE[n.id] = n; });
  let rtUp = 0, rtDown = 0, tcp = 0, udp = 0, udpKnown = false;
  const el = $('trafficRows');
  const sc = $('trafficScroll');
  const keepScroll = sc ? sc.scrollTop : 0;
  if (!nodes.length){
    el.innerHTML = '<div class="empty">还没有节点，去入站列表创建一个吧</div>';
  } else {
    el.innerHTML = nodes.map(n => {
      rtUp += n.rate_up; rtDown += n.rate_down; tcp += n.tcp_conns;
      if (n.udp_conns >= 0){ udp += n.udp_conns; udpKnown = true; }
      return `<div class="row">
        <span class="dot ${n.running ? 'on' : 'off'}"></span>
        <div class="grow"><div class="t">${escHtml(n.name)} ${protoBadge(n.protocol)}</div>
          <div class="s">${escHtml(effAddr(n))}:${n.port} · ${n.enabled ? (n.running ? '运行中' : '核心未启动') : '已停用'}${quotaText(n)}</div>
          <div class="s2">${escHtml(protoFull(n.protocol, nodeCfg(n.id)))}</div></div>
        <div class="nums">今日 <b>${fmtBytes(n.today_up)} ↑ / ${fmtBytes(n.today_down)} ↓</b><br>本月 <b>${fmtBytes(n.month_up)} ↑ / ${fmtBytes(n.month_down)} ↓</b> · 总 <b>${fmtBytes(n.total_up + n.total_down)}</b></div>
      </div>`;
    }).join('');
  }
  // 默认只看 3 条：列表超高时出滚动条 + 下箭头，点一下往下滚；
  // 每 5 秒刷新会重绘列表，这里把滚动位置还回去，不打断查看。
  if (sc){
    sc.scrollTop = keepScroll;
    const more = $('trafficMore');
    if (more) more.style.display = (nodes.length > 3 && sc.scrollHeight > sc.clientHeight + 8) ? '' : 'none';
    sc.onscroll = () => {
      if (more) more.style.display = (sc.scrollHeight - sc.scrollTop - sc.clientHeight > 8) ? '' : 'none';
    };
  }
  $('rtUp').textContent = fmtRate(rtUp);
  $('rtDown').textContent = fmtRate(rtDown);
  $('rtTcp').textContent = tcp;
  $('rtUdp').textContent = udpKnown ? udp : '-';
  $('totToday').textContent = fmtBytes(u.totals.today_up) + ' ↑ / ' + fmtBytes(u.totals.today_down) + ' ↓';
  $('totMonth').textContent = fmtBytes(u.totals.month_up) + ' ↑ / ' + fmtBytes(u.totals.month_down) + ' ↓';
  $('totAll').textContent = fmtBytes(u.totals.total_up) + ' ↑ / ' + fmtBytes(u.totals.total_down) + ' ↓';
  $('statsErr').textContent = u.stats_error ? ('流量统计异常：' + u.stats_error) : '';
  renderLocalRows();
}
function renderLocalRows(){
  const el = $('localRows');
  if (!el) return;
  if (!NODES.length){
    el.innerHTML = '<div class="empty">还没有节点，点左上角“添加入站”创建一个吧</div>';
    $('localSub').textContent = '';
    return;
  }
  $('localSub').textContent = '共 ' + NODES.length + ' 个节点';
  el.innerHTML = NODES.map(n => {
    const u = USAGE[n.id];
    const today = u ? (fmtBytes(u.today_up) + ' ↑ / ' + fmtBytes(u.today_down) + ' ↓') : '-';
    const total = u ? fmtBytes(u.total_up + u.total_down) : '-';
    const uq = u ? quotaText(u) : '';
    let cfg = null;
    try { cfg = n.config ? JSON.parse(n.config) : null; } catch(e){}
    const isDomainMode = (n.protocol === 'trojan' && cfg && (cfg.mode === 'cf' || cfg.mode === 'h2' || cfg.mode === 'httpupgrade')) ||
      (n.protocol === 'vless' && cfg && (cfg.mode === 'ws' || cfg.mode === 'h2' || cfg.mode === 'httpupgrade')) ||
      (n.protocol === 'vmess' && cfg && cfg.mode && cfg.mode !== 'tcp') || n.protocol === 'naive';
    const sniWordShown = isDomainMode ? '域名' : sniWord(n.protocol);
    const hideSni = n.protocol === 'ss' || n.protocol === 'socks' || n.protocol === 'http' || n.protocol === 'wireguard' || n.protocol === 'dokodemo' || (n.protocol === 'vmess' && (!cfg || !cfg.mode || cfg.mode === 'tcp'));
    const sniPart = hideSni ? '' : ` · ${sniWordShown} ${escHtml(n.sni)}`;
    const certHint = (n.protocol === 'naive' && cfg && !cfg.cert_file) ? ' · 缺 CA 证书，点 ⋮ 上传' : '';
    return `<div class="nrow">
      <button class="menu-btn" title="设置" onclick="openNodeMenu('${n.id}')">⋮</button>
      <input type="checkbox" class="switch" ${n.enabled ? 'checked' : ''} title="${n.enabled ? '停用' : '启用'}" onchange="toggleNode('${n.id}', this.checked)">
      <div style="min-width:0"><div class="t">${escHtml(n.name)}</div>
        <div class="s">${escHtml(effAddr(n))}:${n.port}${sniPart} · ${n.enabled ? (u && u.running === false ? '核心未启动' : '运行中') : '已停用'}${uq}${certHint}</div>
        <div class="s" style="color:var(--blue)">${escHtml(protoFull(n.protocol, cfg))}</div></div>
      <div class="cell"><b>${n.port}</b></div>
      <div class="cell">${protoBadge(n.protocol)}</div>
      <div class="cell hide-m"><b>${today}</b></div>
      <div class="cell hide-m"><b>${total}</b></div>
    </div>`;
  }).join('');
}
function nodeById(id){
  return NODES.find(x => x.id === id) || USAGE[id] || null;
}
function showLink(id){
  const n = nodeById(id);
  if (!n) return;
  const link = n.link || '';
  const extra = n.tme_link ? `<div style="margin-top:12px"><label>t.me 链接</label><div class="input-row"><input id="lkTme" readonly value="${escHtml(n.tme_link)}"><button class="btn ghost small" onclick="copyText('lkTme')">复制</button></div></div>` : '';
  const linkField = (n.protocol === 'wireguard' || n.protocol === 'naive')
    ? `<label>${n.protocol === 'naive' ? 'Naive 配置（参考客户端 JSON 配置，不是 URL，别贴进 URL 导入框）' : 'WireGuard 配置（贴进官方客户端，或扫下方二维码）'}</label><textarea id="lkMain" readonly rows="11" style="width:100%;font-family:monospace">${escHtml(link)}</textarea><div style="margin-top:8px"><button class="btn ghost small" onclick="copyText('lkMain')">复制配置</button></div>`
    : `<label>节点链接</label><div class="input-row"><input id="lkMain" readonly value="${escHtml(link)}"><button class="btn ghost small" onclick="copyText('lkMain')">复制</button></div>`;
  const link6Field = !n.link6 ? '' : (n.protocol === 'wireguard'
    ? `<div style="margin-top:12px"><label>WireGuard 配置 IPv6</label><textarea id="lkMain6" readonly rows="11" style="width:100%;font-family:monospace">${escHtml(n.link6)}</textarea><div style="margin-top:8px"><button class="btn ghost small" onclick="copyText('lkMain6')">复制配置</button></div></div>`
    : `<div style="margin-top:12px"><label>节点链接 IPv6</label><div class="input-row"><input id="lkMain6" readonly value="${escHtml(n.link6)}"><button class="btn ghost small" onclick="copyText('lkMain6')">复制</button></div></div>`);
  openModal(`<h4>${escHtml(n.name)} · 链接</h4>
    ${linkField}
    ${link6Field}
    ${extra}
    <div class="qr-box"><img src="/api/inbounds/${n.id}/qr" alt="二维码"></div>
    <div class="foot"><button class="btn ghost" onclick="closeModal()">关闭</button></div>`);
}
function openNodeMenu(id){
  const n = nodeById(id);
  if (!n) return;
  openModal(`<h4>${escHtml(n.name)}</h4><div class="menu-list">
    <button onclick="closeModal();openEditNodeModal('${id}')">编辑</button>
    <button onclick="closeModal();showLink('${id}')">节点链接</button>
    ${n.protocol === 'naive' ? `<button onclick="closeModal();openCertModal('${id}')">上传 CA 证书</button>` : ''}
    <button onclick="closeModal();cloneNode('${id}')">克隆节点</button>
    <button class="danger" onclick="closeModal();delNode('${id}','${escHtml(n.name)}')">删除节点</button>
  </div>
  <div class="foot"><button class="btn ghost" onclick="closeModal()">关闭</button></div>`);
}
function openCertModal(id){
  const n = nodeById(id);
  if (!n) return;
  openModal(`<h4>${escHtml(n.name)} · 上传 CA 证书</h4>
    <div class="hint" style="margin:0 0 12px">Naive 必须用 CA 证书：证书上的域名要和节点域名一致，且解析到这台服务器。证书和私钥配对校验通过才保存，保存后立即重启生效。</div>
    <div><label>证书（PEM）</label><textarea id="cfCert" rows="8" style="width:100%;font-family:monospace" placeholder="-----BEGIN CERTIFICATE-----"></textarea></div>
    <div style="margin-top:12px"><label>私钥（PEM）</label><textarea id="cfKey" rows="8" style="width:100%;font-family:monospace" placeholder="-----BEGIN PRIVATE KEY-----"></textarea></div>
    <div class="foot"><button class="btn ghost" onclick="closeModal()">取消</button><button class="btn" id="certSaveBtn" onclick="uploadCert('${id}')">上传并启动</button></div>
    <div class="msg" id="certMsg"></div>`, true);
}
async function uploadCert(id){
  const btn = $('certSaveBtn'); btn.disabled = true;
  try {
    await api('/api/inbounds/' + id + '/cert', 'POST', { cert: $('cfCert').value.trim(), key: $('cfKey').value.trim() });
    toast('证书已上传，节点已启动'); closeModal();
    await refreshStatus(); await loadChains();
  } catch(e){
    $('certMsg').className = 'msg err'; $('certMsg').textContent = e.message;
    btn.disabled = false;
  }
}
function sniLabel(p, mode){
  if (p === 'hy2' || p === 'tuic' || p === 'anytls') return 'TLS SNI（自签证书域名）';
  if (p === 'mtg') return 'Fake-TLS 伪装域名';
  if (p === 'naive') return '真实域名（CA 证书域名）';
  if (p === 'vmess') return mode && mode !== 'tcp' ? '域名' : '域名（CF 模式必填）';
  if (p === 'trojan') return (mode === 'cf' || mode === 'h2' || mode === 'httpupgrade') ? '域名' : '伪装域名（Reality SNI）';
  if (p === 'vless') return (mode === 'ws' || mode === 'h2' || mode === 'httpupgrade') ? '域名（TLS 证书域名）' : '伪装域名（Reality SNI）';
  return '伪装域名（Reality SNI）';
}
// 节点列表里的域名叫法也要按协议分开，不能一律写“伪装”：
// VLESS 的是 Reality 伪装域名，HY2 的是真 TLS 的 SNI（证书名），
// MTG 的是编进 ee 密钥的 Fake-TLS 伪装域名。
function sniWord(p){
  if (p === 'hy2' || p === 'tuic' || p === 'anytls') return 'SNI';
  if (p === 'mtg') return 'Fake-TLS';
  if (p === 'naive') return '域名';
  return '伪装';
}
function sniHintEdit(p, mode){
  if (p === 'hy2') return 'Hy2 是 QUIC/UDP + 真 TLS：面板按这个域名生成自签证书，客户端握手时 SNI 就是它（链接里 insecure=1，证书不校验真伪）。不需要真实域名，也不需要把域名解析到服务器，留空会自动推荐一个。改 SNI 后证书要重建，旧链接失效。';
  if (p === 'tuic') return 'TUIC 是 QUIC/UDP + 真 TLS：面板按这个域名生成自签证书，客户端握手时 SNI 就是它（链接里 allow_insecure=1）。不需要真实域名，也不需要把域名解析到服务器，留空会自动推荐一个。改 SNI 后证书要重建，旧链接失效。';
  if (p === 'anytls') return 'AnyTLS 是 TCP + 真 TLS：面板按这个域名生成自签证书，客户端握手时 SNI 就是它（链接里 insecure=1）。不需要真实域名，也不需要把域名解析到服务器，留空会自动推荐一个。改 SNI 后证书要重建，旧链接失效。';
  if (p === 'naive') return 'Naive 的域名必须是真实域名：CA 证书上的名字就是它，且要解析到这台服务器。改域名后要重新上传对应证书，旧链接失效。';
  if (p === 'mtg') return 'MTProto 本身是 TCP 密钥加密，不是 TLS；这里的域名只是 Fake-TLS 伪装，编进 ee 密钥里，让流量看起来像去这个域名的 HTTPS，服务器并不真的做 TLS 握手。改域名等于换密钥。';
  if (p === 'vless') return (mode === 'ws' || mode === 'h2' || mode === 'httpupgrade') ? 'VLESS TLS 档的域名就是链接里的地址，必须解析到这台服务器；面板按这个域名生成自签证书，客户端要允许不验证证书。改域名后证书要重建，旧链接失效。' : 'VLESS 改伪装域名时目标地址会跟着换，除非你之前手动改过它。';
  if (p === 'vmess') return (mode && mode !== 'tcp') ? 'VMess 直连档的域名就是链接里的地址（HTTP 档除外：HTTP 档链接地址是服务器 IP，域名只做 Host 头），TLS 档面板按这个域名生成自签证书，客户端要允许不验证证书。CF 档的域名在下方传输方式里改。' : 'VMess TCP 档不需要域名。';
  if (p === 'trojan') return mode === 'cf' ? 'Trojan CF 档的域名在下方传输方式里改。' : (mode === 'h2' || mode === 'httpupgrade') ? 'Trojan TLS 档的域名就是链接里的地址，必须解析到这台服务器；面板按这个域名生成自签证书，客户端要允许不验证证书。改域名后证书要重建，旧链接失效。' : 'Trojan Reality 档改伪装域名时目标地址会跟着换，除非你之前手动改过它；CF 档的域名在下方传输方式里改。';
  return 'VLESS 改伪装域名时目标地址会跟着换，除非你之前手动改过它。';
}
// 编辑 = 添加的完整表单：基础项 + 高级参数（默认折叠）+ 流量设置（默认折叠），
// 协议本身不能改——改协议等于换一个节点，去“添加入站”建新的。
function openEditNodeModal(id){
  const n = nodeById(id);
  if (!n) return;
  let cfg = null;
  try { cfg = n.config ? JSON.parse(n.config) : null; } catch(e){}
  cfg = cfg || {};
  const qGB = n.quota_bytes ? (n.quota_bytes / 1073741824).toFixed(2).replace(/\.00$/, '') : '';
  let adv = '';
  if (n.protocol === 'vless'){
    adv = `<details class="adv"><summary>高级配置</summary><div class="form-grid">
      <div><label>传输方式</label><select id="eVlessMode"><option value="reality" ${(!cfg.mode || cfg.mode === 'reality') ? 'selected' : ''}>Reality + TCP</option><option value="ws" ${cfg.mode === 'ws' ? 'selected' : ''}>WS + TLS</option><option value="h2" ${cfg.mode === 'h2' ? 'selected' : ''}>H2 + TLS</option><option value="httpupgrade" ${cfg.mode === 'httpupgrade' ? 'selected' : ''}>HTTPUpgrade + TLS</option></select></div>
      <div><label>路径（TLS 档）</label><input id="eVlessPath" value="${escHtml(cfg.path || '')}" placeholder="留空自动生成"></div>
      <div><label>UUID</label><input id="eUuid" value="${escHtml(cfg.uuid || '')}" placeholder="留空保持原值"></div>
      <div><label>流控（Reality 档）</label><select id="eFlow"><option value="xtls-rprx-vision" ${cfg.flow === 'xtls-rprx-vision' ? 'selected' : ''}>xtls-rprx-vision</option><option value="" ${!cfg.flow ? 'selected' : ''}>无</option></select></div>
      <div><label>目标地址（dest，Reality 档）</label><input id="eDest" value="${escHtml(cfg.dest || '')}" placeholder="留空保持原值"></div>
      <div><label>ShortId（Reality 档）</label><input id="eShortId" value="${escHtml(cfg.short_id || '')}" placeholder="留空保持原值"></div>
      <div><label>客户端指纹</label><select id="eFp">${['chrome','firefox','safari','random'].map(f => `<option value="${f}" ${cfg.fingerprint === f ? 'selected' : ''}>${f}</option>`).join('')}</select></div>
      <div><label>SpiderX</label><input id="eSpiderX" value="${escHtml(cfg.spider_x || '/')}"></div>
      <div><label>监听地址</label><input id="eListen" value="${escHtml(cfg.listen || '')}" placeholder="留空保持原值"></div>
    </div></details>`;
  } else if (n.protocol === 'hy2'){
    adv = `<details class="adv"><summary>高级配置</summary><div class="form-grid">
      <div><label>密码</label><input id="eHPass" value="" placeholder="留空保持原值"></div>
      <div><label>混淆类型</label><select id="eHObfs"><option value="" ${!cfg.obfs_type ? 'selected' : ''}>无</option><option value="salamander" ${cfg.obfs_type === 'salamander' ? 'selected' : ''}>salamander</option></select></div>
      <div><label>混淆密码</label><input id="eHObfsPass" value="" placeholder="留空保持原值"></div>
      <div><label>上行限速（Mbps，留空不限）</label><input id="eHUp" value="${escHtml(cfg.up_mbps || '')}"></div>
      <div><label>下行限速（Mbps，留空不限）</label><input id="eHDown" value="${escHtml(cfg.down_mbps || '')}"></div>
      <div><label>监听地址</label><input id="eHListen" value="${escHtml(cfg.listen || '')}" placeholder="留空保持原值"></div>
    </div></details>`;
  } else if (n.protocol === 'mtg'){
    adv = `<details class="adv"><summary>高级配置</summary><div class="form-grid">
      <div class="full"><label>密钥（ee 开头，留空 = 改域名时自动重生成、不改域名时保持原值）</label><input id="eMSecret" value="" placeholder="留空"></div>
      <div><label>监听地址</label><input id="eMListen" value="${escHtml(cfg.listen || '')}" placeholder="留空保持原值"></div>
    </div></details>`;
  } else if (n.protocol === 'vmess'){
    adv = `<details class="adv"><summary>高级配置</summary><div class="form-grid">
      <div><label>UUID</label><input id="eVUuid" value="${escHtml(cfg.uuid || '')}" placeholder="留空保持原值"></div>
      <div><label>传输方式</label><select id="eVMode">${[['tcp','TCP 直连'],['cf','WS + Cloudflare'],['http','HTTP 明文'],['quic','QUIC + TLS'],['h2','H2 + TLS'],['httpupgrade','HTTPUpgrade + TLS']].map(([v, t]) => `<option value="${v}" ${(cfg.mode || 'tcp') === v ? 'selected' : ''}>${t}</option>`).join('')}</select></div>
      <div><label>域名（非 TCP 档）</label><input id="eVDomain" value="${escHtml(cfg.domain || n.sni || '')}" placeholder="CF/TLS 档必填，直连档就是 SNI"></div>
      <div><label>路径（CF/HTTP/H2/HTTPUpgrade 档）</label><input id="eVPath" value="${escHtml(cfg.path || '')}" placeholder="留空保持原值"></div>
      <div><label>监听地址</label><input id="eVListen" value="${escHtml(cfg.listen || '')}" placeholder="留空保持原值"></div>
    </div></details>`;
  } else if (n.protocol === 'ss'){
    adv = `<details class="adv"><summary>高级配置</summary><div class="form-grid">
      <div><label>加密方法</label><select id="eSSMethod">${['2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm','aes-256-gcm','chacha20-ietf-poly1305'].map(m => `<option value="${m}" ${cfg.method === m ? 'selected' : ''}>${m}</option>`).join('')}</select></div>
      <div><label>密码</label><input id="eSSPass" value="" placeholder="留空保持原值（换方法时留空自动生成对应密钥）"></div>
      <div><label>监听地址</label><input id="eSListen" value="${escHtml(cfg.listen || '')}" placeholder="留空保持原值"></div>
    </div></details>`;
  } else if (n.protocol === 'socks'){
    adv = `<details class="adv"><summary>高级配置</summary><div class="form-grid">
      <div><label>用户名</label><input id="eSKUser" value="${escHtml(cfg.user || '')}" placeholder="留空保持原值"></div>
      <div><label>密码</label><input id="eSKPass" value="" placeholder="留空保持原值"></div>
      <div><label>监听地址</label><input id="eSKListen" value="${escHtml(cfg.listen || '')}" placeholder="留空保持原值"></div>
    </div></details>`;
  } else if (n.protocol === 'http'){
    adv = `<details class="adv"><summary>高级配置</summary><div class="form-grid">
      <div><label>用户名</label><input id="eHTUser" value="${escHtml(cfg.user || '')}" placeholder="留空保持原值"></div>
      <div><label>密码</label><input id="eHTPass" value="" placeholder="留空保持原值"></div>
      <div><label>监听地址</label><input id="eHTListen" value="${escHtml(cfg.listen || '')}" placeholder="留空保持原值"></div>
    </div></details>`;
  } else if (n.protocol === 'trojan'){
    adv = `<details class="adv"><summary>高级配置</summary><div class="form-grid">
      <div><label>密码</label><input id="eTPass" value="" placeholder="留空保持原值"></div>
      <div><label>传输方式</label><select id="eTMode">${[['reality','Reality 直连'],['cf','WS + Cloudflare'],['h2','H2 + TLS'],['httpupgrade','HTTPUpgrade + TLS']].map(([v, t]) => `<option value="${v}" ${(cfg.mode || 'reality') === v ? 'selected' : ''}>${t}</option>`).join('')}</select></div>
      <div><label>域名（CF/TLS 档）</label><input id="eTDomain" value="${escHtml(cfg.domain || n.sni || '')}" placeholder="CF/TLS 档必填"></div>
      <div><label>路径（CF/TLS 档）</label><input id="eTPath" value="${escHtml(cfg.path || '')}" placeholder="留空保持原值"></div>
      <div><label>监听地址</label><input id="eTListen" value="${escHtml(cfg.listen || '')}" placeholder="留空保持原值"></div>
    </div></details>`;
  } else if (n.protocol === 'wireguard'){
    adv = `<details class="adv"><summary>高级配置</summary><div class="form-grid">
      <div><label>客户端地址</label><input id="eWGIP" value="${escHtml(cfg.client_ip || '')}" placeholder="如 10.0.0.2/32，留空保持原值"></div>
      <div><label>监听地址</label><input id="eWGListen" value="${escHtml(cfg.listen || '')}" placeholder="留空保持原值"></div>
    </div></details><div class="hint">密钥建节点时已生成，编辑不换密钥；要换密钥就删了重建（克隆也会换全套密钥）。</div>`;
  } else if (n.protocol === 'tuic'){
    adv = `<details class="adv"><summary>高级配置</summary><div class="form-grid">
      <div><label>UUID</label><input id="eTUuid" value="${escHtml(cfg.uuid || '')}" placeholder="留空保持原值"></div>
      <div><label>密码</label><input id="eTPw" value="" placeholder="留空保持原值"></div>
      <div><label>监听地址</label><input id="eTListen" value="${escHtml(cfg.listen || '')}" placeholder="留空保持原值"></div>
    </div></details>`;
  } else if (n.protocol === 'anytls'){
    adv = `<details class="adv"><summary>高级配置</summary><div class="form-grid">
      <div><label>用户名</label><input id="eAName" value="${escHtml(cfg.name || '')}" placeholder="留空保持原值"></div>
      <div><label>密码</label><input id="eAPw" value="" placeholder="留空保持原值"></div>
      <div><label>监听地址</label><input id="eAListen" value="${escHtml(cfg.listen || '')}" placeholder="留空保持原值"></div>
    </div></details>`;
  } else if (n.protocol === 'naive'){
    adv = `<details class="adv"><summary>高级配置</summary><div class="form-grid">
      <div><label>用户名</label><input id="eNUser" value="${escHtml(cfg.username || '')}" placeholder="留空保持原值"></div>
      <div><label>密码</label><input id="eNPw" value="" placeholder="留空保持原值"></div>
      <div><label>监听地址</label><input id="eNListen" value="${escHtml(cfg.listen || '')}" placeholder="留空保持原值"></div>
    </div></details><div class="hint">证书在节点菜单“上传 CA 证书”里换；换域名后要重新上传对应证书。</div>`;
  }
  // Trojan 不进 noSni：Reality 档的 SNI 就用上面这行改，CF 档的域名
  // 在下方传输方式里改（保存时 CF 档以域名为准，上面那行会被忽略）。
  const noSni = ['vmess', 'ss', 'socks', 'http', 'wireguard', 'dokodemo'].includes(n.protocol);
  openModal(`<h4>编辑节点：${escHtml(n.name)}</h4>
    <div class="hint" style="margin:0 0 12px">${escHtml(protoFull(n.protocol, cfg))}</div>
    <div class="form-grid">
      <div><label>节点名</label><input id="eName" value="${escHtml(n.name)}"></div>
      <div><label>节点地址</label><input id="eAddr" value="${escHtml(n.address)}"></div>
      <div><label>端口</label><input id="ePort" type="number" value="${n.port}"></div>
      ${noSni ? '' : `<div><label>${sniLabel(n.protocol, cfg.mode)}</label><input id="eSni" value="${escHtml(n.sni)}"></div>`}
    </div>
    <div class="hint">${sniHintEdit(n.protocol, cfg.mode)}</div>
    ${adv}
    <details class="adv"><summary>流量设置</summary><div class="form-grid">
      <div><label>限额模式</label><select id="eQMode"><option value="" ${!n.quota_mode ? 'selected' : ''}>不限</option><option value="total" ${n.quota_mode === 'total' ? 'selected' : ''}>总流量（上下行合计）</option><option value="down" ${n.quota_mode === 'down' ? 'selected' : ''}>下行总流量（只计出口）</option></select></div>
      <div><label>限额（G，面板的 GB）</label><input id="eQGB" type="number" step="any" value="${qGB}" placeholder="如 1000"></div>
    </div><div class="hint">服务器单项计算流量的，填“下行总流量”。达到限额前 1G 自动停用（填 1000G，到 999G 停），停了手动再开。</div></details>
    <div class="foot"><button class="btn ghost" onclick="closeModal()">取消</button><button class="btn" id="editSaveBtn" onclick="saveEditNode('${id}')">保存</button></div>
    <div class="msg" id="editMsg"></div>`, true);
}
async function saveEditNode(id){
  const btn = $('editSaveBtn'); btn.disabled = true;
  const port = parseInt($('ePort').value, 10);
  const n = nodeById(id);
  const body = {
    name: $('eName').value.trim(),
    address: $('eAddr').value.trim(),
    port: isNaN(port) ? undefined : port,
    sni: $('eSni') ? $('eSni').value.trim() : undefined,
    advanced: {},
  };
  if (n && n.protocol === 'vless'){
    const adv = {};
    if ($('eUuid').value.trim()) adv.uuid = $('eUuid').value.trim();
    adv.mode = $('eVlessMode').value;
    if ($('eVlessPath').value.trim()) adv.path = $('eVlessPath').value.trim();
    adv.flow = $('eFlow').value;
    if ($('eDest').value.trim()) adv.dest = $('eDest').value.trim();
    if ($('eShortId').value.trim()) adv.short_id = $('eShortId').value.trim();
    adv.fingerprint = $('eFp').value;
    adv.spider_x = $('eSpiderX').value || '/';
    if ($('eListen').value.trim()) adv.listen = $('eListen').value.trim();
    body.advanced = adv;
  } else if (n && n.protocol === 'hy2'){
    const adv = {};
    if ($('eHPass').value.trim()) adv.password = $('eHPass').value.trim();
    adv.obfs_type = $('eHObfs').value;
    if ($('eHObfsPass').value.trim()) adv.obfs_password = $('eHObfsPass').value.trim();
    if ($('eHUp').value.trim()) adv.up_mbps = $('eHUp').value.trim();
    if ($('eHDown').value.trim()) adv.down_mbps = $('eHDown').value.trim();
    if ($('eHListen').value.trim()) adv.listen = $('eHListen').value.trim();
    body.advanced = adv;
  } else if (n && n.protocol === 'mtg'){
    const adv = {};
    if ($('eMSecret').value.trim()) adv.secret = $('eMSecret').value.trim();
    if ($('eMListen').value.trim()) adv.listen = $('eMListen').value.trim();
    body.advanced = adv;
  } else if (n && n.protocol === 'vmess'){
    const adv = {};
    if ($('eVUuid').value.trim()) adv.uuid = $('eVUuid').value.trim();
    adv.mode = $('eVMode').value;
    if ($('eVPath').value.trim()) adv.path = $('eVPath').value.trim();
    if ($('eVListen').value.trim()) adv.listen = $('eVListen').value.trim();
    body.advanced = adv;
    body.sni = adv.mode === 'tcp' ? '' : $('eVDomain').value.trim();
  } else if (n && n.protocol === 'ss'){
    const adv = { method: $('eSSMethod').value };
    if ($('eSSPass').value.trim()) adv.password = $('eSSPass').value.trim();
    if ($('eSListen').value.trim()) adv.listen = $('eSListen').value.trim();
    body.advanced = adv;
  } else if (n && n.protocol === 'socks'){
    const adv = {};
    if ($('eSKUser').value.trim()) adv.user = $('eSKUser').value.trim();
    if ($('eSKPass').value.trim()) adv.pass = $('eSKPass').value.trim();
    if ($('eSKListen').value.trim()) adv.listen = $('eSKListen').value.trim();
    body.advanced = adv;
  } else if (n && n.protocol === 'http'){
    const adv = {};
    if ($('eHTUser').value.trim()) adv.user = $('eHTUser').value.trim();
    if ($('eHTPass').value.trim()) adv.pass = $('eHTPass').value.trim();
    if ($('eHTListen').value.trim()) adv.listen = $('eHTListen').value.trim();
    body.advanced = adv;
  } else if (n && n.protocol === 'trojan'){
    const adv = {};
    if ($('eTPass').value.trim()) adv.password = $('eTPass').value.trim();
    adv.mode = $('eTMode').value;
    if ($('eTPath').value.trim()) adv.path = $('eTPath').value.trim();
    if ($('eTListen').value.trim()) adv.listen = $('eTListen').value.trim();
    body.advanced = adv;
    body.sni = (adv.mode === 'cf' || adv.mode === 'h2' || adv.mode === 'httpupgrade') ? $('eTDomain').value.trim() : $('eSni') ? $('eSni').value.trim() : undefined;
  } else if (n && n.protocol === 'wireguard'){
    const adv = {};
    if ($('eWGIP').value.trim()) adv.client_ip = $('eWGIP').value.trim();
    if ($('eWGListen').value.trim()) adv.listen = $('eWGListen').value.trim();
    body.advanced = adv;
  } else if (n && n.protocol === 'tuic'){
    const adv = {};
    if ($('eTUuid').value.trim()) adv.uuid = $('eTUuid').value.trim();
    if ($('eTPw').value.trim()) adv.password = $('eTPw').value.trim();
    if ($('eTListen').value.trim()) adv.listen = $('eTListen').value.trim();
    body.advanced = adv;
  } else if (n && n.protocol === 'anytls'){
    const adv = {};
    if ($('eAName').value.trim()) adv.name = $('eAName').value.trim();
    if ($('eAPw').value.trim()) adv.password = $('eAPw').value.trim();
    if ($('eAListen').value.trim()) adv.listen = $('eAListen').value.trim();
    body.advanced = adv;
  } else if (n && n.protocol === 'naive'){
    const adv = {};
    if ($('eNUser').value.trim()) adv.username = $('eNUser').value.trim();
    if ($('eNPw').value.trim()) adv.password = $('eNPw').value.trim();
    if ($('eNListen').value.trim()) adv.listen = $('eNListen').value.trim();
    body.advanced = adv;
  }
  const qMode = $('eQMode') ? $('eQMode').value : '';
  const qGB = $('eQGB') ? parseFloat($('eQGB').value) : NaN;
  body.quota_mode = qMode;
  body.quota_bytes = qMode && !isNaN(qGB) && qGB > 0 ? Math.round(qGB * 1073741824) : 0;
  try {
    await api('/api/inbounds/' + id, 'PUT', body);
    toast('已保存'); closeModal();
    await refreshStatus(); await loadChains();
  } catch(e){
    $('editMsg').className = 'msg err'; $('editMsg').textContent = e.message;
    btn.disabled = false;
  }
}
async function cloneNode(id){
  try {
    const r = await api('/api/inbounds/' + id + '/clone', 'POST', {});
    toast('已克隆：' + r.inbound.name + '（默认停用，手动开启）');
    await refreshStatus(); await loadChains();
  } catch(e){ toast(e.message, true); }
}
async function toggleNode(id, enable){
  try { await api('/api/inbounds/' + id, 'PUT', { enabled: enable }); refreshStatus(); }
  // 开关失败时必须重载节点列表回滚视觉：以前只刷状态不刷 NODES，
  // 开关保持翻转后的错误状态，直到切视图才恢复。
  catch(e){ toast(e.message, true); try { const list = await api('/api/inbounds'); NODES = Array.isArray(list) ? list : []; } catch(_){} renderLocalRows(); }
}
function delNode(id, name){
  confirmModal('删除节点', `确定删除 <b>${name}</b> 吗？配置和累计用量会一起删掉。`, '删除', async ()=>{
    await api('/api/inbounds/' + id, 'DELETE');
    toast('已删除'); refreshStatus(); loadChains();
  });
}
// ---------- add inbound (popup) ----------
function addFormHTML(){
  return `<h4>添加入站</h4>
    <div class="tabs" id="protoTabs">
      <button data-proto="vless" class="on" onclick="setProto('vless')">VLESS<span class="tab-star">★</span></button>
      <button data-proto="hy2" onclick="setProto('hy2')">Hysteria2<span class="tab-star">★</span></button>
      <button data-proto="mtg" onclick="setProto('mtg')">MTProto</button>
      <button data-proto="vmess" onclick="setProto('vmess')">VMess</button>
      <button data-proto="trojan" onclick="setProto('trojan')">Trojan</button>
      <button data-proto="tuic" onclick="setProto('tuic')">TUIC</button>
      <button data-proto="anytls" onclick="setProto('anytls')">AnyTLS</button>
      <button data-proto="naive" onclick="setProto('naive')">Naive</button>
      <button data-proto="ss" onclick="setProto('ss')">SS</button>
      <button data-proto="socks" onclick="setProto('socks')">SOCKS</button>
      <button data-proto="http" onclick="setProto('http')">HTTP</button>
      <button data-proto="wireguard" onclick="setProto('wireguard')">WireGuard</button>
    </div>
    <div class="hint" id="protoStack" style="margin:0 0 14px">默认 · VLESS + Reality + TCP + xtls-rprx-vision</div>
    <div class="form-grid">
      <div>
        <label>端口</label>
        <div class="input-row">
          <input id="fPort" type="number" placeholder="留空自动建议">
          <button class="btn ghost small" onclick="fillSuggestPort()">自动建议</button>
        </div>
        <div class="hint" id="portHint"></div>
      </div>
      <div id="sniRow">
        <label id="sniLabel">伪装域名（Reality SNI）</label>
        <div class="input-row">
          <input id="fSni" placeholder="留空自动推荐">
          <button class="btn ghost small" onclick="randomSni()">换一个</button>
        </div>
        <div class="hint" id="sniHint">默认从精选清单里推荐，点“换一个”随机换。</div>
      </div>
      <div>
        <label>节点名</label>
        <input id="fName" placeholder="留空自动生成，如 VLESS-8443">
      </div>
      <div>
        <label>节点地址</label>
        <input id="fAddr" placeholder="留空自动取公网 IP">
      </div>
    </div>
    <div id="vlessOpts" style="display:none">
      <div class="form-grid" style="margin-top:12px">
        <div><label>传输方式</label><select id="vlMode" onchange="setProto('vless')">
          <option value="reality">Reality + TCP（默认，和 Trojan 同套）</option>
          <option value="ws">WS + TLS</option>
          <option value="h2">H2 + TLS</option>
          <option value="httpupgrade">HTTPUpgrade + TLS</option>
        </select></div>
        <div id="vlPathRow" style="display:none"><label>路径</label><input id="vlPath" placeholder="留空自动生成"></div>
      </div>
      <div class="hint" id="vlHint" style="display:none">TLS 档：填了域名，链接地址就是该域名（须解析到本机）；留空则链接地址用服务器 IP，同样能通。面板按域名生成自签证书，客户端要允许不验证证书（链接里 allowInsecure=1）。</div>
    </div>
    <div id="vmessOpts" style="display:none">
      <div class="form-grid" style="margin-top:12px">
        <div><label>传输方式</label><select id="vMode" onchange="setProto('vmess')">
          <option value="tcp">TCP 直连</option>
          <option value="cf">WS + Cloudflare（域名套 CF）</option>
          <option value="http">HTTP 明文</option>
          <option value="quic">QUIC + TLS</option>
          <option value="h2">H2 + TLS</option>
          <option value="httpupgrade">HTTPUpgrade + TLS</option>
        </select></div>
        <div id="vDomainRow" style="display:none"><label id="vDomainLabel">域名（已接入 Cloudflare，橙色云朵）</label><input id="vDomain" placeholder="如 example.com，必填"></div>
        <div id="vPathRow" style="display:none"><label>路径</label><input id="vPath" placeholder="留空自动生成"></div>
      </div>
      <div class="hint" id="vHint" style="display:none">CF 模式：访客连 CF:源站端口，CF 按同端口转发到源站（所以链接端口就是源站端口，不是 443）；域名必须已接入 CF（橙色云朵）并解析到这台服务器 IP；源站端口必须是 CF 允许的端口（443/2053/2083/2087/2096/8443）。源站是 WS+TLS 自签证书：区 SSL 模式是 Full 才能用（Strict 不接受自签，得用源站证书，面板暂不支持）。没有 CF 域名就用 TCP 直连。</div>
      <div class="hint" id="vTlsHint" style="display:none">TLS 档：填了域名，链接地址就是该域名（须解析到本机）；留空则链接地址用服务器 IP，同样能通。面板按域名生成自签证书，客户端要允许不验证证书。QUIC 档没有路径。</div>
      <div class="hint" id="vHttpHint" style="display:none">HTTP 档是明文 HTTP 传输：链接地址是服务器 IP，域名只做 Host 头约束（客户端发这个 Host 才能连上）。</div>
    </div>
    <div id="ssOpts" style="display:none">
      <div class="form-grid" style="margin-top:12px">
        <div><label>加密方法</label><select id="ssMethod">
          <option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm（默认，最新）</option>
          <option value="2022-blake3-aes-256-gcm">2022-blake3-aes-256-gcm</option>
          <option value="aes-256-gcm">aes-256-gcm（兼容最广）</option>
          <option value="chacha20-ietf-poly1305">chacha20-ietf-poly1305</option>
        </select></div>
        <div><label>密码</label><input id="ssPass" placeholder="留空自动生成（2022 方法自动生成对应长度密钥）"></div>
      </div>
    </div>
    <div id="socksOpts" style="display:none">
      <div class="form-grid" style="margin-top:12px">
        <div><label>用户名</label><input id="skUser" placeholder="留空自动生成"></div>
        <div><label>密码</label><input id="skPass" placeholder="留空自动生成"></div>
      </div>
      <div class="hint">SOCKS5 带账号密码，UDP 转发已开启。</div>
    </div>
    <div id="httpOpts" style="display:none">
      <div class="form-grid" style="margin-top:12px">
        <div><label>用户名</label><input id="htUser" placeholder="留空自动生成"></div>
        <div><label>密码</label><input id="htPass" placeholder="留空自动生成"></div>
      </div>
      <div class="hint">HTTP 代理带账号密码，客户端用 HTTP 代理或 CONNECT 方式走它。</div>
    </div>
    <div id="trojanOpts" style="display:none">
      <div class="form-grid" style="margin-top:12px">
        <div><label>传输方式</label><select id="tMode" onchange="setProto('trojan')">
          <option value="reality">Reality 直连（默认，和 VLESS 同套）</option>
          <option value="cf">WS + Cloudflare（域名套 CF）</option>
          <option value="h2">H2 + TLS</option>
          <option value="httpupgrade">HTTPUpgrade + TLS</option>
        </select></div>
        <div><label>密码</label><input id="tPass" placeholder="留空自动生成"></div>
        <div id="tDomainRow" style="display:none"><label id="tDomainLabel">域名（已接入 Cloudflare，橙色云朵）</label><input id="tDomain" placeholder="如 example.com，必填"></div>
        <div id="tPathRow" style="display:none"><label>路径</label><input id="tPath" placeholder="留空自动生成"></div>
      </div>
      <div class="hint" id="tHint" style="display:none">CF 模式和 VMess CF 同机制：访客连 CF:源站端口，源站 WS+TLS 自签证书，区 SSL 模式要是 Full（Strict 不接受自签）。</div>
      <div class="hint" id="tTlsHint" style="display:none">TLS 档：填了域名，链接地址就是该域名（须解析到本机）；留空则链接地址用服务器 IP，同样能通。面板按域名生成自签证书，客户端要允许不验证证书。</div>
    </div>
    <div id="tuicOpts" style="display:none">
      <div class="hint" style="margin-top:12px">TUIC 走 QUIC/UDP + 真 TLS：面板按伪装域名生成自签证书，客户端握手时 SNI 就是它（链接里 allow_insecure=1）。拥塞算法固定 bbr，零 RTT 默认关闭（防重放）。</div>
    </div>
    <div id="anytlsOpts" style="display:none">
      <div class="hint" style="margin-top:12px">AnyTLS 走 TCP + 真 TLS：面板按伪装域名生成自签证书，客户端握手时 SNI 就是它（链接里 insecure=1）。抗封锁思路和 Trojan 类似，但协议更轻。</div>
    </div>
    <div id="naiveOpts" style="display:none">
      <div class="hint" style="margin-top:12px">Naive 是 Chromium 真浏览器网络栈的代理，抗封锁最像正常浏览，但必须用真实域名 + CA 证书（自签不行）。建好节点后，在节点菜单里“上传 CA 证书”，上传后节点才能启动；链接交付的是参考客户端 JSON 配置，不是 URL。</div>
    </div>
    <div id="mtgOpts" style="display:none">
      <div class="hint" style="margin-top:12px">Telegram 专用：这个协议只能给 Telegram 客户端用（mtg 代理），不是通用翻墙协议；链接是 tg:// 格式，贴进 Telegram 就能用。</div>
    </div>
    <div id="wgOpts" style="display:none">
      <div class="hint" style="margin-top:12px">WireGuard 走 UDP：面板给每个节点生成两对密钥（服务端一对、客户端一对），客户端公钥直接写进服务端，建好就能用。创建成功后在节点行“链接”里复制完整配置，贴进官方 WireGuard 客户端（或扫二维码）。</div>
    </div>

    <details class="adv" id="advVless">
      <summary>高级配置</summary>
      <div class="form-grid">
        <div><label>UUID</label><div class="input-row"><input id="aUuid" placeholder="留空自动生成"><button class="btn ghost small" onclick="document.getElementById('aUuid').value=uuidv4()">随机</button></div></div>
        <div><label>流控</label><select id="aFlow"><option value="xtls-rprx-vision">xtls-rprx-vision</option><option value="">无</option></select></div>
        <div><label>目标地址（dest）</label><input id="aDest" placeholder="留空跟随伪装域名，如 www.samsung.com:443"></div>
        <div><label>ShortId</label><input id="aShortId" placeholder="留空自动生成"></div>
        <div><label>客户端指纹</label><select id="aFp"><option value="chrome">chrome</option><option value="firefox">firefox</option><option value="safari">safari</option><option value="random">random</option></select></div>
        <div><label>SpiderX</label><input id="aSpiderX" value="/" placeholder="/"></div>
        <div><label>监听地址</label><input id="aListen" placeholder="默认 0.0.0.0"></div>
      </div>
    </details>
    <details class="adv" id="advHy2" style="display:none">
      <summary>高级配置</summary>
      <div class="form-grid">
        <div><label>密码</label><input id="hPass" placeholder="留空自动生成"></div>
        <div><label>混淆类型</label><select id="hObfs"><option value="">无</option><option value="salamander">salamander</option></select></div>
        <div><label>混淆密码</label><input id="hObfsPass" placeholder="混淆类型选 salamander 时填写"></div>
        <div><label>上行限速（Mbps，留空不限）</label><input id="hUp" placeholder="如 100"></div>
        <div><label>下行限速（Mbps，留空不限）</label><input id="hDown" placeholder="如 100"></div>
        <div><label>监听地址</label><input id="hListen" placeholder="默认全部地址"></div>
      </div>
    </details>
    <details class="adv" id="advMtg" style="display:none">
      <summary>高级配置</summary>
      <div class="form-grid">
        <div class="full"><label>密钥（ee 开头，留空按伪装域名自动生成）</label><input id="mSecret" placeholder="留空自动生成"></div>
        <div><label>监听地址</label><input id="mListen" placeholder="默认 0.0.0.0"></div>
      </div>
    </details>

    <details class="adv"><summary>流量设置</summary><div class="form-grid">
      <div><label>限额模式</label><select id="qMode"><option value="">不限</option><option value="total">总流量（上下行合计）</option><option value="down">下行总流量（只计出口）</option></select></div>
      <div><label>限额（G，面板的 GB）</label><input id="qGB" type="number" step="any" placeholder="如 1000"></div>
    </div><div class="hint">服务器单项计算流量的，填“下行总流量”。达到限额前 1G 自动停用（填 1000G，到 999G 停），停了手动再开。</div></details>

    <div class="foot"><button class="btn ghost" onclick="closeModal()">取消</button><button class="btn" id="btnCreate" onclick="createInbound()">创建节点</button></div>
    <div class="msg" id="createMsg"></div>`;
}
function openAddModal(){
  CUR_PROTO = 'vless';
  openModal(addFormHTML(), true);
  fillSuggestPort(true);
}
function setProto(p){
  CUR_PROTO = p;
  document.querySelectorAll('#protoTabs button').forEach(b => b.classList.toggle('on', b.dataset.proto === p));
  $('advVless').style.display = p === 'vless' ? '' : 'none';
  $('advHy2').style.display = p === 'hy2' ? '' : 'none';
  $('advMtg').style.display = p === 'mtg' ? '' : 'none';
  // SNI 行只留给需要域名的协议：VLESS（Reality 伪装或 TLS 域名）、Hy2/MTG/TUIC/AnyTLS
  // （SNI）、Naive（真实域名）；SS/SOCKS/HTTP/WireGuard 没有域名概念；
  // VMess/Trojan 的域名只在非 TCP/非 Reality 档里才有意义，单独放在各自的 opts 里。
  const vlessMode = p === 'vless' ? $('vlMode').value : '';
  const trojanMode = p === 'trojan' ? $('tMode').value : '';
  const trojanDomain = p === 'trojan' && trojanMode !== 'reality';
  $('sniRow').style.display = (p === 'vless' || p === 'hy2' || p === 'mtg' || p === 'tuic' || p === 'anytls' || p === 'naive' || (p === 'trojan' && !trojanDomain)) ? '' : 'none';
  $('vlessOpts').style.display = p === 'vless' ? '' : 'none';
  $('mtgOpts').style.display = p === 'mtg' ? '' : 'none';
  $('vmessOpts').style.display = p === 'vmess' ? '' : 'none';
  $('trojanOpts').style.display = p === 'trojan' ? '' : 'none';
  $('tuicOpts').style.display = p === 'tuic' ? '' : 'none';
  $('anytlsOpts').style.display = p === 'anytls' ? '' : 'none';
  $('naiveOpts').style.display = p === 'naive' ? '' : 'none';
  $('wgOpts').style.display = p === 'wireguard' ? '' : 'none';
  $('ssOpts').style.display = p === 'ss' ? '' : 'none';
  $('socksOpts').style.display = p === 'socks' ? '' : 'none';
  $('httpOpts').style.display = p === 'http' ? '' : 'none';
  if (p === 'vless'){
    const tls = vlessMode !== 'reality';
    $('vlPathRow').style.display = tls ? '' : 'none';
    $('vlHint').style.display = tls ? '' : 'none';
    $('sniLabel').textContent = sniLabel('vless', vlessMode);
    $('fSni').placeholder = tls ? '留空用服务器 IP' : '留空自动推荐';
    $('protoStack').textContent = protoFull('vless', { mode: vlessMode, flow: $('aFlow') ? $('aFlow').value : 'xtls-rprx-vision' });
  } else if (p === 'vmess'){
    const mode = $('vMode').value;
    const cf = mode === 'cf';
    const tls = mode === 'quic' || mode === 'h2' || mode === 'httpupgrade';
    $('vDomainRow').style.display = mode === 'tcp' ? 'none' : '';
    $('vDomainLabel').textContent = cf ? '域名（已接入 Cloudflare，橙色云朵）' : (mode === 'http' ? '域名（HTTP Host 头）' : '域名（须解析到本机）');
    if (cf) $('vDomain').placeholder = '如 example.com，必填'; else if (tls) $('vDomain').placeholder = '留空用服务器 IP';
    $('vPathRow').style.display = (cf || mode === 'http' || mode === 'h2' || mode === 'httpupgrade') ? '' : 'none';
    $('vHint').style.display = cf ? '' : 'none';
    $('vTlsHint').style.display = tls ? '' : 'none';
    $('vHttpHint').style.display = mode === 'http' ? '' : 'none';
    $('protoStack').textContent = protoFull('vmess', { mode: mode });
  } else if (p === 'trojan'){
    $('tDomainRow').style.display = trojanDomain ? '' : 'none';
    $('tDomainLabel').textContent = trojanMode === 'cf' ? '域名（已接入 Cloudflare，橙色云朵）' : '域名（须解析到本机）';
    if (trojanMode === 'cf') $('tDomain').placeholder = '如 example.com，必填'; else if (trojanDomain) $('tDomain').placeholder = '留空用服务器 IP';
    $('tPathRow').style.display = trojanDomain ? '' : 'none';
    $('tHint').style.display = trojanMode === 'cf' ? '' : 'none';
    $('tTlsHint').style.display = (trojanMode === 'h2' || trojanMode === 'httpupgrade') ? '' : 'none';
    $('protoStack').textContent = protoFull('trojan', { mode: trojanMode });
  } else {
    $('sniLabel').textContent = sniLabel(p);
    $('protoStack').textContent = protoFull(p, null);
  }
  $('sniHint').textContent = p === 'mtg'
    ? 'MTProto 本身是 TCP 密钥加密，不是 TLS；这个域名只是 Fake-TLS 伪装，编进 ee 密钥里，让流量看起来像去这个域名的 HTTPS。'
    : (p === 'hy2' || p === 'tuic' || p === 'anytls')
    ? '面板按这个域名生成自签证书，客户端握手时 SNI 就是它（链接里 insecure=1，证书不校验真伪）。不需要真实域名，也不需要把域名解析到服务器，留空会自动推荐一个。'
    : p === 'naive'
    ? 'Naive 的域名必须是真实域名：CA 证书上的名字就是它，且要解析到这台服务器。建好节点后在节点菜单里上传证书。'
    : p === 'vless' && vlessMode !== 'reality'
    ? 'TLS 档：填了域名，链接地址就是该域名（须解析到本机）；留空则链接地址用服务器 IP，同样能通。面板按域名生成自签证书，客户端要允许不验证证书。'
    : '默认从精选清单里推荐，点“换一个”随机换。';
  fillSuggestPort(true);
}
async function fillSuggestPort(quiet){
  try {
    let q = '/api/suggest-port?protocol=' + CUR_PROTO;
    if (CUR_PROTO === 'vmess' && $('vMode') && $('vMode').value === 'cf') q += '&mode=cf';
    if (CUR_PROTO === 'trojan' && $('tMode') && $('tMode').value === 'cf') q += '&mode=cf';
    const r = await api(q);
    $('fPort').value = r.port;
    $('portHint').textContent = r.reason;
  } catch(e){ if (!quiet) toast(e.message, true); }
}
async function randomSni(){
  try {
    const cur = $('fSni').value.trim();
    const r = await api('/api/sni-random?exclude=' + encodeURIComponent(cur));
    $('fSni').value = r.domain;
    $('sniHint').textContent = r.domain + '（' + r.label + '）';
  } catch(e){ toast(e.message, true); }
}
async function createInbound(){
  const btn = $('btnCreate');
  btn.disabled = true; btn.textContent = '创建中…';
  $('createMsg').textContent = '';
  // 前端先拦一道：需要的内核没装，根本不发创建请求；
  // 后端还会再拦一道，没装核的节点一个都建不出来。
  const needCore = { vless: 'sing-box', vmess: 'sing-box', ss: 'sing-box', socks: 'sing-box', http: 'sing-box', trojan: 'sing-box', wireguard: 'sing-box', hy2: 'sing-box', tuic: 'sing-box', anytls: 'sing-box', naive: 'sing-box', mtg: 'mtg' }[CUR_PROTO];
  const coreRow = CORE_LIST.find(c => c.name === needCore);
  if (coreRow && !coreRow.installed){
    $('createMsg').className = 'msg err';
    $('createMsg').textContent = needCore + ' 内核还没安装：先去“系统状态”页的内核卡片安装 ' + needCore + '，装好再创建节点';
    btn.disabled = false; btn.textContent = '创建节点';
    return;
  }
  const port = parseInt($('fPort').value, 10);
  const qMode = $('qMode') ? $('qMode').value : '';
  const qGB = $('qGB') ? parseFloat($('qGB').value) : NaN;
  const body = {
    protocol: CUR_PROTO,
    port: isNaN(port) ? 0 : port,
    name: $('fName').value.trim(),
    address: $('fAddr').value.trim(),
    sni: $('fSni').value.trim(),
    advanced: {},
    quota_mode: qMode,
    quota_bytes: qMode && !isNaN(qGB) && qGB > 0 ? Math.round(qGB * 1073741824) : 0,
  };
  if (CUR_PROTO === 'vless'){
    const adv = {};
    if ($('aUuid').value.trim()) adv.uuid = $('aUuid').value.trim();
    adv.mode = $('vlMode').value;
    if ($('vlPath').value.trim()) adv.path = $('vlPath').value.trim();
    adv.flow = $('aFlow').value;
    if ($('aDest').value.trim()) adv.dest = $('aDest').value.trim();
    if ($('aShortId').value.trim()) adv.short_id = $('aShortId').value.trim();
    adv.fingerprint = $('aFp').value;
    adv.spider_x = $('aSpiderX').value || '/';
    if ($('aListen').value.trim()) adv.listen = $('aListen').value.trim();
    body.advanced = adv;
  } else if (CUR_PROTO === 'hy2'){
    const adv = {};
    if ($('hPass').value.trim()) adv.password = $('hPass').value.trim();
    if ($('hObfs').value) adv.obfs_type = $('hObfs').value;
    if ($('hObfsPass').value.trim()) adv.obfs_password = $('hObfsPass').value.trim();
    if ($('hUp').value.trim()) adv.up_mbps = $('hUp').value.trim();
    if ($('hDown').value.trim()) adv.down_mbps = $('hDown').value.trim();
    if ($('hListen').value.trim()) adv.listen = $('hListen').value.trim();
    body.advanced = adv;
  } else if (CUR_PROTO === 'mtg'){
    const adv = {};
    if ($('mSecret').value.trim()) adv.secret = $('mSecret').value.trim();
    if ($('mListen').value.trim()) adv.listen = $('mListen').value.trim();
    body.advanced = adv;
  } else if (CUR_PROTO === 'vmess'){
    const mode = $('vMode').value;
    body.sni = mode === 'tcp' ? '' : $('vDomain').value.trim();
    body.advanced = { mode: mode, path: (mode === 'tcp' || mode === 'quic') ? '' : $('vPath').value.trim() };
  } else if (CUR_PROTO === 'trojan'){
    const mode = $('tMode').value;
    body.sni = mode === 'reality' ? $('fSni').value.trim() : $('tDomain').value.trim();
    const adv = { mode: mode, path: mode === 'reality' ? '' : $('tPath').value.trim() };
    if ($('tPass').value.trim()) adv.password = $('tPass').value.trim();
    body.advanced = adv;
  } else if (CUR_PROTO === 'wireguard'){
    body.advanced = {};
  } else if (CUR_PROTO === 'tuic' || CUR_PROTO === 'anytls' || CUR_PROTO === 'naive'){
    body.advanced = {};
  } else if (CUR_PROTO === 'ss'){
    const adv = { method: $('ssMethod').value };
    if ($('ssPass').value.trim()) adv.password = $('ssPass').value.trim();
    body.advanced = adv;
  } else if (CUR_PROTO === 'socks'){
    const adv = {};
    if ($('skUser').value.trim()) adv.user = $('skUser').value.trim();
    if ($('skPass').value.trim()) adv.pass = $('skPass').value.trim();
    body.advanced = adv;
  } else if (CUR_PROTO === 'http'){
    const adv = {};
    if ($('htUser').value.trim()) adv.user = $('htUser').value.trim();
    if ($('htPass').value.trim()) adv.pass = $('htPass').value.trim();
    body.advanced = adv;
  }
  try {
    const r = await api('/api/inbounds', 'POST', body);
    closeModal();
    // WireGuard 没有 URL 链接、Naive 交付的是 JSON 配置，都用多行框展示。
    const linkField = (CUR_PROTO === 'wireguard' || CUR_PROTO === 'naive')
      ? `<label>${CUR_PROTO === 'naive' ? 'Naive 配置（参考客户端 JSON 配置，不是 URL，别贴进 URL 导入框）' : 'WireGuard 配置（贴进官方客户端，或扫下方二维码）'}</label><textarea id="lkMain" readonly rows="11" style="width:100%;font-family:monospace">${escHtml(r.link)}</textarea><div style="margin-top:8px"><button class="btn ghost small" onclick="copyText('lkMain')">复制配置</button></div>`
      : `<label>节点链接</label><div class="input-row"><input id="lkMain" readonly value="${escHtml(r.link)}"><button class="btn ghost small" onclick="copyText('lkMain')">复制</button></div>`;
    const link6Field = !r.link6 ? '' : (CUR_PROTO === 'wireguard'
      ? `<div style="margin-top:12px"><label>WireGuard 配置 IPv6</label><textarea id="lkMain6" readonly rows="11" style="width:100%;font-family:monospace">${escHtml(r.link6)}</textarea><div style="margin-top:8px"><button class="btn ghost small" onclick="copyText('lkMain6')">复制配置</button></div></div>`
      : `<div style="margin-top:12px"><label>节点链接 IPv6</label><div class="input-row"><input id="lkMain6" readonly value="${escHtml(r.link6)}"><button class="btn ghost small" onclick="copyText('lkMain6')">复制</button></div></div>`);
    openModal(`<h4>节点已创建：${escHtml(r.inbound.name)}</h4>
      ${linkField}
      ${link6Field}
      ${r.tme_link ? `<div style="margin-top:12px"><label>t.me 链接</label><div class="input-row"><input id="lkTme" readonly value="${escHtml(r.tme_link)}"><button class="btn ghost small" onclick="copyText('lkTme')">复制</button></div></div>` : ''}
      ${CUR_PROTO === 'naive' ? `<div class="hint" style="margin-top:12px">Naive 节点还没证书、暂时启动不了：去入站列表点节点行的 ⋮ → “上传 CA 证书”，上传后立即启动。</div>` : ''}
      <div class="qr-box"><img src="/api/inbounds/${r.inbound.id}/qr" alt="二维码"></div>
      <div class="foot"><button class="btn" onclick="closeModal()">知道了</button></div>`);
    await refreshStatus(); await loadChains();
  } catch(e){ $('createMsg').className = 'msg err'; $('createMsg').textContent = '创建失败：' + e.message; }
  btn.disabled = false; btn.textContent = '创建节点';
}

// ---------- chains & bnodes ----------
async function loadChains(){
  try { const c = await api('/api/chains'); CHAINS = Array.isArray(c) ? c : []; } catch(e){ CHAINS = []; }
  try { const b = await api('/api/bnodes'); BNODES = Array.isArray(b) ? b : []; } catch(e){ BNODES = []; }
  try { const list = await api('/api/inbounds'); NODES = Array.isArray(list) ? list : []; } catch(e){}
  renderBNodeRows();
  renderChainRows();
  renderLocalRows();
}
function renderBNodeRows(){
  const el = $('bnodeRows');
  if (!el) return;
  if (!BNODES.length){ el.innerHTML = '<div class="empty">还没有其他节点，点右上角“添加其他节点”，粘贴别的服务器的节点链接进来</div>'; return; }
  el.innerHTML = BNODES.map(b => `
    <div class="row">
      <div class="grow"><div class="t">${escHtml(b.name)} ${protoBadge(b.protocol)}</div>
        <div class="s mono">${escHtml(b.link.slice(0, 90))}${b.link.length > 90 ? '…' : ''}</div></div>
      <span class="ping" id="bping-${b.id}" title="本机到该节点服务器的延迟">测活中…</span>
      <button class="btn ghost small" data-link="${escHtml(b.link)}" onclick="copyBLink(this)">复制链接</button>
      <button class="btn ghost small" style="color:var(--red)" onclick="delBNode('${b.id}','${escHtml(b.name)}')">删除</button>
    </div>`).join('');
  refreshBNodePing();
}
// 其他节点测活：本机 → B 节点服务器的 TCP 建连延迟，
// 入站列表页每 3 秒刷新一次，只改 ping 数字，不重绘列表。
async function refreshBNodePing(){
  if (!$('view-inbounds') || !$('view-inbounds').classList.contains('on')) return;
  if (!BNODES.length) return;
  try {
    const rows = await api('/api/bnodes-latency');
    rows.forEach(r => {
      const el = $('bping-' + r.id);
      if (!el) return;
      if (r.kind === 'udp') el.textContent = 'UDP 协议不适用';
      else if (r.ms >= 0) el.textContent = r.ms + 'ms';
      else el.textContent = '不通';
    });
  } catch(e){}
}
function copyBLink(btn){
  copyText(null, btn.dataset.link);
}
function delBNode(id, name){
  const used = CHAINS.filter(c => c.bnode_id === id);
  const warn = used.length ? `它正被 ${used.length} 条链式规则用着，删了那条链式会一起失效（链式本身不会自动删，B 节点没了会启动失败）。` : '';
  confirmModal('删除其他节点', `确定删除 <b>${name}</b> 吗？${warn}`, '删除', async ()=>{
    await api('/api/bnodes/' + id, 'DELETE');
    toast('已删除'); loadChains();
  });
}
function openAddBNodeModal(){
  openModal(`<h4>添加其他节点</h4>
    <label>粘贴节点链接（自动识别协议）</label>
    <input id="bLink" placeholder="vless://、vmess://、trojan://、ss://、socks://、http://、hysteria2://">
    <div class="hint">B 节点只支持这 7 种：VLESS、VMess、Trojan、SS、SOCKS、HTTP、Hysteria2。MTProto（tg://）是 TG 客户端专用协议，不能做 B 节点；其他协议的链接保存时会被直接拒绝，不会混进来。</div>
    <div class="foot"><button class="btn ghost" onclick="closeModal()">取消</button><button class="btn" id="bSaveBtn" onclick="saveBNodeFromModal()">保存</button></div>
    <div class="msg" id="bMsg"></div>`);
}
async function saveBNodeFromModal(){
  const link = $('bLink').value.trim();
  if (!link){ $('bMsg').className = 'msg err'; $('bMsg').textContent = '请先粘贴节点链接'; return; }
  // 前端先拦一道：协议不在 B 节点范围内的，根本不发请求；
  // 后端 ParseBLink 还会再拦一道，两道都过不去才进得来。
  const scheme = link.split('://')[0].toLowerCase();
  const okSchemes = ['vless', 'vmess', 'trojan', 'ss', 'socks', 'socks5', 'http', 'https', 'hysteria2', 'hy2'];
  if (!okSchemes.includes(scheme)){
    $('bMsg').className = 'msg err';
    $('bMsg').textContent = '不支持的协议：' + scheme + '（B 节点只支持 VLESS/VMess/Trojan/SS/SOCKS/HTTP/Hysteria2，MTProto 不能做 B 节点）';
    return;
  }
  const btn = $('bSaveBtn'); btn.disabled = true;
  try {
    const r = await api('/api/bnodes', 'POST', { link });
    toast('已保存：' + r.name + '（' + r.protocol + '）');
    closeModal(); await loadChains();
  } catch(e){
    $('bMsg').className = 'msg err'; $('bMsg').textContent = '保存失败：' + e.message;
    btn.disabled = false;
  }
}
function vlessOptions(selectedId, excludeChainId){
  // A 节点下拉：把所有本地节点都列出来，选不了的灰掉并写明原因，
  // 不再只列 VLESS——否则像甲骨文这样只剩 HY2/MTG 可选时，
  // 下拉里一片空白，用户根本不知道为什么不能设。
  if (!NODES.length) return '<option value="">（暂无本地节点，先去添加入站）</option>';
  return NODES.map(n => {
    let dis = '', note = '';
    if (n.protocol !== 'vless'){
      dis = ' disabled';
      note = '（只有 VLESS 能做 A 节点）';
    } else {
      const usedBy = CHAINS.find(c => c.inbound_id === n.id && c.id !== excludeChainId);
      if (usedBy){ dis = ' disabled'; note = '（已有链式）'; }
    }
    const sel = n.id === selectedId ? ' selected' : '';
    return `<option value="${n.id}"${sel}${dis}>${escHtml(n.name)} :${n.port}${note}</option>`;
  }).join('');
}
function bnodeOptions(selectedId){
  if (!BNODES.length) return '<option value="">（暂无其他节点，先添加其他节点）</option>';
  return BNODES.map(b => `<option value="${b.id}"${b.id === selectedId ? ' selected' : ''}>${escHtml(b.name)}（${b.protocol}）</option>`).join('');
}
function chainFormHTML(chain){
  const c = chain || {};
  return `<div class="form-grid chain-form">
    <div class="full"><label>链式名称</label><input id="chName" value="${escHtml(c.name || '')}" placeholder="留空自动命名（链式-节点名），订阅里链式入口就显示这个名字"></div>
    <div><label>A 节点（本机 VLESS 节点，一个 A 节点只能有一条链式）</label><select id="chA">${vlessOptions(c.inbound_id || '', c.id || '')}</select><div class="hint">只有 VLESS 能做 A 节点：链式路由在 sing-box 里，MTProto 是独立核心，不能做 A 节点。想再加一条链式，先去添加一个 VLESS 节点，或者编辑已有的链式。</div></div>
    <div><label>B 节点（从其他节点里选）</label><select id="chB">${bnodeOptions(c.bnode_id || '')}</select><div class="hint">B 节点要在入站列表的“其他节点”里先添加：粘贴别的服务器的节点链接进来。B 节点只支持 VLESS/VMess/Trojan/SS/SOCKS/HTTP/Hysteria2，MTProto 不能做 B 节点。</div></div>
    <div class="full"><label>域名或 IP 清单（一行一个，域名支持子域，如 example.com；IP 支持 CIDR，如 1.2.3.4/32）</label><textarea id="chList" placeholder="example.com&#10;1.2.3.4">${escHtml(c.list || '')}</textarea></div>
  </div>`;
}
function openChainModal(){
  openModal(`<h4>添加链式</h4>${chainFormHTML(null)}
    <div class="foot"><button class="btn ghost" onclick="closeModal()">取消</button><button class="btn" id="chSaveBtn" onclick="saveChain(null)">保存</button></div>
    <div class="msg" id="chMsg"></div>`);
}
function openChainEditModal(id){
  const c = CHAINS.find(x => x.id === id);
  if (!c) return;
  openModal(`<h4>编辑链式：${escHtml(c.name)}</h4>${chainFormHTML(c)}
    <div class="foot"><button class="btn ghost" onclick="closeModal()">取消</button><button class="btn" id="chSaveBtn" onclick="saveChain('${id}')">保存</button></div>
    <div class="msg" id="chMsg"></div>`);
}
async function saveChain(id){
  const a = $('chA').value, b = $('chB').value, list = $('chList').value.trim(), name = $('chName').value.trim();
  if (id && !name){ $('chMsg').className = 'msg err'; $('chMsg').textContent = '链式名不能为空'; return; }
  if (!a || !b){ $('chMsg').className = 'msg err'; $('chMsg').textContent = 'A 节点和 B 节点都要选'; return; }
  const aOpt = $('chA').selectedOptions[0];
  if (aOpt && aOpt.disabled){
    $('chMsg').className = 'msg err';
    $('chMsg').textContent = '这个 A 节点选不了：' + (aOpt.text.includes('已有链式') ? '它已经有一条链式了，一个 A 节点只能有一条' : '只有 VLESS 能做 A 节点') + '。想再加一条，先去添加一个 VLESS 节点。';
    return;
  }
  if (!list){ $('chMsg').className = 'msg err'; $('chMsg').textContent = '域名或 IP 清单不能为空'; return; }
  const btn = $('chSaveBtn'); btn.disabled = true;
  try {
    if (id){
      await api('/api/chains/' + id, 'PUT', { name, inbound_id: a, bnode_id: b, list });
      toast('链式已保存');
    } else {
      await api('/api/chains', 'POST', { name, inbound_id: a, bnode_id: b, list });
      toast('链式规则已添加');
    }
    closeModal(); await loadChains();
  } catch(e){
    $('chMsg').className = 'msg err'; $('chMsg').textContent = e.message;
    btn.disabled = false;
  }
}
function renderChainRows(){
  const el = $('chainRows');
  if (!el) return;
  if (!CHAINS.length){ el.innerHTML = '<div class="empty">还没有链式规则</div>'; return; }
  el.innerHTML = CHAINS.map(c => {
    const a = NODES.find(n => n.id === c.inbound_id);
    const b = BNODES.find(x => x.id === c.bnode_id);
    const lines = (c.list || '').split('\n').filter(x => x.trim()).length;
    return `<div class="row">
      <input type="checkbox" class="switch" ${c.enabled ? 'checked' : ''} onchange="toggleChain('${c.id}', this.checked)">
      <div class="grow"><div class="t">${escHtml(c.name)}</div>
        <div class="s">A：${a ? escHtml(a.name) : c.inbound_id} → B：${b ? escHtml(b.name) : c.bnode_id} · 清单 ${lines} 条 · ${c.enabled ? '生效中' : '已停用'}</div></div>
      <button class="btn ghost small" onclick="openChainEditModal('${c.id}')">编辑</button>
      <button class="btn ghost small" style="color:var(--red)" onclick="delChain('${c.id}','${escHtml(c.name)}')">删除</button>
    </div>`;
  }).join('');
}
async function toggleChain(id, enable){
  try { await api('/api/chains/' + id, 'PUT', { enabled: enable }); loadChains(); }
  catch(e){ toast(e.message, true); loadChains(); }
}
function delChain(id, name){
  confirmModal('删除链式规则', `确定删除 <b>${name}</b> 吗？`, '删除', async ()=>{
    await api('/api/chains/' + id, 'DELETE');
    toast('已删除'); loadChains();
  });
}

// ---------- settings ----------
async function loadSettings(){
  try {
    await loadPanelCerts();
  } catch(e){}
  try {
    const me = await api('/api/me');
    if ($('curUser')) $('curUser').value = me.username || '';
  } catch(e){}
  checkUpdate(true);
}
async function changeUsername(){
  const v = $('newUser').value.trim();
  if (!v){ toast('新账号不能为空', true); return; }
  try {
    const r = await api('/api/settings/username', 'POST', { new: v });
    toast('账号已改为 ' + r.username + '，立即生效');
    $('curUser').value = r.username; $('newUser').value = '';
  } catch(e){ toast(e.message, true); }
}
// ---------- 在线更新 ----------
// 自动检查：打开面板设置时查一次；面板启动后后台每 12 小时再查一次
// （服务端存着最新版和检查时间）。更新永远手动点，不自动装。
let UPD_LATEST = '';
async function checkUpdate(auto){
  const msg = $('updMsg'); if (!msg) return;
  const btn = $('updCheckBtn');
  if (btn) btn.disabled = true;
  if (!auto) msg.textContent = '正在检查…';
  try {
    const r = await api('/api/update/check', 'POST', {});
    if ($('updCur')) $('updCur').value = r.current || '';
    if ($('updLatest')) $('updLatest').value = r.latest || '未查到';
    if ($('updChecked')) $('updChecked').value = r.checked_at || '';
    UPD_LATEST = r.latest || '';
    const apply = $('updApplyBtn');
    if (apply) apply.disabled = !r.has_update;
    msg.textContent = r.has_update ? ('有新版 ' + r.latest + '，点“更新到最新版”手动更新。') : (r.latest ? '已是最新版。' : '没查到新版信息，稍后再试。');
  } catch(e){
    msg.textContent = '检查失败：' + e.message;
  }
  if (btn) btn.disabled = false;
}
async function applyUpdate(){
  if (!UPD_LATEST) { toast('先检查更新', true); return; }
  const btn = $('updApplyBtn'); const msg = $('updMsg');
  btn.disabled = true; btn.textContent = '下载中…';
  let timer = setInterval(async () => {
    try {
      const p = await api('/api/update/progress');
      if (p.phase === 'installing') btn.textContent = '安装中…';
      else if (p.phase === 'downloading') btn.textContent = '下载中…';
      else if (p.phase === 'restarting') btn.textContent = '重启中…';
    } catch(_){}
  }, 800);
  try {
    const r = await api('/api/update/apply', 'POST', {});
    clearInterval(timer);
    if (r.restart_required){
      msg.textContent = '已更新到 ' + r.version + '，但面板未自动重启（非标准安装路径），请手动重启面板服务后再登录验证版本。';
      btn.disabled = false; btn.textContent = '更新到最新版';
      return;
    }
    msg.textContent = '已更新到 ' + r.version + '，面板正在重启…';
    btn.textContent = '重启中…';
    // 重启后内存会话全清，必须重新登录；轮询面板起来后回到登录页。
    let tries = 0;
    const wait = setInterval(async () => {
      tries++;
      try {
        await fetch('/api/setup-status');
        clearInterval(wait);
        msg.textContent = '更新完成（' + r.version + '），请重新登录。';
        btn.textContent = '更新到最新版';
        showLogin();
      } catch(_){}
      if (tries > 45){ clearInterval(wait); msg.textContent = '面板 90 秒还没起来，请手动刷新或看服务日志。'; btn.disabled = false; btn.textContent = '更新到最新版'; }
    }, 2000);
  } catch(e){
    clearInterval(timer);
    msg.textContent = '更新失败：' + e.message;
    btn.disabled = false; btn.textContent = '更新到最新版';
  }
}
// ---------- 面板域名和证书（手动添加 / 在线申请 / 启用 HTTPS） ----------
let PANEL_CERTS = [];
let PANEL_CERT_ID = '';
function panelCertDomain(id){
  for (const x of PANEL_CERTS || []) if (x.id === id) return (x.domains || [])[0] || '';
  return '';
}
// HTTPS 提示地址：当前选用证书的首域名（证书域名就是面板域名），
// 没有证书才回落到当前访问 host。端口一律用当前访问端口（面板端口）。
function panelHttpsUrl(certId){
  const host = panelCertDomain(certId || PANEL_CERT_ID) || location.hostname;
  const port = location.port ? ':' + location.port : '';
  return 'https://' + host + port;
}
function panelCertNameById(list, id){
  for (const x of list || []) if (x.id === id) return x.name;
  return id || '';
}
async function loadPanelCerts(){
  try {
    const c = await api('/api/settings/certs');
    const list = c.certs || [];
    PANEL_CERTS = list; PANEL_CERT_ID = c.panel_cert || '';
    const box = $('panelCertList'); if (!box) return;
    if (!list.length){
      box.textContent = '还没有证书：先手动添加或在线申请一张，再选它启用 HTTPS。';
    } else {
      box.innerHTML = list.map(x => {
        const exp = x.days_left === -9999 ? '到期未知'
          : (x.days_left < 0 ? '已过期 ' + (-x.days_left) + ' 天' : '剩余 ' + x.days_left + ' 天');
        return '<div>' + escHtml(x.name) + '（' + escHtml((x.domains || []).join('、')) + '，' + exp
          + (x.selected ? '，面板当前选用' : '') + '）</div>';
      }).join('');
    }
    const sel = $('panelHttpsCert'); if (sel){
      sel.innerHTML = '<option value="">— 选择证书 —</option>' + list.map(x =>
        '<option value="' + escHtml(x.id) + '"' + (x.id === c.panel_cert ? ' selected' : '') + '>'
        + escHtml(x.name) + '（' + escHtml((x.domains || [])[0] || x.id) + '）</option>').join('');
    }
    const hint = $('panelHttpsHint'); if (hint){
      if (c.panel_https){
        const u = panelHttpsUrl(c.panel_cert);
        hint.innerHTML = 'HTTPS 已启用（证书：' + escHtml(panelCertNameById(list, c.panel_cert))
          + '）。请用 <a href="' + escHtml(u) + '">' + escHtml(u) + '</a> 访问面板。';
      } else {
        hint.textContent = '当前走 HTTP。选一张证书并启用 HTTPS 后，面板地址变为 https。';
      }
    }
  } catch(e){}
}
async function savePanelHttps(enable){
  if (enable){
    const cert = $('panelHttpsCert').value;
    if (!cert){ toast('请先选择一张证书', true); return; }
    const u = panelHttpsUrl(cert);
    confirmModal('启用 HTTPS',
      '启用后，面板同时支持两种打开方式：<a href="' + escHtml(u) + '">' + escHtml(u) + '</a>（加密，日常用这个）；http://' + location.host + ' 也能打开，但是明文，登录信息不加密，只当备用入口。证书丢了/过期，重启面板会自动回落 HTTP。',
      '确定启用', async ()=>{
      await api('/api/settings/panel-https', 'POST', { enabled: true, cert });
      // 启用后 http 页仍可调接口（双协议），直接把 https 链接写进提示。
      const hint = $('panelHttpsHint'); if (hint){
        hint.innerHTML = 'HTTPS 已启用。请用 <a href="' + escHtml(u) + '">' + escHtml(u) + '</a> 访问面板。';
      }
      toast('HTTPS 已启用，请用 https 地址访问面板');
    });
  } else {
    try {
      await api('/api/settings/panel-https', 'POST', { enabled: false });
      // 服务器已切回 HTTP：当前若是 https 页，刷新会失败，直接跳回 http。
      location.href = 'http://' + location.host + location.pathname;
    } catch(e){ toast(e.message, true); }
  }
}
function openManualCertDialog(){
  openModal('<h3>手动添加证书</h3><div class="form-grid">'
    + '<div class="full"><label>证书名（备注，留空 = 用证书里的第一域名）</label><input id="mCertName"></div>'
    + '<div class="full"><label>证书文件（.crt / .pem，须与私钥成对）</label><input id="mCertFile" type="file"></div>'
    + '<div class="full"><label>私钥文件（.key）</label><input id="mCertKey" type="file"></div>'
    + '<div class="full"><button class="btn" onclick="uploadPanelCert()">上传添加</button>'
    + '<button class="btn ghost" onclick="closeModal()">关闭</button></div>'
    + '<div class="full"><div class="hint" id="mCertResult"></div></div></div>');
}
async function uploadPanelCert(){
  const name = $('mCertName').value.trim();
  const cert = $('mCertFile').files[0], key = $('mCertKey').files[0];
  const res = $('mCertResult');
  if (!cert || !key){ res.textContent = '请同时选择证书与私钥文件'; return; }
  const fd = new FormData();
  fd.append('name', name); fd.append('cert', cert); fd.append('key', key);
  res.textContent = '上传中…';
  try {
    const r = await fetch('/api/settings/cert-manual', { method: 'POST', body: fd });
    let j = {}; try { j = await r.json(); } catch(e){}
    if (r.status === 401){ showLogin(); throw new Error('未登录'); }
    if (!j.ok) throw new Error(j.error || ('请求失败 ' + r.status));
    res.textContent = '已添加证书：' + (j.data.cert ? j.data.cert.name : name);
    await loadPanelCerts();
  } catch(e){ res.textContent = '失败：' + e.message; }
}
async function openAcmeDialog(){
  let configured = false;
  try { const c = await api('/api/settings/certs'); configured = !!c.cf_token_configured; } catch(e){}
  openModal('<h3>在线申请证书</h3><div class="form-grid">'
    + '<div class="full"><label>域名（一行一个，首域名决定证书存放名）</label><textarea id="aCertDomains" rows="3"></textarea></div>'
    + '<div class="full"><label>证书名（备注，留空 = 用首域名）</label><input id="aCertName"></div>'
    + '<div class="full"><label>验证方式</label><select id="aCertMethod">'
    + '<option value="">自动（80 空闲走 HTTP-01，80 被占走 DNS-01）</option>'
    + '<option value="http-01">HTTP-01（需 80 端口空闲）</option>'
    + '<option value="dns-01">DNS-01（需 Cloudflare Token）</option></select></div>'
    + '<div class="full"><label>Cloudflare API Token（DNS-01 用，需对应域名的 DNS 编辑权限；只存服务器本地，用于自动续期）</label>'
    + '<input id="aCertToken" type="password" placeholder="' + (configured ? '已保存 Token（留空表示沿用，填新值则覆盖）' : 'Cloudflare API Token') + '"></div>'
    + '<div class="full"><div class="hint">自动：80 空闲走 HTTP-01，80 被占走 DNS-01（需 Token）。通配符域名只能 DNS-01。默认到期前 30 天自动续期。</div></div>'
    + '<div class="full"><button class="btn" onclick="applyAcme()">开始申请</button>'
    + '<button class="btn ghost" onclick="closeModal()">关闭</button></div>'
    + '<div class="full"><div class="hint" id="aCertResult"></div></div></div>');
}
async function applyAcme(){
  const domains = $('aCertDomains').value.split('\n').map(s => s.trim()).filter(Boolean);
  const name = $('aCertName').value.trim();
  const method = $('aCertMethod').value;
  const cfToken = $('aCertToken').value;
  const res = $('aCertResult');
  if (!domains.length){ res.textContent = '请填写域名（一行一个）'; return; }
  res.textContent = '申请中…';
  try {
    const r = await api('/api/settings/cert-acme', 'POST', { domains, method, cfToken, name });
    res.textContent = '已提交（' + (r.method === 'http-01' ? 'HTTP-01' : 'DNS-01') + '），等待验证…';
    pollAcmeStatus();
  } catch(e){ res.textContent = '失败：' + e.message; }
}
async function pollAcmeStatus(){
  const el = $('aCertResult'); if (!el) return; // 弹窗已关就停，不再轮询
  try {
    const j = await api('/api/settings/cert-acme-status');
    if (j.running){
      el.textContent = '验证进行中…（' + (j.domains || []).join('、') + '，' + j.method + '）';
      setTimeout(pollAcmeStatus, 2000);
      return;
    }
    if (j.last_err){ el.textContent = '失败：' + j.last_err; }
    else if (j.last_ok){
      el.textContent = '申请成功（' + j.last_ok + '）。请在下方证书列表里确认，然后启用 HTTPS。';
      await loadPanelCerts();
    }
  } catch(e){ el.textContent = '状态查询失败：' + e.message; }
}
async function changePassword(){
  const newP = $('pwNew').value, newP2 = $('pwNew2').value;
  if (!newP){ toast('新密码不能为空', true); return; }
  if (newP !== newP2){ toast('两次输入的新密码不一致', true); return; }
  try {
    await api('/api/settings/password', 'POST', { new: newP, new2: newP2 });
    toast('密码已修改'); $('pwNew').value = ''; $('pwNew2').value = '';
  } catch(e){ toast(e.message, true); }
}
function subLinkValue(token){
  const scheme = location.protocol === 'https:' ? 'https' : 'http';
  const host = panelCertDomain(PANEL_CERT_ID) || location.hostname;
  const port = location.port ? ':' + location.port : '';
  return scheme + '://' + host + port + '/sub/' + token;
}
async function openSubModal(){
  openModal(`<h4>订阅配置</h4><div class="muted" style="padding:8px 0">正在读取订阅…</div>`);
  try {
    const s = await api('/api/settings');
    const link = subLinkValue(s.sub_token);
    const excluded = new Set(s.sub_excluded || []);
    const locals = (NODES || []).map(n => `<div class="row"><input type="checkbox" class="sub-check" data-key="in:${n.id}" ${excluded.has('in:' + n.id) ? '' : 'checked'}><div class="grow"><div class="t">${escHtml(n.name)} ${protoBadge(n.protocol)}</div><div class="s">本地节点 · ${n.enabled ? '启用中' : '已停用（停用的节点订阅里也不会出）'}</div></div></div>`).join('');
    const others = (BNODES || []).map(b => `<div class="row"><input type="checkbox" class="sub-check" data-key="bn:${b.id}" ${excluded.has('bn:' + b.id) ? '' : 'checked'}><div class="grow"><div class="t">${escHtml(b.name)} ${protoBadge(b.protocol)}</div><div class="s">其他节点</div></div></div>`).join('');
    openModal(`<h4>订阅配置</h4>
      <label>订阅链接</label><div class="input-row"><input id="subLink" readonly value="${escHtml(link)}"><button class="btn ghost small" onclick="copyText('subLink')">复制</button><button class="btn ghost small" onclick="regenSubFromModal()">换一个</button></div>
      <div class="hint">默认包含全部节点；取消勾选、点保存后，客户端刷新订阅就变了。</div>
      <div style="margin-top:14px"><label>订阅包含的节点（默认全选）</label>${locals || '<div class="muted">暂无本地节点</div>'}${others}</div>
      <div class="hint">要加其他服务器的节点，去入站列表的“其他节点”里添加，那里添加的默认就进订阅。</div>
      <div class="foot"><button class="btn ghost" onclick="closeModal()">关闭</button><button class="btn" id="subSaveBtn" onclick="saveSubSelection()">保存</button></div>
      <div class="msg" id="subMsg"></div>`);
  } catch(e){ toast(e.message, true); }
}
async function saveSubSelection(){
  const excluded = [];
  document.querySelectorAll('.sub-check').forEach(cb => { if (!cb.checked) excluded.push(cb.dataset.key); });
  const btn = $('subSaveBtn'); btn.disabled = true;
  try {
    await api('/api/settings/sub-excluded', 'POST', { excluded });
    $('subMsg').className = 'msg ok'; $('subMsg').textContent = '订阅已保存，客户端刷新订阅就生效';
    toast('订阅已保存');
  } catch(e){
    $('subMsg').className = 'msg err'; $('subMsg').textContent = e.message;
  }
  btn.disabled = false;
}
async function regenSubFromModal(){
  confirmModal('更换订阅链接', '换了之后，<b>旧订阅链接立即失效</b>，原来用旧链接的客户端要重新换新链接才能刷新。确定换吗？', '确定更换', async ()=>{
    try {
      const r = await api('/api/settings/sub-token', 'POST', {});
      $('subLink').value = subLinkValue(r.sub_token);
      toast('订阅链接已更换，旧链接已失效');
    } catch(e){ toast(e.message, true); }
  });
}

// ---------- boot ----------
async function refreshAll(){
  await refreshStatus();
  await loadChains();
  await loadSettings();
}
(async function(){
  try {
    const st = await api('/api/setup-status');
    if (st.setup_required){ showSetup(); return; }
  } catch(e){}
  try {
    await api('/api/me');
    showApp();
  } catch(e){ showLogin(); }
})();

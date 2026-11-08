'use strict';
/*
 * Yarpa Launcher server — login, time-limited access, blocking, admin panel.
 * No external dependencies: needs only Node.js 18+.
 *
 * Environment variables:
 *   ADMIN_PASSWORD  (required) password for the admin panel at /admin
 *   PORT            default 3000
 *   DATA_DIR        where users.json is stored (default ./data) — must be persistent storage
 *   GAMES_DIR       where the simulator HTML files are (default ./games)
 *   DOWNLOAD_URL    link to the launcher installer, shown on the home page
 *   LICENSE_SECRET  optional; otherwise a random secret is created in DATA_DIR/secret.key
 *   ALLOW_WEB_PLAY  set to 1 to also allow playing in the browser (default: desktop launcher only)
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = +process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const GAMES_DIR = path.resolve(process.env.GAMES_DIR || path.join(__dirname, 'games'));
const VIEWS = path.join(__dirname, 'views');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const GUARD_INTERVAL_SEC = 30;
const DOWNLOAD_URL = process.env.DOWNLOAD_URL || '';
const ALLOW_WEB_PLAY = process.env.ALLOW_WEB_PLAY === '1';
const DAY = 86400000;

if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 8) {
  console.error('ERROR: set ADMIN_PASSWORD (at least 8 characters) before starting.');
  process.exit(1);
}
fs.mkdirSync(DATA_DIR, { recursive: true });

/* ---------------- games ---------------- */
function loadGames() {
  try { return JSON.parse(fs.readFileSync(path.join(__dirname, 'games.json'), 'utf8')); }
  catch (e) { console.error('games.json missing or invalid:', e.message); return []; }
}
function gameFile(g) { return path.join(GAMES_DIR, path.basename(g.file)); }
function gameAvailable(g) { try { return fs.statSync(gameFile(g)).isFile(); } catch { return false; } }

/* ---------------- storage ---------------- */
let DB = { users: [], log: [] };
try { DB = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); DB.users ||= []; DB.log ||= []; }
catch (e) { if (e.code !== 'ENOENT') console.error('Could not read users.json:', e.message); }
function save() {
  const tmp = USERS_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(DB, null, 2));
  fs.renameSync(tmp, USERS_FILE);
}
DB.apps ||= []; // desktop launcher sessions: {th, user, created, device, revoked}
function logEvent(user, ev, ip) {
  DB.log.unshift({ t: Date.now(), user, ev, ip });
  if (DB.log.length > 500) DB.log.length = 500;
}

/* ---------------- passwords ---------------- */
function hashPw(pw, salt = crypto.randomBytes(16).toString('hex')) {
  return { salt, hash: crypto.scryptSync(pw, salt, 64).toString('hex') };
}
function checkPw(pw, u) {
  const h = crypto.scryptSync(String(pw), u.salt, 64);
  const ref = Buffer.from(u.hash, 'hex');
  return ref.length === h.length && crypto.timingSafeEqual(ref, h);
}
function genPassword() {
  const abc = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  const b = crypto.randomBytes(10);
  let s = '';
  for (let i = 0; i < 10; i++) s += abc[b[i] % abc.length];
  return s.slice(0, 5) + '-' + s.slice(5);
}
const safeEq = (a, b) => {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
};

/* ---------------- users ---------------- */
const findUser = name => DB.users.find(u => u.username.toLowerCase() === String(name || '').trim().toLowerCase());
function userStatus(u, now = Date.now()) {
  if (u.blocked) return 'blocked';
  if (u.expiresAt && now >= u.expiresAt) return 'expired';
  if (!u.expiresAt) return 'pending'; // clock starts at first login
  return 'active';
}
function publicUser(u) {
  return {
    username: u.username, label: u.label || '', status: userStatus(u),
    createdAt: u.createdAt, expiresAt: u.expiresAt || null, durationDays: u.durationMs / DAY,
    startOnFirstLogin: !!u.startOnFirstLogin, blocked: !!u.blocked, maxDevices: u.maxDevices,
    firstLogin: u.firstLogin || null, lastLogin: u.lastLogin || null, lastIp: u.lastIp || '',
    loginCount: u.loginCount || 0, sessions: [...SESS.values()].filter(s => s.user === u.username).length + DB.apps.filter(a => a.user === u.username && !a.revoked).length
  };
}

/* ---------------- sessions (memory) ---------------- */
const SESS = new Map();   // token -> {user, created, ip}
const ASESS = new Map();  // admin token -> {created}
const REVOKED = new Map(); // token -> {reason, t}  (so the game can show *why* access ended)
const newToken = () => crypto.randomBytes(32).toString('hex');
function killSessions(username, reason = 'nosession') {
  for (const [k, s] of SESS) if (s.user === username) { SESS.delete(k); REVOKED.set(k, { reason, t: Date.now() }); }
  for (const a of DB.apps) if (a.user === username && !a.revoked) { a.revoked = reason; a.rt = Date.now(); }
}
const tHash = t => crypto.createHash('sha256').update(String(t)).digest('hex');
function appUser(req) {
  const m = /^Bearer\s+([a-f0-9]{64})$/i.exec(req.headers.authorization || '');
  if (!m) return { err: 'nosession' };
  const a = DB.apps.find(x => x.th === tHash(m[1]));
  if (!a) return { err: 'nosession' };
  if (a.revoked) return { err: a.revoked };
  const u = findUser(a.user);
  if (!u) { a.revoked = 'blocked'; a.rt = Date.now(); save(); return { err: 'blocked' }; }
  const st = userStatus(u);
  if (st === 'blocked' || st === 'expired') { a.revoked = st; a.rt = Date.now(); save(); return { err: st }; }
  return { u, a };
}
function gameVersion(g) {
  try { return crypto.createHash('sha256').update(fs.readFileSync(gameFile(g))).digest('hex').slice(0, 16); } catch { return null; }
}
/* Games are sent to the desktop launcher encrypted (AES-256-GCM). The key is handed out separately,
   only at launch time and only while the user's access is valid — so the copy left on disk is useless after expiry. */
const SECRET = (() => {
  if (process.env.LICENSE_SECRET) return Buffer.from(process.env.LICENSE_SECRET);
  const f = path.join(DATA_DIR, 'secret.key');
  try { return Buffer.from(fs.readFileSync(f, 'utf8').trim(), 'hex'); }
  catch { const k = crypto.randomBytes(32); fs.writeFileSync(f, k.toString('hex'), { mode: 0o600 }); return k; }
})();
const hm = (label) => crypto.createHmac('sha256', SECRET).update(label).digest();
const gameKey = (g, ver) => hm(`key:${g.id}:${ver}`);
const ENC_CACHE = new Map(); // id -> {ver, buf}
function encryptedGame(g) {
  const ver = gameVersion(g); if (!ver) return null;
  const c = ENC_CACHE.get(g.id); if (c && c.ver === ver) return c;
  const iv = hm(`iv:${g.id}:${ver}`).subarray(0, 12);
  const ci = crypto.createCipheriv('aes-256-gcm', gameKey(g, ver), iv);
  const ct = Buffer.concat([ci.update(fs.readFileSync(gameFile(g))), ci.final()]);
  const out = { ver, buf: Buffer.concat([Buffer.from('YRP1'), iv, ci.getAuthTag(), ct]) };
  ENC_CACHE.set(g.id, out); return out;
}
function sessionUser(req) {
  const tok = cookies(req).sid;
  const s = tok && SESS.get(tok);
  if (!s) return { err: (tok && REVOKED.get(tok)?.reason) || 'nosession' };
  const u = findUser(s.user);
  if (!u) { SESS.delete(tok); return { err: 'nosession' }; }
  const st = userStatus(u);
  if (st === 'blocked' || st === 'expired') { SESS.delete(tok); REVOKED.set(tok, { reason: st, t: Date.now() }); return { err: st }; }
  return { u, tok };
}
function isAdmin(req) {
  const t = cookies(req).asid, s = t && ASESS.get(t);
  if (!s) return false;
  if (Date.now() - s.created > 12 * 3600e3) { ASESS.delete(t); return false; }
  return true;
}

/* ---------------- rate limit ---------------- */
const RL = new Map();
function limited(key, max = 10, win = 15 * 60e3) {
  const now = Date.now(), r = RL.get(key) || { n: 0, t: now };
  if (now - r.t > win) { r.n = 0; r.t = now; }
  r.n++; RL.set(key, r);
  return r.n > max;
}

/* ---------------- http helpers ---------------- */
function cookies(req) {
  const o = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('='); if (i > 0) o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return o;
}
const isHttps = req => req.headers['x-forwarded-proto'] === 'https' || req.socket.encrypted;
function setCookie(req, res, name, val, maxAgeSec) {
  const parts = [`${name}=${val}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${maxAgeSec}`];
  if (isHttps(req)) parts.push('Secure');
  const prev = res.getHeader('Set-Cookie') || [];
  res.setHeader('Set-Cookie', [...[].concat(prev), parts.join('; ')]);
}
const ip = req => (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
const BASE_HEADERS = {
  'Cache-Control': 'no-store',
  'X-Frame-Options': 'SAMEORIGIN',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer'
};
function send(res, code, body, type = 'application/json; charset=utf-8', extra = {}) {
  res.writeHead(code, { ...BASE_HEADERS, 'Content-Type': type, ...extra });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}
const json = (res, code, obj) => send(res, code, obj);
const redirect = (res, to) => { res.writeHead(302, { ...BASE_HEADERS, Location: to }); res.end(); };
function view(res, name) {
  try { send(res, 200, fs.readFileSync(path.join(VIEWS, name)), 'text/html; charset=utf-8'); }
  catch { send(res, 500, 'missing view', 'text/plain'); }
}
function body(req, limit = 2e6) {
  return new Promise((resolve, reject) => {
    let n = 0; const chunks = [];
    req.on('data', c => { n += c.length; if (n > limit) { reject(new Error('too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); } catch { reject(new Error('bad json')); } });
    req.on('error', reject);
  });
}

/* ---------------- guard injected into each game ---------------- */
function guardScript(u) {
  const label = JSON.stringify((u.label ? u.label + ' · ' : '') + u.username);
  return `<script>(function(){
var LBL=${label};
function lock(msg){try{document.documentElement.innerHTML='<head><meta charset="utf-8"><title>הגישה הסתיימה</title></head><body style="margin:0;height:100vh;display:flex;align-items:center;justify-content:center;background:#0a1226;color:#e8eefb;font-family:Segoe UI,Arial,sans-serif;direction:rtl;text-align:center"><div><h1 style="margin:0 0 10px">הגישה לסימולטור הסתיימה</h1><p style="color:#9fb0cc;margin:0 0 18px">'+msg+'</p><a href="/" style="color:#0a1430;background:#c6e24a;padding:10px 26px;text-decoration:none;font-weight:700">חזרה למסך הכניסה</a></div></body>'}catch(e){location.replace('/')}}
var R={blocked:'החשבון נחסם על ידי מנהל המערכת.',expired:'תקופת הגישה של החשבון הסתיימה.',nosession:'יש להתחבר מחדש דרך מסך הכניסה.',device:'נכנסו לחשבון ממכשיר אחר, ולכן החיבור כאן נותק.'};
function check(){fetch('/api/me',{credentials:'same-origin',cache:'no-store'}).then(function(r){return r.json().then(function(j){if(!r.ok||!j.ok)lock(R[j.error]||R.nosession)})}).catch(function(){lock('אין חיבור לשרת הרישוי.')})}
if(location.protocol==='file:'){lock('הסימולטור זמין רק דרך הלאנצר.');return}
check();setInterval(check,${GUARD_INTERVAL_SEC * 1000});
document.addEventListener('visibilitychange',function(){if(!document.hidden)check()});
addEventListener('DOMContentLoaded',function(){var w=document.createElement('div');w.textContent='רישיון: '+LBL;w.setAttribute('style','position:fixed;bottom:6px;left:50%;transform:translateX(-50%);z-index:99999;font:11px Arial,sans-serif;color:rgba(255,255,255,.45);pointer-events:none;direction:rtl');document.body.appendChild(w)});
})();</script>`;
}
function serveGame(res, g, u) {
  let html;
  try { html = fs.readFileSync(gameFile(g), 'utf8'); } catch { return send(res, 404, 'הסימולטור לא נמצא בשרת', 'text/plain; charset=utf-8'); }
  const inject = guardScript(u);
  html = /<head[^>]*>/i.test(html) ? html.replace(/<head[^>]*>/i, m => m + inject) : inject + html;
  send(res, 200, html, 'text/html; charset=utf-8');
}

/* ---------------- routes ---------------- */
async function route(req, res) {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname.replace(/\/+$/, '') || '/';
  const M = req.method;

  // ---- pages ----
  if (M === 'GET' && p === '/') {
    if (!ALLOW_WEB_PLAY) return view(res, 'download.html');
    return sessionUser(req).u ? redirect(res, '/launcher') : view(res, 'login.html');
  }
  if (M === 'GET' && p === '/api/info') return json(res, 200, { downloadUrl: DOWNLOAD_URL, webPlay: ALLOW_WEB_PLAY });
  if (!ALLOW_WEB_PLAY && (p === '/launcher' || p.startsWith('/play/') || p === '/api/login')) return redirect(res, '/');
  if (M === 'GET' && p === '/launcher') {
    const s = sessionUser(req);
    return s.u ? view(res, 'launcher.html') : redirect(res, '/?e=' + s.err);
  }
  if (M === 'GET' && p === '/admin') return view(res, 'admin.html');
  if (M === 'GET' && p.startsWith('/play/')) {
    const s = sessionUser(req);
    if (!s.u) return redirect(res, '/?e=' + s.err);
    const g = loadGames().find(x => x.id === p.slice(6));
    if (!g) return send(res, 404, 'not found', 'text/plain');
    logEvent(s.u.username, 'play:' + g.id, ip(req)); save();
    return serveGame(res, g, s.u);
  }
  if (M === 'GET' && p === '/healthz') return json(res, 200, { ok: true });

  // ---- user API ----
  if (M === 'POST' && p === '/api/login') {
    if (limited('login:' + ip(req))) return json(res, 429, { ok: false, error: 'rate' });
    const b = await body(req);
    const u = findUser(b.username);
    if (!u || !checkPw(b.password || '', u)) { logEvent(String(b.username || '').slice(0, 40), 'login-fail', ip(req)); save(); return json(res, 401, { ok: false, error: 'bad' }); }
    const now = Date.now();
    if (u.blocked) { logEvent(u.username, 'login-blocked', ip(req)); save(); return json(res, 403, { ok: false, error: 'blocked' }); }
    if (u.expiresAt && now >= u.expiresAt) { logEvent(u.username, 'login-expired', ip(req)); save(); return json(res, 403, { ok: false, error: 'expired' }); }
    if (!u.expiresAt) { u.expiresAt = now + u.durationMs; }
    if (!u.firstLogin) u.firstLogin = now;
    u.lastLogin = now; u.lastIp = ip(req); u.loginCount = (u.loginCount || 0) + 1;
    // device limit: drop oldest sessions
    const mine = [...SESS.entries()].filter(([, s]) => s.user === u.username).sort((a, b) => a[1].created - b[1].created);
    while (mine.length >= (u.maxDevices || 2)) { const k = mine.shift()[0]; SESS.delete(k); REVOKED.set(k, { reason: 'device', t: now }); }
    const tok = newToken();
    SESS.set(tok, { user: u.username, created: now, ip: ip(req) });
    logEvent(u.username, 'login', ip(req)); save();
    setCookie(req, res, 'sid', tok, Math.max(60, Math.ceil((u.expiresAt - now) / 1000)));
    return json(res, 200, { ok: true });
  }
  if (M === 'POST' && p === '/api/logout') {
    const t = cookies(req).sid; if (t) SESS.delete(t);
    setCookie(req, res, 'sid', '', 0);
    return json(res, 200, { ok: true });
  }
  if (M === 'GET' && p === '/api/me') {
    const s = sessionUser(req);
    if (!s.u) return json(res, 401, { ok: false, error: s.err });
    const u = s.u;
    return json(res, 200, {
      ok: true, username: u.username, label: u.label || '', expiresAt: u.expiresAt, now: Date.now(),
      games: loadGames().map(g => ({ id: g.id, title: g.title, subtitle: g.subtitle || '', desc: g.desc || '', available: gameAvailable(g) }))
    });
  }

  // ---- desktop launcher API (Authorization: Bearer <token>) ----
  if (M === 'POST' && p === '/api/app/login') {
    if (limited('login:' + ip(req))) return json(res, 429, { ok: false, error: 'rate' });
    const b = await body(req);
    const u = findUser(b.username);
    if (!u || !checkPw(b.password || '', u)) { logEvent(String(b.username || '').slice(0, 40), 'login-fail', ip(req)); save(); return json(res, 401, { ok: false, error: 'bad' }); }
    const now = Date.now();
    if (u.blocked) { logEvent(u.username, 'login-blocked', ip(req)); save(); return json(res, 403, { ok: false, error: 'blocked' }); }
    if (u.expiresAt && now >= u.expiresAt) { logEvent(u.username, 'login-expired', ip(req)); save(); return json(res, 403, { ok: false, error: 'expired' }); }
    if (!u.expiresAt) u.expiresAt = now + u.durationMs;
    if (!u.firstLogin) u.firstLogin = now;
    u.lastLogin = now; u.lastIp = ip(req); u.loginCount = (u.loginCount || 0) + 1;
    const mine = DB.apps.filter(a => a.user === u.username && !a.revoked).sort((x, y) => x.created - y.created);
    while (mine.length >= (u.maxDevices || 2)) { const a = mine.shift(); a.revoked = 'device'; a.rt = now; }
    const tok = newToken();
    DB.apps.push({ th: tHash(tok), user: u.username, created: now, device: String(b.device || '').slice(0, 60) });
    DB.apps = DB.apps.filter(a => !a.revoked || now - a.rt < 30 * DAY);
    logEvent(u.username, 'login', ip(req)); save();
    return json(res, 200, { ok: true, token: tok });
  }
  if (p.startsWith('/api/app/')) {
    const s = appUser(req);
    if (!s.u) return json(res, s.err === 'nosession' ? 401 : 403, { ok: false, error: s.err });
    const u = s.u, sub = p.slice(9);
    if (M === 'GET' && sub === 'me') {
      return json(res, 200, { ok: true, username: u.username, label: u.label || '', expiresAt: u.expiresAt, now: Date.now(),
        games: loadGames().map(g => ({ id: g.id, title: g.title, subtitle: g.subtitle || '', desc: g.desc || '', version: gameVersion(g), available: gameAvailable(g) })) });
    }
    if (M === 'GET' && sub.startsWith('game/')) {
      const g = loadGames().find(x => x.id === sub.slice(5));
      if (!g || !gameAvailable(g)) return json(res, 404, { ok: false, error: 'missing' });
      const e = encryptedGame(g);
      logEvent(u.username, 'download:' + g.id, ip(req)); save();
      return send(res, 200, e.buf, 'application/octet-stream', { 'X-Game-Version': e.ver });
    }
    if (M === 'POST' && sub.startsWith('key/')) {
      const g = loadGames().find(x => x.id === sub.slice(4));
      if (!g || !gameAvailable(g)) return json(res, 404, { ok: false, error: 'missing' });
      const ver = gameVersion(g);
      logEvent(u.username, 'play:' + g.id, ip(req)); save();
      return json(res, 200, { ok: true, version: ver, key: gameKey(g, ver).toString('base64') });
    }
    if (M === 'POST' && sub.startsWith('play/')) { logEvent(u.username, 'play:' + sub.slice(5), ip(req)); save(); return json(res, 200, { ok: true }); }
    if (M === 'POST' && sub === 'logout') { s.a.revoked = 'logout'; s.a.rt = Date.now(); save(); return json(res, 200, { ok: true }); }
    return json(res, 404, { ok: false });
  }

  // ---- admin API ----
  if (p === '/api/admin/login' && M === 'POST') {
    if (limited('admin:' + ip(req), 8)) return json(res, 429, { ok: false, error: 'rate' });
    const b = await body(req);
    if (!safeEq(b.password || '', ADMIN_PASSWORD)) return json(res, 401, { ok: false });
    const t = newToken(); ASESS.set(t, { created: Date.now() });
    setCookie(req, res, 'asid', t, 12 * 3600);
    return json(res, 200, { ok: true });
  }
  if (p.startsWith('/api/admin/')) {
    if (!isAdmin(req)) return json(res, 401, { ok: false, error: 'admin' });
    const parts = p.split('/').slice(3); // after /api/admin/
    if (M === 'POST' && parts[0] === 'logout') { ASESS.delete(cookies(req).asid); setCookie(req, res, 'asid', '', 0); return json(res, 200, { ok: true }); }
    if (M === 'GET' && parts[0] === 'users' && !parts[1]) {
      return json(res, 200, { ok: true, now: Date.now(), users: DB.users.map(publicUser), log: DB.log.slice(0, 100),
        games: loadGames().map(g => ({ id: g.id, title: g.title, available: gameAvailable(g) })) });
    }
    if (M === 'POST' && parts[0] === 'users' && !parts[1]) {
      const b = await body(req);
      const username = String(b.username || '').trim();
      if (!/^[\p{L}\p{N}_.\-]{3,32}$/u.test(username)) return json(res, 400, { ok: false, error: 'שם משתמש: 3–32 תווים, אותיות/ספרות/נקודה/מקף' });
      if (findUser(username)) return json(res, 400, { ok: false, error: 'שם המשתמש כבר קיים' });
      const days = Number(b.days);
      if (!(days > 0 && days <= 3650)) return json(res, 400, { ok: false, error: 'מספר ימים לא תקין' });
      const password = (b.password && String(b.password).length >= 6) ? String(b.password) : genPassword();
      const now = Date.now();
      const u = {
        username, label: String(b.label || '').slice(0, 60), ...hashPw(password),
        createdAt: now, durationMs: Math.round(days * DAY), startOnFirstLogin: !!b.startOnFirstLogin,
        expiresAt: b.startOnFirstLogin ? null : now + Math.round(days * DAY),
        blocked: false, maxDevices: Math.min(20, Math.max(1, +b.maxDevices || 2))
      };
      DB.users.push(u); logEvent(username, 'admin:create', ip(req)); save();
      return json(res, 200, { ok: true, username, password, user: publicUser(u) });
    }
    if (parts[0] === 'users' && parts[1]) {
      const u = findUser(decodeURIComponent(parts[1]));
      if (!u) return json(res, 404, { ok: false, error: 'לא נמצא' });
      const act = parts[2];
      if (M === 'DELETE' && !act) { killSessions(u.username, 'blocked'); DB.users = DB.users.filter(x => x !== u); logEvent(u.username, 'admin:delete', ip(req)); save(); return json(res, 200, { ok: true }); }
      if (M === 'POST') {
        const b = await body(req);
        if (act === 'block') { u.blocked = true; killSessions(u.username, 'blocked'); }
        else if (act === 'unblock') { u.blocked = false; }
        else if (act === 'extend') {
          const days = Number(b.days); if (!(days > 0 && days <= 3650)) return json(res, 400, { ok: false, error: 'מספר ימים לא תקין' });
          if (!u.expiresAt) u.durationMs += Math.round(days * DAY);
          else u.expiresAt = Math.max(u.expiresAt, Date.now()) + Math.round(days * DAY);
        }
        else if (act === 'expire-now') { u.expiresAt = Date.now(); killSessions(u.username, 'expired'); }
        else if (act === 'reset-password') {
          const pw = genPassword(); Object.assign(u, hashPw(pw)); killSessions(u.username);
          logEvent(u.username, 'admin:reset-password', ip(req)); save();
          return json(res, 200, { ok: true, password: pw });
        }
        else if (act === 'kick') { killSessions(u.username); }
        else if (act === 'update') {
          if (b.label != null) u.label = String(b.label).slice(0, 60);
          if (b.maxDevices != null) u.maxDevices = Math.min(20, Math.max(1, +b.maxDevices || 2));
        }
        else return json(res, 400, { ok: false });
        logEvent(u.username, 'admin:' + act, ip(req)); save();
        return json(res, 200, { ok: true, user: publicUser(u) });
      }
    }
    if (M === 'GET' && parts[0] === 'export') {
      return send(res, 200, JSON.stringify(DB, null, 2), 'application/json; charset=utf-8', { 'Content-Disposition': 'attachment; filename="yarpa-users-backup.json"' });
    }
    if (M === 'POST' && parts[0] === 'import') {
      const b = await body(req, 10e6);
      if (!b || !Array.isArray(b.users) || !b.users.every(u => u.username && u.hash && u.salt)) return json(res, 400, { ok: false, error: 'קובץ גיבוי לא תקין' });
      DB = { users: b.users, log: Array.isArray(b.log) ? b.log : [] }; SESS.clear(); save();
      return json(res, 200, { ok: true, count: DB.users.length });
    }
    return json(res, 404, { ok: false });
  }

  send(res, 404, 'Not found', 'text/plain');
}

http.createServer((req, res) => {
  route(req, res).catch(e => { console.error(e); if (!res.headersSent) json(res, 400, { ok: false, error: e.message }); });
}).listen(PORT, () => {
  console.log(`Yarpa launcher on http://localhost:${PORT}  (admin: /admin)`);
  console.log(`data: ${USERS_FILE}`);
  for (const g of loadGames()) console.log(`game ${g.id}: ${gameFile(g)} ${gameAvailable(g) ? 'OK' : 'MISSING'}`);
});

// periodic cleanup of sessions for expired users
setInterval(() => {
  for (const [k, s] of SESS) { const u = findUser(s.user); if (!u || ['blocked', 'expired'].includes(userStatus(u))) { SESS.delete(k); REVOKED.set(k, { reason: u ? userStatus(u) : 'blocked', t: Date.now() }); } }
  for (const [k, r] of REVOKED) if (Date.now() - r.t > 7 * DAY) REVOKED.delete(k);
}, 60e3).unref();

'use strict';
const { app, BrowserWindow, ipcMain, protocol, Menu } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { Client } = require('./lib/client');

// Server URL: baked in at build time (config.json) or overridable for testing.
let SERVER = process.env.YARPA_SERVER || '';
try { SERVER = SERVER || JSON.parse(fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8')).server; } catch {}

const CACHE = path.join(app.getPath('userData'), 'games');
const SAVE = path.join(app.getPath('userData'), 'session.json');
const client = new Client(SERVER, CACHE);

const HEARTBEAT_MS = 20000;   // check licence every 20 s
const OFFLINE_GRACE = 3;      // lock the game after ~1 minute without contact with the server

let win = null, gameWin = null, heart = null, offlineCount = 0;
let access = { ok: false, reason: 'nosession' };
let currentHtml = '';

// The game is served from a fixed private origin (yarpa://game) so its saved settings
// (stick/throttle mapping in localStorage) survive between launches.
protocol.registerSchemesAsPrivileged([{ scheme: 'yarpa', privileges: { standard: true, secure: true, supportFetchAPI: true, stream: true } }]);

function deviceName() { try { return (os.hostname() || 'PC') + ' · ' + os.userInfo().username; } catch { return 'PC'; } }

/* ---- guard injected into the running game ---- */
function guardScript(label) {
  return `<script>(function(){
var L=${JSON.stringify(label)};
function lock(m){try{document.documentElement.innerHTML='<head><meta charset=utf-8></head><body style="margin:0;height:100vh;display:flex;align-items:center;justify-content:center;background:#0a1226;color:#e8eefb;font-family:Segoe UI,Arial,sans-serif;direction:rtl;text-align:center"><div><h1>הגישה לסימולטור הסתיימה</h1><p style="color:#9fb0cc">'+m+'</p></div></body>'}catch(e){}}
var R={blocked:'החשבון נחסם על ידי מנהל המערכת.',expired:'תקופת הגישה הסתיימה.',device:'נכנסו לחשבון ממכשיר אחר.',logout:'התנתקת.',nosession:'יש להתחבר מחדש בלאנצר.',offline:'אין חיבור לשרת הרישוי.'};
function c(){fetch('yarpa://game/__status',{cache:'no-store'}).then(function(r){return r.json()}).then(function(j){if(!j.ok)lock(R[j.reason]||R.nosession)}).catch(function(){lock(R.nosession)})}
c();setInterval(c,5000);
addEventListener('DOMContentLoaded',function(){var w=document.createElement('div');w.textContent='רישיון: '+L;w.setAttribute('style','position:fixed;bottom:6px;left:50%;transform:translateX(-50%);z-index:99999;font:11px Arial;color:rgba(255,255,255,.45);pointer-events:none;direction:rtl');document.body.appendChild(w)});
})();</script>`;
}
const injectGuard = (html, g) => /<head[^>]*>/i.test(html) ? html.replace(/<head[^>]*>/i, m => m + g) : g + html;

function registerProtocol() {
  protocol.handle('yarpa', req => {
    const u = new URL(req.url);
    if (u.pathname === '/__status') return new Response(JSON.stringify(access), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
    if (!access.ok || !currentHtml) return new Response('<!doctype html><meta charset=utf-8><body style="background:#0a1226;color:#e8eefb;font-family:Arial;direction:rtl;text-align:center;padding-top:30vh">הסימולטור זמין רק דרך הלאנצר.</body>', { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    return new Response(currentHtml, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
  });
}

/* ---- windows ---- */
function createWindow() {
  win = new BrowserWindow({
    width: 1040, height: 720, minWidth: 900, minHeight: 600, backgroundColor: '#0a1226',
    title: 'סימולטור ירפ"א', autoHideMenuBar: true,
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false }
  });
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
}

function closeGame() { currentHtml = ''; if (gameWin && !gameWin.isDestroyed()) gameWin.close(); }

function openGame(title) {
  if (gameWin && !gameWin.isDestroyed()) { gameWin.focus(); gameWin.loadURL('yarpa://game/'); return; }
  gameWin = new BrowserWindow({
    width: 1280, height: 820, backgroundColor: '#000', title: 'סימולטור ' + title, autoHideMenuBar: true,
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true, devTools: false }
  });
  gameWin.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  gameWin.webContents.on('will-navigate', (e, url) => { if (!url.startsWith('yarpa://')) e.preventDefault(); });
  gameWin.webContents.on('before-input-event', (_e, i) => { if (i.type === 'keyDown' && i.key === 'F11') gameWin.setFullScreen(!gameWin.isFullScreen()); });
  gameWin.loadURL('yarpa://game/');
  gameWin.on('closed', () => { gameWin = null; currentHtml = ''; });
}

/* ---- licence heartbeat ---- */
function stopHeartbeat() { if (heart) { clearInterval(heart); heart = null; } }
function startHeartbeat() {
  stopHeartbeat(); offlineCount = 0;
  const tick = async () => {
    const r = await client.me();
    if (r.ok) { offlineCount = 0; access = { ok: true, expiresAt: r.expiresAt, now: r.now }; }
    else if (r.error === 'offline' || r.status >= 500) {
      // short network drops don't kill a running session; a long one does
      if (++offlineCount >= OFFLINE_GRACE) { access = { ok: false, reason: 'offline' }; closeGame(); }
    } else { access = { ok: false, reason: r.error || 'nosession' }; closeGame(); clearSaved(); }
    if (win && !win.isDestroyed()) win.webContents.send('access', { ...access, offline: r.error === 'offline' });
  };
  heart = setInterval(tick, HEARTBEAT_MS);
  tick();
}

/* ---- IPC ---- */
ipcMain.handle('info', () => ({ server: SERVER, device: deviceName(), saved: !!loadSaved() }));
ipcMain.handle('login', async (_e, { username, password, remember }) => {
  const r = await client.login(username, password, deviceName());
  if (r.ok) { access = { ok: true }; if (remember) saveSession(client.token); else clearSaved(); startHeartbeat(); }
  return { ok: r.ok, error: r.error, status: r.status };
});
ipcMain.handle('resume', async () => {
  const t = loadSaved(); if (!t) return { ok: false };
  client.token = t.token;
  const r = await client.me();
  if (r.ok) { access = { ok: true }; startHeartbeat(); return { ok: true }; }
  if (r.error === 'offline') return { ok: false, offline: true };
  clearSaved(); return { ok: false, error: r.error };
});
ipcMain.handle('me', () => client.me());
ipcMain.handle('logout', async () => { stopHeartbeat(); closeGame(); await client.logout(); clearSaved(); access = { ok: false, reason: 'logout' }; return { ok: true }; });
ipcMain.handle('download', (e, g) => client.ensureGame(g, p => e.sender.send('progress', { id: g.id, p })));
ipcMain.handle('play', async (_e, g) => {
  const info = await client.me();
  if (!info.ok) return { ok: false, error: info.error };
  let k = await client.key(g.id);
  if (!k.ok) return { ok: false, error: k.error };
  // the server has a newer version than the cached one → download it first
  if ((client.meta(g.id) || {}).version !== k.version) {
    const d = await client.ensureGame({ ...g, version: k.version });
    if (!d.ok) return { ok: false, error: d.error };
  }
  let html;
  try { html = client.readGame(g.id, k.key); }
  catch { try { fs.unlinkSync(client.file(g.id)); } catch {} return { ok: false, error: 'corrupt' }; }
  const label = (info.label ? info.label + ' · ' : '') + info.username;
  currentHtml = injectGuard(html, guardScript(label));
  access = { ok: true, expiresAt: info.expiresAt };
  openGame(g.title);
  return { ok: true };
});

/* ---- saved session (encrypted with the OS keychain when available) ---- */
function saveSession(token) {
  try {
    const { safeStorage } = require('electron');
    const data = safeStorage.isEncryptionAvailable() ? { enc: safeStorage.encryptString(token).toString('base64') } : { token };
    fs.writeFileSync(SAVE, JSON.stringify(data), { mode: 0o600 });
  } catch {}
}
function loadSaved() {
  try {
    const d = JSON.parse(fs.readFileSync(SAVE, 'utf8'));
    if (d.enc) { const { safeStorage } = require('electron'); return { token: safeStorage.decryptString(Buffer.from(d.enc, 'base64')) }; }
    return d.token ? d : null;
  } catch { return null; }
}
function clearSaved() { try { fs.unlinkSync(SAVE); } catch {} }

if (!app.requestSingleInstanceLock()) app.quit();
else {
  app.on('second-instance', () => { if (win) { if (win.isMinimized()) win.restore(); win.focus(); } });
  app.whenReady().then(() => {
    Menu.setApplicationMenu(null);
    registerProtocol();
    createWindow();
    app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
  });
  app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
}

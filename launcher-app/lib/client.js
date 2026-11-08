'use strict';
// Talks to the licence server and keeps downloaded games in a local cache.
// Plain Node (no Electron APIs) so it can be tested on its own.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class Client {
  constructor(serverUrl, cacheDir) {
    this.server = String(serverUrl).replace(/\/+$/, '');
    this.cacheDir = cacheDir;
    this.token = null;
    fs.mkdirSync(cacheDir, { recursive: true });
  }

  async req(p, opt = {}) {
    let r;
    try {
      r = await fetch(this.server + p, {
        method: opt.method || 'GET',
        headers: { ...(this.token ? { Authorization: 'Bearer ' + this.token } : {}), ...(opt.body ? { 'Content-Type': 'application/json' } : {}) },
        body: opt.body ? JSON.stringify(opt.body) : undefined,
        signal: AbortSignal.timeout(opt.timeout || 20000)
      });
    } catch (e) { return { ok: false, status: 0, error: 'offline' }; }
    if (opt.raw) return r;
    const j = await r.json().catch(() => ({}));
    return { status: r.status, ...j, ok: r.ok && j.ok !== false };
  }

  async login(username, password, device) {
    const r = await this.req('/api/app/login', { method: 'POST', body: { username, password, device } });
    if (r.ok) this.token = r.token;
    return r;
  }
  me() { return this.req('/api/app/me'); }
  async logout() { if (this.token) await this.req('/api/app/logout', { method: 'POST' }); this.token = null; }
  notePlay(id) { return this.req('/api/app/play/' + encodeURIComponent(id), { method: 'POST' }); }
  // The decryption key is only given by the server while access is valid.
  key(id) { return this.req('/api/app/key/' + encodeURIComponent(id), { method: 'POST' }); }

  file(id) { return path.join(this.cacheDir, id.replace(/[^\w-]/g, '_') + '.bin'); }
  meta(id) { try { return JSON.parse(fs.readFileSync(this.file(id) + '.json', 'utf8')); } catch { return null; } }
  isCurrent(g) { const m = this.meta(g.id); return !!(m && m.version === g.version && fs.existsSync(this.file(g.id))); }

  // Download (or update) a game, reporting progress 0..1
  async ensureGame(g, onProgress = () => {}) {
    if (this.isCurrent(g)) { onProgress(1); return { ok: true, cached: true }; }
    const r = await this.req('/api/app/game/' + encodeURIComponent(g.id), { raw: true, timeout: 300000 });
    if (!r || r.ok === false && r.status === 0) return { ok: false, error: 'offline' };
    if (!r.ok) { const j = await r.json().catch(() => ({})); return { ok: false, status: r.status, error: j.error || 'download' }; }
    const total = +r.headers.get('content-length') || 0, chunks = [];
    let got = 0;
    const reader = r.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(Buffer.from(value)); got += value.length;
      if (total) onProgress(Math.min(1, got / total));
    }
    const out = this.file(g.id), tmp = out + '.part';
    fs.writeFileSync(tmp, Buffer.concat(chunks));
    fs.renameSync(tmp, out);
    fs.writeFileSync(out + '.json', JSON.stringify({ version: r.headers.get('x-game-version') || g.version, at: Date.now() }));
    onProgress(1);
    return { ok: true, cached: false };
  }

  // Decrypt the cached game in memory (never written to disk in plain form).
  readGame(id, keyB64) {
    const b = fs.readFileSync(this.file(id));
    if (b.subarray(0, 4).toString() !== 'YRP1') throw new Error('bad file');
    const d = crypto.createDecipheriv('aes-256-gcm', Buffer.from(keyB64, 'base64'), b.subarray(4, 16));
    d.setAuthTag(b.subarray(16, 32));
    return Buffer.concat([d.update(b.subarray(32)), d.final()]).toString('utf8');
  }
}

module.exports = { Client };

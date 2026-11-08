'use strict';
const $ = s => document.querySelector(s);
const show = id => document.querySelectorAll('.view').forEach(v => v.classList.toggle('show', v.id === id));
const ERR = { bad: 'שם משתמש או סיסמה שגויים.', blocked: 'החשבון נחסם. לפרטים פנה לבעל התוכנה.', expired: 'תקופת הגישה הסתיימה. לחידוש פנה לבעל התוכנה.',
  rate: 'יותר מדי ניסיונות. נסה שוב בעוד כמה דקות.', device: 'נכנסו לחשבון ממכשיר אחר, ולכן החיבור כאן נותק.', offline: 'אין חיבור לשרת הרישוי. בדוק את החיבור לאינטרנט.', nosession: 'יש להתחבר מחדש.', corrupt: 'קובץ הסימולטור פגום. לחץ שוב על "שחק" כדי להוריד אותו מחדש.', missing: 'הסימולטור לא זמין כרגע בשרת.' };
let ME = null, SEL = null, skew = 0;
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const fmtLeft = ms => { if (ms <= 0) return 'הסתיימה'; const d = Math.floor(ms / 864e5), h = Math.floor(ms % 864e5 / 36e5), m = Math.floor(ms % 36e5 / 6e4), s = Math.floor(ms % 6e4 / 1e3);
  return d > 0 ? `${d} ימים ${h} שעות` : h > 0 ? `${h}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}` : `${m}:${String(s).padStart(2, '0')}`; };

function lmsg(t, ok) { const e = $('#lmsg'); e.textContent = t || ''; e.className = 'msg' + (t ? ' show' : '') + (ok ? ' ok' : ''); }
function alert(t, warn) { const e = $('#alert'); e.textContent = t || ''; e.className = 'alert' + (t ? ' show' : '') + (warn ? ' warn' : ''); }

async function boot() {
  const r = await window.yarpa.resume();
  if (r.ok) return enterMain();
  if (r.offline) { show('login'); lmsg(ERR.offline); return; }
  show('login');
}
$('#lf').addEventListener('submit', async e => {
  e.preventDefault(); lmsg(''); $('#go').disabled = true;
  const r = await window.yarpa.login({ username: $('#u').value.trim(), password: $('#p').value, remember: $('#rem').checked });
  $('#go').disabled = false;
  if (r.ok) { $('#p').value = ''; enterMain(); } else lmsg(ERR[r.error] || ERR.bad);
});
$('#logout').onclick = async () => { await window.yarpa.logout(); ME = null; show('login'); };

async function enterMain() {
  show('main'); alert('');
  const r = await window.yarpa.me();
  if (!r.ok) { show('login'); lmsg(ERR[r.error] || ERR.nosession); return; }
  ME = r; skew = r.now - Date.now();
  $('#who').textContent = (r.label ? r.label + ' · ' : '') + r.username;
  $('#list').innerHTML = r.games.map(g => `<button class="g${g.available ? '' : ' na'}" data-id="${esc(g.id)}"><b>${esc(g.title)}</b><small>${esc(g.subtitle)}${g.available ? '' : ' · לא זמין'}</small></button>`).join('');
  const first = r.games.find(g => g.available) || r.games[0];
  if (first) select(first.id);
}
function select(id) {
  SEL = ME.games.find(g => g.id === id); if (!SEL) return;
  document.querySelectorAll('.g').forEach(b => b.classList.toggle('sel', b.dataset.id === id));
  $('#gcode').textContent = 'YARPA-' + id.toUpperCase() + ' · SIMULATOR';
  $('#gtitle').textContent = 'סימולטור ' + SEL.title; $('#gsub').textContent = SEL.subtitle; $('#gdesc').textContent = SEL.desc;
  $('#prog').classList.remove('show');
  $('#play').disabled = !SEL.available;
  $('#play').textContent = SEL.available ? 'שחק ◄' : 'לא זמין';
}
$('#list').addEventListener('click', e => { const b = e.target.closest('.g'); if (b) select(b.dataset.id); });

$('#play').onclick = async () => {
  if (!SEL || !SEL.available) return;
  const btn = $('#play'); btn.disabled = true;
  $('#prog').classList.add('show'); $('#fill').style.width = '0%'; $('#ptxt').textContent = 'בודק גרסה…';
  const d = await window.yarpa.download(SEL);
  if (!d.ok) { $('#ptxt').textContent = 'ההורדה נכשלה: ' + (ERR[d.error] || d.error || 'שגיאה'); btn.disabled = false; return; }
  $('#fill').style.width = '100%'; $('#ptxt').textContent = 'מפעיל…';
  const pr = await window.yarpa.play(SEL);
  $('#prog').classList.remove('show'); btn.disabled = false;
  if (!pr.ok) alert(ERR[pr.error] || 'לא ניתן להפעיל כרגע.');
};
window.yarpa.onProgress(d => { if (SEL && d.id === SEL.id) { $('#fill').style.width = Math.round(d.p * 100) + '%'; $('#ptxt').textContent = d.p < 1 ? `מוריד… ${Math.round(d.p * 100)}%` : 'כמעט מוכן…'; } });
window.yarpa.onAccess(a => {
  if (!ME) return;
  if (a.offline) { alert('אין חיבור לשרת הרישוי. בזמן ניתוק לא ניתן לפתוח סימולטור חדש.', true); return; }
  if (!a.ok) { alert(''); ME = null; show('login'); lmsg(ERR[a.reason] || ERR.nosession); return; }
  alert('');
  if (a.expiresAt) ME.expiresAt = a.expiresAt;
});
setInterval(() => {
  if (!ME || !ME.expiresAt) return;
  const left = ME.expiresAt - (Date.now() + skew), el = $('#left');
  el.textContent = fmtLeft(left); el.classList.toggle('warn', left < 864e5);
  if (left <= 0) { ME = null; show('login'); lmsg(ERR.expired); }
}, 1000);
boot();

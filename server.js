const express = require('express'), { Pool } = require('pg'), jwt = require('jsonwebtoken'), crypto = require('crypto'), path = require('path');
const { DATABASE_URL, JWT_SECRET, APPS_SCRIPT_URL, APPS_SCRIPT_KEY, SUPERADMIN_MOBILE, SUPERADMIN_PASSWORD, SUPERADMIN_NAME = 'Super Admin' } = process.env;
if (!DATABASE_URL || !JWT_SECRET) throw new Error('Set DATABASE_URL and JWT_SECRET');
const pool = new Pool({ connectionString: DATABASE_URL, ssl: /localhost|127\.0\.0\.1/.test(DATABASE_URL) ? false : { rejectUnauthorized: false } });
pool.on('error', e => console.error('Idle database connection dropped (safe to ignore):', e.message));
const q = (t, p) => pool.query(t, p);

/* ---------- helpers ---------- */
const hash = pw => { const s = crypto.randomBytes(16).toString('hex'); return s + ':' + crypto.scryptSync(pw, s, 64).toString('hex'); };
const check = (pw, h) => { const [s, k] = h.split(':'); return crypto.timingSafeEqual(Buffer.from(k, 'hex'), crypto.scryptSync(pw, s, 64)); };
const nm = s => String(s || '').replace(/[\s-]/g, ''), MOB = /^\+?\d{10,15}$/;
const pub = u => ({ id: u.id, name: u.name, mobile: u.mobile, email: u.email, city: u.city, hub: u.hub, role: u.role, status: u.status, scope_all: u.scope_all, cities: u.cities, created_at: u.created_at });
const h = f => (req, res, next) => f(req, res, next).catch(e => { console.error(e); res.status(500).json({ error: 'Server error' }); });
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });

const auth = (...roles) => h(async (req, res, next) => {
  let id; try { id = jwt.verify((req.headers.authorization || '').slice(7), JWT_SECRET).id; } catch { return bad(res, 'Please sign in.', 401); }
  const u = (await q('SELECT * FROM users WHERE id=$1', [id])).rows[0];   // checked every time, so delete/reject takes effect at once
  if (!u || u.status !== 'approved') return bad(res, 'Not allowed.', 401);
  if (roles.length && !roles.includes(u.role)) return bad(res, 'Not allowed.', 403);
  req.me = u; next();
});
const STAFF = ['admin', 'semi_admin', 'viewer'], ROLES = ['rider', ...STAFF];
const READ = ['super_admin', ...STAFF], WRITE = ['super_admin', 'admin', 'semi_admin'], DEL = ['super_admin', 'admin'];
const allCities = me => me.role === 'super_admin' || me.scope_all;
const inScope = (me, city) => allCities(me) || (me.cities || []).includes(city);
const scopeW = (me, p, col) => { if (allCities(me)) return null; p.push(me.cities || []); return `${col} = ANY($${p.length})`; };
const cleanList = a => [...new Set((Array.isArray(a) ? a : []).map(c => String(c).trim()).filter(Boolean))];

function toCsv(rows, cols) {
  const cell = v => {
    if (v == null) return '';
    if (v instanceof Date) return v.toISOString();
    if (typeof v === 'number') return String(v);
    v = String(v); if (/^[=+\-@]/.test(v)) v = "'" + v;      // stops spreadsheet formula injection
    return /[",\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
  };
  return [cols.join(','), ...rows.map(r => cols.map(c => cell(r[c])).join(','))].join('\n');
}
function photoFilter(f, me) {
  const w = [], p = [], add = (c, v) => { p.push(v); w.push(c.replace('?', '$' + p.length)); };
  if (f.from) add('device_time >= ?', f.from);
  if (f.to) add('device_time < (?::date + 1)', f.to);
  if (f.city) add('city = ?', f.city);
  if (f.hub) add('hub = ?', f.hub);
  if (f.mobile) add('mobile = ?', nm(f.mobile));
  const sc = scopeW(me, p, 'city'); if (sc) w.push(sc);
  return [w.length ? 'WHERE ' + w.join(' AND ') : '', p];
}

/* ---------- app ---------- */
const app = express();
app.use(express.json({ limit: '8mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/hubs', h(async (_, res) => res.json((await q('SELECT * FROM hubs ORDER BY city, hub')).rows)));

app.post('/api/register', h(async (req, res) => {
  const { name, mobile, email, city, hub, password } = req.body || {}, m = nm(mobile);
  if (!String(name || '').trim() || !MOB.test(m) || !city || !hub || String(password || '').length < 6)
    return bad(res, 'Enter name, a valid mobile number, city, hub and a password of at least 6 characters.');
  if (!(await q('SELECT 1 FROM hubs WHERE city=$1 AND hub=$2', [city, hub])).rowCount) return bad(res, 'Choose a valid city and hub.');
  try { await q('INSERT INTO users(name,mobile,email,city,hub,pw) VALUES($1,$2,$3,$4,$5,$6)', [String(name).trim(), m, String(email || '').trim() || null, city, hub, hash(String(password))]); }
  catch (e) { if (e.code === '23505') return bad(res, 'This mobile number is already registered.', 409); throw e; }
  res.json({ ok: true });
}));

app.post('/api/login', h(async (req, res) => {
  const { mobile, password } = req.body || {};
  const u = (await q('SELECT * FROM users WHERE mobile=$1', [nm(mobile)])).rows[0];
  if (!u || !check(String(password || ''), u.pw)) return bad(res, 'Wrong mobile number or password.', 401);
  if (u.status === 'pending') return bad(res, 'Your request is waiting for admin approval.', 403);
  if (u.status === 'rejected') return bad(res, 'Your request was not approved. Contact your admin.', 403);
  res.json({ token: jwt.sign({ id: u.id }, JWT_SECRET, { expiresIn: u.role === 'rider' ? '30d' : '1d' }), user: pub(u) });
}));
app.get('/api/me', auth(), (req, res) => res.json({ user: pub(req.me) }));

/* ----- users (admin portal) ----- */
// Roles: super_admin = everything. admin = approve/edit/delete riders. semi_admin = approve/edit riders (no delete, no password reset). viewer = read + CSV only.
// Every staff role except super_admin only sees and changes riders and photos in the cities given to them (or all cities).
app.get('/api/users', auth(...READ), h(async (req, res) => {
  const { role = 'rider', status } = req.query, p = [], w = [];
  if (role === 'rider') { w.push("role='rider'"); const sc = scopeW(req.me, p, 'city'); if (sc) w.push(sc); }
  else if (req.me.role === 'super_admin') w.push("role IN ('admin','semi_admin','viewer')");
  else return bad(res, 'Only the super admin can see staff.', 403);
  if (status) { p.push(status); w.push(`status=$${p.length}`); }
  res.json((await q(`SELECT * FROM users WHERE ${w.join(' AND ')} ORDER BY created_at DESC`, p)).rows.map(pub));
}));
app.get('/api/export/riders.csv', auth(...READ), h(async (req, res) => {
  const p = [], w = ["role='rider'"], sc = scopeW(req.me, p, 'city'); if (sc) w.push(sc);
  const rows = (await q(`SELECT * FROM users WHERE ${w.join(' AND ')} ORDER BY created_at DESC`, p)).rows;
  res.type('text/csv').attachment('riders.csv').send(toCsv(rows, ['id', 'name', 'mobile', 'email', 'city', 'hub', 'status', 'created_at']));
}));
async function target(req, res) {
  const t = (await q('SELECT * FROM users WHERE id=$1', [parseInt(req.params.id, 10) || 0])).rows[0];
  if (!t) { bad(res, 'Not found.', 404); return null; }
  if (req.me.role !== 'super_admin') {
    if (t.role !== 'rider') { bad(res, 'Only the super admin can change staff.', 403); return null; }
    if (!inScope(req.me, t.city)) { bad(res, 'This rider is outside your cities.', 403); return null; }
  }
  return t;
}
app.patch('/api/users/:id', auth(...WRITE), h(async (req, res) => {
  const t = await target(req, res); if (!t) return;
  const b = req.body || {}, su = req.me.role === 'super_admin', set = [], p = [], add = (c, v) => { p.push(v); set.push(`${c}=$${p.length}`); };
  for (const k of ['name', 'email', 'city', 'hub']) if (k in b) add(k, String(b[k] || '').trim() || null);
  if ('city' in b && !inScope(req.me, String(b.city || '').trim())) return bad(res, 'That city is outside your access.', 403);
  if ('mobile' in b) { if (!MOB.test(nm(b.mobile))) return bad(res, 'Invalid mobile number.'); add('mobile', nm(b.mobile)); }
  if (t.role !== 'super_admin') {
    if (b.status) { if (!['pending', 'approved', 'rejected'].includes(b.status)) return bad(res, 'Invalid status.'); add('status', b.status); }
    if (su && b.role) {
      if (!ROLES.includes(b.role)) return bad(res, 'Invalid role.');
      add('role', b.role); if (STAFF.includes(b.role) && !b.status) add('status', 'approved');
    }
    if (su && ('scope_all' in b || 'cities' in b)) { add('scope_all', !!b.scope_all); add('cities', cleanList(b.cities)); }
  }
  if (b.password) {
    if (req.me.role === 'semi_admin') return bad(res, 'Semi admins cannot reset passwords.', 403);
    if (String(b.password).length < 6) return bad(res, 'Password needs at least 6 characters.');
    add('pw', hash(String(b.password)));
  }
  if (!set.length) return res.json({ ok: true });
  p.push(t.id);
  try { await q(`UPDATE users SET ${set.join(',')} WHERE id=$${p.length}`, p); }
  catch (e) { if (e.code === '23505') return bad(res, 'That mobile number is already used.', 409); throw e; }
  res.json({ ok: true });
}));
app.delete('/api/users/:id', auth(...DEL), h(async (req, res) => {
  const t = await target(req, res); if (!t) return;
  if (t.role === 'super_admin' || t.id === req.me.id) return bad(res, 'This account cannot be deleted.');
  await q('DELETE FROM users WHERE id=$1', [t.id]); res.json({ ok: true });
}));
app.post('/api/staff', auth('super_admin'), h(async (req, res) => {
  const { name, mobile, email, password, role, scope_all, cities } = req.body || {}, m = nm(mobile), cs = cleanList(cities);
  if (!STAFF.includes(role)) return bad(res, 'Choose a role.');
  if (!String(name || '').trim() || !MOB.test(m) || String(password || '').length < 6) return bad(res, 'Enter name, a valid mobile number and a password of at least 6 characters.');
  if (!scope_all && !cs.length) return bad(res, 'Choose at least one city, or all cities.');
  try { await q("INSERT INTO users(name,mobile,email,role,status,pw,scope_all,cities) VALUES($1,$2,$3,$4,'approved',$5,$6,$7)", [String(name).trim(), m, String(email || '').trim() || null, role, hash(String(password)), !!scope_all, cs]); }
  catch (e) { if (e.code === '23505') return bad(res, 'This mobile number is already registered.', 409); throw e; }
  res.json({ ok: true });
}));

/* ----- city to hub mapping (super admin) ----- */
app.post('/api/hubs', auth('super_admin'), h(async (req, res) => {
  const { city, hub } = req.body || {};
  if (!String(city || '').trim() || !String(hub || '').trim()) return bad(res, 'Enter city and hub.');
  await q('INSERT INTO hubs(city,hub) VALUES($1,$2) ON CONFLICT DO NOTHING', [city.trim(), hub.trim()]); res.json({ ok: true });
}));
app.delete('/api/hubs/:id', auth('super_admin'), h(async (req, res) => { await q('DELETE FROM hubs WHERE id=$1', [parseInt(req.params.id, 10) || 0]); res.json({ ok: true }); }));

/* ----- photos ----- */
app.post('/api/photos', auth('rider'), h(async (req, res) => {
  const d = req.body || {}, u = req.me;
  if (!d.id || String(d.id).length > 64 || !d.photo || !String(d.shipmentId || '').trim() || !isFinite(d.lat) || !isFinite(d.lng)) return bad(res, 'Missing photo data.');
  if ((await q('SELECT 1 FROM photos WHERE id=$1', [d.id])).rowCount) return res.json({ ok: true, duplicate: true });
  let driveUrl = null;
  if (APPS_SCRIPT_URL) {   // photo goes to Google Drive + Sheet; the secret key never reaches the phone
    const r = await fetch(APPS_SCRIPT_URL, { method: 'POST', body: JSON.stringify({ ...d, key: APPS_SCRIPT_KEY, user: `${u.name} (${u.mobile})`, source: 'web' }) });
    const j = await r.json(); if (!j.ok) throw new Error('Drive upload failed: ' + j.error); driveUrl = j.fileUrl || null;
  }
  await q(`INSERT INTO photos(id,user_id,rider_name,mobile,city,hub,shipment_id,scanned,lat,lng,accuracy,device_time,gps_time,drive_url)
           VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT DO NOTHING`,
    [d.id, u.id, u.name, u.mobile, u.city, u.hub, String(d.shipmentId).trim(), !!d.scanned, d.lat, d.lng, d.accuracy || null, d.deviceTime, d.gpsTime || null, driveUrl]);
  res.json({ ok: true });
}));
app.get('/api/photos', auth(...READ), h(async (req, res) => {
  const [w, p] = photoFilter(req.query, req.me);
  res.json((await q(`SELECT * FROM photos ${w} ORDER BY device_time DESC LIMIT 500`, p)).rows);
}));
app.get('/api/export/photos.csv', auth(...READ), h(async (req, res) => {
  const [w, p] = photoFilter(req.query, req.me);
  const rows = (await q(`SELECT * FROM photos ${w} ORDER BY device_time DESC`, p)).rows;
  rows.forEach(r => { r.map_link = `https://www.google.com/maps?q=${r.lat},${r.lng}`; });
  res.type('text/csv').attachment('photos.csv').send(toCsv(rows, ['received_at', 'rider_name', 'mobile', 'city', 'hub', 'shipment_id', 'scanned', 'lat', 'lng', 'accuracy', 'device_time', 'gps_time', 'map_link', 'drive_url', 'id']));
}));

/* ---------- start ---------- */
(async () => {
  await q(`CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY, name TEXT NOT NULL, mobile TEXT UNIQUE NOT NULL, email TEXT, city TEXT, hub TEXT,
    role TEXT NOT NULL DEFAULT 'rider', status TEXT NOT NULL DEFAULT 'pending', pw TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now());
    CREATE TABLE IF NOT EXISTS hubs(id SERIAL PRIMARY KEY, city TEXT NOT NULL, hub TEXT NOT NULL, UNIQUE(city,hub));
    CREATE TABLE IF NOT EXISTS photos(id TEXT PRIMARY KEY, user_id INT REFERENCES users(id) ON DELETE SET NULL, rider_name TEXT, mobile TEXT, city TEXT, hub TEXT,
      shipment_id TEXT, scanned BOOLEAN, lat DOUBLE PRECISION, lng DOUBLE PRECISION, accuracy REAL, device_time TIMESTAMPTZ, gps_time TIMESTAMPTZ,
      received_at TIMESTAMPTZ DEFAULT now(), drive_url TEXT);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS scope_all BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS cities TEXT[] NOT NULL DEFAULT '{}';`);
  if (SUPERADMIN_MOBILE && SUPERADMIN_PASSWORD && !(await q("SELECT 1 FROM users WHERE role='super_admin'")).rowCount)
    await q("INSERT INTO users(name,mobile,role,status,pw) VALUES($1,$2,'super_admin','approved',$3)", [SUPERADMIN_NAME, nm(SUPERADMIN_MOBILE), hash(SUPERADMIN_PASSWORD)]);
  app.listen(process.env.PORT || 3000, () => console.log('ShipShot backend running'));
})().catch(e => { console.error(e); process.exit(1); });

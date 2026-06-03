const express      = require('express');
const session      = require('express-session');
const SQLiteStore  = require('connect-sqlite3')(session);
const bcrypt       = require('bcryptjs');
const https        = require('https');
const path         = require('path');
const fs           = require('fs');
const { DuckDBInstance } = require('@duckdb/node-api');
const { db, stmt, generateGiftCode, isSubscribed } = require('./db');

const app          = express();
const PORT         = 8212;
const PARQUET_DIR  = '../';
const MERGED_FILE  = '../merged.parquet';

// ── Security: Rate limiter ────────────────────────────────────
const rateBuckets = new Map(); // ip -> { count, resetAt }
function rateLimit(max, windowMs = 60000) {
  return (req, res, next) => {
    const ip  = req.ip || req.socket.remoteAddress;
    const now = Date.now();
    let b = rateBuckets.get(ip);
    if (!b || now > b.resetAt) b = { count: 0, resetAt: now + windowMs };
    b.count++;
    rateBuckets.set(ip, b);
    if (b.count > max) {
      return res.status(429).json({ error: 'Trop de requêtes. Réessayez dans une minute.' });
    }
    next();
  };
}
// Clean rate buckets every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, b] of rateBuckets) if (now > b.resetAt) rateBuckets.delete(ip);
}, 300000);

// ── Security: Anti-bot ────────────────────────────────────────
const BLOCKED_UA = ['curl/', 'python-requests', 'python-httpx', 'python/', 'wget/', 'scrapy',
  'httpie', 'go-http-client', 'java/', 'libwww', 'okhttp', 'postman', 'insomnia',
  'httpclient', 'restsharp', 'mechanize', 'aiohttp'];

function antiBot(req, res, next) {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  if (!ua || BLOCKED_UA.some(b => ua.includes(b))) {
    return res.status(403).json({ error: 'Accès refusé' });
  }
  // API calls must have proper headers
  if (req.path.startsWith('/api/') && !req.headers['origin'] && !req.headers['referer'] && !req.session?.userId) {
    const accept = req.headers['accept'] || '';
    if (!accept.includes('text/html') && !accept.includes('application/json') && !accept.includes('text/event-stream') && !accept.includes('*/*')) {
      return res.status(403).json({ error: 'Accès refusé' });
    }
  }
  next();
}

// ── Security: Anti-VPN/Proxy ──────────────────────────────────
const vpnCache = new Map(); // ip -> { blocked, at }
const VPN_TTL  = 3600000;  // 1h cache
const LOCAL_IPS = new Set(['::1', '127.0.0.1', '::ffff:127.0.0.1']);
function isLocalIP(ip) {
  if (!ip) return true;
  if (LOCAL_IPS.has(ip)) return true;
  const clean = ip.replace('::ffff:', '');
  return clean.startsWith('192.168.') || clean.startsWith('10.') ||
    clean.startsWith('172.16.') || clean.startsWith('172.17.') ||
    clean.startsWith('172.18.') || clean.startsWith('172.31.');
}

async function checkVPN(ip) {
  if (isLocalIP(ip)) return false;
  const cached = vpnCache.get(ip);
  if (cached && Date.now() - cached.at < VPN_TTL) return cached.blocked;

  return new Promise(resolve => {
    const req = https.get(
      `https://ip-api.com/json/${ip}?fields=status,proxy,hosting,tor`,
      { timeout: 3000 },
      r => {
        let body = '';
        r.on('data', d => body += d);
        r.on('end', () => {
          try {
            const d = JSON.parse(body);
            const blocked = d.status === 'success' && !!(d.proxy || d.tor || d.hosting);
            vpnCache.set(ip, { blocked, at: Date.now() });
            resolve(blocked);
          } catch { resolve(false); }
        });
      }
    );
    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
  });
}

function antiVPN(req, res, next) {
  const ip = (req.ip || req.socket.remoteAddress || '').replace('::ffff:', '');
  checkVPN(ip).then(blocked => {
    if (blocked) return res.status(403).json({ error: 'Connexions via VPN/Proxy/Tor non autorisées sur cette plateforme.' });
    next();
  }).catch(() => next());
}

// ── Middleware ────────────────────────────────────────────────
// BigInt → Number pour JSON.stringify (DuckDB retourne COUNT() en BigInt)
app.set('json replacer', (_, v) => typeof v === 'bigint' ? Number(v) : v);

app.set('trust proxy', true);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(antiBot);
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: __dirname }),
  secret: 'nx_secret_2025_xK9pLv8qRm3',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 3600 * 1000, httpOnly: true, sameSite: 'lax' },
}));

// ── Auth middleware ───────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Non connecté' });
  const user = stmt.getUserById.get(req.session.userId);
  if (!user || user.is_banned) return res.status(403).json({ error: 'Accès refusé' });
  req.user = user;
  next();
}
function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (!req.user.is_admin) return res.status(403).json({ error: 'Admin requis' });
    next();
  });
}
function requireSub(req, res, next) {
  requireAuth(req, res, () => {
    if (!req.user.is_admin && !isSubscribed(req.user))
      return res.status(402).json({ error: 'Abonnement requis', code: 'NO_SUB' });
    next();
  });
}

// ── Static pages ──────────────────────────────────────────────
function servePage(file) {
  return (req, res) => res.sendFile(path.join(__dirname, 'public', file));
}
app.get('/',         (req, res) => res.redirect(req.session.userId ? '/search' : '/login'));
app.get('/login',    servePage('login.html'));
app.get('/register', servePage('login.html'));
app.get('/activate', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public', 'activate.html'));
});
app.get('/search', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public', 'search.html'));
});
app.get('/history', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public', 'history.html'));
});
app.get('/settings', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public', 'settings.html'));
});
app.get('/admin', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  const user = stmt.getUserById.get(req.session.userId);
  if (!user || !user.is_admin) return res.redirect('/search');
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});
app.use(express.static(path.join(__dirname, 'public')));

// ── Auth routes ───────────────────────────────────────────────
app.post('/api/auth/register', rateLimit(5, 300000), antiVPN, (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: 'Champs manquants' });
  if (username.length < 3 || username.length > 24)
    return res.status(400).json({ error: 'Pseudo 3-24 caractères' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Mot de passe trop court (6 min)' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: 'Email invalide' });
  if (!/^[a-zA-Z0-9_\-\.]+$/.test(username))
    return res.status(400).json({ error: 'Pseudo invalide (lettres, chiffres, _ - . seulement)' });
  if (stmt.getUserByUsername.get(username))
    return res.status(409).json({ error: 'Pseudo déjà utilisé' });
  if (stmt.getUserByEmail.get(email))
    return res.status(409).json({ error: 'Email déjà utilisé' });
  const hash = bcrypt.hashSync(password, 10);
  const info = stmt.createUser.run(username, email, hash);
  req.session.userId = info.lastInsertRowid;
  res.json({ ok: true, redirect: '/activate' });
});

app.post('/api/auth/login', rateLimit(10, 300000), antiVPN, (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Champs manquants' });
  const user = stmt.getUserByUsername.get(username) || stmt.getUserByEmail.get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'Identifiants incorrects' });
  if (user.is_banned)
    return res.status(403).json({ error: `Compte banni${user.ban_reason ? ' : ' + user.ban_reason : ''}` });
  req.session.userId = user.id;
  res.json({ ok: true, redirect: user.is_admin ? '/admin' : '/search' });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const user = stmt.getUserById.get(req.session.userId);
  if (!user) return res.json({ user: null });
  res.json({
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      is_admin: !!user.is_admin,
      is_banned: !!user.is_banned,
      subscription_expires_at: user.subscription_expires_at,
      subscribed: isSubscribed(user),
    }
  });
});

// ── User: password change ─────────────────────────────────────
app.post('/api/user/change-password', requireAuth, rateLimit(5, 300000), (req, res) => {
  const { current_password, new_password } = req.body;
  if (!current_password || !new_password)
    return res.status(400).json({ error: 'Champs manquants' });
  if (new_password.length < 6)
    return res.status(400).json({ error: 'Nouveau mot de passe trop court (6 min)' });
  if (!bcrypt.compareSync(current_password, req.user.password_hash))
    return res.status(401).json({ error: 'Mot de passe actuel incorrect' });
  const hash = bcrypt.hashSync(new_password, 10);
  stmt.changePassword.run(hash, req.user.id);
  req.session.destroy();
  res.json({ ok: true });
});

// ── User: history ─────────────────────────────────────────────
app.get('/api/user/history', requireAuth, (req, res) => {
  const history = stmt.getUserHistory.all(req.user.id);
  res.json(history);
});

app.delete('/api/user/history/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  if (req.params.id === 'all') {
    stmt.softDeleteAllHistory.run(req.user.id);
  } else {
    stmt.softDeleteHistory.run(id, req.user.id);
  }
  res.json({ ok: true });
});

app.delete('/api/user/history', requireAuth, (req, res) => {
  stmt.softDeleteAllHistory.run(req.user.id);
  res.json({ ok: true });
});

// ── Gift card activation ──────────────────────────────────────
app.post('/api/activate', requireAuth, rateLimit(10, 60000), (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'Code manquant' });
  const card = stmt.getGiftCard.get(code.trim().toUpperCase());
  if (!card) return res.status(404).json({ error: 'Code invalide ou inexistant' });
  if (card.used_by) return res.status(409).json({ error: 'Ce code a déjà été utilisé' });
  stmt.useGiftCard.run(req.user.id, card.code);
  stmt.setSubscription.run(String(card.duration_days), req.user.id);
  const updated = stmt.getUserById.get(req.user.id);
  res.json({ ok: true, expires_at: updated.subscription_expires_at, days: card.duration_days });
});

// ── Admin: users ──────────────────────────────────────────────
app.get('/api/admin/users', requireAdmin, (req, res) => {
  const users = stmt.getAllUsers.all().map(u => ({
    ...u,
    subscribed: isSubscribed(u),
    is_admin: !!u.is_admin,
    is_banned: !!u.is_banned,
  }));
  res.json(users);
});

app.post('/api/admin/users/:id/ban', requireAdmin, (req, res) => {
  const { reason } = req.body;
  const user = stmt.getUserById.get(Number(req.params.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  if (user.is_admin) return res.status(403).json({ error: 'Impossible de bannir un admin' });
  stmt.banUser.run(reason || null, user.id);
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/unban', requireAdmin, (req, res) => {
  stmt.unbanUser.run(Number(req.params.id));
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/subscription', requireAdmin, (req, res) => {
  const days = Math.max(1, parseInt(req.body.days) || 30);
  stmt.setSubscription.run(String(days), Number(req.params.id));
  const user = stmt.getUserById.get(Number(req.params.id));
  res.json({ ok: true, expires_at: user.subscription_expires_at });
});

app.delete('/api/admin/users/:id/subscription', requireAdmin, (req, res) => {
  stmt.clearSubscription.run(Number(req.params.id));
  res.json({ ok: true });
});

app.get('/api/admin/users/:id/history', requireAdmin, (req, res) => {
  const history = stmt.getUserHistoryAdmin.all(Number(req.params.id));
  res.json(history);
});

// ── Admin: gift cards ─────────────────────────────────────────
app.get('/api/admin/giftcards', requireAdmin, (req, res) => {
  res.json(stmt.getAllGiftCards.all());
});

app.post('/api/admin/giftcards', requireAdmin, (req, res) => {
  let { count = 1, duration_days = 30, label = '' } = req.body;
  count         = Math.min(Math.max(1, parseInt(count) || 1), 100);
  duration_days = Math.max(1, parseInt(duration_days) || 30);
  const codes   = [];
  for (let i = 0; i < count; i++) {
    const code = generateGiftCode();
    stmt.createGiftCard.run(code, duration_days, label || null);
    codes.push(code);
  }
  res.json({ ok: true, codes });
});

app.delete('/api/admin/giftcards/:id', requireAdmin, (req, res) => {
  stmt.deleteGiftCard.run(Number(req.params.id));
  res.json({ ok: true });
});

// ── Admin: databases ──────────────────────────────────────────
app.get('/api/admin/databases', requireAdmin, (req, res) => {
  const files = fs.readdirSync(PARQUET_DIR)
    .filter(f => f.endsWith('.parquet'))
    .map(f => {
      const stat = fs.statSync(path.join(PARQUET_DIR, f));
      return {
        name:     f.replace('.parquet', ''),
        file:     f,
        size_mb:  +(stat.size / 1048576).toFixed(1),
        modified: stat.mtime.toISOString(),
      };
    })
    .sort((a, b) => b.size_mb - a.size_mb);
  res.json(files);
});

app.delete('/api/admin/databases/:name', requireAdmin, (req, res) => {
  const safe = path.basename(req.params.name).replace(/[^a-zA-Z0-9_\-]/g, '');
  const file  = path.join(PARQUET_DIR, safe + '.parquet');
  if (!fs.existsSync(file)) return res.status(404).json({ error: 'Fichier introuvable' });
  fs.unlinkSync(file);
  res.json({ ok: true });
});

// ── Admin: history (sees everything including soft-deleted) ───
app.get('/api/admin/history', requireAdmin, (req, res) => {
  res.json(stmt.getAllHistory.all());
});

// ── Stats ─────────────────────────────────────────────────────
let cachedTotal = 0;
let cachedSources = [];
async function computeTotal() {
  if (!fs.existsSync(MERGED_FILE)) {
    console.log('  merged.parquet absent — exécutez merge_all.py');
    return;
  }
  try {
    const rows = await runSQL(`SELECT COUNT(*) AS n FROM '${MERGED_FILE}'`);
    cachedTotal = Number(rows[0]?.n ?? 0);
    const srcs = await runSQL(`SELECT source, COUNT(*) AS n FROM '${MERGED_FILE}' GROUP BY source ORDER BY n DESC`);
    cachedSources = srcs;
    console.log(`  ${cachedTotal.toLocaleString('fr-FR')} entrees dans merged.parquet`);
    srcs.forEach(s => console.log(`    ${s.source}: ${Number(s.n).toLocaleString('fr-FR')}`));
  } catch (e) { console.error('  Comptage:', e.message); }
}

app.get('/api/stats', (req, res) => {
  res.json({
    files_count: cachedSources.length || getParquetFiles().length,
    total_rows:  cachedTotal,
    sources:     cachedSources,
    merged_ready: fs.existsSync(MERGED_FILE),
  });
});

// ── DuckDB ────────────────────────────────────────────────────
let conn = null;
async function initDuckDB() {
  const instance = await DuckDBInstance.create(':memory:');
  conn = await instance.connect();
  await conn.run("PRAGMA threads=8");
  await conn.run("PRAGMA enable_object_cache=true");
  await conn.run("PRAGMA enable_progress_bar=false");
  console.log('  DuckDB OK');
}

function getParquetFiles() {
  return fs.readdirSync(PARQUET_DIR)
    .filter(f => f.endsWith('.parquet'))
    .map(f => path.join(PARQUET_DIR, f).replace(/\\/g, '/'));
}

function normalizeRow(row) {
  const out = {};
  for (const [k, v] of Object.entries(row)) {
    if (v && typeof v === 'object' && Array.isArray(v.items))
      out[k] = v.items.filter(x => x != null);
    else if (typeof v === 'bigint')
      out[k] = Number(v);
    else
      out[k] = v;
  }
  return out;
}

async function runSQL(sql) {
  const result = await conn.run(sql);
  return (await result.getRowObjects()).map(normalizeRow);
}

function esc(str) {
  return String(str).replace(/'/g, "''").replace(/\\/g, '\\\\').slice(0, 200);
}

function phoneVariants(raw) {
  const digits = raw.replace(/\D/g, '');
  const v = new Set([raw.trim()]);
  if (digits.length === 10 && digits[0] === '0') {
    v.add('+33' + digits.slice(1)); v.add('33' + digits.slice(1)); v.add(digits);
  } else if (digits.length === 11 && digits.startsWith('33')) {
    v.add('0' + digits.slice(2)); v.add('+33' + digits.slice(2));
  } else if (digits.length === 12 && raw.startsWith('+33')) {
    v.add('0' + digits.slice(2)); v.add('33' + digits.slice(2));
  }
  return [...v].filter(Boolean);
}

function detectType(q) {
  const c = q.replace(/[\s\-\.\(\)\+]/g, '');
  if (q.includes('@'))                                       return 'email';
  if (/^\d{15}$/.test(c))                                    return 'nir';
  if (/^FR\d{2}[A-Z0-9]{23}$/i.test(q.replace(/\s/g, ''))) return 'iban';
  if (/^\d{8,15}$/.test(c))                                  return 'phone';
  if (/^\d{5}$/.test(q.trim()))                              return 'postal';
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(q.trim())) return 'ip';
  return 'general';
}

function buildWhere(q, filters) {
  const conds = [];
  const cleanQ = (q || '').trim();

  if (cleanQ.length > 0 && cleanQ.length < 3) return null;

  const prefixRange = (col, val) => `
    ${col} >= '${esc(val)}'
    AND ${col} < '${esc(val)}\uffff'
  `;

  if (cleanQ) {
    const type = detectType(cleanQ);

    if (type === 'email') {
      conds.push(`list_contains(email_address, '${esc(cleanQ)}')`);
    }

    else if (type === 'phone') {
      const variants = phoneVariants(cleanQ)
        .map(v => `list_contains(phone_numbers, '${esc(v.toUpperCase())}')`);
      conds.push(`(${variants.join(' OR ')})`);
    }

    else if (type === 'postal') {
      conds.push(`postal_code = '${esc(cleanQ.toUpperCase())}'`);
    }

    else if (type === 'ip') {
      conds.push(`ip_address = '${esc(cleanQ.toUpperCase())}'`);
    }
    

    else {
      // 🔥 PLUS DE ILIKE → RANGE
      conds.push(`(
        ${prefixRange('last_name', cleanQ.toUpperCase())}
        OR
        ${prefixRange('first_name', cleanQ.toUpperCase())}
      )`);
    }
  }

  const fv = k => (filters[k] || '').toString().trim();

  // ⚡ EXACT (rapide)
  for (const k of ['postal_code', 'ip_address', 'nir', 'iban', 'discord_id','representative_last_name','representative_first_name']) {
    const val = fv(k);
    if (val) conds.push(`${k} LIKE '${esc(val.toUpperCase())}%'`);
  }
  for (const k of ['date_of_born']) {
    const val = fv(k);
    if (val) conds.push(`${k} LIKE '%${esc(val.toUpperCase())}%'`);
  }

  // 🔥 PREFIX optimisé
  for (const k of [
    'last_name', 'first_name', 'city', 'city_of_born',
    'username', 'bic', 'vehicule_imatriculation'
  ]) {
    const val = fv(k);
    if (val) conds.push(prefixRange(k, val.toUpperCase()));
  }

  // ❌ contains = lent → à éviter si possible
  const address = fv('address');
  if (address) conds.push(`address LIKE '%${esc(address.toUpperCase())}%'`);

  // listes
  const email = fv('email');
  if (email) conds.push(`list_contains(email_address, '${esc(email)}')`);

  const phone = fv('phone');
  if (phone) {
    const variants = phoneVariants(phone)
      .map(v => `list_contains(phone_numbers, '${esc(v.toUpperCase())}')`);
    conds.push(`(${variants.join(' OR ')})`);
  }

  return conds.length ? conds.join(' AND ') : null;
}

const SELECT_COLS = `
  source,
  gender, last_name, first_name, address, postal_code, city,
  date_of_born, city_of_born, iban, bic, vehicule_imatriculation,
  username, ip_address, discord_id, nir,
  phone_numbers, email_address,
  representative_gender, representative_last_name, representative_first_name,
  representative_email_address, representative_phone_numbers
`;

// ── Search — requête unique sur merged.parquet ────────────────
app.get('/api/search/stream', rateLimit(20, 60000), requireSub, async (req, res) => {
  const q       = (req.query.q || '').trim();
  const filters = (() => { try { return JSON.parse(req.query.filters || '{}'); } catch { return {}; } })();

  if (!q && !Object.values(filters).some(v => String(v || '').trim())) {
    return res.status(400).end();
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const send = obj => { if (!res.writableEnded) res.write(`data: ${JSON.stringify(obj)}\n\n`); };

  if (!fs.existsSync(MERGED_FILE)) {
    send({ type: 'error', message: 'merged.parquet introuvable. Exécutez merge_all.py d\'abord.' });
    res.end(); return;
  }

  const where = buildWhere(q, filters);
  if (!where) { send({ type: 'done', total: 0 }); res.end(); return; }

  // Heartbeat toutes les 3s pour garder la connexion SSE active
  const heartbeat = setInterval(() => {
    if (!res.writableEnded) res.write(': ping\n\n');
  }, 3000);

  send({ type: 'searching' });

  const t0 = Date.now();
  try {
    const sql = `
      SELECT ${SELECT_COLS}
      FROM '${MERGED_FILE}'
      WHERE ${where}
      LIMIT 200
    `;
    console.log(sql)
    const rows = await runSQL(sql);
    clearInterval(heartbeat);

    if (rows.length) send({ type: 'results', results: rows, source: 'merged' });

    try { stmt.addHistory.run(req.user.id, q || null, JSON.stringify(filters), rows.length); } catch {}

    send({ type: 'done', total: rows.length, time_ms: Date.now() - t0 });
  } catch (e) {
    clearInterval(heartbeat);
    send({ type: 'error', message: e.message });
    send({ type: 'done', total: 0, time_ms: Date.now() - t0 });
  }

  res.end();
});

// ── Start ─────────────────────────────────────────────────────
(async () => {
  await initDuckDB();
  const files = getParquetFiles();
  app.listen(PORT, () => {
    console.log(`\n  NEXUS  ->  http://localhost:${PORT}`);
    console.log(`  ${files.length} bases de donnees`);
    console.log('  Calcul du total...\n');
  });
  computeTotal();
})(); 
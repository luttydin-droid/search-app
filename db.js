const Database = require('better-sqlite3');
const bcrypt   = require('bcryptjs');
const path     = require('path');
const crypto   = require('crypto');

const db = new Database(path.join(__dirname, 'datasearch.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    username               TEXT UNIQUE NOT NULL,
    email                  TEXT UNIQUE NOT NULL,
    password_hash          TEXT NOT NULL,
    is_admin               INTEGER DEFAULT 0,
    is_banned              INTEGER DEFAULT 0,
    ban_reason             TEXT,
    subscription_expires_at TEXT,
    created_at             TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS gift_cards (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    code          TEXT UNIQUE NOT NULL,
    duration_days INTEGER NOT NULL,
    label         TEXT,
    used_by       INTEGER REFERENCES users(id),
    used_at       TEXT,
    created_at    TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS search_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER REFERENCES users(id) ON DELETE CASCADE,
    query           TEXT,
    filters         TEXT,
    results_count   INTEGER,
    searched_at     TEXT DEFAULT (datetime('now')),
    deleted_by_user INTEGER DEFAULT 0
  );

  CREATE INDEX IF NOT EXISTS idx_history_user ON search_history(user_id);
  CREATE INDEX IF NOT EXISTS idx_history_date ON search_history(searched_at);

  -- Lignes masquées par un admin (tombstones) : exclues de toutes les recherches
  CREATE TABLE IF NOT EXISTS deleted_rows (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    row_key     TEXT UNIQUE NOT NULL,
    source      TEXT,
    preview     TEXT,
    deleted_by  INTEGER REFERENCES users(id),
    deleted_at  TEXT DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_deleted_key ON deleted_rows(row_key);
`);

// Migrations (idempotent)
try { db.exec('ALTER TABLE search_history ADD COLUMN deleted_by_user INTEGER DEFAULT 0'); } catch {}

// Default admin account
const adminExists = db.prepare('SELECT id FROM users WHERE is_admin = 1').get();
if (!adminExists) {
  const hash = bcrypt.hashSync('Admin@2025!', 10);
  db.prepare(
    'INSERT OR IGNORE INTO users (username, email, password_hash, is_admin) VALUES (?,?,?,1)'
  ).run('admin', 'admin@nexus.local', hash);
  console.log('  Admin cree -> admin / Admin@2025!');
}

// ── Statements ────────────────────────────────────────────────
const stmt = {
  getUserByUsername:  db.prepare('SELECT * FROM users WHERE username = ?'),
  getUserByEmail:     db.prepare('SELECT * FROM users WHERE email = ?'),
  getUserById:        db.prepare('SELECT * FROM users WHERE id = ?'),
  getAllUsers:        db.prepare('SELECT id,username,email,is_admin,is_banned,ban_reason,subscription_expires_at,created_at FROM users ORDER BY created_at DESC'),
  createUser:         db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?,?,?)'),
  banUser:            db.prepare('UPDATE users SET is_banned=1, ban_reason=? WHERE id=?'),
  unbanUser:          db.prepare('UPDATE users SET is_banned=0, ban_reason=NULL WHERE id=?'),
  setSubscription:    db.prepare("UPDATE users SET subscription_expires_at = datetime('now', ? || ' days') WHERE id=?"),
  clearSubscription:  db.prepare('UPDATE users SET subscription_expires_at=NULL WHERE id=?'),
  changePassword:     db.prepare('UPDATE users SET password_hash=? WHERE id=?'),

  // History — user sees only their non-deleted entries
  addHistory:             db.prepare('INSERT INTO search_history (user_id,query,filters,results_count) VALUES (?,?,?,?)'),
  getUserHistory:         db.prepare('SELECT * FROM search_history WHERE user_id=? AND deleted_by_user=0 ORDER BY searched_at DESC LIMIT 300'),
  softDeleteHistory:      db.prepare('UPDATE search_history SET deleted_by_user=1 WHERE id=? AND user_id=?'),
  softDeleteAllHistory:   db.prepare('UPDATE search_history SET deleted_by_user=1 WHERE user_id=?'),
  // Admin sees everything including deleted
  getAllHistory:          db.prepare('SELECT h.*, u.username FROM search_history h JOIN users u ON h.user_id=u.id ORDER BY h.searched_at DESC LIMIT 1000'),
  getUserHistoryAdmin:    db.prepare('SELECT * FROM search_history WHERE user_id=? ORDER BY searched_at DESC LIMIT 500'),

  createGiftCard:  db.prepare('INSERT INTO gift_cards (code,duration_days,label) VALUES (?,?,?)'),
  getGiftCard:     db.prepare('SELECT * FROM gift_cards WHERE code=?'),
  useGiftCard:     db.prepare("UPDATE gift_cards SET used_by=?, used_at=datetime('now') WHERE code=?"),
  getAllGiftCards:  db.prepare('SELECT g.*, u.username as used_by_name FROM gift_cards g LEFT JOIN users u ON g.used_by=u.id ORDER BY g.created_at DESC'),
  deleteGiftCard:  db.prepare('DELETE FROM gift_cards WHERE id=?'),

  // Lignes masquées (tombstones)
  addDeletedRow:   db.prepare('INSERT OR IGNORE INTO deleted_rows (row_key, source, preview, deleted_by) VALUES (?,?,?,?)'),
  getDeletedKeys:  db.prepare('SELECT row_key FROM deleted_rows'),
  countDeletedRows: db.prepare('SELECT COUNT(*) AS n FROM deleted_rows'),
};

function generateGiftCode() {
  const chars    = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const segments = [4, 4, 4];
  return segments.map(n =>
    Array.from({ length: n }, () => chars[crypto.randomInt(chars.length)]).join('')
  ).join('-');
}

function isSubscribed(user) {
  if (!user.subscription_expires_at) return false;
  return new Date(user.subscription_expires_at + 'Z') > new Date();
}

module.exports = { db, stmt, generateGiftCode, isSubscribed };

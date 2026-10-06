
/* ---------- 00-core.js ---------- */
/* ==========================================================================
   DegenLand · server (Cloudflare Pages "advanced mode" + D1)
   Un solo file, nessuna dipendenza. Generato da server/parts/*.js
   ========================================================================== */
const NOW = () => (globalThis.__NOW != null ? globalThis.__NOW : Date.now());
const SEC = 1000, MIN = 60000, HOUR = 3600000, DAY = 86400000;
const LAMPORTS = 1000000000;

class HttpError extends Error { constructor(status, code, message) { super(message || code); this.status = status; this.code = code; } }
const bad = (code, msg) => new HttpError(400, code, msg);
const unauth = (code = 'unauthorized', msg) => new HttpError(401, code, msg);
const forbid = (code = 'forbidden', msg) => new HttpError(403, code, msg);
const notfound = (code = 'not_found', msg) => new HttpError(404, code, msg);
const conflict = (code = 'conflict', msg) => new HttpError(409, code, msg);
const tooMany = (code = 'rate_limited', msg) => new HttpError(429, code, msg);

const enc = new TextEncoder();
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const b64u = b => { let s = ''; new Uint8Array(b).forEach(x => s += String.fromCharCode(x)); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
const rndBytes = n => { const a = new Uint8Array(n); crypto.getRandomValues(a); return a; };
const rid = (n = 16) => b64u(rndBytes(n));
const sha256hex = async s => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
const hmacRaw = async (keyBytes, data, hash = 'SHA-256') => {
  const k = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, typeof data === 'string' ? enc.encode(data) : data));
};
function randInt(min, max) { // inclusivo, uniforme
  const range = max - min + 1; const lim = Math.floor(0x100000000 / range) * range; let x;
  do { x = new Uint32Array(rndBytes(4).buffer)[0]; } while (x >= lim);
  return min + (x % range);
}
const randFloat = () => new Uint32Array(rndBytes(4).buffer)[0] / 0x100000000;
const timingSafeEq = (a, b) => { a = String(a); b = String(b); if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; };

/* --- base58 (indirizzi Solana) --- */
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58enc(bytes) {
  let n = 0n; for (const b of bytes) n = (n << 8n) + BigInt(b);
  let s = ''; while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const b of bytes) { if (b === 0) s = '1' + s; else break; }
  return s;
}
function b58dec(str) {
  let n = 0n; for (const c of str) { const i = B58.indexOf(c); if (i < 0) return null; n = n * 58n + BigInt(i); }
  const out = []; while (n > 0n) { out.unshift(Number(n & 255n)); n >>= 8n; }
  for (const c of str) { if (c === '1') out.unshift(0); else break; }
  return new Uint8Array(out);
}
const isSolAddress = a => typeof a === 'string' && /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(a) && (b58dec(a) || []).length === 32;

/* --- base32 + TOTP (RFC 6238) per la console --- */
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const b32enc = bytes => { let bits = 0, v = 0, o = ''; for (const b of bytes) { v = (v << 8) | b; bits += 8; while (bits >= 5) { o += B32[(v >>> (bits - 5)) & 31]; bits -= 5; } } if (bits > 0) o += B32[(v << (5 - bits)) & 31]; return o; };
const b32dec = s => { let bits = 0, v = 0; const o = []; for (const c of s.replace(/=+$/, '').toUpperCase()) { const i = B32.indexOf(c); if (i < 0) continue; v = (v << 5) | i; bits += 5; if (bits >= 8) { o.push((v >>> (bits - 8)) & 255); bits -= 8; } } return new Uint8Array(o); };
async function totpAt(secretB32, t) {
  const ctr = Math.floor(t / 30000); const buf = new ArrayBuffer(8); new DataView(buf).setUint32(4, ctr);
  const h = await hmacRaw(b32dec(secretB32), new Uint8Array(buf), 'SHA-1');
  const o = h[19] & 15; const code = ((h[o] & 127) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1000000;
  return String(code).padStart(6, '0');
}
async function totpVerify(secretB32, code, t = NOW()) {
  code = String(code || '').replace(/\s/g, ''); if (!/^\d{6}$/.test(code)) return false;
  for (const d of [-1, 0, 1]) if (timingSafeEq(await totpAt(secretB32, t + d * 30000), code)) return true;
  return false;
}

/* --- HTTP helpers --- */
const SEC_HEADERS = { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin', 'Cache-Control': 'no-store' };
function json(data, status = 200, headers = {}) { return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...SEC_HEADERS, ...headers } }); }
function parseCookies(req) { const o = {}; (req.headers.get('Cookie') || '').split(/;\s*/).forEach(p => { const i = p.indexOf('='); if (i > 0) o[p.slice(0, i)] = decodeURIComponent(p.slice(i + 1)); }); return o; }
const cookieStr = (name, val, { maxAge, path = '/' } = {}) => `${name}=${encodeURIComponent(val)}; Path=${path}; HttpOnly; Secure; SameSite=Lax` + (maxAge != null ? `; Max-Age=${maxAge}` : '');
async function readJson(req, max = 20000) {
  const t = await req.text(); if (t.length > max) throw bad('payload_too_large'); if (!t) return {};
  try { const v = JSON.parse(t); return v && typeof v === 'object' ? v : {}; } catch (e) { throw bad('bad_json'); }
}
function ipKey(ip) {   // IPv4 così com'è; IPv6 raggruppato per /64 (un dispositivo mobile riceve un intero /64)
  ip = String(ip || '').toLowerCase(); if (!ip.includes(':')) return ip;
  if (ip.includes('.')) return ip.slice(ip.lastIndexOf(':') + 1);            // IPv4 mappato in IPv6
  const [h, t] = ip.split('::'); const head = h ? h.split(':') : [], tail = t ? t.split(':') : [];
  const full = [...head, ...Array(Math.max(0, 8 - head.length - tail.length)).fill('0'), ...tail];
  return full.slice(0, 4).map(x => x.replace(/^0+(?=.)/, '')).join(':') + '::/64';
}
const ipEventStmt = (db, userId, ip, kind) => st(db, 'INSERT INTO ip_events(user_id,ip,ip_key,kind,created_at) VALUES(?,?,?,?,?)', userId, ip, ipKey(ip), kind, NOW());
const ipOf = req => req.headers.get('CF-Connecting-IP') || (req.headers.get('X-Forwarded-For') || '').split(',')[0].trim() || '0.0.0.0';
const clamp = (x, a, b) => Math.min(b, Math.max(a, x));
const isInt = x => Number.isInteger(x);
const dayOf = t => Math.floor(t / DAY);
const normEmail = e => String(e || '').trim().toLowerCase();
const validEmail = e => /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/.test(e) && e.length <= 254;


/* ---------- 10-db.js ---------- */
/* ============================ DATABASE (D1 / SQLite) ============================
   Convenzioni: importi SOL in lamport (interi), token in millesimi (1 token = 1000),
   tempi in millisecondi UTC. Le operazioni multiple passano SEMPRE da db.batch()
   (atomico): i vincoli CHECK/UNIQUE fanno fallire e annullare l'intero batch. */
const SCHEMA_VERSION = 5;
const MIGRATIONS = { 5: ["UPDATE adv_campaigns SET frame=1 WHERE kind='house'"],   // v5: anteprima navigabile per gli annunci della casa
  4: [   // v4: Advertise Center (campagne a rotazione negli annunci del gioco)
  'ALTER TABLE ad_sessions ADD COLUMN campaign_id INTEGER',
  'ALTER TABLE ad_sessions ADD COLUMN min_seconds INTEGER',
`CREATE TABLE IF NOT EXISTS adv_campaigns(
  id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL DEFAULT 'paid' CHECK(kind IN ('paid','house')),
  title TEXT NOT NULL, descr TEXT, url TEXT NOT NULL, seconds INTEGER NOT NULL CHECK(seconds IN (5,7,10)),
  views_total INTEGER NOT NULL DEFAULT 0, views_done INTEGER NOT NULL DEFAULT 0, clicks INTEGER NOT NULL DEFAULT 0,
  pay_method TEXT CHECK(pay_method IN ('SOL','TOKEN')), price_usd REAL, price_lamports INTEGER, price_milli INTEGER,
  user_id INTEGER, contact TEXT, payer_wallet TEXT, tx_signature TEXT, view_key_hash TEXT,
  status TEXT NOT NULL CHECK(status IN ('in_attesa','attiva','in_pausa','completata','rifiutata')),
  frame INTEGER NOT NULL DEFAULT 0, reject_reason TEXT, last_served_at INTEGER NOT NULL DEFAULT 0,
  ip TEXT, created_at INTEGER NOT NULL, decided_at INTEGER, decided_by INTEGER)`,
`CREATE INDEX IF NOT EXISTS adv_serve ON adv_campaigns(status, kind, last_served_at)`,
`INSERT OR IGNORE INTO adv_campaigns(id,kind,title,descr,url,seconds,status,frame,created_at) VALUES(1,'house','ToolsEdge','Free crypto and iGaming calculators in one place','https://toolsedge.cloud/',5,'attiva',1,CAST(strftime('%s','now') AS INTEGER)*1000)`,
`INSERT OR IGNORE INTO adv_campaigns(id,kind,title,descr,url,seconds,status,frame,created_at) VALUES(2,'house','Edge Rates','Compare swap routes and rates across providers','https://toolsedge.cloud/crypto/edge-rates',5,'attiva',1,CAST(strftime('%s','now') AS INTEGER)*1000)`,
`INSERT OR IGNORE INTO adv_campaigns(id,kind,title,descr,url,seconds,status,frame,created_at) VALUES(3,'house','Edge Staking','Compare staking yields and APY before you stake','https://toolsedge.cloud/crypto/edge-staking',5,'attiva',1,CAST(strftime('%s','now') AS INTEGER)*1000)`,
`INSERT OR IGNORE INTO adv_campaigns(id,kind,title,descr,url,seconds,status,frame,created_at) VALUES(4,'house','Edge Wagering','Casino bonus wagering calculator','https://toolsedge.cloud/igaming/edge-wagering',5,'attiva',1,CAST(strftime('%s','now') AS INTEGER)*1000)`,
`INSERT OR IGNORE INTO adv_campaigns(id,kind,title,descr,url,seconds,status,frame,created_at) VALUES(5,'house','Edge Rakeback','Casino rakeback calculator and comparison','https://toolsedge.cloud/igaming/edge-rakeback',5,'attiva',1,CAST(strftime('%s','now') AS INTEGER)*1000)`,
`INSERT OR IGNORE INTO adv_campaigns(id,kind,title,descr,url,seconds,status,frame,created_at) VALUES(6,'house','Edge DCA','Simulate a dollar-cost averaging strategy','https://toolsedge.cloud/crypto/edge-dca',5,'attiva',1,CAST(strftime('%s','now') AS INTEGER)*1000)`,
`INSERT OR IGNORE INTO adv_campaigns(id,kind,title,descr,url,seconds,status,frame,created_at) VALUES(7,'house','Edge Liquidation','Futures margin and liquidation price calculator','https://toolsedge.cloud/crypto/edge-liquidation',5,'attiva',1,CAST(strftime('%s','now') AS INTEGER)*1000)`,
`INSERT OR IGNORE INTO adv_campaigns(id,kind,title,descr,url,seconds,status,frame,created_at) VALUES(8,'house','Edge CEX Arbitrage','Scan price gaps between exchanges','https://toolsedge.cloud/crypto/edge-cex-arbitrage',5,'attiva',1,CAST(strftime('%s','now') AS INTEGER)*1000)`,
`INSERT OR IGNORE INTO adv_campaigns(id,kind,title,descr,url,seconds,status,frame,created_at) VALUES(9,'house','Edge DEX Arbitrage','Scan price gaps between liquidity pools','https://toolsedge.cloud/crypto/edge-dex-arbitrage',5,'attiva',1,CAST(strftime('%s','now') AS INTEGER)*1000)`,
`INSERT OR IGNORE INTO adv_campaigns(id,kind,title,descr,url,seconds,status,frame,created_at) VALUES(10,'house','Edge Surebet','Find sportsbook arbitrage opportunities','https://toolsedge.cloud/sports/edge-surebet',5,'attiva',1,CAST(strftime('%s','now') AS INTEGER)*1000)`,
], 3: [
  'ALTER TABLE users ADD COLUMN wd_hold INTEGER NOT NULL DEFAULT 0',
  'ALTER TABLE miners ADD COLUMN special TEXT',
  'ALTER TABLE ip_events ADD COLUMN ip_key TEXT',
  'UPDATE ip_events SET ip_key = ip WHERE ip_key IS NULL',
  'CREATE INDEX IF NOT EXISTS ip_events_key ON ip_events(ip_key, created_at)',
  `CREATE TABLE IF NOT EXISTS pioneers(no INTEGER PRIMARY KEY CHECK(no BETWEEN 1 AND 1000), user_id INTEGER NOT NULL UNIQUE REFERENCES users(id), ip_key TEXT, granted_at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS ip_allow(ip_key TEXT PRIMARY KEY, note TEXT, admin_id INTEGER, created_at INTEGER NOT NULL)`,
], 2: ['ALTER TABLE users ADD COLUMN nick_changed_at INTEGER', 'ALTER TABLE users ADD COLUMN lb_hidden INTEGER NOT NULL DEFAULT 0'] };   // v2: nickname scelto dall'utente, opt-out dalle classifiche
const SCHEMA = [
`CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT)`,
`CREATE TABLE IF NOT EXISTS guards(k TEXT PRIMARY KEY, created_at INTEGER NOT NULL)`,
`CREATE TABLE IF NOT EXISTS rate_limits(k TEXT PRIMARY KEY, window_start INTEGER NOT NULL, count INTEGER NOT NULL)`,
`CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nickname TEXT NOT NULL UNIQUE COLLATE NOCASE,
  status TEXT NOT NULL DEFAULT 'attivo' CHECK(status IN ('attivo','sospeso','chiuso')),
  referrer_id INTEGER REFERENCES users(id),
  referral_code TEXT NOT NULL UNIQUE,
  is_dev INTEGER NOT NULL DEFAULT 0,
  mine_mode TEXT NOT NULL DEFAULT 'SOL' CHECK(mine_mode IN ('SOL','TOKEN')),
  energy INTEGER NOT NULL DEFAULT 200 CHECK(energy >= 0),
  racks INTEGER NOT NULL DEFAULT 1 CHECK(racks BETWEEN 1 AND 6),
  tg_confirm INTEGER NOT NULL DEFAULT 0,
  locale TEXT NOT NULL DEFAULT 'en',
  last_tap_at INTEGER,
  taps_total INTEGER NOT NULL DEFAULT 0,
  suspended_reason TEXT,
  terms_at INTEGER,
  nick_changed_at INTEGER,
  lb_hidden INTEGER NOT NULL DEFAULT 0,
  wd_hold INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER)`,
`CREATE UNIQUE INDEX IF NOT EXISTS one_dev ON users(is_dev) WHERE is_dev = 1`,
`CREATE INDEX IF NOT EXISTS users_referrer ON users(referrer_id)`,
`CREATE TABLE IF NOT EXISTS identities(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  provider TEXT NOT NULL CHECK(provider IN ('email','telegram')),
  subject TEXT NOT NULL,
  display TEXT,
  chat_ok INTEGER NOT NULL DEFAULT 0,
  verified_at INTEGER,
  created_at INTEGER NOT NULL,
  UNIQUE(provider, subject), UNIQUE(user_id, provider))`,
`CREATE TABLE IF NOT EXISTS sessions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  token_hash TEXT NOT NULL UNIQUE, ip TEXT, ua TEXT,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER)`,
`CREATE TABLE IF NOT EXISTS auth_codes(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  purpose TEXT NOT NULL, subject TEXT NOT NULL, code_hash TEXT NOT NULL,
  user_id INTEGER, attempts INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL, used_at INTEGER, created_at INTEGER NOT NULL)`,
`CREATE INDEX IF NOT EXISTS auth_codes_subject ON auth_codes(purpose, subject, created_at)`,
`CREATE TABLE IF NOT EXISTS addresses(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  address TEXT NOT NULL, is_current INTEGER NOT NULL DEFAULT 1,
  locked_until INTEGER, created_at INTEGER NOT NULL, replaced_at INTEGER)`,
`CREATE UNIQUE INDEX IF NOT EXISTS one_current_addr ON addresses(user_id) WHERE is_current = 1`,
`CREATE INDEX IF NOT EXISTS addr_lookup ON addresses(address)`,
`CREATE TABLE IF NOT EXISTS ip_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id), ip TEXT NOT NULL, ip_key TEXT, kind TEXT NOT NULL, created_at INTEGER NOT NULL)`,
`CREATE INDEX IF NOT EXISTS ip_events_ip ON ip_events(ip, created_at)`,
`CREATE INDEX IF NOT EXISTS ip_events_user ON ip_events(user_id, created_at)`,
`CREATE INDEX IF NOT EXISTS ip_events_key ON ip_events(ip_key, created_at)`,
`CREATE TABLE IF NOT EXISTS pioneers(no INTEGER PRIMARY KEY CHECK(no BETWEEN 1 AND 1000), user_id INTEGER NOT NULL UNIQUE REFERENCES users(id), ip_key TEXT, granted_at INTEGER NOT NULL)`,
`CREATE TABLE IF NOT EXISTS ip_allow(ip_key TEXT PRIMARY KEY, note TEXT, admin_id INTEGER, created_at INTEGER NOT NULL)`,
`CREATE TABLE IF NOT EXISTS param_sets(
  id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT NOT NULL, data TEXT NOT NULL,
  created_by INTEGER, created_at INTEGER NOT NULL)`,
`CREATE TABLE IF NOT EXISTS pools(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  number INTEGER NOT NULL UNIQUE,
  param_set_id INTEGER NOT NULL REFERENCES param_sets(id),
  status TEXT NOT NULL CHECK(status IN ('attiva','in_chiusura','chiusa')),
  blocks INTEGER NOT NULL DEFAULT 0,
  halvings INTEGER NOT NULL DEFAULT 0,
  scrap_pct REAL, close_cursor INTEGER NOT NULL DEFAULT 0,
  opened_at INTEGER, closed_at INTEGER)`,
`CREATE UNIQUE INDEX IF NOT EXISTS one_open_pool ON pools(status) WHERE status IN ('attiva','in_chiusura')`,
`CREATE TABLE IF NOT EXISTS pool_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, pool_id INTEGER NOT NULL REFERENCES pools(id),
  kind TEXT NOT NULL, at_blocks INTEGER NOT NULL, generation INTEGER, details TEXT, created_at INTEGER NOT NULL)`,
`CREATE TABLE IF NOT EXISTS miners(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id INTEGER NOT NULL REFERENCES users(id),
  model_id INTEGER NOT NULL,
  pool_id INTEGER REFERENCES pools(id),
  generation INTEGER NOT NULL DEFAULT 0,
  is_welcome INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL DEFAULT 'magazzino' CHECK(state IN ('magazzino','installato','in_vendita','rottamato')),
  rack INTEGER, slot INTEGER,
  worked_blocks INTEGER NOT NULL DEFAULT 0,
  special TEXT,
  break_at INTEGER,
  broken INTEGER NOT NULL DEFAULT 0,
  paid_milli INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  CHECK((state = 'installato') = (rack IS NOT NULL AND slot IS NOT NULL)))`,
`CREATE UNIQUE INDEX IF NOT EXISTS miner_slot ON miners(owner_id, rack, slot) WHERE state = 'installato'`,
`CREATE INDEX IF NOT EXISTS miners_owner ON miners(owner_id, state)`,
`CREATE INDEX IF NOT EXISTS miners_pool ON miners(pool_id, state)`,
`CREATE TABLE IF NOT EXISTS miner_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, miner_id INTEGER NOT NULL, kind TEXT NOT NULL,
  actor_id INTEGER, details TEXT, created_at INTEGER NOT NULL)`,
`CREATE TABLE IF NOT EXISTS farms(
  user_id INTEGER PRIMARY KEY REFERENCES users(id),
  video_until INTEGER NOT NULL DEFAULT 0, ext_until INTEGER NOT NULL DEFAULT 0, on_until INTEGER NOT NULL DEFAULT 0,
  last_block_at INTEGER NOT NULL DEFAULT 0, last_settled_at INTEGER NOT NULL DEFAULT 0,
  blocks_total INTEGER NOT NULL DEFAULT 0)`,
`CREATE TABLE IF NOT EXISTS farm_starts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, pool_id INTEGER NOT NULL,
  source TEXT NOT NULL, pool_block_no INTEGER, created_at INTEGER NOT NULL)`,
`CREATE INDEX IF NOT EXISTS farm_starts_user ON farm_starts(user_id, created_at)`,
`CREATE TABLE IF NOT EXISTS extensions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, days INTEGER NOT NULL,
  price_milli INTEGER NOT NULL, starts_at INTEGER NOT NULL, ends_at INTEGER NOT NULL, created_at INTEGER NOT NULL)`,
`CREATE TABLE IF NOT EXISTS ad_sessions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, purpose TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE, started_at INTEGER NOT NULL, completed_at INTEGER, ip TEXT, campaign_id INTEGER, min_seconds INTEGER)`,
`CREATE TABLE IF NOT EXISTS adv_campaigns(
  id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL DEFAULT 'paid' CHECK(kind IN ('paid','house')),
  title TEXT NOT NULL, descr TEXT, url TEXT NOT NULL, seconds INTEGER NOT NULL CHECK(seconds IN (5,7,10)),
  views_total INTEGER NOT NULL DEFAULT 0, views_done INTEGER NOT NULL DEFAULT 0, clicks INTEGER NOT NULL DEFAULT 0,
  pay_method TEXT CHECK(pay_method IN ('SOL','TOKEN')), price_usd REAL, price_lamports INTEGER, price_milli INTEGER,
  user_id INTEGER, contact TEXT, payer_wallet TEXT, tx_signature TEXT, view_key_hash TEXT,
  status TEXT NOT NULL CHECK(status IN ('in_attesa','attiva','in_pausa','completata','rifiutata')),
  frame INTEGER NOT NULL DEFAULT 0, reject_reason TEXT, last_served_at INTEGER NOT NULL DEFAULT 0,
  ip TEXT, created_at INTEGER NOT NULL, decided_at INTEGER, decided_by INTEGER)`,
`CREATE INDEX IF NOT EXISTS adv_serve ON adv_campaigns(status, kind, last_served_at)`,
`INSERT OR IGNORE INTO adv_campaigns(id,kind,title,descr,url,seconds,status,frame,created_at) VALUES(1,'house','ToolsEdge','Free crypto and iGaming calculators in one place','https://toolsedge.cloud/',5,'attiva',1,CAST(strftime('%s','now') AS INTEGER)*1000)`,
`INSERT OR IGNORE INTO adv_campaigns(id,kind,title,descr,url,seconds,status,frame,created_at) VALUES(2,'house','Edge Rates','Compare swap routes and rates across providers','https://toolsedge.cloud/crypto/edge-rates',5,'attiva',1,CAST(strftime('%s','now') AS INTEGER)*1000)`,
`INSERT OR IGNORE INTO adv_campaigns(id,kind,title,descr,url,seconds,status,frame,created_at) VALUES(3,'house','Edge Staking','Compare staking yields and APY before you stake','https://toolsedge.cloud/crypto/edge-staking',5,'attiva',1,CAST(strftime('%s','now') AS INTEGER)*1000)`,
`INSERT OR IGNORE INTO adv_campaigns(id,kind,title,descr,url,seconds,status,frame,created_at) VALUES(4,'house','Edge Wagering','Casino bonus wagering calculator','https://toolsedge.cloud/igaming/edge-wagering',5,'attiva',1,CAST(strftime('%s','now') AS INTEGER)*1000)`,
`INSERT OR IGNORE INTO adv_campaigns(id,kind,title,descr,url,seconds,status,frame,created_at) VALUES(5,'house','Edge Rakeback','Casino rakeback calculator and comparison','https://toolsedge.cloud/igaming/edge-rakeback',5,'attiva',1,CAST(strftime('%s','now') AS INTEGER)*1000)`,
`INSERT OR IGNORE INTO adv_campaigns(id,kind,title,descr,url,seconds,status,frame,created_at) VALUES(6,'house','Edge DCA','Simulate a dollar-cost averaging strategy','https://toolsedge.cloud/crypto/edge-dca',5,'attiva',1,CAST(strftime('%s','now') AS INTEGER)*1000)`,
`INSERT OR IGNORE INTO adv_campaigns(id,kind,title,descr,url,seconds,status,frame,created_at) VALUES(7,'house','Edge Liquidation','Futures margin and liquidation price calculator','https://toolsedge.cloud/crypto/edge-liquidation',5,'attiva',1,CAST(strftime('%s','now') AS INTEGER)*1000)`,
`INSERT OR IGNORE INTO adv_campaigns(id,kind,title,descr,url,seconds,status,frame,created_at) VALUES(8,'house','Edge CEX Arbitrage','Scan price gaps between exchanges','https://toolsedge.cloud/crypto/edge-cex-arbitrage',5,'attiva',1,CAST(strftime('%s','now') AS INTEGER)*1000)`,
`INSERT OR IGNORE INTO adv_campaigns(id,kind,title,descr,url,seconds,status,frame,created_at) VALUES(9,'house','Edge DEX Arbitrage','Scan price gaps between liquidity pools','https://toolsedge.cloud/crypto/edge-dex-arbitrage',5,'attiva',1,CAST(strftime('%s','now') AS INTEGER)*1000)`,
`INSERT OR IGNORE INTO adv_campaigns(id,kind,title,descr,url,seconds,status,frame,created_at) VALUES(10,'house','Edge Surebet','Find sportsbook arbitrage opportunities','https://toolsedge.cloud/sports/edge-surebet',5,'attiva',1,CAST(strftime('%s','now') AS INTEGER)*1000)`,
`CREATE TABLE IF NOT EXISTS accounts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id INTEGER REFERENCES users(id), system_code TEXT,
  asset TEXT NOT NULL CHECK(asset IN ('SOL','TOKEN','CREDIT')),
  created_at INTEGER NOT NULL,
  CHECK((owner_id IS NULL) <> (system_code IS NULL)))`,
`CREATE UNIQUE INDEX IF NOT EXISTS acc_user ON accounts(owner_id, asset) WHERE owner_id IS NOT NULL`,
`CREATE UNIQUE INDEX IF NOT EXISTS acc_sys ON accounts(system_code, asset) WHERE system_code IS NOT NULL`,
`CREATE TABLE IF NOT EXISTS ledger_tx(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ref TEXT NOT NULL UNIQUE, kind TEXT NOT NULL,
  memo TEXT, idem TEXT UNIQUE, admin_id INTEGER, created_at INTEGER NOT NULL)`,
`CREATE TABLE IF NOT EXISTS ledger_entries(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tx_id INTEGER NOT NULL REFERENCES ledger_tx(id),
  account_id INTEGER NOT NULL REFERENCES accounts(id),
  amount INTEGER NOT NULL CHECK(amount <> 0), created_at INTEGER NOT NULL)`,
`CREATE INDEX IF NOT EXISTS le_account ON ledger_entries(account_id, created_at)`,
`CREATE INDEX IF NOT EXISTS le_tx ON ledger_entries(tx_id)`,
`CREATE TABLE IF NOT EXISTS balances(
  account_id INTEGER PRIMARY KEY REFERENCES accounts(id),
  amount INTEGER NOT NULL DEFAULT 0, min_amount INTEGER NOT NULL DEFAULT 0,
  CHECK(amount >= min_amount))`,
`CREATE TABLE IF NOT EXISTS deposit_intents(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id),
  lamports INTEGER NOT NULL, status TEXT NOT NULL CHECK(status IN ('aperto','accreditato','scaduto')),
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, signature TEXT)`,
`CREATE UNIQUE INDEX IF NOT EXISTS open_amount ON deposit_intents(lamports) WHERE status = 'aperto'`,
`CREATE TABLE IF NOT EXISTS deposits(
  id INTEGER PRIMARY KEY AUTOINCREMENT, signature TEXT NOT NULL UNIQUE,
  lamports INTEGER NOT NULL, sender TEXT, user_id INTEGER, intent_id INTEGER,
  sol_usd REAL, token_milli INTEGER,
  status TEXT NOT NULL CHECK(status IN ('accreditato','non_abbinato','scartato')),
  detected_at INTEGER NOT NULL, credited_at INTEGER, note TEXT)`,
`CREATE TABLE IF NOT EXISTS market_listings(
  id INTEGER PRIMARY KEY AUTOINCREMENT, miner_id INTEGER NOT NULL REFERENCES miners(id),
  seller_id INTEGER NOT NULL REFERENCES users(id),
  price_milli INTEGER NOT NULL CHECK(price_milli > 0),
  status TEXT NOT NULL CHECK(status IN ('attivo','venduto','ritirato')),
  buyer_id INTEGER, created_at INTEGER NOT NULL, closed_at INTEGER)`,
`CREATE UNIQUE INDEX IF NOT EXISTS one_listing ON market_listings(miner_id) WHERE status = 'attivo'`,
`CREATE TABLE IF NOT EXISTS market_sales(
  listing_id INTEGER PRIMARY KEY, buyer_id INTEGER NOT NULL, price_milli INTEGER NOT NULL, created_at INTEGER NOT NULL)`,
`CREATE TABLE IF NOT EXISTS scrap_credits(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, pool_id INTEGER NOT NULL,
  miners INTEGER NOT NULL, scrap_pct REAL NOT NULL, credit_milli INTEGER NOT NULL, created_at INTEGER NOT NULL,
  UNIQUE(user_id, pool_id))`,
`CREATE TABLE IF NOT EXISTS referral_earnings(
  id INTEGER PRIMARY KEY AUTOINCREMENT, referrer_id INTEGER NOT NULL, referee_id INTEGER NOT NULL,
  day INTEGER NOT NULL, asset TEXT NOT NULL, amount INTEGER NOT NULL,
  UNIQUE(referrer_id, referee_id, day, asset))`,
`CREATE TABLE IF NOT EXISTS withdrawals(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id),
  address TEXT NOT NULL, lamports INTEGER NOT NULL CHECK(lamports > 0),
  status TEXT NOT NULL CHECK(status IN ('conferma','attesa','eseguito','rifiutato','annullato')),
  tg_confirmed_at INTEGER, risk_score INTEGER NOT NULL DEFAULT 0, risk_flags TEXT NOT NULL DEFAULT '[]',
  handled_by INTEGER, handled_at INTEGER, reject_reason TEXT, tx_signature TEXT,
  requested_ip TEXT, day INTEGER NOT NULL, created_at INTEGER NOT NULL)`,
`CREATE UNIQUE INDEX IF NOT EXISTS one_wd_day ON withdrawals(user_id, day) WHERE status IN ('conferma','attesa','eseguito')`,
`CREATE INDEX IF NOT EXISTS wd_queue ON withdrawals(status, created_at)`,
`CREATE TABLE IF NOT EXISTS risk_flags(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, code TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'media', details TEXT, resolved_by INTEGER, resolved_at INTEGER, created_at INTEGER NOT NULL)`,
`CREATE INDEX IF NOT EXISTS risk_open ON risk_flags(user_id) WHERE resolved_at IS NULL`,
`CREATE TABLE IF NOT EXISTS notifications(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, channel TEXT NOT NULL,
  kind TEXT NOT NULL, payload TEXT, sent_at INTEGER, error TEXT, created_at INTEGER NOT NULL)`,
`CREATE INDEX IF NOT EXISTS notif_pending ON notifications(created_at) WHERE sent_at IS NULL`,
`CREATE TABLE IF NOT EXISTS fx_rates(
  id INTEGER PRIMARY KEY AUTOINCREMENT, sol_usd REAL NOT NULL, source TEXT NOT NULL, reason TEXT NOT NULL, valid_from INTEGER NOT NULL)`,
`CREATE TABLE IF NOT EXISTS treasury_movements(
  id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, lamports INTEGER NOT NULL,
  tx_signature TEXT, admin_id INTEGER, note TEXT, created_at INTEGER NOT NULL)`,
`CREATE TABLE IF NOT EXISTS treasury_snapshots(
  day INTEGER PRIMARY KEY, pool_lamports INTEGER, pending_lamports INTEGER, queued_lamports INTEGER,
  prod30 INTEGER, coverage REAL, scrap_pct REAL, active_farms INTEGER, blocks INTEGER)`,
`CREATE TABLE IF NOT EXISTS admin_users(
  id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE COLLATE NOCASE, name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'operatore' CHECK(role IN ('superadmin','operatore','supporto','sola_lettura')),
  key_hash TEXT NOT NULL, totp_secret TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL, last_login_at INTEGER)`,
`CREATE TABLE IF NOT EXISTS admin_sessions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, admin_id INTEGER NOT NULL REFERENCES admin_users(id),
  token_hash TEXT NOT NULL UNIQUE, ip TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER)`,
`CREATE TABLE IF NOT EXISTS admin_notes(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, admin_id INTEGER NOT NULL, body TEXT NOT NULL, created_at INTEGER NOT NULL)`,
`CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, admin_id INTEGER, action TEXT NOT NULL,
  target_table TEXT, target_id INTEGER, before TEXT, after TEXT, ip TEXT, created_at INTEGER NOT NULL)`,
`CREATE INDEX IF NOT EXISTS audit_time ON audit_log(created_at)`,
/* registro attività e contabilità: solo inserimenti */
`CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT,'audit_log append-only'); END`,
`CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log BEGIN SELECT RAISE(ABORT,'audit_log append-only'); END`,
`CREATE TRIGGER IF NOT EXISTS le_no_update BEFORE UPDATE ON ledger_entries BEGIN SELECT RAISE(ABORT,'ledger append-only'); END`,
`CREATE TRIGGER IF NOT EXISTS le_no_delete BEFORE DELETE ON ledger_entries BEGIN SELECT RAISE(ABORT,'ledger append-only'); END`,
`CREATE TRIGGER IF NOT EXISTS lt_no_update BEFORE UPDATE ON ledger_tx BEGIN SELECT RAISE(ABORT,'ledger append-only'); END`,
`CREATE TRIGGER IF NOT EXISTS lt_no_delete BEFORE DELETE ON ledger_tx BEGIN SELECT RAISE(ABORT,'ledger append-only'); END`,
/* un prelievo chiuso non cambia più stato */
`CREATE TRIGGER IF NOT EXISTS wd_final BEFORE UPDATE OF status ON withdrawals
  WHEN OLD.status IN ('eseguito','rifiutato','annullato') AND NEW.status <> OLD.status
  BEGIN SELECT RAISE(ABORT,'withdrawal closed'); END`,
];

/* parametri di gioco di default (Pool 1) — modificabili dalla console per le pool successive */
const DEFAULT_PARAMS = {
  token_usd: 0.01,
  miners: [
    { id: 0, code: 'pixel', name: 'Pixel', price_sol: 0.025, payback: 240 },
    { id: 1, code: 'bit_buddy', name: 'Bit Buddy', price_sol: 0.1, payback: 240 },
    { id: 2, code: 'nebula', name: 'Nebula', price_sol: 0.3, payback: 220 },
    { id: 3, code: 'quasar', name: 'Quasar', price_sol: 0.5, payback: 200 },
    { id: 4, code: 'pulsar', name: 'Pulsar', price_sol: 1, payback: 160 },
    { id: 5, code: 'singolarita', name: 'Singolarità', price_sol: 3, payback: 120 },
  ],
  break_from: 1.1, break_to: 1.7, repair_pct: 0.30,
  scrap_max: 0.50, scrap_min: 0.10, safety_days: 30,
  referral_pct: 0.15,
  withdraw_min_lamports: 100000000, address_lock_hours: 48,
  halving_blocks: [100000, 300000, 600000], close_blocks: 1000000,
  market_min_pct: 0.25, market_max_pct: 3.0, market_fee_pct: 0,
  tap_reward_milli: 5, energy_max: 200,
  rack_prices_token: [0, 500, 1000, 2000, 4000, 8000], max_racks: 6, slots_per_rack: 4,
  extensions: [{ days: 3, usd: 0.30 }, { days: 7, usd: 0.60 }, { days: 14, usd: 1.00 }],
  farm_window_hours: 24, ad_min_seconds: 3,
  adv_cpm_usd: { 5: 2.0, 7: 2.8, 10: 3.8 }, adv_packs: [1000, 2000, 5000, 10000], adv_discount: [0, 0.05, 0.10, 0.15],
  deposit_min_lamports: 10000000, deposit_max_lamports: 50000000000, deposit_ttl_minutes: 60,
};

const SYSTEM_ACCOUNTS = [
  ['pool_sol', 'SOL', -9000000000000000], ['pending_sol', 'SOL', -9000000000000000], ['external_sol', 'SOL', -9000000000000000],
  ['token_mint', 'TOKEN', -9000000000000000], ['token_sink', 'TOKEN', -9000000000000000],
  ['credit_mint', 'CREDIT', -9000000000000000], ['credit_sink', 'CREDIT', -9000000000000000],
];

let SCHEMA_READY = false;
const _cache = { params: null, paramsAt: 0, sys: {} };
async function ensureSchema(env) {
  if (SCHEMA_READY) return;
  const db = env.DB;
  let v = 0;
  try { const r = await db.prepare("SELECT value FROM meta WHERE key='schema_version'").first(); v = r ? +r.value : 0; } catch (e) { v = 0; }
  if (v > 0 && v < SCHEMA_VERSION) {   // database esistente: applica solo le migrazioni mancanti
    for (let n = v + 1; n <= SCHEMA_VERSION; n++) for (const sql of MIGRATIONS[n] || []) { try { await db.prepare(sql).run(); } catch (e) { if (!/duplicate column/i.test(String(e && e.message || e))) throw e; } }
    await db.prepare("INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version',?)").bind(String(SCHEMA_VERSION)).run();
  } else if (v === 0) {
    for (let i = 0; i < SCHEMA.length; i += 20) await db.batch(SCHEMA.slice(i, i + 20).map(s => db.prepare(s)));   // gruppi piccoli: tutte le istruzioni sono idempotenti
    const t = NOW();
    const seed = [];
    seed.push(db.prepare("INSERT OR IGNORE INTO param_sets(id,label,data,created_at) VALUES(1,'Lancio · Pool 1',?,?)").bind(JSON.stringify(DEFAULT_PARAMS), t));
    seed.push(db.prepare("INSERT OR IGNORE INTO pools(id,number,param_set_id,status,opened_at) VALUES(1,1,1,'attiva',?)").bind(t));
    for (const [code, asset, min] of SYSTEM_ACCOUNTS) {
      seed.push(db.prepare('INSERT OR IGNORE INTO accounts(system_code,asset,created_at) VALUES(?,?,?)').bind(code, asset, t));
      seed.push(db.prepare('INSERT OR IGNORE INTO balances(account_id,amount,min_amount) VALUES((SELECT id FROM accounts WHERE system_code=? AND asset=?),0,?)').bind(code, asset, min));
    }
    const fx = +(env.FX_FALLBACK || 130);
    seed.push(db.prepare("INSERT INTO fx_rates(sol_usd,source,reason,valid_from) SELECT ?,'iniziale','manuale',? WHERE NOT EXISTS(SELECT 1 FROM fx_rates)").bind(fx, t));
    seed.push(db.prepare("INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version',?)").bind(String(SCHEMA_VERSION)));
    await db.batch(seed);
  }
  SCHEMA_READY = true;
}

/* --- helper di accesso --- */
const nn = a => a.map(v => v === undefined ? null : v);   // D1 non accetta undefined
const dbOne = (db, sql, ...a) => db.prepare(sql).bind(...nn(a)).first();
const dbAll = async (db, sql, ...a) => (await db.prepare(sql).bind(...nn(a)).all()).results || [];
const dbRun = (db, sql, ...a) => db.prepare(sql).bind(...nn(a)).run();
const st = (db, sql, ...a) => db.prepare(sql).bind(...nn(a)); // statement per i batch
const guard = (db, key) => st(db, 'INSERT INTO guards(k,created_at) VALUES(?,?)', key, NOW());
async function runBatch(db, stmts) {
  try { return await db.batch(stmts); }
  catch (e) {
    const m = String(e && e.message || e);
    if (m.includes('amount>=min_amount') || m.includes('amount >= min_amount')) throw bad('insufficient_funds', 'Saldo insufficiente');
    if (m.includes('guards.k')) throw conflict('busy', 'Operazione già in corso, riprova');
    throw e;
  }
}

async function getParams(env, poolParamSetId) {
  const t = NOW(); const key = poolParamSetId || 'cur';
  if (_cache.params && _cache.params.key === key && t - _cache.paramsAt < 5000) return _cache.params.p;
  let row;
  if (poolParamSetId) row = await dbOne(env.DB, 'SELECT data FROM param_sets WHERE id=?', poolParamSetId);
  else row = await dbOne(env.DB, "SELECT ps.data FROM pools p JOIN param_sets ps ON ps.id=p.param_set_id WHERE p.status IN ('attiva','in_chiusura') ORDER BY p.id DESC LIMIT 1");
  const p = Object.assign({}, DEFAULT_PARAMS, row ? JSON.parse(row.data) : {});
  _cache.params = { key, p }; _cache.paramsAt = t; return p;
}
const invalidateCaches = () => { _cache.params = null; _cache.fx = null; };
async function currentPool(env) {
  return dbOne(env.DB, "SELECT * FROM pools WHERE status IN ('attiva','in_chiusura') ORDER BY id DESC LIMIT 1");
}
async function getFx(env) {
  const t = NOW();
  if (_cache.fx && t - _cache.fxAt < 5000) return _cache.fx;
  const r = await dbOne(env.DB, 'SELECT sol_usd FROM fx_rates ORDER BY id DESC LIMIT 1');
  _cache.fx = r ? +r.sol_usd : 130; _cache.fxAt = t; return _cache.fx;
}


/* ---------- 20-ledger-auth.js ---------- */
/* ============================ CONTABILITÀ (partita doppia) ============================
   Ogni movimento è una ledger_tx con voci che sommano ZERO per ciascun asset.
   I saldi stanno in balances con CHECK(amount >= min_amount): un addebito che
   scoprirebbe il conto fa fallire l'intero batch (nessun saldo negativo per gli utenti). */
async function sysAcc(db, code, asset) {
  const k = code + ':' + asset;
  if (_cache.sys[k]) return _cache.sys[k];
  const r = await dbOne(db, 'SELECT id FROM accounts WHERE system_code=? AND asset=?', code, asset);
  if (!r) throw new Error('conto di sistema mancante: ' + k);
  return (_cache.sys[k] = r.id);
}
async function userAccs(ctx, userId) {
  ctx.accs = ctx.accs || {};
  if (ctx.accs[userId]) return ctx.accs[userId];
  const rows = await dbAll(ctx.db, 'SELECT id, asset FROM accounts WHERE owner_id=?', userId);
  const m = {}; rows.forEach(r => m[r.asset] = r.id);
  if (!m.SOL) throw new Error('conti utente mancanti ' + userId);
  return (ctx.accs[userId] = m);
}
/* entries: [{acc, asset, amt}] → array di statement (da inserire in un batch insieme alle modifiche di dominio) */
function ledgerStmts(db, kind, entries, opts = {}) {
  const sums = {};
  for (const e of entries) { if (!isInt(e.amt) || e.amt === 0) throw new Error('importo non valido ' + e.amt); sums[e.asset] = (sums[e.asset] || 0) + e.amt; }
  for (const a in sums) if (sums[a] !== 0) throw new Error('transazione non bilanciata (' + a + ' ' + sums[a] + ') in ' + kind);
  const ref = opts.ref || rid(12), t = NOW();
  const out = [st(db, 'INSERT INTO ledger_tx(ref,kind,memo,idem,admin_id,created_at) VALUES(?,?,?,?,?,?)', ref, kind, opts.memo || null, opts.idem || null, opts.admin || null, t)];
  for (const e of entries) {
    out.push(st(db, 'INSERT INTO ledger_entries(tx_id,account_id,amount,created_at) VALUES((SELECT id FROM ledger_tx WHERE ref=?),?,?,?)', ref, e.acc, e.amt, t));
    out.push(st(db, 'UPDATE balances SET amount = amount + ? WHERE account_id=?', e.amt, e.acc));
  }
  return out;
}
async function balancesOf(db, userId) {
  const rows = await dbAll(db, 'SELECT a.asset, b.amount FROM accounts a JOIN balances b ON b.account_id=a.id WHERE a.owner_id=?', userId);
  const o = { SOL: 0, TOKEN: 0, CREDIT: 0 }; rows.forEach(r => o[r.asset] = r.amount); return o;
}

/* ============================ ACCESSI ============================ */
async function rateLimit(db, key, limit, windowMs) {
  const t = NOW(), w = t - (t % windowMs);
  const r = await dbOne(db, 'SELECT window_start, count FROM rate_limits WHERE k=?', key);
  if (!r || r.window_start !== w) { await dbRun(db, 'INSERT INTO rate_limits(k,window_start,count) VALUES(?,?,1) ON CONFLICT(k) DO UPDATE SET window_start=?, count=1', key, w, w); return; }
  if (r.count >= limit) throw tooMany();
  await dbRun(db, 'UPDATE rate_limits SET count=count+1 WHERE k=?', key);
}
async function turnstileCheck(ctx, token) {
  const secret = ctx.env.TURNSTILE_SECRET; if (!secret) return;
  if (!token) throw bad('captcha_required');
  const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ secret, response: token, remoteip: ctx.ip }) });
  const j = await r.json().catch(() => ({})); if (!j.success) throw bad('captcha_failed');
}
async function sendMail(env, to, subject, text, html) {
  if (env.RESEND_API_KEY) {
    const payload = { from: env.MAIL_FROM || 'DegenLand <no-reply@degenland.site>', to: [to], subject, text }; if (html) payload.html = html; if (env.MAIL_REPLY_TO) payload.reply_to = env.MAIL_REPLY_TO;
    const r = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { 'Authorization': 'Bearer ' + env.RESEND_API_KEY, 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    if (!r.ok) throw new HttpError(502, 'email_failed', 'Invio email non riuscito');
    return;
  }
  if (env.DEV_MODE === '1') { globalThis.__lastMail = { to, subject, text, html }; return; }
  throw new HttpError(503, 'email_unavailable', 'Servizio email non configurato');
}
const pepper = env => env.SESSION_SECRET || 'dev-pepper';
async function issueSession(ctx, userId) {
  const token = rid(32), t = NOW();
  await dbRun(ctx.db, 'INSERT INTO sessions(user_id,token_hash,ip,ua,created_at,expires_at) VALUES(?,?,?,?,?,?)', userId, await sha256hex(token), ctx.ip, (ctx.req.headers.get('User-Agent') || '').slice(0, 200), t, t + 30 * DAY);
  ctx.setCookie = cookieStr('dl_s', token, { maxAge: 30 * 86400 });
}
async function authUser(ctx, { required = true } = {}) {
  const tok = parseCookies(ctx.req).dl_s;
  if (!tok) { if (required) throw unauth(); return null; }
  const row = await dbOne(ctx.db, `SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id
    WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>?`, await sha256hex(tok), NOW());
  if (!row) { if (required) throw unauth(); return null; }
  if (row.status !== 'attivo') throw forbid('account_suspended', 'Account sospeso');
  ctx.user = row;
  if (!row.last_seen_at || NOW() - row.last_seen_at > 5 * MIN) dbRun(ctx.db, 'UPDATE users SET last_seen_at=? WHERE id=?', NOW(), row.id).catch(() => {});
  return row;
}
function cleanNick(s) { return String(s || '').toLowerCase().replace(/[^a-z0-9_.]/g, '').slice(0, 16); }
async function createUser(ctx, { provider, subject, display, ref, locale, accept, noPioneer }) {
  const db = ctx.db, t = NOW();
  let referrerId = null;
  if (ref) { const r = await dbOne(db, 'SELECT id FROM users WHERE referral_code=? AND status=?', String(ref).slice(0, 16), 'attivo'); if (r) referrerId = r.id; }
  if (!referrerId) { const d = await dbOne(db, 'SELECT id FROM users WHERE is_dev=1'); if (d) referrerId = d.id; }
  const params = await getParams(ctx.env);
  let pioneerNo = noPioneer ? null : await pioneerAssign(ctx);
  for (let attempt = 0; attempt < 8; attempt++) {
    const nick = 'player' + randInt(1000, 99999);   // mai derivato dall'email: l'utente sceglierà il proprio
    const code = rid(6).replace(/[^a-z0-9]/gi, '').toLowerCase().padEnd(8, 'x').slice(0, 8);
    const s = [];
    s.push(st(db, 'INSERT INTO users(nickname,referrer_id,referral_code,energy,locale,terms_at,created_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?)', nick, referrerId, code, params.energy_max, ['en','es','ru','it'].includes(locale) ? locale : 'en', accept ? t : null, t, t));
    const U = '(SELECT id FROM users WHERE referral_code=?)';
    s.push(st(db, `INSERT INTO identities(user_id,provider,subject,display,verified_at,created_at) VALUES(${U},?,?,?,?,?)`, code, provider, subject, display || null, t, t));
    for (const asset of ['SOL', 'TOKEN', 'CREDIT']) {
      s.push(st(db, `INSERT INTO accounts(owner_id,asset,created_at) VALUES(${U},?,?)`, code, asset, t));
      s.push(st(db, `INSERT INTO balances(account_id,amount,min_amount) VALUES((SELECT id FROM accounts WHERE owner_id=${U} AND asset=?),0,0)`, code, asset));
    }
    s.push(st(db, `INSERT INTO farms(user_id) VALUES(${U})`, code));
    s.push(st(db, `INSERT INTO miners(owner_id,model_id,pool_id,generation,is_welcome,special,state,rack,slot,created_at) VALUES(${U},0,NULL,0,1,?,'installato',1,1,?)`, code, pioneerNo ? 'pioneer' : null, t));
    if (pioneerNo) s.push(st(db, `INSERT INTO pioneers(no,user_id,ip_key,granted_at) VALUES(?,${U},?,?)`, pioneerNo, code, ipKey(ctx.ip), t));
    s.push(st(db, `INSERT INTO ip_events(user_id,ip,ip_key,kind,created_at) VALUES(${U},?,?,?,?)`, code, ctx.ip, ipKey(ctx.ip), 'registrazione', t));
    try { await db.batch(s); }
    catch (e) { const m = String(e.message || e); if (m.includes('pioneers.no') || m.includes('pioneers.user_id')) { pioneerNo = await pioneerAssign(ctx); continue; } if (m.includes('users.nickname') || m.includes('users.referral_code')) continue; if (m.includes('identities.provider') || m.includes('identities.subject')) throw conflict('identity_in_use'); throw e; }
    const u = await dbOne(db, 'SELECT * FROM users WHERE referral_code=?', code);
    return u;
  }
  throw new Error('impossibile creare il nickname');
}
/* Beta chiusa: con SIGNUPS_CLOSED=1 si registrano solo gli indirizzi in ALLOW_EMAILS; chi ha già un account entra sempre. */
const signupsClosed = env => ['1', 'true', 'yes', 'on', 'si', 'sì'].includes(String(env.SIGNUPS_CLOSED == null ? '' : env.SIGNUPS_CLOSED).trim().toLowerCase());   // accetta anche il tipo JSON (numero 1, true)
const emailAllowed = (env, email) => (Array.isArray(env.ALLOW_EMAILS) ? env.ALLOW_EMAILS.join(',') : String(env.ALLOW_EMAILS || '')).toLowerCase().split(/[\s,;"'\[\]]+/).filter(Boolean).includes(normEmail(email));
async function assertSignupAllowed(ctx, provider, subject) {
  if (!signupsClosed(ctx.env)) return;
  if (provider === 'email' && emailAllowed(ctx.env, subject)) return;
  throw forbid('signups_closed', 'Registrazioni chiuse');
}
async function loginOrCreate(ctx, provider, subject, display, ref, locale, accept) {
  const idn = await dbOne(ctx.db, 'SELECT user_id FROM identities WHERE provider=? AND subject=?', provider, subject);
  let user;
  if (idn) { user = await dbOne(ctx.db, 'SELECT * FROM users WHERE id=?', idn.user_id); if (user.status !== 'attivo') throw forbid('account_suspended', 'Account sospeso'); }
  else { await assertSignupAllowed(ctx, provider, subject); if (accept !== true) throw bad('terms_required', 'Devi confermare di avere almeno 18 anni e di accettare i Termini'); user = await createUser(ctx, { provider, subject, display, ref, locale, accept: true }); }
  await issueSession(ctx, user.id);
  await ipEventStmt(ctx.db, user.id, ctx.ip, 'login').run();
  return user;
}
/* --- email: codice monouso (niente password: sicuro e leggero per il piano gratuito) --- */
const CODE_MAIL = {
  en: { subject: c => `Your DegenLand code: ${c}`, intro: 'Your DegenLand sign-in code is:', expires: 'It expires in 10 minutes.', ignore: "If you didn't try to sign in, you can ignore this email." },
  es: { subject: c => `Tu código de DegenLand: ${c}`, intro: 'Tu código para entrar en DegenLand es:', expires: 'Caduca en 10 minutos.', ignore: 'Si no has intentado entrar, puedes ignorar este correo.' },
  ru: { subject: c => `Ваш код DegenLand: ${c}`, intro: 'Ваш код для входа в DegenLand:', expires: 'Действует 10 минут.', ignore: 'Если вы не пытались войти, просто проигнорируйте это письмо.' },
  it: { subject: c => `Il tuo codice DegenLand: ${c}`, intro: 'Il tuo codice per entrare in DegenLand è:', expires: 'Scade tra 10 minuti.', ignore: 'Se non hai provato ad accedere, puoi ignorare questa email.' },
};
async function emailStart(ctx, body) {
  const email = normEmail(body.email); if (!validEmail(email)) throw bad('invalid_email');
  if (signupsClosed(ctx.env) && !ctx.user && !emailAllowed(ctx.env, email) && !(await dbOne(ctx.db, "SELECT 1 x FROM identities WHERE provider='email' AND subject=?", email))) throw forbid('signups_closed', 'Registrazioni chiuse');
  await rateLimit(ctx.db, 'mail:ip:' + ctx.ip, 20, HOUR);
  await rateLimit(ctx.db, 'mail:addr:' + email, 5, HOUR);
  await turnstileCheck(ctx, body.captcha);
  const code = String(randInt(0, 999999)).padStart(6, '0');
  await dbRun(ctx.db, 'INSERT INTO auth_codes(purpose,subject,code_hash,expires_at,created_at) VALUES(?,?,?,?,?)', 'email', email, await sha256hex(code + '|' + email + '|' + pepper(ctx.env)), NOW() + 10 * MIN, NOW());
  const M = CODE_MAIL[['en', 'es', 'ru', 'it'].includes(body.locale) ? body.locale : 'en'];
  await sendMail(ctx.env, email, M.subject(code), `${M.intro}\n\n${code}\n\n${M.expires}\n${M.ignore}\n\nDegenLand · https://degenland.site`,
    `<div style="font-family:Arial,Helvetica,sans-serif;max-width:420px;margin:0 auto;padding:24px;color:#111"><h2 style="margin:0 0 14px;font-size:18px">DegenLand</h2><p style="margin:0 0 6px">${M.intro}</p><p style="font-size:32px;letter-spacing:6px;font-weight:bold;margin:14px 0">${code}</p><p style="color:#555;font-size:13px;margin:0">${M.expires}</p><hr style="border:none;border-top:1px solid #ddd;margin:20px 0"><p style="color:#777;font-size:12px;margin:0">${M.ignore}<br>degenland.site</p></div>`);
  return { sent: true };
}
async function consumeEmailCode(ctx, email, code) {
  email = normEmail(email); code = String(code || '').trim();
  if (!validEmail(email) || !/^\d{6}$/.test(code)) throw bad('invalid_code');
  const r = await dbOne(ctx.db, 'SELECT * FROM auth_codes WHERE purpose=? AND subject=? AND used_at IS NULL AND expires_at>? ORDER BY id DESC LIMIT 1', 'email', email, NOW());
  if (!r) throw bad('invalid_code');
  if (r.attempts >= 5) throw tooMany('too_many_attempts');
  if (!timingSafeEq(r.code_hash, await sha256hex(code + '|' + email + '|' + pepper(ctx.env)))) {
    await dbRun(ctx.db, 'UPDATE auth_codes SET attempts=attempts+1 WHERE id=?', r.id); throw bad('invalid_code');
  }
  const u = await dbRun(ctx.db, 'UPDATE auth_codes SET used_at=? WHERE id=? AND used_at IS NULL', NOW(), r.id);
  if (!u.meta.changes) throw bad('invalid_code');
  return email;
}
async function emailVerify(ctx, body) {
  const email = await consumeEmailCode(ctx, body.email, body.code);
  const user = await loginOrCreate(ctx, 'email', email, email.split('@')[0], body.ref, body.locale, body.accept);
  return user;
}
/* --- Telegram Login Widget --- */
async function verifyTelegram(env, d) {
  if (!env.TELEGRAM_BOT_TOKEN) throw new HttpError(503, 'telegram_unavailable');
  if (!d || !d.hash || !d.id || !d.auth_date) throw bad('invalid_telegram');
  if (NOW() / 1000 - Number(d.auth_date) > 86400) throw bad('telegram_expired');
  const fields = Object.keys(d).filter(k => k !== 'hash').sort().map(k => `${k}=${d[k]}`).join('\n');
  const secret = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(env.TELEGRAM_BOT_TOKEN)));
  const h = hex(await hmacRaw(secret, fields));
  if (!timingSafeEq(h, String(d.hash))) throw bad('invalid_telegram');
  return { id: String(d.id), username: d.username ? '@' + d.username : null, name: d.first_name || null };
}
async function telegramLogin(ctx, body) {
  const t = await verifyTelegram(ctx.env, body.data || body);
  return loginOrCreate(ctx, 'telegram', t.id, t.username ? t.username.slice(1) : (t.name || 'player'), body.ref, body.locale, body.accept);
}
async function linkIdentity(ctx, provider, subject, display) {
  try { await dbRun(ctx.db, 'INSERT INTO identities(user_id,provider,subject,display,verified_at,created_at) VALUES(?,?,?,?,?,?)', ctx.user.id, provider, subject, display || null, NOW(), NOW()); }
  catch (e) { const m = String(e.message || e); if (m.includes('UNIQUE') && m.includes('identities.user_id')) throw conflict('already_linked'); if (m.includes('UNIQUE')) throw conflict('identity_in_use'); throw e; }
}
async function identitiesOf(db, userId) {
  const rows = await dbAll(db, 'SELECT provider, subject, display, chat_ok FROM identities WHERE user_id=?', userId);
  const o = {}; rows.forEach(r => o[r.provider] = r); return o;
}


/* ---------- 40-game.js ---------- */
/* ============================ MOTORE DI GIOCO (autorevole sul server) ============================ */
const priceLamports = (p, m) => Math.round(p.miners[m].price_sol * LAMPORTS);
const tokMilli = (lam, fx, p) => Math.round(lam / LAMPORTS * fx / p.token_usd * 1000);            // lamport → millesimi di token
const priceMilli = (p, m, fx) => tokMilli(priceLamports(p, m), fx, p);
const dailyLamports = (p, m) => Math.round(priceLamports(p, m) / p.miners[m].payback);              // produzione per blocco lavorato
const minerFactor = (mi, pool) => mi.special === 'pioneer' ? 1 : mi.model_id === 0 ? Math.pow(0.5, pool.halvings)
  : (mi.pool_id === pool.id ? Math.pow(0.5, Math.max(0, pool.halvings - mi.generation)) : 0);
const rollBreak = (p, m) => Math.round(p.miners[m].payback * (p.break_from + randFloat() * (p.break_to - p.break_from)));
const tokenBalanceNeeded = (b, cost) => b.TOKEN + b.CREDIT >= cost;

async function ctxGame(ctx) { // pool, params, fx del momento
  const env = ctx.env; const pool = await currentPool(env); const p = await getParams(env, pool.param_set_id); const fx = await getFx(env);
  return { pool, p, fx };
}
async function requireOpenPool(ctx) {
  const g = await ctxGame(ctx); if (g.pool.status !== 'attiva') throw new HttpError(503, 'pool_closing', 'La pool si sta chiudendo'); return g;
}

/* ---------- accumulo della produzione (lazy) ---------- */
async function computeSettlement(ctx, userId, now) {
  const db = ctx.db;
  const farm = await dbOne(db, 'SELECT * FROM farms WHERE user_id=?', userId);
  if (!farm || farm.on_until <= farm.last_settled_at) return null;
  const hi = Math.min(now, farm.on_until), lo = farm.last_settled_at;
  if (hi <= lo) return null;
  const { pool, p, fx } = await ctxGame(ctx);
  const rows = await dbAll(db, "SELECT * FROM miners WHERE owner_id=? AND state='installato' AND broken=0 ORDER BY id", userId);
  const sim = rows.map(m => ({ id: m.id, special: m.special, model_id: m.model_id, pool_id: m.pool_id, generation: m.generation, worked: m.worked_blocks, break_at: m.break_at, broken: 0, changed: false }));
  const bts = []; if (pool.status === 'attiva') for (let k = 1; ; k++) { const bt = farm.last_block_at + k * DAY; if (bt >= farm.on_until || bt > hi) break; bts.push(bt); }
  const edges = [lo, ...bts, hi]; let prod = 0, blocks = 0, lastBlock = null;
  for (let i = 0; i < edges.length - 1; i++) {
    const a = edges[i], b = edges[i + 1];
    let rate = 0; for (const m of sim) if (!m.broken) rate += dailyLamports(p, m.model_id) * minerFactor({ model_id: m.model_id, pool_id: m.pool_id, generation: m.generation, special: m.special }, pool);
    prod += (b - a) / DAY * rate;
    if (i < bts.length) { blocks++; lastBlock = b; for (const m of sim) if (!m.broken) { m.worked++; m.changed = true; if (m.break_at != null && m.worked >= m.break_at) m.broken = 1; } }
  }
  return { farm, lo, hi, prod: Math.floor(prod), blocks, lastBlock, sim, pool, p, fx };
}
async function settle(ctx, userId, { lazy = false } = {}) {
  const now = NOW(); const c = await computeSettlement(ctx, userId, now);
  if (!c) return { produced: 0 };
  if (lazy && c.hi - c.lo < 5 * MIN && c.hi < c.farm.on_until) return { produced: 0, deferred: true };
  const db = ctx.db; const user = await dbOne(db, 'SELECT * FROM users WHERE id=?', userId);
  const accs = await userAccs(ctx, userId);
  const s = [guard(db, `settle:${userId}:${c.lo}`)];
  let produced = 0;
  if (c.prod > 0) {
    const tokenMode = user.mine_mode === 'TOKEN';
    const amt = tokenMode ? tokMilli(c.prod, c.fx, c.p) : c.prod; produced = amt;
    if (amt > 0) {
      const asset = tokenMode ? 'TOKEN' : 'SOL'; const src = await sysAcc(db, tokenMode ? 'token_mint' : 'pool_sol', asset);
      s.push(...ledgerStmts(db, 'produzione', [{ acc: src, asset, amt: -amt }, { acc: accs[asset], asset, amt }]));
      const ref = user.referrer_id ? Math.floor(amt * c.p.referral_pct) : 0;
      if (ref > 0) {
        const racc = await userAccs(ctx, user.referrer_id);
        s.push(...ledgerStmts(db, 'referral', [{ acc: src, asset, amt: -ref }, { acc: racc[asset], asset, amt: ref }]));
        s.push(st(db, 'INSERT INTO referral_earnings(referrer_id,referee_id,day,asset,amount) VALUES(?,?,?,?,?) ON CONFLICT(referrer_id,referee_id,day,asset) DO UPDATE SET amount=amount+excluded.amount', user.referrer_id, userId, dayOf(now), asset, ref));
      }
    }
  }
  for (const m of c.sim) if (m.changed) s.push(st(db, 'UPDATE miners SET worked_blocks=?, broken=? WHERE id=?', m.worked, m.broken, m.id));
  s.push(st(db, 'UPDATE farms SET last_settled_at=?, last_block_at=COALESCE(?,last_block_at), blocks_total=blocks_total+? WHERE user_id=?', c.hi, c.lastBlock, c.blocks, userId));
  if (c.blocks > 0) s.push(st(db, "UPDATE pools SET blocks=blocks+? WHERE id=? AND status='attiva'", c.blocks, c.pool.id));
  await runBatch(db, s);
  if (c.blocks > 0) await checkPoolThresholds(ctx);
  return { produced, blocks: c.blocks };
}

/* ---------- pubblicità (sessioni) ---------- */
async function adBegin(ctx, body) {
  const purpose = body.purpose; if (!['farm', 'energy'].includes(purpose)) throw bad('invalid_purpose');
  await rateLimit(ctx.db, 'ad:' + ctx.user.id, 40, HOUR);
  const p = await getParams(ctx.env); const token = rid(24);
  const c = await advPick(ctx.db); const min = Math.max(p.ad_min_seconds, c ? c.seconds : 0);
  await dbRun(ctx.db, 'INSERT INTO ad_sessions(user_id,purpose,token_hash,started_at,ip,campaign_id,min_seconds) VALUES(?,?,?,?,?,?,?)', ctx.user.id, purpose, await sha256hex(token), NOW(), ctx.ip, c ? c.id : null, min);
  return { token, min_seconds: min, ad: c ? { title: c.title, descr: c.descr || '', url: c.url, frame: !!c.frame, house: c.kind === 'house' } : null };
}
async function adCheck(ctx, token, purpose) { // verifica (senza consumare); il consumo avviene nel batch con una guard
  if (!token) throw bad('ad_required');
  const r = await dbOne(ctx.db, 'SELECT * FROM ad_sessions WHERE token_hash=?', await sha256hex(String(token)));
  if (!r || r.user_id !== ctx.user.id || r.purpose !== purpose) throw bad('ad_invalid');
  if (r.completed_at) throw bad('ad_used');
  const p = await getParams(ctx.env);
  if (NOW() - r.started_at > 15 * MIN) throw bad('ad_expired');
  if (NOW() - r.started_at < (r.min_seconds || p.ad_min_seconds) * SEC) throw bad('ad_too_early');
  return r;
}
const adConsume = (db, r) => [guard(db, 'ad:' + r.id), st(db, 'UPDATE ad_sessions SET completed_at=? WHERE id=?', NOW(), r.id),
  ...(r.campaign_id ? [st(db, "UPDATE adv_campaigns SET views_done=views_done+1, status=CASE WHEN kind='paid' AND views_done+1>=views_total THEN 'completata' ELSE status END WHERE id=?", r.campaign_id)] : [])];

/* ============================ ADVERTISE CENTER ============================
   Le campagne pagate (SOL o token) entrano a rotazione negli annunci che i giocatori guardano per
   avviare la farm o ricaricare l'energia. Una "view" conta quando l'annuncio viene guardato fino alla fine.
   Senza campagne pagate attive girano gli annunci della casa (kind='house'). */
async function advPick(db) {
  let c = await dbOne(db, "SELECT * FROM adv_campaigns WHERE status='attiva' AND kind='paid' AND views_done<views_total ORDER BY last_served_at ASC, id ASC LIMIT 1");
  if (!c) c = await dbOne(db, "SELECT * FROM adv_campaigns WHERE status='attiva' AND kind='house' ORDER BY last_served_at ASC, id ASC LIMIT 1");
  if (c) await dbRun(db, 'UPDATE adv_campaigns SET last_served_at=? WHERE id=?', NOW(), c.id);
  return c;
}
async function adClick(ctx, body) {
  const r = await dbOne(ctx.db, 'SELECT * FROM ad_sessions WHERE token_hash=?', await sha256hex(String(body.token || '')));
  if (!r || r.user_id !== ctx.user.id || !r.campaign_id) return {};
  try { await runBatch(ctx.db, [guard(ctx.db, 'adclick:' + r.id), st(ctx.db, 'UPDATE adv_campaigns SET clicks=clicks+1 WHERE id=?', r.campaign_id)]); } catch (e) { /* già contato */ }
  return {};
}
const ADV_SECONDS = [5, 7, 10];
function advQuote(p, fx, views, seconds) {
  const i = p.adv_packs.indexOf(views); if (i < 0 || !ADV_SECONDS.includes(seconds)) return null;
  const usd = Math.round(p.adv_cpm_usd[seconds] * views / 1000 * (1 - (p.adv_discount[i] || 0)) * 100) / 100;
  return { views, seconds, usd, lamports: Math.ceil(usd / fx * LAMPORTS / 1e6) * 1e6, milli: Math.round(usd / p.token_usd * 1000) };
}
async function advInfo(ctx) {
  const p = await getParams(ctx.env), fx = await getFx(ctx.env); const quotes = [];
  for (const v of p.adv_packs) for (const sec of ADV_SECONDS) { const q = advQuote(p, fx, v, sec); quotes.push({ views: v, seconds: sec, usd: q.usd, sol: solStr(q.lamports), tokens: q.milli / 1000 }); }
  ctx.cacheControl = 'public, max-age=60';
  return { packs: p.adv_packs, seconds: ADV_SECONDS, discount: p.adv_discount, sol_usd: fx, quotes, sol_enabled: !!ctx.env.TREASURY_ADDRESS };
}
const cleanText = (v, max) => String(v || '').replace(/[\u0000-\u001f\u007f<>]/g, '').replace(/\s+/g, ' ').trim().slice(0, max);
async function advRequest(ctx, body) {
  const db = ctx.db, env = ctx.env, p = await getParams(env);
  await rateLimit(db, 'adv:ip:' + ctx.ip, 6, HOUR);
  const title = cleanText(body.title, 40), descr = cleanText(body.descr, 90), contact = cleanText(body.contact, 120), wallet = cleanText(body.wallet, 64);
  if (title.length < 3) throw bad('adv_title', 'Titolo troppo corto');
  let url; try { url = new URL(String(body.url || '').trim()); } catch (e) { throw bad('adv_url', 'Indirizzo web non valido'); }
  if (!/^https?:$/.test(url.protocol) || url.href.length > 300 || !url.hostname.includes('.')) throw bad('adv_url', 'Indirizzo web non valido');
  const views = +body.views, seconds = +body.seconds, method = body.method === 'TOKEN' ? 'TOKEN' : 'SOL';
  const fx = await getFx(env); const q = advQuote(p, fx, views, seconds); if (!q) throw bad('adv_pack', 'Pacchetto non valido');
  if (wallet && !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(wallet)) throw bad('adv_wallet', 'Indirizzo Solana non valido');
  await turnstileCheck(ctx, body.captcha);
  const key = rid(16), keyHash = await sha256hex(key), t = NOW();
  const cols = 'kind,title,descr,url,seconds,views_total,pay_method,price_usd,price_lamports,price_milli,user_id,contact,payer_wallet,view_key_hash,status,ip,created_at';
  if (method === 'TOKEN') {
    await authUser(ctx, { required: false }); if (!ctx.user) throw unauth('login_required', 'Accedi al gioco per pagare con i token');
    const n = (await dbOne(db, "SELECT COUNT(*) c FROM adv_campaigns WHERE user_id=? AND status='in_attesa'", ctx.user.id)).c; if (n >= 3) throw conflict('adv_too_many', 'Hai già 3 richieste in attesa');
    const b = await balancesOf(db, ctx.user.id); if (b.TOKEN < q.milli) throw bad('insufficient_funds', 'Token insufficienti');
    await dbRun(db, `INSERT INTO adv_campaigns(${cols}) VALUES('paid',?,?,?,?,?,'TOKEN',?,NULL,?,?,?,?,?,'in_attesa',?,?)`, title, descr, url.href, seconds, views, q.usd, q.milli, ctx.user.id, contact || null, wallet || null, keyHash, ctx.ip, t);
    const r = await dbOne(db, 'SELECT id FROM adv_campaigns WHERE view_key_hash=?', keyHash);
    return { id: r.id, key, method, usd: q.usd, tokens: q.milli / 1000, nickname: ctx.user.nickname };
  }
  if (!env.TREASURY_ADDRESS) throw new HttpError(503, 'deposits_unavailable', 'Pagamenti in SOL non ancora attivi');
  if (contact.length < 3) throw bad('adv_contact', 'Inserisci un contatto');
  // importo unico: multiplo di 0,00001 SOL, così non si confonde mai con i depositi dei giocatori (che finiscono con 1-9999 lamport)
  let lam = 0;
  for (let i = 0; i < 20 && !lam; i++) { const c = q.lamports + randInt(1, 99) * 10000; if (!(await dbOne(db, "SELECT 1 x FROM adv_campaigns WHERE status='in_attesa' AND price_lamports=?", c))) lam = c; }
  if (!lam) throw conflict('busy');
  await dbRun(db, `INSERT INTO adv_campaigns(${cols}) VALUES('paid',?,?,?,?,?,'SOL',?,?,NULL,NULL,?,?,?,'in_attesa',?,?)`, title, descr, url.href, seconds, views, q.usd, lam, contact, wallet || null, keyHash, ctx.ip, t);
  const r = await dbOne(db, 'SELECT id FROM adv_campaigns WHERE view_key_hash=?', keyHash);
  return { id: r.id, key, method, usd: q.usd, lamports: lam, sol: solStr(lam), address: env.TREASURY_ADDRESS, uri: `solana:${env.TREASURY_ADDRESS}?amount=${solStr(lam)}&label=DegenLand%20Ads` };
}
async function advStatus(ctx, url) {
  const id = +url.searchParams.get('id'), key = String(url.searchParams.get('k') || '');
  const c = isInt(id) ? await dbOne(ctx.db, 'SELECT * FROM adv_campaigns WHERE id=? AND kind=\'paid\'', id) : null;
  if (!c || !key || !timingSafeEq(c.view_key_hash || '', await sha256hex(key))) throw notfound('adv_not_found', 'Campagna non trovata');
  ctx.cacheControl = 'no-store';
  return { campaign: { id: c.id, title: c.title, descr: c.descr, url: c.url, seconds: c.seconds, views_total: c.views_total, views_done: c.views_done, clicks: c.clicks, status: c.status, method: c.pay_method, usd: c.price_usd,
    sol: c.price_lamports ? solStr(c.price_lamports) : null, tokens: c.price_milli ? c.price_milli / 1000 : null, address: c.pay_method === 'SOL' && c.status === 'in_attesa' ? ctx.env.TREASURY_ADDRESS : null, reject_reason: c.reject_reason, created_at: c.created_at } };
}
/* --- console --- */
async function advPaymentSeen(db, c) {
  if (c.pay_method !== 'SOL' || !c.price_lamports) return null;
  return dbOne(db, "SELECT id, signature, sender, detected_at FROM deposits WHERE lamports=? AND status='non_abbinato' AND detected_at>=? ORDER BY id LIMIT 1", c.price_lamports, c.created_at - 10 * MIN);
}
async function adminAdvList(ctx, url) {
  const db = ctx.db, f = url.searchParams.get('status') || 'in_attesa';
  const where = f === 'house' ? "c.kind='house'" : f === 'tutte' ? "c.kind='paid'" : "c.kind='paid' AND c.status=?";
  const rows = await dbAll(db, `SELECT c.*, u.nickname FROM adv_campaigns c LEFT JOIN users u ON u.id=c.user_id WHERE ${where} ORDER BY c.id DESC LIMIT 200`, ...(f === 'house' || f === 'tutte' ? [] : [f]));
  for (const r of rows) { delete r.view_key_hash; delete r.ip; if (r.status === 'in_attesa') r.payment = await advPaymentSeen(db, r); r.sol = r.price_lamports ? solStr(r.price_lamports) : null; r.tokens = r.price_milli ? r.price_milli / 1000 : null; }
  const counts = Object.fromEntries((await dbAll(db, "SELECT status, COUNT(*) n FROM adv_campaigns WHERE kind='paid' GROUP BY status")).map(r => [r.status, r.n]));
  return { campaigns: rows, counts, treasury: ctx.env.TREASURY_ADDRESS || null };
}
async function adminAdvApprove(ctx, id, body) {
  const db = ctx.db, a = ctx.admin, c = await dbOne(db, "SELECT * FROM adv_campaigns WHERE id=? AND status='in_attesa' AND kind='paid'", id); if (!c) throw notfound('adv_not_found', 'Richiesta non in attesa');
  const t = NOW(), frame = body.frame ? 1 : 0; const s = [guard(db, 'adv:' + id)];
  if (c.pay_method === 'SOL') {
    const dep = await advPaymentSeen(db, c); const tx = String(body.tx || '').trim().slice(0, 120) || (dep && dep.signature) || null;
    if (!dep && !body.confirm) throw bad('adv_unpaid', 'Pagamento non trovato: verifica a mano e conferma');
    if (dep) s.push(st(db, "UPDATE deposits SET status='scartato', note=? WHERE id=? AND status='non_abbinato'", 'pubblicità #' + id, dep.id));
    const ext = await sysAcc(db, 'external_sol', 'SOL'), pool = await sysAcc(db, 'pool_sol', 'SOL');
    s.push(st(db, 'INSERT INTO treasury_movements(kind,lamports,tx_signature,admin_id,note,created_at) VALUES(?,?,?,?,?,?)', 'ricavi_extra', c.price_lamports, tx, a.id, 'Advertise Center #' + id, t));
    s.push(...ledgerStmts(db, 'pubblicita_sol', [{ acc: ext, asset: 'SOL', amt: -c.price_lamports }, { acc: pool, asset: 'SOL', amt: c.price_lamports }], { admin: a.id, memo: 'Advertise Center #' + id }));
    s.push(st(db, "UPDATE adv_campaigns SET status='attiva', frame=?, tx_signature=?, decided_at=?, decided_by=? WHERE id=? AND status='in_attesa'", frame, tx, t, a.id, id));
  } else {
    const accs = await userAccs(ctx, c.user_id), tsink = await sysAcc(db, 'token_sink', 'TOKEN');
    s.push(...ledgerStmts(db, 'pubblicita_token', [{ acc: accs.TOKEN, asset: 'TOKEN', amt: -c.price_milli }, { acc: tsink, asset: 'TOKEN', amt: c.price_milli }], { admin: a.id, memo: 'Advertise Center #' + id }));
    s.push(st(db, "UPDATE adv_campaigns SET status='attiva', frame=?, decided_at=?, decided_by=? WHERE id=? AND status='in_attesa'", frame, t, a.id, id));
  }
  s.push(auditStmt(db, a.id, 'approva_pubblicita', 'adv_campaigns', id, { status: 'in_attesa' }, { status: 'attiva', method: c.pay_method }, ctx.ip));
  await runBatch(db, s); invalidateCaches(); return {};
}
async function adminAdvReject(ctx, id, body) {
  const db = ctx.db, reason = cleanText(body.reason, 200); if (reason.length < 3) throw bad('reason_required', 'Indica il motivo');
  const c = await dbOne(db, "SELECT * FROM adv_campaigns WHERE id=? AND status='in_attesa' AND kind='paid'", id); if (!c) throw notfound('adv_not_found', 'Richiesta non in attesa');
  await runBatch(db, [guard(db, 'adv:' + id), st(db, "UPDATE adv_campaigns SET status='rifiutata', reject_reason=?, decided_at=?, decided_by=? WHERE id=? AND status='in_attesa'", reason, NOW(), ctx.admin.id, id),
    auditStmt(db, ctx.admin.id, 'rifiuta_pubblicita', 'adv_campaigns', id, { status: 'in_attesa' }, { status: 'rifiutata', reason }, ctx.ip)]);
  return {};
}
async function adminAdvSet(ctx, id, body) {
  const db = ctx.db, c = await dbOne(db, 'SELECT * FROM adv_campaigns WHERE id=?', id); if (!c) throw notfound('adv_not_found');
  const act = body.action; let sql;
  if (act === 'pause' && c.status === 'attiva') sql = "UPDATE adv_campaigns SET status='in_pausa' WHERE id=?";
  else if (act === 'resume' && c.status === 'in_pausa') sql = "UPDATE adv_campaigns SET status='attiva' WHERE id=?";
  else if (act === 'frame_on' || act === 'frame_off') sql = `UPDATE adv_campaigns SET frame=${act === 'frame_on' ? 1 : 0} WHERE id=?`;
  else throw bad('invalid_action');
  await db.batch([st(db, sql, id), auditStmt(db, ctx.admin.id, 'pubblicita_' + act, 'adv_campaigns', id, { status: c.status }, null, ctx.ip)]);
  return {};
}

/* ---------- avvio della farm ---------- */
function windowStmts(db, ctxUser, farm, pool, source, extra = {}) {
  const now = NOW(), s = [];
  s.push(guard(db, `fstart:${ctxUser.id}:${farm.on_until}:${farm.last_block_at}`));
  const video = extra.video_until != null ? extra.video_until : farm.video_until;
  const ext = extra.ext_until != null ? extra.ext_until : farm.ext_until;
  s.push(st(db, 'UPDATE farms SET video_until=?, ext_until=?, on_until=?, last_block_at=?, last_settled_at=?, blocks_total=blocks_total+1 WHERE user_id=?', video, ext, Math.max(video, ext), now, now, ctxUser.id));
  s.push(st(db, 'INSERT INTO farm_starts(user_id,pool_id,source,pool_block_no,created_at) VALUES(?,?,?,?,?)', ctxUser.id, pool.id, source, pool.blocks + 1, now));
  s.push(st(db, "UPDATE pools SET blocks=blocks+1 WHERE id=? AND status='attiva'", pool.id));
  s.push(st(db, "UPDATE miners SET worked_blocks=worked_blocks+1, broken=CASE WHEN break_at IS NOT NULL AND worked_blocks+1>=break_at THEN 1 ELSE 0 END WHERE owner_id=? AND state='installato' AND broken=0", ctxUser.id));
  return s;
}
async function farmStart(ctx, body) {
  const { pool, p } = await requireOpenPool(ctx); const u = ctx.user, db = ctx.db;
  const ad = await adCheck(ctx, body.token, 'farm');
  await settle(ctx, u.id, { lazy: false });
  const farm = await dbOne(db, 'SELECT * FROM farms WHERE user_id=?', u.id);
  const now = NOW(); if (now < farm.on_until) throw conflict('already_on', 'La farm è già accesa');
  const s = [...adConsume(db, ad), ...windowStmts(db, u, farm, pool, 'video', { video_until: now + p.farm_window_hours * HOUR })];
  s.push(st(db, 'UPDATE users SET energy=? WHERE id=?', p.energy_max, u.id));
  await runBatch(db, s); await checkPoolThresholds(ctx);
  return { started: true };
}

/* ---------- estrazione a tocco ---------- */
async function tap(ctx, body) {
  const db = ctx.db; const p = await getParams(ctx.env); const n = clamp(Math.floor(+body.n || 0), 1, 25);
  const u = await dbOne(db, 'SELECT * FROM users WHERE id=?', ctx.user.id); const now = NOW();
  const dt = u.last_tap_at ? (now - u.last_tap_at) / 1000 : 30;
  const taps = Math.min(n, u.energy, Math.floor(dt * 12) + 10);
  if (taps <= 0) return { taps: 0, energy: u.energy, reward_milli: 0 };
  const reward = taps * p.tap_reward_milli; const accs = await userAccs(ctx, u.id); const mint = await sysAcc(db, 'token_mint', 'TOKEN');
  await runBatch(db, [guard(db, `tap:${u.id}:${u.taps_total}`), st(db, 'UPDATE users SET energy=energy-?, last_tap_at=?, taps_total=taps_total+? WHERE id=?', taps, now, taps, u.id),
    ...ledgerStmts(db, 'tap', [{ acc: mint, asset: 'TOKEN', amt: -reward }, { acc: accs.TOKEN, asset: 'TOKEN', amt: reward }])]);
  return { taps, energy: u.energy - taps, reward_milli: reward };
}
async function energyRecharge(ctx, body) {
  const db = ctx.db, p = await getParams(ctx.env); const ad = await adCheck(ctx, body.token, 'energy');
  await runBatch(db, [...adConsume(db, ad), st(db, 'UPDATE users SET energy=? WHERE id=?', p.energy_max, ctx.user.id)]);
  return { energy: p.energy_max };
}
async function setMode(ctx, body) {
  const mode = body.mode; if (!['SOL', 'TOKEN'].includes(mode)) throw bad('invalid_mode');
  await settle(ctx, ctx.user.id); await dbRun(ctx.db, 'UPDATE users SET mine_mode=? WHERE id=?', mode, ctx.user.id); return { mode };
}

/* ---------- slot e acquisti ---------- */
async function freeSlot(ctx, userId, racks, p) {
  const occ = new Set((await dbAll(ctx.db, "SELECT rack, slot FROM miners WHERE owner_id=? AND state='installato'", userId)).map(r => r.rack + ':' + r.slot));
  for (let r = 1; r <= racks; r++) for (let s = 1; s <= p.slots_per_rack; s++) if (!occ.has(r + ':' + s)) return { rack: r, slot: s };
  return null;
}
async function buyMiner(ctx, body) {
  const { pool, p, fx } = await requireOpenPool(ctx); const db = ctx.db, u = ctx.user;
  const model = body.model; if (!isInt(model) || model < 0 || model >= p.miners.length) throw bad('invalid_model');
  await settle(ctx, u.id);
  const price = priceMilli(p, model, fx); const b = await balancesOf(db, u.id); const useCredit = Math.min(b.CREDIT, price), useTok = price - useCredit;
  if (b.TOKEN < useTok) throw bad('insufficient_funds', 'Token insufficienti');
  const accs = await userAccs(ctx, u.id); const tsink = await sysAcc(db, 'token_sink', 'TOKEN'), csink = await sysAcc(db, 'credit_sink', 'CREDIT');
  const fresh = await dbOne(db, 'SELECT racks FROM users WHERE id=?', u.id);
  for (let attempt = 0; attempt < 3; attempt++) {
    const slot = await freeSlot(ctx, u.id, fresh.racks, p); const t = NOW();
    const s = [];
    if (useCredit > 0) s.push(...ledgerStmts(db, 'acquisto_miner', [{ acc: accs.CREDIT, asset: 'CREDIT', amt: -useCredit }, { acc: csink, asset: 'CREDIT', amt: useCredit }]));
    if (useTok > 0) s.push(...ledgerStmts(db, 'acquisto_miner', [{ acc: accs.TOKEN, asset: 'TOKEN', amt: -useTok }, { acc: tsink, asset: 'TOKEN', amt: useTok }]));
    s.push(st(db, 'INSERT INTO miners(owner_id,model_id,pool_id,generation,state,rack,slot,break_at,paid_milli,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)',
      u.id, model, model === 0 ? null : pool.id, pool.halvings, slot ? 'installato' : 'magazzino', slot ? slot.rack : null, slot ? slot.slot : null, model === 0 ? null : rollBreak(p, model), price, t));
    try { await runBatch(db, s); return { model, price_milli: price, installed: !!slot }; }
    catch (e) { if (String(e.message).includes('miner_slot') || String(e.message).includes('miners.owner_id')) continue; throw e; }
  }
  throw conflict('busy');
}
async function buyRack(ctx) {
  const { p } = await requireOpenPool(ctx); const db = ctx.db, u = await dbOne(ctx.db, 'SELECT * FROM users WHERE id=?', ctx.user.id);
  if (u.racks >= p.max_racks) throw bad('max_racks');
  const price = p.rack_prices_token[u.racks] * 1000; const b = await balancesOf(db, u.id); if (b.TOKEN < price) throw bad('insufficient_funds');
  const accs = await userAccs(ctx, u.id); const tsink = await sysAcc(db, 'token_sink', 'TOKEN');
  await runBatch(db, [guard(db, `rack:${u.id}:${u.racks}`), st(db, 'UPDATE users SET racks=racks+1 WHERE id=?', u.id),
    ...ledgerStmts(db, 'acquisto_rack', [{ acc: accs.TOKEN, asset: 'TOKEN', amt: -price }, { acc: tsink, asset: 'TOKEN', amt: price }])]);
  return { racks: u.racks + 1 };
}
async function buyExtension(ctx, body) {
  const { pool, p } = await requireOpenPool(ctx); const db = ctx.db, u = ctx.user;
  const ex = p.extensions.find(e => e.days === body.days); if (!ex) throw bad('invalid_extension');
  const price = Math.round(ex.usd / p.token_usd * 1000);
  await settle(ctx, u.id);
  const farm = await dbOne(db, 'SELECT * FROM farms WHERE user_id=?', u.id); const now = NOW();
  const accs = await userAccs(ctx, u.id); const tsink = await sysAcc(db, 'token_sink', 'TOKEN');
  const newExt = Math.max(now, farm.ext_until) + ex.days * DAY;
  const s = [...ledgerStmts(db, 'acquisto_estensione', [{ acc: accs.TOKEN, asset: 'TOKEN', amt: -price }, { acc: tsink, asset: 'TOKEN', amt: price }]),
    st(db, 'INSERT INTO extensions(user_id,days,price_milli,starts_at,ends_at,created_at) VALUES(?,?,?,?,?,?)', u.id, ex.days, price, now, newExt, now)];
  if (now < farm.on_until) { s.push(guard(db, `ext:${u.id}:${farm.ext_until}:${farm.on_until}`), st(db, 'UPDATE farms SET ext_until=?, on_until=? WHERE user_id=?', newExt, Math.max(farm.video_until, newExt), u.id)); }
  else s.push(...windowStmts(db, u, farm, pool, 'estensione', { ext_until: newExt }));
  await runBatch(db, s); await checkPoolThresholds(ctx);
  return { ext_until: newExt };
}
async function ownMiner(ctx, id) {
  const m = await dbOne(ctx.db, 'SELECT * FROM miners WHERE id=? AND owner_id=?', id, ctx.user.id);
  if (!m || m.state === 'rottamato') throw notfound('miner_not_found'); return m;
}
async function installMiner(ctx, body) {
  const m = await ownMiner(ctx, body.miner_id); const p = await getParams(ctx.env); const u = await dbOne(ctx.db, 'SELECT racks FROM users WHERE id=?', ctx.user.id);
  const rack = body.rack, slot = body.slot;
  if (!isInt(rack) || !isInt(slot) || rack < 1 || rack > u.racks || slot < 1 || slot > p.slots_per_rack) throw bad('invalid_slot');
  if (m.state !== 'magazzino') throw bad('miner_not_in_storage');
  await settle(ctx, ctx.user.id);
  try { await runBatch(ctx.db, [guard(ctx.db, `inst:${m.id}:${m.state}`), st(ctx.db, "UPDATE miners SET state='installato', rack=?, slot=? WHERE id=? AND state='magazzino'", rack, slot, m.id)]); }
  catch (e) { if (String(e.message).includes('miner_slot') || String(e.message).includes('miners.owner_id')) throw conflict('slot_taken'); throw e; }
  return { ok: true };
}
async function uninstallMiner(ctx, body) {
  const m = await ownMiner(ctx, body.miner_id); if (m.state !== 'installato') throw bad('miner_not_installed');
  await settle(ctx, ctx.user.id);
  await runBatch(ctx.db, [guard(ctx.db, `uninst:${m.id}:${m.rack}:${m.slot}`), st(ctx.db, "UPDATE miners SET state='magazzino', rack=NULL, slot=NULL WHERE id=? AND state='installato'", m.id)]);
  return { ok: true };
}
async function repairMiner(ctx, body) {
  const { p, fx } = await requireOpenPool(ctx); const m = await ownMiner(ctx, body.miner_id); const db = ctx.db;
  await settle(ctx, ctx.user.id); const fresh = await dbOne(db, 'SELECT * FROM miners WHERE id=?', m.id);
  if (fresh.model_id === 0 || !fresh.broken) throw bad('not_broken');
  const cost = Math.round(priceMilli(p, fresh.model_id, fx) * p.repair_pct); const accs = await userAccs(ctx, ctx.user.id); const tsink = await sysAcc(db, 'token_sink', 'TOKEN');
  await runBatch(db, [guard(db, `rep:${m.id}:${fresh.worked_blocks}`), st(db, 'UPDATE miners SET worked_blocks=0, broken=0, break_at=? WHERE id=?', rollBreak(p, fresh.model_id), m.id),
    ...ledgerStmts(db, 'riparazione', [{ acc: accs.TOKEN, asset: 'TOKEN', amt: -cost }, { acc: tsink, asset: 'TOKEN', amt: cost }]),
    st(db, 'INSERT INTO miner_events(miner_id,kind,actor_id,details,created_at) VALUES(?,?,?,?,?)', m.id, 'riparazione', ctx.user.id, JSON.stringify({ cost }), NOW())]);
  return { cost_milli: cost };
}
async function convertSol(ctx, body) {
  const db = ctx.db, { p, fx } = await ctxGame(ctx); await settle(ctx, ctx.user.id);
  const b = await balancesOf(db, ctx.user.id); const lam = body.all ? b.SOL : Math.floor(+body.lamports || 0);
  if (!isInt(lam) || lam <= 0) throw bad('invalid_amount'); if (lam > b.SOL) throw bad('insufficient_funds');
  const tokens = tokMilli(lam, fx, p); if (tokens <= 0) throw bad('amount_too_small');
  const accs = await userAccs(ctx, ctx.user.id); const pool = await sysAcc(db, 'pool_sol', 'SOL'), mint = await sysAcc(db, 'token_mint', 'TOKEN');
  await runBatch(db, ledgerStmts(db, 'conversione_saldo', [{ acc: accs.SOL, asset: 'SOL', amt: -lam }, { acc: pool, asset: 'SOL', amt: lam }, { acc: mint, asset: 'TOKEN', amt: -tokens }, { acc: accs.TOKEN, asset: 'TOKEN', amt: tokens }]));
  return { lamports: lam, token_milli: tokens };
}

/* ---------- mercato tra giocatori ---------- */
async function marketList(ctx, body) {
  const { p, fx } = await requireOpenPool(ctx); const m = await ownMiner(ctx, body.miner_id); const db = ctx.db;
  if (m.special) throw bad('not_tradable', 'Questo miner non si può vendere');
  if (m.state !== 'magazzino') throw bad('miner_not_in_storage', 'Il miner deve essere in magazzino');
  const base = priceMilli(p, m.model_id, fx), lo = Math.ceil(base * p.market_min_pct), hi = Math.floor(base * p.market_max_pct); const price = Math.round(+body.price_milli);
  if (!isInt(price) || price < lo || price > hi) throw bad('price_out_of_range', `Prezzo tra ${lo} e ${hi}`);
  try { await runBatch(db, [guard(db, `list:${m.id}:${m.state}`), st(db, "UPDATE miners SET state='in_vendita' WHERE id=? AND state='magazzino'", m.id),
    st(db, "INSERT INTO market_listings(miner_id,seller_id,price_milli,status,created_at) VALUES(?,?,?,'attivo',?)", m.id, ctx.user.id, price, NOW())]); }
  catch (e) { if (String(e.message).includes('one_listing') || String(e.message).includes('market_listings.miner_id')) throw conflict('already_listed'); throw e; }
  return { ok: true };
}
async function marketCancel(ctx, body) {
  const l = await dbOne(ctx.db, "SELECT * FROM market_listings WHERE id=? AND seller_id=? AND status='attivo'", body.listing_id, ctx.user.id); if (!l) throw notfound('listing_not_found');
  await runBatch(ctx.db, [guard(ctx.db, 'listing:' + l.id), st(ctx.db, "UPDATE market_listings SET status='ritirato', closed_at=? WHERE id=?", NOW(), l.id),
    st(ctx.db, "UPDATE miners SET state='magazzino' WHERE id=? AND state='in_vendita'", l.miner_id)]);
  return { ok: true };
}
async function marketBuy(ctx, body) {
  const { p } = await requireOpenPool(ctx); const db = ctx.db, u = ctx.user;
  const l = await dbOne(db, "SELECT * FROM market_listings WHERE id=? AND status='attivo'", body.listing_id); if (!l) throw notfound('listing_not_found');
  if (l.seller_id === u.id) throw bad('own_listing'); await settle(ctx, u.id); const m = await dbOne(db, 'SELECT * FROM miners WHERE id=?', l.miner_id);
  const fee = Math.floor(l.price_milli * p.market_fee_pct); const b = await balancesOf(db, u.id); if (b.TOKEN < l.price_milli) throw bad('insufficient_funds', 'Token insufficienti');
  const fresh = await dbOne(db, 'SELECT racks FROM users WHERE id=?', u.id); const slot = await freeSlot(ctx, u.id, fresh.racks, p);
  const ba = await userAccs(ctx, u.id), sa = await userAccs(ctx, l.seller_id), tsink = await sysAcc(db, 'token_sink', 'TOKEN'); const t = NOW();
  const entries = [{ acc: ba.TOKEN, asset: 'TOKEN', amt: -l.price_milli }, { acc: sa.TOKEN, asset: 'TOKEN', amt: l.price_milli - fee }]; if (fee > 0) entries.push({ acc: tsink, asset: 'TOKEN', amt: fee });
  await runBatch(db, [guard(db, 'listing:' + l.id), st(db, 'INSERT INTO market_sales(listing_id,buyer_id,price_milli,created_at) VALUES(?,?,?,?)', l.id, u.id, l.price_milli, t),
    st(db, "UPDATE market_listings SET status='venduto', buyer_id=?, closed_at=? WHERE id=?", u.id, t, l.id),
    st(db, "UPDATE miners SET owner_id=?, state=?, rack=?, slot=?, paid_milli=? WHERE id=? AND state='in_vendita'", u.id, slot ? 'installato' : 'magazzino', slot ? slot.rack : null, slot ? slot.slot : null, l.price_milli, m.id),
    st(db, 'INSERT INTO miner_events(miner_id,kind,actor_id,details,created_at) VALUES(?,?,?,?,?)', m.id, 'vendita', u.id, JSON.stringify({ from: l.seller_id, price: l.price_milli }), t),
    ...ledgerStmts(db, 'vendita_mercato', entries)]);
  return { ok: true, installed: !!slot };
}


/* ---------- 50-pool.js ---------- */
/* ============================ POOL, HALVING, STAGIONI ============================ */
async function poolHealth(env, pool, p) {
  const db = env.DB; const t = NOW();
  const poolAcc = await sysAcc(db, 'pool_sol', 'SOL'), pendAcc = await sysAcc(db, 'pending_sol', 'SOL');
  const poolLam = (await dbOne(db, 'SELECT amount FROM balances WHERE account_id=?', poolAcc)).amount;
  const pending = (await dbOne(db, 'SELECT amount FROM balances WHERE account_id=?', pendAcc)).amount;
  const users = (await dbOne(db, "SELECT COALESCE(SUM(b.amount),0) s FROM balances b JOIN accounts a ON a.id=b.account_id WHERE a.owner_id IS NOT NULL AND a.asset='SOL'")).s;
  const prod30 = (await dbOne(db, `SELECT COALESCE(SUM(e.amount),0) s FROM ledger_entries e JOIN ledger_tx x ON x.id=e.tx_id JOIN accounts a ON a.id=e.account_id
    WHERE x.kind IN ('produzione','referral') AND a.asset='SOL' AND a.owner_id IS NOT NULL AND e.amount>0 AND x.created_at>?`, t - p.safety_days * DAY)).s;
  const threshold = users + pending + prod30;
  const coverage = threshold <= 0 ? 99 : Math.max(0, poolLam) / threshold;
  const rate = coverage >= 2 ? p.scrap_max : coverage <= 1 ? p.scrap_min : p.scrap_min + (p.scrap_max - p.scrap_min) * (coverage - 1);
  return { pool_lamports: poolLam, users_lamports: users, pending_lamports: pending, prod30, threshold, coverage, scrap_pct: rate };
}
async function checkPoolThresholds(ctx) {
  const env = ctx.env, db = env.DB; const pool = await currentPool(env);
  if (!pool || pool.status !== 'attiva') return;
  const p = await getParams(env, pool.param_set_id); const t = NOW();
  const h = p.halving_blocks.filter(x => pool.blocks >= x).length;
  if (h > pool.halvings) {
    const s = [st(db, 'UPDATE pools SET halvings=? WHERE id=? AND halvings<?', h, pool.id, h)];
    for (let i = pool.halvings + 1; i <= h; i++) s.push(st(db, "INSERT INTO pool_events(pool_id,kind,at_blocks,generation,created_at) SELECT ?,'halving',?,?,? WHERE NOT EXISTS(SELECT 1 FROM pool_events WHERE pool_id=? AND kind='halving' AND generation=?)", pool.id, p.halving_blocks[i - 1], i, t, pool.id, i));
    await db.batch(s); invalidateCaches();
  }
  if (pool.blocks >= p.close_blocks) {
    const hl = await poolHealth(env, pool, p);
    await db.batch([st(db, "UPDATE pools SET status='in_chiusura', scrap_pct=? WHERE id=? AND status='attiva'", hl.scrap_pct, pool.id),
      st(db, "INSERT INTO pool_events(pool_id,kind,at_blocks,details,created_at) SELECT ?,'chiusura',?,?,? WHERE NOT EXISTS(SELECT 1 FROM pool_events WHERE pool_id=? AND kind='chiusura')", pool.id, pool.blocks, JSON.stringify(hl), t, pool.id)]);
    invalidateCaches();
  }
}
/* chiusura a blocchi: rottamazione dei miner della pool → credito (CREDIT) sul prezzo pagato */
async function processClosing(ctx, limit = 25) {
  const env = ctx.env, db = env.DB; const pool = await currentPool(env);
  if (!pool || pool.status !== 'in_chiusura') return { done: true };
  const rows = await dbAll(db, "SELECT * FROM miners WHERE pool_id=? AND model_id<>0 AND state IN ('magazzino','installato','in_vendita') ORDER BY id LIMIT ?", pool.id, limit);
  const t = NOW(), rate = pool.scrap_pct;
  if (rows.length) {
    const byOwner = {}; rows.forEach(m => (byOwner[m.owner_id] = byOwner[m.owner_id] || []).push(m));
    const credit = await sysAcc(db, 'credit_mint', 'CREDIT'); const s = [];
    for (const owner in byOwner) {
      const ms = byOwner[owner]; const accs = await userAccs(ctx, +owner);
      const total = ms.reduce((a, m) => a + Math.floor(m.paid_milli * rate), 0);
      for (const m of ms) {
        s.push(st(db, "UPDATE market_listings SET status='ritirato', closed_at=? WHERE miner_id=? AND status='attivo'", t, m.id));
        s.push(st(db, "UPDATE miners SET state='rottamato', rack=NULL, slot=NULL WHERE id=?", m.id));
        s.push(st(db, 'INSERT INTO miner_events(miner_id,kind,details,created_at) VALUES(?,?,?,?)', m.id, 'rottamazione', JSON.stringify({ pool: pool.id, rate }), t));
      }
      if (total > 0) s.push(...ledgerStmts(db, 'rottamazione', [{ acc: credit, asset: 'CREDIT', amt: -total }, { acc: accs.CREDIT, asset: 'CREDIT', amt: total }]));
      s.push(st(db, 'INSERT INTO scrap_credits(user_id,pool_id,miners,scrap_pct,credit_milli,created_at) VALUES(?,?,?,?,?,?) ON CONFLICT(user_id,pool_id) DO UPDATE SET miners=miners+excluded.miners, credit_milli=credit_milli+excluded.credit_milli', +owner, pool.id, ms.length, rate, total, t));
    }
    await db.batch(s);
    if (rows.length === limit) return { done: false, processed: rows.length };
  }
  await openNextPool(ctx, pool); return { done: true, processed: rows.length };
}
async function openNextPool(ctx, pool) {
  const db = ctx.db, t = NOW();
  const nextSet = await dbOne(db, "SELECT value FROM meta WHERE key='next_param_set'");
  const latest = await dbOne(db, 'SELECT MAX(id) id FROM param_sets');
  const setId = nextSet ? +nextSet.value : latest.id;
  await db.batch([st(db, "UPDATE pools SET status='chiusa', closed_at=? WHERE id=? AND status='in_chiusura'", t, pool.id),
    st(db, "INSERT INTO pools(number,param_set_id,status,opened_at) VALUES(?,?,'attiva',?)", pool.number + 1, setId, t),
    st(db, "INSERT INTO pool_events(pool_id,kind,at_blocks,created_at) VALUES((SELECT id FROM pools WHERE number=?),'apertura',0,?)", pool.number + 1, t),
    st(db, "DELETE FROM meta WHERE key='next_param_set'")]);
  invalidateCaches();
}

/* ============================ CAMBIO SOL/USD ============================ */
async function fetchSolUsd(env) {
  if (env.FX_FIXED) return { usd: +env.FX_FIXED, source: 'fisso' };
  try { // Pyth Hermes (feed SOL/USD)
    const r = await fetch('https://hermes.pyth.network/v2/updates/price/latest?ids[]=0xef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d&parsed=true');
    const j = await r.json(); const pp = j.parsed[0].price; const usd = Number(pp.price) * Math.pow(10, pp.expo);
    if (usd > 1 && usd < 10000) return { usd, source: 'pyth' };
  } catch (e) { /* prova la seconda fonte */ }
  try {
    const r = await fetch('https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd'); const j = await r.json();
    if (j.solana && j.solana.usd > 1) return { usd: j.solana.usd, source: 'coingecko' };
  } catch (e) { /* nessuna fonte */ }
  return null;
}
async function fxTick(env, force = false) {
  const db = env.DB; const last = await dbOne(db, 'SELECT * FROM fx_rates ORDER BY id DESC LIMIT 1'); const t = NOW();
  if (!force && last && t - last.valid_from < HOUR) return;
  const f = await fetchSolUsd(env); if (!f) return;
  const move = Math.abs(f.usd / last.sol_usd - 1); const p = await getParams(env);
  const reason = move * 100 > 10 ? 'anticipato' : (t - last.valid_from >= DAY ? 'giornaliero' : null);
  if (!reason && !force) return;
  await dbRun(db, 'INSERT INTO fx_rates(sol_usd,source,reason,valid_from) VALUES(?,?,?,?)', f.usd, f.source, force ? 'manuale' : reason, t); invalidateCaches();
}

/* ============================ LAVORI PERIODICI (a richiesta) ============================ */
async function snapshotTick(env) {
  const db = env.DB, day = dayOf(NOW()); const has = await dbOne(db, 'SELECT day FROM treasury_snapshots WHERE day=?', day); if (has) return;
  const pool = await currentPool(env); const p = await getParams(env, pool.param_set_id); const h = await poolHealth(env, pool, p);
  const farms = (await dbOne(db, 'SELECT COUNT(*) c FROM farms WHERE on_until>?', NOW())).c;
  await dbRun(db, 'INSERT OR IGNORE INTO treasury_snapshots(day,pool_lamports,pending_lamports,queued_lamports,prod30,coverage,scrap_pct,active_farms,blocks) VALUES(?,?,?,?,?,?,?,?,?)', day, h.pool_lamports, h.users_lamports, h.pending_lamports, h.prod30, h.coverage, h.scrap_pct, farms, pool.blocks);
}
async function tick(ctx) {
  const t = NOW(); if (_cache.lastTick && t - _cache.lastTick < 30000) return; _cache.lastTick = t;
  const env = ctx.env;
  const jobs = [fxTick(env), processClosing(ctx), snapshotTick(env), flushNotifications(env, 5), checkDeposits(env), dbRun(env.DB, 'DELETE FROM guards WHERE created_at<?', t - 2 * DAY), dbRun(env.DB, 'DELETE FROM rate_limits WHERE window_start<?', t - 2 * DAY)];
  for (const j of jobs) { try { await j; } catch (e) { console.error('tick job', e && e.message); } }
}


/* ---------- 60-money.js ---------- */
/* ============================ DEPOSITI (SOL → token) ============================
   Metodo "importo unico": l'utente invia un importo esatto (con coda di lamport univoca)
   all'indirizzo della tesoreria; il server lo riconosce e accredita i token.
   Nessuna chiave privata sul server: ricevere non richiede firmare. */
async function solRpc(env, method, params) {
  if (!env.SOLANA_RPC) throw new HttpError(503, 'rpc_unavailable');
  const r = await fetch(env.SOLANA_RPC, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  const j = await r.json(); if (j.error) throw new Error('rpc ' + method + ': ' + (j.error.message || 'errore')); return j.result;
}
const solStr = lam => (lam / LAMPORTS).toFixed(9).replace(/0+$/, '').replace(/\.$/, '');
async function depositIntent(ctx, body) {
  const env = ctx.env, db = ctx.db, u = ctx.user; const p = await getParams(env);
  if (!env.TREASURY_ADDRESS) throw new HttpError(503, 'deposits_unavailable', 'Depositi non ancora attivi');
  const want = Math.round((+body.sol || 0) * LAMPORTS);
  if (!isInt(want) || want < p.deposit_min_lamports || want > p.deposit_max_lamports) throw bad('invalid_amount', `Importo tra ${solStr(p.deposit_min_lamports)} e ${solStr(p.deposit_max_lamports)} SOL`);
  await rateLimit(db, 'dep:' + u.id, 10, HOUR);
  const base = want - (want % 10000), t = NOW();
  await dbRun(db, "UPDATE deposit_intents SET status='scaduto' WHERE status='aperto' AND (user_id=? OR expires_at<?)", u.id, t);
  for (let i = 0; i < 12; i++) {
    const lam = base + randInt(1, 9999);
    try {
      await dbRun(db, "INSERT INTO deposit_intents(user_id,lamports,status,created_at,expires_at) VALUES(?,?,'aperto',?,?)", u.id, lam, t, t + p.deposit_ttl_minutes * MIN);
      return depositView({ lamports: lam, expires_at: t + p.deposit_ttl_minutes * MIN, status: 'aperto' }, env);
    } catch (e) { if (!String(e.message).includes('UNIQUE')) throw e; }
  }
  throw conflict('busy');
}
const depositView = (i, env) => ({ status: i.status, lamports: i.lamports, sol: solStr(i.lamports), expires_at: i.expires_at, address: env.TREASURY_ADDRESS, uri: `solana:${env.TREASURY_ADDRESS}?amount=${solStr(i.lamports)}&label=DegenLand` });
async function checkDeposits(env, { force = false } = {}) {
  if (!env.TREASURY_ADDRESS || !env.SOLANA_RPC) return { skipped: true };
  const db = env.DB, t = NOW(); const m = await dbOne(db, "SELECT value FROM meta WHERE key='dep_check_at'");
  if (!force && m && t - +m.value < 15000) return { skipped: true };
  await dbRun(db, "INSERT OR REPLACE INTO meta(key,value) VALUES('dep_check_at',?)", String(t));
  await dbRun(db, "UPDATE deposit_intents SET status='scaduto' WHERE status='aperto' AND expires_at<?", t - 10 * MIN);
  const cur = await dbOne(db, "SELECT value FROM meta WHERE key='dep_cursor'");
  const opts = { limit: 25, commitment: 'finalized' }; if (cur) opts.until = cur.value;
  const sigs = await solRpc(env, 'getSignaturesForAddress', [env.TREASURY_ADDRESS, opts]);
  let credited = 0; const list = sigs.slice().reverse(); const p = await getParams(env); const ctx = { env, db };
  for (const s of list) {
    if (s.err) continue;
    if (await dbOne(db, 'SELECT id FROM deposits WHERE signature=?', s.signature)) continue;
    const tx = await solRpc(env, 'getTransaction', [s.signature, { encoding: 'json', commitment: 'finalized', maxSupportedTransactionVersion: 0 }]);
    if (!tx || !tx.meta || tx.meta.err) continue;
    const keys = tx.transaction.message.accountKeys; const idx = keys.indexOf(env.TREASURY_ADDRESS); if (idx < 0) continue;
    const delta = tx.meta.postBalances[idx] - tx.meta.preBalances[idx]; if (delta <= 0) continue;
    const it = await dbOne(db, "SELECT * FROM deposit_intents WHERE lamports=? AND status='aperto'", delta);
    if (it) { await creditDeposit(ctx, { signature: s.signature, lamports: delta, sender: keys[0], userId: it.user_id, intentId: it.id }); credited++; }
    else await dbRun(db, "INSERT OR IGNORE INTO deposits(signature,lamports,sender,status,detected_at,note) VALUES(?,?,?,'non_abbinato',?,'nessun importo corrispondente')", s.signature, delta, keys[0], NOW());
  }
  if (sigs.length) await dbRun(db, "INSERT OR REPLACE INTO meta(key,value) VALUES('dep_cursor',?)", sigs[0].signature);
  return { checked: list.length, credited };
}
async function creditDeposit(ctx, { signature, lamports, sender, userId, intentId, adminId, existingId }) {
  const db = ctx.db, env = ctx.env; const fx = await getFx(env); const pool = await currentPool(env); const p = await getParams(env, pool.param_set_id);
  const tokens = tokMilli(lamports, fx, p); const t = NOW(); const accs = await userAccs(ctx, userId);
  const ext = await sysAcc(db, 'external_sol', 'SOL'), poolAcc = await sysAcc(db, 'pool_sol', 'SOL'), mint = await sysAcc(db, 'token_mint', 'TOKEN');
  const s = [];
  if (existingId) s.push(guard(db, 'dep:' + existingId), st(db, "UPDATE deposits SET status='accreditato', user_id=?, sol_usd=?, token_milli=?, credited_at=?, note=? WHERE id=? AND status='non_abbinato'", userId, fx, tokens, t, 'assegnato da admin', existingId));
  else s.push(st(db, "INSERT INTO deposits(signature,lamports,sender,user_id,intent_id,sol_usd,token_milli,status,detected_at,credited_at) VALUES(?,?,?,?,?,?,?,'accreditato',?,?)", signature, lamports, sender || null, userId, intentId || null, fx, tokens, t, t));
  if (intentId) s.push(st(db, "UPDATE deposit_intents SET status='accreditato', signature=? WHERE id=? AND status='aperto'", signature, intentId));
  s.push(...ledgerStmts(db, 'deposito', [{ acc: ext, asset: 'SOL', amt: -lamports }, { acc: poolAcc, asset: 'SOL', amt: lamports }, { acc: mint, asset: 'TOKEN', amt: -tokens }, { acc: accs.TOKEN, asset: 'TOKEN', amt: tokens }], { idem: 'dep:' + signature, admin: adminId }));
  await runBatch(db, s); await notify(db, userId, 'deposito_ok', { sol: solStr(lamports), tokens: tokens / 1000 });
  return { tokens };
}
async function depositStatus(ctx) {
  await checkDeposits(ctx.env).catch(() => {});
  const i = await dbOne(ctx.db, "SELECT * FROM deposit_intents WHERE user_id=? AND status='aperto' AND expires_at>? ORDER BY id DESC LIMIT 1", ctx.user.id, NOW());
  const last = await dbOne(ctx.db, 'SELECT lamports, token_milli, credited_at FROM deposits WHERE user_id=? ORDER BY id DESC LIMIT 1', ctx.user.id);
  return { intent: i ? depositView(i, ctx.env) : null, last_deposit: last || null };
}

/* ============================ INDIRIZZO E PRELIEVI ============================ */
async function setAddress(ctx, body) {
  const addr = String(body.address || '').trim(); if (!isSolAddress(addr)) throw bad('invalid_address', 'Indirizzo Solana non valido');
  const db = ctx.db, p = await getParams(ctx.env); const cur = await dbOne(db, 'SELECT * FROM addresses WHERE user_id=? AND is_current=1', ctx.user.id);
  if (cur && cur.address === addr) return { address: addr, locked_until: cur.locked_until };
  const t = NOW(), lock = cur ? t + p.address_lock_hours * HOUR : null;
  await runBatch(db, [guard(db, `addr:${ctx.user.id}:${cur ? cur.id : 0}`), st(db, 'UPDATE addresses SET is_current=0, replaced_at=? WHERE user_id=? AND is_current=1', t, ctx.user.id),
    st(db, 'INSERT INTO addresses(user_id,address,is_current,locked_until,created_at) VALUES(?,?,1,?,?)', ctx.user.id, addr, lock, t)]);
  return { address: addr, locked_until: lock };
}
async function riskFlagsFor(ctx, user, addr, amount, tgOk) {
  const db = ctx.db, t = NOW(), f = [];
  if (t - user.created_at < 7 * DAY) f.push('account_nuovo');
  const dep = await dbOne(db, "SELECT COALESCE(SUM(lamports),0) s FROM deposits WHERE user_id=? AND status='accreditato'", user.id);
  if (dep.s === 0) f.push('solo_miner_gratuito');
  const allowed = new Set((await dbAll(db, 'SELECT ip_key FROM ip_allow')).map(r => r.ip_key));   // connessioni condivise autorizzate dalla console
  const ips = (await dbAll(db, 'SELECT DISTINCT COALESCE(ip_key, ip) ip FROM ip_events WHERE user_id=? AND created_at>?', user.id, t - 30 * DAY)).filter(r => !allowed.has(r.ip));
  if (ips.length) { const q = ips.map(() => '?').join(','); const o = await dbOne(db, `SELECT COUNT(DISTINCT user_id) c FROM ip_events WHERE COALESCE(ip_key, ip) IN (${q}) AND user_id<>? AND created_at>?`, ...ips.map(r => r.ip), user.id, t - 30 * DAY); if (o.c > 0) f.push('ip_condiviso'); }
  if (await dbOne(db, 'SELECT 1 x FROM pioneers WHERE user_id=?', user.id)) f.push('pioniere');
  const same = await dbOne(db, 'SELECT COUNT(DISTINCT user_id) c FROM addresses WHERE address=? AND user_id<>?', addr.address, user.id); if (same.c > 0) f.push('indirizzo_condiviso');
  if (t - addr.created_at < 7 * DAY && addr.locked_until) f.push('indirizzo_recente');
  if (user.referrer_id && ips.length) { const q = ips.map(() => '?').join(','); const o = await dbOne(db, `SELECT COUNT(*) c FROM ip_events WHERE user_id=? AND COALESCE(ip_key, ip) IN (${q})`, user.referrer_id, ...ips.map(r => r.ip)); if (o.c > 0) f.push('referral_stesso_ip'); }
  const done = await dbOne(db, "SELECT COALESCE(SUM(lamports),0) s FROM withdrawals WHERE user_id=? AND status='eseguito'", user.id);
  if ((done.s + amount) > 1.5 * dep.s && t - user.created_at < 60 * DAY && dep.s > 0) f.push('prelievi_alti');
  if (!tgOk) f.push('senza_conferma_telegram');
  return f;
}
async function withdrawRequest(ctx, body) {
  const db = ctx.db, u = await dbOne(ctx.db, 'SELECT * FROM users WHERE id=?', ctx.user.id), p = await getParams(ctx.env); const t = NOW();
  if (u.wd_hold) throw forbid('withdrawals_held', 'Prelievi sospesi: contatta il supporto');
  const addr = await dbOne(db, 'SELECT * FROM addresses WHERE user_id=? AND is_current=1', u.id); if (!addr) throw bad('address_required', 'Salva prima un indirizzo Solana');
  if (addr.locked_until && t < addr.locked_until) throw bad('address_locked', 'Indirizzo cambiato di recente: prelievi bloccati', { until: addr.locked_until });
  await settle(ctx, u.id);
  const b = await balancesOf(db, u.id); const amount = body.amount_lamports ? Math.floor(+body.amount_lamports) : b.SOL;
  if (!isInt(amount) || amount < p.withdraw_min_lamports) throw bad('below_minimum', `Minimo ${solStr(p.withdraw_min_lamports)} SOL`);
  if (amount > b.SOL) throw bad('insufficient_funds');
  const ids = await identitiesOf(db, u.id); const tgOk = !!(u.tg_confirm && ids.telegram && ids.telegram.chat_ok);
  const flags = await riskFlagsFor(ctx, u, addr, amount, tgOk); const score = flags.length;
  const status = tgOk ? 'conferma' : 'attesa'; const accs = await userAccs(ctx, u.id); const pend = await sysAcc(db, 'pending_sol', 'SOL');
  try {
    await runBatch(db, [st(db, 'INSERT INTO withdrawals(user_id,address,lamports,status,risk_score,risk_flags,requested_ip,day,created_at) VALUES(?,?,?,?,?,?,?,?,?)', u.id, addr.address, amount, status, score, JSON.stringify(flags), ctx.ip, dayOf(t), t),
      ...ledgerStmts(db, 'prelievo_richiesta', [{ acc: accs.SOL, asset: 'SOL', amt: -amount }, { acc: pend, asset: 'SOL', amt: amount }])]);
  } catch (e) { if (String(e.message).includes('one_wd_day') || String(e.message).includes('withdrawals.user_id')) throw conflict('already_requested_today', 'Hai già richiesto un prelievo oggi'); throw e; }
  await ipEventStmt(db, u.id, ctx.ip, 'prelievo').run();
  const w = await dbOne(db, 'SELECT * FROM withdrawals WHERE user_id=? ORDER BY id DESC LIMIT 1', u.id);
  if (status === 'conferma') await notify(db, u.id, 'prelievo_conferma', { id: w.id, sol: solStr(amount), address: addr.address });
  return { id: w.id, status, lamports: amount };
}
function wdRefund(db, w, accs, pend, kind, admin) { return ledgerStmts(db, kind, [{ acc: pend, asset: 'SOL', amt: -w.lamports }, { acc: accs.SOL, asset: 'SOL', amt: w.lamports }], { admin }); }
async function withdrawCancel(ctx, body) { // dall'utente, solo in attesa di conferma Telegram
  const w = await dbOne(ctx.db, "SELECT * FROM withdrawals WHERE id=? AND user_id=? AND status='conferma'", body.id, ctx.user.id); if (!w) throw notfound('withdrawal_not_found');
  await wdCloseByUser(ctx, w, 'annullato'); return { ok: true };
}
async function wdCloseByUser(ctx, w, status) {
  const accs = await userAccs(ctx, w.user_id), pend = await sysAcc(ctx.db, 'pending_sol', 'SOL');
  await runBatch(ctx.db, [guard(ctx.db, 'wd:' + w.id), st(ctx.db, "UPDATE withdrawals SET status=?, handled_at=? WHERE id=? AND status='conferma'", status, NOW(), w.id), ...wdRefund(ctx.db, w, accs, pend, 'prelievo_annullato')]);
}
async function wdConfirmTelegram(ctx, w) {
  await runBatch(ctx.db, [guard(ctx.db, 'wdc:' + w.id), st(ctx.db, "UPDATE withdrawals SET status='attesa', tg_confirmed_at=? WHERE id=? AND status='conferma'", NOW(), w.id)]);
}
async function withdrawList(ctx) {
  return dbAll(ctx.db, 'SELECT id, lamports, status, address, reject_reason, tx_signature, created_at, handled_at FROM withdrawals WHERE user_id=? ORDER BY id DESC LIMIT 20', ctx.user.id);
}
/* esecuzione/rifiuto manuale dalla console */
async function wdExecute(env, adminId, id, tx, ip) {
  const db = env.DB, w = await dbOne(db, "SELECT * FROM withdrawals WHERE id=? AND status='attesa'", id); if (!w) throw notfound('withdrawal_not_found', 'Richiesta non in attesa');
  const pend = await sysAcc(db, 'pending_sol', 'SOL'), ext = await sysAcc(db, 'external_sol', 'SOL'); const t = NOW();
  await runBatch(db, [guard(db, 'wd:' + id), st(db, "UPDATE withdrawals SET status='eseguito', handled_by=?, handled_at=?, tx_signature=? WHERE id=? AND status='attesa'", adminId, t, tx || null, id),
    ...ledgerStmts(db, 'prelievo_eseguito', [{ acc: pend, asset: 'SOL', amt: -w.lamports }, { acc: ext, asset: 'SOL', amt: w.lamports }], { admin: adminId }),
    auditStmt(db, adminId, 'esegui_prelievo', 'withdrawals', id, { status: 'attesa' }, { status: 'eseguito', tx: tx || null }, ip)]);
  await notify(db, w.user_id, 'prelievo_eseguito', { sol: solStr(w.lamports), tx: tx || null });
  return { ok: true };
}
async function wdReject(env, adminId, id, reason, suspend, ip) {
  const db = env.DB, w = await dbOne(db, "SELECT * FROM withdrawals WHERE id=? AND status='attesa'", id); if (!w) throw notfound('withdrawal_not_found', 'Richiesta non in attesa');
  if (!reason) throw bad('reason_required'); const ctx = { env, db }; const accs = await userAccs(ctx, w.user_id), pend = await sysAcc(db, 'pending_sol', 'SOL'); const t = NOW();
  const s = [guard(db, 'wd:' + id), st(db, "UPDATE withdrawals SET status='rifiutato', handled_by=?, handled_at=?, reject_reason=? WHERE id=? AND status='attesa'", adminId, t, String(reason).slice(0, 200), id),
    ...wdRefund(db, w, accs, pend, 'prelievo_rifiutato', adminId), auditStmt(db, adminId, 'rifiuta_prelievo', 'withdrawals', id, { status: 'attesa' }, { status: 'rifiutato', reason, suspend: !!suspend }, ip)];
  if (suspend) s.push(st(db, "UPDATE users SET status='sospeso', suspended_reason=? WHERE id=?", String(reason).slice(0, 200), w.user_id), st(db, "UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", t, w.user_id));
  await runBatch(db, s); await notify(db, w.user_id, 'prelievo_rifiutato', { reason });
  return { ok: true };
}
const auditStmt = (db, adminId, action, table, id, before, after, ip) => st(db, 'INSERT INTO audit_log(admin_id,action,target_table,target_id,before,after,ip,created_at) VALUES(?,?,?,?,?,?,?,?)', adminId || null, action, table || null, id || null, before ? JSON.stringify(before) : null, after ? JSON.stringify(after) : null, ip || null, NOW());

/* ============================ NOTIFICHE E BOT TELEGRAM ============================ */
async function notify(db, userId, kind, payload) {
  try { await dbRun(db, "INSERT INTO notifications(user_id,channel,kind,payload,created_at) VALUES(?, 'telegram', ?, ?, ?)", userId, kind, JSON.stringify(payload || {}), NOW()); } catch (e) { /* le notifiche non devono mai bloccare */ }
}
const MSG = {
  prelievo_conferma: { en: p => `Withdrawal request: ${p.sol} SOL to ${p.address}. Confirm it?`, es: p => `Solicitud de retiro: ${p.sol} SOL a ${p.address}. ¿Confirmas?`, ru: p => `Заявка на вывод: ${p.sol} SOL на ${p.address}. Подтвердить?`, it: p => `Richiesta di prelievo: ${p.sol} SOL verso ${p.address}. Confermi?` },
  prelievo_eseguito: { en: p => `Withdrawal of ${p.sol} SOL sent.`, es: p => `Retiro de ${p.sol} SOL enviado.`, ru: p => `Вывод ${p.sol} SOL выполнен.`, it: p => `Prelievo di ${p.sol} SOL eseguito.` },
  prelievo_rifiutato: { en: p => `Withdrawal rejected: ${p.reason}. The SOL is back in your wallet.`, es: p => `Retiro rechazado: ${p.reason}. El SOL vuelve a tu monedero.`, ru: p => `Вывод отклонён: ${p.reason}. SOL возвращён на кошелёк.`, it: p => `Prelievo rifiutato: ${p.reason}. Il SOL è tornato nel tuo portafoglio.` },
  deposito_ok: { en: p => `Deposit received: ${p.sol} SOL → ${p.tokens} tokens.`, es: p => `Depósito recibido: ${p.sol} SOL → ${p.tokens} tokens.`, ru: p => `Депозит получен: ${p.sol} SOL → ${p.tokens} токенов.`, it: p => `Deposito ricevuto: ${p.sol} SOL → ${p.tokens} token.` },
};
async function tgApi(env, method, body) {
  const r = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/${method}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({})); if (!j.ok) throw new Error('telegram ' + method + ': ' + (j.description || r.status)); return j.result;
}
async function flushNotifications(env, limit = 5) {
  if (!env.TELEGRAM_BOT_TOKEN) return; const db = env.DB;
  const rows = await dbAll(db, `SELECT n.*, i.subject tg, u.locale FROM notifications n JOIN identities i ON i.user_id=n.user_id AND i.provider='telegram' AND i.chat_ok=1
    JOIN users u ON u.id=n.user_id WHERE n.sent_at IS NULL ORDER BY n.id LIMIT ?`, limit);
  for (const n of rows) {
    const pl = JSON.parse(n.payload || '{}'); const tpl = MSG[n.kind]; const loc = tpl && tpl[n.locale] ? n.locale : 'en';
    try {
      if (tpl) {
        const body = { chat_id: n.tg, text: tpl[loc](pl) };
        if (n.kind === 'prelievo_conferma') body.reply_markup = { inline_keyboard: [[{ text: '✅ OK', callback_data: 'wd:ok:' + pl.id }, { text: '✖', callback_data: 'wd:no:' + pl.id }]] };
        await tgApi(env, 'sendMessage', body);
      }
      await dbRun(db, 'UPDATE notifications SET sent_at=? WHERE id=?', NOW(), n.id);
    } catch (e) { await dbRun(db, 'UPDATE notifications SET sent_at=?, error=? WHERE id=?', NOW(), String(e.message).slice(0, 200), n.id); }
  }
}
async function telegramLinkCode(ctx) {
  if (!ctx.env.TELEGRAM_BOT_USERNAME) throw new HttpError(503, 'telegram_unavailable');
  const code = rid(9).replace(/[^a-z0-9]/gi, 'x'); await dbRun(ctx.db, 'INSERT INTO auth_codes(purpose,subject,code_hash,user_id,expires_at,created_at) VALUES(?,?,?,?,?,?)', 'tg_link', String(ctx.user.id), await sha256hex(code), ctx.user.id, NOW() + 15 * MIN, NOW());
  return { url: `https://t.me/${ctx.env.TELEGRAM_BOT_USERNAME}?start=${code}`, code };
}
async function telegramWebhook(ctx, upd) {
  const env = ctx.env, db = ctx.db;
  if (upd.message && upd.message.text && upd.message.from) {
    const from = upd.message.from, text = upd.message.text.trim(); const m = text.match(/^\/start(?:\s+(\S+))?$/);
    if (m) {
      if (m[1]) {
        const r = await dbOne(db, "SELECT * FROM auth_codes WHERE purpose='tg_link' AND code_hash=? AND used_at IS NULL AND expires_at>?", await sha256hex(m[1]), NOW());
        if (r) {
          const other = await dbOne(db, "SELECT user_id FROM identities WHERE provider='telegram' AND subject=?", String(from.id));
          if (other && other.user_id !== r.user_id) return tgApi(env, 'sendMessage', { chat_id: from.id, text: 'This Telegram account is linked to another player.' });
          await db.batch([st(db, "UPDATE auth_codes SET used_at=? WHERE id=?", NOW(), r.id),
            st(db, "INSERT INTO identities(user_id,provider,subject,display,chat_ok,verified_at,created_at) VALUES(?,'telegram',?,?,1,?,?) ON CONFLICT(user_id,provider) DO UPDATE SET chat_ok=1", r.user_id, String(from.id), from.username ? '@' + from.username : null, NOW(), NOW())]);
          return tgApi(env, 'sendMessage', { chat_id: from.id, text: '✅ Telegram linked to DegenLand.' });
        }
        return tgApi(env, 'sendMessage', { chat_id: from.id, text: 'Link expired. Generate a new one in the game.' });
      }
      await dbRun(db, "UPDATE identities SET chat_ok=1 WHERE provider='telegram' AND subject=?", String(from.id));
      return tgApi(env, 'sendMessage', { chat_id: from.id, text: 'DegenLand bot ready ✅' });
    }
  }
  const cb = upd.callback_query;
  if (cb && cb.data && /^wd:(ok|no):\d+$/.test(cb.data)) {
    const [, act, sid] = cb.data.split(':'); const w = await dbOne(db, "SELECT * FROM withdrawals WHERE id=? AND status='conferma'", +sid);
    const idn = w && await dbOne(db, "SELECT 1 x FROM identities WHERE provider='telegram' AND subject=? AND user_id=?", String(cb.from.id), w.user_id);
    if (w && idn) { if (act === 'ok') await wdConfirmTelegram(ctx, w); else await wdCloseByUser(ctx, w, 'annullato'); }
    await tgApi(env, 'answerCallbackQuery', { callback_query_id: cb.id, text: w && idn ? (act === 'ok' ? 'Confirmed' : 'Cancelled') : 'Not available' }).catch(() => {});
  }
}


/* ---------- 70-state.js ---------- */
/* ============================ STATO PER IL CLIENT ============================ */
async function buildState(ctx) {
  const db = ctx.db; const u = await dbOne(db, 'SELECT * FROM users WHERE id=?', ctx.user.id);
  await settle(ctx, u.id, { lazy: true });
  const { pool, p, fx } = await ctxGame(ctx); const now = NOW();
  const b = await balancesOf(db, u.id); const farm = await dbOne(db, 'SELECT * FROM farms WHERE user_id=?', u.id);
  const miners = await dbAll(db, "SELECT id, model_id, pool_id, generation, is_welcome, special, state, rack, slot, worked_blocks, paid_milli, broken FROM miners WHERE owner_id=? AND state<>'rottamato' ORDER BY id", u.id);
  const c = await computeSettlement(ctx, u.id, now);
  const pendingProd = c ? (u.mine_mode === 'TOKEN' ? tokMilli(c.prod, fx, p) : c.prod) : 0;
  const mine = await dbAll(db, "SELECT id, miner_id, price_milli, created_at FROM market_listings WHERE seller_id=? AND status='attivo'", u.id);
  const addr = await dbOne(db, 'SELECT address, locked_until FROM addresses WHERE user_id=? AND is_current=1', u.id);
  const ids = await identitiesOf(db, u.id); const wds = await withdrawList(ctx);
  const intent = await dbOne(db, "SELECT * FROM deposit_intents WHERE user_id=? AND status='aperto' AND expires_at>? ORDER BY id DESC LIMIT 1", u.id, now);
  const nextH = p.halving_blocks.find(x => pool.blocks < x) || null;
  const ref = await dbOne(db, 'SELECT COUNT(*) c FROM users WHERE referrer_id=?', u.id);
  const earned = await dbAll(db, 'SELECT asset, SUM(amount) s FROM referral_earnings WHERE referrer_id=? GROUP BY asset', u.id);
  const shopMiners = p.miners.map((m, i) => ({ model: i, code: m.code, name: m.name, price_sol: m.price_sol, price_milli: priceMilli(p, i, fx),
    power: Math.round(m.price_sol / m.payback * 1e6), reward_per_block_lamports: dailyLamports(p, i), life_min: Math.round(m.payback * p.break_from), life_max: Math.round(m.payback * p.break_to), indestructible: i === 0 }));
  return {
    server_time: now,
    me: { id: u.id, nickname: u.nickname, referral_code: u.referral_code, mode: u.mine_mode, energy: u.energy, energy_max: p.energy_max, racks: u.racks, tg_confirm: !!u.tg_confirm, locale: u.locale, nick_set: !!u.nick_changed_at, pioneer_no: (await dbOne(db, 'SELECT no FROM pioneers WHERE user_id=?', u.id) || {}).no || null, wd_hold: !!u.wd_hold, lb_hidden: !!u.lb_hidden,
      email: ids.email ? ids.email.subject : null, telegram: ids.telegram ? (ids.telegram.display || ids.telegram.subject) : null, telegram_chat_ok: !!(ids.telegram && ids.telegram.chat_ok) },
    fx: { sol_usd: fx, token_usd: p.token_usd },
    balances: { sol_lamports: b.SOL, token_milli: b.TOKEN, credit_milli: b.CREDIT },
    farm: { on_until: farm.on_until, video_until: farm.video_until, ext_until: farm.ext_until, is_on: now < farm.on_until, pending: pendingProd, pending_asset: u.mine_mode },
    miners, listings: mine, shop: { miners: shopMiners, next_rack_milli: u.racks < p.max_racks ? p.rack_prices_token[u.racks] * 1000 : null,
      extensions: p.extensions.map(e => ({ days: e.days, price_milli: Math.round(e.usd / p.token_usd * 1000) })), tap_reward_milli: p.tap_reward_milli, repair_pct: p.repair_pct, market_min_pct: p.market_min_pct, market_max_pct: p.market_max_pct },
    pool: { number: pool.number, status: pool.status, blocks: pool.blocks, halvings: pool.halvings, next_halving_at: nextH, close_at: p.close_blocks, halving_blocks: p.halving_blocks },
    address: addr || null, withdrawals: wds, withdraw_min_lamports: p.withdraw_min_lamports,
    deposit: intent ? depositView(intent, ctx.env) : null, deposits_enabled: !!ctx.env.TREASURY_ADDRESS,
    referral: { code: u.referral_code, invited: ref.c, pct: p.referral_pct, earned: Object.fromEntries(earned.map(r => [r.asset, r.s])) },
  };
}
async function marketBrowse(ctx) {
  const rows = await dbAll(ctx.db, `SELECT l.id, l.price_milli, l.created_at, m.model_id, m.generation, m.worked_blocks, m.broken, m.paid_milli, u.nickname seller
    FROM market_listings l JOIN miners m ON m.id=l.miner_id JOIN users u ON u.id=l.seller_id
    WHERE l.status='attivo' AND l.seller_id<>? ORDER BY l.id DESC LIMIT 60`, ctx.user.id);
  return { listings: rows };
}
async function accountSettings(ctx, body) {
  const db = ctx.db; const s = [];
  if (body.tg_confirm != null) {
    const ids = await identitiesOf(db, ctx.user.id);
    if (body.tg_confirm && !(ids.telegram && ids.telegram.chat_ok)) throw bad('telegram_not_ready', 'Collega Telegram e avvia il bot');
    s.push(st(db, 'UPDATE users SET tg_confirm=? WHERE id=?', body.tg_confirm ? 1 : 0, ctx.user.id));
  }
  if (body.lb_hidden != null) s.push(st(db, 'UPDATE users SET lb_hidden=? WHERE id=?', body.lb_hidden ? 1 : 0, ctx.user.id));
  if (body.locale != null) { if (!['en', 'es', 'ru', 'it'].includes(body.locale)) throw bad('invalid_locale'); s.push(st(db, 'UPDATE users SET locale=? WHERE id=?', body.locale, ctx.user.id)); }
  if (s.length) await db.batch(s); return { ok: true };
}


/* ---------- 75-social.js ---------- */
/* ============================ NICKNAME, CLASSIFICHE, AFFILIATI, CONTATORE ============================ */
const NICK_RE = /^[A-Za-z0-9_.-]{3,16}$/;
const NICK_RESERVED = ['admin', 'administrator', 'degenland', 'team', 'support', 'staff', 'mod', 'moderator', 'system', 'root', 'official', 'owner', 'null', 'undefined', 'help', 'bot', 'sistema'];
function validNick(raw) {
  const nick = String(raw == null ? '' : raw).trim();
  if (!NICK_RE.test(nick)) throw bad('invalid_nickname', 'Nickname non valido');
  const low = nick.toLowerCase(), letters = low.replace(/[^a-z]/g, '');
  if (NICK_RESERVED.includes(low) || NICK_RESERVED.includes(letters)) throw bad('reserved_nickname', 'Nickname non disponibile');
  return nick;
}
async function setNickname(ctx, body) {
  const db = ctx.db, nick = validNick(body.nickname); await rateLimit(db, 'nick:' + ctx.user.id, 10, HOUR);
  const u = await dbOne(db, 'SELECT nickname, nick_changed_at FROM users WHERE id=?', ctx.user.id);
  if (u.nickname === nick) { await dbRun(db, 'UPDATE users SET nick_changed_at=COALESCE(nick_changed_at,?) WHERE id=?', NOW(), ctx.user.id); return { nickname: nick }; }
  if (u.nick_changed_at && NOW() - u.nick_changed_at < 7 * DAY) { const e = bad('nickname_cooldown', 'Puoi cambiare nickname una volta ogni 7 giorni'); e.days = Math.ceil((7 * DAY - (NOW() - u.nick_changed_at)) / DAY); throw e; }
  try { await dbRun(db, 'UPDATE users SET nickname=?, nick_changed_at=? WHERE id=?', nick, NOW(), ctx.user.id); }
  catch (e) { if (String(e.message || e).includes('users.nickname')) throw conflict('nickname_taken', 'Nickname già in uso'); throw e; }
  return { nickname: nick };
}

/* --- classifiche: power (potenza installata ora), mined (estratto, in $), referral (guadagno da invitati, in $) --- */
const LB_PERIODS = { '7d': 7, '30d': 30, all: null };
async function computeBoard(env, board, period) {   // include anche chi si è nascosto: il filtro si applica in risposta, così vale subito
  const db = env.DB, t = NOW(), key = `${board}:${period}`;
  _cache.lb = _cache.lb || {}; const hit = _cache.lb[key]; if (hit && t - hit.at < 60000) return hit.rows;
  const pool = await currentPool(env), p = await getParams(env, pool.param_set_id), fx = await getFx(env); const vis = '';
  const usd = (asset, s) => asset === 'SOL' ? s / LAMPORTS * fx : s / 1000 * p.token_usd;
  let rows = [];
  if (board === 'power') {
    const q = await dbAll(db, `SELECT m.owner_id id, m.model_id, COUNT(*) c FROM miners m JOIN users u ON u.id=m.owner_id WHERE m.state='installato' AND m.broken=0 AND u.status='attivo' AND u.is_dev=0${vis} GROUP BY m.owner_id, m.model_id`);
    const acc = {}; for (const r of q) { const m = p.miners[r.model_id]; if (m) acc[r.id] = (acc[r.id] || 0) + r.c * Math.round(m.price_sol / m.payback * 1e6); }
    rows = Object.entries(acc).map(([id, v]) => ({ id: +id, value: v }));
  } else {
    const days = LB_PERIODS[period]; const acc = {};
    if (board === 'mined') {
      const q = await dbAll(db, `SELECT a.owner_id id, a.asset, SUM(e.amount) s FROM ledger_entries e JOIN ledger_tx x ON x.id=e.tx_id JOIN accounts a ON a.id=e.account_id JOIN users u ON u.id=a.owner_id
        WHERE x.kind='produzione' AND e.amount>0 AND a.owner_id IS NOT NULL AND x.created_at>=? AND u.status='attivo' AND u.is_dev=0${vis} GROUP BY a.owner_id, a.asset`, days ? t - days * DAY : 0);
      for (const r of q) acc[r.id] = (acc[r.id] || 0) + usd(r.asset, r.s);
      rows = Object.entries(acc).map(([id, v]) => ({ id: +id, value: v }));
    } else {
      const q = await dbAll(db, `SELECT r.referrer_id id, r.asset, SUM(r.amount) s FROM referral_earnings r JOIN users u ON u.id=r.referrer_id WHERE r.day>? AND u.status='attivo' AND u.is_dev=0${vis} GROUP BY r.referrer_id, r.asset`, days ? dayOf(t) - days : -1);
      for (const r of q) acc[r.id] = (acc[r.id] || 0) + usd(r.asset, r.s);
      const inv = {}; (await dbAll(db, 'SELECT referrer_id id, COUNT(*) c FROM users WHERE referrer_id IS NOT NULL GROUP BY referrer_id')).forEach(r => inv[r.id] = r.c);
      rows = Object.entries(acc).map(([id, v]) => ({ id: +id, value: v, extra: inv[id] || 0 }));
    }
  }
  rows = rows.filter(r => r.value > 0).sort((a, b) => b.value - a.value || a.id - b.id);
  _cache.lb[key] = { at: t, rows }; return rows;
}
async function nicknamesFor(db, ids) {
  const out = {}; if (!ids.length) return out;
  const q = ids.map(() => '?').join(','); (await dbAll(db, `SELECT id, nickname FROM users WHERE id IN (${q})`, ...ids)).forEach(r => out[r.id] = r.nickname); return out;
}
function boardArgs(url) {
  const board = url.searchParams.get('board') || 'power', period = url.searchParams.get('period') || '30d';
  if (!['power', 'mined', 'referral'].includes(board) || !(period in LB_PERIODS)) throw bad('invalid_board');
  return { board, period: board === 'power' ? 'all' : period };
}
async function leaderboardPublic(ctx, url) {
  const { board, period } = boardArgs(url); const hidden = new Set((await dbAll(ctx.db, 'SELECT id FROM users WHERE lb_hidden=1')).map(r => r.id));
  const rows = (await computeBoard(ctx.env, board, period)).filter(r => !hidden.has(r.id));   // chi si nasconde sparisce subito, anche se la classifica è in cache
  const top = rows.slice(0, 20), nicks = await nicknamesFor(ctx.db, top.map(r => r.id));
  const pn = {}; if (top.length) (await dbAll(ctx.db, `SELECT user_id, no FROM pioneers WHERE user_id IN (${top.map(() => '?').join(',')})`, ...top.map(r => r.id))).forEach(r => pn[r.user_id] = r.no);
  const idx = rows.findIndex(r => r.id === ctx.user.id); const mine = await dbOne(ctx.db, 'SELECT lb_hidden FROM users WHERE id=?', ctx.user.id);
  return { board, period, total: rows.length, top: top.map((r, i) => ({ rank: i + 1, nickname: nicks[r.id], value: r.value, extra: r.extra, pioneer: pn[r.id] || null, me: r.id === ctx.user.id })),
    me: mine.lb_hidden ? { hidden: true } : (idx >= 0 ? { rank: idx + 1, value: rows[idx].value, extra: rows[idx].extra } : null) };
}
async function adminLeaderboard(ctx, url) { // per assegnare i premi: qui si vedono anche gli utenti nascosti e l'email
  const { board, period } = boardArgs(url); const limit = clamp(+url.searchParams.get('limit') || 50, 1, 200);
  const rows = (await computeBoard(ctx.env, board, period)).slice(0, limit), nicks = await nicknamesFor(ctx.db, rows.map(r => r.id));
  const mails = {}; if (rows.length) { const q = rows.map(() => '?').join(','); (await dbAll(ctx.db, `SELECT user_id, subject FROM identities WHERE provider='email' AND user_id IN (${q})`, ...rows.map(r => r.id))).forEach(r => mails[r.user_id] = r.subject); }
  return { board, period, rows: rows.map((r, i) => ({ rank: i + 1, id: r.id, nickname: nicks[r.id], email: mails[r.id] || null, value: r.value, extra: r.extra })) };
}

/* --- affiliati di chi ha invitato altri --- */
async function referralsList(ctx) {
  const db = ctx.db, uid = ctx.user.id, t = NOW();
  const list = await dbAll(db, 'SELECT u.id, u.nickname, u.created_at, f.on_until FROM users u LEFT JOIN farms f ON f.user_id=u.id WHERE u.referrer_id=? ORDER BY u.id DESC LIMIT 200', uid);
  const per = {}; (await dbAll(db, 'SELECT referee_id id, asset, SUM(amount) s FROM referral_earnings WHERE referrer_id=? GROUP BY referee_id, asset', uid)).forEach(r => { (per[r.id] = per[r.id] || {})[r.asset] = r.s; });
  const sum = rows => Object.fromEntries(rows.map(r => [r.asset, r.s]));
  const total = sum(await dbAll(db, 'SELECT asset, SUM(amount) s FROM referral_earnings WHERE referrer_id=? GROUP BY asset', uid));
  const last30 = sum(await dbAll(db, 'SELECT asset, SUM(amount) s FROM referral_earnings WHERE referrer_id=? AND day>? GROUP BY asset', uid, dayOf(t) - 30));
  const invited = (await dbOne(db, 'SELECT COUNT(*) c FROM users WHERE referrer_id=?', uid)).c;
  const active = (await dbOne(db, 'SELECT COUNT(*) c FROM users u JOIN farms f ON f.user_id=u.id WHERE u.referrer_id=? AND f.on_until>?', uid, t)).c;
  return { invited, active, earned: total, earned_30d: last30,
    list: list.map(r => ({ nickname: r.nickname, joined: r.created_at, active: (r.on_until || 0) > t, earned: per[r.id] || {} })).sort((a, b) => ((b.earned.SOL || 0) / LAMPORTS * 100 + (b.earned.TOKEN || 0) / 1000 * 0.01) - ((a.earned.SOL || 0) / LAMPORTS * 100 + (a.earned.TOKEN || 0) / 1000 * 0.01)) };
}

/* --- contatore pubblico per la home --- */
async function publicStats(ctx) {
  const t = NOW(); let s = _cache.stats;
  if (!s || t - s.at > 60000) { const n = (await dbOne(ctx.db, "SELECT COUNT(*) c FROM users WHERE is_dev=0 AND status<>'chiuso'")).c; s = _cache.stats = { at: t, users: n }; }
  const min = +ctx.env.PUBLIC_COUNTER_MIN || 0;
  ctx.cacheControl = 'public, max-age=15';   // breve: i posti Pionieri devono aggiornarsi in fretta
  const pc = await pioneerCounts(ctx.env);
  return { users: s.users >= min ? s.users : null, pioneers: pc.total ? { total: pc.total, left: pc.left } : null };   // sotto la soglia il contatore non viene mostrato
}


/* ---------- 76-pioneers.js ---------- */
/* ============================ PROGRAMMA PIONIERI ============================
   I primi N iscritti (N = variabile PIONEER_SLOTS, 0 = programma spento) ricevono, al posto del Pixel di benvenuto,
   un miner Pioniere: produce come un Pixel, non dimezza con gli halving, non si rompe, non si vende né si rottama.
   Un solo Pioniere per connessione: se l'IP è già stato usato da un altro account negli ultimi 30 giorni, niente Pioniere
   (salvo connessioni autorizzate dalla console). Un posto liberato (ban o revoca) torna disponibile. */
const pioneerSlots = env => Math.max(0, Math.min(1000, Math.floor(+env.PIONEER_SLOTS || 0)));
async function pioneerFreeNo(db, slots) {
  const used = new Set((await dbAll(db, 'SELECT no FROM pioneers')).map(r => r.no));
  for (let n = 1; n <= slots; n++) if (!used.has(n)) return n; return null;
}
async function pioneerAssign(ctx) {   // numero da assegnare a un nuovo iscritto, oppure null
  const slots = pioneerSlots(ctx.env); if (!slots) return null;
  const no = await pioneerFreeNo(ctx.db, slots); if (!no) return null;
  const key = ipKey(ctx.ip);
  if (await dbOne(ctx.db, 'SELECT 1 x FROM ip_allow WHERE ip_key=?', key)) return no;
  const shared = await dbOne(ctx.db, 'SELECT 1 x FROM ip_events e JOIN users u ON u.id=e.user_id WHERE COALESCE(e.ip_key,e.ip)=? AND u.is_dev=0 AND e.created_at>? LIMIT 1', key, NOW() - 30 * DAY);
  return shared ? null : no;
}
async function pioneerCounts(env) {
  const slots = pioneerSlots(env); if (!slots) return { total: 0, taken: 0, left: 0 };
  const taken = (await dbOne(env.DB, "SELECT COUNT(*) c FROM pioneers p JOIN users u ON u.id=p.user_id WHERE u.status<>'chiuso'")).c;
  return { total: slots, taken, left: Math.max(0, slots - taken) };
}
async function pioneerGrant(ctx, userId) {   // assegnazione manuale (per chi ha una connessione condivisa autorizzata)
  const slots = pioneerSlots(ctx.env); if (!slots) throw bad('pioneers_off', 'Il programma Pionieri non è attivo');
  if (await dbOne(ctx.db, 'SELECT 1 x FROM pioneers WHERE user_id=?', userId)) throw conflict('already_pioneer');
  const no = await pioneerFreeNo(ctx.db, slots); if (!no) throw conflict('no_slots', 'Nessun posto libero');
  const m = await dbOne(ctx.db, 'SELECT id FROM miners WHERE owner_id=? AND is_welcome=1 AND special IS NULL AND state<>\'rottamato\'', userId); if (!m) throw bad('no_welcome_miner', 'Manca il Pixel di benvenuto da trasformare');
  await runBatch(ctx.db, [st(ctx.db, 'INSERT INTO pioneers(no,user_id,ip_key,granted_at) VALUES(?,?,NULL,?)', no, userId, NOW()), st(ctx.db, "UPDATE miners SET special='pioneer' WHERE id=?", m.id)]);
  _cache.stats = null; return no;
}
function pioneerRevokeStmts(db, userId) {   // il Pioniere torna un normale Pixel di benvenuto e il numero si libera
  return [st(db, 'DELETE FROM pioneers WHERE user_id=?', userId), st(db, "UPDATE miners SET special=NULL WHERE owner_id=? AND special='pioneer'", userId)];
}
/* --- console: pionieri, conflitti di IP, connessioni autorizzate --- */
async function adminPioneers(ctx) {
  const db = ctx.db, c = await pioneerCounts(ctx.env);
  const rows = await dbAll(db, `SELECT p.no, p.user_id id, p.granted_at, u.nickname, u.status, u.wd_hold, u.created_at,
      (SELECT subject FROM identities i WHERE i.user_id=u.id AND i.provider='email') email,
      (SELECT COUNT(DISTINCT e2.user_id) FROM ip_events e1 JOIN ip_events e2 ON COALESCE(e2.ip_key,e2.ip)=COALESCE(e1.ip_key,e1.ip) AND e2.user_id<>e1.user_id WHERE e1.user_id=u.id
         AND COALESCE(e1.ip_key,e1.ip) NOT IN (SELECT ip_key FROM ip_allow)) shared
    FROM pioneers p JOIN users u ON u.id=p.user_id ORDER BY p.no`);
  return { slots: c.total, taken: c.taken, left: c.left, pioneers: rows };
}
async function adminIpConflicts(ctx) {
  const db = ctx.db, since = NOW() - 30 * DAY;
  const keys = await dbAll(db, `SELECT COALESCE(e.ip_key,e.ip) k, COUNT(DISTINCT e.user_id) n, MAX(e.created_at) last FROM ip_events e JOIN users u ON u.id=e.user_id
    WHERE u.is_dev=0 AND e.created_at>? AND COALESCE(e.ip_key,e.ip) NOT IN (SELECT ip_key FROM ip_allow) GROUP BY k HAVING n>=2 ORDER BY last DESC LIMIT 100`, since);
  const out = [];
  for (const r of keys) out.push({ ip_key: r.k, last: r.last, users: await dbAll(db, `SELECT DISTINCT u.id, u.nickname, u.status, (SELECT no FROM pioneers WHERE user_id=u.id) pioneer_no FROM ip_events e JOIN users u ON u.id=e.user_id WHERE COALESCE(e.ip_key,e.ip)=? AND u.is_dev=0 AND e.created_at>? ORDER BY u.id`, r.k, since) });
  return { conflicts: out };
}
async function adminIpAllowList(ctx) { return { allowed: await dbAll(ctx.db, 'SELECT a.ip_key, a.note, a.created_at, x.name admin FROM ip_allow a LEFT JOIN admin_users x ON x.id=a.admin_id ORDER BY a.created_at DESC') }; }
async function adminIpAllowAdd(ctx, body) {
  const key = ipKey(String(body.ip_key || '').trim()); if (!/^[0-9a-f:.\/]{3,60}$/i.test(key)) throw bad('invalid_ip');
  const note = String(body.note || '').trim().slice(0, 200); if (note.length < 3) throw bad('reason_required', 'Serve una nota (chi è e perché)');
  await ctx.db.batch([st(ctx.db, 'INSERT OR REPLACE INTO ip_allow(ip_key,note,admin_id,created_at) VALUES(?,?,?,?)', key, note, ctx.admin.id, NOW()), auditStmt(ctx.db, ctx.admin.id, 'autorizza_ip', 'ip_allow', null, null, { ip_key: key, note }, ctx.ip)]);
  return { ok: true, ip_key: key };
}
async function adminIpAllowRemove(ctx, body) {
  const key = String(body.ip_key || '').trim(); await ctx.db.batch([st(ctx.db, 'DELETE FROM ip_allow WHERE ip_key=?', key), auditStmt(ctx.db, ctx.admin.id, 'revoca_ip', 'ip_allow', null, { ip_key: key }, null, ctx.ip)]); return { ok: true };
}


/* ---------- 80-admin.js ---------- */
/* ============================ CONSOLE AMMINISTRATORE ============================
   Accesso: email + chiave d'accesso (256 bit, mostrata una sola volta) + codice TOTP.
   Le chiavi sono casuali e lunghe, quindi bastano SHA-256 e il piano gratuito di Cloudflare. */
const ADMIN_ROLES = {
  wd: ['superadmin', 'operatore'],              // eseguire/rifiutare prelievi
  user: ['superadmin', 'operatore', 'supporto'],  // sospendere, note
  money: ['superadmin'],                        // parametri, tesoreria, cambio, assegnazione depositi, admin
};
async function adminSetupStatus(ctx) { // pubblico: dice solo se il primo avvio è ancora possibile
  const n = (await dbOne(ctx.db, 'SELECT COUNT(*) c FROM admin_users')).c;
  const needed = n === 0 && !!ctx.env.BOOTSTRAP_TOKEN;
  return { needed, needs_setup: needed, has_admin: n > 0 };   // 'needed' e 'needs_setup': stesso significato, nomi usati da parti diverse
}
async function adminBootstrap(ctx, body) {
  const env = ctx.env, db = ctx.db;
  await rateLimit(db, 'boot:' + ctx.ip, 10, HOUR);
  if (!env.BOOTSTRAP_TOKEN) throw forbid('bootstrap_disabled');
  if (!timingSafeEq(ctx.req.headers.get('X-Bootstrap') || '', env.BOOTSTRAP_TOKEN)) throw forbid('bad_bootstrap');
  if ((await dbOne(db, 'SELECT COUNT(*) c FROM admin_users')).c > 0) throw conflict('already_bootstrapped');
  const email = normEmail(body.email); if (!validEmail(email)) throw bad('invalid_email');
  const out = await createAdmin(db, email, body.name || 'Admin', 'superadmin', ctx.ip);
  if (!(await dbOne(db, 'SELECT id FROM users WHERE is_dev=1'))) { // account del team: riceve i referral di chi si iscrive senza invito
    const u = await createUser(ctx, { provider: 'email', subject: 'team@degenland.internal', display: 'degenland', ref: null, locale: 'en', accept: true, noPioneer: true });
    await dbRun(db, 'UPDATE users SET is_dev=1 WHERE id=?', u.id);
  }
  return out;
}
async function createAdmin(db, email, name, role, ip, byAdmin) {
  const key = rid(32), secret = b32enc(rndBytes(20));
  await runBatch(db, [st(db, 'INSERT INTO admin_users(email,name,role,key_hash,totp_secret,created_at) VALUES(?,?,?,?,?,?)', email, name, role, await sha256hex(key), secret, NOW()),
    auditStmt(db, byAdmin || null, 'crea_admin', 'admin_users', null, null, { email, role }, ip)]);
  return { email, role, access_key: key, totp_secret: secret, otpauth: `otpauth://totp/DegenLand:${encodeURIComponent(email)}?secret=${secret}&issuer=DegenLand` };
}
async function adminLogin(ctx, body) {
  const db = ctx.db; const email = normEmail(body.email);
  await rateLimit(db, 'adm:ip:' + ctx.ip, 10, 15 * MIN); await rateLimit(db, 'adm:em:' + email, 6, 15 * MIN);
  const a = await dbOne(db, 'SELECT * FROM admin_users WHERE email=? AND active=1', email);
  const okKey = a && timingSafeEq(a.key_hash, await sha256hex(String(body.key || '')));
  const okTotp = a && await totpVerify(a.totp_secret, body.code);
  if (!a || !okKey || !okTotp) throw unauth('bad_credentials', 'Credenziali non valide');
  const token = rid(32), t = NOW();
  await db.batch([st(db, 'INSERT INTO admin_sessions(admin_id,token_hash,ip,created_at,expires_at) VALUES(?,?,?,?,?)', a.id, await sha256hex(token), ctx.ip, t, t + 12 * HOUR),
    st(db, 'UPDATE admin_users SET last_login_at=? WHERE id=?', t, a.id), auditStmt(db, a.id, 'login_admin', 'admin_users', a.id, null, null, ctx.ip)]);
  ctx.setCookie = cookieStr('dl_a', token, { maxAge: 12 * 3600 });
  return { email: a.email, name: a.name, role: a.role };
}
async function adminAuth(ctx, roles) {
  const tok = parseCookies(ctx.req).dl_a; if (!tok) throw unauth();
  const a = await dbOne(ctx.db, `SELECT a.* FROM admin_sessions s JOIN admin_users a ON a.id=s.admin_id WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>? AND a.active=1`, await sha256hex(tok), NOW());
  if (!a) throw unauth();
  if (roles && !roles.includes(a.role)) throw forbid('role_not_allowed', 'Permesso insufficiente');
  if (a.role === 'sola_lettura' && ctx.req.method !== 'GET') throw forbid('read_only');
  ctx.admin = a; return a;
}
async function adminDashboard(ctx) {
  const db = ctx.db, env = ctx.env; const pool = await currentPool(env); const p = await getParams(env, pool.param_set_id); const h = await poolHealth(env, pool, p); const t = NOW();
  const users = (await dbOne(db, 'SELECT COUNT(*) c FROM users')).c;
  const paying = (await dbOne(db, "SELECT COUNT(DISTINCT user_id) c FROM deposits WHERE status='accreditato'")).c;
  const farms = (await dbOne(db, 'SELECT COUNT(*) c FROM farms WHERE on_until>?', t)).c;
  const q = await dbOne(db, "SELECT COUNT(*) c, COALESCE(SUM(lamports),0) s, MIN(created_at) oldest FROM withdrawals WHERE status='attesa'");
  const flagged = (await dbOne(db, "SELECT COUNT(*) c FROM withdrawals WHERE status='attesa' AND risk_score>0")).c;
  const unmatched = (await dbOne(db, "SELECT COUNT(*) c FROM deposits WHERE status='non_abbinato'")).c;
  const flows = await dbAll(db, `SELECT x.kind, SUM(e.amount) amount FROM ledger_entries e JOIN ledger_tx x ON x.id=e.tx_id JOIN accounts a ON a.id=e.account_id
    WHERE a.system_code='pool_sol' AND x.created_at>? GROUP BY x.kind`, t - 30 * DAY);
  const fx = await getFx(env);
  return { pool: { number: pool.number, status: pool.status, blocks: pool.blocks, halvings: pool.halvings, close_at: p.close_blocks }, health: h, users, paying, active_farms: farms,
    queue: { pending: q.c, lamports: q.s, oldest: q.oldest, flagged }, unmatched_deposits: unmatched, flows_30d: flows, sol_usd: fx };
}
async function adminWithdrawals(ctx, url) {
  const status = url.searchParams.get('status') || 'attesa';
  const rows = await dbAll(ctx.db, `SELECT w.*, u.nickname, u.created_at user_created,
      (SELECT COUNT(*) FROM farm_starts f WHERE f.user_id=u.id) starts
    FROM withdrawals w JOIN users u ON u.id=w.user_id WHERE w.status=? ORDER BY w.id ASC LIMIT 200`, status);
  rows.forEach(r => r.risk_flags = JSON.parse(r.risk_flags || '[]')); return { withdrawals: rows };
}
async function adminUsers(ctx, url) {
  const q = (url.searchParams.get('q') || '').trim(); const f = url.searchParams.get('filter') || 'all'; const args = []; let where = '1=1';
  if (q) { where += ' AND (u.nickname LIKE ? OR EXISTS(SELECT 1 FROM identities i WHERE i.user_id=u.id AND (i.subject LIKE ? OR i.display LIKE ?)) OR EXISTS(SELECT 1 FROM ip_events e WHERE e.user_id=u.id AND e.ip=?) OR u.id=?)'; args.push(`%${q}%`, `%${q}%`, `%${q}%`, q, +q || -1); }
  if (f === 'sospesi') where += " AND u.status='sospeso'";
  if (f === 'segnalati') where += ' AND EXISTS(SELECT 1 FROM risk_flags r WHERE r.user_id=u.id AND r.resolved_at IS NULL)';
  const rows = await dbAll(ctx.db, `SELECT u.id, u.nickname, u.status, u.created_at, u.last_seen_at, u.referrer_id,
      (SELECT COALESCE(SUM(lamports),0) FROM deposits d WHERE d.user_id=u.id AND d.status='accreditato') deposited,
      (SELECT COALESCE(SUM(lamports),0) FROM withdrawals w WHERE w.user_id=u.id AND w.status='eseguito') withdrawn,
      (SELECT b.amount FROM accounts a JOIN balances b ON b.account_id=a.id WHERE a.owner_id=u.id AND a.asset='SOL') sol,
      (SELECT COUNT(*) FROM miners m WHERE m.owner_id=u.id AND m.state<>'rottamato') miners
    FROM users u WHERE ${where} ORDER BY u.id DESC LIMIT 100`, ...args);
  return { users: rows };
}
async function adminUserDetail(ctx, id) {
  const db = ctx.db; const u = await dbOne(db, 'SELECT * FROM users WHERE id=?', id); if (!u) throw notfound('user_not_found');
  const ips = await dbAll(db, 'SELECT ip, COUNT(*) n, MAX(created_at) last FROM ip_events WHERE user_id=? GROUP BY ip', id);
  const shared = []; for (const r of ips) { const o = await dbAll(db, 'SELECT DISTINCT u.id, u.nickname FROM ip_events e JOIN users u ON u.id=e.user_id WHERE e.ip=? AND e.user_id<>?', r.ip, id); if (o.length) shared.push({ ip: r.ip, users: o }); }
  return { user: u, identities: await dbAll(db, 'SELECT provider, subject, display, chat_ok FROM identities WHERE user_id=?', id), balances: await balancesOf(db, id),
    addresses: await dbAll(db, 'SELECT address, is_current, locked_until, created_at FROM addresses WHERE user_id=? ORDER BY id DESC', id),
    miners: await dbAll(db, "SELECT id, model_id, state, generation, worked_blocks, broken, paid_milli FROM miners WHERE owner_id=? AND state<>'rottamato'", id),
    withdrawals: await dbAll(db, 'SELECT id, lamports, status, risk_flags, created_at, reject_reason FROM withdrawals WHERE user_id=? ORDER BY id DESC LIMIT 20', id),
    deposits: await dbAll(db, 'SELECT lamports, token_milli, credited_at FROM deposits WHERE user_id=? ORDER BY id DESC LIMIT 20', id),
    pioneer_no: (await dbOne(db, 'SELECT no FROM pioneers WHERE user_id=?', id) || {}).no || null, referred: (await dbOne(db, 'SELECT COUNT(*) c FROM users WHERE referrer_id=?', id)).c, referrer: u.referrer_id ? (await dbOne(db, 'SELECT id, nickname FROM users WHERE id=?', u.referrer_id)) : null,
    ips, shared_ips: shared, notes: await dbAll(db, 'SELECT n.body, n.created_at, a.name FROM admin_notes n JOIN admin_users a ON a.id=n.admin_id WHERE n.user_id=? ORDER BY n.id DESC', id) };
}
async function adminUserAction(ctx, id, action, body) {
  const db = ctx.db, a = ctx.admin; const u = await dbOne(db, 'SELECT * FROM users WHERE id=?', id); if (!u) throw notfound('user_not_found');
  if (u.is_dev) throw bad('dev_account_protected');
  if (['ban', 'revoke_pioneer', 'grant_pioneer', 'hold', 'unhold'].includes(action) && !ADMIN_ROLES.wd.includes(a.role)) throw forbid('role_not_allowed', 'Permesso insufficiente per questa azione');
  if (action === 'ban') { const why = String(body.reason || '').trim(); if (why.length < 3) throw bad('reason_required', 'Serve un motivo');
    await db.batch([st(db, "UPDATE users SET status='chiuso', suspended_reason=? WHERE id=?", why.slice(0, 200), id), st(db, 'UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL', NOW(), id), ...pioneerRevokeStmts(db, id),
      auditStmt(db, a.id, 'banna_utente', 'users', id, { status: u.status }, { status: 'chiuso', reason: why.slice(0, 200) }, ctx.ip)]); _cache.stats = null; _cache.lb = {}; }
  else if (action === 'revoke_pioneer') { await db.batch([...pioneerRevokeStmts(db, id), auditStmt(db, a.id, 'revoca_pioniere', 'users', id, null, { reason: String(body.reason || '').slice(0, 120) }, ctx.ip)]); _cache.stats = null; }
  else if (action === 'grant_pioneer') { const no = await pioneerGrant(ctx, id); await dbRun(db, 'INSERT INTO audit_log(admin_id,action,target_table,target_id,after,ip,created_at) VALUES(?,?,?,?,?,?,?)', a.id, 'assegna_pioniere', 'users', id, JSON.stringify({ no }), ctx.ip, NOW()); }
  else if (action === 'hold' || action === 'unhold') { await db.batch([st(db, 'UPDATE users SET wd_hold=? WHERE id=?', action === 'hold' ? 1 : 0, id), auditStmt(db, a.id, action === 'hold' ? 'sospendi_prelievi' : 'riattiva_prelievi', 'users', id, null, { reason: String(body.reason || '').slice(0, 120) }, ctx.ip)]); }
  else if (action === 'suspend') { await db.batch([st(db, "UPDATE users SET status='sospeso', suspended_reason=? WHERE id=?", String(body.reason || '').slice(0, 200) || null, id), st(db, 'UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL', NOW(), id), auditStmt(db, a.id, 'sospendi_utente', 'users', id, { status: u.status }, { status: 'sospeso', reason: body.reason }, ctx.ip)]); }
  else if (action === 'reactivate') { await db.batch([st(db, "UPDATE users SET status='attivo', suspended_reason=NULL WHERE id=?", id), auditStmt(db, a.id, 'riattiva_utente', 'users', id, { status: u.status }, { status: 'attivo' }, ctx.ip)]); }
  else if (action === 'rename') { const nick = validNick(body.nickname); try { await db.batch([st(db, 'UPDATE users SET nickname=?, nick_changed_at=NULL WHERE id=?', nick, id), auditStmt(db, a.id, 'rinomina_utente', 'users', id, { nickname: u.nickname }, { nickname: nick, reason: String(body.reason || '').slice(0, 120) }, ctx.ip)]); } catch (e) { if (String(e.message).includes('users.nickname')) throw conflict('nickname_taken'); throw e; } }
  else if (action === 'note') { if (!String(body.body || '').trim()) throw bad('empty_note'); await db.batch([st(db, 'INSERT INTO admin_notes(user_id,admin_id,body,created_at) VALUES(?,?,?,?)', id, a.id, String(body.body).slice(0, 1000), NOW()), auditStmt(db, a.id, 'nota_utente', 'users', id, null, null, ctx.ip)]); }
  else throw notfound('action');
  return { ok: true };
}
async function adminAdjust(ctx, id, body) { // rettifica di saldo: sempre con motivo, sempre nel registro
  const db = ctx.db, a = ctx.admin; const u = await dbOne(db, 'SELECT * FROM users WHERE id=?', id); if (!u) throw notfound('user_not_found');
  const asset = body.asset; if (!['SOL', 'TOKEN'].includes(asset)) throw bad('invalid_asset');
  const amount = asset === 'SOL' ? Math.round(+body.amount * LAMPORTS) : Math.round(+body.amount * 1000);
  const cap = asset === 'SOL' ? 100 * LAMPORTS : 1e9;
  if (!isInt(amount) || amount === 0 || Math.abs(amount) > cap) throw bad('invalid_amount');
  const reason = String(body.reason || '').trim(); if (reason.length < 3) throw bad('reason_required', 'Serve un motivo');
  const accs = await userAccs(ctx, id); const src = await sysAcc(db, asset === 'SOL' ? 'pool_sol' : 'token_mint', asset);
  await runBatch(db, [...ledgerStmts(db, 'rettifica', [{ acc: src, asset, amt: -amount }, { acc: accs[asset], asset, amt: amount }], { admin: a.id, memo: reason.slice(0, 200) }),
    auditStmt(db, a.id, 'rettifica_saldo', 'users', id, null, { asset, amount, reason: reason.slice(0, 200) }, ctx.ip)]);
  return { ok: true, balance: (await balancesOf(db, id))[asset] };
}
async function adminTeamInfo(ctx) {
  const db = ctx.db; const u = await dbOne(db, 'SELECT id, nickname, status FROM users WHERE is_dev=1'); if (!u) return { team: null };
  const idn = await dbOne(db, "SELECT subject FROM identities WHERE user_id=? AND provider='email'", u.id);
  const earned = await dbAll(db, 'SELECT asset, SUM(amount) s FROM referral_earnings WHERE referrer_id=? GROUP BY asset', u.id);
  const invited = (await dbOne(db, 'SELECT COUNT(*) c FROM users WHERE referrer_id=?', u.id)).c;
  const addr = await dbOne(db, 'SELECT address FROM addresses WHERE user_id=? AND is_current=1', u.id);
  return { team: { id: u.id, nickname: u.nickname, email: idn ? idn.subject : null, internal: !idn || idn.subject.endsWith('@degenland.internal'),
    balances: await balancesOf(db, u.id), earned: Object.fromEntries(earned.map(r => [r.asset, r.s])), invited, address: addr ? addr.address : null } };
}
async function adminTeamEmail(ctx, body) { // collega all'account del team un indirizzo email vero (per poter entrare e prelevare come un giocatore)
  const db = ctx.db, email = normEmail(body.email);
  if (!validEmail(email) || email.endsWith('@degenland.internal')) throw bad('invalid_email');
  const u = await dbOne(db, 'SELECT id FROM users WHERE is_dev=1'); if (!u) throw notfound('team_not_found');
  const other = await dbOne(db, "SELECT user_id FROM identities WHERE provider='email' AND subject=? AND user_id<>?", email, u.id); if (other) throw conflict('identity_in_use', 'Questa email appartiene già a un altro account');
  const cur = await dbOne(db, "SELECT subject FROM identities WHERE user_id=? AND provider='email'", u.id);
  await db.batch([cur ? st(db, "UPDATE identities SET subject=?, display=?, verified_at=? WHERE user_id=? AND provider='email'", email, email.split('@')[0], NOW(), u.id)
      : st(db, "INSERT INTO identities(user_id,provider,subject,display,verified_at,created_at) VALUES(?,'email',?,?,?,?)", u.id, email, email.split('@')[0], NOW(), NOW()),
    auditStmt(db, ctx.admin.id, 'email_account_team', 'users', u.id, { email: cur ? cur.subject : null }, { email }, ctx.ip)]);
  return { ok: true };
}
async function adminPool(ctx) {
  const db = ctx.db, env = ctx.env; const pool = await currentPool(env); const p = await getParams(env, pool.param_set_id);
  return { pool, params_id: pool.param_set_id, health: await poolHealth(env, pool, p), events: await dbAll(db, 'SELECT * FROM pool_events ORDER BY id DESC LIMIT 30'),
    seasons: await dbAll(db, "SELECT p.number, p.status, p.blocks, p.halvings, p.scrap_pct, p.opened_at, p.closed_at, (SELECT COALESCE(SUM(credit_milli),0) FROM scrap_credits s WHERE s.pool_id=p.id) scrap_milli FROM pools p ORDER BY p.id DESC LIMIT 12"),
    snapshots: await dbAll(db, 'SELECT * FROM treasury_snapshots ORDER BY day DESC LIMIT 60'), treasury: await dbAll(db, 'SELECT * FROM treasury_movements ORDER BY id DESC LIMIT 30') };
}
async function pendingParams(db) {
  const n = await dbOne(db, "SELECT value FROM meta WHERE key='next_param_set'"); if (!n) return null;
  const r = await dbOne(db, 'SELECT id,label,data,created_at FROM param_sets WHERE id=?', +n.value); if (!r) return null;
  return { id: r.id, label: r.label, created_at: r.created_at, data: Object.assign({}, DEFAULT_PARAMS, JSON.parse(r.data)) };
}
async function adminGetParams(ctx) {
  const pool = await currentPool(ctx.env);
  return { current: await getParams(ctx.env, pool.param_set_id), pending: await pendingParams(ctx.db), pool: { id: pool.id, number: pool.number, param_set_id: pool.param_set_id },
    sets: await dbAll(ctx.db, 'SELECT id,label,created_at FROM param_sets ORDER BY id DESC LIMIT 20') };
}
async function adminSetParams(ctx, body) {
  // le modifiche partono dai parametri già in attesa (se ci sono), così due salvataggi di fila non si annullano
  const db = ctx.db, a = ctx.admin; const pool = await currentPool(ctx.env); const pend = await pendingParams(db);
  const cur = pend ? pend.data : await getParams(ctx.env, pool.param_set_id);
  const data = Object.assign({}, cur, body.data || {}); const now = !!body.apply_now;
  if (!Array.isArray(data.miners) || data.miners.length !== 6) throw bad('invalid_miners');
  for (const m of data.miners) if (!(m.price_sol > 0) || !(m.payback > 0)) throw bad('invalid_miners');
  if (!(data.repair_pct >= 0 && data.repair_pct <= 1) || !(data.scrap_max >= data.scrap_min && data.scrap_max <= 1) || !(data.referral_pct >= 0 && data.referral_pct <= 0.5)) throw bad('invalid_params');
  if (!Array.isArray(data.halving_blocks) || data.halving_blocks.length !== 3 || data.close_blocks <= data.halving_blocks[2]) throw bad('invalid_halvings');
  const t = NOW();
  const s = [st(db, 'INSERT INTO param_sets(label,data,created_by,created_at) VALUES(?,?,?,?)', String(body.label || 'Parametri').slice(0, 80), JSON.stringify(data), a.id, t)];
  if (now) s.push(st(db, 'UPDATE pools SET param_set_id=(SELECT MAX(id) FROM param_sets) WHERE id=?', pool.id), st(db, "DELETE FROM meta WHERE key='next_param_set'"));
  else s.push(st(db, "INSERT OR REPLACE INTO meta(key,value) VALUES('next_param_set',(SELECT MAX(id) FROM param_sets))"));
  s.push(auditStmt(db, a.id, now ? 'parametri_subito' : 'modifica_parametri', 'param_sets', null, null, { label: body.label, pool: now ? pool.number : 'prossima' }, ctx.ip));
  await db.batch(s); invalidateCaches();
  return { ok: true, applies_from: now ? 'subito' : 'prossima pool' };
}
async function adminApplyPending(ctx) {
  const db = ctx.db, pend = await pendingParams(db); if (!pend) throw notfound('no_pending', 'Nessuna modifica in attesa');
  const pool = await currentPool(ctx.env);
  await db.batch([st(db, 'UPDATE pools SET param_set_id=? WHERE id=?', pend.id, pool.id), st(db, "DELETE FROM meta WHERE key='next_param_set'"),
    auditStmt(db, ctx.admin.id, 'parametri_subito', 'param_sets', pend.id, null, { label: pend.label, pool: pool.number }, ctx.ip)]);
  invalidateCaches(); return {};
}
async function adminDiscardPending(ctx) {
  const db = ctx.db, pend = await pendingParams(db); if (!pend) throw notfound('no_pending', 'Nessuna modifica in attesa');
  await db.batch([st(db, "DELETE FROM meta WHERE key='next_param_set'"), auditStmt(db, ctx.admin.id, 'parametri_annullati', 'param_sets', pend.id, null, { label: pend.label }, ctx.ip)]);
  return {};
}
async function adminTreasury(ctx, body) {
  const db = ctx.db, a = ctx.admin; const kind = body.kind; const lam = Math.floor(+body.lamports);
  if (!['rendimento', 'ricavi_extra', 'spostamento'].includes(kind)) throw bad('invalid_kind'); if (!isInt(lam) || lam <= 0) throw bad('invalid_amount');
  const s = [st(db, 'INSERT INTO treasury_movements(kind,lamports,tx_signature,admin_id,note,created_at) VALUES(?,?,?,?,?,?)', kind, lam, body.tx || null, a.id, String(body.note || '').slice(0, 200) || null, NOW()), auditStmt(db, a.id, 'tesoreria_' + kind, 'treasury_movements', null, null, { lam }, ctx.ip)];
  if (kind !== 'spostamento') { const ext = await sysAcc(db, 'external_sol', 'SOL'), pool = await sysAcc(db, 'pool_sol', 'SOL'); s.push(...ledgerStmts(db, 'tesoreria_' + kind, [{ acc: ext, asset: 'SOL', amt: -lam }, { acc: pool, asset: 'SOL', amt: lam }], { admin: a.id })); }
  await db.batch(s); return { ok: true };
}
async function adminDeposits(ctx, url) { return { deposits: await dbAll(ctx.db, 'SELECT * FROM deposits WHERE status=? ORDER BY id DESC LIMIT 100', url.searchParams.get('status') || 'non_abbinato') }; }
async function adminAssignDeposit(ctx, id, body) {
  const d = await dbOne(ctx.db, "SELECT * FROM deposits WHERE id=? AND status='non_abbinato'", id); if (!d) throw notfound('deposit_not_found');
  const u = await dbOne(ctx.db, 'SELECT id FROM users WHERE id=?', body.user_id); if (!u) throw notfound('user_not_found');
  await creditDeposit(ctx, { signature: d.signature, lamports: d.lamports, sender: d.sender, userId: u.id, adminId: ctx.admin.id, existingId: d.id });
  await dbRun(ctx.db, 'INSERT INTO audit_log(admin_id,action,target_table,target_id,after,ip,created_at) VALUES(?,?,?,?,?,?,?)', ctx.admin.id, 'assegna_deposito', 'deposits', id, JSON.stringify({ user: u.id }), ctx.ip, NOW());
  return { ok: true };
}
async function adminSetFx(ctx, body) {
  const v = +body.sol_usd; if (!(v > 1 && v < 10000)) throw bad('invalid_rate');
  await ctx.db.batch([st(ctx.db, "INSERT INTO fx_rates(sol_usd,source,reason,valid_from) VALUES(?,?,?,?)", v, 'admin', 'manuale', NOW()), auditStmt(ctx.db, ctx.admin.id, 'cambio_manuale', 'fx_rates', null, null, { v }, ctx.ip)]); invalidateCaches(); return { ok: true };
}
async function adminForceClose(ctx) {
  const env = ctx.env, db = ctx.db; const pool = await currentPool(env); if (pool.status !== 'attiva') throw conflict('not_active'); const p = await getParams(env, pool.param_set_id);
  await db.batch([st(db, 'UPDATE pools SET blocks=? WHERE id=?', Math.max(pool.blocks, p.close_blocks), pool.id), auditStmt(db, ctx.admin.id, 'chiusura_forzata', 'pools', pool.id, null, null, ctx.ip)]);
  await checkPoolThresholds(ctx); let r; do { r = await processClosing(ctx, 50); } while (!r.done); return { ok: true };
}
async function adminAudit(ctx) { return { audit: await dbAll(ctx.db, 'SELECT l.*, a.name FROM audit_log l LEFT JOIN admin_users a ON a.id=l.admin_id ORDER BY l.id DESC LIMIT 200') }; }


/* ---------- 99-router.js ---------- */
/* ============================ ROUTER ============================ */
const P = (m, path, fn, auth, roles) => ({ m, re: new RegExp('^' + path.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'), fn, auth, roles: roles || null });
const ROUTES = [
  // pubbliche
  P('GET', '/api/config', async c => ({ telegram_bot: c.env.TELEGRAM_BOT_USERNAME || null, turnstile_site_key: c.env.TURNSTILE_SITE_KEY || null, deposits: !!c.env.TREASURY_ADDRESS, signups_closed: signupsClosed(c.env), email: !!(c.env.RESEND_API_KEY || c.env.DEV_MODE === '1') })),
  P('POST', '/api/auth/email/start', (c, b) => emailStart(c, b)),
  P('POST', '/api/auth/email/verify', async (c, b) => { const u = await emailVerify(c, b); return { nickname: u.nickname }; }),
  P('POST', '/api/auth/telegram', async (c, b) => { const u = await telegramLogin(c, b); return { nickname: u.nickname }; }),
  P('POST', '/api/auth/logout', async c => { const tok = parseCookies(c.req).dl_s; if (tok) await dbRun(c.db, 'UPDATE sessions SET revoked_at=? WHERE token_hash=?', NOW(), await sha256hex(tok)); c.setCookie = cookieStr('dl_s', '', { maxAge: 0 }); return {}; }),
  // giocatore
  P('GET', '/api/public/stats', c => publicStats(c)),
  P('GET', '/api/state', c => buildState(c), 'user'),
  P('POST', '/api/account/nickname', (c, b) => setNickname(c, b), 'user'),
  P('GET', '/api/leaderboard', c => leaderboardPublic(c, c.url), 'user'),
  P('GET', '/api/referrals', c => referralsList(c), 'user'),
  P('POST', '/api/ad/begin', (c, b) => adBegin(c, b), 'user'),
  P('POST', '/api/ad/click', (c, b) => adClick(c, b), 'user'),
  P('GET', '/api/adv/info', c => advInfo(c)),
  P('POST', '/api/adv/request', (c, b) => advRequest(c, b)),
  P('GET', '/api/adv/status', c => advStatus(c, c.url)),
  P('GET', '/api/admin/adv', c => adminAdvList(c, c.url), 'admin'),
  P('POST', '/api/admin/adv/:id/approve', (c, b) => adminAdvApprove(c, +c.params.id, b), 'admin', ADMIN_ROLES.wd),
  P('POST', '/api/admin/adv/:id/reject', (c, b) => adminAdvReject(c, +c.params.id, b), 'admin', ADMIN_ROLES.wd),
  P('POST', '/api/admin/adv/:id/set', (c, b) => adminAdvSet(c, +c.params.id, b), 'admin', ADMIN_ROLES.wd),
  P('POST', '/api/farm/start', (c, b) => farmStart(c, b), 'user'),
  P('POST', '/api/tap', (c, b) => tap(c, b), 'user'),
  P('POST', '/api/energy/recharge', (c, b) => energyRecharge(c, b), 'user'),
  P('POST', '/api/mode', (c, b) => setMode(c, b), 'user'),
  P('POST', '/api/shop/miner', (c, b) => buyMiner(c, b), 'user'),
  P('POST', '/api/shop/rack', c => buyRack(c), 'user'),
  P('POST', '/api/shop/extension', (c, b) => buyExtension(c, b), 'user'),
  P('POST', '/api/miner/install', (c, b) => installMiner(c, b), 'user'),
  P('POST', '/api/miner/uninstall', (c, b) => uninstallMiner(c, b), 'user'),
  P('POST', '/api/miner/repair', (c, b) => repairMiner(c, b), 'user'),
  P('GET', '/api/market', c => marketBrowse(c), 'user'),
  P('POST', '/api/market/list', (c, b) => marketList(c, b), 'user'),
  P('POST', '/api/market/cancel', (c, b) => marketCancel(c, b), 'user'),
  P('POST', '/api/market/buy', (c, b) => marketBuy(c, b), 'user'),
  P('POST', '/api/wallet/convert', (c, b) => convertSol(c, b), 'user'),
  P('POST', '/api/wallet/address', (c, b) => setAddress(c, b), 'user'),
  P('POST', '/api/wallet/withdraw', (c, b) => withdrawRequest(c, b), 'user'),
  P('POST', '/api/wallet/withdraw/cancel', (c, b) => withdrawCancel(c, b), 'user'),
  P('POST', '/api/deposit/intent', (c, b) => depositIntent(c, b), 'user'),
  P('GET', '/api/deposit/status', c => depositStatus(c), 'user'),
  P('POST', '/api/account/settings', (c, b) => accountSettings(c, b), 'user'),
  P('POST', '/api/account/link/email/start', (c, b) => emailStart(c, b), 'user'),
  P('POST', '/api/account/link/email/verify', async (c, b) => { const e = await consumeEmailCode(c, b.email, b.code); await linkIdentity(c, 'email', e, e); return { ok: true }; }, 'user'),
  P('POST', '/api/account/link/telegram', async (c, b) => { const t = await verifyTelegram(c.env, b.data || b); await linkIdentity(c, 'telegram', t.id, t.username || t.name); return { ok: true }; }, 'user'),
  P('POST', '/api/account/telegram/link-code', c => telegramLinkCode(c), 'user'),
  // Telegram bot
  P('POST', '/api/telegram/webhook/:secret', async (c, b) => {
    const s = c.env.TELEGRAM_WEBHOOK_SECRET; if (!s || !timingSafeEq(c.params.secret, s) || !timingSafeEq(c.req.headers.get('X-Telegram-Bot-Api-Secret-Token') || s, s)) throw forbid();
    try { await telegramWebhook(c, b); } catch (e) { console.error('webhook', e && e.message); } return {};
  }),
  // console amministratore
  P('GET', '/api/admin/setup', c => adminSetupStatus(c)),
  P('POST', '/api/admin/bootstrap', (c, b) => adminBootstrap(c, b)),
  P('POST', '/api/admin/login', (c, b) => adminLogin(c, b)),
  P('POST', '/api/admin/logout', async c => { const tok = parseCookies(c.req).dl_a; if (tok) await dbRun(c.db, 'UPDATE admin_sessions SET revoked_at=? WHERE token_hash=?', NOW(), await sha256hex(tok)); c.setCookie = cookieStr('dl_a', '', { maxAge: 0 }); return {}; }),
  P('GET', '/api/admin/me', async c => ({ email: c.admin.email, name: c.admin.name, role: c.admin.role }), 'admin'),
  P('GET', '/api/admin/dashboard', c => adminDashboard(c), 'admin'),
  P('GET', '/api/admin/withdrawals', c => adminWithdrawals(c, c.url), 'admin'),
  P('POST', '/api/admin/withdrawals/:id/execute', (c, b) => wdExecute(c.env, c.admin.id, +c.params.id, b.tx, c.ip), 'admin', ADMIN_ROLES.wd),
  P('POST', '/api/admin/withdrawals/:id/reject', (c, b) => wdReject(c.env, c.admin.id, +c.params.id, b.reason, b.suspend, c.ip), 'admin', ADMIN_ROLES.wd),
  P('GET', '/api/admin/users', c => adminUsers(c, c.url), 'admin'),
  P('GET', '/api/admin/users/:id', c => adminUserDetail(c, +c.params.id), 'admin'),
  P('POST', '/api/admin/users/:id/adjust', (c, b) => adminAdjust(c, +c.params.id, b), 'admin', ADMIN_ROLES.money),
  P('POST', '/api/admin/users/:id/:action', (c, b) => adminUserAction(c, +c.params.id, c.params.action, b), 'admin', ADMIN_ROLES.user),
  P('GET', '/api/admin/pool', c => adminPool(c), 'admin'),
  P('GET', '/api/admin/pioneers', c => adminPioneers(c), 'admin'),
  P('GET', '/api/admin/ip-conflicts', c => adminIpConflicts(c), 'admin'),
  P('GET', '/api/admin/ip-allow', c => adminIpAllowList(c), 'admin'),
  P('POST', '/api/admin/ip-allow', (c, b) => adminIpAllowAdd(c, b), 'admin', ADMIN_ROLES.wd),
  P('POST', '/api/admin/ip-allow/remove', (c, b) => adminIpAllowRemove(c, b), 'admin', ADMIN_ROLES.wd),
  P('GET', '/api/admin/leaderboard', c => adminLeaderboard(c, c.url), 'admin'),
  P('GET', '/api/admin/team', c => adminTeamInfo(c), 'admin'),
  P('POST', '/api/admin/team/email', (c, b) => adminTeamEmail(c, b), 'admin', ADMIN_ROLES.money),
  P('GET', '/api/admin/params', c => adminGetParams(c), 'admin'),
  P('POST', '/api/admin/params', (c, b) => adminSetParams(c, b), 'admin', ADMIN_ROLES.money),
  P('POST', '/api/admin/params/apply-pending', (c) => adminApplyPending(c), 'admin', ADMIN_ROLES.money),
  P('POST', '/api/admin/params/discard-pending', (c) => adminDiscardPending(c), 'admin', ADMIN_ROLES.money),
  P('POST', '/api/admin/treasury', (c, b) => adminTreasury(c, b), 'admin', ADMIN_ROLES.money),
  P('GET', '/api/admin/deposits', c => adminDeposits(c, c.url), 'admin'),
  P('POST', '/api/admin/deposits/:id/assign', (c, b) => adminAssignDeposit(c, +c.params.id, b), 'admin', ADMIN_ROLES.money),
  P('POST', '/api/admin/fx', (c, b) => adminSetFx(c, b), 'admin', ADMIN_ROLES.money),
  P('POST', '/api/admin/pool/force-close', c => adminForceClose(c), 'admin', ADMIN_ROLES.money),
  P('POST', '/api/admin/admins', async (c, b) => { const email = normEmail(b.email); if (!validEmail(email)) throw bad('invalid_email'); if (!['superadmin', 'operatore', 'supporto', 'sola_lettura'].includes(b.role)) throw bad('invalid_role'); return createAdmin(c.db, email, b.name || email, b.role, c.ip, c.admin.id); }, 'admin', ADMIN_ROLES.money),
  P('GET', '/api/admin/audit', c => adminAudit(c), 'admin'),
];

async function handleApi(request, env, evt) {
  const url = new URL(request.url); const headers = {};
  const ctx = { env, db: env.DB, req: request, url, ip: ipOf(request), setCookie: null, params: {} };
  try {
    await ensureSchema(env);
    let route = null;
    for (const r of ROUTES) { if (r.m !== request.method) continue; const m = url.pathname.match(r.re); if (m) { route = r; ctx.params = m.groups || {}; break; } }
    if (!route) throw notfound('no_route');
    if (request.method !== 'GET') { // difesa CSRF: intestazione personalizzata + Origin coerente
      if (!request.headers.get('X-DL')) throw forbid('csrf');
      const o = request.headers.get('Origin'); if (o && new URL(o).host !== url.host) throw forbid('csrf');
    }
    if (route.auth === 'user') await authUser(ctx);
    if (route.auth === 'admin') await adminAuth(ctx, route.roles);
    const body = request.method === 'GET' ? {} : await readJson(request);
    const out = await route.fn(ctx, body);
    if (ctx.setCookie) headers['Set-Cookie'] = ctx.setCookie;
    if (ctx.cacheControl) headers['Cache-Control'] = ctx.cacheControl;
    if (route.auth === 'user' && evt && evt.waitUntil) evt.waitUntil(tick(ctx));
    return json({ ok: true, ...(out || {}) }, 200, headers);
  } catch (e) {
    if (e instanceof HttpError) return json({ ok: false, error: e.code, message: e.message }, e.status, ctx.setCookie ? { 'Set-Cookie': ctx.setCookie } : {});
    console.error('errore interno', e && e.stack || e);
    return json({ ok: false, error: 'internal', message: 'Errore interno' }, 500);
  }
}

/* ============================ MANUTENZIONE ============================
   Variabile MAINTENANCE=1 (Cloudflare, poi nuovo deploy): sito e gioco mostrano la pagina di
   manutenzione (HTTP 503) e le API di gioco rispondono 'maintenance'. Restano attivi la console
   (/console/ e /api/admin/*) e i file in /assets/. Con MAINTENANCE_KEY impostata, chi apre
   /?maint=CHIAVE riceve un cookie e vede il sito normale per provarlo (/?maint=off lo toglie). */
async function maintenanceGate(request, env, url) {
  if (env.MAINTENANCE !== '1') return null;
  const p = url.pathname, key = env.MAINTENANCE_KEY || '';
  if (p.startsWith('/assets/') || p.startsWith('/console') || p.startsWith('/api/admin/') || p === '/maintenance' || p === '/maintenance.html' || p === '/robots.txt' || p === '/favicon.ico') return null;
  const q = url.searchParams.get('maint');
  if (q != null) {
    const clean = new URL(url); clean.searchParams.delete('maint');
    const ok = key && timingSafeEq(q, key);
    const cookie = ok ? cookieStr('dl_mk', key, { maxAge: 12 * 3600 }) : cookieStr('dl_mk', '', { maxAge: 0 });
    return new Response(null, { status: 302, headers: { Location: clean.pathname + clean.search, 'Set-Cookie': cookie, 'Cache-Control': 'no-store' } });
  }
  if (key && timingSafeEq(parseCookies(request).dl_mk || '', key)) return null;
  const head = { 'Cache-Control': 'no-store', 'Retry-After': '1800' };
  if (p.startsWith('/api/')) return new Response(JSON.stringify({ ok: false, error: 'maintenance', message: 'Manutenzione in corso' }), { status: 503, headers: { ...head, 'Content-Type': 'application/json; charset=utf-8' } });
  if (!env.ASSETS) return new Response('Maintenance', { status: 503, headers: head });
  const page = await env.ASSETS.fetch(new Request(new URL('/maintenance', url).toString(), { headers: { Accept: 'text/html' } }));
  return new Response(page.body, { status: 503, headers: { ...head, 'Content-Type': 'text/html; charset=utf-8' } });
}
export default {
  async fetch(request, env, evt) {
    const url = new URL(request.url);
    if (env.CANONICAL_HOST && url.hostname.endsWith('.pages.dev') && url.hostname !== env.CANONICAL_HOST) { url.hostname = env.CANONICAL_HOST; url.port = ''; return Response.redirect(url.toString(), 301); }   // un solo indirizzo pubblico
    const m = await maintenanceGate(request, env, url); if (m) return m;
    if (url.pathname.startsWith('/api/')) return handleApi(request, env, evt);
    if (env.ASSETS) return env.ASSETS.fetch(request);
    return new Response('Not found', { status: 404 });
  },
};
export const __t = { clearCaches: () => { _cache.lb = {}; _cache.stats = null; }, resetSchemaReady: () => { SCHEMA_READY = false; }, guard, runBatch, st, NOW, ensureSchema, dbAll, dbOne, dbRun, tick, settle, computeSettlement, poolHealth, checkPoolThresholds, processClosing, fxTick, checkDeposits, flushNotifications, balancesOf, priceMilli, tokMilli, getParams, getFx, currentPool, invalidateCaches, ledgerStmts, totpAt, b32enc, isSolAddress, b58enc, rndBytes, handleApi, SCHEMA, DEFAULT_PARAMS, userAccs, sysAcc, LAMPORTS, DAY, HOUR, MIN };

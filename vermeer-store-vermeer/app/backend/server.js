/* ═══════════════════════════════════════════════════════════════════
   Vermeer Backend – v1.0.0
   - Envelope encryption (password→scrypt→KEK→DEK→AES-256-GCM)
   - User hierarchy: admin → user (Hauptbenutzer) → observer (Beobachter)
   - Family/group key per main user: albums granted to observers are
     re-encrypted with the owner's family DEK (wrapped per person)
   - Hidden albums with 4-digit PIN (visibility lock, server-enforced)
   - In-app ZIP export of own photos
   ═══════════════════════════════════════════════════════════════════ */
const express = require('express');
const multer  = require('multer');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');
const session = require('express-session');
const bcrypt  = require('bcryptjs');
const sharp   = require('sharp');
const archiver = require('archiver');
const FileStore = require('session-file-store')(session);

const app  = express();
const PORT = process.env.PORT || 3000;
const APP_VERSION = '1.6.0';

const DATA_DIR     = process.env.DATA_DIR || '/data';
const PHOTOS_DIR   = path.join(DATA_DIR, 'photos');
const THUMBS_DIR   = path.join(DATA_DIR, 'thumbs');
const DB_FILE      = path.join(DATA_DIR, 'db.json');
const SESSIONS_DIR = path.join(DATA_DIR, 'sessions');
[PHOTOS_DIR, THUMBS_DIR, SESSIONS_DIR].forEach(d => fs.mkdirSync(d, { recursive: true }));

// ─── Crypto ───────────────────────────────────────────────────────
function deriveLegacyKey(seed) {
  if (!seed) { console.warn('WARNING: No ENCRYPTION_KEY – ephemeral key!'); return crypto.randomBytes(32); }
  if (seed.length === 64) return Buffer.from(seed, 'hex');
  return crypto.createHash('sha256').update(seed).digest();
}
const LEGACY_KEY = deriveLegacyKey(process.env.ENCRYPTION_KEY);
const SHARED_KEY = crypto.createHash('sha256').update(LEGACY_KEY).update('vermeer-shared-v1').digest();

const SCRYPT_OPTS = { N: 2 ** 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 };
function kdf(secret, saltHex) {
  return crypto.scryptSync(String(secret).normalize('NFKC'), Buffer.from(saltHex, 'hex'), 32, SCRYPT_OPTS);
}
function encryptGCM(buf, key) {
  const iv = crypto.randomBytes(12);
  const c  = crypto.createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([c.update(buf), c.final()]);
  return { iv: iv.toString('hex'), tag: c.getAuthTag().toString('hex'), data };
}
function decryptGCM(data, key, ivHex, tagHex) {
  const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
  d.setAuthTag(Buffer.from(tagHex, 'hex'));
  return Buffer.concat([d.update(data), d.final()]);
}
function decryptLegacyCBC(data, ivHex) {
  const d = crypto.createDecipheriv('aes-256-cbc', LEGACY_KEY, Buffer.from(ivHex, 'hex'));
  return Buffer.concat([d.update(data), d.final()]);
}
function wrapKey(keyBuf, kek) { const w = encryptGCM(keyBuf, kek); return { iv: w.iv, tag: w.tag, data: w.data.toString('hex') }; }
function unwrapKey(wrapped, kek) { return decryptGCM(Buffer.from(wrapped.data, 'hex'), kek, wrapped.iv, wrapped.tag); }
function generateRecoveryCode() { return crypto.randomBytes(16).toString('hex').match(/.{4}/g).join('-'); }
function normalizeRecoveryCode(code) { return String(code || '').toLowerCase().replace(/[^0-9a-f]/g, ''); }

// In-memory key caches: sessionID → Buffer. Never on disk.
const dekCache    = new Map();  // main user's personal DEK
const familyCache = new Map();  // family/group DEK (owner + observers)
setInterval(() => { if (dekCache.size > 2000) dekCache.clear(); if (familyCache.size > 2000) familyCache.clear(); }, 3600000);

// ─── Database ─────────────────────────────────────────────────────
const SHARED_ALBUM_ID = '__shared__';
const MAX_VIEW_LOG = 500;

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const db = { users: [], albums: [], photos: [] };
    db.users.push({
      id: uid(), username: 'admin', passwordHash: bcrypt.hashSync('admin', 12),
      role: 'admin', type: 'admin', canViewAlbums: [], mustChangePassword: true, createdAt: Date.now()
    });
    saveDB(db); return db;
  }
  const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  if (!db.albums) db.albums = [];
  if (!db.photos) db.photos = [];
  if (!db.observerLoginLog) db.observerLoginLog = [];
  db.users.forEach(u => {
    if (!u.canViewAlbums) u.canViewAlbums = [];
    if (u.mustChangePassword === undefined) u.mustChangePassword = false;
    if (!u.type) u.type = u.role === 'admin' ? 'admin' : 'user';   // migrate pre-0.9
  });
  db.albums.forEach(a => { if (!a.views) a.views = 0; if (a.hidden === undefined) a.hidden = false; });
  db.photos.forEach(p => {
    if (p.shared === undefined) p.shared = false;
    if (p.views === undefined) p.views = 0;
    if (p.downloads === undefined) p.downloads = 0;
    if (p.viewLog === undefined) p.viewLog = [];
  });
  return db;
}
function saveDB(db) {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_FILE);
}
function uid() { return crypto.randomBytes(8).toString('hex'); }
const ID_RE = /^[a-f0-9]{16}$/;   // uid() format – blocks path traversal / injection

function trackPhotoView(db, photoId, userId) {
  const photo = db.photos.find(p => p.id === photoId); if (!photo) return;
  photo.views = (photo.views || 0) + 1;
  photo.viewLog = photo.viewLog || [];
  photo.viewLog.push({ userId, ts: Date.now() });
  if (photo.viewLog.length > MAX_VIEW_LOG) photo.viewLog.shift();
  const album = db.albums.find(a => a.id === photo.albumId);
  if (album) album.views = (album.views || 0) + 1;
}

// ─── Access control ───────────────────────────────────────────────
function getUser(db, req) { return db.users.find(u => u.id === req.session.userId); }
function expandAlbumIds(db, ids) {
  const set = new Set(ids); let changed = true;
  while (changed) { changed = false; db.albums.forEach(a => { if (a.parentId && set.has(a.parentId) && !set.has(a.id)) { set.add(a.id); changed = true; } }); }
  return [...set];
}
function visibleAlbumIds(db, userId) {
  const user = db.users.find(u => u.id === userId);
  if (!user) return [];
  if (user.type === 'admin') return db.albums.map(a => a.id);
  if (user.type === 'observer') return expandAlbumIds(db, user.canViewAlbums || []);
  const owned = db.albums.filter(a => a.ownerId === userId).map(a => a.id);
  return expandAlbumIds(db, [...new Set([...owned, ...(user.canViewAlbums || [])])]);
}
function canViewAlbum(db, userId, albumId) {
  if (albumId === SHARED_ALBUM_ID) { const u = db.users.find(x => x.id === userId); return u && u.type !== 'observer'; }
  return visibleAlbumIds(db, userId).includes(albumId);
}
function canUploadToAlbum(db, userId, albumId) {
  if (albumId === SHARED_ALBUM_ID) return false;
  const user = db.users.find(u => u.id === userId);
  if (!user || user.type === 'observer') return false;
  if (user.type === 'admin') return true;
  return db.albums.find(a => a.id === albumId)?.ownerId === userId;
}
function canManageAlbum(db, userId, albumId) {
  if (albumId === SHARED_ALBUM_ID) return false;
  const user = db.users.find(u => u.id === userId);
  if (!user || user.type === 'observer') return false;
  if (user.type === 'admin') return true;
  return db.albums.find(a => a.id === albumId)?.ownerId === userId;
}
function descendantAlbumIds(db, albumId) {
  const result = []; const queue = [albumId];
  while (queue.length) { const cur = queue.shift(); db.albums.forEach(a => { if (a.parentId === cur) { result.push(a.id); queue.push(a.id); } }); }
  return result;
}
function ancestorChain(db, albumId) {
  const chain = [albumId]; let cur = db.albums.find(a => a.id === albumId);
  while (cur?.parentId) { chain.push(cur.parentId); cur = db.albums.find(a => a.id === cur.parentId); }
  return chain;
}
// Granted to another MAIN user (admin-managed) → SHARED_KEY
function albumIsGranted(db, albumId) {
  const chain = ancestorChain(db, albumId);
  return db.users.some(u => u.type === 'user' && (u.canViewAlbums || []).some(id => chain.includes(id)));
}
// Granted to any OBSERVER → owner's family key
function albumIsFamilyGranted(db, albumId) {
  const chain = ancestorChain(db, albumId);
  return db.users.some(u => u.type === 'observer' && (u.canViewAlbums || []).some(id => chain.includes(id)));
}
// Hidden albums: inherit from ancestors
function effectiveHidden(db, albumId) {
  return ancestorChain(db, albumId).some(id => db.albums.find(a => a.id === id)?.hidden);
}
function hiddenRootFor(db, albumId) {
  // topmost hidden ancestor (whose PIN unlocks the subtree)
  const chain = ancestorChain(db, albumId).reverse();
  for (const id of chain) { if (db.albums.find(a => a.id === id)?.hidden) return id; }
  return null;
}
function isUnlocked(req, db, albumId) {
  const root = hiddenRootFor(db, albumId);
  if (!root) return true;
  return (req.session.unlockedAlbums || []).includes(root);
}

// ─── Family key helpers ───────────────────────────────────────────
function ensureFamilyKey(db, user, dek) {
  // main user's family DEK, wrapped with their personal DEK
  if (user.familyWrappedDEK) { try { return unwrapKey(user.familyWrappedDEK, dek); } catch { return null; } }
  const fam = crypto.randomBytes(32);
  user.familyWrappedDEK = wrapKey(fam, dek);
  saveDB(db);
  return fam;
}
// Which family does a photo belong to → owner's family key from this session?
function familyKeyFor(db, ownerId, req) {
  const me = getUser(db, req);
  if (!me) return null;
  if (me.id === ownerId || (me.type === 'observer' && me.parentUserId === ownerId)) return familyCache.get(req.sessionID) || null;
  return null;
}

// ─── Photo read-key resolution ────────────────────────────────────
function resolveReadKey(db, photo, req) {
  if (!photo.encryption) return { legacy: true };
  if (photo.encryption === 'shared') return { key: SHARED_KEY };
  if (photo.encryption === 'family') {
    const fk = familyKeyFor(db, photo.ownerId, req);
    if (fk) return { key: fk };
    const me = getUser(db, req);
    if (me && (me.id === photo.ownerId || (me.type === 'observer' && me.parentUserId === photo.ownerId)))
      return { denied: true };
    return { pending: true };
  }
  // 'user'
  if (photo.ownerId === req.session.userId) {
    const dek = dekCache.get(req.sessionID);
    return dek ? { key: dek } : { denied: true };
  }
  return { pending: true };
}
function decryptPhotoFile(filePath, photo, keyInfo, which) {
  const data = fs.readFileSync(filePath);
  if (keyInfo.legacy) return decryptLegacyCBC(data, which === 'thumb' ? photo.thumbIv : photo.iv);
  const iv  = which === 'thumb' ? photo.thumbIv  : photo.iv;
  const tag = which === 'thumb' ? photo.thumbTag : photo.tag;
  return decryptGCM(data, keyInfo.key, iv, tag);
}
function uploadKeyFor(db, albumId, dek, familyDek) {
  if (albumIsGranted(db, albumId)) return { key: SHARED_KEY, enc: 'shared' };
  if (albumIsFamilyGranted(db, albumId) && familyDek) return { key: familyDek, enc: 'family' };
  return { key: dek, enc: 'user' };
}

// ─── Lazy migration at owner login ───────────────────────────────
function migrateUserPhotos(userId, dek, familyDek) {
  try {
    const db = loadDB();
    let changed = 0;
    for (const p of db.photos) {
      if (p.ownerId !== userId) continue;
      const needsLegacy = !p.encryption;
      const needsReenc  = (p.encryption === 'user' || p.encryption === 'family') && p.reencryptPending;
      if (!needsLegacy && !needsReenc) continue;
      const photoPath = path.join(PHOTOS_DIR, `${p.id}.enc`);
      const thumbPath = path.join(THUMBS_DIR, `${p.id}.enc`);
      if (!fs.existsSync(photoPath)) continue;
      let plain, thumbPlain = null;
      try {
        if (needsLegacy) {
          plain = decryptLegacyCBC(fs.readFileSync(photoPath), p.iv);
          if (fs.existsSync(thumbPath)) thumbPlain = decryptLegacyCBC(fs.readFileSync(thumbPath), p.thumbIv);
        } else {
          const cur = p.encryption === 'family' ? familyDek : dek;
          if (!cur) continue;
          plain = decryptGCM(fs.readFileSync(photoPath), cur, p.iv, p.tag);
          if (fs.existsSync(thumbPath)) thumbPlain = decryptGCM(fs.readFileSync(thumbPath), cur, p.thumbIv, p.thumbTag);
        }
      } catch (e) { console.error('Migration decrypt failed:', p.id, e.message); continue; }

      let target;
      if (albumIsGranted(db, p.albumId)) target = { key: SHARED_KEY, enc: 'shared' };
      else if (albumIsFamilyGranted(db, p.albumId) && familyDek) target = { key: familyDek, enc: 'family' };
      else target = { key: dek, enc: 'user' };

      const e1 = encryptGCM(plain, target.key);
      fs.writeFileSync(photoPath, e1.data);
      p.iv = e1.iv; p.tag = e1.tag;
      if (thumbPlain) { const e2 = encryptGCM(thumbPlain, target.key); fs.writeFileSync(thumbPath, e2.data); p.thumbIv = e2.iv; p.thumbTag = e2.tag; }
      p.encryption = target.enc;
      delete p.reencryptPending;
      changed++;
    }
    if (changed) { saveDB(db); console.log(`Migration: ${changed} photo(s) re-encrypted for ${userId}`); }
  } catch (e) { console.error('Migration error:', e.message); }
}

// ─── Middleware ───────────────────────────────────────────────────
app.use(express.json({ limit: '1mb' }));                 // body size cap (uploads use multer separately)
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Security headers on every response
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'SAMEORIGIN');
  res.set('Referrer-Policy', 'no-referrer');
  res.set('Cross-Origin-Resource-Policy', 'same-origin');
  res.set('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  // CSP: allow self + the Google Fonts used by the UI; block plugins/framing
  res.set('Content-Security-Policy',
    "default-src 'self'; " +
    "img-src 'self' data: blob:; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "script-src 'self' 'unsafe-inline'; " +
    "connect-src 'self'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'");
  next();
});
app.use(session({
  store: new FileStore({ path: SESSIONS_DIR, retries: 1, ttl: 86400 }),
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false, saveUninitialized: false,
  name: 'vermeer.sid',
  rolling: true,   // refresh maxAge on activity
  cookie: { maxAge: 86400000, httpOnly: true, sameSite: 'lax', path: '/' }
}));
app.use(express.static(path.join(__dirname, '../frontend')));

function requireAuth(req, res, next) { if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' }); next(); }
function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  const db = loadDB();
  if (getUser(db, req)?.type !== 'admin') return res.status(403).json({ error: 'Admins only' });
  next();
}
function requireMainUser(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  const db = loadDB();
  const t = getUser(db, req)?.type;
  if (t !== 'user' && t !== 'admin') return res.status(403).json({ error: 'Main users only' });
  next();
}
function requireDEK(req, res, next) {
  if (!dekCache.get(req.sessionID)) return res.status(401).json({ error: 'Session key missing – please log in again', code: 'DEK_MISSING' });
  next();
}
const rateBuckets = new Map();
function rateLimit(maxAttempts, windowMs) {
  return (req, res, next) => {
    const key = (req.headers['x-forwarded-for'] || req.ip || 'unknown') + ':' + req.path;
    const now = Date.now();
    let b = rateBuckets.get(key);
    if (!b || now > b.resetAt) { b = { count: 0, resetAt: now + windowMs }; rateBuckets.set(key, b); }
    b.count++;
    if (b.count > maxAttempts) return res.status(429).json({ error: 'Too many attempts – try again later' });
    next();
  };
}
setInterval(() => { const now = Date.now(); for (const [k, b] of rateBuckets) if (now > b.resetAt) rateBuckets.delete(k); }, 300000);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 200 * 1024 * 1024, files: 50 },   // videos up to 200 MB
  fileFilter: (_, file, cb) => {
    const isImage = file.mimetype.startsWith('image/');
    const isVideo = /^video\/(mp4|webm|quicktime)$/.test(file.mimetype);
    if (!isImage && !isVideo) return cb(new Error('Images or videos (mp4/webm/mov) only'));
    cb(null, true);
  }
});

// ═══ AUTH ═══════════════════════════════════════════════════════
app.post('/api/login', rateLimit(10, 900000), (req, res) => {
  const { username, password } = req.body;
  const db = loadDB();
  const user = db.users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.passwordHash))
    return res.status(401).json({ error: 'Invalid credentials' });
  req.session.userId = user.id;
  req.session.unlockedAlbums = [];

  // Observer: unwrap family key with password (even before forced setup)
  if (user.type === 'observer') {
    if (user.familyWrappedDEK && user.kdfSalt) {
      try { familyCache.set(req.sessionID, unwrapKey(user.familyWrappedDEK, kdf(password, user.kdfSalt))); } catch {}
    }
    user.lastLoginAt = Date.now();   // track observer's last visit
    db.observerLoginLog = db.observerLoginLog || [];
    db.observerLoginLog.push({ userId: user.id, ts: Date.now() });
    if (db.observerLoginLog.length > 200) db.observerLoginLog.shift();
    saveDB(db);
    return res.json({ id: user.id, username: user.username, role: user.role, type: 'observer', mustChangePassword: !!user.mustChangePassword });
  }

  if (user.mustChangePassword) {
    return res.json({ id: user.id, username: user.username, role: user.role, type: user.type, mustChangePassword: true, hasExistingData: !!user.wrappedDEK });
  }

  if (user.wrappedDEK) {
    try {
      const dek = unwrapKey(user.wrappedDEK, kdf(password, user.kdfSalt));
      dekCache.set(req.sessionID, dek);
      let fam = null;
      if (user.familyWrappedDEK) { try { fam = unwrapKey(user.familyWrappedDEK, dek); familyCache.set(req.sessionID, fam); } catch {} }
      setImmediate(() => migrateUserPhotos(user.id, dek, fam));
      return res.json({ id: user.id, username: user.username, role: user.role, type: user.type });
    } catch { return res.status(500).json({ error: 'Key unwrap failed' }); }
  }

  // Legacy user without DEK → auto-setup with current password
  const dek = crypto.randomBytes(32);
  const kdfSalt = crypto.randomBytes(16).toString('hex');
  const recoveryCode = generateRecoveryCode();
  const recoverySalt = crypto.randomBytes(16).toString('hex');
  user.kdfSalt = kdfSalt;
  user.wrappedDEK = wrapKey(dek, kdf(password, kdfSalt));
  user.recoverySalt = recoverySalt;
  user.recoveryWrappedDEK = wrapKey(dek, kdf(normalizeRecoveryCode(recoveryCode), recoverySalt));
  saveDB(db);
  dekCache.set(req.sessionID, dek);
  setImmediate(() => migrateUserPhotos(user.id, dek, null));
  res.json({ id: user.id, username: user.username, role: user.role, type: user.type, recoveryCode });
});

app.post('/api/logout', (req, res) => {
  dekCache.delete(req.sessionID); familyCache.delete(req.sessionID);
  req.session.destroy(() => res.json({ success: true }));
});

app.get('/api/me', requireAuth, (req, res) => {
  const db = loadDB();
  const user = getUser(db, req);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({
    id: user.id, username: user.username, role: user.role, type: user.type,
    mustChangePassword: !!user.mustChangePassword,
    hasDEK: user.type === 'observer' ? familyCache.has(req.sessionID) : dekCache.has(req.sessionID),
    version: APP_VERSION
  });
});

app.post('/api/me/setup-password', requireAuth, (req, res) => {
  const { newPassword, recoveryCode } = req.body;
  if (!newPassword || newPassword.length < 8) return res.status(400).json({ error: 'Password min 8 chars' });
  const db = loadDB();
  const user = getUser(db, req);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!user.mustChangePassword) return res.status(400).json({ error: 'Setup not required' });

  // Observer: just re-wrap family key with new password (no recovery code)
  if (user.type === 'observer') {
    const fam = familyCache.get(req.sessionID);
    const kdfSalt = crypto.randomBytes(16).toString('hex');
    user.passwordHash = bcrypt.hashSync(newPassword, 12);
    user.kdfSalt = kdfSalt;
    if (fam) user.familyWrappedDEK = wrapKey(fam, kdf(newPassword, kdfSalt));
    user.mustChangePassword = false;
    saveDB(db);
    return res.json({ success: true, observer: true });
  }

  let dek = null, restored = false;
  if (user.wrappedDEK && user.recoveryWrappedDEK && recoveryCode) {
    try { dek = unwrapKey(user.recoveryWrappedDEK, kdf(normalizeRecoveryCode(recoveryCode), user.recoverySalt)); restored = true; }
    catch { return res.status(401).json({ error: 'Invalid recovery code' }); }
  }
  if (!dek) dek = crypto.randomBytes(32);

  const kdfSalt = crypto.randomBytes(16).toString('hex');
  const newRecoveryCode = generateRecoveryCode();
  const recoverySalt = crypto.randomBytes(16).toString('hex');
  const lostAccess = (user.wrappedDEK && !restored) ? db.photos.filter(p => p.ownerId === user.id && (p.encryption === 'user' || p.encryption === 'family')).length : 0;
  if (user.wrappedDEK && !restored) delete user.familyWrappedDEK; // old family key is lost too

  user.passwordHash = bcrypt.hashSync(newPassword, 12);
  user.kdfSalt = kdfSalt;
  user.wrappedDEK = wrapKey(dek, kdf(newPassword, kdfSalt));
  user.recoverySalt = recoverySalt;
  user.recoveryWrappedDEK = wrapKey(dek, kdf(normalizeRecoveryCode(newRecoveryCode), recoverySalt));
  user.mustChangePassword = false;
  saveDB(db);

  dekCache.set(req.sessionID, dek);
  let fam = null;
  if (user.familyWrappedDEK) { try { fam = unwrapKey(user.familyWrappedDEK, dek); familyCache.set(req.sessionID, fam); } catch {} }
  setImmediate(() => migrateUserPhotos(user.id, dek, fam));
  res.json({ success: true, recoveryCode: newRecoveryCode, restored, lostAccess });
});

app.put('/api/me/password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 8) return res.status(400).json({ error: 'Password min 8 chars' });
  const db = loadDB();
  const user = getUser(db, req);
  if (!bcrypt.compareSync(currentPassword, user.passwordHash)) return res.status(401).json({ error: 'Wrong current password' });

  const newSalt = crypto.randomBytes(16).toString('hex');
  if (user.type === 'observer') {
    let fam = familyCache.get(req.sessionID);
    if (!fam && user.familyWrappedDEK) { try { fam = unwrapKey(user.familyWrappedDEK, kdf(currentPassword, user.kdfSalt)); } catch {} }
    user.kdfSalt = newSalt;
    if (fam) { user.familyWrappedDEK = wrapKey(fam, kdf(newPassword, newSalt)); familyCache.set(req.sessionID, fam); }
  } else if (user.wrappedDEK) {
    let dek;
    try { dek = unwrapKey(user.wrappedDEK, kdf(currentPassword, user.kdfSalt)); }
    catch { return res.status(500).json({ error: 'Key unwrap failed' }); }
    user.kdfSalt = newSalt;
    user.wrappedDEK = wrapKey(dek, kdf(newPassword, newSalt));
    dekCache.set(req.sessionID, dek);
  }
  user.passwordHash = bcrypt.hashSync(newPassword, 12);
  saveDB(db);
  res.json({ success: true });
});

app.post('/api/recover', rateLimit(5, 900000), (req, res) => {
  const { username, recoveryCode, newPassword } = req.body;
  if (!newPassword || newPassword.length < 8) return res.status(400).json({ error: 'Password min 8 chars' });
  const db = loadDB();
  const user = db.users.find(u => u.username === username);
  // Uniform error to avoid revealing whether the username exists
  if (!user || !user.recoveryWrappedDEK) return res.status(401).json({ error: 'Invalid username or recovery code' });
  let dek;
  try { dek = unwrapKey(user.recoveryWrappedDEK, kdf(normalizeRecoveryCode(recoveryCode), user.recoverySalt)); }
  catch { return res.status(401).json({ error: 'Invalid username or recovery code' }); }
  const kdfSalt = crypto.randomBytes(16).toString('hex');
  const newRecoveryCode = generateRecoveryCode();
  const recoverySalt = crypto.randomBytes(16).toString('hex');
  user.passwordHash = bcrypt.hashSync(newPassword, 12);
  user.kdfSalt = kdfSalt;
  user.wrappedDEK = wrapKey(dek, kdf(newPassword, kdfSalt));
  user.recoverySalt = recoverySalt;
  user.recoveryWrappedDEK = wrapKey(dek, kdf(normalizeRecoveryCode(newRecoveryCode), recoverySalt));
  user.mustChangePassword = false;
  saveDB(db);
  res.json({ success: true, recoveryCode: newRecoveryCode });
});

// ═══ USERS (Admin) ═══════════════════════════════════════════════
app.get('/api/users', requireAdmin, (req, res) => {
  const db = loadDB();
  res.json(db.users.map(u => ({
    id: u.id, username: u.username, role: u.role, type: u.type, parentUserId: u.parentUserId || null,
    parentName: u.parentUserId ? (db.users.find(x => x.id === u.parentUserId)?.username ?? '?') : null,
    createdAt: u.createdAt, canViewAlbums: u.canViewAlbums || [], mustChangePassword: !!u.mustChangePassword
  })));
});
const USERNAME_RE = /^[A-Za-z0-9._@ -]{2,40}$/;   // no quotes/brackets → blocks HTML/JS injection
app.post('/api/users', requireAdmin, (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (!USERNAME_RE.test(username.trim())) return res.status(400).json({ error: 'Invalid username (2-40 chars: letters, digits, . _ @ - space)' });
  if (password.length < 6) return res.status(400).json({ error: 'Password min 6 chars' });
  if (password.length > 200) return res.status(400).json({ error: 'Password too long' });
  const db = loadDB();
  if (db.users.find(u => u.username === username)) return res.status(409).json({ error: 'Username taken' });
  const isAdmin = role === 'admin';
  const user = { id: uid(), username: username.trim(), passwordHash: bcrypt.hashSync(password, 12),
    role: isAdmin ? 'admin' : 'user', type: isAdmin ? 'admin' : 'user',
    canViewAlbums: [], mustChangePassword: true, createdAt: Date.now() };
  db.users.push(user); saveDB(db);
  res.status(201).json({ id: user.id, username: user.username, role: user.role, type: user.type });
});
app.delete('/api/users/:id', requireAdmin, (req, res) => {
  const db = loadDB();
  const idx = db.users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  if (db.users[idx].id === req.session.userId) return res.status(400).json({ error: 'Cannot delete own account' });
  const removedId = db.users[idx].id;
  db.users.splice(idx, 1);
  db.users = db.users.filter(u => u.parentUserId !== removedId); // cascade observers
  saveDB(db); res.json({ success: true });
});
app.put('/api/users/:id/password', requireAdmin, (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password min 6 chars' });
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.passwordHash = bcrypt.hashSync(password, 12);
  user.mustChangePassword = true;
  saveDB(db);
  res.json({ success: true });
});
app.put('/api/users/:id/album-permissions', requireAdmin, (req, res) => {
  const { canViewAlbums } = req.body;
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const before = new Set(user.canViewAlbums || []);
  user.canViewAlbums = Array.isArray(canViewAlbums) ? canViewAlbums : [];
  let pendingCount = 0;
  const newly = user.canViewAlbums.filter(id => !before.has(id));
  if (newly.length) {
    const affected = new Set();
    newly.forEach(id => { affected.add(id); descendantAlbumIds(db, id).forEach(d => affected.add(d)); });
    db.photos.forEach(p => { if (affected.has(p.albumId) && (p.encryption === 'user' || p.encryption === 'family') && !p.reencryptPending) { p.reencryptPending = true; pendingCount++; } });
  }
  saveDB(db);
  res.json({ success: true, pendingCount });
});

// ═══ OBSERVERS (managed by main user) ═══════════════════════════
app.get('/api/observers', requireMainUser, (req, res) => {
  const db = loadDB();
  res.json(db.users.filter(u => u.type === 'observer' && u.parentUserId === req.session.userId)
    .map(u => ({ id: u.id, username: u.username, createdAt: u.createdAt, canViewAlbums: u.canViewAlbums || [], mustChangePassword: !!u.mustChangePassword, lastLoginAt: u.lastLoginAt || null })));
});
app.post('/api/observers', requireMainUser, requireDEK, (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (!USERNAME_RE.test(username.trim())) return res.status(400).json({ error: 'Invalid username (2-40 chars: letters, digits, . _ @ - space)' });
  if (password.length < 6) return res.status(400).json({ error: 'Password min 6 chars' });
  if (password.length > 200) return res.status(400).json({ error: 'Password too long' });
  const db = loadDB();
  if (db.users.find(u => u.username === username)) return res.status(409).json({ error: 'Username taken' });
  const me = getUser(db, req);
  const dek = dekCache.get(req.sessionID);
  const fam = ensureFamilyKey(db, me, dek);
  if (!fam) return res.status(500).json({ error: 'Family key error' });
  familyCache.set(req.sessionID, fam);
  const kdfSalt = crypto.randomBytes(16).toString('hex');
  const obs = { id: uid(), username: username.trim(), passwordHash: bcrypt.hashSync(password, 12),
    role: 'user', type: 'observer', parentUserId: me.id,
    kdfSalt, familyWrappedDEK: wrapKey(fam, kdf(password, kdfSalt)),
    canViewAlbums: [], mustChangePassword: true, createdAt: Date.now() };
  db.users.push(obs); saveDB(db);
  res.status(201).json({ id: obs.id, username: obs.username });
});
app.delete('/api/observers/:id', requireMainUser, (req, res) => {
  const db = loadDB();
  const idx = db.users.findIndex(u => u.id === req.params.id && u.type === 'observer' && u.parentUserId === req.session.userId);
  if (idx === -1) return res.status(404).json({ error: 'Observer not found' });
  db.users.splice(idx, 1); saveDB(db); res.json({ success: true });
});
app.put('/api/observers/:id/password', requireMainUser, requireDEK, (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password min 6 chars' });
  const db = loadDB();
  const obs = db.users.find(u => u.id === req.params.id && u.type === 'observer' && u.parentUserId === req.session.userId);
  if (!obs) return res.status(404).json({ error: 'Observer not found' });
  const me = getUser(db, req);
  const fam = ensureFamilyKey(db, me, dekCache.get(req.sessionID));
  const kdfSalt = crypto.randomBytes(16).toString('hex');
  obs.passwordHash = bcrypt.hashSync(password, 12);
  obs.kdfSalt = kdfSalt;
  obs.familyWrappedDEK = wrapKey(fam, kdf(password, kdfSalt));
  obs.mustChangePassword = true;
  saveDB(db);
  res.json({ success: true });
});
app.put('/api/observers/:id/albums', requireMainUser, (req, res) => {
  const { canViewAlbums } = req.body;
  const db = loadDB();
  const obs = db.users.find(u => u.id === req.params.id && u.type === 'observer' && u.parentUserId === req.session.userId);
  if (!obs) return res.status(404).json({ error: 'Observer not found' });
  const myAlbums = new Set(db.albums.filter(a => a.ownerId === req.session.userId).map(a => a.id));
  const requested = (Array.isArray(canViewAlbums) ? canViewAlbums : []).filter(id => myAlbums.has(id));
  const before = new Set(obs.canViewAlbums || []);
  obs.canViewAlbums = requested;
  let pendingCount = 0;
  const newly = requested.filter(id => !before.has(id));
  if (newly.length) {
    const affected = new Set();
    newly.forEach(id => { affected.add(id); descendantAlbumIds(db, id).forEach(d => affected.add(d)); });
    db.photos.forEach(p => { if (affected.has(p.albumId) && p.encryption === 'user' && !p.reencryptPending) { p.reencryptPending = true; pendingCount++; } });
  }
  saveDB(db);
  // Owner is online → run migration right away
  const dek = dekCache.get(req.sessionID);
  const fam = familyCache.get(req.sessionID);
  if (dek) setImmediate(() => migrateUserPhotos(req.session.userId, dek, fam));
  res.json({ success: true, pendingCount });
});

// ═══ ALBUMS ═══════════════════════════════════════════════════════
app.get('/api/albums', requireAuth, (req, res) => {
  const db = loadDB();
  const me = getUser(db, req);
  const allowed = visibleAlbumIds(db, req.session.userId);
  const albums = db.albums.filter(a => allowed.includes(a.id)).map(a => {
    const owner = db.users.find(u => u.id === a.ownerId);
    const hid = effectiveHidden(db, a.id);
    const locked = hid && !isUnlocked(req, db, a.id);
    return {
      id: a.id, name: a.name, parentId: a.parentId,
      ownerId: a.ownerId, ownerName: owner?.username ?? '?',
      description: locked ? '' : (a.description || ''), createdAt: a.createdAt,
      photoCount: locked ? 0 : db.photos.filter(p => p.albumId === a.id).length,
      coverPhotoId: locked ? null : (a.coverPhotoId || null),
      hidden: !!a.hidden, effectiveHidden: hid, hiddenRootId: hid ? hiddenRootFor(db, a.id) : null, locked,
      canUpload: canUploadToAlbum(db, req.session.userId, a.id),
      canManage: canManageAlbum(db, req.session.userId, a.id)
    };
  }).sort((a, b) => a.name.localeCompare(b.name));

  res.json(albums);
});

app.post('/api/albums', requireMainUser, (req, res) => {
  const { name, parentId, description } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Name required' });
  const db = loadDB();
  if (parentId) {
    if (!db.albums.find(a => a.id === parentId)) return res.status(404).json({ error: 'Parent album not found' });
    if (!canManageAlbum(db, req.session.userId, parentId)) return res.status(403).json({ error: 'No permission on parent album' });
  }
  const album = { id: uid(), name: name.trim(), parentId: parentId || null, ownerId: req.session.userId,
    description: description?.trim() || '', createdAt: Date.now(), views: 0, hidden: false };
  db.albums.push(album); saveDB(db);
  res.status(201).json(album);
});

app.put('/api/albums/:id', requireAuth, (req, res) => {
  const db = loadDB();
  const album = db.albums.find(a => a.id === req.params.id);
  if (!album) return res.status(404).json({ error: 'Album not found' });
  if (!canManageAlbum(db, req.session.userId, req.params.id)) return res.status(403).json({ error: 'No permission' });
  const { name, description } = req.body;
  if (name?.trim()) album.name = name.trim();
  if (description !== undefined) album.description = description.trim();
  saveDB(db); res.json({ success: true });
});

// Hide album with 4-digit PIN / unhide with account password
app.put('/api/albums/:id/hide', requireAuth, (req, res) => {
  const { pin, password } = req.body;
  const db = loadDB();
  const album = db.albums.find(a => a.id === req.params.id);
  if (!album) return res.status(404).json({ error: 'Album not found' });
  if (!canManageAlbum(db, req.session.userId, req.params.id)) return res.status(403).json({ error: 'No permission' });
  if (pin) {
    if (!/^\d{4}$/.test(String(pin))) return res.status(400).json({ error: 'PIN must be exactly 4 digits' });
    album.hidden = true;
    album.pinHash = bcrypt.hashSync(String(pin), 10);
  } else {
    const me = getUser(db, req);
    if (!password || !bcrypt.compareSync(password, me.passwordHash))
      return res.status(401).json({ error: 'Account password required to unhide' });
    album.hidden = false;
    delete album.pinHash;
  }
  saveDB(db); res.json({ success: true, hidden: album.hidden });
});

app.post('/api/albums/:id/relock', requireAuth, (req, res) => {
  const db = loadDB();
  const root = hiddenRootFor(db, req.params.id) || req.params.id;
  req.session.unlockedAlbums = (req.session.unlockedAlbums || []).filter(id => id !== root);
  res.json({ success: true });
});

app.post('/api/albums/:id/unlock', requireAuth, rateLimit(5, 900000), (req, res) => {
  const { pin } = req.body;
  const db = loadDB();
  const album = db.albums.find(a => a.id === req.params.id);
  if (!album) return res.status(404).json({ error: 'Album not found' });
  const root = hiddenRootFor(db, req.params.id);
  if (!root) return res.json({ success: true }); // not hidden
  const rootAlbum = db.albums.find(a => a.id === root);
  if (!rootAlbum.pinHash || !bcrypt.compareSync(String(pin || ''), rootAlbum.pinHash))
    return res.status(401).json({ error: 'Wrong PIN' });
  req.session.unlockedAlbums = req.session.unlockedAlbums || [];
  if (!req.session.unlockedAlbums.includes(root)) req.session.unlockedAlbums.push(root);
  res.json({ success: true });
});

app.put('/api/albums/:id/cover', requireAuth, (req, res) => {
  const { photoId } = req.body;
  const db = loadDB();
  const album = db.albums.find(a => a.id === req.params.id);
  if (!album) return res.status(404).json({ error: 'Album not found' });
  if (!canManageAlbum(db, req.session.userId, req.params.id)) return res.status(403).json({ error: 'No permission' });
  if (photoId) {
    const photo = db.photos.find(p => p.id === photoId);
    if (!photo) return res.status(404).json({ error: 'Photo not found' });
    const valid = [req.params.id, ...descendantAlbumIds(db, req.params.id)];
    if (!valid.includes(photo.albumId)) return res.status(400).json({ error: 'Photo is not in this album' });
    album.coverPhotoId = photoId;
  } else delete album.coverPhotoId;
  saveDB(db); res.json({ success: true });
});

app.delete('/api/albums/:id', requireAuth, (req, res) => {
  const db = loadDB();
  const album = db.albums.find(a => a.id === req.params.id);
  if (!album) return res.status(404).json({ error: 'Album not found' });
  if (!canManageAlbum(db, req.session.userId, req.params.id)) return res.status(403).json({ error: 'No permission' });
  const toDelete = [req.params.id, ...descendantAlbumIds(db, req.params.id)];
  db.photos = db.photos.filter(p => {
    if (!toDelete.includes(p.albumId)) return true;
    [path.join(PHOTOS_DIR, `${p.id}.enc`), path.join(THUMBS_DIR, `${p.id}.enc`)].forEach(f => { try { fs.unlinkSync(f); } catch {} });
    return false;
  });
  db.users.forEach(u => { u.canViewAlbums = (u.canViewAlbums || []).filter(id => !toDelete.includes(id)); });
  db.albums = db.albums.filter(a => !toDelete.includes(a.id));
  saveDB(db); res.json({ success: true });
});

// ═══ UPLOAD ═══════════════════════════════════════════════════════
app.post('/api/photos/upload', requireAuth, requireDEK, (req, res) => {
  upload.array('photos', 50)(req, res, async (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ error: 'File too large (max 50 MB)' });
      if (err.code === 'LIMIT_FILE_COUNT') return res.status(400).json({ error: 'Too many files (max 50)' });
      return res.status(400).json({ error: err.message });
    }
    const { albumId } = req.body;
    if (!albumId) return res.status(400).json({ error: 'albumId required' });
    if (!req.files?.length) return res.status(400).json({ error: 'No files received' });
    const db = loadDB();
    if (!db.albums.find(a => a.id === albumId)) return res.status(404).json({ error: 'Album not found' });
    if (!canUploadToAlbum(db, req.session.userId, albumId)) return res.status(403).json({ error: 'No upload permission' });
    if (effectiveHidden(db, albumId) && !isUnlocked(req, db, albumId)) return res.status(423).json({ error: 'Album locked', code: 'LOCKED' });

    const dek = dekCache.get(req.sessionID);
    let fam = familyCache.get(req.sessionID);
    if (!fam && albumIsFamilyGranted(db, albumId)) { const me = getUser(db, req); fam = ensureFamilyKey(db, me, dek); if (fam) familyCache.set(req.sessionID, fam); }
    const { key, enc } = uploadKeyFor(db, albumId, dek, fam);

    const uploaded = [], errors = [];
    for (const file of req.files) {
      try {
        const isVideo = file.mimetype.startsWith('video/');
        const photoId = uid();
        const e1 = encryptGCM(file.buffer, key);
        fs.writeFileSync(path.join(PHOTOS_DIR, `${photoId}.enc`), e1.data);
        const rec = { id: photoId, albumId, ownerId: req.session.userId,
          originalName: file.originalname, mimeType: file.mimetype, size: file.size, uploadedAt: Date.now(),
          encryption: enc, iv: e1.iv, tag: e1.tag,
          shared: false, views: 0, downloads: 0, viewLog: [] };
        if (!isVideo) {
          const thumbBuffer = await sharp(file.buffer).resize(400, 400, { fit: 'cover', position: 'centre' }).jpeg({ quality: 75 }).toBuffer();
          const e2 = encryptGCM(thumbBuffer, key);
          fs.writeFileSync(path.join(THUMBS_DIR, `${photoId}.enc`), e2.data);
          rec.thumbIv = e2.iv; rec.thumbTag = e2.tag;
        }
        db.photos.push(rec);
        uploaded.push({ id: photoId, name: file.originalname });
        file.buffer = null;
      } catch (e) { console.error('Upload error', file.originalname, e.message); errors.push(file.originalname); }
    }
    saveDB(db); res.json({ uploaded, errors });
  });
});

// ═══ SHARE / UNSHARE ══════════════════════════════════════════════
app.get('/api/albums/:albumId/photos', requireAuth, (req, res) => {
  const db = loadDB();
  const me = getUser(db, req);
  const albumId = req.params.albumId;
  const mapPhoto = p => {
    const owner = db.users.find(u => u.id === p.ownerId);
    const keyInfo = resolveReadKey(db, p, req);
    return { id: p.id, albumId: p.albumId, originalName: p.originalName, uploadedAt: p.uploadedAt, size: p.size,
      ownerId: p.ownerId, ownerName: owner?.username ?? '?', shared: p.shared || false,
      mimeType: p.mimeType || 'image/jpeg',
      pending: !!keyInfo.pending,
      canDownload: p.ownerId === req.session.userId && me.type !== 'observer',
      canShare: p.ownerId === req.session.userId && me.type !== 'observer' };
  };
  if (albumId === SHARED_ALBUM_ID) return res.status(403).json({ error: 'Sharing removed' });
  if (!canViewAlbum(db, req.session.userId, albumId)) return res.status(403).json({ error: 'No access to album' });
  if (effectiveHidden(db, albumId) && !isUnlocked(req, db, albumId))
    return res.status(423).json({ error: 'Album locked', code: 'LOCKED' });
  res.json(db.photos.filter(p => p.albumId === albumId).map(mapPhoto).sort((a, b) => b.uploadedAt - a.uploadedAt));
});

app.put('/api/photos/:id/move', requireAuth, (req, res) => {
  const { targetAlbumId } = req.body;
  if (!ID_RE.test(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
  const db = loadDB();
  const photo = db.photos.find(p => p.id === req.params.id);
  if (!photo) return res.status(404).json({ error: 'Photo not found' });
  const me = getUser(db, req);
  if (photo.ownerId !== req.session.userId && me.type !== 'admin') return res.status(403).json({ error: 'Not your photo' });
  if (!canUploadToAlbum(db, req.session.userId, targetAlbumId)) return res.status(403).json({ error: 'No upload permission for target album' });
  const targetAlbum = db.albums.find(a => a.id === targetAlbumId);
  if (!targetAlbum) return res.status(404).json({ error: 'Target album not found' });
  // Cannot move into a locked hidden album unless unlocked this session
  if (effectiveHidden(db, targetAlbumId) && !isUnlocked(req, db, targetAlbumId))
    return res.status(423).json({ error: 'Target album locked', code: 'LOCKED' });

  const oldAlbumId = photo.albumId;
  photo.albumId = targetAlbumId;

  // Re-encryption needed if the target's sharing context differs from current encryption
  const needsShared = albumIsGranted(db, targetAlbumId);
  const needsFamily = !needsShared && albumIsFamilyGranted(db, targetAlbumId);
  const targetEnc = needsShared ? 'shared' : (needsFamily ? 'family' : 'user');
  if (photo.encryption && photo.encryption !== targetEnc && !photo.shared) {
    photo.reencryptPending = true;  // owner's session migration will convert it
  }
  // Clear cover reference if the photo left an album that used it as cover
  const oldAlbum = db.albums.find(a => a.id === oldAlbumId);
  if (oldAlbum && oldAlbum.coverPhotoId === photo.id) delete oldAlbum.coverPhotoId;

  saveDB(db);

  // If owner is online, run migration right away so it's not stuck pending
  const dek = dekCache.get(req.sessionID);
  const fam = familyCache.get(req.sessionID);
  if (photo.reencryptPending && dek && photo.ownerId === req.session.userId)
    setImmediate(() => migrateUserPhotos(req.session.userId, dek, fam));

  res.json({ success: true });
});

app.get('/api/photos/:id/thumb', requireAuth, (req, res) => {
  if (!ID_RE.test(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
  const db = loadDB();
  const photo = db.photos.find(p => p.id === req.params.id);
  if (!photo) return res.status(404).json({ error: 'Photo not found' });
  const me = getUser(db, req);
  const canView = (photo.shared && me.type !== 'observer') || canViewAlbum(db, req.session.userId, photo.albumId);
  if (!canView) return res.status(403).json({ error: 'No access' });
  // Hidden albums: admins with a fresh stats password re-auth may preview them
  const statsBypass = statsUnlocked(req) && (me.type === 'admin' || photo.ownerId === me.id);
  if (effectiveHidden(db, photo.albumId) && !isUnlocked(req, db, photo.albumId) && !statsBypass)
    return res.status(423).json({ error: 'Album locked', code: 'LOCKED' });
  const referer = req.headers['referer'] || req.headers['origin'] || '';
  const host = req.headers['host'] || '';
  if (referer && !referer.includes(host)) return res.status(403).json({ error: 'Direct access not permitted' });
  const keyInfo = resolveReadKey(db, photo, req);
  if (keyInfo.pending) return res.status(423).json({ error: 'Photo awaiting re-encryption by owner', code: 'PENDING' });
  if (keyInfo.denied) return res.status(401).json({ error: 'Session key missing', code: 'DEK_MISSING' });
  const f = path.join(THUMBS_DIR, `${photo.id}.enc`);
  if (!fs.existsSync(f)) return res.status(404).json({ error: 'Thumbnail missing' });
  try {
    res.set('Content-Type', 'image/jpeg');
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.set('Pragma', 'no-cache');
    res.set('X-Frame-Options', 'SAMEORIGIN');
    res.set('X-Content-Type-Options', 'nosniff');
    res.send(decryptPhotoFile(f, photo, keyInfo, 'thumb'));
  } catch (e) { console.error('Thumb error:', e.message); res.status(500).json({ error: 'Decryption failed' }); }
});

// Full-resolution view (same access rules as thumb; for lightbox display)
app.get('/api/photos/:id/full', requireAuth, (req, res) => {
  if (!ID_RE.test(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
  const db = loadDB();
  const photo = db.photos.find(p => p.id === req.params.id);
  if (!photo) return res.status(404).json({ error: 'Photo not found' });
  const me = getUser(db, req);
  const canView = (photo.shared && me.type !== 'observer') || canViewAlbum(db, req.session.userId, photo.albumId);
  if (!canView) return res.status(403).json({ error: 'No access' });
  if (effectiveHidden(db, photo.albumId) && !isUnlocked(req, db, photo.albumId))
    return res.status(423).json({ error: 'Album locked', code: 'LOCKED' });
  const referer = req.headers['referer'] || req.headers['origin'] || '';
  if (referer && !referer.includes(req.headers['host'] || '')) return res.status(403).json({ error: 'Direct access not permitted' });
  const keyInfo = resolveReadKey(db, photo, req);
  if (keyInfo.pending) return res.status(423).json({ error: 'Pending', code: 'PENDING' });
  if (keyInfo.denied) return res.status(401).json({ error: 'Session key missing', code: 'DEK_MISSING' });
  const f = path.join(PHOTOS_DIR, `${photo.id}.enc`);
  if (!fs.existsSync(f)) return res.status(404).json({ error: 'File not found' });
  try {
    // View-Tracking: nur Lightbox-Ansichten zählen, eigene Fotos ausgenommen
    if (photo.ownerId !== req.session.userId) {
      const tenMinAgo = Date.now() - 600000;
      const recent = (photo.viewLog || []).find(e => e.userId === req.session.userId && e.ts > tenMinAgo);
      if (!recent) { trackPhotoView(db, photo.id, req.session.userId); saveDB(db); }
    }
    res.set('Content-Type', photo.mimeType || 'image/jpeg');
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.set('X-Content-Type-Options', 'nosniff');
    res.send(decryptPhotoFile(f, photo, keyInfo, 'photo'));
  } catch (e) { console.error('Full view error:', e.message); res.status(500).json({ error: 'Decryption failed' }); }
});

app.delete('/api/photos/:id', requireAuth, (req, res) => {
  const db = loadDB();
  const idx = db.photos.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Photo not found' });
  const photo = db.photos[idx];
  const me = getUser(db, req);
  if ((photo.ownerId !== req.session.userId && me.type !== 'admin') || me.type === 'observer')
    return res.status(403).json({ error: 'No permission' });
  [path.join(PHOTOS_DIR, `${photo.id}.enc`), path.join(THUMBS_DIR, `${photo.id}.enc`)].forEach(f => { try { fs.unlinkSync(f); } catch {} });
  db.albums.forEach(a => { if (a.coverPhotoId === photo.id) delete a.coverPhotoId; });
  db.photos.splice(idx, 1); saveDB(db); res.json({ success: true });
});

// ═══ EXPORT (all own photos as ZIP) ═══════════════════════════════
app.get('/api/export', requireAuth, requireDEK, (req, res) => {
  const db = loadDB();
  const me = getUser(db, req);
  if (me.type === 'observer') return res.status(403).json({ error: 'Observers cannot export' });
  const dek = dekCache.get(req.sessionID);
  const fam = familyCache.get(req.sessionID);
  const mine = db.photos.filter(p => p.ownerId === req.session.userId);

  res.set('Content-Type', 'application/zip');
  res.set('Content-Disposition', `attachment; filename="vermeer-export-${me.username}-${new Date().toISOString().slice(0,10)}.zip"`);
  const archive = archiver('zip', { zlib: { level: 6 } });
  archive.on('error', err => { console.error('Export error:', err.message); try { res.status(500).end(); } catch {} });
  archive.pipe(res);

  const albumPathCache = {};
  function albumPath(id) {
    if (!id) return '';
    if (albumPathCache[id]) return albumPathCache[id];
    const a = db.albums.find(x => x.id === id);
    if (!a) return '';
    const p = (a.parentId ? albumPath(a.parentId) + '/' : '') + a.name.replace(/[\/\\:*?"<>|]/g, '_');
    albumPathCache[id] = p; return p;
  }
  let exported = 0;
  for (const p of mine) {
    try {
      const f = path.join(PHOTOS_DIR, `${p.id}.enc`);
      if (!fs.existsSync(f)) continue;
      let key;
      if (!p.encryption) key = null;                       // legacy
      else if (p.encryption === 'shared') key = SHARED_KEY;
      else if (p.encryption === 'family') key = fam;
      else key = dek;
      if (p.encryption && !key) continue;
      const plain = p.encryption ? decryptGCM(fs.readFileSync(f), key, p.iv, p.tag) : decryptLegacyCBC(fs.readFileSync(f), p.iv);
      const dir = albumPath(p.albumId);
      archive.append(plain, { name: (dir ? dir + '/' : '') + p.originalName });
      exported++;
    } catch (e) { console.error('Export skip', p.id, e.message); }
  }
  console.log(`Export: ${exported}/${mine.length} photos for ${me.username}`);
  archive.finalize();
});

// ═══ STATISTICS (Admin) ═══════════════════════════════════════════
const STATS_UNLOCK_TTL = 15 * 60 * 1000;   // re-auth valid for 15 minutes
function statsUnlocked(req) {
  return req.session.statsUnlockedAt && (Date.now() - req.session.statsUnlockedAt) < STATS_UNLOCK_TTL;
}
app.post('/api/stats/unlock', requireMainUser, rateLimit(5, 900000), (req, res) => {
  const { password } = req.body;
  const db = loadDB();
  const me = getUser(db, req);
  if (!password || !bcrypt.compareSync(password, me.passwordHash))
    return res.status(401).json({ error: 'Wrong password' });
  req.session.statsUnlockedAt = Date.now();
  res.json({ success: true });
});

app.get('/api/stats', requireMainUser, (req, res) => {
  if (!statsUnlocked(req))
    return res.status(401).json({ error: 'Password confirmation required', code: 'STATS_LOCKED' });
  const fullDb = loadDB();
  const meU = getUser(fullDb, req);
  const isAdmin = meU.type === 'admin';
  // Scope: main users see only their own photos/albums; admin sees everything
  const db = isAdmin ? fullDb : {
    users: fullDb.users,
    albums: fullDb.albums.filter(a => a.ownerId === meU.id),
    photos: fullDb.photos.filter(p => p.ownerId === meU.id)
  };
  const overview = {
    totalPhotos: db.photos.length, totalAlbums: db.albums.length,
    totalUsers: isAdmin ? fullDb.users.length : (fullDb.users.filter(u => u.parentUserId === meU.id).length + 1),
    scope: isAdmin ? 'all' : 'own',
    totalViews: db.photos.reduce((s, p) => s + (p.views || 0), 0),
    sharedPhotos: db.photos.filter(p => p.shared).length,
    totalStorageMB: parseFloat((db.photos.reduce((s, p) => s + (p.size || 0), 0) / 1048576).toFixed(2)),
    appVersion: APP_VERSION
  };
  const nameOf = id => db.users.find(u => u.id === id)?.username ?? '?';
  const topPhotos = db.photos.filter(p => p.views > 0).sort((a, b) => b.views - a.views).slice(0, 10).map(p => {
    // viewers: most-recent-first, de-duplicated by user, with last-view timestamp
    const seen = new Map();
    (p.viewLog || []).slice().reverse().forEach(e => { if (!seen.has(e.userId)) seen.set(e.userId, e.ts); });
    const viewers = [...seen.entries()].map(([id, ts]) => ({ username: nameOf(id), lastView: ts }));
    return {
      id: p.id, name: p.originalName, views: p.views || 0,
      uniqueViewers: seen.size, shared: p.shared,
      viewers,
      ownerName: nameOf(p.ownerId),
      albumName: db.albums.find(a => a.id === p.albumId)?.name ?? '?', uploadedAt: p.uploadedAt };
  });
  const topAlbums = db.albums.filter(a => (a.views || 0) > 0).sort((a, b) => b.views - a.views).slice(0, 10).map(a => ({
    id: a.id, name: a.name, views: a.views || 0,
    photoCount: db.photos.filter(p => p.albumId === a.id).length,
    ownerName: db.users.find(u => u.id === a.ownerId)?.username ?? '?' }));
  const vpu = {};
  db.photos.forEach(p => (p.viewLog || []).forEach(e => { vpu[e.userId] = (vpu[e.userId] || 0) + 1; }));
  const topViewers = Object.entries(vpu).sort((a, b) => b[1] - a[1]).slice(0, 10)
    .map(([id, views]) => ({ username: db.users.find(u => u.id === id)?.username ?? '?', views }));
  const upu = {};
  db.photos.forEach(p => { upu[p.ownerId] = (upu[p.ownerId] || 0) + 1; });
  const topUploaders = Object.entries(upu).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([id, count]) => ({
    username: db.users.find(u => u.id === id)?.username ?? '?', photos: count,
    sizeMB: parseFloat((db.photos.filter(p => p.ownerId === id).reduce((s, p) => s + (p.size || 0), 0) / 1048576).toFixed(2)) }));
  const cutoff = Date.now() - 30 * 86400000;
  const vbd = {};
  db.photos.forEach(p => (p.viewLog || []).forEach(e => { if (e.ts >= cutoff) { const d = new Date(e.ts).toISOString().slice(0, 10); vbd[d] = (vbd[d] || 0) + 1; } }));
  const viewsTimeline = Object.entries(vbd).sort((a, b) => a[0].localeCompare(b[0])).map(([date, count]) => ({ date, count }));
  // Letzte 10 Beobachter-Logins (gescoped: nur eigene Beobachter, Admin: alle)
  const observerLogins = (fullDb.observerLoginLog || [])
    .filter(e => { const u = fullDb.users.find(x => x.id === e.userId); return u && (isAdmin || u.parentUserId === meU.id); })
    .slice(-10).reverse()
    .map(e => ({ username: fullDb.users.find(x => x.id === e.userId)?.username ?? '?', ts: e.ts }));
  res.json({ overview, topPhotos, topAlbums, topViewers, topUploaders, viewsTimeline, observerLogins });
});

// Reset statistics: main users reset their own data, admin resets everything
app.post('/api/stats/reset', requireMainUser, (req, res) => {
  if (!statsUnlocked(req))
    return res.status(401).json({ error: 'Password confirmation required', code: 'STATS_LOCKED' });
  const db = loadDB();
  const me = getUser(db, req);
  const isAdmin = me.type === 'admin';
  // scope: 'own' = only my photos; 'all' = everything (admin only)
  const scope = (isAdmin && req.body.scope === 'all') ? 'all' : 'own';
  let photos = 0, albums = 0;
  db.photos.forEach(p => {
    if (scope === 'all' || p.ownerId === me.id) { p.views = 0; p.downloads = 0; p.viewLog = []; photos++; }
  });
  db.albums.forEach(a => {
    if (scope === 'all' || a.ownerId === me.id) { a.views = 0; albums++; }
  });
  saveDB(db);
  res.json({ success: true, photos, albums, scope });
});

app.get('/api/health', (req, res) => res.json({ status: 'ok', version: APP_VERSION }));
app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Payload too large' });
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON' });
  console.error('Unhandled error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});
app.listen(PORT, () => { console.log(`Vermeer v${APP_VERSION} running on port ${PORT}`); loadDB(); });

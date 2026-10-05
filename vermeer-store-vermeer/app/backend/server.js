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
const APP_VERSION = '2.8.0';

// ─── PDF-Dokumente (2.6.0) ────────────────────────────────────────
// Ein PDF ist aus Sicht der Speicherung exakt ein Foto: eine Ganzdatei,
// die einmal per AES-256-GCM eingepackt wird. Bewusst KEIN eigener
// Verschlüsselungskontext und kein unverschlüsselter Sonderweg – jede
// Ausnahme müsste sonst in migrateUserPhotos, resolveReadKey, Export und
// jedem Torwächter mitgeführt werden. Unterschiedlich ist nur zweierlei:
// das Thumbnail (generiertes Symbol statt Bildinhalt) und die Anzeige
// (pdf.js im Canvas statt <img>/<video>).
const PDF_MIME = 'application/pdf';
function isPdfMime(m) { return String(m || '') === PDF_MIME; }

// ─── Animierte GIF-Dateien (2.7.0) ────────────────────────────────
// Ein GIF ist aus Sicht der Speicherung ebenfalls ein ganz normales Foto:
// Ganzdatei-AES-256-GCM, kein eigener Verschlüsselungskontext, Thumbnail
// per sharp. sharp liest ohne `animated:true` bewusst nur die ERSTE Seite –
// die Kachel bleibt damit ein Standbild (klein, schnell, wie bisher).
// Unterschiedlich ist allein die Großansicht: ein Canvas kann keine
// Animation zeigen, deshalb rendert das Frontend GIFs als <img> und
// begrenzt sie über die eigene Einstellung `lbMaxGifPx` (Default 200 px).
const GIF_MIME = 'image/gif';
function isGifMime(m) { return String(m || '') === GIF_MIME; }

// ─── Galerie-Einstellungen (Admin, ab 1.11.0) ─────────────────────
// Persistiert in db.json unter `settings`. Alle Werte sind reine
// Darstellungs-/Verarbeitungsparameter (keine Krypto-Relevanz).
const SETTINGS_DEFAULTS = Object.freeze({
  galleryName: 'Vermeer',   // Anzeigename (Login, Navbar, Titel, Wasserzeichen)
  taglineDe: 'Verschlüsselte Fotoverwaltung',   // Untertitel Login-Screen (DE)
  taglineEn: 'Encrypted Photo Management',      // Untertitel Login-Screen (EN)
  lbMaxPhotoPx: 1200,       // Lightbox: längste Kante Fotos
  lbMaxVideoPx: 800,        // Lightbox: längste Kante Videos
  lbMaxGifPx: 200,          // Lightbox: längste Kante animierter GIFs (2.7.0)
  thumbSize: 400,           // Kachel-Thumbnails/Video-Poster (gilt nur für NEUE Uploads)
  colors: Object.freeze({   // CSS-Variablen des Frontends (1.12.0)
    accent:  '#c8a96e', accent2: '#e8c98a',
    bg:      '#0d0d0f', surface: '#151518', surface2: '#1c1c21',
    border:  '#2a2a32', text:    '#e8e6e0', muted:    '#7a7872'
  })
});
const GALLERY_NAME_RE = /^[^<>]{1,40}$/;   // kein HTML, max 40 Zeichen
const TAGLINE_RE = /^[^<>]{0,80}$/;        // kein HTML, max 80 Zeichen (leer = Default)
const HEX_COLOR_RE = /^#[0-9a-fA-F]{6}$/;
function clampInt(v, min, max, dflt) {
  const n = parseInt(v, 10);
  if (!Number.isFinite(n)) return dflt;
  return Math.min(max, Math.max(min, n));
}
function sanitizeSettings(raw) {
  const s = raw && typeof raw === 'object' ? raw : {};
  const name = (typeof s.galleryName === 'string' ? s.galleryName.trim() : '');
  const tagDe = (typeof s.taglineDe === 'string' ? s.taglineDe.trim() : '');
  const tagEn = (typeof s.taglineEn === 'string' ? s.taglineEn.trim() : '');
  const rawColors = s.colors && typeof s.colors === 'object' ? s.colors : {};
  const colors = {};
  for (const [k, dflt] of Object.entries(SETTINGS_DEFAULTS.colors)) {
    const v = typeof rawColors[k] === 'string' ? rawColors[k].trim() : '';
    colors[k] = HEX_COLOR_RE.test(v) ? v.toLowerCase() : dflt;
  }
  return {
    galleryName: GALLERY_NAME_RE.test(name) ? name : SETTINGS_DEFAULTS.galleryName,
    taglineDe: (tagDe && TAGLINE_RE.test(tagDe)) ? tagDe : SETTINGS_DEFAULTS.taglineDe,
    taglineEn: (tagEn && TAGLINE_RE.test(tagEn)) ? tagEn : SETTINGS_DEFAULTS.taglineEn,
    lbMaxPhotoPx: clampInt(s.lbMaxPhotoPx, 400, 4000, SETTINGS_DEFAULTS.lbMaxPhotoPx),
    lbMaxVideoPx: clampInt(s.lbMaxVideoPx, 400, 4000, SETTINGS_DEFAULTS.lbMaxVideoPx),
    // GIFs sind typischerweise klein und sollen klein bleiben – deshalb geht
    // die Untergrenze hier bewusst bis 50 px hinunter (Foto/Video: 400).
    lbMaxGifPx:   clampInt(s.lbMaxGifPx,    50, 4000, SETTINGS_DEFAULTS.lbMaxGifPx),
    thumbSize:    clampInt(s.thumbSize,    200, 800,  SETTINGS_DEFAULTS.thumbSize),
    colors
  };
}
function getSettings(db) { return sanitizeSettings(db.settings); }

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
// Duplikaterkennung (2.5.0): Fingerabdruck des KLARTEXTS, aber als HMAC unter
// einem serverspezifischen Schlüssel – ein reiner SHA-256 in der db.json würde
// sonst bestätigen, dass eine bekannte Datei hier liegt (Bekanntes-Klartext-Test).
const DEDUP_KEY  = crypto.createHash('sha256').update(LEGACY_KEY).update('vermeer-dedup-v1').digest();
function contentHash(buf) { return crypto.createHmac('sha256', DEDUP_KEY).update(buf).digest('hex'); }

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
// ─── Chunked encryption "vmr1" for videos (1 MB blocks, random access) ───
const { spawnSync } = require('child_process');
const os = require('os');
// Extract a 400x400 poster frame from a plaintext video buffer via ffmpeg.
// Uses a short-lived temp file (ffmpeg needs seekable input for mp4/mov);
// the file is removed immediately afterwards.
// Ab 2.5.0 liefert die Funktion zusätzlich die Aufnahmezeit (ffprobe-Tag
// `creation_time`), damit die eine Temp-Datei für beides reicht.
function extractVideoMeta(plainBuf, size) {
  const px = clampInt(size, 200, 800, SETTINGS_DEFAULTS.thumbSize);
  const tmpIn = path.join(os.tmpdir(), `vmr-${crypto.randomBytes(6).toString('hex')}.vid`);
  const tmpOut = tmpIn + '.jpg';
  const vf = `scale=${px}:${px}:force_original_aspect_ratio=increase,crop=${px}:${px}`;
  const out = { poster: null, takenAt: null };
  try {
    fs.writeFileSync(tmpIn, plainBuf);
    // Aufnahmezeit (optional – schlägt sie fehl, bleibt takenAt einfach leer)
    try {
      const pr = spawnSync('ffprobe', ['-v', 'quiet', '-show_entries', 'format_tags=creation_time',
        '-of', 'default=nw=1:nk=1', tmpIn], { timeout: 10000, encoding: 'utf8' });
      const iso = String(pr.stdout || '').trim();
      const ts = iso ? Date.parse(iso) : NaN;
      if (Number.isFinite(ts) && ts > 0) out.takenAt = ts;
    } catch {}
    let r = spawnSync('ffmpeg', ['-y', '-ss', '1', '-i', tmpIn, '-frames:v', '1', '-vf', vf, '-q:v', '4', tmpOut], { timeout: 20000 });
    if (r.status !== 0 || !fs.existsSync(tmpOut)) {
      r = spawnSync('ffmpeg', ['-y', '-i', tmpIn, '-frames:v', '1', '-vf', vf, '-q:v', '4', tmpOut], { timeout: 20000 });
      if (r.status !== 0 || !fs.existsSync(tmpOut)) return out;
    }
    out.poster = fs.readFileSync(tmpOut);
    return out;
  } catch { return out; }
  finally {
    try { fs.unlinkSync(tmpIn); } catch {}
    try { fs.unlinkSync(tmpOut); } catch {}
  }
}
function extractVideoPoster(plainBuf, size) { return extractVideoMeta(plainBuf, size).poster; }

// ─── Aufnahmezeit aus EXIF (2.5.0) ────────────────────────────────
// Minimal-Parser für den APP1/TIFF-Block, den sharp als `metadata().exif`
// zurückgibt – bewusst ohne zusätzliche Dependency. Gelesen werden nur die
// drei Datumsfelder; Priorität: DateTimeOriginal > DateTimeDigitized > DateTime.
// Der Zeitstempel steht in EXIF ohne Zeitzone; er wird als UTC interpretiert.
// Für die reine Sortierung ist das ausreichend und stabil.
function parseExifDateTime(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 16) return null;
  const tiff = buf.toString('ascii', 0, 4) === 'Exif' ? 6 : 0;
  const bom = buf.toString('ascii', tiff, tiff + 2);
  if (bom !== 'II' && bom !== 'MM') return null;
  const le = bom === 'II';
  const u16 = o => (o + 2 > buf.length ? 0 : (le ? buf.readUInt16LE(o) : buf.readUInt16BE(o)));
  const u32 = o => (o + 4 > buf.length ? 0 : (le ? buf.readUInt32LE(o) : buf.readUInt32BE(o)));
  if (u16(tiff + 2) !== 42) return null;
  const PRIO = { 0x9003: 3, 0x9004: 2, 0x0132: 1 };   // Original > Digitized > DateTime
  let best = null;
  const readIFD = (rel, depth) => {
    if (depth > 2 || rel <= 0) return;
    const base = tiff + rel;
    if (base + 2 > buf.length) return;
    const n = u16(base);
    for (let i = 0; i < n; i++) {
      const e = base + 2 + i * 12;
      if (e + 12 > buf.length) return;
      const tag = u16(e), type = u16(e + 2), cnt = u32(e + 4);
      if (tag === 0x8769) { readIFD(u32(e + 8), depth + 1); continue; }   // Zeiger auf Exif-IFD
      const prio = PRIO[tag];
      if (!prio || type !== 2 || cnt < 19) continue;
      const vOff = cnt <= 4 ? (e + 8) : (tiff + u32(e + 8));
      if (vOff < 0 || vOff + 19 > buf.length) continue;
      const m = /^(\d{4}):(\d{2}):(\d{2}) (\d{2}):(\d{2}):(\d{2})$/.exec(buf.toString('ascii', vOff, vOff + 19));
      if (!m) continue;
      const ts = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
      if (Number.isFinite(ts) && ts > 0 && (!best || prio > best.prio)) best = { prio, ts };
    }
  };
  readIFD(u32(tiff + 4), 0);
  return best ? best.ts : null;
}

const CHUNK_SIZE = 1024 * 1024;
const CHUNK_OVERHEAD = 28;   // 12 IV + 16 GCM tag per chunk
function chunkAAD(photoId, index) { return Buffer.from(`vmr1:${photoId}:${index}`); }
function encryptChunked(plainBuf, key, photoId) {
  const parts = []; let count = 0;
  for (let off = 0; off < plainBuf.length; off += CHUNK_SIZE) {
    const slice = plainBuf.subarray(off, Math.min(off + CHUNK_SIZE, plainBuf.length));
    const iv = crypto.randomBytes(12);
    const cip = crypto.createCipheriv('aes-256-gcm', key, iv);
    cip.setAAD(chunkAAD(photoId, count));
    const data = Buffer.concat([cip.update(slice), cip.final()]);
    parts.push(iv, data, cip.getAuthTag());
    count++;
  }
  return { data: Buffer.concat(parts), chunkCount: count, plainSize: plainBuf.length };
}
function readDecryptedChunk(fd, photo, key, index) {
  const encChunkSize = CHUNK_SIZE + CHUNK_OVERHEAD;
  const isLast = index === photo.chunkCount - 1;
  const plainLen = isLast ? (photo.plainSize - index * CHUNK_SIZE) : CHUNK_SIZE;
  const encLen = plainLen + CHUNK_OVERHEAD;
  const buf = Buffer.alloc(encLen);
  fs.readSync(fd, buf, 0, encLen, index * encChunkSize);
  const iv = buf.subarray(0, 12), tag = buf.subarray(encLen - 16), data = buf.subarray(12, encLen - 16);
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAAD(chunkAAD(photo.id, index));
  d.setAuthTag(tag);
  return Buffer.concat([d.update(data), d.final()]);
}
function decryptChunkedAll(filePath, photo, key) {
  const fd = fs.openSync(filePath, 'r');
  try {
    const parts = [];
    for (let i = 0; i < photo.chunkCount; i++) parts.push(readDecryptedChunk(fd, photo, key, i));
    return Buffer.concat(parts);
  } finally { fs.closeSync(fd); }
}

function wrapKey(keyBuf, kek) { const w = encryptGCM(keyBuf, kek); return { iv: w.iv, tag: w.tag, data: w.data.toString('hex') }; }
function unwrapKey(wrapped, kek) { return decryptGCM(Buffer.from(wrapped.data, 'hex'), kek, wrapped.iv, wrapped.tag); }
function generateRecoveryCode() { return crypto.randomBytes(16).toString('hex').match(/.{4}/g).join('-'); }
function normalizeRecoveryCode(code) { return String(code || '').toLowerCase().replace(/[^0-9a-f]/g, ''); }

// In-memory key caches: sessionID → Buffer. Never on disk.
const dekCache    = new Map();  // main user's personal DEK
const familyCache = new Map();  // family/group DEK (owner + observers)
// Admin-Beobachter-Verknüpfung (2.0.0): sessionID → Map(ownerId → family DEK).
// Ein Admin kann als Beobachter mehrerer Hauptbenutzer verknüpft sein und
// braucht deshalb pro Besitzer einen eigenen Familienschlüssel im RAM.
const linkedFamilyCache = new Map();
setInterval(() => { if (dekCache.size > 2000) dekCache.clear(); if (familyCache.size > 2000) familyCache.clear(); if (linkedFamilyCache.size > 2000) linkedFamilyCache.clear(); }, 3600000);

// ─── Database ─────────────────────────────────────────────────────
const SHARED_ALBUM_ID = '__shared__';
const MAX_VIEW_LOG = 500;

// ─── Robustes Schreiben der db.json (2.5.0) ───────────────────────
// Die db.json hält sämtliche verpackten Schlüssel – ist sie zerstört, sind die
// Fotos unwiederbringlich, obwohl die verschlüsselten Dateien noch daliegen.
// Deshalb: Schreiben in eine Temp-Datei mit fsync und atomarem rename (ein
// Stromausfall kann so nie eine halb geschriebene Datei hinterlassen) plus
// rollierende Kopien db.json.1 … db.json.5 (max. eine pro Stunde).
const DB_BACKUPS = 5;
const DB_BACKUP_INTERVAL = 3600000;   // höchstens stündlich rotieren
let lastDbBackupAt = 0;
function dbBackupPath(i) { return `${DB_FILE}.${i}`; }
function rotateDbBackups() {
  try {
    if (!fs.existsSync(DB_FILE)) return;
    for (let i = DB_BACKUPS - 1; i >= 1; i--) {
      const from = dbBackupPath(i), to = dbBackupPath(i + 1);
      if (fs.existsSync(from)) fs.renameSync(from, to);
    }
    fs.copyFileSync(DB_FILE, dbBackupPath(1));
  } catch (e) { console.error('DB backup rotation failed:', e.message); }
}
// Liest die db.json und fällt bei defektem Inhalt auf die jüngste brauchbare
// Sicherung zurück (laut und im Log sichtbar, damit es nicht unbemerkt bleibt).
function readDbFile() {
  const candidates = [DB_FILE];
  for (let i = 1; i <= DB_BACKUPS; i++) candidates.push(dbBackupPath(i));
  for (const f of candidates) {
    if (!fs.existsSync(f)) continue;
    try {
      const parsed = JSON.parse(fs.readFileSync(f, 'utf8'));
      if (parsed && Array.isArray(parsed.users)) {
        if (f !== DB_FILE) console.error(`DB RECOVERY: ${DB_FILE} unusable – falling back to ${f}`);
        return parsed;
      }
      console.error(`DB file has no users array: ${f}`);
    } catch (e) { console.error(`DB file unreadable (${f}):`, e.message); }
  }
  throw new Error('No readable database file – refusing to start with an empty database');
}

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const db = { users: [], albums: [], photos: [] };
    db.users.push({
      id: uid(), username: 'admin', passwordHash: bcrypt.hashSync('admin', 12),
      role: 'admin', type: 'admin', canViewAlbums: [], mustChangePassword: true, createdAt: Date.now()
    });
    saveDB(db); return db;
  }
  const db = readDbFile();
  if (!db.albums) db.albums = [];
  if (!db.photos) db.photos = [];
  if (!db.observerLoginLog) db.observerLoginLog = [];
  db.settings = sanitizeSettings(db.settings);   // Defaults ergänzen / Werte begrenzen (1.11.0)
  db.photos.forEach(p => { if (!Array.isArray(p.linkedAlbumIds)) p.linkedAlbumIds = []; });
  db.users.forEach(u => {
    if (!u.canViewAlbums) u.canViewAlbums = [];
    if (u.mustChangePassword === undefined) u.mustChangePassword = false;
    if (!u.type) u.type = u.role === 'admin' ? 'admin' : 'user';   // migrate pre-0.9
  });
  db.albums.forEach(a => {
    if (!a.views) a.views = 0;
    if (a.hidden === undefined) a.hidden = false;
    // 2.5.0: manuelle Reihenfolge – fehlendes Feld = Standardsortierung,
    // kaputtes Feld wird still verworfen (defensive Selbstheilung).
    if (a.photoOrder !== undefined && !Array.isArray(a.photoOrder)) delete a.photoOrder;
  });
  db.photos.forEach(p => {
    if (p.shared === undefined) p.shared = false;
    if (p.views === undefined) p.views = 0;
    if (p.downloads === undefined) p.downloads = 0;
    if (p.viewLog === undefined) p.viewLog = [];
  });
  return db;
}
function saveDB(db) {
  const now = Date.now();
  if (now - lastDbBackupAt > DB_BACKUP_INTERVAL) { lastDbBackupAt = now; rotateDbBackups(); }
  const tmp = DB_FILE + '.tmp';
  const data = JSON.stringify(db, null, 2);
  const fd = fs.openSync(tmp, 'w');
  try { fs.writeSync(fd, data); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(tmp, DB_FILE);
  // Verzeichnis-fsync: sonst kann der rename-Eintrag bei Stromausfall verloren gehen
  try { const dfd = fs.openSync(DATA_DIR, 'r'); try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); } } catch {}
}
function uid() { return crypto.randomBytes(8).toString('hex'); }
const ID_RE = /^[a-f0-9]{16}$/;   // uid() format – blocks path traversal / injection

// ─── Papierkorb mit Rückgängig-Fenster (2.5.0) ────────────────────
// Löschen setzt zunächst nur `deletedAt`; die verschlüsselten Dateien bleiben
// liegen, bis der Janitor sie nach PHOTO_TRASH_TTL endgültig entfernt. In der
// Zwischenzeit kann der Besitzer die Aktion rückgängig machen. Alle Leseflächen
// gehen über `findPhoto`/`isAlive`, damit gelöschte Fotos nirgends auftauchen.
const PHOTO_TRASH_TTL = 10 * 60 * 1000;
function isAlive(p) { return !!p && !p.deletedAt; }
function findPhoto(db, id) { const p = db.photos.find(x => x.id === id); return isAlive(p) ? p : undefined; }

// ─── Manuelle Reihenfolge je Album (2.5.0) ────────────────────────
// Die Position gehört zur BEZIEHUNG Foto↔Album, nicht zum Foto: ein Foto kann
// über `linkedAlbumIds` in mehreren Alben liegen und dort verschiedene Plätze
// haben. Deshalb liegt die Reihenfolge als ID-Liste am Album.
// Fehlt `photoOrder`, gilt wie bisher "neueste zuerst". Unbekannte IDs (gelöscht,
// entlinkt) werden beim Lesen ignoriert und beim nächsten Schreiben entfernt.
function albumHasManualOrder(album) { return Array.isArray(album?.photoOrder); }
function sortPhotosForAlbum(album, list) {
  if (!albumHasManualOrder(album)) return list.slice().sort((a, b) => b.uploadedAt - a.uploadedAt);
  const pos = new Map();
  album.photoOrder.forEach((id, i) => { if (!pos.has(id)) pos.set(id, i); });
  const listed = [], rest = [];
  list.forEach(p => (pos.has(p.id) ? listed : rest).push(p));
  listed.sort((a, b) => pos.get(a.id) - pos.get(b.id));
  // Neu hinzugekommene Fotos hängen chronologisch hinten an (Aufnahmezeit,
  // ersatzweise Upload-Zeit) – so wächst ein kuratiertes Album vorhersagbar.
  rest.sort((a, b) => (a.takenAt || a.uploadedAt) - (b.takenAt || b.uploadedAt));
  return listed.concat(rest);
}
// Alle lebenden Fotos, die in diesem Album erscheinen (Home-Album oder verlinkt)
function photosOfAlbum(db, albumId) { return db.photos.filter(p => isAlive(p) && photoInAlbum(p, albumId)); }

// Janitor: räumt abgelaufene Papierkorb-Einträge endgültig ab (Dateien,
// Cover-Verweise und Einträge in den Sortierlisten).
function purgeExpiredPhotos() {
  try {
    const db = loadDB();
    const cutoff = Date.now() - PHOTO_TRASH_TTL;
    const gone = db.photos.filter(p => p.deletedAt && p.deletedAt < cutoff);
    if (!gone.length) return;
    const goneIds = new Set(gone.map(p => p.id));
    gone.forEach(p => {
      [path.join(PHOTOS_DIR, `${p.id}.enc`), path.join(THUMBS_DIR, `${p.id}.enc`)]
        .forEach(f => { try { fs.unlinkSync(f); } catch {} });
    });
    db.photos = db.photos.filter(p => !goneIds.has(p.id));
    db.albums.forEach(a => {
      if (a.coverPhotoId && goneIds.has(a.coverPhotoId)) delete a.coverPhotoId;
      if (Array.isArray(a.photoOrder)) a.photoOrder = a.photoOrder.filter(id => !goneIds.has(id));
    });
    saveDB(db);
    console.log(`Trash: ${gone.length} photo(s) permanently removed`);
  } catch (e) { console.error('Trash purge error:', e.message); }
}
setInterval(purgeExpiredPhotos, 120000);

// Zentrale View-Zählung mit Owner-Ausnahme und 10-Min-Dedup pro Nutzer.
// Wird von /view (Lightbox-Öffnung) UND als serverseitiges Sicherheitsnetz
// von /stream bzw. /full (Videos) genutzt – das Dedup-Fenster verhindert
// Doppelzählung, wenn beide Pfade beim selben Abspielen feuern (1.12.1).
function countViewOnce(db, photo, userId) {
  if (photo.ownerId === userId) return false;
  const tenMinAgo = Date.now() - 600000;
  if ((photo.viewLog || []).some(e => e.userId === userId && e.ts > tenMinAgo)) return false;
  trackPhotoView(db, photo.id, userId);
  return true;
}

function trackPhotoView(db, photoId, userId) {
  const photo = findPhoto(db, photoId); if (!photo) return;
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
// Versteckte Alben für fremde Betrachter ausblenden (2.1.0).
// Das Recht wird pro Beobachter (`user.canSeeHidden`) bzw. pro Verknüpfung
// (`link.canSeeHidden`) vergeben, Default ist "nein" (Feld fehlt = false).
// OHNE das Recht verschwindet ein verstecktes Album samt Unteralben und Fotos
// vollständig aus der Sicht – keine Kachel, kein Fotolisten-Zugriff, kein
// Thumb/Full/Stream. MIT dem Recht verhält es sich wie beim Besitzer:
// sichtbar, aber weiterhin durch die PIN gesperrt.
// Der Schlüsselkontext bleibt unberührt (`albumIsFamilyGranted` liest weiter
// die rohen Freigabelisten) – ein Umschalten löst also keine Umschlüsselung aus.
function filterHiddenAlbums(db, ids, allowHidden) {
  return allowHidden ? ids : ids.filter(id => !effectiveHidden(db, id));
}
function visibleAlbumIds(db, userId) {
  const user = db.users.find(u => u.id === userId);
  if (!user) return [];
  if (user.type === 'admin') return db.albums.map(a => a.id);
  if (user.type === 'observer')
    return filterHiddenAlbums(db, expandAlbumIds(db, user.canViewAlbums || []), !!user.canSeeHidden);
  const owned = db.albums.filter(a => a.ownerId === userId).map(a => a.id);
  // Eigene und per Admin-Grant zugeteilte Alben bleiben ungefiltert –
  // der Hidden-Filter betrifft nur die Beobachter-Sicht.
  const ids = new Set(expandAlbumIds(db, [...owned, ...(user.canViewAlbums || [])]));
  // Verknüpfte Alben (2.0.0) erst ab bestätigter Verknüpfung – vorher fehlt der
  // Schlüssel. Der Hidden-Filter gilt pro Verknüpfung, weil ein Konto bei
  // mehreren Besitzern mit unterschiedlichem Recht verknüpft sein kann.
  familyLinksOf(user).forEach(l => {
    if (linkExpired(l) || l.status !== 'active') return;
    filterHiddenAlbums(db, expandAlbumIds(db, l.albumIds || []), !!l.canSeeHidden).forEach(id => ids.add(id));
  });
  return [...ids];
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
// A photo appears in an album if it's its home album OR it's linked there
function photoInAlbum(p, albumId) {
  return p.albumId === albumId || (Array.isArray(p.linkedAlbumIds) && p.linkedAlbumIds.includes(albumId));
}
// Key context of an album: 'shared' | 'family' | 'user' – determines link compatibility
function albumKeyContext(db, albumId) {
  if (albumIsGranted(db, albumId)) return 'shared';
  if (albumIsFamilyGranted(db, albumId)) return 'family';
  return 'user';
}
function albumIsGranted(db, albumId) {
  const chain = ancestorChain(db, albumId);
  return db.users.some(u => u.type === 'user' && (u.canViewAlbums || []).some(id => chain.includes(id)));
}
// Granted to any OBSERVER → owner's family key.
// Ab 2.0.0 zählt auch ein als Beobachter verknüpfter Hauptbenutzer
// (familyLinks), damit die betroffenen Alben in den Familien-Kontext
// umgeschlüsselt werden statt in den serverweiten 'shared'-Kontext.
function albumIsFamilyGranted(db, albumId) {
  const chain = ancestorChain(db, albumId);
  if (db.users.some(u => u.type === 'observer' && (u.canViewAlbums || []).some(id => chain.includes(id)))) return true;
  return db.users.some(u => u.type === 'user' &&
    familyLinksOf(u).some(l => !linkExpired(l) && (l.albumIds || []).some(id => chain.includes(id))));
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
  // Hauptbenutzer, der als Beobachter dieses Besitzers verknüpft ist (2.0.0).
  // Die Verknüpfung wird pro Zugriff nachgeprüft, damit ein Entzug sofort
  // greift und nicht erst beim nächsten Login des Benutzers.
  const linked = linkedFamilyCache.get(req.sessionID);
  if (linked && linked.has(ownerId)) {
    if (findFamilyLink(me, ownerId)?.status === 'active') return linked.get(ownerId);
    linked.delete(ownerId);
  }
  return null;
}

// ─── Beobachter-Verknüpfung bestehender Benutzer (2.0.0) ──────────
// Ein Konto MIT ADMIN-RECHTEN kann bestehende Hauptbenutzer (ohne
// Adminrechte) als Beobachter seiner eigenen Alben verknüpfen. Der
// verknüpfte Benutzer behält sein Konto, seine Alben und seinen eigenen
// Schlüssel und bekommt zusätzlich den Familienschlüssel des Admins –
// verpackt unter seinem EIGENEN persönlichen DEK, damit kein Passwort
// geteilt werden muss. Weil der Admin den DEK des anderen nicht kennt,
// läuft die Übergabe über einen Einmal-Code:
//   1. Admin verknüpft   → familyKey wird mit kdf(code) verpackt (status 'pending')
//   2. Benutzer löst den Code in seiner Sitzung ein → Umpacken unter seinen DEK ('active')
// Der Code läuft nach 7 Tagen ab; solange liegt der Familienschlüssel nur
// passwortabgeleitet verpackt auf der Platte, nie im Klartext.
const LINK_TTL_MS = 7 * 24 * 3600 * 1000;
function familyLinksOf(user) { return Array.isArray(user?.familyLinks) ? user.familyLinks : []; }
function findFamilyLink(user, ownerId) { return familyLinksOf(user).find(l => l.ownerId === ownerId); }
function linkExpired(link) { return link.status === 'pending' && link.expiresAt && Date.now() > link.expiresAt; }
// Alle Hauptbenutzer, die bei diesem Besitzer als Beobachter verknüpft (oder angefragt) sind
function linkedUsersFor(db, ownerId) {
  return db.users.filter(u => u.type === 'user' && familyLinksOf(u).some(l => l.ownerId === ownerId && !linkExpired(l)));
}
// Alben, die einem Benutzer über Verknüpfungen zustehen
function linkedAlbumIdsFor(user, activeOnly) {
  const ids = [];
  familyLinksOf(user).forEach(l => {
    if (linkExpired(l)) return;
    if (activeOnly && l.status !== 'active') return;
    (l.albumIds || []).forEach(id => ids.push(id));
  });
  return ids;
}
// Verknüpfte Familienschlüssel einer Sitzung aus dem persönlichen DEK auspacken
function loadLinkedFamilies(user, dek, sessionID) {
  const map = new Map();
  familyLinksOf(user).forEach(l => {
    if (l.status !== 'active' || !l.familyWrappedDEK) return;
    try { map.set(l.ownerId, unwrapKey(l.familyWrappedDEK, dek)); } catch {}
  });
  if (map.size) linkedFamilyCache.set(sessionID, map); else linkedFamilyCache.delete(sessionID);
  return map;
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
    // Verknüpfter Hauptbenutzer (2.0.0): Recht vorhanden, Schlüssel fehlt nur in dieser Sitzung
    if (me && findFamilyLink(me, photo.ownerId)?.status === 'active')
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
      const isChunked = p.encFormat === 'chunked';
      const isVideo = (p.mimeType || '').startsWith('video/');
      const needsLegacy = !p.encryption;
      const needsReenc = p.encryption && p.reencryptPending;
      const needsChunkConvert = p.encryption && isVideo && !isChunked;   // v1.6 whole-file videos
      const needsPoster = p.encryption && isVideo && !p.thumbIv;         // retrofit poster frames
      if (!needsLegacy && !needsReenc && !needsChunkConvert && !needsPoster) continue;
      const photoPath = path.join(PHOTOS_DIR, `${p.id}.enc`);
      const thumbPath = path.join(THUMBS_DIR, `${p.id}.enc`);
      if (!fs.existsSync(photoPath)) continue;

      const curKey = !p.encryption ? null : (p.encryption === 'family' ? familyDek : (p.encryption === 'shared' ? SHARED_KEY : dek));
      if (p.encryption && !curKey) continue;

      let plain, thumbPlain = null;
      try {
        if (needsLegacy) {
          plain = decryptLegacyCBC(fs.readFileSync(photoPath), p.iv);
          if (fs.existsSync(thumbPath)) thumbPlain = decryptLegacyCBC(fs.readFileSync(thumbPath), p.thumbIv);
        } else if (isChunked) {
          plain = decryptChunkedAll(photoPath, p, curKey);
        } else {
          plain = decryptGCM(fs.readFileSync(photoPath), curKey, p.iv, p.tag);
          if (!isVideo && fs.existsSync(thumbPath)) thumbPlain = decryptGCM(fs.readFileSync(thumbPath), curKey, p.thumbIv, p.thumbTag);
        }
      } catch (e) { console.error('Migration decrypt failed:', p.id, e.message); continue; }

      let target;
      if (albumIsGranted(db, p.albumId)) target = { key: SHARED_KEY, enc: 'shared' };
      else if (albumIsFamilyGranted(db, p.albumId) && familyDek) target = { key: familyDek, enc: 'family' };
      else target = { key: dek, enc: 'user' };

      if (isVideo) {
        // Nur neu verschlüsseln, wenn Format/Schlüssel sich ändern (nicht bei reinem Poster-Nachrüsten)
        if (needsLegacy || needsReenc || needsChunkConvert) {
          const ec = encryptChunked(plain, target.key, p.id);
          fs.writeFileSync(photoPath, ec.data);
          p.encFormat = 'chunked'; p.chunkSize = CHUNK_SIZE;
          p.chunkCount = ec.chunkCount; p.plainSize = ec.plainSize;
          delete p.iv; delete p.tag;
        }
        if (!p.thumbIv) {
          const poster = extractVideoPoster(plain, getSettings(db).thumbSize);
          if (poster) {
            const e2 = encryptGCM(poster, target.key);
            fs.writeFileSync(thumbPath, e2.data);
            p.thumbIv = e2.iv; p.thumbTag = e2.tag;
          }
        }
      } else {
        const e1 = encryptGCM(plain, target.key);
        fs.writeFileSync(photoPath, e1.data);
        p.iv = e1.iv; p.tag = e1.tag;
        if (thumbPlain) { const e2 = encryptGCM(thumbPlain, target.key); fs.writeFileSync(thumbPath, e2.data); p.thumbIv = e2.iv; p.thumbTag = e2.tag; }
      }
      p.encryption = target.enc;
      delete p.reencryptPending;
      changed++;
    }
    if (changed) { saveDB(db); console.log(`Migration: ${changed} item(s) re-encrypted for ${userId}`); }
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
  // 2.6.0: `wasm-unsafe-eval` ist für pdf.js nötig – die Decoder für JBIG2,
  // JPEG-2000 und ICC-Profile in gescannten PDFs sind WebAssembly. Das Schlüssel-
  // wort erlaubt ausschließlich das Übersetzen von WASM, KEIN eval() für
  // JavaScript. `worker-src` wird explizit gesetzt (statt über default-src zu
  // erben), damit der pdf.js-Worker beim Nachziehen der CSP nicht stillschweigend
  // wegfällt. `object-src 'none'` bleibt: das eingebaute PDF-Plugin des Browsers
  // wird bewusst NICHT genutzt (es hätte einen Download-Knopf).
  res.set('Content-Security-Policy',
    "default-src 'self'; " +
    "img-src 'self' data: blob:; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; " +
    "worker-src 'self' blob:; " +
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
// 2.5.0: Das Frontend steckt vollständig in einer einzigen index.html. Wird sie
// gecacht, laufen Handys nach einem Update wochenlang auf einer alten Fassung
// (Ursache mehrerer Altfehler). `no-store` genau für HTML kostet praktisch
// nichts und macht das "hart neu laden" überflüssig.
app.use(express.static(path.join(__dirname, '../frontend'), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) res.set('Cache-Control', 'no-store, must-revalidate');
    // pdf.js (2.6.0): versionsgebunden und unveränderlich – der Worker ist über
    // 1 MB groß und soll nicht bei jedem Seitenaufruf neu geladen werden.
    else if (filePath.includes(`${path.sep}vendor${path.sep}`)) res.set('Cache-Control', 'public, max-age=31536000, immutable');
  }
}));

// ─── pdf.js (2.6.0) ───────────────────────────────────────────────
// Liegt als mitgelieferte Datei unter app/frontend/vendor/pdfjs und wird von
// der express.static-Regel oben mit ausgeliefert. Bewusst NICHT von einem CDN
// (CSP `script-src 'self'`, Selbsthosting-Prinzip, funktioniert auch ohne
// Internetzugang des Umbrel) und bewusst NICHT als npm-Abhängigkeit: pdfjs-dist
// zieht optional `@napi-rs/canvas` nach – zweistellige MB an Native-Binaries für
// serverseitiges Rendern, das hier niemand braucht.
// Mitgeliefert ist nur, was der Browser wirklich holt (Fassung siehe
// PDFJS_VERSION); `web/viewer.html` fehlt bewusst – das wäre ein vollständiger
// PDF-Viewer MIT Download- und Druckknopf auf der eigenen Origin und damit
// genau die Lücke, die die Canvas-Anzeige schließen soll.
const PDFJS_VERSION = '6.2.108';

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
    if (!isImage && !isVideo && !isPdfMime(file.mimetype)) return cb(new Error('Images, videos (mp4/webm/mov) or PDF only'));
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
      loadLinkedFamilies(user, dek, req.sessionID);   // Admin-Beobachter-Verknüpfungen (2.0.0)
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
  dekCache.delete(req.sessionID); familyCache.delete(req.sessionID); linkedFamilyCache.delete(req.sessionID);
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
  // Neuer DEK → unter dem alten DEK verpackte Verknüpfungen sind nicht mehr
  // entpackbar; sie müssen von den Besitzern neu vergeben werden (2.0.0).
  if (!restored && familyLinksOf(user).length) user.familyLinks = [];

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
  // Admin-Beobachter-Verknüpfungen auf den gelöschten Besitzer mit entfernen (2.0.0)
  db.users.forEach(u => { if (Array.isArray(u.familyLinks)) u.familyLinks = u.familyLinks.filter(l => l.ownerId !== removedId); });
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
  const list = db.users.filter(u => u.type === 'observer' && u.parentUserId === req.session.userId)
    .map(u => ({ id: u.id, username: u.username, createdAt: u.createdAt, canViewAlbums: u.canViewAlbums || [], canSeeHidden: !!u.canSeeHidden, mustChangePassword: !!u.mustChangePassword, lastLoginAt: u.lastLoginAt || null, linked: false }));
  // Als Beobachter verknüpfte Hauptbenutzer (2.0.0) erscheinen in derselben Liste
  linkedUsersFor(db, req.session.userId).forEach(a => {
    const l = findFamilyLink(a, req.session.userId);
    list.push({
      id: a.id, username: a.username, createdAt: l.createdAt || null,
      canViewAlbums: l.albumIds || [], canSeeHidden: !!l.canSeeHidden, mustChangePassword: false, lastLoginAt: null,
      linked: true, status: l.status, expiresAt: l.expiresAt || null, confirmedAt: l.confirmedAt || null
    });
  });
  res.json(list);
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
  const { canViewAlbums, canSeeHidden } = req.body;
  const db = loadDB();
  const obs = db.users.find(u => u.id === req.params.id && u.type === 'observer' && u.parentUserId === req.session.userId);
  if (!obs) return res.status(404).json({ error: 'Observer not found' });
  const myAlbums = new Set(db.albums.filter(a => a.ownerId === req.session.userId).map(a => a.id));
  const requested = (Array.isArray(canViewAlbums) ? canViewAlbums : []).filter(id => myAlbums.has(id));
  const before = new Set(obs.canViewAlbums || []);
  obs.canViewAlbums = requested;
  setHiddenRight(obs, canSeeHidden);
  const pendingCount = markFamilyPending(db, req.session.userId, requested.filter(id => !before.has(id)));
  saveDB(db);
  // Owner is online → run migration right away
  const dek = dekCache.get(req.sessionID);
  const fam = familyCache.get(req.sessionID);
  if (dek) setImmediate(() => migrateUserPhotos(req.session.userId, dek, fam));
  res.json({ success: true, pendingCount });
});

// Recht "darf versteckte Alben sehen" setzen (2.1.0). Undefiniert = unverändert
// (ältere, gecachte Frontends schicken das Feld nicht mit); false löscht das
// Feld wieder, damit die db.json nicht mit Default-Werten wächst.
function setHiddenRight(target, value) {
  if (value === undefined) return;
  if (value) target.canSeeHidden = true; else delete target.canSeeHidden;
}

// Neu freigegebene Alben für die Umschlüsselung in den Familien-Kontext
// vormerken (gemeinsam genutzt von Beobachter- und Admin-Verknüpfung).
function markFamilyPending(db, ownerId, newlyGranted) {
  if (!newlyGranted.length) return 0;
  const affected = new Set();
  newlyGranted.forEach(id => { affected.add(id); descendantAlbumIds(db, id).forEach(d => affected.add(d)); });
  let n = 0;
  db.photos.forEach(p => {
    if (p.ownerId === ownerId && affected.has(p.albumId) && p.encryption === 'user' && !p.reencryptPending) { p.reencryptPending = true; n++; }
  });
  return n;
}

// ═══ BESTEHENDE BENUTZER ALS BEOBACHTER VERKNÜPFEN (2.0.0) ══════
// Nur ein Konto MIT ADMIN-RECHTEN darf verknüpfen: es setzt voraus, dass
// man andere Konten auflisten und an die eigenen Alben binden kann. Ziel
// sind bestehende Hauptbenutzer OHNE Adminrechte – sie behalten Konto,
// eigene Alben und eigenen Schlüssel und bekommen die freigegebenen Alben
// lesend dazu, ohne dass ein zweites Beobachterkonto nötig ist.
function requireAdminActor(req, res, next) {
  const db = loadDB();
  if (getUser(db, req)?.type !== 'admin') return res.status(403).json({ error: 'Admin rights required' });
  next();
}

// Verknüpfbare Konten: Hauptbenutzer ohne Adminrechte, noch nicht verknüpft
app.get('/api/observers/link-candidates', requireMainUser, requireAdminActor, (req, res) => {
  const db = loadDB();
  const already = new Set(linkedUsersFor(db, req.session.userId).map(u => u.id));
  res.json(db.users
    .filter(u => u.type === 'user' && u.id !== req.session.userId && !already.has(u.id))
    .map(u => ({ id: u.id, username: u.username })));
});

// Verknüpfung anlegen bzw. Einmal-Code neu ausstellen
app.post('/api/observers/link', requireMainUser, requireAdminActor, requireDEK, (req, res) => {
  const userId = String(req.body?.userId || '');
  if (!ID_RE.test(userId)) return res.status(400).json({ error: 'Invalid user id' });
  if (userId === req.session.userId) return res.status(400).json({ error: 'Cannot link your own account' });
  const db = loadDB();
  const target = db.users.find(u => u.id === userId);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.type !== 'user') return res.status(403).json({ error: 'Only main users without admin rights can be linked' });
  const me = getUser(db, req);
  const fam = ensureFamilyKey(db, me, dekCache.get(req.sessionID));
  if (!fam) return res.status(500).json({ error: 'Family key error' });
  familyCache.set(req.sessionID, fam);
  if (!Array.isArray(target.familyLinks)) target.familyLinks = [];
  const existing = findFamilyLink(target, me.id);
  if (existing && existing.status === 'active') return res.status(409).json({ error: 'Already linked' });

  const code = generateRecoveryCode();
  const salt = crypto.randomBytes(16).toString('hex');
  const link = existing || { ownerId: me.id, albumIds: [], createdAt: Date.now() };
  link.status = 'pending';
  link.salt = salt;
  link.wrapped = wrapKey(fam, kdf(normalizeRecoveryCode(code), salt));   // Transport nur unter dem Einmal-Code
  link.expiresAt = Date.now() + LINK_TTL_MS;
  delete link.familyWrappedDEK;
  if (!existing) target.familyLinks.push(link);
  saveDB(db);
  res.status(201).json({ id: target.id, username: target.username, code, expiresAt: link.expiresAt });
});

// Album-Freigabe der Verknüpfung ändern
app.put('/api/observers/link/:userId/albums', requireMainUser, requireAdminActor, (req, res) => {
  const { canViewAlbums, canSeeHidden } = req.body;
  const db = loadDB();
  const target = db.users.find(u => u.id === req.params.userId && u.type === 'user');
  const link = target ? findFamilyLink(target, req.session.userId) : null;
  if (!link) return res.status(404).json({ error: 'Link not found' });
  const myAlbums = new Set(db.albums.filter(a => a.ownerId === req.session.userId).map(a => a.id));
  const requested = (Array.isArray(canViewAlbums) ? canViewAlbums : []).filter(id => myAlbums.has(id));
  const before = new Set(link.albumIds || []);
  link.albumIds = requested;
  setHiddenRight(link, canSeeHidden);
  const pendingCount = markFamilyPending(db, req.session.userId, requested.filter(id => !before.has(id)));
  const dek = dekCache.get(req.sessionID);
  let fam = familyCache.get(req.sessionID);
  if (!fam && dek) { fam = ensureFamilyKey(db, getUser(db, req), dek); if (fam) familyCache.set(req.sessionID, fam); }
  saveDB(db);
  if (dek) setImmediate(() => migrateUserPhotos(req.session.userId, dek, fam));
  res.json({ success: true, pendingCount });
});

// Verknüpfung durch den Besitzer entziehen
app.delete('/api/observers/link/:userId', requireMainUser, requireAdminActor, (req, res) => {
  const db = loadDB();
  const target = db.users.find(u => u.id === req.params.userId);
  if (!target || !Array.isArray(target.familyLinks)) return res.status(404).json({ error: 'Link not found' });
  const before = target.familyLinks.length;
  target.familyLinks = target.familyLinks.filter(l => l.ownerId !== req.session.userId);
  if (target.familyLinks.length === before) return res.status(404).json({ error: 'Link not found' });
  saveDB(db);
  res.json({ success: true });
});

// ─── Sicht des verknüpften Admins ─────────────────────────────────
app.get('/api/me/links', requireMainUser, (req, res) => {
  const db = loadDB();
  const me = getUser(db, req);
  const active = [], pending = [];
  familyLinksOf(me).forEach(l => {
    const owner = db.users.find(u => u.id === l.ownerId);
    const entry = {
      ownerId: l.ownerId, ownerName: owner ? owner.username : '?',
      albumCount: (l.albumIds || []).length, createdAt: l.createdAt || null
    };
    if (l.status === 'active') { entry.confirmedAt = l.confirmedAt || null; active.push(entry); }
    else if (!linkExpired(l)) { entry.expiresAt = l.expiresAt || null; pending.push(entry); }
  });
  res.json({ active, pending, keysLoaded: (linkedFamilyCache.get(req.sessionID)?.size || 0) });
});

// Einmal-Code einlösen: Familienschlüssel unter den eigenen DEK umpacken
app.post('/api/me/links/confirm', rateLimit(5, 900000), requireMainUser, requireDEK, (req, res) => {
  const db = loadDB();
  const me = getUser(db, req);
  const code = normalizeRecoveryCode(req.body?.code);
  if (code.length !== 32) return res.status(401).json({ error: 'Invalid or expired link code' });
  const dek = dekCache.get(req.sessionID);
  let hit = null, fam = null;
  for (const l of familyLinksOf(me)) {
    if (l.status !== 'pending' || linkExpired(l) || !l.wrapped) continue;
    try { fam = unwrapKey(l.wrapped, kdf(code, l.salt)); hit = l; break; } catch {}
  }
  if (!hit) return res.status(401).json({ error: 'Invalid or expired link code' });
  hit.status = 'active';
  hit.familyWrappedDEK = wrapKey(fam, dek);   // ab jetzt nur noch unter dem eigenen DEK
  hit.confirmedAt = Date.now();
  delete hit.wrapped; delete hit.salt; delete hit.expiresAt;
  saveDB(db);
  loadLinkedFamilies(me, dek, req.sessionID);
  const owner = db.users.find(u => u.id === hit.ownerId);
  res.json({ success: true, ownerName: owner ? owner.username : '?' });
});

// Verknüpfung durch den Admin selbst aufgeben
app.delete('/api/me/links/:ownerId', requireMainUser, (req, res) => {
  const db = loadDB();
  const me = getUser(db, req);
  const before = familyLinksOf(me).length;
  if (!before) return res.status(404).json({ error: 'Link not found' });
  me.familyLinks = me.familyLinks.filter(l => l.ownerId !== req.params.ownerId);
  if (me.familyLinks.length === before) return res.status(404).json({ error: 'Link not found' });
  saveDB(db);
  const cache = linkedFamilyCache.get(req.sessionID);
  if (cache) { cache.delete(req.params.ownerId); if (!cache.size) linkedFamilyCache.delete(req.sessionID); }
  res.json({ success: true });
});

// ═══ ALBUMS ═══════════════════════════════════════════════════════
app.get('/api/albums', requireAuth, (req, res) => {
  const db = loadDB();
  const me = getUser(db, req);
  const allowed = visibleAlbumIds(db, req.session.userId);
  const allowedSet = new Set(allowed);
  // 2.1.0: Zähler und Cover dürfen nur Fotos berücksichtigen, deren Home-Album
  // für diesen Betrachter sichtbar ist – sonst zählt bzw. zeigt die Kachel
  // Inhalte aus einem ausgeblendeten versteckten Album (Thumb liefert 403).
  // 2.5.0: Fotos im Papierkorb zählen und erscheinen nirgends mehr.
  const photoVisible = p => isAlive(p) && ((p.shared && me.type !== 'observer') || allowedSet.has(p.albumId));
  const albums = db.albums.filter(a => allowedSet.has(a.id)).map(a => {
    const owner = db.users.find(u => u.id === a.ownerId);
    const hid = effectiveHidden(db, a.id);
    const locked = hid && !isUnlocked(req, db, a.id);
    const cover = a.coverPhotoId ? findPhoto(db, a.coverPhotoId) : null;
    return {
      id: a.id, name: a.name, parentId: a.parentId,
      ownerId: a.ownerId, ownerName: owner?.username ?? '?',
      description: locked ? '' : (a.description || ''), createdAt: a.createdAt,
      photoCount: locked ? 0 : db.photos.filter(p => photoInAlbum(p, a.id) && photoVisible(p)).length,
      coverPhotoId: (locked || !cover || !photoVisible(cover)) ? null : a.coverPhotoId,
      hidden: !!a.hidden, effectiveHidden: hid, hiddenRootId: hid ? hiddenRootFor(db, a.id) : null, locked,
      manualOrder: albumHasManualOrder(a),   // 2.5.0
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
  // 2.1.0: Wer das Album gar nicht sehen darf, darf auch nicht dagegen
  // PIN-raten (bisher prüfte der Endpoint nur die PIN selbst).
  if (!canViewAlbum(db, req.session.userId, req.params.id)) return res.status(403).json({ error: 'No access to album' });
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
    const photo = findPhoto(db, photoId);
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
    // Clean up links pointing to deleted albums
    if (Array.isArray(p.linkedAlbumIds)) p.linkedAlbumIds = p.linkedAlbumIds.filter(a => !toDelete.includes(a));
    if (!toDelete.includes(p.albumId)) return true;
    [path.join(PHOTOS_DIR, `${p.id}.enc`), path.join(THUMBS_DIR, `${p.id}.enc`)].forEach(f => { try { fs.unlinkSync(f); } catch {} });
    return false;
  });
  db.users.forEach(u => { u.canViewAlbums = (u.canViewAlbums || []).filter(id => !toDelete.includes(id)); });
  db.albums = db.albums.filter(a => !toDelete.includes(a.id));
  saveDB(db); res.json({ success: true });
});

// ═══ UPLOAD ═══════════════════════════════════════════════════════
// Verarbeitet eine empfangene Datei (Buffer im RAM) vollständig:
// Video → chunked vmr1 + ffmpeg-Poster, Bild → GCM + sharp-Thumbnail.
// Wird vom klassischen Upload UND vom Chunked-Upload-Finish genutzt.
// Rückgabe: der neue Datensatz ODER `{ duplicate: true }`, wenn derselbe Nutzer
// diese Datei bereits abgelegt hat (Fingerabdruck über den Klartext, 2.5.0).
// ─── PDF-Thumbnail (2.6.0, Variante T1) ───────────────────────────
// Bewusst KEIN Rendern der ersten Seite: dafür bräuchte das Image poppler
// oder mupdf (libvips/sharp kann PDF nur, wenn es mit PDFium/poppler-glib
// übersetzt wurde – im Alpine-Paket ist das nicht der Fall). Stattdessen
// ein aus den Galerie-Farben erzeugtes Dokumentsymbol, exakt nach dem
// Muster der PWA-Icons. Es entsteht EINMAL beim Upload und wird wie jedes
// andere Thumbnail verschlüsselt abgelegt – dadurch funktionieren Kachel,
// Filmstreifen, Album-Cover und Statistik-Vorschau ohne Sonderfall.
// Bewusst ohne <text>: Schriftrendering in librsvg setzt Fonts im Image
// voraus, die dort nicht garantiert sind. Reine Formen rendern immer.
function pdfIconSvg(size, colors) {
  const pw = size * 0.50, ph = size * 0.64;
  const x = (size - pw) / 2, y = (size - ph) / 2;
  const fold = size * 0.15, sw = size * 0.016;
  const lx = x + pw * 0.18, lw = pw * 0.64;
  const l1 = y + ph * 0.52, gap = ph * 0.13, lh = Math.max(1, size * 0.022);
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
    <rect width="${size}" height="${size}" fill="${colors.surface2}"/>
    <path d="M${x} ${y} H${x + pw - fold} L${x + pw} ${y + fold} V${y + ph} H${x} Z"
      fill="${colors.surface}" stroke="${colors.accent}" stroke-width="${sw}" stroke-linejoin="round"/>
    <path d="M${x + pw - fold} ${y} V${y + fold} H${x + pw}"
      fill="none" stroke="${colors.accent}" stroke-width="${sw}" stroke-linejoin="round"/>
    <rect x="${lx}" y="${l1}" width="${lw}" height="${lh}" rx="${lh / 2}" fill="${colors.accent}" opacity="0.75"/>
    <rect x="${lx}" y="${l1 + gap}" width="${lw}" height="${lh}" rx="${lh / 2}" fill="${colors.accent}" opacity="0.55"/>
    <rect x="${lx}" y="${l1 + gap * 2}" width="${lw * 0.6}" height="${lh}" rx="${lh / 2}" fill="${colors.accent}" opacity="0.35"/>
  </svg>`;
}
async function renderPdfThumb(size, colors) {
  const px = clampInt(size, 200, 800, SETTINGS_DEFAULTS.thumbSize);
  return sharp(Buffer.from(pdfIconSvg(px, colors))).jpeg({ quality: 80 }).toBuffer();
}

async function storeIncomingFile(db, file, albumId, ownerId, key, enc) {
  const isVideo = file.mimetype.startsWith('video/');
  const isPdf = isPdfMime(file.mimetype);
  const hash = contentHash(file.buffer);
  const dup = db.photos.find(p => isAlive(p) && p.ownerId === ownerId && p.hash === hash);
  if (dup) return { duplicate: true, existingId: dup.id };
  const photoId = uid();
  const rec = { id: photoId, albumId, ownerId,
    originalName: file.originalname, mimeType: file.mimetype, size: file.size, uploadedAt: Date.now(),
    encryption: enc, hash,
    shared: false, views: 0, downloads: 0, viewLog: [] };
  if (isVideo) {
    const ec = encryptChunked(file.buffer, key, photoId);
    fs.writeFileSync(path.join(PHOTOS_DIR, `${photoId}.enc`), ec.data);
    rec.encFormat = 'chunked'; rec.chunkSize = CHUNK_SIZE;
    rec.chunkCount = ec.chunkCount; rec.plainSize = ec.plainSize;
    const meta = extractVideoMeta(file.buffer, getSettings(db).thumbSize);
    if (meta.takenAt) rec.takenAt = meta.takenAt;
    if (meta.poster) {
      const e2 = encryptGCM(meta.poster, key);
      fs.writeFileSync(path.join(THUMBS_DIR, `${photoId}.enc`), e2.data);
      rec.thumbIv = e2.iv; rec.thumbTag = e2.tag;
    }
  } else if (isPdf) {
    // Ganzdatei-GCM wie bei Fotos; Thumbnail ist das generierte Symbol.
    // Keine EXIF-/Aufnahmezeit – für PDFs bleibt es beim Upload-Zeitpunkt.
    const e1 = encryptGCM(file.buffer, key);
    fs.writeFileSync(path.join(PHOTOS_DIR, `${photoId}.enc`), e1.data);
    rec.iv = e1.iv; rec.tag = e1.tag;
    const s = getSettings(db);
    const thumbBuffer = await renderPdfThumb(s.thumbSize, s.colors);
    const e2 = encryptGCM(thumbBuffer, key);
    fs.writeFileSync(path.join(THUMBS_DIR, `${photoId}.enc`), e2.data);
    rec.thumbIv = e2.iv; rec.thumbTag = e2.tag;
  } else {
    const e1 = encryptGCM(file.buffer, key);
    fs.writeFileSync(path.join(PHOTOS_DIR, `${photoId}.enc`), e1.data);
    rec.iv = e1.iv; rec.tag = e1.tag;
    const ts = getSettings(db).thumbSize;
    // Aufnahmezeit aus EXIF (2.5.0) – dient als Vorsortierung beim Import und
    // als Grundlage für "Nach Aufnahmedatum sortieren". Schlägt das Lesen fehl,
    // bleibt es einfach beim Upload-Zeitpunkt.
    try {
      const md = await sharp(file.buffer).metadata();
      const taken = parseExifDateTime(md && md.exif);
      if (taken) rec.takenAt = taken;
    } catch {}
    // 2.7.0: Auch animierte GIFs laufen genau hier durch. sharp wird bewusst
    // OHNE `{ animated: true }` aufgerufen – es liest damit nur die erste
    // Seite, und das Thumbnail bleibt ein kleines JPEG-Standbild wie bei jedem
    // anderen Foto. Ein animiertes Thumbnail hätte Kachelraster, Filmstreifen
    // und Album-Cover deutlich teurer gemacht, ohne echten Gewinn.
    const thumbBuffer = await sharp(file.buffer).resize(ts, ts, { fit: 'cover', position: 'centre' }).jpeg({ quality: 75 }).toBuffer();
    const e2 = encryptGCM(thumbBuffer, key);
    fs.writeFileSync(path.join(THUMBS_DIR, `${photoId}.enc`), e2.data);
    rec.thumbIv = e2.iv; rec.thumbTag = e2.tag;
  }
  return rec;
}

app.post('/api/photos/upload', requireAuth, requireDEK, (req, res) => {
  upload.array('photos', 50)(req, res, async (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ error: 'File too large (max 200 MB)' });
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

    const uploaded = [], errors = [], duplicates = [];
    for (const file of req.files) {
      try {
        const rec = await storeIncomingFile(db, file, albumId, req.session.userId, key, enc);
        if (rec.duplicate) { duplicates.push(file.originalname); file.buffer = null; continue; }
        db.photos.push(rec);
        uploaded.push({ id: rec.id, name: file.originalname });
        file.buffer = null;
      } catch (e) { console.error('Upload error', file.originalname, e.message); errors.push(file.originalname); }
    }
    saveDB(db); res.json({ uploaded, errors, duplicates });
  });
});

// ═══ CHUNKED UPLOAD (1.10.0) ══════════════════════════════════════
// Umgeht Request-Body-Limits von Reverse-Proxies und Tunneln (z. B.
// 100 MB pro Request bei Cloudflare Free): Der Client zerlegt große
// Dateien in Teile, lädt sie einzeln hoch, der Server setzt sie
// zusammen und verarbeitet sie danach über die NORMALE Pipeline
// (storeIncomingFile → Verschlüsselung, Poster/Thumbnail).
// Sicherheitshinweis (ehrlich): Während des Uploads liegen die noch
// unverschlüsselten Teile als Temp-Datei in /tmp im Container – NICHT
// im persistierten data-Volume. Gelöscht wird bei Finish, Cancel,
// Fehler und per Janitor (TTL 2 h, überlebt auch Server-Neustarts).
const PARTS_DIR = path.join(os.tmpdir(), 'vermeer-parts');
fs.mkdirSync(PARTS_DIR, { recursive: true });
const MAX_UPLOAD_SIZE = 200 * 1024 * 1024;   // wie multer-Limit
const MAX_PART_SIZE = 95 * 1024 * 1024;      // sicher unter Cloudflares 100 MB
const MAX_PENDING_PER_USER = 4;
const PENDING_TTL = 2 * 3600 * 1000;
const pendingUploads = new Map();            // uploadId → Meta (nur RAM)

function cleanupPending(uploadId) {
  const u = pendingUploads.get(uploadId);
  if (!u) return;
  pendingUploads.delete(uploadId);
  try { fs.unlinkSync(u.path); } catch {}
}
setInterval(() => {
  const now = Date.now();
  for (const [id, u] of pendingUploads) if (now - u.createdAt > PENDING_TTL) cleanupPending(id);
  // Waisen-Dateien (z. B. nach Server-Neustart, Map ist dann leer)
  try {
    for (const f of fs.readdirSync(PARTS_DIR)) {
      const fp = path.join(PARTS_DIR, f);
      try { if (now - fs.statSync(fp).mtimeMs > PENDING_TTL) fs.unlinkSync(fp); } catch {}
    }
  } catch {}
}, 900000);

app.post('/api/photos/upload-init', requireAuth, requireDEK, (req, res) => {
  const { albumId, fileName, mimeType, size, partSize } = req.body || {};
  const db = loadDB();
  if (!albumId || !db.albums.find(a => a.id === albumId)) return res.status(404).json({ error: 'Album not found' });
  if (!canUploadToAlbum(db, req.session.userId, albumId)) return res.status(403).json({ error: 'No upload permission' });
  if (effectiveHidden(db, albumId) && !isUnlocked(req, db, albumId)) return res.status(423).json({ error: 'Album locked', code: 'LOCKED' });
  const isImage = typeof mimeType === 'string' && mimeType.startsWith('image/');
  const isVideo = typeof mimeType === 'string' && /^video\/(mp4|webm|quicktime)$/.test(mimeType);
  if (!isImage && !isVideo && !isPdfMime(mimeType)) return res.status(400).json({ error: 'Images, videos (mp4/webm/mov) or PDF only' });
  if (!Number.isInteger(size) || size < 1 || size > MAX_UPLOAD_SIZE) return res.status(400).json({ error: 'File too large (max 200 MB)' });
  if (!Number.isInteger(partSize) || partSize < 1024 * 1024 || partSize > MAX_PART_SIZE) return res.status(400).json({ error: 'Invalid part size' });
  let mine = 0;
  for (const u of pendingUploads.values()) if (u.userId === req.session.userId) mine++;
  if (mine >= MAX_PENDING_PER_USER) return res.status(429).json({ error: 'Too many pending uploads' });
  const uploadId = uid();
  const meta = {
    userId: req.session.userId, albumId,
    fileName: String(fileName || 'upload').slice(0, 200), mimeType,
    size, partSize, partCount: Math.ceil(size / partSize),
    received: new Set(), path: path.join(PARTS_DIR, `${uploadId}.part`),
    createdAt: Date.now()
  };
  fs.writeFileSync(meta.path, Buffer.alloc(0));
  pendingUploads.set(uploadId, meta);
  res.json({ uploadId, partCount: meta.partCount });
});

const partUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_PART_SIZE, files: 1 } });
app.post('/api/photos/upload-part', requireAuth, (req, res) => {
  partUpload.single('part')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    const { uploadId, index } = req.body || {};
    if (!ID_RE.test(String(uploadId || ''))) return res.status(400).json({ error: 'Invalid uploadId' });
    const u = pendingUploads.get(uploadId);
    if (!u || u.userId !== req.session.userId) return res.status(404).json({ error: 'Upload not found' });
    const idx = Number(index);
    if (!Number.isInteger(idx) || idx < 0 || idx >= u.partCount) return res.status(400).json({ error: 'Invalid part index' });
    if (!req.file) return res.status(400).json({ error: 'No part received' });
    const expected = (idx === u.partCount - 1) ? (u.size - idx * u.partSize) : u.partSize;
    if (req.file.size !== expected) return res.status(400).json({ error: 'Part size mismatch' });
    try {
      const fd = fs.openSync(u.path, 'r+');
      try { fs.writeSync(fd, req.file.buffer, 0, req.file.size, idx * u.partSize); }
      finally { fs.closeSync(fd); }
    } catch (e) {
      // z. B. Teil-Datei vom Janitor entfernt (TTL) oder /tmp voll
      console.error('upload-part write error', uploadId, e.message);
      cleanupPending(uploadId);
      return res.status(500).json({ error: 'Part write failed' });
    }
    u.received.add(idx);          // Retry desselben Teils ist idempotent
    u.createdAt = Date.now();     // TTL bei Aktivität verlängern
    res.json({ received: u.received.size, partCount: u.partCount });
  });
});

app.post('/api/photos/upload-finish', requireAuth, requireDEK, async (req, res) => {
  const { uploadId } = req.body || {};
  if (!ID_RE.test(String(uploadId || ''))) return res.status(400).json({ error: 'Invalid uploadId' });
  const u = pendingUploads.get(uploadId);
  if (!u || u.userId !== req.session.userId) return res.status(404).json({ error: 'Upload not found' });
  if (u.received.size !== u.partCount) return res.status(400).json({ error: `Missing parts (${u.received.size}/${u.partCount})` });
  const db = loadDB();
  // Berechtigungen erneut prüfen – zwischen init und finish kann Zeit vergehen
  if (!db.albums.find(a => a.id === u.albumId)) { cleanupPending(uploadId); return res.status(404).json({ error: 'Album not found' }); }
  if (!canUploadToAlbum(db, req.session.userId, u.albumId)) { cleanupPending(uploadId); return res.status(403).json({ error: 'No upload permission' }); }
  if (effectiveHidden(db, u.albumId) && !isUnlocked(req, db, u.albumId)) return res.status(423).json({ error: 'Album locked', code: 'LOCKED' });
  const dek = dekCache.get(req.sessionID);
  let fam = familyCache.get(req.sessionID);
  if (!fam && albumIsFamilyGranted(db, u.albumId)) { const me = getUser(db, req); fam = ensureFamilyKey(db, me, dek); if (fam) familyCache.set(req.sessionID, fam); }
  const { key, enc } = uploadKeyFor(db, u.albumId, dek, fam);
  try {
    const buffer = fs.readFileSync(u.path);
    if (buffer.length !== u.size) { cleanupPending(uploadId); return res.status(400).json({ error: 'Assembled size mismatch' }); }
    const rec = await storeIncomingFile(db, { buffer, originalname: u.fileName, mimetype: u.mimeType, size: u.size }, u.albumId, req.session.userId, key, enc);
    if (rec.duplicate) {
      cleanupPending(uploadId);
      return res.json({ uploaded: [], errors: [], duplicates: [u.fileName] });
    }
    db.photos.push(rec);
    saveDB(db);
    cleanupPending(uploadId);
    res.json({ uploaded: [{ id: rec.id, name: u.fileName }], errors: [], duplicates: [] });
  } catch (e) {
    console.error('Chunked upload finish error', u.fileName, e.message);
    cleanupPending(uploadId);
    res.status(500).json({ error: 'Processing failed' });
  }
});

app.post('/api/photos/upload-cancel', requireAuth, (req, res) => {
  const uploadId = String((req.body || {}).uploadId || '');
  const u = pendingUploads.get(uploadId);
  if (u && u.userId === req.session.userId) cleanupPending(uploadId);
  res.json({ success: true });
});

// ═══ SHARE / UNSHARE ══════════════════════════════════════════════
// Aufbereitung eines Fotos für das Frontend (seit 2.5.0 ausgelagert, weil die
// Favoritenliste dieselbe Form braucht). `albumId` = der Kontext, in dem gelistet
// wird (bestimmt nur das linkedHere-Badge).
function mapPhoto(db, me, req, p, albumId) {
  const owner = db.users.find(u => u.id === p.ownerId);
  const keyInfo = resolveReadKey(db, p, req);
  // Kein linkedHere für Beobachter und verknüpfte Hauptbenutzer: das Link-Badge
  // ist für sie nutzlos und verriete nur die Album-Organisation des Besitzers
  // (keine Link-Verwaltung, kein "Folgen") und verrät nur Album-Organisation.
  const isOwn = p.ownerId === req.session.userId;
  return { id: p.id, albumId: p.albumId, linkedHere: (isOwn || me.type === 'admin') && p.albumId !== albumId, originalName: p.originalName, uploadedAt: p.uploadedAt, takenAt: p.takenAt || null, size: p.size,
    ownerId: p.ownerId, ownerName: owner?.username ?? '?', shared: p.shared || false,
    mimeType: p.mimeType || 'image/jpeg',
    isPdf: isPdfMime(p.mimeType),                              // 2.6.0
    isGif: isGifMime(p.mimeType),                              // 2.7.0
    streamable: p.encFormat === 'chunked',
    hasThumb: !!p.thumbIv,
    pending: !!keyInfo.pending,
    favorite: !!p.favorite,                                    // 2.5.0
    canFavorite: isOwn && me.type !== 'observer',               // 2.5.0
    canDownload: isOwn && me.type !== 'observer',
    canShare: isOwn && me.type !== 'observer' };
}

app.get('/api/albums/:albumId/photos', requireAuth, (req, res) => {
  const db = loadDB();
  const me = getUser(db, req);
  const albumId = req.params.albumId;
  if (albumId === SHARED_ALBUM_ID) return res.status(403).json({ error: 'Sharing removed' });
  if (!canViewAlbum(db, req.session.userId, albumId)) return res.status(403).json({ error: 'No access to album' });
  if (effectiveHidden(db, albumId) && !isUnlocked(req, db, albumId))
    return res.status(423).json({ error: 'Album locked', code: 'LOCKED' });
  // 2.1.0: Ein Foto, dessen Home-Album für den Betrachter unsichtbar ist (z. B.
  // verstecktes Album ohne das Recht dazu), wird auch dann nicht gelistet, wenn
  // es hierher verlinkt ist – sonst erschiene eine Kachel, deren Thumb/Full/Stream
  // konsequenterweise 403 liefert. Alle Zugriffsprüfungen gehen auf `p.albumId`.
  const visible = new Set(visibleAlbumIds(db, req.session.userId));
  const mayShow = p => (p.shared && me.type !== 'observer') || visible.has(p.albumId);
  // 2.5.0: Reihenfolge kommt aus dem Album (manuell) oder bleibt "neueste zuerst".
  const album = db.albums.find(a => a.id === albumId);
  const list = sortPhotosForAlbum(album, photosOfAlbum(db, albumId).filter(mayShow));
  res.json(list.map(p => mapPhoto(db, me, req, p, albumId)));
});

// ─── Manuelle Reihenfolge (2.5.0) ─────────────────────────────────
// Ein Foto an eine Position schieben. `afterId: null` = an den Anfang.
// Beim ersten Aufruf wird die aktuell angezeigte Reihenfolge materialisiert,
// damit nichts springt; danach ist `album.photoOrder` maßgeblich.
app.put('/api/albums/:id/order', requireAuth, (req, res) => {
  const { photoId, afterId } = req.body || {};
  const db = loadDB();
  const album = db.albums.find(a => a.id === req.params.id);
  if (!album) return res.status(404).json({ error: 'Album not found' });
  if (!canManageAlbum(db, req.session.userId, album.id)) return res.status(403).json({ error: 'No permission' });
  if (effectiveHidden(db, album.id) && !isUnlocked(req, db, album.id))
    return res.status(423).json({ error: 'Album locked', code: 'LOCKED' });
  const ids = sortPhotosForAlbum(album, photosOfAlbum(db, album.id)).map(p => p.id);
  if (!ids.includes(photoId)) return res.status(404).json({ error: 'Photo not in this album' });
  if (afterId !== null && afterId !== undefined && !ids.includes(afterId))
    return res.status(400).json({ error: 'Anchor photo not in this album' });
  if (afterId === photoId) return res.json({ success: true, order: ids });
  const without = ids.filter(id => id !== photoId);
  const at = (afterId === null || afterId === undefined) ? 0 : without.indexOf(afterId) + 1;
  without.splice(at, 0, photoId);
  album.photoOrder = without;
  saveDB(db);
  res.json({ success: true, order: without });
});

// Einmalige Vorsortierung – u. a. nach der beim Import gelesenen Aufnahmezeit.
app.post('/api/albums/:id/order/sort', requireAuth, (req, res) => {
  const by = (req.body || {}).by === 'uploaded' ? 'uploaded' : 'taken';
  const desc = !!(req.body || {}).desc;
  const db = loadDB();
  const album = db.albums.find(a => a.id === req.params.id);
  if (!album) return res.status(404).json({ error: 'Album not found' });
  if (!canManageAlbum(db, req.session.userId, album.id)) return res.status(403).json({ error: 'No permission' });
  if (effectiveHidden(db, album.id) && !isUnlocked(req, db, album.id))
    return res.status(423).json({ error: 'Album locked', code: 'LOCKED' });
  const keyOf = p => (by === 'taken' ? (p.takenAt || p.uploadedAt) : p.uploadedAt);
  const ids = photosOfAlbum(db, album.id).sort((a, b) => desc ? keyOf(b) - keyOf(a) : keyOf(a) - keyOf(b)).map(p => p.id);
  album.photoOrder = ids;
  saveDB(db);
  res.json({ success: true, count: ids.length });
});

// Zurück zur Standardsortierung (neueste zuerst)
app.delete('/api/albums/:id/order', requireAuth, (req, res) => {
  const db = loadDB();
  const album = db.albums.find(a => a.id === req.params.id);
  if (!album) return res.status(404).json({ error: 'Album not found' });
  if (!canManageAlbum(db, req.session.userId, album.id)) return res.status(403).json({ error: 'No permission' });
  delete album.photoOrder;
  saveDB(db);
  res.json({ success: true });
});

// ─── Favoriten (2.5.0) ────────────────────────────────────────────
// Bewusst eine Eigenschaft des Fotos, gesetzt nur vom Besitzer: das kommt ohne
// zusätzliche Tabelle aus. Beobachter sehen weder Stern noch Favoritenalbum.
app.put('/api/photos/:id/favorite', requireAuth, (req, res) => {
  if (!ID_RE.test(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
  const db = loadDB();
  const photo = findPhoto(db, req.params.id);
  if (!photo) return res.status(404).json({ error: 'Photo not found' });
  const me = getUser(db, req);
  if (me.type === 'observer' || photo.ownerId !== req.session.userId)
    return res.status(403).json({ error: 'Not your photo' });
  if ((req.body || {}).favorite) photo.favorite = true; else delete photo.favorite;
  saveDB(db);
  res.json({ success: true, favorite: !!photo.favorite });
});

// Virtuelles Album: die eigenen Favoriten, neueste zuerst.
app.get('/api/photos/favorites', requireAuth, (req, res) => {
  const db = loadDB();
  const me = getUser(db, req);
  if (me.type === 'observer') return res.status(403).json({ error: 'Observers have no favorites' });
  const visible = new Set(visibleAlbumIds(db, req.session.userId));
  const list = db.photos.filter(p => isAlive(p) && p.favorite && p.ownerId === me.id && visible.has(p.albumId))
    // Fotos in gesperrten versteckten Alben bleiben draußen, solange die PIN
    // in dieser Sitzung nicht eingegeben wurde.
    .filter(p => !effectiveHidden(db, p.albumId) || isUnlocked(req, db, p.albumId))
    .sort((a, b) => b.uploadedAt - a.uploadedAt);
  // albumId = eigenes Home-Album → kein irreführendes Link-Badge in der Favoritensicht
  res.json(list.map(p => mapPhoto(db, me, req, p, p.albumId)));
});

// Link one photo into multiple albums (Variant A: same key context only)
app.put('/api/photos/:id/links', requireAuth, (req, res) => {
  if (!ID_RE.test(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
  const { albumIds } = req.body;
  if (!Array.isArray(albumIds)) return res.status(400).json({ error: 'albumIds array required' });
  const db = loadDB();
  const photo = findPhoto(db, req.params.id);
  if (!photo) return res.status(404).json({ error: 'Photo not found' });
  const me = getUser(db, req);
  if (photo.ownerId !== req.session.userId && me.type !== 'admin') return res.status(403).json({ error: 'Not your photo' });
  const homeCtx = albumKeyContext(db, photo.albumId);
  const clean = [];
  for (const aid of albumIds) {
    if (aid === photo.albumId) continue;                        // home album is implicit
    const alb = db.albums.find(a => a.id === aid);
    if (!alb) return res.status(404).json({ error: 'Target album not found' });
    if (!canUploadToAlbum(db, req.session.userId, aid)) return res.status(403).json({ error: 'No permission for a target album' });
    if (albumKeyContext(db, aid) !== homeCtx) return res.status(409).json({ error: 'Album has a different sharing context', code: 'CTX_MISMATCH' });
    if (!clean.includes(aid)) clean.push(aid);
  }
  photo.linkedAlbumIds = clean;
  saveDB(db);
  res.json({ success: true, linkedAlbumIds: clean });
});

// Bulk: link several photos into one album
app.put('/api/photos/links', requireAuth, (req, res) => {
  const { photoIds, targetAlbumId } = req.body;
  if (!Array.isArray(photoIds) || !targetAlbumId) return res.status(400).json({ error: 'photoIds and targetAlbumId required' });
  const db = loadDB();
  const me = getUser(db, req);
  if (!canUploadToAlbum(db, req.session.userId, targetAlbumId)) return res.status(403).json({ error: 'No permission for target album' });
  if (effectiveHidden(db, targetAlbumId) && !isUnlocked(req, db, targetAlbumId)) return res.status(423).json({ error: 'Target album locked', code: 'LOCKED' });
  const targetCtx = albumKeyContext(db, targetAlbumId);
  let linked = 0, skipped = 0;
  for (const pid of photoIds) {
    const photo = findPhoto(db, pid);
    if (!photo) { skipped++; continue; }
    if (photo.ownerId !== req.session.userId && me.type !== 'admin') { skipped++; continue; }
    if (photo.albumId === targetAlbumId) { skipped++; continue; }
    if (albumKeyContext(db, photo.albumId) !== targetCtx) { skipped++; continue; }
    photo.linkedAlbumIds = photo.linkedAlbumIds || [];
    if (!photo.linkedAlbumIds.includes(targetAlbumId)) { photo.linkedAlbumIds.push(targetAlbumId); linked++; }
    else skipped++;
  }
  if (linked) saveDB(db);
  res.json({ success: true, linked, skipped });
});

// Remove a link (unlink) – photo stays in its home album
app.delete('/api/photos/:id/links/:albumId', requireAuth, (req, res) => {
  if (!ID_RE.test(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
  const db = loadDB();
  const photo = findPhoto(db, req.params.id);
  if (!photo) return res.status(404).json({ error: 'Photo not found' });
  const me = getUser(db, req);
  if (photo.ownerId !== req.session.userId && me.type !== 'admin') return res.status(403).json({ error: 'Not your photo' });
  photo.linkedAlbumIds = (photo.linkedAlbumIds || []).filter(a => a !== req.params.albumId);
  saveDB(db);
  res.json({ success: true });
});

app.put('/api/photos/:id/move', requireAuth, (req, res) => {
  const { targetAlbumId } = req.body;
  if (!ID_RE.test(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
  const db = loadDB();
  const photo = findPhoto(db, req.params.id);
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
  // Moving changes the key context → drop links that would now be incompatible
  if (Array.isArray(photo.linkedAlbumIds) && photo.linkedAlbumIds.length) {
    const newCtx = albumKeyContext(db, targetAlbumId);
    photo.linkedAlbumIds = photo.linkedAlbumIds.filter(aid => aid !== targetAlbumId && albumKeyContext(db, aid) === newCtx);
  }

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
  const photo = findPhoto(db, req.params.id);
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
// Range-based streaming for chunked videos (206 Partial Content)
app.get('/api/photos/:id/stream', requireAuth, (req, res) => {
  if (!ID_RE.test(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
  const db = loadDB();
  const photo = findPhoto(db, req.params.id);
  if (!photo) return res.status(404).json({ error: 'Not found' });
  const me = getUser(db, req);
  const canView = (photo.shared && me.type !== 'observer') || canViewAlbum(db, req.session.userId, photo.albumId);
  if (!canView) return res.status(403).json({ error: 'No access' });
  if (effectiveHidden(db, photo.albumId) && !isUnlocked(req, db, photo.albumId))
    return res.status(423).json({ error: 'Album locked', code: 'LOCKED' });
  const referer = req.headers['referer'] || req.headers['origin'] || '';
  if (referer && !referer.includes(req.headers['host'] || '')) return res.status(403).json({ error: 'Direct access not permitted' });
  if (photo.encFormat !== 'chunked') return res.status(409).json({ error: 'Not streamable' });
  const keyInfo = resolveReadKey(db, photo, req);
  if (keyInfo.pending) return res.status(423).json({ error: 'Pending', code: 'PENDING' });
  if (keyInfo.denied) return res.status(401).json({ error: 'Session key missing', code: 'DEK_MISSING' });
  const f = path.join(PHOTOS_DIR, `${photo.id}.enc`);
  if (!fs.existsSync(f)) return res.status(404).json({ error: 'File not found' });

  // Sicherheitsnetz (1.12.1): Video-View serverseitig beim Playback-Start zählen,
  // unabhängig davon, ob der Client-/view-Fetch ankommt (gecachtes altes Frontend,
  // blockierter Request o. ä.). "Start" = kein Range-Header oder Range ab Byte 0
  // (deckt auch Safaris bytes=0-1-Probe ab); Seek-Requests (bytes=N-) zählen nicht.
  // Owner-Ausnahme + 10-Min-Dedup in countViewOnce verhindern Doppelzählung mit /view.
  if (!req.headers.range || /^bytes=0-/.test(req.headers.range)) {
    if (countViewOnce(db, photo, req.session.userId)) saveDB(db);
  }

  const total = photo.plainSize;
  let start = 0, end = total - 1, partial = false;
  const m = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range || '');
  if (m) {
    partial = true;
    if (m[1] !== '') start = parseInt(m[1], 10);
    if (m[2] !== '') end = parseInt(m[2], 10);
    else if (m[1] === '') { start = Math.max(0, total - 1); end = total - 1; }
    if (isNaN(start) || isNaN(end) || start > end || start >= total)
      return res.status(416).set('Content-Range', `bytes */${total}`).end();
    end = Math.min(end, total - 1);
  }
  res.status(partial ? 206 : 200);
  res.set('Content-Type', photo.mimeType || 'video/mp4');
  res.set('Accept-Ranges', 'bytes');
  res.set('Content-Length', String(end - start + 1));
  if (partial) res.set('Content-Range', `bytes ${start}-${end}/${total}`);
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.set('X-Content-Type-Options', 'nosniff');

  const fd = fs.openSync(f, 'r');
  try {
    const firstChunk = Math.floor(start / CHUNK_SIZE);
    const lastChunk = Math.floor(end / CHUNK_SIZE);
    for (let i = firstChunk; i <= lastChunk; i++) {
      const plain = readDecryptedChunk(fd, photo, keyInfo.key, i);
      const chunkStart = i * CHUNK_SIZE;
      const from = Math.max(0, start - chunkStart);
      const to = Math.min(plain.length, end - chunkStart + 1);
      res.write(plain.subarray(from, to));
    }
    res.end();
  } catch (e) {
    console.error('Stream error:', photo.id, e.message);
    try { res.end(); } catch {}
  } finally { fs.closeSync(fd); }
});

// Dedicated view counter – called exactly once when the lightbox opens
app.post('/api/photos/:id/view', requireAuth, (req, res) => {
  if (!ID_RE.test(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
  const db = loadDB();
  const photo = findPhoto(db, req.params.id);
  if (!photo) return res.status(404).json({ error: 'Not found' });
  const me = getUser(db, req);
  const canView = (photo.shared && me.type !== 'observer') || canViewAlbum(db, req.session.userId, photo.albumId);
  if (!canView) return res.status(403).json({ error: 'No access' });
  if (effectiveHidden(db, photo.albumId) && !isUnlocked(req, db, photo.albumId))
    return res.status(423).json({ error: 'Album locked', code: 'LOCKED' });
  // Owner excluded, 10-minute dedup per user (zentral in countViewOnce)
  if (countViewOnce(db, photo, req.session.userId)) saveDB(db);
  res.json({ success: true });
});

app.get('/api/photos/:id/full', requireAuth, (req, res) => {
  if (!ID_RE.test(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
  const db = loadDB();
  const photo = findPhoto(db, req.params.id);
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
  // Sicherheitsnetz (1.12.1): nur für VIDEOS (Legacy-Ganzdatei-Wiedergabe via /full).
  // Fotos werden weiterhin ausschließlich über /view gezählt ("einziger View-Zähler"
  // bleibt für Fotos erhalten; /full feuert bei Fotos auch für die progressive Lightbox).
  if (photo.mimeType && photo.mimeType.startsWith('video/')) {
    if (countViewOnce(db, photo, req.session.userId)) saveDB(db);
  }
  try {
    // 2.6.0: PDFs bewusst NICHT als application/pdf ausliefern. Sonst würde ein
    // direkt aufgerufener Endpoint den eingebauten Viewer des Browsers öffnen –
    // inklusive Download- und Druckknopf, vorbei an der Canvas-Anzeige. pdf.js
    // holt die Bytes per fetch(), der Content-Type ist dafür ohne Bedeutung.
    res.set('Content-Type', isPdfMime(photo.mimeType) ? 'application/octet-stream' : (photo.mimeType || 'image/jpeg'));
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.set('X-Content-Type-Options', 'nosniff');
    if (photo.encFormat === 'chunked') { res.send(decryptChunkedAll(f, photo, keyInfo.key)); return; }
    res.send(decryptPhotoFile(f, photo, keyInfo, 'photo'));
  } catch (e) { console.error('Full view error:', e.message); res.status(500).json({ error: 'Decryption failed' }); }
});

// 2.5.0: Löschen markiert zunächst nur. Die Dateien verschwinden erst, wenn der
// Janitor nach PHOTO_TRASH_TTL aufräumt – bis dahin ist /restore möglich.
app.delete('/api/photos/:id', requireAuth, (req, res) => {
  const db = loadDB();
  const photo = findPhoto(db, req.params.id);
  if (!photo) return res.status(404).json({ error: 'Photo not found' });
  const me = getUser(db, req);
  if ((photo.ownerId !== req.session.userId && me.type !== 'admin') || me.type === 'observer')
    return res.status(403).json({ error: 'No permission' });
  photo.deletedAt = Date.now();
  saveDB(db);
  res.json({ success: true, undoMs: PHOTO_TRASH_TTL });
});

// Rückgängig: stellt eben gelöschte Fotos wieder her, solange sie noch im
// Papierkorb liegen. Bewusst als Sammelaufruf, weil im Frontend meist eine
// ganze Auswahl auf einmal gelöscht wird.
app.post('/api/photos/restore', requireAuth, (req, res) => {
  const ids = Array.isArray((req.body || {}).photoIds) ? req.body.photoIds : [];
  if (!ids.length) return res.status(400).json({ error: 'photoIds required' });
  const db = loadDB();
  const me = getUser(db, req);
  if (me.type === 'observer') return res.status(403).json({ error: 'No permission' });
  let restored = 0;
  for (const id of ids) {
    const p = db.photos.find(x => x.id === id && x.deletedAt);
    if (!p) continue;
    if (p.ownerId !== req.session.userId && me.type !== 'admin') continue;
    delete p.deletedAt;
    restored++;
  }
  if (restored) saveDB(db);
  res.json({ success: true, restored });
});

// ═══ EXPORT (all own photos as ZIP) ═══════════════════════════════
app.get('/api/export', requireAuth, requireDEK, (req, res) => {
  const db = loadDB();
  const me = getUser(db, req);
  if (me.type === 'observer') return res.status(403).json({ error: 'Observers cannot export' });
  const dek = dekCache.get(req.sessionID);
  const fam = familyCache.get(req.sessionID);
  const mine = db.photos.filter(p => isAlive(p) && p.ownerId === req.session.userId);

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
      let plain;
      if (p.encFormat === 'chunked') plain = decryptChunkedAll(f, p, key);
      else plain = p.encryption ? decryptGCM(fs.readFileSync(f), key, p.iv, p.tag) : decryptLegacyCBC(fs.readFileSync(f), p.iv);
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
  // 2.5.0: Fotos im Papierkorb fließen nicht in die Statistik ein.
  const db = {
    users: fullDb.users,
    albums: isAdmin ? fullDb.albums : fullDb.albums.filter(a => a.ownerId === meU.id),
    photos: fullDb.photos.filter(p => isAlive(p) && (isAdmin || p.ownerId === meU.id))
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
  // Belegung des Datenträgers (2.5.0) – nur für Admins, da systemweite Angabe.
  // Eine volle Platte ist auf Raspberry-Hardware mit Videos kein Randfall und
  // trifft als Erstes das Schreiben der db.json.
  if (isAdmin) {
    try {
      const st = fs.statfsSync(DATA_DIR);
      const total = st.blocks * st.bsize, free = st.bavail * st.bsize;
      if (total > 0) overview.disk = {
        totalGB: parseFloat((total / 1073741824).toFixed(1)),
        freeGB: parseFloat((free / 1073741824).toFixed(1)),
        usedPct: Math.round((total - free) / total * 100)
      };
    } catch (e) { console.warn('statfs unavailable:', e.message); }
  }
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
    photoCount: db.photos.filter(p => photoInAlbum(p, a.id)).length,
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

// ─── Galerie-Einstellungen (1.11.0) ───────────────────────────────
// GET ist bewusst ohne Auth: enthält nur unkritische Darstellungswerte
// (Galeriename wird bereits auf dem Login-Screen angezeigt).
app.get('/api/settings', (req, res) => {
  const db = loadDB();
  res.json(getSettings(db));
});
app.put('/api/settings', requireAdmin, (req, res) => {
  const { galleryName, taglineDe, taglineEn, lbMaxPhotoPx, lbMaxVideoPx, lbMaxGifPx, thumbSize, colors } = req.body || {};
  if (galleryName !== undefined) {
    const name = String(galleryName).trim();
    if (!GALLERY_NAME_RE.test(name)) return res.status(400).json({ error: 'Invalid gallery name (1-40 chars, no < >)' });
  }
  for (const [label, v] of [['taglineDe', taglineDe], ['taglineEn', taglineEn]]) {
    if (v !== undefined && !TAGLINE_RE.test(String(v).trim())) {
      return res.status(400).json({ error: `Invalid ${label} (max 80 chars, no < >)` });
    }
  }
  if (colors !== undefined) {
    if (typeof colors !== 'object' || colors === null) return res.status(400).json({ error: 'Invalid colors object' });
    for (const [k, v] of Object.entries(colors)) {
      if (!(k in SETTINGS_DEFAULTS.colors)) return res.status(400).json({ error: `Unknown color key: ${k}` });
      if (!HEX_COLOR_RE.test(String(v).trim())) return res.status(400).json({ error: `Invalid color for ${k} (expected #rrggbb)` });
    }
  }
  const db = loadDB();
  const current = getSettings(db);
  db.settings = sanitizeSettings({
    galleryName:  galleryName  !== undefined ? galleryName  : current.galleryName,
    taglineDe:    taglineDe    !== undefined ? taglineDe    : current.taglineDe,
    taglineEn:    taglineEn    !== undefined ? taglineEn    : current.taglineEn,
    lbMaxPhotoPx: lbMaxPhotoPx !== undefined ? lbMaxPhotoPx : current.lbMaxPhotoPx,
    lbMaxVideoPx: lbMaxVideoPx !== undefined ? lbMaxVideoPx : current.lbMaxVideoPx,
    lbMaxGifPx:   lbMaxGifPx   !== undefined ? lbMaxGifPx   : current.lbMaxGifPx,
    thumbSize:    thumbSize    !== undefined ? thumbSize    : current.thumbSize,
    colors:       colors       !== undefined ? Object.assign({}, current.colors, colors) : current.colors
  });
  saveDB(db);
  res.json(db.settings);
});

// ─── PWA-Manifest (2.5.0) ─────────────────────────────────────────
// Erlaubt "Zum Startbildschirm hinzufügen" – die Galerie startet dann ohne
// Browserleiste. BEWUSST OHNE SERVICE WORKER: ein Worker würde genau das
// Cache-Problem zurückbringen, das die no-store-Regel für index.html löst.
// Name und Farben kommen aus den Galerie-Einstellungen.
app.get('/manifest.webmanifest', (req, res) => {
  const s = getSettings(loadDB());
  res.set('Cache-Control', 'no-store');
  res.type('application/manifest+json').json({
    name: s.galleryName,
    short_name: s.galleryName.slice(0, 12),
    start_url: './',
    scope: './',
    display: 'standalone',
    orientation: 'any',
    background_color: s.colors.bg,
    theme_color: s.colors.bg,
    icons: [
      { src: 'icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
      { src: 'icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
      { src: 'icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' }
    ]
  });
});
// Icons werden aus den konfigurierten Farben gerendert und im RAM gepuffert.
const iconCache = new Map();
function appIconSvg(size, colors) {
  const c = size / 2, r = size * 0.3;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
    <rect width="${size}" height="${size}" rx="${size * 0.18}" fill="${colors.bg}"/>
    <circle cx="${c}" cy="${c}" r="${r}" fill="none" stroke="${colors.accent}" stroke-width="${size * 0.045}"/>
    <path d="M${c - r * 0.55} ${c - r * 0.5} L${c} ${c + r * 0.62} L${c + r * 0.55} ${c - r * 0.5}"
      fill="none" stroke="${colors.accent}" stroke-width="${size * 0.075}" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`;
}
function serveIcon(size) {
  return async (req, res) => {
    try {
      const colors = getSettings(loadDB()).colors;
      const key = `${size}:${colors.bg}:${colors.accent}`;
      let png = iconCache.get(key);
      if (!png) {
        png = await sharp(Buffer.from(appIconSvg(size, colors))).png().toBuffer();
        if (iconCache.size > 12) iconCache.clear();
        iconCache.set(key, png);
      }
      res.type('image/png').set('Cache-Control', 'public, max-age=3600').send(png);
    } catch (e) { console.error('Icon render failed:', e.message); res.status(500).end(); }
  };
}
app.get('/icon-192.png', serveIcon(192));
app.get('/icon-512.png', serveIcon(512));

app.get('/api/health', (req, res) => res.json({ status: 'ok', version: APP_VERSION, pdfjs: PDFJS_VERSION }));
app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Payload too large' });
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON' });
  console.error('Unhandled error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});
app.listen(PORT, () => { console.log(`Vermeer v${APP_VERSION} running on port ${PORT}`); loadDB(); });

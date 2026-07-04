# Vermeer – Umbrel Community App Store

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Verschlüsselte Foto-Webanwendung für [Umbrel](https://umbrel.com).

## Repository-Struktur

```
umbrel-app-store.yml                    ← App-Store-Manifest (ID + Name)
vermeer-store-vermeer/
├── umbrel-app.yml                      ← App-Listing für die Umbrel-UI
├── docker-compose.yml                  ← Wird von Umbrel zum Starten genutzt
├── Dockerfile                          ← Image-Definition
└── app/
    ├── backend/
    │   ├── server.js                   ← Express-API
    │   └── package.json
    └── frontend/
        └── index.html                  ← Single-File UI
```

## App installieren

### 1. Image bauen (auf dem Umbrel-Server)

```bash
cd ~/vermeer-store-vermeer
docker build -t vermeer-store-vermeer:1.0.0 .
```

### 2. Community App Store in Umbrel hinzufügen

1. Umbrel öffnen → **App Store** → **Community App Stores**
2. GitHub-URL dieses Repositories eintragen
3. Vermeer installieren

### 3. Erster Login

| Feld | Wert |
|------|------|
| Benutzername | `admin` |
| Passwort | `admin` |

> ⚠️ **Sofort das Admin-Passwort ändern!** (Einstellungen → Konto)

---

## Umbrel-Umgebungsvariablen

Umbrel stellt automatisch bereit:

| Variable | Beschreibung |
|----------|-------------|
| `APP_DATA_DIR` | Persistentes Datenverzeichnis (wird als `/data` gemountet) |
| `APP_SEED` | 256-bit Hex-String, wird als `ENCRYPTION_KEY` genutzt |
| `APP_PASSWORD` | Zufälliges Passwort, wird als `SESSION_SECRET` genutzt |

Der `APP_SEED` ist deterministisch vom Umbrel-Master-Seed abgeleitet –  
d.h. nach einer Neuinstallation mit demselben Seed sind alle Fotos weiterhin entschlüsselbar.

---

## Sicherheitskonzept

- **AES-256-CBC** – Originale und Thumbnails werden einzeln mit zufälligem IV verschlüsselt
- Entschlüsselung **nur im RAM**, niemals auf Disk
- **bcrypt** (12 Runden) für Passwort-Hashing
- **Download-Schutz**: Nur der Eigentümer und Admins können Originale herunterladen
- **Sichtbarkeits-Rechte**: Admin vergibt pro Benutzer, wessen Fotos er sehen darf

---

## Dateistruktur im Volume

```
/data/
├── db.json        ← Benutzer & Foto-Metadaten (kein Klartext der Bilder)
├── sessions/      ← Server-Sessions
├── photos/        ← Verschlüsselte Originale (*.enc)
└── thumbs/        ← Verschlüsselte Thumbnails (*.enc)
```

---

## Lizenz

Dieses Projekt steht unter der [MIT-Lizenz](LICENSE).

---

## Windows: Skript ausführen

`chmod` existiert unter Windows nicht. Stattdessen eine der folgenden Optionen nutzen:

### Option A – Git Bash (empfohlen, einfachste Lösung)
Git für Windows bringt Git Bash mit, das bash-Skripte direkt ausführen kann.

1. [Git für Windows](https://git-scm.com/download/win) installieren (falls noch nicht vorhanden)
2. [GitHub CLI](https://cli.github.com) installieren
3. **Git Bash** öffnen (Rechtsklick im Ordner → „Git Bash Here")
4. Skript starten:
   ```bash
   bash setup-github.sh
   ```

### Option B – PowerShell (ohne Bash)
Falls kein Git Bash vorhanden ist, die Befehle direkt in PowerShell ausführen:

```powershell
# 1. In den Projektordner wechseln
cd vermeer-umbrel

# 2. GitHub CLI anmelden (einmalig)
gh auth login

# 3. Repository erstellen und pushen
git init -b main
git add -A
git commit -m "feat: initial release Vermeer v1.0.0"
gh repo create vermeer-umbrel-app-store --public --source=. --remote=origin --push
git tag -a "v1.0.0" -m "Vermeer 0.5 Beta – Initial release"
git push origin v1.0.0
gh release create "v1.0.0" --title "Vermeer 0.5 Beta" --notes "Initial release"
```

### Option C – WSL (Windows Subsystem for Linux)
Falls WSL installiert ist:
```bash
bash setup-github.sh
```


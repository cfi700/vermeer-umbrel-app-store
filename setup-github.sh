#!/usr/bin/env bash
# =============================================================
#  Vermeer – GitHub Repository Setup Script
#  Lädt das Vermeer Umbrel Community App Store Repository
#  auf deinen GitHub-Account hoch.
#
#  Voraussetzungen:
#    - git  (brew install git  /  apt install git)
#    - gh   (GitHub CLI: https://cli.github.com)
#
#  Aufruf:
#    chmod +x setup-github.sh
#    ./setup-github.sh
# =============================================================
set -e

# ── Farben ──────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "${GREEN}✓${NC} $*"; }
info() { echo -e "${CYAN}→${NC} $*"; }
warn() { echo -e "${YELLOW}!${NC} $*"; }
die()  { echo -e "${RED}✗ Fehler:${NC} $*"; exit 1; }

echo -e "\n${BOLD}🔐 Vermeer – GitHub Repository Setup${NC}"
echo    "────────────────────────────────────────"

# ── Abhängigkeiten prüfen ──────────────────────────────────
command -v git >/dev/null 2>&1 || die "git ist nicht installiert. Bitte zuerst installieren."
command -v gh  >/dev/null 2>&1 || die "GitHub CLI (gh) ist nicht installiert.\nInstallation: https://cli.github.com\nDanach: gh auth login"

# ── GitHub Login prüfen ───────────────────────────────────
if ! gh auth status >/dev/null 2>&1; then
  warn "Du bist noch nicht bei GitHub CLI angemeldet."
  info "Starte: gh auth login"
  gh auth login || die "GitHub-Anmeldung fehlgeschlagen."
fi

GH_USER=$(gh api user --jq '.login' 2>/dev/null) || die "GitHub-Benutzer konnte nicht ermittelt werden."
ok "Angemeldet als: ${BOLD}${GH_USER}${NC}"

# ── Konfiguration ──────────────────────────────────────────
REPO_NAME="vermeer-umbrel-app-store"
REPO_DESC="Vermeer – Encrypted Photo Vault for Umbrel (Community App Store)"
INITIAL_TAG="v0.5-beta"
INITIAL_TAG_MSG="Vermeer 0.5 Beta – Initial release"

echo ""
info "Repository-Name : ${BOLD}${REPO_NAME}${NC}"
info "GitHub-Account  : ${BOLD}${GH_USER}${NC}"
info "Erster Tag      : ${BOLD}${INITIAL_TAG}${NC}"
info "Sichtbarkeit    : öffentlich (erforderlich für Umbrel App Store)"
echo ""
read -r -p "Fortfahren? [j/N] " confirm
[[ "$confirm" =~ ^[jJyY]$ ]] || { echo "Abgebrochen."; exit 0; }

# ── Arbeitsverzeichnis ─────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${SCRIPT_DIR}"

info "Arbeitsverzeichnis: ${REPO_DIR}"

[[ -f "${REPO_DIR}/umbrel-app-store.yml" ]] || \
  die "umbrel-app-store.yml nicht gefunden.\nBitte das Skript aus dem vermeer-umbrel-Ordner ausführen."

# ── Git initialisieren ─────────────────────────────────────
cd "${REPO_DIR}"

if [[ -d ".git" ]]; then
  warn ".git existiert bereits – überspringe git init"
else
  info "Initialisiere Git-Repository…"
  git init -b main
  ok "Git initialisiert (Branch: main)"
fi

# ── .gitignore anlegen ────────────────────────────────────
if [[ ! -f ".gitignore" ]]; then
  cat > .gitignore << 'EOF'
# Node
node_modules/
npm-debug.log*

# Runtime data (never commit!)
/data/
*.enc
db.json
sessions/

# OS
.DS_Store
Thumbs.db

# Editor
.vscode/
.idea/
*.swp
EOF
  ok ".gitignore erstellt"
fi

# ── Git-Identität prüfen ──────────────────────────────────
if [[ -z "$(git config user.email)" ]]; then
  GH_EMAIL=$(gh api user/emails --jq '.[0].email' 2>/dev/null || echo "")
  if [[ -n "$GH_EMAIL" ]]; then
    git config user.email "$GH_EMAIL"
    git config user.name "$GH_USER"
    ok "Git-Identität gesetzt: ${GH_USER} <${GH_EMAIL}>"
  else
    warn "Git-E-Mail nicht gefunden. Bitte manuell setzen:"
    warn "  git config user.email 'deine@email.de'"
    warn "  git config user.name  '${GH_USER}'"
  fi
fi

# ── GitHub Repository erstellen ───────────────────────────
info "Erstelle GitHub Repository ${GH_USER}/${REPO_NAME}…"

if gh repo view "${GH_USER}/${REPO_NAME}" >/dev/null 2>&1; then
  warn "Repository ${GH_USER}/${REPO_NAME} existiert bereits – überspringe Erstellung"
else
  gh repo create "${REPO_NAME}" \
    --public \
    --description "${REPO_DESC}" \
    --source="${REPO_DIR}" \
    --remote=origin \
    --push=false
  ok "Repository erstellt: https://github.com/${GH_USER}/${REPO_NAME}"
fi

# ── Remote setzen ─────────────────────────────────────────
REMOTE_URL="https://github.com/${GH_USER}/${REPO_NAME}.git"
if git remote get-url origin >/dev/null 2>&1; then
  git remote set-url origin "${REMOTE_URL}"
else
  git remote add origin "${REMOTE_URL}"
fi
ok "Remote gesetzt: ${REMOTE_URL}"

# ── Initialer Commit ──────────────────────────────────────
info "Erstelle initialen Commit…"
git add -A

if git diff --cached --quiet; then
  warn "Nichts zu committen – bereits committed?"
else
  git commit -m "feat: initial release Vermeer ${INITIAL_TAG}

- AES-256-CBC encrypted photo and thumbnail storage
- Album / sub-album structure with unlimited depth
- Granular per-album access control via user management
- DE/EN language toggle with localStorage persistence
- Umbrel Community App Store compatible
- MIT License"
  ok "Initialer Commit erstellt"
fi

# ── Branch auf main setzen ────────────────────────────────
git branch -M main

# ── Push ──────────────────────────────────────────────────
info "Pushe nach GitHub…"
git push -u origin main
ok "Code hochgeladen"

# ── Git Tag für Version 0.5-beta ─────────────────────────
info "Erstelle Release-Tag ${INITIAL_TAG}…"

if git tag -l | grep -q "^${INITIAL_TAG}$"; then
  warn "Tag ${INITIAL_TAG} existiert bereits – überspringe"
else
  git tag -a "${INITIAL_TAG}" -m "${INITIAL_TAG_MSG}"
  git push origin "${INITIAL_TAG}"
  ok "Tag ${INITIAL_TAG} erstellt und gepusht"
fi

# ── GitHub Release erstellen ──────────────────────────────
info "Erstelle GitHub Release…"

if gh release view "${INITIAL_TAG}" >/dev/null 2>&1; then
  warn "Release ${INITIAL_TAG} existiert bereits – überspringe"
else
  gh release create "${INITIAL_TAG}" \
    --title "Vermeer 0.5 Beta" \
    --notes "## Vermeer 0.5 Beta – Initial Release

### Features
- 🔒 **AES-256-CBC** encryption for all photos and thumbnails
- 📁 **Album / Sub-Album** structure with unlimited nesting depth
- 👥 **User management** with granular per-album access control
- ⬇️ **Download protection** – only the photo owner (or admin) can download originals
- 🌐 **DE / EN** language toggle with browser language auto-detection
- 🐳 **Umbrel Community App Store** compatible

### First Login
| Field | Value |
|-------|-------|
| Username | \`admin\` |
| Password | \`admin\` |

> ⚠️ Please change the admin password immediately after first login!

### Installation
Add this URL to your Umbrel Community App Stores:
\`\`\`
https://github.com/${GH_USER}/${REPO_NAME}
\`\`\`"
  ok "GitHub Release erstellt"
fi

# ── Zusammenfassung ───────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}✅ Fertig!${NC}"
echo "────────────────────────────────────────────────────────"
echo -e "📦 Repository  : ${CYAN}https://github.com/${GH_USER}/${REPO_NAME}${NC}"
echo -e "🏷  Version     : ${CYAN}${INITIAL_TAG}${NC}"
echo -e "🚀 Release     : ${CYAN}https://github.com/${GH_USER}/${REPO_NAME}/releases/tag/${INITIAL_TAG}${NC}"
echo ""
echo -e "${BOLD}Umbrel Community App Store URL:${NC}"
echo -e "  ${CYAN}https://github.com/${GH_USER}/${REPO_NAME}${NC}"
echo ""
echo "In Umbrel hinzufügen:"
echo "  App Store → Community App Stores → URL eintragen → Vermeer installieren"
echo "────────────────────────────────────────────────────────"

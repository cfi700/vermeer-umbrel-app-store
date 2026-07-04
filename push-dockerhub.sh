#!/usr/bin/env bash
# =============================================================
#  Vermeer – Docker Hub Push Script
#  Baut das Image für ARM64 + AMD64 und pusht es auf Docker Hub.
#
#  Voraussetzungen:
#    - Docker Desktop installiert und gestartet
#    - Docker Hub Account: cfi700
#
#  Aufruf (Git Bash oder WSL):
#    bash push-dockerhub.sh
# =============================================================
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $*"; }
info() { echo -e "${CYAN}→${NC} $*"; }
die()  { echo -e "${RED}✗ Fehler:${NC} $*"; exit 1; }

DOCKERHUB_USER="cfi700"
IMAGE_NAME="vermeer"
IMAGE_TAG="1.0.0"
FULL_IMAGE="${DOCKERHUB_USER}/${IMAGE_NAME}:${IMAGE_TAG}"

echo -e "\n${BOLD}🐳 Vermeer – Docker Hub Build & Push${NC}"
echo    "─────────────────────────────────────────"
info "Image : ${FULL_IMAGE}"
info "Plattformen: linux/amd64, linux/arm64"
echo ""

# Check Docker is running
docker info >/dev/null 2>&1 || die "Docker läuft nicht. Bitte Docker Desktop starten."
ok "Docker läuft"

# Login to Docker Hub
info "Anmelden bei Docker Hub als ${DOCKERHUB_USER}…"
docker login --username "${DOCKERHUB_USER}" || die "Docker Hub Login fehlgeschlagen."
ok "Eingeloggt"

# Enable buildx for multi-arch
info "Erstelle buildx Builder (multi-arch)…"
docker buildx create --name vermeer-builder --use 2>/dev/null || \
  docker buildx use vermeer-builder 2>/dev/null || true
docker buildx inspect --bootstrap
ok "Builder bereit"

# Build & push from the app folder
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${SCRIPT_DIR}/vermeer-store-vermeer"

[[ -f "${APP_DIR}/Dockerfile" ]] || die "Dockerfile nicht gefunden in ${APP_DIR}"

info "Baue und pushe Multi-Arch Image (ARM64 + AMD64)…"
info "Das kann 5-15 Minuten dauern…"
echo ""

docker buildx build \
  --platform linux/arm64,linux/amd64 \
  --tag "${FULL_IMAGE}" \
  --output "type=registry" \
  "${APP_DIR}"

echo ""
ok "Image erfolgreich auf Docker Hub gepusht!"
echo ""
echo -e "${BOLD}Docker Hub:${NC} https://hub.docker.com/r/${DOCKERHUB_USER}/${IMAGE_NAME}"
echo ""
echo -e "${BOLD}Nächster Schritt:${NC} GitHub Repository aktualisieren:"
echo "  git add -A"
echo "  git commit -m \"fix: use Docker Hub image cfi700/vermeer:${IMAGE_TAG}\""
echo "  git push"
echo ""
echo "Dann in Umbrel: App deinstallieren → neu installieren"

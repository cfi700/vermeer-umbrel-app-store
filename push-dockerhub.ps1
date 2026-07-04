# =============================================================
#  Vermeer – Docker Hub Build & Push
#  PowerShell Script fuer Windows
#
#  Aufruf in PowerShell:
#    .\push-dockerhub.ps1
# =============================================================

$DOCKERHUB_USER = "cfi700"
$IMAGE_NAME     = "vermeer"
$IMAGE_TAG      = "1.0.0"
$FULL_IMAGE     = "${DOCKERHUB_USER}/${IMAGE_NAME}:${IMAGE_TAG}"

Write-Host ""
Write-Host "=== Vermeer - Docker Hub Build & Push ===" -ForegroundColor Cyan
Write-Host "Image : $FULL_IMAGE" -ForegroundColor Yellow
Write-Host ""

# Pfad zum App-Verzeichnis (relativ zum Skript)
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$APP_DIR    = Join-Path $SCRIPT_DIR "vermeer-store-vermeer"

if (-not (Test-Path "$APP_DIR\Dockerfile")) {
    Write-Host "FEHLER: Dockerfile nicht gefunden in $APP_DIR" -ForegroundColor Red
    Write-Host "Bitte das Skript aus dem vermeer-umbrel Ordner ausfuehren." -ForegroundColor Red
    exit 1
}

# Docker pruefen
try {
    docker info | Out-Null
    Write-Host "[OK] Docker laeuft" -ForegroundColor Green
} catch {
    Write-Host "FEHLER: Docker laeuft nicht. Bitte Docker Desktop starten." -ForegroundColor Red
    exit 1
}

# Docker Hub Login
Write-Host ""
Write-Host "[->] Anmelden bei Docker Hub als $DOCKERHUB_USER ..." -ForegroundColor Cyan
docker login --username $DOCKERHUB_USER
if ($LASTEXITCODE -ne 0) {
    Write-Host "FEHLER: Docker Hub Login fehlgeschlagen." -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Eingeloggt bei Docker Hub" -ForegroundColor Green

# buildx Builder erstellen
Write-Host ""
Write-Host "[->] Erstelle Multi-Arch Builder ..." -ForegroundColor Cyan
docker buildx create --name vermeer-builder --use 2>$null
docker buildx use vermeer-builder 2>$null
docker buildx inspect --bootstrap
Write-Host "[OK] Builder bereit" -ForegroundColor Green

# Build & Push
Write-Host ""
Write-Host "[->] Baue Image fuer linux/amd64 + linux/arm64 ..." -ForegroundColor Cyan
Write-Host "     Das kann 5-15 Minuten dauern ..." -ForegroundColor Yellow
Write-Host ""

docker buildx build `
    --platform linux/arm64,linux/amd64 `
    --tag $FULL_IMAGE `
    --output "type=registry" `
    $APP_DIR

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "FEHLER: Build/Push fehlgeschlagen." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=============================================" -ForegroundColor Green
Write-Host "[OK] Image erfolgreich auf Docker Hub!" -ForegroundColor Green
Write-Host "     https://hub.docker.com/r/$DOCKERHUB_USER/$IMAGE_NAME" -ForegroundColor Cyan
Write-Host ""
Write-Host "Naechster Schritt - GitHub aktualisieren:" -ForegroundColor Yellow
Write-Host "  git add -A"
Write-Host "  git commit -m `"fix: use Docker Hub image $FULL_IMAGE`""
Write-Host "  git push"
Write-Host ""
Write-Host "Dann in Umbrel: App deinstallieren -> neu installieren" -ForegroundColor Yellow
Write-Host "=============================================" -ForegroundColor Green

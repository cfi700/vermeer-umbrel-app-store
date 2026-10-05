# Vermeer – Android-Companion-App

Schlanke Android-App, die die Vermeer-Weboberfläche in einer WebView kapselt.
Keine Play-Store-Veröffentlichung – die APK wird direkt über GitHub geladen:

**https://github.com/cfi700/vermeer-umbrel-app-store/releases/download/android-latest/vermeer-android.apk**

## Was die App kann

| Funktion | Umsetzung |
|---|---|
| Server wählen | Beim ersten Start Adresse eingeben (z. B. `http://umbrel.local:3769` oder die Tunnel-Adresse). Geprüft wird über `/api/health`. Ändern später unter **Konto → App** oder auf dem Anmeldebildschirm. |
| Handy-Ansicht | Die Web-UI erkennt die App am User-Agent (`VermeerAndroid/x.y.z`) und schaltet auf die Handy-Darstellung. |
| Upload | Android-Dateiauswahl inkl. Mehrfachauswahl (Fotos, Videos, PDFs, GIFs). |
| Videos | Vollbild über den Player-Knopf. |
| ZIP-Export | Über den Android-Download-Manager in den Ordner *Download*. |
| Zurück-Taste | Schließt Lightbox/Dialog bzw. geht ein Album hoch; auf der Startseite zweimal drücken zum Beenden. |
| Leistenfarbe | Folgt der in Vermeer eingestellten Hintergrundfarbe. |
| Fremde Links | Öffnen im Browser, nicht in der App. |
| Screenshot-Schutz | Bildschirmfotos und -aufnahmen bleiben schwarz, die Vorschau in der App-Übersicht ist leer, kein Übertragen auf Screencast/Mirroring (`FLAG_SECURE`). Gilt für alle Benutzer. |

Nicht enthalten (bewusst): Service Worker / Offline-Cache, Push-Benachrichtigungen,
Speichern einzelner Bilder (Download-Schutz bleibt wie im Browser).

Mindestversion: Android 8.0 (API 26).

## Installation auf dem Handy

1. Den Link oben auf dem Handy öffnen (oder in Vermeer: **Konto → Android-App**).
2. Die heruntergeladene `vermeer-android.apk` antippen.
3. Android fragt einmalig, ob Browser bzw. Dateimanager Apps installieren dürfen
   („Unbekannte Apps installieren") – erlauben.
4. Updates: neue APK genauso installieren – Daten und Server-Adresse bleiben erhalten,
   solange die APK mit demselben Schlüssel signiert ist (siehe unten).

## Bauen

Gebaut wird per GitHub Actions (`.github/workflows/android.yml`):

* **Push** mit Änderungen unter `android/` → Test-APK als Workflow-Artefakt.
* **Tag `android-vX.Y.Z`** → signierte APK als Release `Android X.Y.Z`
  und Aktualisierung des festen Download-Releases `android-latest`.

```bash
git tag android-v1.0.0
git push origin android-v1.0.0
```

`versionCode` wird aus dem Tag berechnet (`X*10000 + Y*100 + Z`), muss also bei
jedem Release steigen.

Lokal (Android-SDK nötig, `ANDROID_HOME` gesetzt):

```bash
cd android
./gradlew assembleRelease     # ohne Schlüssel-Umgebung: Debug-signiert
```

## Signaturschlüssel (einmalig)

Android installiert ein Update nur, wenn es mit **demselben Schlüssel** signiert ist
wie die installierte Version. Der Schlüssel wird einmal erzeugt und als
GitHub-Secret hinterlegt – **gut aufbewahren**, ein verlorener Schlüssel heißt:
App deinstallieren und neu installieren.

```bash
keytool -genkeypair -v -keystore vermeer-release.jks -alias vermeer \
  -keyalg RSA -keysize 4096 -validity 10000 \
  -dname "CN=Vermeer Companion"
base64 -w0 vermeer-release.jks > vermeer-release.jks.b64
```

Unter **GitHub → Settings → Secrets and variables → Actions** anlegen:

| Secret | Inhalt |
|---|---|
| `ANDROID_KEYSTORE_BASE64` | Inhalt von `vermeer-release.jks.b64` |
| `ANDROID_KEYSTORE_PASSWORD` | Keystore-Passwort |
| `ANDROID_KEY_ALIAS` | `vermeer` |
| `ANDROID_KEY_PASSWORD` | Schlüssel-Passwort (bei PKCS12 = Keystore-Passwort) |

Ohne diese Secrets bricht ein Release-Tag mit einer Fehlermeldung ab;
Test-Builds werden dann mit einem wechselnden Debug-Schlüssel signiert
(installierbar, aber nicht als Update über eine Release-Version).

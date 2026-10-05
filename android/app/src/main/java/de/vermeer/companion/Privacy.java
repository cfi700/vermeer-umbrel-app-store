package de.vermeer.companion;

import android.app.Activity;
import android.os.Build;
import android.view.WindowManager;

/**
 * Screenshot-Schutz: Bildschirmfotos und -aufnahmen zeigen nur Schwarz, die
 * Vorschau in der App-Uebersicht (Recents) bleibt leer, und der Inhalt wird
 * nicht auf unsichere Displays (Screencast/Mirroring) uebertragen.
 * Passt zum Download-Schutz der Web-UI; gilt fuer alle Benutzer.
 */
final class Privacy {
    private Privacy() {}

    static void secure(Activity a) {
        a.getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE);
        // Ab Android 13 zusaetzlich ausdruecklich: kein Recents-Schnappschuss.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            a.setRecentsScreenshotEnabled(false);
        }
    }
}

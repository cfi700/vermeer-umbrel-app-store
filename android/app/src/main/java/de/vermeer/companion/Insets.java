package de.vermeer.companion;

import android.os.Build;
import android.view.View;
import android.view.WindowInsets;

/**
 * Ab Android 15 zeichnet jede App (targetSdk 35) randlos unter Status- und
 * Navigationsleiste. Der Inhalt bekommt deshalb die Systemleisten – und die
 * Tastatur, die adjustResize randlos nicht mehr beruecksichtigt – als Padding.
 * Auf aelteren Versionen erledigt das Fenster selbst beides.
 */
final class Insets {
    private Insets() {}

    static void applySystemBars(View root) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.VANILLA_ICE_CREAM) return;
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            android.graphics.Insets i = insets.getInsets(WindowInsets.Type.systemBars()
                    | WindowInsets.Type.displayCutout() | WindowInsets.Type.ime());
            v.setPadding(i.left, i.top, i.right, i.bottom);
            return insets;
        });
        root.requestApplyInsets();
    }
}

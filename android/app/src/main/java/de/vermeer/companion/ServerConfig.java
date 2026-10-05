package de.vermeer.companion;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;

import java.util.Locale;
import java.util.regex.Pattern;

/** Gespeicherte Server-Adresse und deren Normalisierung. */
final class ServerConfig {
    private static final String PREFS = "vermeer";
    private static final String KEY_SERVER = "server_url";

    // Ziele, die praktisch nur im Heimnetz vorkommen und dort meist ohne TLS laufen.
    private static final Pattern LOCAL_HOST = Pattern.compile(
            "^(localhost|[^.]+|.*\\.local|.*\\.lan|.*\\.home|\\d{1,3}(\\.\\d{1,3}){3})$");

    private ServerConfig() {}

    static String get(Context ctx) {
        return prefs(ctx).getString(KEY_SERVER, null);
    }

    static void set(Context ctx, String url) {
        prefs(ctx).edit().putString(KEY_SERVER, url).apply();
    }

    private static SharedPreferences prefs(Context ctx) {
        return ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    /**
     * Macht aus einer Benutzereingabe eine Basis-URL ohne abschliessenden Slash,
     * oder null, wenn die Eingabe keine brauchbare Adresse ist.
     * Ohne Schema: Heimnetz-Ziele (umbrel.local, 192.168.x.x, …) bekommen http,
     * alles andere https.
     */
    static String normalize(String input) {
        if (input == null) return null;
        String s = input.trim();
        if (s.isEmpty()) return null;
        if (s.matches("(?i)^[a-z][a-z0-9+.-]*://.*")) {
            if (!s.matches("(?i)^https?://.*")) return null;
        } else {
            String host = s.split("[/:?#]", 2)[0].toLowerCase(Locale.ROOT);
            s = (LOCAL_HOST.matcher(host).matches() ? "http://" : "https://") + s;
        }
        Uri u = Uri.parse(s);
        String scheme = u.getScheme();
        String host = u.getHost();
        if (scheme == null || host == null || host.isEmpty()) return null;
        StringBuilder b = new StringBuilder()
                .append(scheme.toLowerCase(Locale.ROOT)).append("://")
                .append(host.toLowerCase(Locale.ROOT));
        if (u.getPort() != -1) b.append(':').append(u.getPort());
        String path = u.getPath();
        if (path != null) {
            while (path.endsWith("/")) path = path.substring(0, path.length() - 1);
            b.append(path);
        }
        return b.toString();
    }

    /** Gleicher Ursprung (Schema, Host, Port) wie die Server-Adresse? */
    static boolean sameOrigin(String base, Uri target) {
        if (base == null || target == null) return false;
        Uri b = Uri.parse(base);
        return eq(b.getScheme(), target.getScheme())
                && eq(b.getHost(), target.getHost())
                && port(b) == port(target);
    }

    private static boolean eq(String a, String b) {
        return a != null && a.equalsIgnoreCase(b);
    }

    private static int port(Uri u) {
        if (u.getPort() != -1) return u.getPort();
        return "https".equalsIgnoreCase(u.getScheme()) ? 443 : 80;
    }
}

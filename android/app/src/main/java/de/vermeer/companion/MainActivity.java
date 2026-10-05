package de.vermeer.companion;

import android.Manifest;
import android.app.Activity;
import android.app.DownloadManager;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.text.Html;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.view.WindowInsetsController;
import android.webkit.CookieManager;
import android.webkit.JavascriptInterface;
import android.webkit.MimeTypeMap;
import android.webkit.URLUtil;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Huelle um die Vermeer-Weboberflaeche. Die Web-UI erkennt die App am
 * User-Agent-Zusatz "VermeerAndroid/x.y.z" und an der Bruecke window.VermeerApp.
 */
public class MainActivity extends Activity {
    static final String EXTRA_RELOAD = "reload";

    private static final int REQ_FILES = 1;
    private static final int REQ_STORAGE = 2;
    private static final long EXIT_WINDOW_MS = 2000;

    private FrameLayout root;
    private WebView web;
    private String server;

    private ValueCallback<Uri[]> fileCallback;
    private View customView;
    private WebChromeClient.CustomViewCallback customViewCallback;
    private long lastBackPress;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Privacy.secure(this);
        server = ServerConfig.get(this);
        if (server == null) {
            startActivity(new Intent(this, SetupActivity.class));
            finish();
            return;
        }

        root = new FrameLayout(this);
        root.setBackgroundColor(getColor(R.color.bg));
        web = new WebView(this);
        root.addView(web, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        setContentView(root);
        Insets.applySystemBars(root);

        configureWebView();
        if (savedInstanceState == null || web.restoreState(savedInstanceState) == null) {
            web.loadUrl(server + "/");
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        if (web != null && intent.getBooleanExtra(EXTRA_RELOAD, false)) {
            server = ServerConfig.get(this);
            web.clearHistory();
            web.loadUrl(server + "/");
        }
    }

    private void configureWebView() {
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setMediaPlaybackRequiresUserGesture(true);
        s.setAllowFileAccess(false);
        s.setAllowContentAccess(false);
        s.setSupportMultipleWindows(false);
        s.setUserAgentString(s.getUserAgentString() + " VermeerAndroid/" + BuildConfig.VERSION_NAME);

        CookieManager.getInstance().setAcceptCookie(true);
        CookieManager.getInstance().setAcceptThirdPartyCookies(web, false);

        web.addJavascriptInterface(new Bridge(), "VermeerApp");
        web.setWebViewClient(new Client());
        web.setWebChromeClient(new Chrome());
        web.setDownloadListener(this::download);
    }

    // ── Zurueck-Taste ────────────────────────────────────────────────
    // Die Web-UI kennt ihre Ebenen selbst (Lightbox, Modal, Unteralbum);
    // window.vermeerNativeBack() schliesst die oberste und meldet true.
    @Override
    @SuppressWarnings("deprecation")
    public void onBackPressed() {
        if (customView != null) { hideCustomView(); return; }
        if (web == null) { super.onBackPressed(); return; }
        web.evaluateJavascript(
                "(function(){try{return !!(window.vermeerNativeBack&&window.vermeerNativeBack());}catch(e){return false;}})()",
                handled -> {
                    if ("true".equals(handled)) { lastBackPress = 0; return; }
                    long now = System.currentTimeMillis();
                    if (now - lastBackPress < EXIT_WINDOW_MS) {
                        finish();
                    } else {
                        lastBackPress = now;
                        Toast.makeText(this, R.string.back_exit, Toast.LENGTH_SHORT).show();
                    }
                });
    }

    // ── Lebenszyklus ─────────────────────────────────────────────────
    @Override
    protected void onPause() {
        super.onPause();
        if (web != null) web.onPause();
        CookieManager.getInstance().flush();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (web != null) web.onResume();
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        if (web != null) web.saveState(outState);
    }

    @Override
    protected void onDestroy() {
        if (web != null) {
            web.destroy();
            web = null;
        }
        super.onDestroy();
    }

    // ── Navigation & Fehlerseite ─────────────────────────────────────
    private class Client extends WebViewClient {
        @Override
        public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
            Uri uri = request.getUrl();
            if (ServerConfig.sameOrigin(server, uri)) return false;
            // Fremde Ziele (z. B. GitHub, Hilfeseiten) im Browser oeffnen.
            try {
                startActivity(new Intent(Intent.ACTION_VIEW, uri));
            } catch (ActivityNotFoundException ignored) {
            }
            return true;
        }

        @Override
        public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
            if (request.isForMainFrame()) showErrorPage();
        }
    }

    private void showErrorPage() {
        String html = "<!DOCTYPE html><html><head><meta charset='utf-8'>"
                + "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                + "<style>body{margin:0;background:#0d0d0f;color:#e8e6e0;font-family:sans-serif;"
                + "display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center}"
                + ".c{padding:28px;max-width:420px}h1{color:#c8a96e;font-weight:400;font-size:22px}"
                + "p{color:#7a7872;line-height:1.5}button{display:block;width:100%;margin:12px 0;padding:13px;"
                + "border-radius:8px;font-size:15px;border:1px solid #c8a96e}"
                + ".p{background:#c8a96e;color:#0d0d0f}.g{background:transparent;color:#c8a96e}</style></head>"
                + "<body><div class='c'><div style='font-size:42px'>&#128225;</div>"
                + "<h1>" + Html.escapeHtml(getString(R.string.error_title)) + "</h1>"
                + "<p>" + Html.escapeHtml(getString(R.string.error_desc, server)) + "</p>"
                + "<button class='p' onclick='VermeerApp.retry()'>"
                + Html.escapeHtml(getString(R.string.error_retry)) + "</button>"
                + "<button class='g' onclick='VermeerApp.changeServer()'>"
                + Html.escapeHtml(getString(R.string.error_change)) + "</button>"
                + "</div></body></html>";
        web.loadDataWithBaseURL(null, html, "text/html", "utf-8", null);
    }

    // ── JS-Bruecke ───────────────────────────────────────────────────
    // Nur harmlose Funktionen: Version/Adresse lesen, Server-Dialog oeffnen,
    // neu laden, Leistenfarbe setzen.
    private class Bridge {
        @JavascriptInterface
        public String version() {
            return BuildConfig.VERSION_NAME;
        }

        @JavascriptInterface
        public String server() {
            return server;
        }

        @JavascriptInterface
        public void changeServer() {
            runOnUiThread(() -> startActivity(new Intent(MainActivity.this, SetupActivity.class)
                    .putExtra(SetupActivity.EXTRA_CHANGE, true)));
        }

        @JavascriptInterface
        public void retry() {
            runOnUiThread(() -> { if (web != null) web.loadUrl(server + "/"); });
        }

        @JavascriptInterface
        public void setThemeColor(String hex) {
            final int color;
            try {
                color = Color.parseColor(hex);
            } catch (IllegalArgumentException | NullPointerException e) {
                return;
            }
            runOnUiThread(() -> applyBarColor(color));
        }
    }

    @SuppressWarnings("deprecation")
    private void applyBarColor(int color) {
        if (root != null) root.setBackgroundColor(color);
        // Bis Android 14 faerbt das Fenster die Leisten; ab 15 scheint der
        // Hintergrund von root durch (randlos).
        getWindow().setStatusBarColor(color);
        getWindow().setNavigationBarColor(color);
        boolean light = Color.luminance(color) > 0.5f;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            WindowInsetsController c = getWindow().getInsetsController();
            if (c != null) {
                int mask = WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                        | WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS;
                c.setSystemBarsAppearance(light ? mask : 0, mask);
            }
        } else {
            View d = getWindow().getDecorView();
            int f = d.getSystemUiVisibility();
            int mask = View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR | View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR;
            d.setSystemUiVisibility(light ? (f | mask) : (f & ~mask));
        }
    }

    // ── Upload: Dateiauswahl ─────────────────────────────────────────
    private class Chrome extends WebChromeClient {
        @Override
        public boolean onShowFileChooser(WebView view, ValueCallback<Uri[]> callback,
                                         FileChooserParams params) {
            if (fileCallback != null) fileCallback.onReceiveValue(null);
            fileCallback = callback;

            Intent pick = new Intent(Intent.ACTION_GET_CONTENT)
                    .addCategory(Intent.CATEGORY_OPENABLE)
                    .putExtra(Intent.EXTRA_ALLOW_MULTIPLE,
                            params.getMode() == FileChooserParams.MODE_OPEN_MULTIPLE);
            String[] mimes = mimeTypes(params.getAcceptTypes());
            if (mimes.length == 1) {
                pick.setType(mimes[0]);
            } else {
                pick.setType("*/*");
                if (mimes.length > 1) pick.putExtra(Intent.EXTRA_MIME_TYPES, mimes);
            }
            try {
                startActivityForResult(Intent.createChooser(pick, null), REQ_FILES);
            } catch (ActivityNotFoundException e) {
                fileCallback = null;
                Toast.makeText(MainActivity.this, R.string.no_file_app, Toast.LENGTH_SHORT).show();
                return false;
            }
            return true;
        }

        // Vollbild fuer Videos (Fullscreen-Knopf im Player).
        @Override
        public void onShowCustomView(View view, CustomViewCallback callback) {
            if (customView != null) { callback.onCustomViewHidden(); return; }
            customView = view;
            customViewCallback = callback;
            root.addView(view, new FrameLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
            web.setVisibility(View.GONE);
            setFullscreenBars(true);
        }

        @Override
        public void onHideCustomView() {
            hideCustomView();
        }
    }

    private void hideCustomView() {
        if (customView == null) return;
        root.removeView(customView);
        customView = null;
        web.setVisibility(View.VISIBLE);
        setFullscreenBars(false);
        if (customViewCallback != null) customViewCallback.onCustomViewHidden();
        customViewCallback = null;
    }

    @SuppressWarnings("deprecation")
    private void setFullscreenBars(boolean on) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            WindowInsetsController c = getWindow().getInsetsController();
            if (c == null) return;
            if (on) {
                c.setSystemBarsBehavior(WindowInsetsController.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE);
                c.hide(WindowInsets.Type.systemBars());
            } else {
                c.show(WindowInsets.Type.systemBars());
            }
        } else {
            getWindow().getDecorView().setSystemUiVisibility(on
                    ? View.SYSTEM_UI_FLAG_FULLSCREEN | View.SYSTEM_UI_FLAG_HIDE_NAVIGATION
                    | View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY
                    : View.SYSTEM_UI_FLAG_VISIBLE);
        }
    }

    /** accept-Liste des Inputs ("image/*", ".gif", …) in MIME-Typen uebersetzen. */
    private static String[] mimeTypes(String[] accept) {
        Set<String> out = new LinkedHashSet<>();
        if (accept != null) {
            for (String entry : accept) {
                if (entry == null) continue;
                for (String a : entry.split(",")) {
                    a = a.trim().toLowerCase(Locale.ROOT);
                    if (a.isEmpty()) continue;
                    if (a.startsWith(".")) {
                        String m = MimeTypeMap.getSingleton().getMimeTypeFromExtension(a.substring(1));
                        if (m != null) out.add(m);
                    } else if (a.contains("/")) {
                        out.add(a);
                    }
                }
            }
        }
        return out.toArray(new String[0]);
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode != REQ_FILES) {
            super.onActivityResult(requestCode, resultCode, data);
            return;
        }
        if (fileCallback == null) return;
        Uri[] result = null;
        if (resultCode == RESULT_OK && data != null) {
            List<Uri> uris = new ArrayList<>();
            ClipData clip = data.getClipData();
            if (clip != null) {
                for (int i = 0; i < clip.getItemCount(); i++) uris.add(clip.getItemAt(i).getUri());
            } else if (data.getData() != null) {
                uris.add(data.getData());
            }
            if (!uris.isEmpty()) result = uris.toArray(new Uri[0]);
        }
        fileCallback.onReceiveValue(result);
        fileCallback = null;
    }

    // ── Download: ZIP-Export ─────────────────────────────────────────
    // Der Export ist der einzige Download der Web-UI (window.location =
    // '/api/export'). Der DownloadManager braucht dafuer das Session-Cookie.
    private void download(String url, String userAgent, String contentDisposition,
                          String mimeType, long contentLength) {
        Uri uri = Uri.parse(url);
        if (!ServerConfig.sameOrigin(server, uri)) return;
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q
                && checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE)
                != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE}, REQ_STORAGE);
            Toast.makeText(this, R.string.download_permission, Toast.LENGTH_LONG).show();
            return;
        }
        try {
            String name = URLUtil.guessFileName(url, contentDisposition, mimeType);
            DownloadManager.Request req = new DownloadManager.Request(uri)
                    .setTitle(name)
                    .setMimeType(mimeType)
                    .addRequestHeader("User-Agent", userAgent)
                    .setNotificationVisibility(
                            DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
                    .setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, name);
            String cookies = CookieManager.getInstance().getCookie(url);
            if (cookies != null) req.addRequestHeader("Cookie", cookies);
            DownloadManager dm = getSystemService(DownloadManager.class);
            dm.enqueue(req);
            Toast.makeText(this, R.string.download_started, Toast.LENGTH_LONG).show();
        } catch (RuntimeException e) {
            Toast.makeText(this, R.string.download_failed, Toast.LENGTH_LONG).show();
        }
    }
}

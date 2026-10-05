package de.vermeer.companion;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Erststart bzw. "Server ändern": Adresse eingeben, per /api/health pruefen,
 * speichern und die Galerie oeffnen.
 */
public class SetupActivity extends Activity {
    /** true = aus der laufenden App geoeffnet; dann ist Abbrechen moeglich. */
    static final String EXTRA_CHANGE = "change";

    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());

    private EditText urlField;
    private Button connect;
    private Button anyway;
    private TextView status;
    private String pendingUrl;
    private int attempt;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_setup);
        Insets.applySystemBars(findViewById(R.id.setup_root));

        urlField = findViewById(R.id.setup_url);
        connect = findViewById(R.id.setup_connect);
        anyway = findViewById(R.id.setup_anyway);
        status = findViewById(R.id.setup_status);
        Button cancel = findViewById(R.id.setup_cancel);

        String current = ServerConfig.get(this);
        if (current != null) urlField.setText(current);

        boolean change = getIntent().getBooleanExtra(EXTRA_CHANGE, false) && current != null;
        cancel.setVisibility(change ? View.VISIBLE : View.GONE);
        cancel.setOnClickListener(v -> finish());

        connect.setOnClickListener(v -> check());
        anyway.setOnClickListener(v -> { if (pendingUrl != null) save(pendingUrl); });
        urlField.setOnEditorActionListener((v, actionId, e) -> {
            if (actionId == EditorInfo.IME_ACTION_GO) { check(); return true; }
            return false;
        });
    }

    @Override
    protected void onDestroy() {
        io.shutdownNow();
        super.onDestroy();
    }

    private void check() {
        anyway.setVisibility(View.GONE);
        String url = ServerConfig.normalize(urlField.getText().toString());
        if (urlField.getText().toString().trim().isEmpty()) { show(getString(R.string.setup_empty), true); return; }
        if (url == null) { show(getString(R.string.setup_invalid), true); return; }
        urlField.setText(url);
        pendingUrl = url;
        connect.setEnabled(false);
        show(getString(R.string.setup_checking), false);
        final int token = ++attempt;
        io.execute(() -> {
            String version = null;
            String error = null;
            try {
                version = probe(url);
                if (version == null) error = getString(R.string.setup_not_vermeer);
            } catch (Exception e) {
                String msg = e.getMessage();
                error = getString(R.string.setup_failed,
                        msg != null ? msg : e.getClass().getSimpleName());
            }
            final String v = version, err = error;
            main.post(() -> {
                if (isFinishing() || token != attempt) return;
                connect.setEnabled(true);
                if (err == null) {
                    show(getString(R.string.setup_ok, v), false);
                    save(url);
                } else {
                    show(err, true);
                    // Z. B. hinter Cloudflare Access liefert /api/health erst nach
                    // dem Login JSON – dann soll man die Adresse trotzdem nutzen koennen.
                    anyway.setVisibility(View.VISIBLE);
                }
            });
        });
    }

    /** Liefert die Vermeer-Version oder null, wenn der Server kein Vermeer ist. */
    private static String probe(String base) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(base + "/api/health").openConnection();
        c.setConnectTimeout(8000);
        c.setReadTimeout(8000);
        c.setInstanceFollowRedirects(true);
        c.setRequestProperty("Accept", "application/json");
        try {
            if (c.getResponseCode() != 200) return null;
            StringBuilder sb = new StringBuilder();
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(c.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null && sb.length() < 4096) sb.append(line);
            }
            JSONObject o = new JSONObject(sb.toString());
            if (!"ok".equals(o.optString("status"))) return null;
            return o.optString("version", "?");
        } catch (org.json.JSONException e) {
            return null;
        } finally {
            c.disconnect();
        }
    }

    private void save(String url) {
        ServerConfig.set(this, url);
        Intent i = new Intent(this, MainActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_NEW_TASK)
                .putExtra(MainActivity.EXTRA_RELOAD, true);
        startActivity(i);
        finish();
    }

    private void show(String text, boolean error) {
        status.setVisibility(View.VISIBLE);
        status.setText(text);
        status.setTextColor(getColor(error ? R.color.danger : R.color.muted));
    }
}

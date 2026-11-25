package app.telegramws.proxy;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import java.io.File;
import java.io.IOException;
import java.util.concurrent.CompletableFuture;

public final class MainActivity extends Activity {
    private static final int BACKGROUND = Color.rgb(16, 25, 35);
    private static final int SURFACE = Color.rgb(24, 38, 50);
    private static final int BORDER = Color.rgb(53, 72, 86);
    private static final int TEXT = Color.rgb(236, 245, 248);
    private static final int MUTED = Color.rgb(175, 192, 203);
    private static final int MINT = Color.rgb(153, 235, 202);
    private static final int ERROR = Color.rgb(255, 182, 168);
    private final Handler ui = new Handler(Looper.getMainLooper());
    private final Runnable update = new Runnable() {
        @Override
        public void run() {
            render();
            ui.postDelayed(this, 400);
        }
    };
    private ProxySettings settings;
    private TextView status, address, description, probeStatus;
    private Button toggle, connect, copy, probe, edit;
    private Button diagnostics, shareReport;
    private int announcedDiagnostics;
    private long busyUntil;

    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        settings = new ProxySettings(this);
        ScrollView root = new ScrollView(this);
        root.setFillViewport(true);
        root.setBackgroundColor(BACKGROUND);
        root.setOnApplyWindowInsetsListener((view, insets) -> {
            if (Build.VERSION.SDK_INT >= 30) {
                var safe = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
                view.setPadding(safe.left, safe.top, safe.right, safe.bottom);
            }
            return insets;
        });
        setContentView(root);

        LinearLayout page = column();
        page.setPadding(dp(22), dp(16), dp(22), dp(28));
        root.addView(page);
        TextView title = text("Telegram WS", 32, TEXT);
        title.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        add(page, title, 4);
        add(page, text("Локальный MTProto-прокси", 15, MUTED), 24);

        LinearLayout card = column();
        card.setPadding(dp(18), dp(18), dp(18), dp(18));
        card.setBackground(shape(SURFACE, BORDER, 22));
        add(page, card, 18);
        status = sectionTitle("");
        add(card, status, 7);
        address = text("", 22, TEXT);
        address.setTypeface(Typeface.MONOSPACE);
        add(card, address, 8);
        description = text("", 14, MUTED);
        add(card, description, 14);
        toggle = button("Запустить прокси", true, v -> toggle());
        add(card, toggle, 0);

        add(page, sectionTitle("Подключение"), 3);
        add(page, text("Откройте настройки прокси в Telegram и подтвердите подключение.", 14, MUTED), 10);
        connect = button("Открыть в Telegram", false, v -> openTelegram());
        add(page, connect, Build.VERSION.SDK_INT >= 29 ? 7 : 21);
        copy = button("Копировать ссылку", false, v -> {
            ClipboardManager clipboard = getSystemService(ClipboardManager.class);
            ClipData clip = ClipData.newPlainText("Telegram proxy", proxyLink().toString());
            android.os.PersistableBundle extras = new android.os.PersistableBundle();
            extras.putBoolean("android.content.extra.IS_SENSITIVE", true);
            clip.getDescription().setExtras(extras);
            clipboard.setPrimaryClip(clip);
            if (Build.VERSION.SDK_INT < 33) {
                toast("Ссылка скопирована");
            }
        });
        if (Build.VERSION.SDK_INT >= 29) {
            add(page, copy, 21);
        }

        add(page, sectionTitle("Диагностика"), 7);
        probe = button("Проверить связь с Telegram", false, v -> runProbe());
        add(page, probe, 6);
        probeStatus = text("", 14, MINT);
        add(page, probeStatus, 6);
        diagnostics = button("Расширенная диагностика", false, v -> offerDiagnostics());
        add(page, diagnostics, 7);
        shareReport = button("Поделиться последним отчётом", false,
            v -> shareDiagnostics(NetworkDiagnostics.status().report()));
        add(page, shareReport, 7);
        add(page, button("Журнал соединений", false, v -> openJournal()), 7);
        edit = button("Настройки маршрутов", false, v -> openSettings());
        add(page, edit, 0);
        render();
    }

    @Override
    protected void onResume() {
        super.onResume();
        ui.removeCallbacks(update);
        update.run();
    }

    @Override
    protected void onPause() {
        ui.removeCallbacks(update);
        super.onPause();
    }

    private void render() {
        ProxyStatus.Snapshot view = ProxyStatus.snapshot();
        boolean online = view.phase() == ProxyStatus.Phase.RUNNING;
        boolean starting = view.phase() == ProxyStatus.Phase.STARTING;
        String title = switch (view.phase()) {
            case OFF -> "Прокси выключен";
            case STARTING -> "Прокси запускается";
            case RUNNING -> "Прокси работает";
            case FAILED -> "Ошибка запуска";
        };
        status.setText(title);
        status.setTextColor(view.phase() == ProxyStatus.Phase.FAILED ? ERROR : online ? MINT : TEXT);
        int port = online ? view.port() : settings.port();
        address.setText(getString(R.string.loopback_address, Integer.toString(port)));
        description.setText(view.phase() == ProxyStatus.Phase.FAILED ? view.detail()
            : online ? "Сервис продолжит работать после выхода с этого экрана."
            : "Запустите сервис, чтобы подключить Telegram на этом устройстве.");
        toggle.setText(online || starting ? "Остановить прокси" : "Запустить прокси");
        toggle.setEnabled(android.os.SystemClock.uptimeMillis() >= busyUntil);
        connect.setEnabled(online);
        copy.setEnabled(online);
        probe.setEnabled(online && !view.probing());
        edit.setEnabled(!online && !starting);
        probeStatus.setVisibility(view.probe().isEmpty() ? View.GONE : View.VISIBLE);
        probeStatus.setText(view.probe());
        renderDiagnostics();
    }

    private void renderDiagnostics() {
        NetworkDiagnostics.State state = NetworkDiagnostics.status();
        diagnostics.setEnabled(!state.running());
        diagnostics.setText(state.running() ? "Проверяем сеть…" : "Расширенная диагностика");
        shareReport.setVisibility(state.report() == null ? View.GONE : View.VISIBLE);
        if (state.id() == 0 || state.running() || state.id() == announcedDiagnostics || !hasWindowFocus()) {
            return;
        }
        announcedDiagnostics = state.id();
        if (state.report() == null) {
            toast("Не удалось сохранить диагностический отчёт");
            return;
        }
        new AlertDialog.Builder(this).setTitle("Диагностика завершена")
            .setMessage("Можно отправить текстовый отчёт. В нём только результаты проверок и общие параметры подключения.")
            .setPositiveButton("Поделиться .txt", (dialog, which) -> shareDiagnostics(state.report()))
            .setNegativeButton("Закрыть", null).show();
    }

    private void offerDiagnostics() {
        new AlertDialog.Builder(this).setTitle("Расширенная диагностика")
            .setMessage("Тест проверяет IPv4 и IPv6, адреса Telegram, контрольный HTTPS и настроенные маршруты. "
                + "Полная проверка также обращается к публичным доменам Flowseal, которые видят IP соединения. "
                + "Отчёт можно отправить вручную после завершения.")
            .setPositiveButton("Полная проверка", (dialog, which) -> startDiagnostics(true))
            .setNeutralButton("Без доменов Flowseal", (dialog, which) -> startDiagnostics(false))
            .setNegativeButton("Отмена", null).show();
    }

    private void startDiagnostics(boolean includeCommunity) {
        NetworkDiagnostics.start(this, includeCommunity);
        renderDiagnostics();
    }

    private void shareDiagnostics(File report) {
        if (report == null || !report.isFile()) {
            toast("Отчёт недоступен. Запустите диагностику ещё раз.");
            return;
        }
        Uri uri = DiagnosticReport.uri(this, report);
        Intent send = new Intent(Intent.ACTION_SEND).setType("text/plain")
            .putExtra(Intent.EXTRA_STREAM, uri)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        send.setClipData(ClipData.newUri(getContentResolver(), "Отчёт диагностики", uri));
        startActivity(Intent.createChooser(send, "Отправить отчёт"));
    }

    private void toggle() {
        ProxyStatus.Phase phase = ProxyStatus.snapshot().phase();
        if (phase == ProxyStatus.Phase.RUNNING || phase == ProxyStatus.Phase.STARTING) {
            stopService(new Intent(this, ProxyService.class));
            updateAfterToggle();
        } else if (settings.hasAutomaticRouteChoice()) {
            startProxy();
        } else {
            new AlertDialog.Builder(this).setTitle("Добавить автоматический резерв?")
                .setMessage("Если прямое подключение не отвечает, прокси подберёт маршрут через публичные "
                    + "серверы Flowseal. Эти серверы видят IP и время подключения. При необходимости "
                    + "используется порт 80 без внешнего TLS. Выбор можно изменить в настройках маршрутов.")
                .setPositiveButton("Разрешить резерв", (dialog, which) -> startWithAutomaticRoutes(true))
                .setNegativeButton("Оставить мои настройки", (dialog, which) -> startWithAutomaticRoutes(false))
                .show();
        }
    }

    private void startWithAutomaticRoutes(boolean enabled) {
        settings.setAutomaticRoutes(enabled);
        startProxy();
    }

    private void startProxy() {
        startForegroundService(new Intent(this, ProxyService.class).setAction(ProxyService.START));
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
            && !getPreferences(MODE_PRIVATE).getBoolean("notificationsAsked", false)) {
            getPreferences(MODE_PRIVATE).edit().putBoolean("notificationsAsked", true).apply();
            requestPermissions(new String[] {Manifest.permission.POST_NOTIFICATIONS}, 1);
        }
        updateAfterToggle();
    }

    private void updateAfterToggle() {
        busyUntil = android.os.SystemClock.uptimeMillis() + 550;
        render();
    }

    private Uri proxyLink() {
        Routes.Config config = settings.load();
        return new Uri.Builder().scheme("tg").authority("proxy")
            .appendQueryParameter("server", "127.0.0.1")
            .appendQueryParameter("port", Integer.toString(config.port()))
            .appendQueryParameter("secret", "dd" + config.secret()).build();
    }

    private void openTelegram() {
        Uri link = proxyLink();
        for (String packageName : new String[] {"org.telegram.messenger", "org.telegram.messenger.web"}) {
            Intent intent = new Intent(Intent.ACTION_VIEW, link).setPackage(packageName);
            try {
                startActivity(intent);
                return;
            } catch (ActivityNotFoundException ignored) {
                // Try the other official Telegram distribution.
            }
        }
        toast("Установите официальный Telegram");
    }

    private void runProbe() {
        Routes.Config config = settings.load();
        int id = ProxyStatus.beginProbe();
        render();
        byte[] key = ProxySettings.key(config.secret());
        var main = probeRoute(config.port(), key, (short) 2, "DC2");
        var media2 = probeRoute(config.port(), key, (short) -2, "Медиа DC2");
        var media4 = probeRoute(config.port(), key, (short) -4, "Медиа DC4");
        var cdn = probeRoute(config.port(), key, (short) 203, "CDN DC203");
        CompletableFuture.allOf(main, media2, media4, cdn).thenRun(() ->
            ProxyStatus.endProbe(id, String.join("\n", main.join(), media2.join(), media4.join(), cdn.join())));
    }

    private CompletableFuture<String> probeRoute(int port, byte[] key, short dc, String label) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return label + " · " + ProxyProbe.check(port, key, dc) + " мс";
            } catch (IOException e) {
                return label + " · нет ответа";
            }
        });
    }

    private void openJournal() {
        ScrollView scroll = new ScrollView(this);
        TextView body = text("", 13, TEXT);
        body.setPadding(dp(20), dp(10), dp(20), dp(12));
        body.setTextIsSelectable(true);
        scroll.addView(body);
        AlertDialog dialog = new AlertDialog.Builder(this).setTitle("Журнал соединений")
            .setView(scroll).setPositiveButton("Закрыть", null).create();
        Runnable refresh = new Runnable() {
            @Override
            public void run() {
                String journal = ProxyStatus.snapshot().journal();
                String logs = journal.isEmpty() ? "Пока нет событий." : journal;
                if (!logs.contentEquals(body.getText())) {
                    boolean bottom = !scroll.canScrollVertically(1);
                    body.setText(logs);
                    if (bottom) {
                        scroll.post(() -> scroll.fullScroll(View.FOCUS_DOWN));
                    }
                }
                ui.postDelayed(this, 600);
            }
        };
        dialog.setOnDismissListener(ignored -> ui.removeCallbacks(refresh));
        dialog.show();
        refresh.run();
    }

    private void openSettings() {
        Routes.Config current = settings.load();
        LinearLayout form = column();
        form.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        form.setPadding(dp(20), dp(8), dp(20), dp(8));
        ScrollView scroll = new ScrollView(this);
        scroll.addView(form);
        EditText port = field(form, "Порт", Integer.toString(current.port()), InputType.TYPE_CLASS_NUMBER);
        EditText ips = field(form, "DC → IPv4", settings.ips(),
            InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        add(form, text("Одна пара DC:IPv4 на строку. Пустое поле включает обычный DNS.", 13, MUTED), 10);
        EditText cf = field(form, "Домен Cloudflare", current.cloudflare(), InputType.TYPE_TEXT_VARIATION_URI);
        EditText worker = field(form, "Домен Cloudflare Worker", current.worker(), InputType.TYPE_TEXT_VARIATION_URI);
        CheckBox communityAuto = check(form, "Автовыбор с резервом Flowseal", current.communityAuto());
        add(form, text("Пробует публичные серверы, если обычные маршруты не работают. Их операторы видят IP. "
            + "На порту 80 сохраняется шифрование MTProto без внешнего TLS.", 13, MUTED), 10);
        CheckBox community = check(form, "Резервные домены Flowseal (WSS)", current.community());
        CheckBox communityPlain = check(form, "Мобильный режим Flowseal (WS, порт 80)", current.communityPlain());
        add(form, text("Сначала пробует публичные домены Flowseal. Этот маршрут работает без TLS, "
            + "шифрование MTProto сохраняется.", 13, MUTED), 10);
        CheckBox tcp = check(form, "Резервное прямое TCP-подключение к Telegram", current.tcp());
        Socks5.Endpoint socks = current.socks();
        EditText socksAddress = field(form, "Адрес SOCKS5", socks == null ? "" : socks.address(),
            InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        EditText socksUser = field(form, "Логин SOCKS5", socks == null ? "" : socks.user(),
            InputType.TYPE_CLASS_TEXT);
        EditText socksPassword = field(form, "Пароль SOCKS5", socks == null ? "" : socks.password(),
            InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        CheckBox socksFirst = check(form, "Пробовать SOCKS5 первым", current.socksFirst());
        TextView error = text("", 14, ERROR);
        add(form, error, 3);
        AlertDialog dialog = new AlertDialog.Builder(this).setTitle("Настройки маршрутов").setView(scroll)
            .setNegativeButton("Отмена", null).setPositiveButton("Сохранить", null).create();
        dialog.show();
        dialog.getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE);
        dialog.getWindow().setSoftInputMode(android.view.WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN
            | android.view.WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(view -> {
            try {
                settings.save(port.getText().toString(), ips.getText().toString(), cf.getText().toString(),
                    worker.getText().toString(), community.isChecked(), tcp.isChecked(),
                    socksAddress.getText().toString(), socksUser.getText().toString(),
                    socksPassword.getText().toString(), socksFirst.isChecked(), communityPlain.isChecked(),
                    communityAuto.isChecked());
                dialog.dismiss();
                render();
            } catch (IllegalArgumentException e) {
                error.setText(e.getMessage());
                error.announceForAccessibility(e.getMessage());
                scroll.post(() -> scroll.fullScroll(View.FOCUS_DOWN));
            }
        });
    }

    private EditText field(LinearLayout form, String label, String value, int type) {
        TextView caption = text(label, 14, MUTED);
        add(form, caption, 0);
        EditText editText = new EditText(this);
        editText.setId(View.generateViewId());
        caption.setLabelFor(editText.getId());
        editText.setTextSize(16);
        editText.setInputType(type);
        editText.setText(value);
        if ((type & InputType.TYPE_MASK_VARIATION) == InputType.TYPE_TEXT_VARIATION_PASSWORD) {
            editText.setSaveEnabled(false);
        }
        add(form, editText, 10);
        return editText;
    }

    private CheckBox check(LinearLayout form, String label, boolean checked) {
        CheckBox box = new CheckBox(this);
        box.setText(label);
        box.setChecked(checked);
        add(form, box, 2);
        return box;
    }

    private LinearLayout column() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        return layout;
    }

    private TextView text(String value, int size, int color) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(size);
        view.setTextColor(color);
        return view;
    }

    private TextView sectionTitle(String value) {
        TextView heading = text(value, 18, TEXT);
        heading.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        if (Build.VERSION.SDK_INT >= 28) {
            heading.setAccessibilityHeading(true);
        }
        return heading;
    }

    private Button button(String label, boolean primary, View.OnClickListener action) {
        Button button = new Button(this);
        button.setAllCaps(false);
        button.setTextSize(15);
        button.setText(label);
        button.setGravity(Gravity.CENTER);
        button.setMinimumHeight(dp(50));
        button.setPadding(dp(12), dp(4), dp(12), dp(4));
        int[][] states = {{-android.R.attr.state_enabled}, {}};
        button.setTextColor(new ColorStateList(states, new int[] {0xff80929e, primary ? BACKGROUND : TEXT}));
        android.graphics.drawable.StateListDrawable fill = new android.graphics.drawable.StateListDrawable();
        fill.addState(states[0], shape(0xff202c35, 0xff34444f, 14));
        fill.addState(states[1], shape(primary ? MINT : SURFACE, primary ? MINT : BORDER, 14));
        button.setBackground(new android.graphics.drawable.RippleDrawable(
            ColorStateList.valueOf(primary ? 0x3330453d : 0x33a4ffd9), fill, null));
        button.setOnClickListener(action);
        return button;
    }

    private GradientDrawable shape(int fill, int stroke, int radius) {
        GradientDrawable background = new GradientDrawable();
        background.setColor(fill);
        background.setStroke(dp(1), stroke);
        background.setCornerRadius(dp(radius));
        return background;
    }

    private void add(LinearLayout layout, View view, int bottom) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2);
        params.bottomMargin = dp(bottom);
        layout.addView(view, params);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private void toast(String message) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show();
    }
}

package ru.ino.adb;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.RemoteInput;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.graphics.drawable.Icon;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayDeque;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * InoService: antarmuka pairing/connect/shell.
 *  - Service: cari layanan pairing lewat mDNS, tampilkan notifikasi dengan kolom reply kode 6 digit.
 *  - Static API (panggil dari thread background): pair(), connect(), shell(), discover().
 * Semua hasil berupa String bergaya Shizuku ("info: ...").
 */
public class InoService extends Service {

    private static final String P = InoService.class.getName();
    public static final String ACTION_START = P + ".START";
    public static final String ACTION_REPLY = P + ".REPLY";
    public static final String ACTION_STOP = P + ".STOP";
    public static final String TYPE_PAIRING = "_adb-tls-pairing._tcp.";
    public static final String TYPE_CONNECT = "_adb-tls-connect._tcp.";

    private static final String CHANNEL = "ino_adb";
    private static final String KEY_CODE = "code";
    private static final int NOTIF_ID = 7001;

    // ------------------------------------------------------------------ hasil & listener

    public static final class Result {
        public final boolean ok;
        public final String output;
        Result(boolean ok, String output) { this.ok = ok; this.output = output; }
        @Override public String toString() { return output; }
    }

    public interface Listener { void onOutput(String line); void onResult(boolean ok); }

    private static volatile Listener sListener;
    public static void setListener(Listener l) { sListener = l; }

    private static final class Log implements InoAdb.Out {
        final StringBuilder sb = new StringBuilder();
        public void line(String s) {
            sb.append(s).append('\n');
            Listener l = sListener;
            if (l != null) l.onOutput(s);
        }
    }

    private static final ExecutorService EXEC = Executors.newSingleThreadExecutor();

    // ------------------------------------------------------------------ API statis (sinkron)

    public static Result pair(Context ctx, String host, int port, String code) {
        Log log = new Log();
        log.line("Starting with wireless adb in port " + port + "...");
        log.line("");
        log.line("info: pairing begin");
        log.line("info: connecting to " + host + ":" + port);
        boolean ok = false;
        try {
            InoAdb.pair(ctx, host, port, code, log);
            log.line("info: pairing succeeded, device name is " + InoAdb.getDeviceName());
            ok = true;
        } catch (Throwable t) {
            log.line("error: " + t);
        }
        Listener l = sListener;
        if (l != null) l.onResult(ok);
        return new Result(ok, log.sb.toString());
    }

    /** host == null: pakai endpoint tersimpan, jika gagal cari ulang lewat mDNS. */
    public static Result connect(Context ctx, String host, int port) {
        Log log = new Log();
        boolean ok = false;
        try {
            InoAdb.Client c = open(ctx, host, port, log);
            c.close();
            ok = true;
        } catch (Throwable t) {
            log.line("error: " + t);
        }
        Listener l = sListener;
        if (l != null) l.onResult(ok);
        return new Result(ok, log.sb.toString());
    }

    public static Result shell(Context ctx, String cmd) {
        Log log = new Log();
        boolean ok = false;
        try {
            InoAdb.Client c = open(ctx, null, 0, log);
            try {
                String r = c.shell(cmd);
                log.line(r.endsWith("\n") ? r.substring(0, r.length() - 1) : r);
                ok = true;
            } finally { c.close(); }
        } catch (Throwable t) {
            log.line("error: " + t);
        }
        return new Result(ok, log.sb.toString());
    }

    /** Aktifkan mode TCP (adb tcpip) lewat wireless debugging, lalu simpan port-nya. */
    public static Result tcpip(Context ctx, int tcpPort) {
        Log log = new Log();
        boolean ok = false;
        try {
            InoAdb.Client c = open(ctx, null, 0, log);
            try {
                log.line("info: " + c.exec("tcpip:" + tcpPort).trim());
                InoAdb.saveTcpPort(ctx, tcpPort);
                ok = true;
            } finally { c.close(); }
        } catch (Throwable t) {
            log.line("error: " + t);
        }
        return new Result(ok, log.sb.toString());
    }

    private static InoAdb.Client open(Context ctx, String host, int port, Log log) throws Exception {
        if (host == null) { host = InoAdb.savedHost(ctx); port = InoAdb.savedPort(ctx); }
        if (host != null && port > 0) {
            try {
                log.line("info: connecting to " + host + ":" + port);
                InoAdb.Client c = InoAdb.Client.connect(ctx, host, port, log);
                InoAdb.saveEndpoint(ctx, host, port);
                log.line("info: connected");
                return c;
            } catch (Exception e) {
                log.line("info: endpoint lama gagal (" + e.getMessage() + "), cari lewat mDNS...");
            }
        }
        String[] f = discover(ctx, TYPE_CONNECT, 8000);
        if (f == null) throw new java.io.IOException("layanan wireless debugging tidak ditemukan (aktifkan dan sambung ke Wi-Fi)");
        log.line("info: mDNS found " + f[0] + ":" + f[1]);
        int p = Integer.parseInt(f[1]);
        InoAdb.Client c = InoAdb.Client.connect(ctx, f[0], p, log);
        InoAdb.saveEndpoint(ctx, f[0], p);
        log.line("info: connected");
        return c;
    }

    /** Cari layanan lokal lewat mDNS. Return {host, port} atau null. */
    public static String[] discover(Context ctx, String type, long timeoutMs) {
        final CountDownLatch latch = new CountDownLatch(1);
        final AtomicReference<String[]> ref = new AtomicReference<String[]>();
        Discovery d = new Discovery(ctx, true, new Discovery.Callback() {
            public void onFound(String host, int port) {
                ref.compareAndSet(null, new String[]{host, String.valueOf(port)});
                latch.countDown();
            }
        });
        try {
            d.start(type);
            latch.await(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (Throwable ignored) {
        } finally {
            d.stop();
        }
        return ref.get();
    }

    // ------------------------------------------------------------------ mDNS

    static final class Discovery implements NsdManager.DiscoveryListener {
        interface Callback { void onFound(String host, int port); }

        private final NsdManager nsd;
        private final Callback cb;
        private final boolean localOnly;
        private final ArrayDeque<NsdServiceInfo> queue = new ArrayDeque<NsdServiceInfo>();
        private boolean resolving;
        private volatile boolean stopped;

        Discovery(Context c, boolean localOnly, Callback cb) {
            this.nsd = (NsdManager) c.getApplicationContext().getSystemService(Context.NSD_SERVICE);
            this.localOnly = localOnly;
            this.cb = cb;
        }

        void start(String type) { nsd.discoverServices(type, NsdManager.PROTOCOL_DNS_SD, this); }

        void stop() {
            stopped = true;
            try { nsd.stopServiceDiscovery(this); } catch (Throwable ignored) {}
        }

        private void next() {
            final NsdServiceInfo s;
            synchronized (this) {
                if (resolving || stopped || queue.isEmpty()) return;
                resolving = true;
                s = queue.poll();
            }
            try {
                nsd.resolveService(s, new NsdManager.ResolveListener() {
                    public void onResolveFailed(NsdServiceInfo i, int code) { done(); }
                    public void onServiceResolved(NsdServiceInfo i) {
                        try { handle(i); } finally { done(); }
                    }
                });
            } catch (Throwable t) { done(); }
        }

        private void done() {
            synchronized (this) { resolving = false; }
            next();
        }

        private void handle(NsdServiceInfo i) {
            InetAddress a = i.getHost();
            if (a == null || stopped) return;
            if (localOnly) {
                try { if (NetworkInterface.getByInetAddress(a) == null) return; }
                catch (Exception e) { return; }
            }
            String host = a instanceof Inet4Address ? a.getHostAddress() : "127.0.0.1";
            cb.onFound(host, i.getPort());
        }

        public void onServiceFound(NsdServiceInfo s) { synchronized (this) { queue.add(s); } next(); }
        public void onServiceLost(NsdServiceInfo s) {}
        public void onDiscoveryStarted(String t) {}
        public void onDiscoveryStopped(String t) {}
        public void onStartDiscoveryFailed(String t, int e) {}
        public void onStopDiscoveryFailed(String t, int e) {}
    }

    // ------------------------------------------------------------------ Service + notifikasi reply

    private Discovery discovery;
    private volatile String pHost;
    private volatile int pPort;

    /** Mulai mencari layanan pairing dan tampilkan notifikasi reply. */
    public static void startPairing(Context ctx) {
        Intent i = new Intent(ctx, InoService.class).setAction(ACTION_START);
        if (Build.VERSION.SDK_INT >= 26) ctx.startForegroundService(i); else ctx.startService(i);
    }

    public static void stop(Context ctx) {
        ctx.startService(new Intent(ctx, InoService.class).setAction(ACTION_STOP));
    }

    @Override public IBinder onBind(Intent i) { return null; }

    @Override public int onStartCommand(Intent i, int flags, int startId) {
        String a = i == null ? null : i.getAction();
        if (ACTION_STOP.equals(a)) {
            stopDiscovery();
            stopForeground(true);
            stopSelf();
        } else if (ACTION_REPLY.equals(a)) {
            handleReply(i);
        } else {
            ensureChannel();
            startFg(build("Mencari layanan pairing (Wi-Fi + Wireless debugging harus aktif)...", false, true));
            startDiscovery();
        }
        return START_NOT_STICKY;
    }

    @Override public void onDestroy() { stopDiscovery(); super.onDestroy(); }

    private void startDiscovery() {
        stopDiscovery();
        discovery = new Discovery(this, true, new Discovery.Callback() {
            public void onFound(String host, int port) {
                pHost = host;
                pPort = port;
                notifyNow(build("Ditemukan " + host + ":" + port + " - ketuk Masukkan kode lalu ketik 6 digit.", true, true));
            }
        });
        try { discovery.start(TYPE_PAIRING); }
        catch (Throwable t) { notifyNow(build("mDNS gagal: " + t.getMessage(), false, false)); }
    }

    private void stopDiscovery() {
        if (discovery != null) { discovery.stop(); discovery = null; }
    }

    private void handleReply(Intent i) {
        Bundle r = RemoteInput.getResultsFromIntent(i);
        CharSequence cs = r == null ? null : r.getCharSequence(KEY_CODE);
        final String code = cs == null ? "" : cs.toString().replaceAll("\\s", "");
        if (pHost == null) {
            notifyNow(build("Layanan pairing belum ditemukan. Buka Wireless debugging > Pairing code.", false, true));
            return;
        }
        if (!code.matches("\\d{6}")) {
            notifyNow(build("Kode harus 6 digit. Coba lagi.", true, true));
            return;
        }
        notifyNow(build("Memasangkan...", false, true));
        final String host = pHost;
        final int port = pPort;
        final Context ctx = getApplicationContext();
        EXEC.execute(new Runnable() {
            public void run() {
                Result res = pair(ctx, host, port, code);
                if (!res.ok) {
                    notifyNow(build("Gagal: " + lastLine(res.output) + " - masukkan kode lagi.", true, true));
                    return;
                }
                notifyNow(build("Pairing berhasil, menyambung...", false, true));
                Result c = connect(ctx, null, 0);
                stopDiscovery();
                notifyNow(build(c.ok ? "Tersambung sebagai " + InoAdb.getDeviceName()
                        : "Pairing OK, connect gagal: " + lastLine(c.output), false, false));
                stopForeground(false);
                stopSelf();
            }
        });
    }

    private static String lastLine(String s) {
        String[] p = s.trim().split("\n");
        return p.length == 0 ? "" : p[p.length - 1];
    }

    private void ensureChannel() {
        if (Build.VERSION.SDK_INT < 26) return;
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        nm.createNotificationChannel(new NotificationChannel(CHANNEL, "Wireless ADB pairing", NotificationManager.IMPORTANCE_HIGH));
    }

    private Notification build(String text, boolean withReply, boolean ongoing) {
        Notification.Builder b = Build.VERSION.SDK_INT >= 26 ? new Notification.Builder(this, CHANNEL) : new Notification.Builder(this);
        b.setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
                .setContentTitle("Pairing " + InoAdb.getDeviceName())
                .setContentText(text)
                .setStyle(new Notification.BigTextStyle().bigText(text))
                .setOngoing(ongoing)
                .setOnlyAlertOnce(true);
        int mut = Build.VERSION.SDK_INT >= 31 ? PendingIntent.FLAG_MUTABLE : 0;
        if (withReply) {
            RemoteInput ri = new RemoteInput.Builder(KEY_CODE).setLabel("Kode 6 digit").build();
            PendingIntent pi = PendingIntent.getService(this, 1,
                    new Intent(this, InoService.class).setAction(ACTION_REPLY),
                    PendingIntent.FLAG_UPDATE_CURRENT | mut);
            b.addAction(new Notification.Action.Builder(
                    Icon.createWithResource(this, android.R.drawable.ic_menu_edit), "Masukkan kode", pi)
                    .addRemoteInput(ri).build());
        }
        PendingIntent stop = PendingIntent.getService(this, 2,
                new Intent(this, InoService.class).setAction(ACTION_STOP),
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        b.addAction(new Notification.Action.Builder(
                Icon.createWithResource(this, android.R.drawable.ic_menu_close_clear_cancel), "Berhenti", stop).build());
        return b.build();
    }

    private void startFg(Notification n) {
        if (Build.VERSION.SDK_INT >= 29)
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE);
        else
            startForeground(NOTIF_ID, n);
    }

    private void notifyNow(Notification n) {
        ((NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE)).notify(NOTIF_ID, n);
    }
}

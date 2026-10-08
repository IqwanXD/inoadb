package ru.ino.adb;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

/**
 * InoAdb: loader libadb.so + klien ADB (pair / connect / shell) tanpa androidx.
 * Nama paket bebas: cukup ubah baris "package" di atas, libadb.so TIDAK perlu di-build ulang.
 */
public final class InoAdb {

    private InoAdb() {}

    public interface Out { void line(String s); }

    private static boolean sLoaded;
    private static String sDeviceName = "SenOS";

    // ------------------------------------------------------------------ loader

    /** Muat libadb.so dari nativeLibraryDir aplikasi. */
    public static synchronized void load() {
        if (sLoaded) return;
        System.setProperty("ino.adb.class", Natives.class.getName().replace('.', '/'));
        System.loadLibrary("adb");
        sLoaded = true;
    }

    /** Muat libadb.so dari path absolut (mis. disalin ke filesDir). */
    public static synchronized void load(String absolutePath) {
        if (sLoaded) return;
        System.setProperty("ino.adb.class", Natives.class.getName().replace('.', '/'));
        System.load(absolutePath);
        sLoaded = true;
    }

    public static void setDeviceName(String name) { if (name != null && name.length() > 0) sDeviceName = name; }
    public static String getDeviceName() { return sDeviceName; }

    // ------------------------------------------------------------------ penyimpanan (agar tidak pairing ulang)

    private static SharedPreferences prefs(Context c) {
        return c.getApplicationContext().getSharedPreferences("ino_adb", Context.MODE_PRIVATE);
    }

    public static void saveEndpoint(Context c, String host, int port) {
        prefs(c).edit().putString("host", host).putInt("port", port).apply();
    }
    public static String savedHost(Context c) { return prefs(c).getString("host", null); }
    public static int savedPort(Context c) { return prefs(c).getInt("port", 0); }
    public static void saveTcpPort(Context c, int port) { prefs(c).edit().putInt("tcp_port", port).apply(); }
    public static int savedTcpPort(Context c) { return prefs(c).getInt("tcp_port", 5555); }
    public static boolean isPaired(Context c) { return prefs(c).getBoolean("paired", false); }
    static void markPaired(Context c) { prefs(c).edit().putBoolean("paired", true).apply(); }

    // ------------------------------------------------------------------ native binding

    /** Kelas ini yang didaftarkan oleh JNI_OnLoad (namanya dikirim lewat system property). */
    static final class Natives {
        static native long nativeConstructor(boolean isClient, byte[] password);
        static native byte[] nativeMsg(long ptr);
        static native boolean nativeInitCipher(long ptr, byte[] theirMsg);
        static native byte[] nativeEncrypt(long ptr, byte[] in);
        static native byte[] nativeDecrypt(long ptr, byte[] in);
        static native void nativeDestroy(long ptr);
    }

    static final class PairingContext {
        private long ptr;
        PairingContext(byte[] password) {
            ptr = Natives.nativeConstructor(true, password);
            if (ptr == 0) throw new IllegalStateException("SPAKE2 gagal dibuat");
        }
        byte[] msg() { return Natives.nativeMsg(ptr); }
        boolean initCipher(byte[] their) { return Natives.nativeInitCipher(ptr, their); }
        byte[] encrypt(byte[] in) { return Natives.nativeEncrypt(ptr, in); }
        byte[] decrypt(byte[] in) { return Natives.nativeDecrypt(ptr, in); }
        void destroy() { if (ptr != 0) { Natives.nativeDestroy(ptr); ptr = 0; } }
    }

    // ------------------------------------------------------------------ kunci RSA + sertifikat

    static final class AdbKey {
        final PrivateKey priv;
        final RSAPublicKey pub;
        final X509Certificate cert;
        private static AdbKey sCache;

        private AdbKey(PrivateKey p, RSAPublicKey u, X509Certificate c) { priv = p; pub = u; cert = c; }

        static synchronized AdbKey get(Context ctx) throws Exception {
            if (sCache != null) return sCache;
            SharedPreferences sp = prefs(ctx);
            String p = sp.getString("key_priv", null);
            String u = sp.getString("key_pub", null);
            String c = sp.getString("key_cert", null);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            if (p != null && u != null && c != null) {
                sCache = new AdbKey(
                        kf.generatePrivate(new PKCS8EncodedKeySpec(Base64.decode(p, Base64.NO_WRAP))),
                        (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(Base64.decode(u, Base64.NO_WRAP))),
                        (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64.decode(c, Base64.NO_WRAP))));
                return sCache;
            }
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(2048);
            KeyPair kp = g.generateKeyPair();
            RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
            byte[] der = makeCert(kp.getPrivate(), pub, sDeviceName);
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
            sp.edit()
                    .putString("key_priv", Base64.encodeToString(kp.getPrivate().getEncoded(), Base64.NO_WRAP))
                    .putString("key_pub", Base64.encodeToString(pub.getEncoded(), Base64.NO_WRAP))
                    .putString("key_cert", Base64.encodeToString(der, Base64.NO_WRAP))
                    .apply();
            sCache = new AdbKey(kp.getPrivate(), pub, cert);
            return sCache;
        }

        /** Format kunci publik ADB: base64(struct RSAPublicKey) + " nama" + NUL. */
        byte[] pubString() {
            BigInteger n = pub.getModulus();
            BigInteger r32 = BigInteger.ONE.shiftLeft(32);
            int n0inv = -n.mod(r32).modInverse(r32).intValue();
            BigInteger rr = BigInteger.ONE.shiftLeft(4096).mod(n);
            ByteBuffer bb = ByteBuffer.allocate(4 + 4 + 256 + 256 + 4).order(ByteOrder.LITTLE_ENDIAN);
            bb.putInt(64).putInt(n0inv).put(le(n, 256)).put(le(rr, 256)).putInt(pub.getPublicExponent().intValue());
            String s = Base64.encodeToString(bb.array(), Base64.NO_WRAP) + " " + sDeviceName + "\0";
            return s.getBytes(StandardCharsets.UTF_8);
        }

        /** Tanda tangan token AUTH (jalur TCP klasik, mis. port 5555). */
        byte[] sign(byte[] token) throws Exception {
            byte[] prefix = b(0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14);
            Signature s = Signature.getInstance("NONEwithRSA");
            s.initSign(priv);
            s.update(cat(prefix, token));
            return s.sign();
        }

        SSLContext sslContext() throws Exception {
            final PrivateKey k = priv;
            final X509Certificate cr = cert;
            SSLContext c = SSLContext.getInstance("TLSv1.3");
            c.init(new KeyManager[]{new X509KeyManager() {
                public String[] getClientAliases(String t, Principal[] i) { return new String[]{"ino"}; }
                public String chooseClientAlias(String[] t, Principal[] i, Socket s) { return "ino"; }
                public String[] getServerAliases(String t, Principal[] i) { return null; }
                public String chooseServerAlias(String t, Principal[] i, Socket s) { return null; }
                public X509Certificate[] getCertificateChain(String a) { return new X509Certificate[]{cr}; }
                public PrivateKey getPrivateKey(String a) { return k; }
            }}, new TrustManager[]{new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] c, String a) {}
                public void checkServerTrusted(X509Certificate[] c, String a) {}
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }}, new SecureRandom());
            return c;
        }
    }

    // ------------------------------------------------------------------ helper byte / DER

    private static byte[] b(int... v) {
        byte[] r = new byte[v.length];
        for (int i = 0; i < v.length; i++) r[i] = (byte) v[i];
        return r;
    }

    private static byte[] cat(byte[]... parts) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] p : parts) o.write(p, 0, p.length);
        return o.toByteArray();
    }

    private static byte[] le(BigInteger v, int len) {
        byte[] be = v.toByteArray();
        byte[] out = new byte[len];
        for (int i = 0; i < len && i < be.length; i++) out[i] = be[be.length - 1 - i];
        return out;
    }

    private static byte[] tlv(int tag, byte[]... parts) {
        byte[] body = cat(parts);
        int n = body.length;
        byte[] l = n < 128 ? b(n) : n < 256 ? b(0x81, n) : b(0x82, n >> 8, n & 0xff);
        return cat(b(tag), l, body);
    }

    /** Sertifikat X.509 self-signed minimal (tanpa BouncyCastle). */
    private static byte[] makeCert(PrivateKey priv, RSAPublicKey pub, String cn) throws Exception {
        byte[] sigAlg = tlv(0x30, b(0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B), b(0x05, 0x00));
        byte[] name = tlv(0x30, tlv(0x31, tlv(0x30, b(0x06, 0x03, 0x55, 0x04, 0x03),
                tlv(0x0C, cn.getBytes(StandardCharsets.UTF_8)))));
        SimpleDateFormat f = new SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US);
        f.setTimeZone(TimeZone.getTimeZone("UTC"));
        long now = System.currentTimeMillis();
        byte[] validity = tlv(0x30,
                tlv(0x17, f.format(new Date(now - 86400000L)).getBytes(StandardCharsets.US_ASCII)),
                tlv(0x17, f.format(new Date(now + 20L * 365L * 86400000L)).getBytes(StandardCharsets.US_ASCII)));
        byte[] tbs = tlv(0x30, tlv(0xA0, tlv(0x02, b(2))), tlv(0x02, BigInteger.valueOf(now).toByteArray()),
                sigAlg, name, validity, name, pub.getEncoded());
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(priv);
        s.update(tbs);
        return tlv(0x30, tbs, sigAlg, tlv(0x03, b(0), s.sign()));
    }

    // ------------------------------------------------------------------ PAIR

    public static void pair(Context ctx, String host, int port, String code, Out out) throws Exception {
        load();
        AdbKey key = AdbKey.get(ctx);
        Socket raw = new Socket();
        raw.connect(new InetSocketAddress(host, port), 8000);
        raw.setSoTimeout(15000);
        SSLSocket ssl = (SSLSocket) key.sslContext().getSocketFactory().createSocket(raw, host, port, true);
        PairingContext pc = null;
        try {
            ssl.startHandshake();
            out.line("info: tls handshake ok");
            byte[] km = exportKeyingMaterial(ssl, "adb-label\u0000", 64);
            byte[] pwd = cat(code.getBytes(StandardCharsets.UTF_8), km);

            DataInputStream in = new DataInputStream(ssl.getInputStream());
            OutputStream os = ssl.getOutputStream();
            pc = new PairingContext(pwd);

            writePacket(os, 0, pc.msg());                       // SPAKE2_MSG
            byte[] their = readPacket(in, 0);
            if (!pc.initCipher(their)) throw new IOException("SPAKE2 gagal (kode salah?)");
            out.line("info: spake2 ok");

            byte[] pi = new byte[8192];                         // PeerInfo: type(1) + data(8191)
            byte[] ks = key.pubString();
            pi[0] = 0;                                          // ADB_RSA_PUB_KEY
            System.arraycopy(ks, 0, pi, 1, Math.min(ks.length, 8191));
            byte[] enc = pc.encrypt(pi);
            if (enc == null) throw new IOException("encrypt peer info gagal");
            writePacket(os, 1, enc);                            // PEER_INFO

            byte[] peerEnc = readPacket(in, 1);
            byte[] peer = pc.decrypt(peerEnc);
            if (peer == null) throw new IOException("kode pairing salah");
            out.line("info: peer info ok");
            markPaired(ctx);
        } finally {
            if (pc != null) pc.destroy();
            try { ssl.close(); } catch (IOException ignored) {}
        }
    }

    private static void writePacket(OutputStream os, int type, byte[] payload) throws IOException {
        ByteBuffer bb = ByteBuffer.allocate(6 + payload.length);
        bb.put((byte) 1).put((byte) type).putInt(payload.length).put(payload);
        os.write(bb.array());
        os.flush();
    }

    private static byte[] readPacket(DataInputStream in, int expectType) throws IOException {
        byte[] h = new byte[6];
        in.readFully(h);
        int version = h[0] & 0xff, type = h[1] & 0xff;
        int len = ByteBuffer.wrap(h, 2, 4).getInt();
        if (version != 1) throw new IOException("versi paket " + version);
        if (type != expectType) throw new IOException("tipe paket " + type);
        if (len <= 0 || len > 16384) throw new IOException("ukuran paket " + len);
        byte[] p = new byte[len];
        in.readFully(p);
        return p;
    }

    private static byte[] exportKeyingMaterial(SSLSocket s, String label, int n) throws Exception {
        String[] names = {"com.android.org.conscrypt.Conscrypt", "org.conscrypt.Conscrypt"};
        for (String cn : names) {
            try {
                Method m = Class.forName(cn).getMethod("exportKeyingMaterial",
                        SSLSocket.class, String.class, byte[].class, int.class);
                return (byte[]) m.invoke(null, s, label, null, n);
            } catch (Throwable ignored) {}
        }
        try {
            Method m = s.getClass().getMethod("exportKeyingMaterial", String.class, byte[].class, int.class);
            m.setAccessible(true);
            return (byte[]) m.invoke(s, label, null, n);
        } catch (Throwable ignored) {}
        throw new IOException("exportKeyingMaterial tidak tersedia (cek hidden API / bundel conscrypt-android)");
    }

    // ------------------------------------------------------------------ CONNECT + SHELL

    public static final class Client implements Closeable {
        static final int A_CNXN = 0x4e584e43, A_AUTH = 0x48545541, A_OPEN = 0x4e45504f,
                A_OKAY = 0x59414b4f, A_CLSE = 0x45534c43, A_WRTE = 0x45545257, A_STLS = 0x534c5453;
        static final int VERSION = 0x01000000, MAX_DATA = 4096;

        private Socket socket;
        private InputStream in;
        private OutputStream os;

        private static final class Msg { int cmd, arg0, arg1; byte[] data; }

        /** host:port = alamat wireless debugging (TLS) atau TCP 5555 (AUTH klasik). */
        public static Client connect(Context ctx, String host, int port, Out out) throws Exception {
            load();
            AdbKey key = AdbKey.get(ctx);
            Client c = new Client();
            try {
                c.socket = new Socket();
                c.socket.setTcpNoDelay(true);
                c.socket.connect(new InetSocketAddress(host, port), 5000);
                c.socket.setSoTimeout(30000);
                c.in = c.socket.getInputStream();
                c.os = c.socket.getOutputStream();

                c.write(A_CNXN, VERSION, MAX_DATA, "host::\0".getBytes(StandardCharsets.UTF_8));
                Msg m = c.read();
                if (m.cmd == A_STLS) {
                    out.line("info: server minta TLS");
                    c.write(A_STLS, VERSION, 0, null);
                    SSLSocket ssl = (SSLSocket) key.sslContext().getSocketFactory()
                            .createSocket(c.socket, host, port, true);
                    ssl.startHandshake();
                    c.socket = ssl;
                    c.in = ssl.getInputStream();
                    c.os = ssl.getOutputStream();
                    m = c.read();
                } else if (m.cmd == A_AUTH && m.arg0 == 1) {
                    out.line("info: auth token");
                    c.write(A_AUTH, 2, 0, key.sign(m.data));
                    m = c.read();
                    if (m.cmd == A_AUTH) {
                        out.line("info: kirim kunci publik (izinkan di dialog USB debugging)");
                        c.write(A_AUTH, 3, 0, key.pubString());
                        m = c.read();
                    }
                }
                if (m.cmd != A_CNXN) throw new IOException("handshake ADB gagal (cmd=0x" + Integer.toHexString(m.cmd) + ")");
                return c;
            } catch (Exception e) {
                c.close();
                throw e;
            }
        }

        /** Jalankan "shell:<cmd>" lalu kembalikan outputnya. */
        public String shell(String cmd) throws IOException { return exec("shell:" + cmd); }

        /** Layanan ADB apa pun, mis. "tcpip:5555". */
        public String exec(String service) throws IOException {
            final int local = 1;
            write(A_OPEN, local, 0, (service + "\0").getBytes(StandardCharsets.UTF_8));
            Msg m = read();
            while (m.cmd != A_OKAY && m.cmd != A_CLSE) m = read();
            if (m.cmd == A_CLSE) throw new IOException("layanan ditolak: " + service);
            int remote = m.arg0;
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            while (true) {
                m = read();
                if (m.cmd == A_WRTE) {
                    bo.write(m.data, 0, m.data.length);
                    write(A_OKAY, local, remote, null);
                } else if (m.cmd == A_CLSE) {
                    break;
                }
            }
            return new String(bo.toByteArray(), StandardCharsets.UTF_8);
        }

        private void write(int cmd, int a0, int a1, byte[] data) throws IOException {
            byte[] d = data == null ? new byte[0] : data;
            int sum = 0;
            for (byte x : d) sum += (x & 0xff);
            ByteBuffer bb = ByteBuffer.allocate(24 + d.length).order(ByteOrder.LITTLE_ENDIAN);
            bb.putInt(cmd).putInt(a0).putInt(a1).putInt(d.length).putInt(sum).putInt(~cmd).put(d);
            os.write(bb.array());
            os.flush();
        }

        private Msg read() throws IOException {
            ByteBuffer h = ByteBuffer.wrap(readFully(24)).order(ByteOrder.LITTLE_ENDIAN);
            Msg m = new Msg();
            m.cmd = h.getInt();
            m.arg0 = h.getInt();
            m.arg1 = h.getInt();
            int len = h.getInt();
            h.getInt();
            int magic = h.getInt();
            if (magic != ~m.cmd) throw new IOException("magic paket salah");
            if (len < 0 || len > (1 << 20)) throw new IOException("ukuran data " + len);
            m.data = readFully(len);
            return m;
        }

        private byte[] readFully(int n) throws IOException {
            byte[] r = new byte[n];
            int o = 0;
            while (o < n) {
                int k = in.read(r, o, n - o);
                if (k < 0) throw new IOException("koneksi ditutup");
                o += k;
            }
            return r;
        }

        @Override public void close() {
            try { if (socket != null) socket.close(); } catch (IOException ignored) {}
        }
    }
}

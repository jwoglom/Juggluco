package tk.glucodata;

import android.app.Activity;
import android.content.Context;
import android.net.Uri;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Opt-in build instrumentation. Never supplies keys or changes crypto results. */
public final class LingoDiagnostics {
    private LingoDiagnostics() {}
    private static final long EVENT_LIMIT = 8L << 20;
    private static final long IMAGE_LIMIT = 64L << 20;
    private static final long TRACE_LIMIT = 16L << 20;
    private static final Object LOCK = new Object();
    private static final AtomicLong ids = new AtomicLong();
    private static final AtomicBoolean fresh = new AtomicBoolean();
    private static final ExecutorService worker = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "LingoDiagnostics"); t.setDaemon(true); return t;
    });
    private static File root, run, events;
    private static long sequence;
    private static long vendorBytes;
    private static boolean vendorCapped;
    private static boolean capped, readyImage, fullImage, resumedImage;
    private static final Set<String> beforeMaps = new HashSet<>();

    public static boolean enabled() { return Log.doLog && BuildConfig.lingoDiagnostics == 1; }

    public static void start(Context context) {
        if (!enabled()) return;
        try {
            synchronized (LOCK) {
                if (run != null) return;
                root = new File(context.getFilesDir(), "lingo-diagnostics");
                if (!root.isDirectory() && !root.mkdirs()) throw new IOException("mkdir " + root);
                File[] old = root.listFiles(f -> f.isDirectory() && f.getName().matches("run-[0-9]+-[0-9]+"));
                if (old != null) {
                    Arrays.sort(old, Comparator.comparing(File::getName).reversed());
                    for (int i = 1; i < old.length; i++) remove(old[i]);
                }
                File next = new File(root, "run-" + System.currentTimeMillis() + "-" + android.os.Process.myPid());
                if (!next.mkdirs()) throw new IOException("mkdir " + next);
                events = new File(next, "events.jsonl");
                run = next;
                try {
                    String maps = readMaps();
                    for (String line : maps.split("\n")) beforeMaps.add(line);
                    write(new File(run, "maps-before-lingo.txt"), maps);
                } catch (Throwable e) { event("", "maps_unavailable", "error", e.toString()); }
                event("", "environment", "schema", 1, "applicationId", BuildConfig.APPLICATION_ID,
                        "version", BuildConfig.VERSION_NAME, "sdk", Build.VERSION.SDK_INT,
                        "android", Build.VERSION.RELEASE, "manufacturer", Build.MANUFACTURER,
                        "model", Build.MODEL, "abis", Build.SUPPORTED_ABIS,
                        "limits", "8 MiB events; three 64 MiB image snapshots; two process runs retained",
                        "memoryNote", "Best-effort non-atomic process memory; no general heap dump");
            }
        } catch (Throwable e) { android.util.Log.e("LingoDiagnostics", "start", e); }
    }

    public static String newContext(String serial) {
        String id = "skb-" + ids.incrementAndGet();
        event(id, "context", "sensorSerial", serial);
        return id;
    }

    public static long callStart(String context, String method, Object[] args) {
        long id = ids.incrementAndGet();
        event(context, "call_start", "call", id, "method", method, "args", args);
        return id;
    }

    public static void callEnd(String context, long id, String method, Object result,
                               Object[] args, long elapsedNs, Throwable error) {
        event(context, "call_end", "call", id, "method", method, "result", result,
                "argsAfter", args, "durationNs", elapsedNs, "error", error == null ? null : error.toString());
    }

    public static void event(String context, String kind, Object... pairs) {
        if (!enabled()) return;
        try {
            synchronized (LOCK) {
                if (events == null || capped) return;
                JSONObject obj = new JSONObject();
                obj.put("schema", 1); obj.put("seq", ++sequence);
                obj.put("timeMs", System.currentTimeMillis());
                obj.put("elapsedMs", SystemClock.elapsedRealtime());
                obj.put("thread", Thread.currentThread().getName());
                obj.put("context", context); obj.put("event", kind);
                for (int i = 0; i + 1 < pairs.length; i += 2)
                    obj.put(String.valueOf(pairs[i]), value(pairs[i + 1], 0));
                byte[] data = (obj + "\n").getBytes(StandardCharsets.UTF_8);
                if (events.length() + data.length > EVENT_LIMIT) {
                    capped = true;
                    data = "{\"schema\":1,\"event\":\"capture_limit\",\"limitBytes\":8388608}\n".getBytes(StandardCharsets.UTF_8);
                }
                try (FileOutputStream out = new FileOutputStream(events, true)) { out.write(data); }
            }
        } catch (Throwable e) { android.util.Log.e("LingoDiagnostics", "event", e); }
    }

    // Reflect only fields of the supplied Abbott object/class, never invoke its
    // getters, getEncoded(), or additional native crypto operations.
    public static void fields(String context, String stage, Class<?> cls, Object instance) {
        if (!enabled()) return;
        try {
            JSONObject data = new JSONObject();
            Field[] fields = cls.getDeclaredFields();
            Arrays.sort(fields, Comparator.comparing(Field::getName));
            for (Field f : fields) {
                if (f.isSynthetic() || (instance == null && !Modifier.isStatic(f.getModifiers()))) continue;
                try {
                    f.setAccessible(true);
                    Object v = f.get(Modifier.isStatic(f.getModifiers()) ? null : instance);
                    data.put(f.getName(), value(v, 0));
                    if (v != null && v.getClass().getName().equals(
                            "com.adc.dcm.gksensor.security.GKSSKBCryptoLib$TokenHandler"))
                        fields(context, stage + "." + f.getName(), v.getClass(), v);
                } catch (Throwable e) { data.put(f.getName(), "UNAVAILABLE: " + e); }
            }
            event(context, "fields", "stage", stage, "class", cls.getName(), "fields", data);
        } catch (Throwable e) { event(context, "diagnostic_error", "stage", stage, "error", e.toString()); }
    }

    private static Object value(Object v, int depth) throws Exception {
        if (v == null) return JSONObject.NULL;
        if (v instanceof JSONObject || v instanceof JSONArray || v instanceof Boolean || v instanceof Number) return v;
        if (v instanceof String) {
            String s = (String) v;
            return s.length() <= 65536 ? s : s.substring(0, 65536) + " [TRUNCATED]";
        }
        if (v instanceof byte[]) {
            byte[] b = (byte[]) v;
            JSONObject o = new JSONObject(); o.put("length", b.length);
            int len = Math.min(b.length, 1 << 20);
            o.put("hex", hex(b, len)); o.put("truncated", len != b.length);
            o.put("sha256", hex(MessageDigest.getInstance("SHA-256").digest(b), 32));
            return o;
        }
        if (depth < 4 && v.getClass().isArray()) {
            JSONArray a = new JSONArray(); int len = Array.getLength(v);
            for (int i = 0; i < Math.min(len, 256); i++) a.put(value(Array.get(v, i), depth + 1));
            if (len > 256) a.put("TRUNCATED: total " + len);
            return a;
        }
        if (depth < 4 && v instanceof Map) {
            JSONObject o = new JSONObject(); int n = 0;
            for (Object entry : ((Map<?, ?>) v).entrySet()) {
                Map.Entry<?, ?> e = (Map.Entry<?, ?>) entry;
                if (++n > 256) { o.put("TRUNCATED", true); break; }
                o.put(String.valueOf(e.getKey()), value(e.getValue(), depth + 1));
            }
            return o;
        }
        // Do not call arbitrary toString() implementations inside SKB objects.
        JSONObject o = new JSONObject(); o.put("class", v.getClass().getName()); return o;
    }

    public static void vendorLog(String level, String tag, String message) {
        if (!enabled()) return;
        synchronized (LOCK) {
            if (run == null || vendorCapped) return;
            vendorBytes += 2L * ((tag == null ? 0 : tag.length()) + (message == null ? 0 : message.length()));
            if (vendorBytes > (512L << 10)) {
                vendorCapped = true;
                event("vendor", "vendor_log_limit", "limitBytes", 512L << 10);
                return;
            }
        }
        event("vendor", "vendor_log", "level", level, "tag", tag, "message", message);
    }

    public static void requestFresh(Context context) {
        start(context); fresh.set(true);
        event("", "fresh_requested");
        Toast.makeText(context, "Next Lingo connection: full authentication. Turn Use Bluetooth off and on.", Toast.LENGTH_LONG).show();
    }

    public static boolean consumeFresh(String serial) {
        if (!enabled() || !fresh.compareAndSet(true, false)) return false;
        event("", "fresh_consumed", "sensorSerial", serial);
        return true;
    }

    public static void loaded(String context, String dexPath, String nativeDir) {
        if (!enabled()) return;
        try {
        worker.execute(() -> {
            fingerprint(context, new File(dexPath));
            for (String name : new String[]{"libgksdcm.so", "libSecureKeyBoxJava.so", "libgks_skbwrapper.so", "libc++_shared.so"})
                fingerprint(context, new File(nativeDir, name));
        });
        snapshot(context, "ready");
        } catch (Throwable e) { event(context, "diagnostic_error", "stage", "loaded", "error", e.toString()); }
    }

    private static void fingerprint(String context, File f) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            try (InputStream in = new FileInputStream(f)) {
                byte[] b = new byte[65536]; int n;
                while ((n = in.read(b)) != -1) sha.update(b, 0, n);
            }
            event(context, "fingerprint", "file", f.getName(), "length", f.length(), "sha256", hex(sha.digest(), 32));
        } catch (Throwable e) { event(context, "fingerprint_error", "file", f.getName(), "error", e.toString()); }
    }

    public static void snapshot(String context, String stage) {
        if (!enabled()) return;
        try {
        synchronized (LOCK) {
            if (run == null) return;
            if (stage.equals("ready")) { if (readyImage) return; readyImage = true; }
            else if (stage.equals("full-authenticated")) { if (fullImage) return; fullImage = true; }
            else if (stage.equals("resumed-authenticated")) { if (resumedImage) return; resumedImage = true; }
            else return;
        }
        worker.execute(() -> captureImage(context, stage));
        } catch (Throwable e) { event(context, "diagnostic_error", "stage", stage, "error", e.toString()); }
    }

    private static boolean vendorMap(String name) {
        return name.contains("libgksdcm.so") || name.contains("libgks_skbwrapper.so") || name.contains("libSecureKeyBoxJava.so");
    }

    private static void captureImage(String context, String stage) {
        try {
            File dir = new File(run, "memory-" + stage);
            if (!dir.mkdirs()) throw new IOException("mkdir " + dir);
            String maps = readMaps(); write(new File(dir, "maps.txt"), maps);
            event(context, "memory_start", "stage", stage);
            JSONArray index = new JSONArray(); long total = 0, previousEnd = -1; boolean previousVendor = false;
            try (RandomAccessFile mem = new RandomAccessFile("/proc/self/mem", "r")) {
                byte[] buffer = new byte[65536]; int number = 0;
                for (String line : maps.split("\n")) {
                    String[] p = line.trim().split("\\s+", 6);
                    if (p.length < 5) continue;
                    String[] range = p[0].split("-");
                    long start, end;
                    try { start = Long.parseLong(range[0], 16); end = Long.parseLong(range[1], 16); }
                    catch (NumberFormatException ignored) { previousVendor = false; continue; }
                    String name = p.length == 6 ? p[5] : "";
                    boolean anonymous = name.isEmpty() || name.startsWith("[anon:");
                    boolean own = vendorMap(name);
                    boolean possibleBss = previousVendor && start == previousEnd && end - start <= (4L << 20)
                            && (name.isEmpty() || name.equals("[anon:.bss]")) && p[1].startsWith("rw");
                    previousVendor = own; previousEnd = end;
                    boolean newExecutable = anonymous && p[1].contains("x") && !beforeMaps.contains(line)
                            && !name.contains("jit") && !name.contains("dalvik");
                    if (!p[1].startsWith("r") || (!own && !possibleBss && !newExecutable)) continue;
                    JSONObject row = new JSONObject(); row.put("mapping", line);
                    row.put("reason", own ? "vendor" : possibleBss ? "possible_adjacent_vendor_bss" : "new_anonymous_executable");
                    index.put(row);
                    long length = end - start;
                    if (length <= 0 || total + length > IMAGE_LIMIT) { row.put("error", "snapshot byte limit"); continue; }
                    total += length;
                    String filename = String.format(Locale.ROOT, "%03d-%s.bin", ++number, p[0]);
                    File outFile = new File(dir, filename); long written = 0;
                    try (OutputStream out = new FileOutputStream(outFile)) {
                        mem.seek(start);
                        while (written < length) {
                            int n = mem.read(buffer, 0, (int) Math.min(buffer.length, length - written));
                            if (n < 0) throw new EOFException();
                            out.write(buffer, 0, n); written += n;
                        }
                    } catch (Throwable e) { row.put("error", e.toString()); }
                    row.put("file", filename); row.put("bytes", written);
                }
            } catch (Throwable e) { event(context, "memory_unavailable", "stage", stage, "error", e.toString()); }
            write(new File(dir, "index.json"), index.toString(2));
            event(context, "memory_end", "stage", stage, "selectedBytes", total, "mappings", index.length());
        } catch (Throwable e) { event(context, "diagnostic_error", "stage", stage, "error", e.toString()); }
    }

    public static void export(Activity activity, Uri uri) {
        if (!enabled()) return;
        start(activity);
        worker.execute(() -> {
            String message;
            try {
                if (run == null) throw new IOException("Diagnostic storage unavailable");
                event("", "export_requested");
                File trace = new File(run, "trace.log");
                if (Natives.getLogfilesize() <= TRACE_LIMIT) {
                    try (ParcelFileDescriptor fd = ParcelFileDescriptor.open(trace,
                            ParcelFileDescriptor.MODE_CREATE | ParcelFileDescriptor.MODE_TRUNCATE | ParcelFileDescriptor.MODE_WRITE_ONLY)) {
                        Natives.saveLog(fd.detachFd()); // Native saveLog owns and closes the detached fd.
                    }
                } else {
                    trace.delete();
                    event("", "trace_omitted", "reason", "trace exceeds 16 MiB; use normal Save trace.log if needed");
                }
                File snapshot = new File(run, "events-export.jsonl");
                synchronized (LOCK) { if (events.exists()) copy(events, snapshot); }
                write(new File(run, "README.txt"), "Lingo diagnostic capture schema 1\n"
                        + "Current run uses events-export.jsonl; earlier runs use events.jsonl.\n"
                        + "Secrets, sensor identifiers and glucose readings are included. Share privately with the developer.\n"
                        + "Calls are observed at Juggluco's Abbott wrapper boundary, not every internal process1/process2 call.\n"
                        + "Private-key table entries may remain wrapped. Memory images are best-effort, non-atomic, ASLR-addressed.\n"
                        + "A memory_unavailable event does not invalidate the Java credentials or call vectors.\n"
                        + "No arbitrary heap, other app storage, or extra crypto operations are captured.\n");
                try (OutputStream raw = activity.getContentResolver().openOutputStream(uri, "wt")) {
                    if (raw == null) throw new IOException("Cannot open output");
                    try (ZipOutputStream zip = new ZipOutputStream(new BufferedOutputStream(raw))) {
                        File[] dirs = root.listFiles(f -> f.isDirectory() && f.getName().startsWith("run-"));
                        if (dirs != null) for (File dir : dirs) zipTree(zip, dir, dir.getName() + "/", dir.equals(run));
                    }
                }
                message = "Saved Lingo diagnostics";
            } catch (Throwable e) {
                event("", "export_failed", "error", e.toString());
                message = "Lingo diagnostics not saved: " + e.getClass().getSimpleName();
            }
            String result = message;
            activity.runOnUiThread(() -> Toast.makeText(activity, result, Toast.LENGTH_LONG).show());
        });
    }

    private static void zipTree(ZipOutputStream zip, File dir, String prefix, boolean current) throws IOException {
        File[] files = dir.listFiles(); if (files == null) return;
        Arrays.sort(files, Comparator.comparing(File::getName));
        byte[] buffer = new byte[65536];
        for (File f : files) {
            if (current && f.getName().equals("events.jsonl")) continue;
            if (!current && f.getName().equals("events-export.jsonl")) continue;
            if (f.isDirectory()) { zipTree(zip, f, prefix + f.getName() + "/", current); continue; }
            zip.putNextEntry(new ZipEntry(prefix + f.getName()));
            try (InputStream in = new FileInputStream(f)) { int n; while ((n = in.read(buffer)) != -1) zip.write(buffer, 0, n); }
            zip.closeEntry();
        }
    }

    private static String hex(byte[] bytes, int len) {
        char[] out = new char[len * 2], alphabet = "0123456789abcdef".toCharArray();
        for (int i = 0; i < len; i++) { int b = bytes[i] & 255; out[i * 2] = alphabet[b >>> 4]; out[i * 2 + 1] = alphabet[b & 15]; }
        return new String(out);
    }
    private static String readMaps() throws IOException {
        try (InputStream in = new FileInputStream("/proc/self/maps"); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] b = new byte[8192]; int n;
            while ((n = in.read(b)) != -1) { if (out.size() + n > (2 << 20)) throw new IOException("maps too large"); out.write(b, 0, n); }
            return out.toString("UTF-8");
        }
    }
    private static void write(File file, String text) throws IOException {
        try (OutputStream out = new FileOutputStream(file)) { out.write(text.getBytes(StandardCharsets.UTF_8)); }
    }
    private static void copy(File source, File dest) throws IOException {
        try (InputStream in = new FileInputStream(source); OutputStream out = new FileOutputStream(dest)) {
            byte[] b = new byte[65536]; int n; while ((n = in.read(b)) != -1) out.write(b, 0, n);
        }
    }
    private static void remove(File file) {
        if (file.isDirectory()) { File[] children = file.listFiles(); if (children != null) for (File f : children) remove(f); }
        file.delete();
    }
}

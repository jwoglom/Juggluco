/*      This file is part of Juggluco, an Android app to receive and display         */
/*      glucose values from Freestyle Libre 2 and 3 sensors.                         */
/*                                                                                   */
/*      Copyright (C) 2021 Jaap Korthals Altes <jaapkorthalsaltes@gmail.com>         */
/*                                                                                   */
/*      Juggluco is free software: you can redistribute it and/or modify             */
/*      it under the terms of the GNU General Public License as published            */
/*      by the Free Software Foundation, either version 3 of the License, or          */
/*      (at your option) any later version.                                          */
/*                                                                                   */
/*      Juggluco is distributed in the hope that it will be useful, but              */
/*      WITHOUT ANY WARRANTY; without even the implied warranty of                   */
/*      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                         */
/*      See the GNU General Public License for more details.                         */
/*                                                                                   */
/*      You should have received a copy of the GNU General Public License            */
/*      along with Juggluco. If not, see <https://www.gnu.org/licenses/>.            */

package tk.glucodata;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

import dalvik.system.DexClassLoader;

/*
 * Bridge to Abbott's SecureKeyBox (SKB) white-box for Abbott Lingo pairing.
 *
 * Lingo uses the GKS / FreeStyle Libre 3 stack with different credentials.
 * An independent Lingo authentication implementation is not yet established.
 * This bridge drives Abbott's own SKB libraries, the same way Juggluco uses Abbott's
 * libcalibrate.so for Libre calibration.
 *
 * The three SKB libraries (libgks_skbwrapper.so, libSecureKeyBoxJava.so,
 * libgksdcm.so) are bundled in the libre3 flavor's jniLibs (fetched at build
 * time from the private repository; never committed). The GKS Java classes the
 * libraries bind their natives to are loaded from a supplied dex through a
 * DexClassLoader whose parent is this class's loader, so:
 *   - android.* and the no-op com.adc.dcs.core.MSLog (shipped in this flavor)
 *     resolve to Juggluco's copies via parent delegation, and
 *   - the SKB's only Java up-call (MSLog logging) becomes harmless.
 *
 * Only GKSSKBCryptoLib's authentication operations are used; they all take and
 * return byte[]/int, so this bridge needs no compile-time dependency on the GKS
 * classes and no BouncyCastle. The post-authentication data plane is handled by
 * Juggluco's existing AES-CCM code (initcrypt / intDecrypt), which is byte-for-
 * byte the same construction as the sensor's.
 *
 * All operations are reflective and every failure is reported as false/null (and
 * logged), so a build without the SKB present simply cannot construct a LingoSKB
 * and the Lingo path stays inert.
 */
class LingoSKB {
    private static final String LOG_ID = "LingoSKB";
    private static final String PKG = "com.adc.dcm.gksensor.security.";

    /** Name of the bundled dex jar (libre3 asset, fetched at build time). */
    private static final String DEX_ASSET = "lingogks.jar";

    /**
     * Build a LingoSKB using the bundled GKS classes dex and the SecureKeyBox
     * libraries shipped in this app. Returns null (logging why) if the SKB is
     * not present in this build or fails to initialise, so callers can fall back.
     */
    static LingoSKB create(Context context, String serial) {
        LingoDiagnostics.start(context);
        String diagnosticContext = LingoDiagnostics.newContext(serial);
        try {
            final File jar = new File(context.getCodeCacheDir(), DEX_ASSET);
            copyAssetIfNeeded(context, DEX_ASSET, jar);
            final String optimizedDir = context.getCodeCacheDir().getAbsolutePath();
            final String nativeLibDir = context.getApplicationInfo().nativeLibraryDir;
            return new LingoSKB(jar.getAbsolutePath(), optimizedDir, nativeLibDir, diagnosticContext);
        } catch (Throwable e) {
            LingoDiagnostics.event(diagnosticContext, "create_failed", "error", e.toString());
            Log.e(LOG_ID, "create failed (Lingo SecureKeyBox unavailable): " + e);
            return null;
        }
    }

    private static synchronized void copyAssetIfNeeded(Context context, String asset, File out)
            throws Exception {
        // Recreate the bundled code once per process, including after upgrades.
        // Android 14+ requires dynamically loaded code to be read-only.
        if (assetCopied && out.exists()) return;
        if (out.exists() && !out.delete()) throw new java.io.IOException("Cannot replace " + out);
        try (InputStream in = context.getAssets().open(asset);
             OutputStream os = new FileOutputStream(out)) {
            if (!out.setReadOnly()) throw new java.io.IOException("Cannot make dex read-only");
            final byte[] buf = new byte[1 << 16];
            int n;
            while ((n = in.read(buf)) > 0) os.write(buf, 0, n);
        }
        assetCopied = true;
    }
    private static boolean assetCopied;

    private final String diagnosticContext;
    private int realtimeSamples;
    private boolean fullAuthentication;
    private final Class<?> credentialsClass;
    private final Object crypto;                 // GKSSKBCryptoLib instance
    private final Method mGetAppCertificate;
    private final Method mInitECDH;              // (byte[] savedAuthorization, int securityVersion)
    private final Method mSetPatchCertificate;   // (byte[] patchCertificate)
    private final Method mGenerateEphemeralKeys; // () -> app ephemeral public key
    private final Method mGenerateKAuth;         // (byte[] patchEphemeralPublicKey)
    private final Method mEncrypt;               // (byte[] nonce, byte[] plaintext)
    private final Method mDecrypt;               // (byte[] nonce, byte[] ciphertext)
    private final Method mExportAuthorizationKey;
    private final Method mGetKeyIndexFromVersion;// (int) — private

    /**
     * @param dexPath        path to a dex/apk holding the GKS security classes
     * @param optimizedDir   writable directory for the DexClassLoader (e.g. code_cache)
     * @param nativeLibDir   directory holding the SKB .so (the app's nativeLibraryDir)
     * @throws Exception if the SKB or its classes are unavailable / fail to init
     */
    LingoSKB(String dexPath, String optimizedDir, String nativeLibDir, String diagnosticContext) throws Exception {
        this.diagnosticContext = diagnosticContext;
        final ClassLoader parent = LingoSKB.class.getClassLoader();

        // Load our no-op MSLog in the parent loader so it shadows the Lingo dex's
        // (null EventBus) when the SKB natives up-call it; also keeps R8 off it.
        com.adc.dcs.core.MSLog.i(LOG_ID, "init");

        final DexClassLoader loader =
                new DexClassLoader(dexPath, optimizedDir, nativeLibDir, parent);

        // Initialising GKSSecurityCredentials runs the self-decrypting loader and
        // $gksdcm$COI(), which loads the .so and fills the key table.
        credentialsClass = Class.forName(PKG + "GKSSecurityCredentials", true, loader);
        LingoDiagnostics.fields(diagnosticContext, "credentials_initialized", credentialsClass, null);

        final Class<?> skbCls = Class.forName(PKG + "GKSSKBCryptoLib", true, loader);
        final Constructor<?> ctor = skbCls.getDeclaredConstructor();
        ctor.setAccessible(true);
        crypto = ctor.newInstance();

        mGetAppCertificate     = skbCls.getMethod("getAppCertificate");
        mInitECDH              = skbCls.getMethod("initECDH", byte[].class, int.class);
        mSetPatchCertificate   = skbCls.getMethod("setPatchCertificate", byte[].class);
        mGenerateEphemeralKeys = skbCls.getMethod("generateEphemeralKeys");
        mGenerateKAuth         = skbCls.getMethod("generateKAuth", byte[].class);
        mEncrypt               = skbCls.getMethod("encrypt", byte[].class, byte[].class);
        mDecrypt               = skbCls.getMethod("decrypt", byte[].class, byte[].class);
        mExportAuthorizationKey= skbCls.getMethod("exportAuthorizationKey");
        mGetKeyIndexFromVersion= skbCls.getDeclaredMethod("getKeyIndexFromVersion", int.class);
        mGetKeyIndexFromVersion.setAccessible(true);

        LingoDiagnostics.fields(diagnosticContext, "crypto_constructed", skbCls, crypto);
        LingoDiagnostics.loaded(diagnosticContext, dexPath, nativeLibDir);
        info(LOG_ID + ": SecureKeyBox ready");
    }

    /** The securityVersion->key-index map inside the white-box; -1 on error. */
    int getKeyIndexFromVersion(int securityVersion) {
        try {
            return (Integer) invoke(mGetKeyIndexFromVersion, securityVersion);
        } catch (Throwable e) { err("getKeyIndexFromVersion", e); return -1; }
    }

    /** Begin ECDH for the given securityVersion; savedAuthorization may be null. */
    boolean initECDH(byte[] savedAuthorization, int securityVersion) {
        try {
            return (Boolean) invoke(mInitECDH, savedAuthorization, securityVersion);
        } catch (Throwable e) { err("initECDH", e); return false; }
    }

    /** The 162-byte app certificate to send to the sensor; null on error. */
    byte[] getAppCertificate() {
        try { return (byte[]) invoke(mGetAppCertificate); }
        catch (Throwable e) { err("getAppCertificate", e); return null; }
    }

    /** Accept and verify the sensor's (patch) certificate. */
    boolean setPatchCertificate(byte[] patchCertificate) {
        try { return (Boolean) invoke(mSetPatchCertificate, (Object) patchCertificate); }
        catch (Throwable e) { err("setPatchCertificate", e); return false; }
    }

    /** Generate the app ephemeral key pair and return its public key; null on error. */
    byte[] generateEphemeralKeys() {
        try { return (byte[]) invoke(mGenerateEphemeralKeys); }
        catch (Throwable e) { err("generateEphemeralKeys", e); return null; }
    }

    /** Complete ECDH with the sensor's ephemeral public key, deriving kAuth. */
    boolean generateKAuth(byte[] patchEphemeralPublicKey) {
        try { return (Boolean) invoke(mGenerateKAuth, (Object) patchEphemeralPublicKey); }
        catch (Throwable e) { err("generateKAuth", e); return false; }
    }

    /** AES-CCM encrypt the authorization challenge reply; null on error. */
    byte[] encrypt(byte[] nonce, byte[] plaintext) {
        try { return (byte[]) invoke(mEncrypt, nonce, plaintext); }
        catch (Throwable e) { err("encrypt", e); return null; }
    }

    /** AES-CCM decrypt the authorization challenge response; null on error. */
    byte[] decrypt(byte[] nonce, byte[] ciphertext) {
        try { return (byte[]) invoke(mDecrypt, nonce, ciphertext); }
        catch (Throwable e) { err("decrypt", e); return null; }
    }

    /** The persistent fast-reconnect blob (kAuth); null on error. */
    byte[] exportAuthorizationKey() {
        try { return (byte[]) invoke(mExportAuthorizationKey); }
        catch (Throwable e) { err("exportAuthorizationKey", e); return null; }
    }

    private Object invoke(Method method, Object... args) throws Throwable {
        if (!LingoDiagnostics.enabled()) return method.invoke(crypto, args);
        long call = LingoDiagnostics.callStart(diagnosticContext, method.getName(), args);
        long started = android.os.SystemClock.elapsedRealtimeNanos();
        Object result = null;
        Throwable error = null;
        try {
            result = method.invoke(crypto, args);
            return result;
        } catch (Throwable e) {
            error = e instanceof java.lang.reflect.InvocationTargetException && e.getCause() != null ? e.getCause() : e;
            throw e;
        } finally {
            LingoDiagnostics.callEnd(diagnosticContext, call, method.getName(), result, args,
                    android.os.SystemClock.elapsedRealtimeNanos() - started, error);
            if (method == mInitECDH) {
                realtimeSamples = 0;
                fullAuthentication = args.length > 0 && args[0] == null;
                LingoDiagnostics.fields(diagnosticContext, "credentials_after_initECDH", credentialsClass, null);
            }
            if (method == mInitECDH || method == mGenerateKAuth || method == mExportAuthorizationKey)
                LingoDiagnostics.fields(diagnosticContext, method.getName(), crypto.getClass(), crypto);
            if (method == mExportAuthorizationKey && result instanceof byte[])
                LingoDiagnostics.snapshot(diagnosticContext, fullAuthentication ? "full-authenticated" : "resumed-authenticated");
        }
    }

    void recordRealtime(byte[] encrypted, byte[] clear, long timeMs) {
        if (LingoDiagnostics.enabled() && realtimeSamples++ < 8)
            LingoDiagnostics.event(diagnosticContext, "realtime", "timeReceivedMs", timeMs,
                    "encrypted", encrypted, "clear", clear);
    }

    private static void info(String s) { if (Log.doLog) Log.i(LOG_ID, s); }
    private static void err(String what, Throwable e) {
        // Reflective calls wrap the real error in InvocationTargetException; unwrap
        // the whole cause chain and log each level's stack so the underlying SKB
        // failure (not just the wrapper) is visible in the trace.
        Throwable t = e;
        StringBuilder sb = new StringBuilder(what + " failed: " + e);
        while (t instanceof java.lang.reflect.InvocationTargetException
                && t.getCause() != null) {
            t = t.getCause();
            sb.append(" -> cause: ").append(t);
        }
        Log.e(LOG_ID, sb.toString());
        Log.stack(LOG_ID, what + " stack", t);
    }
}

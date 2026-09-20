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

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

import dalvik.system.DexClassLoader;

/*
 * Bridge to Abbott's SecureKeyBox (SKB) white-box for Abbott Lingo pairing.
 *
 * Lingo is the same GKS / FreeStyle Libre 3 stack but re-keyed, and its app
 * private key never leaves the WhiteCryption white-box, so — unlike Libre 3 —
 * Juggluco cannot reproduce the handshake crypto in its own native code. Instead
 * it drives Abbott's own SKB libraries, the same way it uses Abbott's
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
    LingoSKB(String dexPath, String optimizedDir, String nativeLibDir) throws Exception {
        final ClassLoader parent = LingoSKB.class.getClassLoader();
        final DexClassLoader loader =
                new DexClassLoader(dexPath, optimizedDir, nativeLibDir, parent);

        // Initialising GKSSecurityCredentials runs the self-decrypting loader and
        // $gksdcm$COI(), which loads the .so and fills the key table.
        Class.forName(PKG + "GKSSecurityCredentials", true, loader);

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

        info(LOG_ID + ": SecureKeyBox ready");
    }

    /** The securityVersion->key-index map inside the white-box; -1 on error. */
    int getKeyIndexFromVersion(int securityVersion) {
        try {
            return (Integer) mGetKeyIndexFromVersion.invoke(crypto, securityVersion);
        } catch (Throwable e) { err("getKeyIndexFromVersion", e); return -1; }
    }

    /** Begin ECDH for the given securityVersion; savedAuthorization may be null. */
    boolean initECDH(byte[] savedAuthorization, int securityVersion) {
        try {
            return (Boolean) mInitECDH.invoke(crypto, savedAuthorization, securityVersion);
        } catch (Throwable e) { err("initECDH", e); return false; }
    }

    /** The 162-byte app certificate to send to the sensor; null on error. */
    byte[] getAppCertificate() {
        try { return (byte[]) mGetAppCertificate.invoke(crypto); }
        catch (Throwable e) { err("getAppCertificate", e); return null; }
    }

    /** Accept and verify the sensor's (patch) certificate. */
    boolean setPatchCertificate(byte[] patchCertificate) {
        try { return (Boolean) mSetPatchCertificate.invoke(crypto, (Object) patchCertificate); }
        catch (Throwable e) { err("setPatchCertificate", e); return false; }
    }

    /** Generate the app ephemeral key pair and return its public key; null on error. */
    byte[] generateEphemeralKeys() {
        try { return (byte[]) mGenerateEphemeralKeys.invoke(crypto); }
        catch (Throwable e) { err("generateEphemeralKeys", e); return null; }
    }

    /** Complete ECDH with the sensor's ephemeral public key, deriving kAuth. */
    boolean generateKAuth(byte[] patchEphemeralPublicKey) {
        try { return (Boolean) mGenerateKAuth.invoke(crypto, (Object) patchEphemeralPublicKey); }
        catch (Throwable e) { err("generateKAuth", e); return false; }
    }

    /** AES-CCM encrypt the authorization challenge reply; null on error. */
    byte[] encrypt(byte[] nonce, byte[] plaintext) {
        try { return (byte[]) mEncrypt.invoke(crypto, nonce, plaintext); }
        catch (Throwable e) { err("encrypt", e); return null; }
    }

    /** AES-CCM decrypt the authorization challenge response; null on error. */
    byte[] decrypt(byte[] nonce, byte[] ciphertext) {
        try { return (byte[]) mDecrypt.invoke(crypto, nonce, ciphertext); }
        catch (Throwable e) { err("decrypt", e); return null; }
    }

    /** The persistent fast-reconnect blob (kAuth); null on error. */
    byte[] exportAuthorizationKey() {
        try { return (byte[]) mExportAuthorizationKey.invoke(crypto); }
        catch (Throwable e) { err("exportAuthorizationKey", e); return null; }
    }

    private static void info(String s) { if (Log.doLog) Log.i(LOG_ID, s); }
    private static void err(String what, Throwable e) {
        Log.e(LOG_ID, what + " failed: " + e);
    }
}

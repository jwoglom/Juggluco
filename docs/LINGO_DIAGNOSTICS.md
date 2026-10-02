# Lingo diagnostic build

This is an instrumented version of Juggluco for investigating an independent
Lingo authentication implementation. It continues to use the bundled Abbott
SecureKeyBox code. It does not yet remove that dependency.

## Tester procedure

Use a 64-bit Android phone with an already working Lingo connection in Juggluco.
Install the diagnostic APK as an update. It uses application ID `tk.glucodata`
and the repository's default `everyone.keystore` unless built with your own
signing configuration. The update must match the installed app's signing key
and have a compatible version code. If Android rejects the update, ask the
builder to sign this source with the existing key; do not uninstall Juggluco or
clear its data to get around an update rejection.

1. Open Juggluco and let the Lingo sensor connect normally. Wait for two fresh
   readings. This can capture the normal saved-key reconnect path.
2. Open **Settings → Logging**. Enable normal trace logging too if you want the
   surrounding Bluetooth trace. The dedicated capture works even when the trace
   logging checkbox is off.
3. Press **Full Lingo authentication**. Close the logging screen and turn
   **Use Bluetooth** off and back on in Juggluco. Keep the app process running;
   the request is deliberately a one-time, in-memory flag for the next Lingo
   connection. If several Lingo sensors are configured, whichever connects next
   consumes it.
4. Wait for the Lingo connection and several fresh readings, preferably about
   eight minutes. The app captures up to eight encrypted/decrypted minute-packet
   pairs per authentication initialization.
5. For a reconnect after that full authentication, turn **Use Bluetooth** off
   and on once more, without pressing the full-authentication button. Wait for
   two more fresh readings.
6. Return to **Settings → Logging → Save Lingo diagnostics**. Pick a location
   for `lingo-diagnostics.zip` and wait for **Saved Lingo diagnostics**. Return
   this ZIP privately to the developer. If the connection fails, export the ZIP
   anyway and describe what the screen showed and approximately when it failed.

No computer, root, or Frida is required. Do not scan/activate a new sensor solely
for this capture. The full-authentication button bypasses the saved-key import
for one connection. It does not delete that saved key; the existing successful
challenge-response path replaces it normally. It still performs a real sensor
authentication and can temporarily interrupt reception.

The ZIP includes authentication material, sensor identifiers and glucose data.
Share it privately, not in a public issue. Nothing is uploaded automatically.

## Capture contents

- `events-export.jsonl` for the current process and `events.jsonl` for the previous
  retained process, each with schema version, sequence, wall/monotonic time,
  thread, context ID and event type.
- Initialized `GKSSecurityCredentials` fields, including the version/key-index
  map, app certificates, public-key strings, private-key table entries and patch
  signing keys. These are read after the protected native initialization runs.
- `GKSSKBCryptoLib` fields and the existing token handler's fields, including
  extension/return-code constants and selected key index. Reflection reads
  fields only; it never calls extra SKB operations or a key object's getEncoded.
- Before/after arguments, return values, exceptions and timings for the existing
  bridge's authentication calls. Byte arrays carry full hex, length and SHA-256.
  These are wrapper-boundary vectors, **not hooks of every internal process1 or
  process2 call**.
- A few encrypted and decrypted realtime packet pairs, suitable for checking the
  data plane against keys/IVs in a successful challenge response.
- SHA-256 fingerprints of the bundled dex and native libraries.
- Best-effort native memory snapshots after loading, after the first full
  authentication, and after the first resumed authentication. They include readable mappings for the three SKB libraries,
  one immediately adjacent small anonymous writable mapping when it could be
  library BSS, and newly observed anonymous executable mappings excluding named
  JIT/Dalvik mappings. `maps.txt` and `index.json` identify ASLR addresses, file
  offsets, selection reasons, bytes written and errors. Snapshots are asynchronous
  and non-atomic; their names mark the request stage, not an exact CPU instant.
- Abbott logging callbacks and the normal `trace.log` if it is at most 16 MiB.
  A larger trace can be saved separately with the normal trace save button.

The diagnostic APK keeps the current and previous process runs in private app
storage. Events are limited to 8 MiB per run; verbose vendor messages have a
separate 512 KiB text budget. At most three native snapshots of 64 MiB each are
attempted per run. Limit/error records are explicit. Some Android versions will
refuse `/proc/self/mem`; the Java credentials and call vectors remain useful.
No general heap or another application's private storage is dumped.

Private-key table entries may still be wrapped. A complete capture supplies
credentials, reference vectors and often decrypted native code for subsequent
analysis; it does not guarantee a usable scalar or a finished independent
implementation. The next work is to compare these credentials/operations with
Juggluco's existing Libre 3 implementation and reproduce the Lingo full and
resumed handshakes against these vectors.

## Build and source changes

Base: `jwoglom/Juggluco` commit
`7a4192093b718105bbeba4be84f09f3275794506`.

Use the repository's normal JDK 21, Gradle, SDK 36, NDK 30.0.16138531 and CMake
4.1.2 setup, plus the prebuilt calibration libraries and ICU development files.
Initialize submodules. Supply `Common/src/libre3/assets/lingogks.jar` and the
four arm64 native libraries using the repository's existing Lingo fetch script
or the corresponding official APK inputs. The source patch does not contain
Abbott's binaries.

```
./gradlew --no-daemon --no-configuration-cache -PlingoDiagnostics=1 \
  assembleMobileLibre3SiDexNogoogleReleaseLog
```

The diagnostic flag defaults to zero. It adds the `lingodiag1` version marker,
restricts this APK to arm64, and enables the two logging-screen buttons and
capture code. Ordinary builds do not capture diagnostic secrets. Build with the
same signing configuration as the tester's installed copy when distributing an
update. The version code remains 907, as in the base fork.

The changes also recreate the bundled dex as read-only before loading it, as
required by [Android 14+ for dynamically loaded code](https://developer.android.com/about/versions/14/behavior-changes-14#safer-dynamic-code-loading), and remove the explicit
`compileSdkMinor 0` setting which requests the unavailable `android-36.0` target
with the SDK 36 package. The existing `compileSdk 36` stays in place.

The cumulative patch includes the earlier Lingo rate-of-change/trend parsing
fix, including the shared unknown-rate fallback correction. If that fix is
already installed, apply the diagnostics-only patch instead of the cumulative
patch.

## Inspect a returned capture

```
python3 scripts/inspect-lingo-diagnostics.py lingo-diagnostics.zip
```

The checker prints counts and field names, not secrets. It verifies binary
lengths/hashes and reports full/resumed handshakes followed by decoded readings,
missing/unfinished calls, memory availability and the event limit. A run with
no full handshake is still useful, but repeat steps 3–4 when possible. A completed
handshake means the observed wrapper calls succeeded and readings followed; it
is not a cryptographic proof of an independent implementation.

## Validation boundaries

The host behavioral test compiles the actual diagnostic collector and LingoSKB
bridge with Android/Abbott stubs. It checks exact byte capture, reflection,
exception/result preservation, write-failure isolation, packet limits, ZIP
export and retention. It also executes the actual full-authentication handler
with a saved-key stub to verify one-shot consumption and cache preservation.
This does not execute Abbott's native code or prove compatibility with a live
sensor. The diagnostic APK needs that on-device test.

Run the host check with a JDK and the public `org.json:json:20250517` JAR:

```
python3 scripts/test-lingo-diagnostics.py . /path/to/json-20250517.jar /tmp/lingo-check
```

The trend parser and actual save functions were separately replayed against the
427 provided sensor records in both capped and uncapped builds with undefined
behavior checks. All records passed, including missing-rate fallbacks.

#!/usr/bin/env python3
"""Host behavioral checks with Android and Abbott stubs; no sensor validation."""
import json, pathlib, subprocess, sys, zipfile, importlib.util
root, jar, dest = map(pathlib.Path, sys.argv[1:4]); root=root.resolve(); jar=jar.resolve(); dest=dest.resolve(); dest.mkdir(parents=True,exist_ok=True)
src=dest/'src'; classes=dest/'classes'; classes.mkdir(exist_ok=True)
files={
'android/content/Context.java':'''package android.content; import java.io.*; public class Context {
 public static File base; public File getFilesDir(){return new File(base,"files");}
 public File getCodeCacheDir(){File f=new File(base,"cache");f.mkdirs();return f;}
 public android.content.pm.ApplicationInfo getApplicationInfo(){return new android.content.pm.ApplicationInfo();}
 public android.content.res.AssetManager getAssets(){return new android.content.res.AssetManager();}
 public ContentResolver getContentResolver(){return new ContentResolver();}}''',
'android/content/pm/ApplicationInfo.java':'''package android.content.pm; public class ApplicationInfo {public String nativeLibraryDir="/nonexistent/diagnostic-test";}''',
'android/content/res/AssetManager.java':'''package android.content.res; public class AssetManager {public java.io.InputStream open(String name){return new java.io.ByteArrayInputStream(new byte[]{1,2,3});}}''',
'android/content/ContentResolver.java':'''package android.content; public class ContentResolver {public java.io.OutputStream openOutputStream(android.net.Uri uri,String mode)throws Exception{return new java.io.FileOutputStream(uri.path);}}''',
'android/app/Activity.java':'''package android.app; public class Activity extends android.content.Context {public void runOnUiThread(Runnable r){r.run();}}''',
'android/net/Uri.java':'''package android.net; public class Uri {public final String path;public Uri(String path){this.path=path;}}''',
'android/os/Build.java':'''package android.os; public class Build {public static String MANUFACTURER="test",MODEL="host";public static String[] SUPPORTED_ABIS={"host"};public static class VERSION {public static int SDK_INT=36;public static String RELEASE="test";}}''',
'android/os/Process.java':'''package android.os; public class Process {public static int myPid(){return 123;}}''',
'android/os/SystemClock.java':'''package android.os; public class SystemClock {public static long elapsedRealtime(){return System.nanoTime()/1000000;}public static long elapsedRealtimeNanos(){return System.nanoTime();}}''',
'android/os/ParcelFileDescriptor.java':'''package android.os; import java.io.*; public class ParcelFileDescriptor implements AutoCloseable {public static int MODE_CREATE=1,MODE_TRUNCATE=2,MODE_WRITE_ONLY=4;public static ParcelFileDescriptor open(File f,int mode)throws Exception{new FileOutputStream(f).close();return new ParcelFileDescriptor();}public int detachFd(){return 7;}public void close(){}}''',
'android/widget/Toast.java':'''package android.widget; public class Toast {public static int LENGTH_LONG=1;public static Toast makeText(android.content.Context c,String s,int d){return new Toast();}public void show(){}}''',
'android/util/Log.java':'''package android.util; public class Log {public static int e(String t,String s,Throwable e){return 0;}}''',
'dalvik/system/DexClassLoader.java':'''package dalvik.system; public class DexClassLoader extends ClassLoader {public DexClassLoader(String a,String b,String c,ClassLoader parent){super(parent);}}''',
 'tk/glucodata/BuildConfig.java':'''package tk.glucodata; public class BuildConfig {public static final int lingoDiagnostics=1;public static final String APPLICATION_ID="test",VERSION_NAME="test";}''',
 'tk/glucodata/Log.java':'''package tk.glucodata; public class Log {public static final boolean doLog=true;public static void i(String a,String b){}public static void e(String a,String b){}public static void stack(String a,String b,Throwable e){}}''',
 'tk/glucodata/Natives.java':'''package tk.glucodata; public class Natives {public static byte[] saved={1,2,3};public static byte[] getLibre3kAuth(long p){return saved;}public static long getLogfilesize(){return 0;}public static void saveLog(int fd){}}''',
 'com/adc/dcm/gksensor/security/GKSSecurityCredentials.java':'''package com.adc.dcm.gksensor.security; import java.util.*;public class GKSSecurityCredentials {private static final Map<Integer,Integer> keysMap=Map.of(3,1);private static final byte[][] LIBRE3_APP_PRIVATE_KEYS={new byte[]{0,1,(byte)255}};private static final String[] LIBRE3_APP_CERTIFICATES={"certificate"};private static final String[] LIBRE3_APP_PUBLIC_KEYS={"public"};private static final String[] LIBRE3_PATCH_SIGNING_KEYS={"patch"};}''',
 'com/adc/dcm/gksensor/security/GKSSKBCryptoLib.java':'''package com.adc.dcm.gksensor.security; import java.util.*; public class GKSSKBCryptoLib {
 private int keyIndex; private static final TokenHandler tokenHandler=new TokenHandler();
 private static class TokenHandler {private static byte[] exportedKey={6,7};private java.util.concurrent.atomic.AtomicLong tokenCounter=new java.util.concurrent.atomic.AtomicLong(10);}
 private int getKeyIndexFromVersion(int v){return v==3?1:-1;}
 public boolean initECDH(byte[] saved,int v){keyIndex=getKeyIndexFromVersion(v);return keyIndex>=0;}
 public byte[] getAppCertificate(){return new byte[162];}
 public boolean setPatchCertificate(byte[] cert){cert[0]=9;return true;}
 public byte[] generateEphemeralKeys(){return new byte[65];}
 public boolean generateKAuth(byte[] p){return p.length==65;}
 public byte[] encrypt(byte[] n,byte[] p){if(p.length==0)throw new IllegalArgumentException("test");return p.clone();}
 public byte[] decrypt(byte[] n,byte[] c){return new byte[56];}
 public byte[] exportAuthorizationKey(){return new byte[149];}
 }''',
 'tk/glucodata/Check.java':'''package tk.glucodata;
 import java.io.*;import java.lang.reflect.*;import java.util.*;import java.util.concurrent.*;
 public class Check {
 static void ok(boolean b){if(!b)throw new AssertionError();}
 static void drain()throws Exception{Field f=LingoDiagnostics.class.getDeclaredField("worker");f.setAccessible(true);((ExecutorService)f.get(null)).submit(()->{}).get();}
 public static void main(String[] args)throws Exception{
 android.content.Context.base=new File(args[0]);new File(args[0],"files").mkdirs();
 File oldRoot=new File(args[0],"files/lingo-diagnostics");oldRoot.mkdirs();new File(oldRoot,"run-100-1").mkdir();new File(oldRoot,"run-200-1").mkdir();new File(oldRoot,"unrelated").mkdir();
 android.app.Activity act=new android.app.Activity();LingoSKB skb=LingoSKB.create(act,"TEST-SENSOR");ok(skb!=null);drain();
 ok(!new File(oldRoot,"run-100-1").exists());ok(new File(oldRoot,"run-200-1").exists());ok(new File(oldRoot,"unrelated").exists());
 ok(skb.getKeyIndexFromVersion(3)==1);ok(skb.initECDH(null,3));ok(skb.getAppCertificate().length==162);
 byte[] patch=new byte[140];ok(skb.setPatchCertificate(patch));ok(patch[0]==9);ok(skb.generateEphemeralKeys().length==65);ok(skb.generateKAuth(new byte[65]));
 ok(Arrays.equals(skb.encrypt(new byte[7],new byte[]{1,2,3}),new byte[]{1,2,3}));ok(skb.decrypt(new byte[7],new byte[67]).length==56);ok(skb.exportAuthorizationKey().length==149);
 for(int i=0;i<12;i++)skb.recordRealtime(new byte[57],new byte[51],1000+i);
 ok(skb.encrypt(new byte[7],new byte[0])==null);drain();
 // Disk failure must not change the underlying crypto result or throw.
 Field ef=LingoDiagnostics.class.getDeclaredField("events");ef.setAccessible(true);File ev=(File)ef.get(null);File backup=new File(ev.getParentFile(),"saved");ok(ev.renameTo(backup));ok(ev.mkdir());
 ok(skb.initECDH(new byte[149],3));ok(ev.delete());ok(backup.renameTo(ev));
 // Capture a normal successful resumed connection after that failure.
 ok(skb.initECDH(new byte[149],3));skb.encrypt(new byte[7],new byte[40]);skb.decrypt(new byte[7],new byte[67]);skb.exportAuthorizationKey();skb.recordRealtime(new byte[57],new byte[51],2000);
 FreshCheck fresh=new FreshCheck();fresh.test(act);
 LingoDiagnostics.export(act,new android.net.Uri(args[1]));drain();ok(new File(args[1]).length()>0);
 System.out.println("PASS: actual wrapper results/exceptions, credentials, before/after bytes, disk-failure isolation, bounded packets, fresh-auth cache preservation, ZIP export, retention");
 }
 }'''
}
source=(root/'Common/src/libre3/java/tk/glucodata/Libre3GattCallback.java').read_text();start=source.index('private void handleMSLibre3SecurityNotificationsEnabledEvent()');left=source.index('{',start);depth=1;end=left+1
while depth:
 depth+=(source[end]=='{')-(source[end]=='}');end+=1
method=source[start:end]
files['tk/glucodata/FreshCheck.java']='''package tk.glucodata; class FreshCheck {
 boolean doLog=true,isPreAuthorized=true;int securityVersion=3,commandphase=0,command;long sensorptr=1;
 String SerialNumber="TEST-SENSOR",LOG_ID="test";byte[] imported;boolean initSecurityKeys(byte[] b,int level){imported=b;return true;}void sendSecurityCommand(int code){command=code;}
'''+method+'''
 void test(android.content.Context act){
 byte[] original=Natives.saved;LingoDiagnostics.requestFresh(act);handleMSLibre3SecurityNotificationsEnabledEvent();
 Check.ok(command==1 && imported==null && !isPreAuthorized && Natives.saved==original);
 command=0;handleMSLibre3SecurityNotificationsEnabledEvent();Check.ok(command==17 && imported==original && isPreAuthorized && Natives.saved==original);
 LingoDiagnostics.requestFresh(act);securityVersion=1;handleMSLibre3SecurityNotificationsEnabledEvent();Check.ok(LingoDiagnostics.consumeFresh("TEST-SENSOR"));Check.ok(!LingoDiagnostics.consumeFresh("TEST-SENSOR"));
 }
}'''
for n,text in files.items():
 f=src/n;f.parent.mkdir(parents=True,exist_ok=True);f.write_text(text)
prod=[root/'Common/src/main/java/tk/glucodata/LingoDiagnostics.java',root/'Common/src/libre3/java/tk/glucodata/LingoSKB.java',root/'Common/src/libre3/java/com/adc/dcs/core/MSLog.java']
subprocess.run(['javac','-cp',str(jar),'-d',str(classes),*[str(f)for f in src.rglob('*.java')],*map(str,prod)],check=True)
out=dest/'capture.zip'
subprocess.run(['java','-ea','-cp',str(classes)+':'+str(jar),'tk.glucodata.Check',str(dest/'app'),str(out)],check=True)
with zipfile.ZipFile(out) as z:
 n=next(n for n in z.namelist() if n.endswith('/events-export.jsonl'));rows=[json.loads(l)for l in z.read(n).splitlines()]
 assert len([r for r in rows if r['event']=='realtime'])==9
 assert {r['stage'] for r in rows if r['event']=='memory_start'}=={'ready','full-authenticated','resumed-authenticated'}
 creds=next(r for r in rows if r['event']=='fields' and r['stage']=='credentials_initialized')['fields']
 assert creds['keysMap']=={'3':1};assert creds['LIBRE3_APP_PRIVATE_KEYS'][0]['hex']=='0001ff'
 start=next(r for r in rows if r['event']=='call_start' and r['method']=='setPatchCertificate');end=next(r for r in rows if r['event']=='call_end' and r['call']==start['call'])
 assert start['args'][0]['hex'].startswith('00') and end['argsAfter'][0]['hex'].startswith('09')
spec=importlib.util.spec_from_file_location('inspect_lingo',root/'scripts/inspect-lingo-diagnostics.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
report=mod.inspect(out);assert not report['integrity_errors'],report
r=next(r for r in report['runs'] if r['events']);assert r['full_handshakes_with_readings']==1 and r['resumed_handshakes_with_readings']==1,r
(dest/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: diagnostic ZIP integrity checker recognizes full and resumed handshakes')

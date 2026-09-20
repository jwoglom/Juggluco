/*      This file is part of Juggluco, an Android app to receive and display         */
/*      glucose values from Freestyle Libre 2 and 3 sensors.                         */
/*                                                                                   */
/*      Copyright (C) 2021 Jaap Korthals Altes <jaapkorthalsaltes@gmail.com>         */
/*                                                                                   */
/*      Juggluco is free software: you can redistribute it and/or modify             */
/*      it under the terms of the GNU General Public License as published            */
/*      by the Free Software Foundation, either version 3 of the License, or         */
/*      (at your option) any later version.                                          */
/*                                                                                   */
/*      Juggluco is distributed in the hope that it will be useful, but              */
/*      WITHOUT ANY WARRANTY; without even the implied warranty of                   */
/*      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                         */
/*      See the GNU General Public License for more details.                         */
/*                                                                                   */
/*      You should have received a copy of the GNU General Public License            */
/*      along with Juggluco. If not, see <https://www.gnu.org/licenses/>.            */
/*                                                                                   */
/*      Fri Jan 27 15:31:05 CET 2023                                                 */


package tk.glucodata;


import android.nfc.Tag;

import static tk.glucodata.BuildConfig.libreVersion;
import static tk.glucodata.BuildConfig.nfcProbeOnly;
import static tk.glucodata.Log.doLog;
import static tk.glucodata.Log.showbytes;

public class  Libre3 {
private static final String LOG_ID="Libre3";
// productType reported in the NFC patch info: FreeStyle Libre 3 = 4, Abbott
// Lingo = 9. Lingo runs the same GKS stack but is re-keyed, with its app private
// key inside a WhiteCryption white-box, so it cannot be paired with Juggluco's
// clean-room crypto. Instead the libre3 flavor drives Abbott's embedded
// SecureKeyBox (LingoSKB); a Lingo scan records its securityVersion below so the
// GATT handshake takes that path. Experimental, arm64 only.
private static final int PRODUCT_TYPE_LINGO=9;
// Set when a Lingo sensor is scanned; read by the libre3 Libre3GattCallback to
// drive the SecureKeyBox handshake. Declared here (main source set) so it is
// visible to all flavors without referencing a libre3-only class.
public static volatile int pendingLingoSecurityVersion=0;
public static byte[] firstnfc(Tag tag) {
	final byte[] firstcom={(byte)0x02,(byte)0xA1,(byte)0x7A};
    var res=AlgNfcV.wholenfccmd(tag,firstcom );
	if(doLog){showbytes("NFC res: ",res);};
	return res;
	}

public static	long   	libre3NFC(Tag tag) {
	byte[] res = firstnfc(tag);
	if(res == null) {
		{if(doLog) {Log.i(LOG_ID,"firstnfc==null");};};
		return 2L;
		}
    if(res.length<29)  {
        return 2L;
        }
	if(libreVersion == 3) {
		if(doLog||nfcProbeOnly==1) {
			// Decodes and logs securityVersion, productType, patchState,
			// warmup, wearDuration and serial. Read-only: the patch info has
			// already been read above, nothing is written to the sensor.
			final int secVersion=Natives.logLibre3PatchInfo(res);
			final String summary="patch info securityVersion="+secVersion;
			Log.i(LOG_ID,summary);
			android.util.Log.i(LOG_ID,summary);
			}
		if(nfcProbeOnly==1) {
			// Probe build: stop before the activation write, so that scanning
			// an unknown sensor cannot burn it.
			final String msg="nfcProbeOnly: not activating this sensor";
			Log.i(LOG_ID,msg);
			android.util.Log.i(LOG_ID,msg);
			return 2L;
			}
		if(Natives.libre3PatchProductType(res)==PRODUCT_TYPE_LINGO) {
			// Abbott Lingo: experimental standalone pairing via the embedded
			// SecureKeyBox. Record the securityVersion so the GATT handshake drives
			// the white-box (LingoSKB) instead of the clean-room native crypto, then
			// proceed with activation + pairing.
			final int secver=Natives.logLibre3PatchInfo(res);
			pendingLingoSecurityVersion = secver>=2 ? secver : 3;
			final String msg="Abbott Lingo sensor detected (securityVersion "+secver+"); using SecureKeyBox pairing path";
			Log.i(LOG_ID,msg);
			android.util.Log.i(LOG_ID,msg);
			}
		long streamptr=tk.glucodata.libre3.NFC.second(res,tag);
//		SensorBluetooth.resetDevice(streamptr);
		{if(doLog) {Log.i(LOG_ID,"streamptr="+streamptr);};};
		return streamptr;
		}
	{if(doLog) {Log.i(LOG_ID,"libreVersion!=3");};};
	return 1L;
  	}

}

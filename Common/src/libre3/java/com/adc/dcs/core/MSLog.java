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

package com.adc.dcs.core;

/*
 * No-op replacement for Abbott's com.adc.dcs.core.MSLog.
 *
 * The SecureKeyBox native libraries (loaded from the Lingo classes via a
 * DexClassLoader whose parent is this app's class loader) call back into
 * MSLog for logging while running the crypto. In Abbott's own class the static
 * EventBus is never assigned (the initializer binds a local, not the field), so
 * every log call throws NullPointerException outside the full Lingo app.
 *
 * Because a DexClassLoader delegates to its parent first, defining MSLog here —
 * in Juggluco's own class loader, with the same package/class name and the same
 * (bytecode) method names v/e/i/w/g — shadows the copy in the Lingo dex, so the
 * native code's log up-calls resolve to these harmless no-ops and the crypto
 * proceeds. This class is only referenced by the Lingo SecureKeyBox path.
 */
public class MSLog {
    public static void v(String tag, String msg) { }
    public static void e(String tag, String msg) { }
    public static void i(String tag, String msg) { }
    public static void w(String tag, String msg) { }
    public static void g(String tag, String msg) { }
}

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

#include "lingo_realtime.h"

/*
 * Frame layout (offsets into the 51-byte decrypted plaintext), from
 * LINGO_PROTOCOL.md section 7 and confirmed against captured frames:
 *
 *   @0    uint16 LE  lifeCount
 *   @2    uint16 LE  historicLifeCount
 *   @34   uint8      analyte-type map: low nibble = ch0 type, high nibble = ch1 type
 *   @37   uint16 LE  temperature (1/100 degC, 0x8000 = invalid)
 *
 * Current glucose cappedReading, uint16 LE at offset 0x13 (=19):
 *   value & 0x0FFF        -> reading, mg/dL (scale 1)
 *   (value & 0x6000) >> 13 -> result range
 *   value & 0x8000        -> data-quality / invalid flag
 *
 * The glucose offset (0x13) and its bit layout are confirmed on a real, warmed-up
 * decode (177 mg/dL; see lingo-apk BREAK_CONFIRMED.md) and against the warm-up
 * captures in lingo_realtime_test.c.  The full per-analyte sub-block layout in
 * LINGO_PROTOCOL.md section 7 is not reproduced here: only the fields verified
 * against real captures are decoded, so nothing unverified reaches a reading.
 */
#define OFF_LIFECOUNT        0
#define OFF_HIST_LIFECOUNT   2
#define OFF_TYPEMAP          34
#define OFF_TEMPERATURE      37

/* Confirmed current-glucose cappedReading offset (0x13). */
#define OFF_CURRENT_GLUCOSE  0x13

#define READING_MASK      0x0FFFu
#define DATA_QUALITY_FLAG 0x8000u
#define TEMPERATURE_INVALID 0x8000u

static uint16_t rd_u16le(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

int lingo_parse_realtime(const uint8_t *plain, size_t len, lingo_realtime_t *out) {
    if (plain == NULL || out == NULL) return -1;
    if (len != LINGO_REALTIME_LEN) return -2;

    out->life_count = rd_u16le(plain + OFF_LIFECOUNT);
    out->historic_life_count = rd_u16le(plain + OFF_HIST_LIFECOUNT);

    const uint8_t typemap = plain[OFF_TYPEMAP];
    out->channel0_type = (uint8_t)(typemap & 0x0F);
    out->channel1_type = (uint8_t)((typemap >> 4) & 0x0F);

    /* Glucose is reported on channel 0 on every observed Lingo frame; require it
     * so a future variant that moves glucose elsewhere is treated as invalid
     * rather than silently mis-read. */
    out->glucose_valid = false;
    out->glucose_mgdl = 0;
    if (out->channel0_type == LINGO_ANALYTE_GLUCOSE) {
        const uint16_t capped = rd_u16le(plain + OFF_CURRENT_GLUCOSE);
        if ((capped & DATA_QUALITY_FLAG) == 0) {
            out->glucose_valid = true;
            out->glucose_mgdl = (uint16_t)(capped & READING_MASK);
        }
    }

    const uint16_t temp = rd_u16le(plain + OFF_TEMPERATURE);
    if (temp == TEMPERATURE_INVALID) {
        out->temperature_valid = false;
        out->temperature_centi = 0;
    } else {
        out->temperature_valid = true;
        out->temperature_centi = (int16_t)temp;
    }

    return 0;
}

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

/*
 * Host self-test for lingo_parse_realtime().  Not part of the app build.
 *
 * The four frames below are real decrypted Lingo realtime plaintexts captured
 * from a fresh sensor during warm-up (session keys read from the live
 * GKSBCSecurityContext; see lingo-apk).  Because the sensor was warming up,
 * every glucose reading carries the data-quality (invalid) flag, so the decoder
 * must report glucose_valid == false for all of them while still recovering the
 * structural fields (lifeCount, analyte-type map, temperature-invalid).  This is
 * exactly the safety property we want: warm-up data is never reported as a
 * number.  The WARM[] vectors below are real frames from the same sensor after
 * it warmed up; they decode to 201 mg/dL, matching the value the Lingo app
 * displayed, validating the value path on real (non-warm-up) data.
 *
 * Build and run on the host:
 *   cc -DLINGO_REALTIME_SELFTEST -std=c11 -Wall -Wextra \
 *      lingo_realtime.c lingo_realtime_test.c -o /tmp/lingo_test && /tmp/lingo_test
 */

#ifdef LINGO_REALTIME_SELFTEST

#include "lingo_realtime.h"
#include <stdio.h>
#include <string.h>

static int hexbyte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t unhex(const char *hex, uint8_t *out, size_t cap) {
    size_t n = 0;
    for (const char *p = hex; p[0] && p[1] && n < cap; p += 2) {
        out[n++] = (uint8_t)((hexbyte(p[0]) << 4) | hexbyte(p[1]));
    }
    return n;
}

struct vec {
    const char *name;
    const char *hex;
    uint16_t expect_life_count;
};

/* Captured, decrypted realtime frames (type 3), warm-up sensor. */
static const struct vec VECTORS[] = {
    {"prior#1", "01000000008000800000ffff00800800800080208000800000ffff0080082080008010000000806d00110cba49680f00080000", 1},
    {"prior#2", "02000000008000800000ffff00800800800080208000800000ffff00800820800080100000008070000807b1494f0e00000000", 2},
    {"live#1",  "03000000008000800000ffff00800800800080208000800000ffff00800820800080100000008070001606ec491c0e00000000", 3},
    {"live#2",  "04000000008000800000ffff00800800800080008000800000ffff0080080080008010000000807000d805fe490d0e00000000", 4},
};

int main(void) {
    int failures = 0;
    for (size_t i = 0; i < sizeof(VECTORS) / sizeof(VECTORS[0]); i++) {
        const struct vec *v = &VECTORS[i];
        uint8_t buf[64];
        size_t len = unhex(v->hex, buf, sizeof(buf));

        lingo_realtime_t r;
        int rc = lingo_parse_realtime(buf, len, &r);

        int ok = 1;
        if (len != LINGO_REALTIME_LEN) { ok = 0; printf("[%s] wrong length %zu\n", v->name, len); }
        if (rc != 0)                   { ok = 0; printf("[%s] rc=%d\n", v->name, rc); }
        if (r.life_count != v->expect_life_count) {
            ok = 0; printf("[%s] lifeCount %u != %u\n", v->name, r.life_count, v->expect_life_count);
        }
        /* Channel 0 = Glucose, channel 1 = Inactive (confirmed from the app). */
        if (r.channel0_type != LINGO_ANALYTE_GLUCOSE) {
            ok = 0; printf("[%s] ch0 type %u != GLUCOSE\n", v->name, r.channel0_type);
        }
        if (r.channel1_type != LINGO_ANALYTE_INACTIVE) {
            ok = 0; printf("[%s] ch1 type %u != INACTIVE\n", v->name, r.channel1_type);
        }
        /* Warm-up: glucose must be reported invalid, never as a number. */
        if (r.glucose_valid) {
            ok = 0; printf("[%s] glucose_valid true on warm-up frame\n", v->name);
        }
        /* Warm-up temperature is 0x8000 (invalid). */
        if (r.temperature_valid) {
            ok = 0; printf("[%s] temperature_valid true on warm-up frame\n", v->name);
        }

        printf("[%s] lifeCount=%u hist=%u ch0=%u ch1=%u glucose_valid=%d temp_valid=%d : %s\n",
               v->name, r.life_count, r.historic_life_count, r.channel0_type,
               r.channel1_type, r.glucose_valid, r.temperature_valid, ok ? "OK" : "FAIL");
        if (!ok) failures++;
    }

    /* Real warmed-up frames captured from the same sensor once it started
     * reporting glucose.  The Lingo app displayed 201 mg/dL at lifeCount 63;
     * these decode to the same value, proving the value path on real data (not
     * just structure).  raw@0x13 = 0x40c9: data-quality bit clear (valid),
     * result-range bits 0x4000, reading 0x0c9 = 201. */
    static const struct vec WARM[] = {
        {"warm lc58", "3a002800008000800000ffff00800800800080c94000800000ffff008008c9000080100000d30c7000b808764de60e00000000", 58},
        {"warm lc63", "3f002d00008000800000ffff00800800800080c94000800000ffff008008d0000080100000b90c70000109e14ced0e00000000", 63},
    };
    for (size_t i = 0; i < sizeof(WARM) / sizeof(WARM[0]); i++) {
        const struct vec *v = &WARM[i];
        uint8_t buf[64];
        size_t len = unhex(v->hex, buf, sizeof(buf));
        lingo_realtime_t r;
        int rc = lingo_parse_realtime(buf, len, &r);
        int ok = (rc == 0 && r.life_count == v->expect_life_count &&
                  r.channel0_type == LINGO_ANALYTE_GLUCOSE &&
                  r.glucose_valid && r.glucose_mgdl == 201);
        printf("[%s] lifeCount=%u glucose_valid=%d mgdl=%u : %s\n",
               v->name, r.life_count, r.glucose_valid, r.glucose_mgdl, ok ? "OK" : "FAIL");
        if (!ok) failures++;
    }

    if (failures) { printf("\n%d FAILURE(S)\n", failures); return 1; }
    printf("\nall lingo_realtime tests passed\n");
    return 0;
}

#endif /* LINGO_REALTIME_SELFTEST */

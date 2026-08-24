/* Runtime UI art generation, in C.
 *
 * The single implementation. `probes/artgen_*.c` link this file and diff its output
 * against `tools/tropico-artset.py`; `proxy/tropico_fix.c` calls it at launch. That is
 * deliberate and it is the point: a probe that validated its own private copy would be
 * testing code the game never runs. Every byte-identity claim in FINDINGS 93/94/95 is a
 * claim about THIS file.
 *
 * No Windows headers, no CRT beyond stdio/stdlib/string/math, so the probes build
 * natively and the proxy builds for i686-mingw from the same source.
 *
 * BUILD NOTE for 32-bit: -msse2 -mfpmath=sse is required. x87's 80-bit intermediates
 * change box_resample's rounding and break byte-identity (FINDINGS 94).
 */
#ifndef ARTGEN_H
#define ARTGEN_H

#include <stddef.h>

/* --- the archive index -------------------------------------------------- */

typedef struct { unsigned hash, size, offset; int archive; } ag_entry;

typedef struct {
    char      dir[1024];          /* the data\ directory holding the PK2s        */
    char      paths[4][1088];
    int       present[4];
    ag_entry *ent;   size_t nent;
    unsigned *map;   size_t mapcap;
} ag_index;

int  ag_index_load(ag_index *ix, const char *datadir);
void ag_index_free(ag_index *ix);
const ag_entry *ag_lookup(const ag_index *ix, const char *name);
unsigned ag_name_hash(const char *name);

/* --- names -------------------------------------------------------------- */

typedef struct { char **v; size_t n, cap; } ag_names;

/* Every asset the generator should produce, as "<base>.i16" names paired with the
 * archive entry to read from. `with_menu` appends the seven assets PopTop only
 * authored at 640x480, after the sorted main list -- the order is part of the
 * contract (FINDINGS 95). */
typedef struct {
    char           **name;        /* "<base>.i16"                                */
    const ag_entry **src;
    int             *from_i06;    /* 1 when the source class is i06 (640x480)     */
    size_t           n, cap;
} ag_assets;

int  ag_harvest(const ag_index *ix, const char *exepath, ag_names *out);
int  ag_resolve(const ag_index *ix, const ag_names *names, int with_menu, ag_assets *out);
void ag_names_free(ag_names *s);
void ag_assets_free(ag_assets *a);

/* --- generation --------------------------------------------------------- */

/* One container, rescaled. Returns a malloc'd buffer the caller frees, or NULL.
 * `from_w/from_h` is what the source class is authored for -- 1600x1200 for i16,
 * 640x480 for the menu assets. Fonts ignore it and take `font_scale` uniformly. */
unsigned char *ag_rescale_container(const unsigned char *d, size_t len,
                                    int to_w, int to_h, int from_w, int from_h,
                                    double font_scale, int font_nn,
                                    size_t *out_len);

/* The whole set: harvest, resolve, generate, write loose files into <gamedir>\data,
 * then the manifest and the marker. Returns the number of assets written, or -1.
 * `log` may be NULL. */
int ag_generate_set(const char *gamedir, int to_w, int to_h, double font_scale,
                    int font_nn, void (*log)(const char *));

/* Does data\ already hold a set for this mode? Reads the marker only -- cheap. */
int ag_set_is_current(const char *gamedir, int to_w, int to_h, double font_scale);

#endif

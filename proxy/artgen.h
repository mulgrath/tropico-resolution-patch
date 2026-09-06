/* Runtime UI art generation, in C.
 *
 * The single implementation. `probes/artgen_*.c` link this file and diff its output
 * against `tools/tropico-artset.py`; `proxy/tropico_fix.c` calls it at launch. That is
 * deliberate and it is the point: a probe that validated its own private copy would be
 * testing code the game never runs. Every byte-identity claim in ../dev/FINDINGS.md
 * against the Python oracle (25,820 sprites across four font scales and both filters,
 * plus the name/asset harvest) is a claim about THIS file.
 *
 * No Windows headers, no CRT beyond stdio/stdlib/string/math, so the probes build
 * natively and the proxy builds for i686-mingw from the same source.
 *
 * BUILD NOTE for 32-bit: -msse2 -mfpmath=sse is required. x87's 80-bit intermediates
 * change box_resample's rounding and break byte-identity against the Python oracle.
 */
#ifndef ARTGEN_H
#define ARTGEN_H

#include <stddef.h>

/* --- the archive index -------------------------------------------------- */

typedef struct { unsigned hash, size, offset; int archive; } ag_entry;

/* EVERY *.pk2 in data\, not a fixed list of four. The exe enumerates data\*.pk2
 * itself, opening them in ascending strcmp order, and a later archive shadows an
 * earlier one's entry -- that is how the px2..px4 patch archives override px.PK2,
 * and how a language pack's px3_cyrl.PK2 (the stock font families, glyphs repainted
 * as Cyrillic, under the stock names) replaces the fonts without touching px.PK2.
 * The index mirrors that order exactly, so the generator's source for each name is
 * the one the game would have used. */
#define AG_MAX_ARCHIVES 32

typedef struct {
    char      dir[1024];          /* the data\ directory holding the PK2s        */
    char      paths[AG_MAX_ARCHIVES][1088];
    char      names[AG_MAX_ARCHIVES][64];   /* on-disk file name, e.g. "px3_cyrl.PK2" */
    unsigned  sizes[AG_MAX_ARCHIVES];       /* file size, part of the cache key      */
    int       present[AG_MAX_ARCHIVES];
    int       narch;
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
 * contract the oracle diff checks against, so it is not merely cosmetic. */
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

/* Does data\ already hold a set for this mode AND this set of archives? Reads the
 * marker and the archive directory listing only -- cheap. */
int ag_set_is_current(const char *gamedir, int to_w, int to_h, double font_scale);

/* The marker text a set for this mode over these archives carries: "WxH" on the
 * first line (what tools/tropico-setmode.sh and the proxy's cross-check read), then
 * one "name size" line per archive in index order. */
int ag_marker_text(const char *datadir, int to_w, int to_h, char *out, size_t n);

#endif

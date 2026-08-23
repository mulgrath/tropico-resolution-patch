/* Step 4 of the runtime art generator: archive reading and name harvesting, in C.
 *
 * WHAT THIS HAS TO REPRODUCE, and why each part is load-bearing:
 *
 *   the PK2 index      entry offsets are RELATIVE to the data region, not absolute
 *                      (FINDINGS 19). Reading them as absolute shifts every blob by
 *                      data_start and yields plausible-looking garbage rather than an
 *                      obvious error.
 *   the name hash      entries carry only a hash, so a name must be hashed to be
 *                      found. Read out of the loop at 0x4ef409, with the game's OWN
 *                      toupper at 0x4eb270 -- which also upcases bytes >= 0xF0.
 *   THREE name sources All of them. The exe alone yields 42 assets; adding the .WIN
 *                      records inside the archives yields 79 (FINDINGS 48.2); adding
 *                      the numeric families yields the rest. Miss the third and the
 *                      182 brNN building portraits fall back to archived 1600x1200 art
 *                      in a regenerated hole -- an unpainted crescent down the right
 *                      of every build-menu icon, which is exactly what FINDINGS 90
 *                      cost to find. "It ran" is not the test; the test is the same
 *                      names, in the same order, resolving to the same archive entries.
 *
 * SCOPE: names and entries only. No decoding, no rescaling -- artgen_probe.c does that.
 * Output is a plain text listing so the diff against the Python is readable when it
 * fails, rather than a byte blob that only says "somewhere".
 *
 * Build:  cc -O2 -o artgen_names artgen_names.c
 * Run:    artgen_names <datadir> <exe> [--with-menu] > names.txt
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *ARCHIVES[] = { "px.PK2", "px2.PK2", "px3.PK2", "px4.PK2" };
#define NARCH 4

/* ------------------------------------------------------------------ the hash */

/* The game's toupper at 0x4eb270. It also upcases bytes >= 0xF0, which a library
 * toupper() will not do -- and a lowercase variant of this hash scores 0 matches
 * against the archives, so this is not a detail that can be approximated. */
static unsigned game_toupper(unsigned c)
{
    return ((c >= 0x61 && c <= 0x7A) || c >= 0xF0) ? c - 0x20 : c;
}

static unsigned name_hash(const char *s)
{
    unsigned h = 7;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        h = h * 0x41C64E6Eu + game_toupper(*p) + 0x3039u;
    return h;
}

/* ----------------------------------------------------------------- the index */

typedef struct { unsigned hash, size, offset; int archive; } entry_t;

static entry_t *g_ent; static size_t g_nent, g_entcap;
static unsigned *g_map;            /* open-addressed: index into g_ent, +1; 0 = empty */
static size_t g_mapcap;

static unsigned rd32(const unsigned char *d, size_t o)
{ return d[o] | (d[o+1]<<8) | (d[o+2]<<16) | ((unsigned)d[o+3]<<24); }

static void map_put(unsigned hash, size_t idx)
{
    size_t m = g_mapcap, i = hash & (m - 1);
    /* LAST WRITER WINS, matching the Python's `idx[e['hash']] = e` over the archive
     * list in order -- a later archive shadows an earlier one's entry. */
    for (;;) {
        if (!g_map[i]) { g_map[i] = (unsigned)(idx + 1); return; }
        if (g_ent[g_map[i] - 1].hash == hash) { g_map[i] = (unsigned)(idx + 1); return; }
        i = (i + 1) & (m - 1);
    }
}

static entry_t *map_get(unsigned hash)
{
    size_t m = g_mapcap, i = hash & (m - 1);
    for (;;) {
        if (!g_map[i]) return NULL;
        entry_t *e = &g_ent[g_map[i] - 1];
        if (e->hash == hash) return e;
        i = (i + 1) & (m - 1);
    }
}

static unsigned char *slurp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *d = (unsigned char *)malloc((size_t)n ? (size_t)n : 1);
    if (!d || fread(d, 1, (size_t)n, f) != (size_t)n) { free(d); fclose(f); return NULL; }
    fclose(f); *len = (size_t)n;
    return d;
}

/* ------------------------------------------------------------------ name set */

typedef struct { char **v; size_t n, cap; } names_t;

static int name_cmp(const void *a, const void *b)
{ return strcmp(*(char *const *)a, *(char *const *)b); }

static void names_add(names_t *s, const char *n)
{
    if (s->n == s->cap) {
        s->cap = s->cap ? s->cap * 2 : 256;
        s->v = (char **)realloc(s->v, s->cap * sizeof *s->v);
        if (!s->v) { fprintf(stderr, "out of memory\n"); exit(2); }
    }
    s->v[s->n++] = strdup(n);
}

/* sort + unique, which is how the Python's set becomes a sorted list. Python sorts
 * str by code point and these are ASCII, so strcmp order is the same order. */
static void names_finish(names_t *s)
{
    if (!s->n) return;
    qsort(s->v, s->n, sizeof *s->v, name_cmp);
    size_t w = 1;
    for (size_t i = 1; i < s->n; i++)
        if (strcmp(s->v[i], s->v[w-1])) s->v[w++] = s->v[i];
    s->n = w;
}

static int names_has(const names_t *s, const char *n)   /* on a SORTED set */
{
    size_t lo = 0, hi = s->n;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        int c = strcmp(s->v[mid], n);
        if (c == 0) return 1;
        if (c < 0) lo = mid + 1; else hi = mid;
    }
    return 0;
}

/* --------------------------------------------------------------- the scanner
 *
 * Python: re.finditer(rb'[A-Za-z0-9_\-]{1,20}\.imm', d)
 *
 * Reimplemented rather than approximated, because the two places it is subtle both
 * occur in real data:
 *
 *   the {1,20} CAP    a run longer than 20 characters does not fail to match -- the
 *                     regex slides its start forward and matches the LAST 20. Taking
 *                     the whole run instead would invent names that are not there.
 *   NON-OVERLAPPING   scanning resumes after a match, so a second ".imm" cannot
 *                     borrow characters the previous match already consumed.
 */
static int name_char(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
        || (c >= '0' && c <= '9') || c == '_' || c == '-';
}

static void scan_imm(const unsigned char *d, size_t len, names_t *out)
{
    size_t last_end = 0;
    for (size_t i = 0; i + 4 <= len; i++) {
        if (d[i] != '.' || d[i+1] != 'i' || d[i+2] != 'm' || d[i+3] != 'm') continue;
        size_t run = 0;
        while (run < i && name_char(d[i - 1 - run])) run++;
        size_t start = i - run;
        if (i - start > 20) start = i - 20;         /* the {1,20} cap */
        if (start < last_end) start = last_end;     /* non-overlapping */
        if (start >= i) continue;                   /* nothing left to match */
        size_t n = i - start;
        char buf[32];
        memcpy(buf, d + start, n);
        memcpy(buf + n, ".imm", 4);
        buf[n + 4] = 0;
        names_add(out, buf);
        last_end = i + 4;
        i += 3;
    }
}

/* ------------------------------------------------------------------- harvest */

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <datadir> <exe> [--with-menu]\n", argv[0]);
        return 2;
    }
    const char *datadir = argv[1], *exepath = argv[2];
    int with_menu = 0, dump_names = 0;
    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--with-menu"))  with_menu = 1;
        if (!strcmp(argv[i], "--dump-names")) dump_names = 1;
    }

    char paths[NARCH][4096]; int present[NARCH]; int narch = 0;
    for (int a = 0; a < NARCH; a++) {
        snprintf(paths[a], sizeof paths[a], "%s/%s", datadir, ARCHIVES[a]);
        FILE *f = fopen(paths[a], "rb");
        present[a] = f != NULL;
        if (f) { fclose(f); narch++; }
    }
    if (!narch) { fprintf(stderr, "no archives in %s\n", datadir); return 2; }

    /* --- pass 1: indices ---------------------------------------------------- */
    for (int a = 0; a < NARCH; a++) {
        if (!present[a]) continue;
        FILE *f = fopen(paths[a], "rb");
        unsigned char head[8];
        if (fread(head, 1, 8, f) != 8) { fclose(f); return 2; }
        if (rd32(head, 0) != 1000) {
            fprintf(stderr, "%s: magic is %u, expected 1000\n", paths[a], rd32(head, 0));
            fclose(f); return 2;
        }
        unsigned count = rd32(head, 4);
        unsigned char *raw = (unsigned char *)malloc((size_t)13 * count);
        if (fread(raw, 1, (size_t)13 * count, f) != (size_t)13 * count) { fclose(f); return 2; }
        fclose(f);
        size_t data_start = 8 + (size_t)13 * count;
        if (g_nent + count > g_entcap) {
            while (g_entcap < g_nent + count) g_entcap = g_entcap ? g_entcap * 2 : 4096;
            g_ent = (entry_t *)realloc(g_ent, g_entcap * sizeof *g_ent);
        }
        for (unsigned i = 0; i < count; i++) {
            entry_t e;
            e.hash   = rd32(raw, 13 * (size_t)i);
            e.size   = rd32(raw, 13 * (size_t)i + 4);
            e.offset = (unsigned)(data_start + rd32(raw, 13 * (size_t)i + 8));
            e.archive = a;
            g_ent[g_nent++] = e;
        }
        free(raw);
    }
    g_mapcap = 1; while (g_mapcap < g_nent * 2) g_mapcap *= 2;
    g_map = (unsigned *)calloc(g_mapcap, sizeof *g_map);
    for (size_t i = 0; i < g_nent; i++) map_put(g_ent[i].hash, i);

    /* --- pass 2: names from the exe ----------------------------------------- */
    names_t names = {0};
    size_t exelen; unsigned char *exe = slurp(exepath, &exelen);
    if (!exe) { perror(exepath); return 2; }
    scan_imm(exe, exelen, &names);
    free(exe);
    /* Dedup before counting. The raw scan yields one hit per OCCURRENCE and a name
     * appears in the exe many times over; the Python's set() hides that, so an
     * undeduped count here reads as a 67-vs-51 disagreement that does not exist. */
    names_finish(&names);
    size_t from_exe = names.n;

    /* --- pass 3: names from the .WIN records inside the archives -------------
     * FINDINGS 48.2: the names of HUD art live in the .WIN files, not the exe --
     * which is why an exe-only harvest undercounts, and why int_main.imm, the bottom
     * bar, is invisible to it. A .WIN record is identified by its leading u32 == 0x7d0. */
    for (int a = 0; a < NARCH; a++) {
        if (!present[a]) continue;
        size_t blen; unsigned char *blob = slurp(paths[a], &blen);
        if (!blob) { perror(paths[a]); return 2; }
        for (size_t i = 0; i < g_nent; i++) {
            if (g_ent[i].archive != a) continue;
            size_t off = g_ent[i].offset, sz = g_ent[i].size;
            if (off + sz > blen || sz < 4) continue;
            if (rd32(blob, off) != 0x7d0) continue;
            scan_imm(blob + off, sz, &names);
        }
        free(blob);
    }
    names_finish(&names);
    size_t after_win = names.n;

    /* --- pass 4: numeric families --------------------------------------------
     * FINDINGS 90. A name the game BUILDS at runtime appears in no file: the build
     * menu's portraits are brNN.imm, one per building type, and only br00 is written
     * down anywhere. The rule stays deliberately narrow -- alpha prefix, trailing
     * digits, and a candidate is kept only if the archive actually holds it -- which
     * against the shipped archives adds exactly the 182 missing brNN and nothing else. */
    names_t fam = {0};
    for (size_t i = 0; i < names.n; i++) {
        const char *n = names.v[i];
        size_t L = strlen(n);
        if (L < 6 || strcmp(n + L - 4, ".imm")) continue;
        size_t stem = L - 4, p = 0;
        while (p < stem && ((n[p] >= 'A' && n[p] <= 'Z') || (n[p] >= 'a' && n[p] <= 'z')
                            || n[p] == '_')) p++;
        if (p == 0 || p == stem) continue;                  /* need prefix AND digits */
        size_t q = p;
        while (q < stem && n[q] >= '0' && n[q] <= '9') q++;
        if (q != stem) continue;                            /* digits must run to the end */
        char prefix[64];
        if (p >= sizeof prefix) continue;
        memcpy(prefix, n, p); prefix[p] = 0;
        for (int k = 0; k < 1000; k++) {
            char cand[96], probe[128];
            snprintf(cand, sizeof cand, "%s%02d", prefix, k);
            snprintf(probe, sizeof probe, "%s.i16", cand);
            if (map_get(name_hash(probe))) {
                char immn[128];
                snprintf(immn, sizeof immn, "%s.imm", cand);
                names_add(&fam, immn);
            }
        }
    }
    for (size_t i = 0; i < fam.n; i++) names_add(&names, fam.v[i]);
    names_finish(&names);

    /* --- resolve ------------------------------------------------------------- */
    fprintf(stderr, "exe:%zu  +win:%zu  +family:%zu\n", from_exe, after_win, names.n);

    /* The HARVESTED set, before resolution drops anything without an .i16. Resolution
     * is a filter, so a spurious extra name is invisible in the final listing --
     * which makes the resolved diff a weaker oracle than it looks. This is the
     * strong one. */
    if (dump_names) {
        for (size_t i = 0; i < names.n; i++) printf("%s\n", names.v[i]);
        return 0;
    }

    /* One pass of the Python's asset_names(). out_ext is always i16 here. */
    #define RESOLVE(src_ext, missing_only)                                            \
      for (size_t i = 0; i < names.n; i++) {                                          \
        const char *n = names.v[i]; size_t L = strlen(n);                             \
        char base[128], src[160];                                                     \
        if (L < 5 || L - 4 >= sizeof base) continue;                                  \
        memcpy(base, n, L - 4); base[L - 4] = 0;                                       \
        snprintf(src, sizeof src, "%s.%s", base, src_ext);                            \
        entry_t *e = map_get(name_hash(src));                                          \
        if (!e) continue;                                                              \
        if (missing_only) {                                                            \
            char i16[160]; snprintf(i16, sizeof i16, "%s.i16", base);                  \
            if (map_get(name_hash(i16))) continue;                                     \
        }                                                                              \
        char outn[160]; snprintf(outn, sizeof outn, "%s.i16", base);                   \
        EMIT(outn, e);                                                                 \
      }

    names_t emitted = {0};
    #define EMIT(outn, e) do {                                                        \
        printf("%s\t%s\t%u\t%u\n", (outn), ARCHIVES[(e)->archive], (e)->offset, (e)->size); \
        names_add(&emitted, (outn));                                                   \
    } while (0)

    RESOLVE("i16", 0)
    names_finish(&emitted);

    if (with_menu) {
        /* FINDINGS 69.5: seven assets exist only as .i06, because PopTop authored the
         * menu, the credits and the folder screens at 640x480 and nothing else. The
         * menu dies with "Error opening pack file item 'setuplb.i16'" without them.
         * Appended AFTER the sorted main list, and only when not already present --
         * so the final order is not globally sorted, and reproducing that matters. */
        #undef EMIT
        #define EMIT(outn, e) do {                                                    \
            if (!names_has(&emitted, (outn)))                                          \
                printf("%s\t%s\t%u\t%u\n", (outn), ARCHIVES[(e)->archive],             \
                       (e)->offset, (e)->size);                                        \
        } while (0)
        RESOLVE("i06", 1)
    }
    return 0;
}

/* Runtime UI art generation -- see artgen.h for why this file is shared between the
 * probes and the proxy rather than copied into each.
 *
 * The codec, the resampling and the name harvest below are carried across VERBATIM
 * from the probes that validated them (FINDINGS 93/94/95): 25,820 sprites byte-identical
 * to tools/tropico-artset.py across four font scales and both filters, and 280 names /
 * 268 resolved assets identical to the Python harvest. Moving them was a cut and paste,
 * deliberately, so that "the probe passed" keeps meaning something about this file.
 *
 * New here, and NOT yet covered by those runs when first written: the container writer
 * (ag_rescale_container) and the set driver (ag_generate_set).
 */
#include "artgen.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* -------------------------------------------------------------------- buffers */

typedef struct { unsigned char *p; size_t n, cap; } buf_t;

static void buf_need(buf_t *b, size_t extra)
{
    if (b->n + extra <= b->cap) return;
    size_t cap = b->cap ? b->cap : 4096;
    while (cap < b->n + extra) cap *= 2;
    b->p = (unsigned char *)realloc(b->p, cap);
    if (!b->p) { fprintf(stderr, "out of memory\n"); exit(2); }
    b->cap = cap;
}
static void buf_u8(buf_t *b, unsigned char v) { buf_need(b, 1); b->p[b->n++] = v; }
static void buf_add(buf_t *b, const unsigned char *s, size_t n)
{ buf_need(b, n); memcpy(b->p + b->n, s, n); b->n += n; }
static void buf_u32(buf_t *b, unsigned v) __attribute__((unused));
static void buf_u32(buf_t *b, unsigned v)
{ unsigned char t[4]; t[0]=v; t[1]=v>>8; t[2]=v>>16; t[3]=v>>24; buf_add(b, t, 4); }

/* ------------------------------------------------------------- column entries
 *
 * One decoded pixel. PAYLOAD BYTES ARE NEVER INTERPRETED -- a literal's palette
 * index and an alpha's opacity are carried through verbatim, because re-deriving
 * either would mean knowing the palette and the blend, and neither is needed to
 * move a pixel sideways. Only the opcode headers, which encode counts, are
 * re-synthesised. */
enum { C_NONE = 0, C_LIT, C_TINT, C_ALPHA, C_IDXA };
typedef struct { unsigned char kind, a, b; } cell_t;

/* ------------------------------------------------------------------ the codec */

/* Row framing (FINDINGS 28): b < 0x80 -> a 1-byte header declaring length b;
 * b >= 0x80 -> a 2-byte header declaring ((b&0x7f)<<8)|next. The length COUNTS the
 * header. The blit itself skips the header without reading the length and relies on
 * the 0x00 opcode to advance -- but the length is what makes rows addressable, so
 * everything here is header-driven. */
static void row_bounds(const unsigned char *d, size_t p, int *hl, unsigned *len)
{
    unsigned b0 = d[p];
    if (b0 < 0x80) { *hl = 1; *len = b0; }
    else           { *hl = 2; *len = ((b0 & 0x7f) << 8) | d[p + 1]; }
}

/* Decode one row into `cols` (w entries, C_NONE = transparent). Returns 0 on
 * success, -1 on a malformed row. `*len` receives the row's byte length so the
 * caller can step to the next one; `*term` receives 0x00, 0xC0 or -1 for none. */
static int decode_row(const unsigned char *d, size_t p, int w, cell_t *cols,
                      unsigned *len, int *term)
{
    int hl; unsigned L;
    row_bounds(d, p, &hl, &L);
    *len = L;
    *term = -1;
    memset(cols, 0, (size_t)w * sizeof *cols);

    size_t q = p + hl, end = p + L;
    int x = 0;
    while (q < end) {
        unsigned op = d[q];
        size_t o = q, next = q + 1;
        int adv = 0;
        if (op == 0x00) {
            *term = 0x00;                 /* rest of the row is transparent */
            return 0;
        } else if (op < 0x80) {           /* literal run: `op` palette indices  */
            adv = (int)op; next += op;
        } else if (op < 0xa0) {           /* recolour run: no payload           */
            unsigned n = op & 7;
            if (n == 0) { n = d[next]; next++; }
            adv = (int)n;
        } else if (op < 0xb0) {           /* alpha run: one byte per pixel      */
            unsigned n = op & 15;
            if (n == 0) { n = d[next]; next++; }
            adv = (int)n; next += n;
        } else if (op < 0xc0) {           /* index+alpha run: two per pixel     */
            unsigned n = op & 15;
            if (n == 0) { n = d[next]; next++; }
            adv = (int)n; next += (size_t)n * 2;
        } else if (op == 0xc0) {
            *term = 0xC0;                 /* end of SPRITE; a final row may use it */
            return 0;
        } else {                          /* 0xc1..0xff: transparent skip       */
            adv = (int)(op & 0x3f);
        }
        if (next > end) return -1;        /* the packet overruns its own row    */
        if (x + adv > w) return -1;       /* ...or the sprite's declared width  */

        if (op < 0x80) {
            const unsigned char *src = d + o + 1;
            for (int k = 0; k < adv; k++)
            { cols[x+k].kind = C_LIT; cols[x+k].a = src[k]; }
        } else if (op < 0xa0) {
            unsigned char sel = (unsigned char)((op >> 3) & 3);
            for (int k = 0; k < adv; k++)
            { cols[x+k].kind = C_TINT; cols[x+k].a = sel; }
        } else if (op < 0xb0) {
            const unsigned char *src = d + next - adv;
            for (int k = 0; k < adv; k++)
            { cols[x+k].kind = C_ALPHA; cols[x+k].a = src[k]; }
        } else if (op < 0xc0) {
            const unsigned char *src = d + next - (size_t)2 * adv;
            for (int k = 0; k < adv; k++)
            { cols[x+k].kind = C_IDXA; cols[x+k].a = src[2*k]; cols[x+k].b = src[2*k+1]; }
        }
        /* a skip leaves the span C_NONE */
        x += adv;
        q = next;
    }
    return 0;
}

/* Encode `n` column entries as one complete row record, header included.
 * `term` is 0x00, 0xC0, or -1 for none -- the caller decides it from the row's
 * POSITION, never from the source row (see the file header). Returns 0, or -1 if
 * the row will not fit the 15-bit length header. */
static int emit_row(const cell_t *cols, int n, int term, buf_t *out)
{
    static buf_t body;                    /* reused across every row in the run */
    body.n = 0;

    /* Trailing transparency is never encoded. */
    int last = n;
    while (last > 0 && cols[last-1].kind == C_NONE) last--;

    int i = 0;
    while (i < last) {
        if (cols[i].kind == C_NONE) {
            int j = i;
            while (j < last && cols[j].kind == C_NONE) j++;
            int run = j - i;
            /* 0xc0 on its own is end-of-sprite, so a skip is never emitted as 0. */
            while (run) { int k = run > 0x3f ? 0x3f : run; buf_u8(&body, (unsigned char)(0xc0|k)); run -= k; }
            i = j;
            continue;
        }
        unsigned char kind = cols[i].kind, sel = cols[i].a;
        int j = i;
        while (j < last && cols[j].kind == kind && (kind != C_TINT || cols[j].a == sel)) j++;
        int run = j - i;
        while (run) {
            int k;
            if (kind == C_LIT) {
                k = run > 0x7f ? 0x7f : run;
                buf_u8(&body, (unsigned char)k);
                buf_need(&body, (size_t)k);
                for (int t = 0; t < k; t++) body.p[body.n++] = cols[i+t].a;
            } else if (kind == C_TINT) {
                k = run > 0xff ? 0xff : run;
                unsigned char base = (unsigned char)(0x80 | (sel << 3));
                if (k <= 7) buf_u8(&body, (unsigned char)(base | k));
                else { buf_u8(&body, base); buf_u8(&body, (unsigned char)k); }
            } else if (kind == C_ALPHA) {
                k = run > 0xff ? 0xff : run;
                if (k <= 15) buf_u8(&body, (unsigned char)(0xa0 | k));
                else { buf_u8(&body, 0xa0); buf_u8(&body, (unsigned char)k); }
                buf_need(&body, (size_t)k);
                for (int t = 0; t < k; t++) body.p[body.n++] = cols[i+t].a;
            } else {                       /* C_IDXA */
                k = run > 0xff ? 0xff : run;
                if (k <= 15) buf_u8(&body, (unsigned char)(0xb0 | k));
                else { buf_u8(&body, 0xb0); buf_u8(&body, (unsigned char)k); }
                buf_need(&body, (size_t)k * 2);
                for (int t = 0; t < k; t++)
                { body.p[body.n++] = cols[i+t].a; body.p[body.n++] = cols[i+t].b; }
            }
            i += k; run -= k;
        }
    }
    if (term >= 0) buf_u8(&body, (unsigned char)term);

    size_t total = body.n + 1;
    if (total < 0x80) {
        buf_u8(out, (unsigned char)total);
    } else {
        total = body.n + 2;
        if (total > 0x7fff) return -1;
        buf_u8(out, (unsigned char)(0x80 | (total >> 8)));
        buf_u8(out, (unsigned char)(total & 0xff));
    }
    buf_add(out, body.p, body.n);
    return 0;
}

/* Nearest-neighbour selection, sampling at DESTINATION cell centres. Monotonic
 * non-decreasing in i, which is what lets rescale_sprite keep a one-row cache
 * where the Python keeps a dict. */
static void pick(int n_src, int n_dst, int *out)
{
    for (int i = 0; i < n_dst; i++) {
        long v = ((long)(2*i + 1) * n_src) / (2L * n_dst);
        out[i] = (int)(v > n_src - 1 ? n_src - 1 : v);
    }
}

/* ------------------------------------------------------------------ container */

typedef struct { unsigned size; int x, y; unsigned w, h, fmt; size_t data_offset; } sprite_t;

typedef struct {
    const unsigned char *d; size_t len;
    unsigned count; size_t table_base; sprite_t *sprites; int exact;
} cont_t;

static unsigned rd32(const unsigned char *d, size_t o)
{ return d[o] | (d[o+1]<<8) | (d[o+2]<<16) | ((unsigned)d[o+3]<<24); }
static unsigned rd16(const unsigned char *d, size_t o) { return d[o] | (d[o+1]<<8); }

#define CONT_MAGIC 0x27D8

static int cont_parse(cont_t *c, const unsigned char *d, size_t len)
{
    if (len < 0x3f) return -1;
    if (rd16(d, 0) != CONT_MAGIC) return -1;
    c->d = d; c->len = len;
    c->count = rd16(d, 2);
    c->table_base = rd32(d, 0x07);                 /* start[0] */
    size_t off = c->table_base + 15 * (size_t)c->count;
    c->sprites = (sprite_t *)malloc(sizeof(sprite_t) * (c->count ? c->count : 1));
    if (!c->sprites) return -1;
    for (unsigned i = 0; i < c->count; i++) {
        if (off + 13 > len) { free(c->sprites); c->sprites = NULL; return -1; }
        sprite_t *s = &c->sprites[i];
        s->size = rd32(d, off);
        s->x = (short)rd16(d, off + 4);
        s->y = (short)rd16(d, off + 6);
        s->w = rd16(d, off + 8);
        s->h = rd16(d, off + 10);
        s->fmt = d[off + 12];
        s->data_offset = off + 13;
        off += 13 + (size_t)s->size;
        if (off > len) { free(c->sprites); c->sprites = NULL; return -1; }
    }
    c->exact = (off == len);
    return 0;
}

/* ------------------------------------------------------------- rescale_sprite */

/* Scratch, reused for the whole run: this is the allocation churn that costs the
 * Python 16 M minor faults, and reusing it is most of why the C is fast. */
static cell_t *g_src, *g_dst; static size_t g_srccap, g_dstcap;
static int *g_cols, *g_rows; static size_t g_colcap, g_rowcap;

static void *grow(void *p, size_t *cap, size_t need, size_t elem)
{
    if (need <= *cap) return p;
    size_t c = *cap ? *cap : 64;
    while (c < need) c *= 2;
    p = realloc(p, c * elem);
    if (!p) { fprintf(stderr, "out of memory\n"); exit(2); }
    *cap = c;
    return p;
}

static int rescale_sprite(const cont_t *c, const sprite_t *s, int nw, int nh, buf_t *out)
{
    int w = (int)s->w, h = (int)s->h;

    g_src  = (cell_t *)grow(g_src,  &g_srccap, (size_t)w,  sizeof(cell_t));
    g_dst  = (cell_t *)grow(g_dst,  &g_dstcap, (size_t)nw, sizeof(cell_t));
    g_cols = (int *)   grow(g_cols, &g_colcap, (size_t)nw, sizeof(int));
    g_rows = (int *)   grow(g_rows, &g_rowcap, (size_t)nh, sizeof(int));
    pick(w, nw, g_cols);
    pick(h, nh, g_rows);

    /* Walk the row records once to index them, and check the sprite terminator --
     * exactly what row_offsets does. A sprite that does not end 0xC0 is corrupt. */
    size_t p = s->data_offset;
    static size_t *offs; static size_t offscap;
    offs = (size_t *)grow(offs, &offscap, (size_t)h, sizeof(size_t));
    for (int r = 0; r < h; r++) {
        offs[r] = p;
        int hl; unsigned L;
        row_bounds(c->d, p, &hl, &L);
        (void)hl;
        p += L;
        if (p > c->len) return -1;
    }
    if (p >= c->len || c->d[p] != 0xC0) return -1;

    int cached = -1, cached_term = -1;
    for (int r = 0; r < nh; r++) {
        int src = g_rows[r];
        if (src != cached) {
            unsigned L;
            if (decode_row(c->d, offs[src], w, g_src, &L, &cached_term) < 0) return -1;
            cached = src;
        }
        /* THE POSITIONAL TERMINATOR RULE. Both halves matter and both were
         * measured; see the file header. */
        int term;
        if (r != nh - 1)             term = 0x00;
        else if (cached_term == 0x00) term = -1;
        else                          term = cached_term;

        for (int i = 0; i < nw; i++) g_dst[i] = g_src[g_cols[i]];
        if (emit_row(g_dst, nw, term, out) < 0) return -1;
    }
    buf_u8(out, 0xC0);
    return 0;
}

/* ------------------------------------------------------------- the font path
 *
 * FONTS ARE DIFFERENT ON TWO INDEPENDENT COUNTS, both measured (FINDINGS 63/65/86):
 *
 * 1. Every pixel in a font container is alpha-run class -- 922150 of 922150 across
 *    all 17 assets -- against 99% palettised literals for the chrome. An alpha is a
 *    NUMBER, so it can be averaged and still mean something. A palette index cannot:
 *    averaging two indices yields an unrelated colour, which is why the chrome must
 *    stay nearest-neighbour and the fonts may be box-filtered.
 * 2. PopTop scaled their own fonts UNIFORMLY, never per-axis. So a font sprite takes
 *    one scale on both axes, where the chrome takes the screen's own two.
 *
 * THE ALPHA CONVENTION, read out of the blend at the end of FUN_00538ba0:
 *
 *     result = (255 - a) * dst + a * src
 *
 * with a == 0 handled separately, writing the constant colour OUTRIGHT. So a stored
 * byte of 0 means FULLY OPAQUE -- it is a sentinel for 256, not transparency.
 * Transparency is a pixel being ABSENT, covered by a skip opcode. Averaging the raw
 * bytes would therefore turn solid text into holes, which is what `opacity` and
 * `to_alpha` exist to prevent.
 */

static int opacity(const cell_t *c)
{
    if (c->kind == C_NONE) return 0;
    return c->a == 0 ? 255 : c->a;      /* a stored 0 means fully opaque */
}

static cell_t to_alpha(int op)
{
    cell_t c;
    c.kind = C_NONE; c.a = 0; c.b = 0;
    if (op <= 0) return c;              /* absent -> a skip opcode, never alpha 0 */
    c.kind = C_ALPHA;
    c.a = (unsigned char)(op >= 255 ? 0 : op);
    return c;
}

/* True when every pixel in the container is alpha-run class. */
static int is_font(const cont_t *c)
{
    long seen = 0;
    for (unsigned i = 0; i < c->count; i++) {
        const sprite_t *s = &c->sprites[i];
        if (s->fmt != 2) continue;
        size_t p = s->data_offset;
        for (unsigned r = 0; r < s->h; r++) {
            int hl; unsigned L;
            row_bounds(c->d, p, &hl, &L);
            size_t q = p + hl, end = p + L;
            while (q < end) {
                unsigned op = c->d[q];
                size_t next = q + 1;
                int adv = 0;
                if (op == 0x00) { q = next; continue; }
                else if (op < 0x80) { adv = (int)op; next += op; }
                else if (op < 0xa0) { unsigned n = op & 7;  if (!n) n = c->d[next++]; adv = (int)n; }
                else if (op < 0xb0) { unsigned n = op & 15; if (!n) n = c->d[next++]; adv = (int)n; next += n; }
                else if (op < 0xc0) { unsigned n = op & 15; if (!n) n = c->d[next++]; adv = (int)n; next += (size_t)n*2; }
                else { q = next; continue; }        /* 0xc0 and skips are not pixels */
                if (!(op >= 0xa0 && op < 0xb0)) return 0;
                seen += adv;
                q = next;
            }
            p += L;
        }
    }
    return seen > 0;
}

/* Area-weighted box filter over opacity. The correct antialiaser, and what a
 * DOWNscale needs.
 *
 * THE FLOATING POINT HERE IS LOAD-BEARING AND MUST MATCH THE PYTHON BIT FOR BIT.
 * The oracle is byte-identity, so the accumulation ORDER (y outer ascending, x inner
 * ascending), the use of double throughout, and the ties-to-even rounding at the end
 * are all part of the contract rather than incidental. Reassociating the sum or
 * rounding with (int)(v+0.5) would produce output that is visually identical and
 * fails the diff. */
static void box_resample(const unsigned char *grid, int w, int h, int nw, int nh,
                         cell_t *out)
{
    for (int r = 0; r < nh; r++) {
        double y0 = (double)(r * h) / (double)nh;
        double y1 = (double)((r + 1) * h) / (double)nh;
        int ystart = (int)y0;
        int yend = (int)ceil(y1); if (yend > h) yend = h;
        for (int c = 0; c < nw; c++) {
            double x0 = (double)(c * w) / (double)nw;
            double x1 = (double)((c + 1) * w) / (double)nw;
            int xstart = (int)x0;
            int xend = (int)ceil(x1); if (xend > w) xend = w;
            double acc = 0.0, area = 0.0;
            for (int y = ystart; y < yend; y++) {
                double wy = ((y + 1) < y1 ? (y + 1) : y1) - ((double)y > y0 ? (double)y : y0);
                if (wy <= 0) continue;
                const unsigned char *line = grid + (size_t)y * w;
                for (int x = xstart; x < xend; x++) {
                    double wx = ((x + 1) < x1 ? (x + 1) : x1) - ((double)x > x0 ? (double)x : x0);
                    if (wx <= 0) continue;
                    double a = wy * wx;
                    area += a;
                    acc += a * line[x];
                }
            }
            out[(size_t)r * nw + c] = to_alpha(area != 0.0 ? (int)nearbyint(acc / area) : 0);
        }
    }
}

/* Nearest-neighbour over opacity, emitted through the same alpha path so only the
 * FILTER differs. Right for an UPscale: at 4/3 the box filter spreads every stem
 * across a fractional pixel and reads soft, where nn keeps stems at full opacity.
 * At exactly 2.0 the two are byte-identical -- each destination cell falls wholly
 * inside one source pixel -- so 4K is a lossless pixel double either way. */
static void nn_resample(const unsigned char *grid, int w, int h, int nw, int nh,
                        cell_t *out)
{
    static int *cx; static size_t cxcap;
    static int *cy; static size_t cycap;
    cx = (int *)grow(cx, &cxcap, (size_t)nw, sizeof(int));
    cy = (int *)grow(cy, &cycap, (size_t)nh, sizeof(int));
    pick(w, nw, cx);
    pick(h, nh, cy);
    for (int r = 0; r < nh; r++) {
        const unsigned char *line = grid + (size_t)cy[r] * w;
        for (int c = 0; c < nw; c++)
            out[(size_t)r * nw + c] = to_alpha(line[cx[c]]);
    }
}

/* Uniformly scaled, and only valid because every pixel is alpha class.
 *
 * Note the terminator rule differs from rescale_sprite: the FINAL row here always
 * closes with nothing, never with a carried source terminator. The rows are
 * synthesised by the filter, so there is no source row to carry one from. */
static int rescale_font_sprite(const cont_t *c, const sprite_t *s, int nw, int nh,
                               int use_nn, buf_t *out)
{
    int w = (int)s->w, h = (int)s->h;

    static unsigned char *grid; static size_t gridcap;
    static cell_t *dst; static size_t dstcap2;
    static cell_t *row; static size_t rowcap;
    grid = (unsigned char *)grow(grid, &gridcap, (size_t)w * h, 1);
    dst  = (cell_t *)grow(dst, &dstcap2, (size_t)nw * nh, sizeof(cell_t));
    row  = (cell_t *)grow(row, &rowcap, (size_t)w, sizeof(cell_t));

    size_t p = s->data_offset;
    for (int r = 0; r < h; r++) {
        unsigned L; int term;
        if (decode_row(c->d, p, w, row, &L, &term) < 0) return -1;
        unsigned char *line = grid + (size_t)r * w;
        for (int x = 0; x < w; x++) line[x] = (unsigned char)opacity(&row[x]);
        p += L;
        if (p > c->len) return -1;
    }
    if (p >= c->len || c->d[p] != 0xC0) return -1;

    if (use_nn) nn_resample(grid, w, h, nw, nh, dst);
    else        box_resample(grid, w, h, nw, nh, dst);

    for (int r = 0; r < nh; r++)
        if (emit_row(dst + (size_t)r * nw, nw, r == nh - 1 ? -1 : 0x00, out) < 0) return -1;
    buf_u8(out, 0xC0);
    return 0;
}

/* ------------------------------------------------------------------ the hash */

/* The game's toupper at 0x4eb270. It also upcases bytes >= 0xF0, which a library
 * toupper() will not do -- and a lowercase variant of this hash scores 0 matches
 * against the archives, so this is not a detail that can be approximated. */
static unsigned game_toupper(unsigned c)
{
    return ((c >= 0x61 && c <= 0x7A) || c >= 0xF0) ? c - 0x20 : c;
}

unsigned ag_name_hash(const char *s)
{
    unsigned h = 7;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        h = h * 0x41C64E6Eu + game_toupper(*p) + 0x3039u;
    return h;
}

/* ----------------------------------------------------------------- the index */


static void map_put(ag_index *ix, unsigned hash, size_t idx)
{
    size_t m = ix->mapcap, i = hash & (m - 1);
    /* LAST WRITER WINS, matching the Python's `idx[e['hash']] = e` over the archive
     * list in order -- a later archive shadows an earlier one's entry. */
    for (;;) {
        if (!ix->map[i]) { ix->map[i] = (unsigned)(idx + 1); return; }
        if (ix->ent[ix->map[i] - 1].hash == hash) { ix->map[i] = (unsigned)(idx + 1); return; }
        i = (i + 1) & (m - 1);
    }
}

static const ag_entry *map_get(const ag_index *ix, unsigned hash)
{
    size_t m = ix->mapcap, i = hash & (m - 1);
    for (;;) {
        if (!ix->map[i]) return NULL;
        const ag_entry *e = &ix->ent[ix->map[i] - 1];
        if (e->hash == hash) return e;
        i = (i + 1) & (m - 1);
    }
}

unsigned char *ag_slurp(const char *path, size_t *len)
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

static int name_cmp(const void *a, const void *b)
{ return strcmp(*(char *const *)a, *(char *const *)b); }

static void names_add(ag_names *s, const char *n)
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
static void names_finish(ag_names *s)
{
    if (!s->n) return;
    qsort(s->v, s->n, sizeof *s->v, name_cmp);
    size_t w = 1;
    for (size_t i = 1; i < s->n; i++)
        if (strcmp(s->v[i], s->v[w-1])) s->v[w++] = s->v[i];
    s->n = w;
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

static void scan_imm(const unsigned char *d, size_t len, ag_names *out)
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


/* Python's round(): nearest, TIES TO EVEN. nearbyint under the default rounding mode
 * is exactly that. A plain (int)(x+0.5) is a DIFFERENT function and would disagree with
 * the oracle on any tie -- which is how sprite dimensions are derived, so a single
 * disagreement changes a whole sprite's size. */
static int py_round(double v) { return (int)nearbyint(v); }

/* ==================================================================== the API
 *
 * Everything above is carried across from the probes. Everything below is new: the
 * index/harvest wrappers, the CONTAINER WRITER, and the set driver.
 */

static const char *ARCHIVES[4] = { "px.PK2", "px2.PK2", "px3.PK2", "px4.PK2" };

unsigned ag_name_hash_public(const char *n) { return ag_name_hash(n); }

const ag_entry *ag_lookup(const ag_index *ix, const char *name)
{ return map_get(ix, ag_name_hash(name)); }

int ag_index_load(ag_index *ix, const char *datadir)
{
    memset(ix, 0, sizeof *ix);
    snprintf(ix->dir, sizeof ix->dir, "%s", datadir);
    int narch = 0;
    for (int a = 0; a < 4; a++) {
        snprintf(ix->paths[a], sizeof ix->paths[a], "%s/%s", datadir, ARCHIVES[a]);
        FILE *f = fopen(ix->paths[a], "rb");
        ix->present[a] = f != NULL;
        if (f) { fclose(f); narch++; }
    }
    if (!narch) return -1;

    size_t cap = 0;
    for (int a = 0; a < 4; a++) {
        if (!ix->present[a]) continue;
        FILE *f = fopen(ix->paths[a], "rb");
        unsigned char head[8];
        if (fread(head, 1, 8, f) != 8) { fclose(f); return -1; }
        /* magic 1000, and the count that sizes the 13-byte entry table */
        if (rd32(head, 0) != 1000) { fclose(f); return -1; }
        unsigned count = rd32(head, 4);
        unsigned char *raw = (unsigned char *)malloc((size_t)13 * count + 1);
        if (!raw || fread(raw, 1, (size_t)13 * count, f) != (size_t)13 * count)
        { free(raw); fclose(f); return -1; }
        fclose(f);
        /* Offsets are RELATIVE to the data region (FINDINGS 19). Absolute reads give
         * plausible garbage rather than an error, which is how it was first missed. */
        size_t data_start = 8 + (size_t)13 * count;
        if (ix->nent + count > cap) {
            while (cap < ix->nent + count) cap = cap ? cap * 2 : 4096;
            ix->ent = (ag_entry *)realloc(ix->ent, cap * sizeof *ix->ent);
            if (!ix->ent) { free(raw); return -1; }
        }
        for (unsigned i = 0; i < count; i++) {
            ag_entry e;
            e.hash    = rd32(raw, 13 * (size_t)i);
            e.size    = rd32(raw, 13 * (size_t)i + 4);
            e.offset  = (unsigned)(data_start + rd32(raw, 13 * (size_t)i + 8));
            e.archive = a;
            ix->ent[ix->nent++] = e;
        }
        free(raw);
    }
    ix->mapcap = 1; while (ix->mapcap < ix->nent * 2) ix->mapcap *= 2;
    ix->map = (unsigned *)calloc(ix->mapcap, sizeof *ix->map);
    if (!ix->map) return -1;
    for (size_t i = 0; i < ix->nent; i++) map_put(ix, ix->ent[i].hash, i);
    return 0;
}

void ag_index_free(ag_index *ix) { free(ix->ent); free(ix->map); memset(ix, 0, sizeof *ix); }
void ag_names_free(ag_names *s)
{ for (size_t i = 0; i < s->n; i++) free(s->v[i]); free(s->v); memset(s, 0, sizeof *s); }
void ag_assets_free(ag_assets *a)
{ for (size_t i = 0; i < a->n; i++) free(a->name[i]); free(a->name); free(a->src);
  free(a->from_i06); memset(a, 0, sizeof *a); }

/* All three name sources. The exe alone yields 51; the .WIN records inside the
 * archives take it to 98 (FINDINGS 48.2); the numeric families take it to 280, of
 * which 183 are brNN and 182 of those appear in no file at all (FINDINGS 90). */
int ag_harvest(const ag_index *ix, const char *exepath, ag_names *out)
{
    memset(out, 0, sizeof *out);
    size_t exelen; unsigned char *exe = ag_slurp(exepath, &exelen);
    if (!exe) return -1;
    scan_imm(exe, exelen, out);
    free(exe);
    names_finish(out);

    for (int a = 0; a < 4; a++) {
        if (!ix->present[a]) continue;
        size_t blen; unsigned char *blob = ag_slurp(ix->paths[a], &blen);
        if (!blob) return -1;
        for (size_t i = 0; i < ix->nent; i++) {
            if (ix->ent[i].archive != a) continue;
            size_t off = ix->ent[i].offset, sz = ix->ent[i].size;
            if (sz < 4 || off + sz > blen) continue;
            if (rd32(blob, off) != 0x7d0) continue;      /* not a .WIN record */
            scan_imm(blob + off, sz, out);
        }
        free(blob);
    }
    names_finish(out);

    ag_names fam; memset(&fam, 0, sizeof fam);
    for (size_t i = 0; i < out->n; i++) {
        const char *n = out->v[i];
        size_t L = strlen(n);
        if (L < 6 || strcmp(n + L - 4, ".imm")) continue;
        size_t stem = L - 4, p = 0;
        while (p < stem && ((n[p] >= 'A' && n[p] <= 'Z') || (n[p] >= 'a' && n[p] <= 'z')
                            || n[p] == '_')) p++;
        if (p == 0 || p == stem) continue;
        size_t q = p;
        while (q < stem && n[q] >= '0' && n[q] <= '9') q++;
        if (q != stem) continue;
        char prefix[64];
        if (p >= sizeof prefix) continue;
        memcpy(prefix, n, p); prefix[p] = 0;
        for (int k = 0; k < 1000; k++) {
            char cand[96], probe[128];
            snprintf(cand, sizeof cand, "%s%02d", prefix, k);
            snprintf(probe, sizeof probe, "%s.i16", cand);
            if (map_get(ix, ag_name_hash(probe))) {
                char immn[128];
                snprintf(immn, sizeof immn, "%s.imm", cand);
                names_add(&fam, immn);
            }
        }
    }
    for (size_t i = 0; i < fam.n; i++) names_add(out, fam.v[i]);
    ag_names_free(&fam);
    names_finish(out);
    return 0;
}

static void assets_add(ag_assets *a, const char *name, const ag_entry *e, int from_i06)
{
    if (a->n == a->cap) {
        a->cap = a->cap ? a->cap * 2 : 512;
        a->name     = (char **)realloc(a->name, a->cap * sizeof *a->name);
        a->src      = (const ag_entry **)realloc(a->src, a->cap * sizeof *a->src);
        a->from_i06 = (int *)realloc(a->from_i06, a->cap * sizeof *a->from_i06);
    }
    a->name[a->n] = strdup(name);
    a->src[a->n] = e;
    a->from_i06[a->n] = from_i06;
    a->n++;
}

static int assets_has(const ag_assets *a, const char *n)
{
    for (size_t i = 0; i < a->n; i++) if (!strcmp(a->name[i], n)) return 1;
    return 0;
}

int ag_resolve(const ag_index *ix, const ag_names *names, int with_menu, ag_assets *out)
{
    memset(out, 0, sizeof *out);
    for (int pass = 0; pass < (with_menu ? 2 : 1); pass++) {
        const char *src_ext = pass ? "i06" : "i16";
        for (size_t i = 0; i < names->n; i++) {
            const char *n = names->v[i];
            size_t L = strlen(n);
            char base[128], src[160], outn[160];
            if (L < 5 || L - 4 >= sizeof base) continue;
            memcpy(base, n, L - 4); base[L - 4] = 0;
            snprintf(src, sizeof src, "%s.%s", base, src_ext);
            const ag_entry *e = map_get(ix, ag_name_hash(src));
            if (!e) continue;
            snprintf(outn, sizeof outn, "%s.i16", base);
            if (pass) {
                /* missing_only: FINDINGS 69.5, the seven assets that exist ONLY as
                 * .i06 because PopTop authored the menu, credits and folder screens
                 * at 640x480. Appended AFTER the sorted main list, not merged into
                 * it -- the order is part of what the oracle checks. */
                char i16[160]; snprintf(i16, sizeof i16, "%s.i16", base);
                if (map_get(ix, ag_name_hash(i16))) continue;
                if (assets_has(out, outn)) continue;
            }
            assets_add(out, outn, e, pass);
        }
    }
    return 0;
}

/* ------------------------------------------------------- the container writer
 *
 * The layout, from the Python's rescale():
 *
 *   [0 .. table_base)   header, copied verbatim -- including the seven REGION START
 *                       offsets at 0x07, which do not move
 *   table               `count` records of 15 bytes; the two u32 at +7 and +11 are
 *                       both rewritten to the new payload length
 *   blocks              per sprite: 13-byte record {size,x,y,w,h,fmt} then payload
 *   0x23 + 4*i          the seven REGION END offsets, all set to the FINAL FILE SIZE
 *
 * A sprite that is not fmt 2, or has a zero dimension, is copied through untouched --
 * geometry included. Everything else is rescaled and its x/y/w/h scaled with it.
 */
unsigned char *ag_rescale_container(const unsigned char *d, size_t len,
                                    int to_w, int to_h, int from_w, int from_h,
                                    double font_scale, int font_nn, size_t *out_len)
{
    cont_t c; c.sprites = NULL;
    if (cont_parse(&c, d, len) < 0) return NULL;
    if (!c.exact) { free(c.sprites); return NULL; }   /* glastube: sections outside the chain */

    double xs = (double)to_w / (double)from_w, ys = (double)to_h / (double)from_h;
    int font = is_font(&c);
    if (font) { xs = font_scale; ys = font_scale; }

    buf_t table = {0}, blocks = {0};
    for (unsigned i = 0; i < c.count; i++) {
        sprite_t *s = &c.sprites[i];
        buf_t pay = {0};
        int nw, nh, nx, ny;
        if (s->fmt != 2 || s->w == 0 || s->h == 0) {
            buf_add(&pay, d + s->data_offset, s->size);
            nw = (int)s->w; nh = (int)s->h; nx = s->x; ny = s->y;
        } else {
            nw = py_round((double)s->w * xs); if (nw < 1) nw = 1;
            nh = py_round((double)s->h * ys); if (nh < 1) nh = 1;
            nx = py_round((double)s->x * xs);
            ny = py_round((double)s->y * ys);
            int rc = font ? rescale_font_sprite(&c, s, nw, nh, font_nn, &pay)
                          : rescale_sprite(&c, s, nw, nh, &pay);
            if (rc < 0) { free(pay.p); free(table.p); free(blocks.p); free(c.sprites); return NULL; }
        }
        /* the 15-byte table record, with both length fields rewritten */
        unsigned char t[15];
        memcpy(t, d + c.table_base + 15 * (size_t)i, 15);
        unsigned pl = (unsigned)pay.n;
        t[7]=pl; t[8]=pl>>8; t[9]=pl>>16; t[10]=pl>>24;
        t[11]=pl; t[12]=pl>>8; t[13]=pl>>16; t[14]=pl>>24;
        buf_add(&table, t, 15);

        unsigned char h[13];
        h[0]=pl; h[1]=pl>>8; h[2]=pl>>16; h[3]=pl>>24;
        h[4]=(unsigned char)(nx & 0xff); h[5]=(unsigned char)((nx >> 8) & 0xff);
        h[6]=(unsigned char)(ny & 0xff); h[7]=(unsigned char)((ny >> 8) & 0xff);
        h[8]=(unsigned char)(nw & 0xff); h[9]=(unsigned char)((nw >> 8) & 0xff);
        h[10]=(unsigned char)(nh & 0xff); h[11]=(unsigned char)((nh >> 8) & 0xff);
        h[12]=(unsigned char)s->fmt;
        buf_add(&blocks, h, 13);
        buf_add(&blocks, pay.p, pay.n);
        free(pay.p);
    }

    buf_t out = {0};
    buf_add(&out, d, c.table_base);
    buf_add(&out, table.p, table.n);
    buf_add(&out, blocks.p, blocks.n);
    free(table.p); free(blocks.p); free(c.sprites);

    unsigned total = (unsigned)out.n;
    for (int i = 0; i < 7; i++) {
        size_t o = 0x23 + 4 * (size_t)i;
        out.p[o]=total; out.p[o+1]=total>>8; out.p[o+2]=total>>16; out.p[o+3]=total>>24;
    }
    *out_len = out.n;
    return out.p;
}

/* The running executable's path. On Windows that is the module the game is actually
 * running, which is what the .imm names have to be read out of; elsewhere there is no
 * such notion and the probes pass a path explicitly, so this simply fails and the
 * caller falls back. */
#ifdef _WIN32
__declspec(dllimport) unsigned long __stdcall GetModuleFileNameA(void *, char *, unsigned long);
static int ag_exe_path(char *out, size_t n)
{ return GetModuleFileNameA(0, out, (unsigned long)n) > 0; }
#else
static int ag_exe_path(char *out, size_t n) { (void)out; (void)n; return 0; }
#endif

/* --------------------------------------------------------------- the set driver
 *
 * THE CACHE KEY IS THE MODE, AND ONLY THE MODE. The staged-set world needed a
 * separate font-scale stamp beside each set (FINDINGS 86) because the scale was a
 * command-line option that could differ between two runs at the same resolution.
 * Here it cannot: the generator derives font_scale from the mode as H/1080, so two
 * runs at the same mode produce the same set by construction. One key, no stamp.
 *
 * The marker stays `data\ARTSET-MODE.txt` holding "WxH", which is the format
 * tools/tropico-setmode.sh already writes and tools/tropico already reads. That is
 * deliberate: on Linux the launcher stages a set and writes the marker before the
 * game starts, so ag_set_is_current() finds a match and this code does nothing at
 * all. Runtime generation is for the platform with no launcher.
 */

static int ag_read_marker(const char *gamedir, char *out, size_t n)
{
    char path[2048];
    snprintf(path, sizeof path, "%s/data/ARTSET-MODE.txt", gamedir);
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    size_t got = fread(out, 1, n - 1, f);
    fclose(f);
    out[got] = 0;
    while (got && (out[got-1] == '\n' || out[got-1] == '\r' || out[got-1] == ' '))
        out[--got] = 0;
    return 1;
}

int ag_set_is_current(const char *gamedir, int to_w, int to_h, double font_scale)
{
    (void)font_scale;                       /* derived from the mode -- see above */
    char have[64], want[64];
    if (!ag_read_marker(gamedir, have, sizeof have)) return 0;
    snprintf(want, sizeof want, "%dx%d", to_w, to_h);
    return strcmp(have, want) == 0;
}

int ag_generate_set(const char *gamedir, int to_w, int to_h, double font_scale,
                    int font_nn, void (*log)(const char *))
{
    char msg[512], datadir[2048], exepath[2048], path[2048];
    snprintf(datadir, sizeof datadir, "%s/data", gamedir);

    /* The running module, not a guessed name: the exe is Tropico.EXE on GOG but a
     * test harness may be running something else entirely, and the .imm names are
     * read out of whichever binary is actually live. */
    if (!ag_exe_path(exepath, sizeof exepath))
        snprintf(exepath, sizeof exepath, "%s/Tropico.EXE", gamedir);

    ag_index ix;
    if (ag_index_load(&ix, datadir) < 0) {
        if (log) log("[x] artgen: no PK2 archives found -- leaving the art alone");
        return -1;
    }
    ag_names names;
    if (ag_harvest(&ix, exepath, &names) < 0) {
        if (log) log("[x] artgen: could not read the executable for asset names");
        ag_index_free(&ix);
        return -1;
    }
    ag_assets as;
    ag_resolve(&ix, &names, 1, &as);

    unsigned char *blob[4] = {0}; size_t blen[4] = {0};
    for (int a = 0; a < 4; a++)
        if (ix.present[a]) blob[a] = ag_slurp(ix.paths[a], &blen[a]);

    /* Write the manifest as we go. Uninstall removes generated art BY MANIFEST and
     * never by glob -- a glob over *.i16 would also sweep up anything the game ships
     * loose, and deleting PopTop's own art is not recoverable without a reinstall. */
    char manpath[2048];
    snprintf(manpath, sizeof manpath, "%s/data/ARTSET-MANIFEST.txt", gamedir);
    FILE *man = fopen(manpath, "wb");

    size_t ok = 0, skipped = 0, failed = 0;
    for (size_t i = 0; i < as.n; i++) {
        const ag_entry *e = as.src[i];
        if (!blob[e->archive] || (size_t)e->offset + e->size > blen[e->archive]) { failed++; continue; }
        int fw = as.from_i06[i] ? 640 : 1600, fh = as.from_i06[i] ? 480 : 1200;
        size_t olen;
        unsigned char *o = ag_rescale_container(blob[e->archive] + e->offset, e->size,
                                                to_w, to_h, fw, fh, font_scale, font_nn, &olen);
        if (!o) { skipped++; continue; }     /* sections outside the sprite chain */
        snprintf(path, sizeof path, "%s/data/%s", gamedir, as.name[i]);
        FILE *f = fopen(path, "wb");
        if (f) {
            int wrote = fwrite(o, 1, olen, f) == olen;
            fclose(f);
            if (wrote) { ok++; if (man) fprintf(man, "%s\n", as.name[i]); }
            else failed++;
        } else failed++;
        free(o);
    }
    if (man) fclose(man);

    /* THE STOCK-CLASS MENU ASSETS (FINDINGS 69.5). Seven assets exist ONLY as .i06,
     * because PopTop authored the menu, the credits and the folder screens at 640x480
     * and nothing else. Without them the menu dies with
     *
     *     Error opening pack file item 'setuplb.i16'
     *
     * the moment it is asked to run at any other resolution. They are MODE-INDEPENDENT
     * -- fixed sizes for slots 1-3 -- so they are keyed on their own manifest rather
     * than on the mode marker, and generated once.
     *
     * Folded into this pass rather than given their own entry point so the 1 GB
     * archive walk happens once. The installer used to do this in Python; moving it
     * here is what lets the installer drop its interpreter entirely. */
    char statpath[2048];
    snprintf(statpath, sizeof statpath, "%s/data/ARTSET-STATIC.txt", gamedir);
    FILE *chk = fopen(statpath, "rb");
    if (chk) fclose(chk);
    else {
        static const struct { const char *ext; int w, h; } SLOTS[3] =
            { { "i08", 800, 600 }, { "i10", 1024, 768 }, { "i12", 1280, 1024 } };
        FILE *sm = fopen(statpath, "wb");
        size_t sok = 0;
        for (size_t i = 0; i < as.n; i++) {
            if (!as.from_i06[i]) continue;          /* only the .i06-only seven */
            const ag_entry *e = as.src[i];
            if (!blob[e->archive]) continue;
            char base[160];
            snprintf(base, sizeof base, "%s", as.name[i]);
            char *dot = strrchr(base, '.'); if (dot) *dot = 0;
            for (int k = 0; k < 3; k++) {
                size_t sl;
                unsigned char *so = ag_rescale_container(blob[e->archive] + e->offset,
                                                         e->size, SLOTS[k].w, SLOTS[k].h,
                                                         640, 480, 1.0, 0, &sl);
                if (!so) continue;
                char sp[2048];
                snprintf(sp, sizeof sp, "%s/data/%s.%s", gamedir, base, SLOTS[k].ext);
                FILE *sf = fopen(sp, "wb");
                if (sf) {
                    if (fwrite(so, 1, sl, sf) == sl && sm)
                    { fprintf(sm, "%s.%s\n", base, SLOTS[k].ext); sok++; }
                    fclose(sf);
                }
                free(so);
            }
        }
        if (sm) fclose(sm);
        if (log) {
            snprintf(msg, sizeof msg, "[+] artgen: %zu stock-class menu asset(s) for"
                     " slots 1-3 (they exist only at 640x480 -- FINDINGS 69.5)", sok);
            log(msg);
        }
    }

    for (int a = 0; a < 4; a++) free(blob[a]);
    ag_assets_free(&as); ag_names_free(&names); ag_index_free(&ix);

    /* The marker LAST, and only on success. An interrupted run then leaves a marker
     * that does not match, so the next launch regenerates rather than trusting a
     * half-written set -- the same reasoning as tropico-setmode.sh staging into a
     * .tmp directory and renaming only when complete. */
    if (failed || !ok) {
        if (log) { snprintf(msg, sizeof msg,
            "[x] artgen: %zu written, %zu failed -- marker NOT written, so the next"
            " launch will try again", ok, failed); log(msg); }
        return -1;
    }
    snprintf(path, sizeof path, "%s/data/ARTSET-MODE.txt", gamedir);
    FILE *mk = fopen(path, "wb");
    if (mk) { fprintf(mk, "%dx%d\n", to_w, to_h); fclose(mk); }

    if (log) {
        snprintf(msg, sizeof msg, "[+] artgen: generated %zu assets for %dx%d"
                 " (font scale %.6f%s), %zu skipped", ok, to_w, to_h, font_scale,
                 font_nn ? ", nearest" : ", box", skipped);
        log(msg);
    }
    return (int)ok;
}

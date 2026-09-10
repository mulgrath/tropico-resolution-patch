/* Runtime UI art generation -- see artgen.h for why this file is shared between the
 * probes and the proxy rather than copied into each.
 *
 * The codec, the resampling and the name harvest below are carried across VERBATIM
 * from the probes that validated them (see ../dev/FINDINGS.md): 25,820 sprites
 * byte-identical to tools/tropico-artset.py across four font scales and both filters,
 * and 280 names / 268 resolved assets identical to the Python harvest. Moving them was a cut and paste,
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
#include <dirent.h>

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

/* Row framing: b < 0x80 -> a 1-byte header declaring length b;
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
 * FONTS ARE DIFFERENT ON TWO INDEPENDENT COUNTS, both measured against the archives:
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


/* ----------------------------------------------- a larger master, scaled uniformly
 *
 * FINDINGS 141. A font scaled UP is drawn from a LARGER SIZE THE GAME ALREADY SHIPS,
 * scaled by ONE factor for the whole font rather than fitted glyph by glyph. §130's
 * path did the latter and made round capitals two rows taller than flat ones (§135);
 * a single factor cannot, because every glyph keeps the master's own proportions.
 *
 * The factor equals the ADVANCES: master_factor() is font_scale times the small
 * font's total advance over A-Z and 0-9 divided by the master's, so a line of text
 * comes out the width the plain resample would draw. Three bands follow from it:
 *
 *   f in [1, 1+SNAP_UP]   snap to exactly 1 and COPY THE MASTER VERBATIM. This is the
 *                         good case: PopTop's own hinted bitmap, never resampled, no
 *                         blended columns at all. The glyph lands a few percent
 *                         smaller than the resample would draw it, which is the price.
 *   f <= DOWN_MAX         a genuine downscale, which is what a box filter is for.
 *   otherwise             no master; the plain resample stands.
 *
 * The gap between DOWN_MAX and 1 is deliberate. A factor of 0.95 keeps every source
 * pixel while blending roughly every other column and leaving the rest 1:1, so one
 * glyph has crisp sides and the next has soft ones -- the owner saw exactly that on
 * the first cut (copp8 from copp12 at 0.918) and called it artifacts on the sides of
 * characters. Snapping UP instead is refused because it widens every string.
 *
 * CAP_MAX is a second guard on the snap. The factor equals the advances, but the eye
 * reads cap height, and two sizes of a hinted face do not share a height-to-width
 * ratio. copp8 from copp10 at 1440p is 7.7% shorter and the owner passed it in game;
 * copp6 from copp12 at 4K would be 10.0% shorter, past anything verified, so it is
 * refused and the resample stands (at 2.0 that resample is an exact pixel double).
 *
 * The family gate is §130's, unchanged: a translation pack's repainted master is not
 * the same face and scores far below it, so the pack keeps the plain resample. */

#ifndef MASTER_FAMILY_MIN
#define MASTER_FAMILY_MIN 0.72   /* between a wrong face and the weakest genuine one */
#endif
#define MASTER_SNAP_UP    0.08
#define MASTER_DOWN_MAX   0.92
#define MASTER_CAP_MAX    0.08

static int py_round(double v);          /* defined with the name harvest below */

/* The container's glyph as an opacity grid. */
static int glyph_grid(const cont_t *c, const sprite_t *s, unsigned char **grid_out)
{
    int w = (int)s->w, h = (int)s->h;
    static unsigned char *grid; static size_t gridcap;
    static cell_t *row; static size_t rowcap;
    grid = (unsigned char *)grow(grid, &gridcap, (size_t)w * h, 1);
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
    *grid_out = grid;
    return 0;
}

static double cells_correlation(const cell_t *a, const cell_t *b, size_t n)
{
    double ma = 0, mb = 0;
    for (size_t i = 0; i < n; i++) { ma += opacity(&a[i]); mb += opacity(&b[i]); }
    ma /= (double)n; mb /= (double)n;
    double num = 0, da = 0, db = 0;
    for (size_t i = 0; i < n; i++) {
        double x = opacity(&a[i]) - ma, y = opacity(&b[i]) - mb;
        num += x * y; da += x * x; db += y * y;
    }
    if (da <= 0 || db <= 0) return 0.0;
    return num / sqrt(da * db);
}

/* A sprite that carries real geometry. Matches the Python's real_sprites(). */
static int sprite_real(const sprite_t *s) { return s->fmt == 2 && s->w > 0 && s->h > 0; }

/* font_scale * (sum of the small font's advances) / (the master's), over A-Z and 0-9
 * present in both. Sprite index is the character code minus 32 (FINDINGS 137.1). */
static double master_factor(const cont_t *c, const cont_t *m, double font_scale)
{
    long a = 0, b = 0;
    for (int code = 48; code <= 90; code++) {
        if (code > 57 && code < 65) continue;
        unsigned i = (unsigned)(code - 32);
        if (i >= c->count || i >= m->count) continue;
        const sprite_t *s = &c->sprites[i], *t = &m->sprites[i];
        if (!sprite_real(s) || !sprite_real(t)) continue;
        a += s->x + (int)s->w;
        b += t->x + (int)t->w;
    }
    return (a && b) ? font_scale * (double)a / (double)b : 0.0;
}

/* (master's H ink height at f) / (the resample's) - 1. H is a flat capital: no
 * overshoot, present in every asset, and the height a line is read by. */
static double cap_error(const cont_t *c, const cont_t *m, double f, double font_scale)
{
    unsigned i = (unsigned)('H' - 32);
    if (i >= c->count || i >= m->count) return 0.0;
    const sprite_t *s = &c->sprites[i], *t = &m->sprites[i];
    if (!sprite_real(s) || !sprite_real(t)) return 0.0;
    double want = (double)s->h * font_scale;
    return want ? (double)t->h * f / want - 1.0 : 0.0;
}

/* The family gate: median correlation of the master box-fitted into the small glyph's
 * scaled cell against the small glyph's own resample, over glyphs 4 px or larger. */
static double family_score(const cont_t *c, const cont_t *m, double font_scale)
{
    static cell_t *base; static size_t basecap;
    static cell_t *cand; static size_t candcap;
    static double *sorted; static size_t sortcap;
    size_t n = 0;
    sorted = (double *)grow(sorted, &sortcap, c->count ? c->count : 1, sizeof(double));
    for (unsigned i = 0; i < c->count; i++) {
        if (i >= m->count) continue;
        const sprite_t *s = &c->sprites[i], *t = &m->sprites[i];
        if (!sprite_real(s) || !sprite_real(t) || s->w < 4 || s->h < 4) continue;
        int nw = py_round((double)s->w * font_scale); if (nw < 1) nw = 1;
        int nh = py_round((double)s->h * font_scale); if (nh < 1) nh = 1;
        unsigned char *g;
        base = (cell_t *)grow(base, &basecap, (size_t)nw * nh, sizeof(cell_t));
        cand = (cell_t *)grow(cand, &candcap, (size_t)nw * nh, sizeof(cell_t));
        if (glyph_grid(c, s, &g) < 0) continue;
        box_resample(g, (int)s->w, (int)s->h, nw, nh, base);
        if (glyph_grid(m, t, &g) < 0) continue;
        box_resample(g, (int)t->w, (int)t->h, nw, nh, cand);
        sorted[n++] = cells_correlation(base, cand, (size_t)nw * nh);
    }
    if (n < 8) return -1.0;
    for (size_t i = 1; i < n; i++) {          /* insertion sort: 224 values at most */
        double v = sorted[i]; size_t j = i;
        while (j > 0 && sorted[j-1] > v) { sorted[j] = sorted[j-1]; j--; }
        sorted[j] = v;
    }
    return sorted[n / 2];
}

/* The grid, whose top-left source pixel sits at (ox, oy) in stock pen units, scaled by
 * f ABOUT THE PEN ORIGIN. Output pixels are the integer grid of the scaled space, so
 * every glyph's baseline and cap line land at the same fractional phase -- which is
 * what makes the result uniform where §135's per-cell fit was not.
 *
 * THE FLOATING POINT IS LOAD-BEARING, exactly as in box_resample: the oracle is
 * byte-identity against the Python, so the expression forms, the accumulation order
 * and the ties-to-even rounding are all part of the contract. */
static void box_resample_at(const unsigned char *grid, int w, int h, double f,
                            int ox, int oy, unsigned char *out, int *ox0, int *oy0,
                            int *onw, int *onh)
{
    int x0 = (int)floor((double)ox * f), x1 = (int)ceil((double)(ox + w) * f);
    int y0 = (int)floor((double)oy * f), y1 = (int)ceil((double)(oy + h) * f);
    int nw = x1 - x0, nh = y1 - y0;
    for (int r = y0; r < y1; r++) {
        double sy0 = (double)r / f - (double)oy, sy1 = (double)(r + 1) / f - (double)oy;
        int ystart = (int)floor(sy0); if (ystart < 0) ystart = 0;
        int yend = (int)ceil(sy1); if (yend > h) yend = h;
        for (int c = x0; c < x1; c++) {
            double sx0 = (double)c / f - (double)ox, sx1 = (double)(c + 1) / f - (double)ox;
            int xstart = (int)floor(sx0); if (xstart < 0) xstart = 0;
            int xend = (int)ceil(sx1); if (xend > w) xend = w;
            double acc = 0.0, area = 0.0;
            for (int y = ystart; y < yend; y++) {
                double wy = ((y + 1) < sy1 ? (double)(y + 1) : sy1)
                          - ((double)y > sy0 ? (double)y : sy0);
                if (wy <= 0) continue;
                const unsigned char *line = grid + (size_t)y * w;
                for (int x = xstart; x < xend; x++) {
                    double wx = ((x + 1) < sx1 ? (double)(x + 1) : sx1)
                              - ((double)x > sx0 ? (double)x : sx0);
                    if (wx <= 0) continue;
                    area += wy * wx;
                    acc += wy * wx * line[x];
                }
            }
            out[(size_t)(r - y0) * nw + (c - x0)] =
                (unsigned char)(area != 0.0 ? (int)nearbyint(acc / area) : 0);
        }
    }
    *ox0 = x0; *oy0 = y0; *onw = nw; *onh = nh;
}

/* The master glyph scaled by f and placed in the resample's cell: the advance edge
 * nx+nw and the baseline are KEPT, so layout is the plain resample's to the byte. The
 * cell grows left or down where the master's ink needs it; ink past the advance slides
 * the glyph left rather than being cut. */
#define AG_MARKER 6

static int master_font_sprite(const cont_t *m, const sprite_t *t, double f,
                              int *pnx, int *pny, int *pnw, int *pnh, buf_t *out)
{
    static unsigned char *sc; static size_t sccap;
    static unsigned char *cell; static size_t cellcap;
    static cell_t *rowbuf; static size_t rowbufcap;
    int tw = (int)t->w, th = (int)t->h;
    unsigned char *g;
    if (glyph_grid(m, t, &g) < 0) return -1;

    /* The font tool stamped alpha-6 pixels in a cell's last column to force its extent
     * (FINDINGS 137.1): a marker, never ink -- every real coverage level is k*16-1.
     * The extent here is the resample's cell, so the marker is dropped before scaling
     * rather than scaled into a phantom column past the advance. */
    static unsigned char *src; static size_t srccap;
    src = (unsigned char *)grow(src, &srccap, (size_t)tw * th, 1);
    memcpy(src, g, (size_t)tw * th);
    for (int r = 0; r < th; r++)
        if (src[(size_t)r * tw + (tw - 1)] == AG_MARKER) src[(size_t)r * tw + (tw - 1)] = 0;

    int gx0, gy0, gw, gh;
    int cw = (int)ceil((double)(t->x + tw) * f) - (int)floor((double)t->x * f) + 2;
    int ch = (int)ceil((double)(t->y + th) * f) - (int)floor((double)t->y * f) + 2;
    sc = (unsigned char *)grow(sc, &sccap, (size_t)cw * ch, 1);
    box_resample_at(src, tw, th, f, t->x, t->y, sc, &gx0, &gy0, &gw, &gh);

    /* trim the empty columns the dropped marker left behind */
    while (gw > 1) {
        int empty = 1;
        for (int r = 0; r < gh; r++) if (sc[(size_t)r * gw + (gw - 1)]) { empty = 0; break; }
        if (!empty) break;
        for (int r = 1; r < gh; r++)
            memmove(sc + (size_t)r * (gw - 1), sc + (size_t)r * gw, (size_t)(gw - 1));
        gw--;
    }

    int nx = *pnx, ny = *pny, nw = *pnw, nh = *pnh;
    int right = nx + nw;
    int x0 = nx < gx0 ? nx : gx0;
    if (gx0 + gw > right) { gx0 = right - gw; if (gx0 < x0) x0 = gx0; }
    int y0 = ny < gy0 ? ny : gy0;
    int bottom = (ny + nh) > (gy0 + gh) ? (ny + nh) : (gy0 + gh);
    int W = right - x0, H = bottom - y0;
    if (W < 1 || H < 1) return -1;

    cell = (unsigned char *)grow(cell, &cellcap, (size_t)W * H, 1);
    memset(cell, 0, (size_t)W * H);
    for (int r = 0; r < gh; r++)
        memcpy(cell + (size_t)(gy0 - y0 + r) * W + (gx0 - x0), sc + (size_t)r * gw, (size_t)gw);

    rowbuf = (cell_t *)grow(rowbuf, &rowbufcap, (size_t)W, sizeof(cell_t));
    for (int r = 0; r < H; r++) {
        for (int c = 0; c < W; c++) rowbuf[c] = to_alpha(cell[(size_t)r * W + c]);
        if (emit_row(rowbuf, W, r == H - 1 ? -1 : 0x00, out) < 0) return -1;
    }
    buf_u8(out, 0xC0);
    *pnx = x0; *pny = y0; *pnw = W; *pnh = H;
    return 0;
}

/* Which band a candidate master falls in. -> 1 verbatim (f set to 1), 2 downscale, 0 no. */
static int master_band(const cont_t *c, const cont_t *m, double font_scale, double *f_out)
{
    double f = master_factor(c, m, font_scale);
    if (f <= 0.0) return 0;
    if (f >= 1.0 && f <= 1.0 + MASTER_SNAP_UP) {
        if (fabs(cap_error(c, m, 1.0, font_scale)) > MASTER_CAP_MAX) return 0;
        *f_out = 1.0;
        return 1;
    }
    if (f <= MASTER_DOWN_MAX) { *f_out = f; return 2; }
    return 0;
}

/* ------------------------------------------- which files are a font's candidates
 *
 * Font assets are named <face><size>.i16: comi07..comi24, copp6..copp12, cour03..08,
 * and singletons (haet46, nose61, scri25, sten10, time16) with nothing larger. EVERY
 * larger size of the same face is a candidate -- §130 picked by the point number, but
 * those numbers are not linear in pixels (FINDINGS 137.3) and that is how copp8 ended
 * up on copp12 at 0.918 instead of copp10 at 1.066. The caller measures each. */
static int font_family(const char *name, char *face, size_t facen, int *size)
{
    size_t i = 0, k = 0;
    while (name[i] && ((name[i] >= 'a' && name[i] <= 'z') || (name[i] >= 'A' && name[i] <= 'Z'))) {
        if (k + 1 < facen) face[k++] = name[i];
        i++;
    }
    face[k] = 0;
    if (k == 0 || name[i] < '0' || name[i] > '9') return 0;
    *size = 0;
    while (name[i] >= '0' && name[i] <= '9') { *size = *size * 10 + (name[i] - '0'); i++; }
    return name[i] == '.' || name[i] == 0;
}

int ag_font_master_next(const ag_assets *as, size_t i, int after_size)
{
    char face[32], f2[32]; int size, s2;
    if (!font_family(as->name[i], face, sizeof face, &size)) return -1;
    int best = -1, best_size = 0;
    for (size_t j = 0; j < as->n; j++) {
        if (j == i || !font_family(as->name[j], f2, sizeof f2, &s2)) continue;
        if (strcmp(face, f2) != 0 || s2 <= size || s2 <= after_size) continue;
        if (best < 0 || s2 < best_size) { best = (int)j; best_size = s2; }
    }
    return best;
}


/* Which master this asset should be drawn from, measured rather than named. Returns an
 * index into `as`, or -1. A VERBATIM copy beats any resample, so a candidate in the
 * snap band wins outright, nearest to 1 first; failing that the mildest genuine
 * downscale. The caller passes the blobs it already has. */
int ag_pick_master(const ag_assets *as, size_t i,
                   unsigned char *const *blob, const size_t *blen, double font_scale)
{
    if (font_scale <= 1.0) return -1;
    const ag_entry *e = as->src[i];
    if (!blob[e->archive] || (size_t)e->offset + e->size > blen[e->archive]) return -1;
    cont_t sc; sc.sprites = NULL;
    if (cont_parse(&sc, blob[e->archive] + e->offset, e->size) != 0 || !sc.exact
        || !is_font(&sc)) { free(sc.sprites); return -1; }

    int best_band = 0, mj = -1, after = 0, j; double best_f = 0.0;
    while ((j = ag_font_master_next(as, i, after)) >= 0) {
        char f2[32]; int s2;
        font_family(as->name[j], f2, sizeof f2, &s2);
        after = s2;
        const ag_entry *me = as->src[j];
        if (!blob[me->archive] || (size_t)me->offset + me->size > blen[me->archive]) continue;
        cont_t mc; mc.sprites = NULL;
        if (cont_parse(&mc, blob[me->archive] + me->offset, me->size) != 0 || !mc.exact) {
            free(mc.sprites); continue;
        }
        double f = 0.0;
        int band = master_band(&sc, &mc, font_scale, &f);
        free(mc.sprites);
        if (!band) continue;
        int better = !best_band || (band < best_band)
                  || (band == best_band && fabs(f - 1.0) < fabs(best_f - 1.0));
        if (better) { best_band = band; best_f = f; mj = j; }
    }
    free(sc.sprites);
    return mj;
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

unsigned ag_name_hash_public(const char *n) { return ag_name_hash(n); }

const ag_entry *ag_lookup(const ag_index *ix, const char *name)
{ return map_get(ix, ag_name_hash(name)); }

/* The exe's own enumeration, reproduced. FUN_004eee00 walks data\*.pk2 with
 * FindFirstFile, picking on each pass the smallest name greater than the last one
 * opened -- a selection sort by strcmp, independent of the order the filesystem
 * hands names back. So the load order is px.PK2, px2.PK2, px3.PK2, px3_cyrl.PK2,
 * px4.PK2 ('.' sorts before '2' and '_'), on Windows and under Wine alike, and the
 * later archive wins a hash collision. */
static int has_pk2_ext(const char *n)
{
    size_t L = strlen(n);
    if (L < 5) return 0;
    const char *e = n + L - 4;
    return e[0] == '.' && (e[1] == 'p' || e[1] == 'P') && (e[2] == 'k' || e[2] == 'K')
           && e[3] == '2';
}

static int cmp_names(const void *a, const void *b)
{ return strcmp((const char *)a, (const char *)b); }

/* Every *.pk2 in datadir, sorted the game's way. Returns the count. */
static int list_archives(const char *datadir, char names[][64], unsigned *sizes)
{
    DIR *d = opendir(datadir);
    if (!d) return 0;
    int n = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL && n < AG_MAX_ARCHIVES) {
        if (!has_pk2_ext(de->d_name) || strlen(de->d_name) >= 64) continue;
        snprintf(names[n], 64, "%s", de->d_name);
        n++;
    }
    closedir(d);
    qsort(names, (size_t)n, 64, cmp_names);
    for (int i = 0; i < n; i++) {
        char path[2048];
        snprintf(path, sizeof path, "%s/%s", datadir, names[i]);
        FILE *f = fopen(path, "rb");
        sizes[i] = 0;
        if (f) {
            if (fseek(f, 0, SEEK_END) == 0) { long L = ftell(f); if (L > 0) sizes[i] = (unsigned)L; }
            fclose(f);
        }
    }
    return n;
}

int ag_index_load(ag_index *ix, const char *datadir)
{
    memset(ix, 0, sizeof *ix);
    snprintf(ix->dir, sizeof ix->dir, "%s", datadir);
    ix->narch = list_archives(datadir, ix->names, ix->sizes);
    int narch = 0;
    for (int a = 0; a < ix->narch; a++) {
        snprintf(ix->paths[a], sizeof ix->paths[a], "%s/%s", datadir, ix->names[a]);
        FILE *f = fopen(ix->paths[a], "rb");
        ix->present[a] = f != NULL;
        if (f) { fclose(f); narch++; }
    }
    if (!narch) return -1;

    size_t cap = 0;
    for (int a = 0; a < ix->narch; a++) {
        if (!ix->present[a]) continue;
        FILE *f = fopen(ix->paths[a], "rb");
        unsigned char head[8];
        if (fread(head, 1, 8, f) != 8) { fclose(f); return -1; }
        /* magic 1000, and the count that sizes the 13-byte entry table. A file that
         * is not an archive at all is skipped, not fatal: the game's own loader
         * would reject it too, and one stray .pk2 must not turn the art off. */
        if (rd32(head, 0) != 1000) { fclose(f); ix->present[a] = 0; continue; }
        unsigned count = rd32(head, 4);
        unsigned char *raw = (unsigned char *)malloc((size_t)13 * count + 1);
        if (!raw || fread(raw, 1, (size_t)13 * count, f) != (size_t)13 * count)
        { free(raw); fclose(f); return -1; }
        fclose(f);
        /* Offsets are RELATIVE to the data region. Absolute reads give
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
 * archives take it to 98; the numeric families take it to 280, of
 * which 183 are brNN and 182 of those appear in no file at all. */
int ag_harvest(const ag_index *ix, const char *exepath, ag_names *out)
{
    memset(out, 0, sizeof *out);
    size_t exelen; unsigned char *exe = ag_slurp(exepath, &exelen);
    if (!exe) return -1;
    scan_imm(exe, exelen, out);
    free(exe);
    names_finish(out);

    for (int a = 0; a < ix->narch; a++) {
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
                /* missing_only: the seven assets that exist ONLY as
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
                                    double font_scale, int font_nn,
                                    const unsigned char *master, size_t master_len,
                                    ag_master_report *rep, size_t *out_len)
{
    cont_t c; c.sprites = NULL;
    if (cont_parse(&c, d, len) < 0) return NULL;
    if (!c.exact) { free(c.sprites); return NULL; }   /* glastube: sections outside the chain */

    double xs = (double)to_w / (double)from_w, ys = (double)to_h / (double)from_h;
    int font = is_font(&c);
    if (font) { xs = font_scale; ys = font_scale; }

    /* The uniform master. Only for a font being scaled UP, only when the family gate
     * passes, and only in one of the two usable bands (see master_band above). */
    cont_t m; m.sprites = NULL;
    int use_master = 0, band = 0; double mf = 0.0, score = -1.0;
    if (font && master && master_len && xs > 1.0 && cont_parse(&m, master, master_len) == 0
        && m.exact) {
        band = master_band(&c, &m, xs, &mf);
        if (band) {
            score = family_score(&c, &m, xs);
            use_master = (score >= MASTER_FAMILY_MIN);
        }
    }
    if (rep) { rep->taken = 0; rep->slid = 0; rep->band = use_master ? band : 0;
               rep->factor = mf; rep->median = score; }

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
            int rc = -1, took = 0;
            if (use_master && i < m.count && sprite_real(&m.sprites[i])) {
                int mx = nx, my = ny, mw = nw, mh = nh;
                rc = master_font_sprite(&m, &m.sprites[i], mf, &mx, &my, &mw, &mh, &pay);
                if (rc == 0) {
                    if (mx != nx) { if (rep) rep->slid++; }
                    nx = mx; ny = my; nw = mw; nh = mh; took = 1;
                    if (rep) rep->taken++;
                }
            }
            if (!took)
                rc = font ? rescale_font_sprite(&c, s, nw, nh, font_nn, &pay)
                          : rescale_sprite(&c, s, nw, nh, &pay);
            if (rc < 0) { free(pay.p); free(table.p); free(blocks.p); free(c.sprites);
                          free(m.sprites); return NULL; }
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
    free(table.p); free(blocks.p); free(c.sprites); free(m.sprites);

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
 * THE CACHE KEY IS THE MODE, AND ONLY THE MODE. The staged-set world (the Python
 * tooling this was ported from) needed a separate font-scale stamp beside each set
 * because there the scale was a command-line option that could differ between two
 * runs at the same resolution.
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
    /* CRLF-tolerant: a marker edited on Windows must still compare equal. */
    size_t w = 0;
    for (size_t i = 0; i < got; i++) if (out[i] != '\r') out[w++] = out[i];
    out[w] = 0;
    while (w && (out[w-1] == '\n' || out[w-1] == ' ')) out[--w] = 0;
    return 1;
}

/* THE ARCHIVES ARE PART OF THE KEY. A language pack drops a new archive into data\
 * and the fonts the game would use change under a set that was generated before
 * it arrived; removing the pack changes them back. Keying on the mode alone left the
 * stale set in place both ways. So the marker names every archive with its size, in
 * the order the game loads them, and any difference regenerates. */
int ag_marker_text(const char *datadir, int to_w, int to_h, char *out, size_t n)
{
    char names[AG_MAX_ARCHIVES][64]; unsigned sizes[AG_MAX_ARCHIVES];
    int na = list_archives(datadir, names, sizes);
    size_t L = (size_t)snprintf(out, n, "%dx%d", to_w, to_h);
    for (int a = 0; a < na && L < n; a++)
        L += (size_t)snprintf(out + L, n - L, "\n%s %u", names[a], sizes[a]);
    /* A REVISION LINE, so a set an older build left behind is rebuilt once on upgrade.
     * The uniform-master path (FINDINGS 141) changes the fonts at every scale above 1
     * without changing the mode or the archives, which the rest of the key covers. */
    if (L < n) L += (size_t)snprintf(out + L, n - L, "\nfonts uniform-master");
    return na;
}

int ag_set_is_current(const char *gamedir, int to_w, int to_h, double font_scale)
{
    (void)font_scale;                       /* derived from the mode -- see above */
    char have[4096], want[4096], datadir[2048];
    if (!ag_read_marker(gamedir, have, sizeof have)) return 0;
    snprintf(datadir, sizeof datadir, "%s/data", gamedir);
    ag_marker_text(datadir, to_w, to_h, want, sizeof want);
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

    unsigned char *blob[AG_MAX_ARCHIVES] = {0}; size_t blen[AG_MAX_ARCHIVES] = {0};
    for (int a = 0; a < ix.narch; a++) {
        if (!ix.present[a]) continue;
        blob[a] = ag_slurp(ix.paths[a], &blen[a]);
        if (log) {
            /* Named in the log because this is the line that says whether a
             * language pack's archive was seen at all. */
            snprintf(msg, sizeof msg, "    archive %d: %s (%u bytes)", a, ix.names[a], ix.sizes[a]);
            log(msg);
        }
    }

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

        const unsigned char *mp = NULL; size_t ml = 0;
        int mj = ag_pick_master(&as, i, blob, blen, font_scale);
        if (mj >= 0) {
            const ag_entry *me = as.src[mj];
            mp = blob[me->archive] + me->offset; ml = me->size;
        }

        size_t olen;
        ag_master_report rep;
        unsigned char *o = ag_rescale_container(blob[e->archive] + e->offset, e->size,
                                                to_w, to_h, fw, fh, font_scale, font_nn,
                                                mp, ml, &rep, &olen);
        if (!o) { skipped++; continue; }     /* sections outside the sprite chain */
        if (mp && log && rep.median >= 0) {
            if (rep.band == 1)
                snprintf(msg, sizeof msg, "    %s: %d glyph(s) COPIED VERBATIM from %s"
                         " (family score %.2f, %d slid)", as.name[i], rep.taken,
                         as.name[mj], rep.median, rep.slid);
            else if (rep.band == 2)
                snprintf(msg, sizeof msg, "    %s: %d glyph(s) from %s downscaled by %.3f"
                         " (family score %.2f, %d slid)", as.name[i], rep.taken,
                         as.name[mj], rep.factor, rep.median, rep.slid);
            else
                snprintf(msg, sizeof msg, "    %s: %s does not match it closely enough"
                         " (family score %.2f) -- plain resample", as.name[i],
                         as.name[mj], rep.median);
            log(msg);
        }
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

    /* THE STOCK-CLASS MENU ASSETS. Seven assets exist ONLY as .i06,
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
                                                         640, 480, 1.0, 0,
                                                         NULL, 0, NULL, &sl);
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
                     " slots 1-3 (they exist only at 640x480)", sok);
            log(msg);
        }
    }

    for (int a = 0; a < ix.narch; a++) free(blob[a]);
    ag_assets_free(&as); ag_names_free(&names);

    /* The marker LAST, and only on success. An interrupted run then leaves a marker
     * that does not match, so the next launch regenerates rather than trusting a
     * half-written set -- the same reasoning as tropico-setmode.sh staging into a
     * .tmp directory and renaming only when complete. */
    if (failed || !ok) {
        if (log) { snprintf(msg, sizeof msg,
            "[x] artgen: %zu written, %zu failed -- marker NOT written, so the next"
            " launch will try again", ok, failed); log(msg); }
        ag_index_free(&ix);
        return -1;
    }
    snprintf(path, sizeof path, "%s/data/ARTSET-MODE.txt", gamedir);
    FILE *mk = fopen(path, "wb");
    if (mk) {
        char marker[4096];
        ag_marker_text(ix.dir, to_w, to_h, marker, sizeof marker);
        fprintf(mk, "%s\n", marker);
        fclose(mk);
    }
    ag_index_free(&ix);

    if (log) {
        snprintf(msg, sizeof msg, "[+] artgen: generated %zu assets for %dx%d"
                 " (font scale %.6f%s), %zu skipped", ok, to_w, to_h, font_scale,
                 font_nn ? ", nearest" : ", box", skipped);
        log(msg);
    }
    return (int)ok;
}

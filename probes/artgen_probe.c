/* De-risking probe for the runtime art generator (runtime-art-generation-design §7).
 *
 * THE QUESTION. The plan to generate the UI art set inside the proxy at launch rests
 * on one estimate: that the ~30 s the Python generator takes is interpreter overhead
 * (16.1 M minor faults, 0 major -- so no I/O at all) rather than work, and that the
 * same work in C is around a second. An estimate is not a measurement, so this ports
 * the sharpest-oracle slice of the pipeline -- decode_row, emit_row, pick and
 * rescale_sprite -- and nothing else. No resampling, no name harvesting, no archive
 * walking: the corpus arrives as loose container files with a manifest.
 *
 * THE ORACLE. For every archived sprite, at a fixed target size, this must produce
 * bytes IDENTICAL to tools/tropico-artset.py. Not "visually identical", not "the same
 * length": the codec round-trips byte-exact today, and that property is the whole
 * safety net for the rewrite. probes/artgen_oracle.py drives both sides and diffs them.
 *
 * THE RULES THAT ARE EASY TO GET WRONG, all of them measured rather than reasoned
 * (FINDINGS 62.3, and the header of tropico-artset.py):
 *
 *   Row terminators are POSITIONAL, not carried. A non-final row always closes 0x00
 *   whatever the source row had -- inheriting a 0xC0 would end the sprite early and
 *   kill every row below it. A final row keeps its source terminator, except that a
 *   0x00 becomes NOTHING, because the sprite's own 0xC0 then serves and a trailing
 *   0x00 would make the blit read that 0xC0 as a length header. Across the archives:
 *   0 final rows end 0x00, 6744 end with no terminator, 500 end 0xC0.
 *
 *   Trailing transparency is never encoded. PopTop drops it and closes with the
 *   terminator, so emit_row trims before it runs.
 *
 *   The axes are independent: x/w follow screen width, y/h follow screen height,
 *   against a 1600x1200 source.
 *
 * Build:  cc -O2 -o artgen_probe artgen_probe.c -lm
 * Run:    artgen_probe <corpus-dir> <manifest> <out.blob> <srcW> <srcH> <dstW> <dstH>
 *
 * The whole corpus is read into memory BEFORE the clock starts and the output is
 * written after it stops, so the number reported is compute alone -- which is the
 * number the design is betting on.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

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

/* --------------------------------------------------------------------- driver */

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

/* Python's round(): nearest, TIES TO EVEN. nearbyint under the default rounding
 * mode is exactly that. A plain (int)(x+0.5) is a different function and would
 * disagree with the oracle on any tie. */
static int py_round(double v) { return (int)nearbyint(v); }

typedef struct { char *name; unsigned char *d; size_t len; } asset_t;

int main(int argc, char **argv)
{
    if (argc != 8) {
        fprintf(stderr, "usage: %s <corpus-dir> <manifest> <out.blob> <srcW> <srcH> <dstW> <dstH>\n",
                argv[0]);
        return 2;
    }
    const char *dir = argv[1], *manifest = argv[2], *outpath = argv[3];
    int from_w = atoi(argv[4]), from_h = atoi(argv[5]);
    int to_w = atoi(argv[6]), to_h = atoi(argv[7]);
    double xs = (double)to_w / (double)from_w, ys = (double)to_h / (double)from_h;

    /* --- load, off the clock ------------------------------------------------ */
    size_t mlen; unsigned char *m = slurp(manifest, &mlen);
    if (!m) { perror(manifest); return 2; }
    size_t nassets = 0;
    for (size_t i = 0; i < mlen; i++) if (m[i] == '\n') nassets++;
    asset_t *assets = (asset_t *)calloc(nassets ? nassets : 1, sizeof(asset_t));
    size_t na = 0, line = 0;
    for (size_t i = 0; i <= mlen; i++) {
        if (i == mlen || m[i] == '\n') {
            if (i > line) {
                char path[4096];
                size_t n = i - line;
                char *name = (char *)malloc(n + 1);
                memcpy(name, m + line, n); name[n] = 0;
                snprintf(path, sizeof path, "%s/%s", dir, name);
                size_t dl; unsigned char *d = slurp(path, &dl);
                if (!d) { perror(path); return 2; }
                assets[na].name = name; assets[na].d = d; assets[na].len = dl;
                na++;
            }
            line = i + 1;
        }
    }

    /* --- compute, on the clock ---------------------------------------------- */
    buf_t out = {0};
    size_t n_sprites = 0, n_rows = 0, n_bytes_in = 0, n_bytes_out = 0, n_skipped = 0;
    int failures = 0;

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (size_t i = 0; i < na; i++) {
        cont_t c; c.sprites = NULL;
        if (cont_parse(&c, assets[i].d, assets[i].len) < 0 || !c.exact) {
            /* glastube and friends: sections outside the sprite chain. The Python
             * refuses these too, so both sides skip them and neither guesses. */
            n_skipped++;
            free(c.sprites);
            continue;
        }
        size_t namelen = strlen(assets[i].name);
        buf_u32(&out, (unsigned)namelen);
        buf_add(&out, (const unsigned char *)assets[i].name, namelen);
        size_t count_at = out.n;
        buf_u32(&out, 0);
        unsigned emitted = 0;

        for (unsigned k = 0; k < c.count; k++) {
            sprite_t *s = &c.sprites[k];
            if (s->fmt != 2 || s->w == 0 || s->h == 0) continue;
            int nw = py_round((double)s->w * xs); if (nw < 1) nw = 1;
            int nh = py_round((double)s->h * ys); if (nh < 1) nh = 1;
            buf_u32(&out, k);
            size_t len_at = out.n;
            buf_u32(&out, 0);
            size_t start = out.n;
            if (rescale_sprite(&c, s, nw, nh, &out) < 0) {
                fprintf(stderr, "FAIL %s sprite %u (%ux%u -> %dx%d)\n",
                        assets[i].name, k, s->w, s->h, nw, nh);
                failures++;
                out.n = len_at - 4;      /* drop the partial record entirely */
                continue;
            }
            unsigned plen = (unsigned)(out.n - start);
            out.p[len_at+0] = plen; out.p[len_at+1] = plen>>8;
            out.p[len_at+2] = plen>>16; out.p[len_at+3] = plen>>24;
            emitted++;
            n_sprites++; n_rows += nh;
            n_bytes_in += s->size; n_bytes_out += plen;
        }
        out.p[count_at+0] = emitted; out.p[count_at+1] = emitted>>8;
        out.p[count_at+2] = emitted>>16; out.p[count_at+3] = emitted>>24;
        free(c.sprites);
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double secs = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;

    /* --- write, off the clock ----------------------------------------------- */
    FILE *f = fopen(outpath, "wb");
    if (!f) { perror(outpath); return 2; }
    fwrite(out.p, 1, out.n, f);
    fclose(f);

    printf("C   %zu assets (%zu skipped), %zu sprites, %zu rows, %zu -> %zu bytes\n",
           na - n_skipped, n_skipped, n_sprites, n_rows, n_bytes_in, n_bytes_out);
    printf("C   compute %.3f s   (%.2f us/sprite, %.3f us/row)\n",
           secs, secs * 1e6 / (n_sprites ? n_sprites : 1),
           secs * 1e6 / (n_rows ? n_rows : 1));
    if (failures) printf("C   %d FAILURES\n", failures);
    return failures ? 1 : 0;
}

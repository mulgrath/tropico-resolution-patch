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
 * Build:  cc -O2 -msse2 -mfpmath=sse -o artgen_probe artgen_probe.c -lm
 * Run:    artgen_probe <corpus-dir> <manifest> <out.blob> <srcW> <srcH> <dstW> <dstH>
 *                      [fontScale] [box|nn]
 *
 * -msse2 -mfpmath=sse IS NOT OPTIONAL ON 32-BIT, and it is the target: the proxy is a
 * 32-bit Windows DLL. Without it gcc emits x87, which keeps intermediates at 80 bits,
 * so `acc += a * line[x]` in box_resample rounds differently than the SSE2 doubles the
 * oracle runs on. Measured: the 32-bit build diverged from the 64-bit one at byte
 * 73,767,001 of a 130 MB corpus -- one sprite in 25,820 -- and the flags made them
 * identical. The integer codec is immune, which is why this only appeared once the
 * font path landed. See FINDINGS 94.
 *
 * The whole corpus is read into memory BEFORE the clock starts and the output is
 * written after it stops, so the number reported is compute alone -- which is the
 * number the design is betting on.
 */
/* THE IMPLEMENTATION IS INCLUDED, NOT COPIED. proxy/artgen.c is the file the game
 * runs; including it here as a single translation unit is what makes "the probe
 * passed" a statement about the shipped code rather than about a private fork of it.
 * Including a .c is unusual and deliberate: the codec's internals are static, and
 * exporting them just to test them would widen the generator's surface for no reason. */
#include "../proxy/artgen.c"
#include <time.h>

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

/* py_round lives in artgen.c, included above. */

typedef struct { char *name; unsigned char *d; size_t len; } asset_t;

int main(int argc, char **argv)
{
    if (argc != 8 && argc != 10) {
        fprintf(stderr, "usage: %s <corpus-dir> <manifest> <out.blob> <srcW> <srcH> <dstW> <dstH>"
                        " [fontScale] [box|nn]\n", argv[0]);
        return 2;
    }
    const char *dir = argv[1], *manifest = argv[2], *outpath = argv[3];
    int from_w = atoi(argv[4]), from_h = atoi(argv[5]);
    int to_w = atoi(argv[6]), to_h = atoi(argv[7]);
    double xs = (double)to_w / (double)from_w, ys = (double)to_h / (double)from_h;
    /* Fonts default to 1.0 -- left stock, byte-identical to PopTop's own, which is
     * also the case that proves the filter exact at 1:1. */
    double font_scale = (argc == 10) ? atof(argv[8]) : 1.0;
    int use_nn = (argc == 10) && strcmp(argv[9], "nn") == 0;

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

        /* A font takes ONE uniform scale on both axes; the chrome takes the
         * screen's own two. Decided per CONTAINER, exactly as the Python does --
         * a container is a font or it is not, never a mix. */
        int font = is_font(&c);
        double axs = font ? font_scale : xs;
        double ays = font ? font_scale : ys;

        for (unsigned k = 0; k < c.count; k++) {
            sprite_t *s = &c.sprites[k];
            if (s->fmt != 2 || s->w == 0 || s->h == 0) continue;
            int nw = py_round((double)s->w * axs); if (nw < 1) nw = 1;
            int nh = py_round((double)s->h * ays); if (nh < 1) nh = 1;
            buf_u32(&out, k);
            size_t len_at = out.n;
            buf_u32(&out, 0);
            size_t start = out.n;
            int rc = font ? rescale_font_sprite(&c, s, nw, nh, use_nn, &out)
                          : rescale_sprite(&c, s, nw, nh, &out);
            if (rc < 0) {
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

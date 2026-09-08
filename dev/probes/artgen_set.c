/* Step 5's prerequisite: the CONTAINER WRITER, and the whole-set driver.
 *
 * The two earlier probes only ever emitted sprite PAYLOADS, because that is all the
 * codec produces. A container is payloads plus a header, a 15-byte-per-sprite table
 * with two length fields, a 13-byte record per sprite carrying the scaled geometry,
 * and seven region-end offsets at 0x23 that all have to become the final file size.
 * None of that was covered, so it gets its own oracle: regenerate a whole asset and
 * compare the FILE to what tools/tropico-artset.py writes.
 *
 * The sharpest case is the identity run -- 1600x1200 from 1600x1200 -- because it must
 * reproduce PopTop's own file byte for byte, container structure included.
 *
 * Same rule as the other probes: include the shipped implementation, never a copy.
 *
 * Build:  cc -O2 -msse2 -mfpmath=sse -o artgen_set artgen_set.c -lm
 * Run:    artgen_set <datadir> <exe> <outdir> <W> <H> [fontScale] [box|nn]
 */
#include "../proxy/artgen.c"

int main(int argc, char **argv)
{
    if (argc < 6) {
        fprintf(stderr, "usage: %s <datadir> <exe> <outdir> <W> <H> [fontScale] [box|nn]\n",
                argv[0]);
        return 2;
    }
    const char *datadir = argv[1], *exepath = argv[2], *outdir = argv[3];
    int to_w = atoi(argv[4]), to_h = atoi(argv[5]);
    double font_scale = (argc > 6) ? atof(argv[6]) : 1.0;
    int font_nn = (argc > 7) && !strcmp(argv[7], "nn");

    ag_index ix;
    if (ag_index_load(&ix, datadir) < 0) { fprintf(stderr, "no archives\n"); return 2; }
    ag_names names;
    if (ag_harvest(&ix, exepath, &names) < 0) { fprintf(stderr, "harvest failed\n"); return 2; }
    ag_assets as;
    ag_resolve(&ix, &names, 1, &as);

    /* One blob per archive, read once. The Python used to re-read the whole archive
     * per asset -- 372 MB a time, 17.5 s of the 27.6 (FINDINGS 93). */
    unsigned char *blob[AG_MAX_ARCHIVES] = {0}; size_t blen[AG_MAX_ARCHIVES] = {0};
    for (int a = 0; a < ix.narch; a++)
        if (ix.present[a]) blob[a] = ag_slurp(ix.paths[a], &blen[a]);

    size_t ok = 0, skipped = 0, failed = 0, bytes = 0;
    for (size_t i = 0; i < as.n; i++) {
        const ag_entry *e = as.src[i];
        const unsigned char *d = blob[e->archive] + e->offset;
        /* The seven menu assets are authored at 640x480, everything else at
         * 1600x1200. Getting this wrong scales them by 2.5x and is invisible until
         * the menu is on screen. */
        int fw = as.from_i06[i] ? 640 : 1600, fh = as.from_i06[i] ? 480 : 1200;
        size_t olen;
        /* No master: the oracle is the plain resample, byte for byte. */
        unsigned char *o = ag_rescale_container(d, e->size, to_w, to_h, fw, fh,
                                                font_scale, font_nn, NULL, 0, NULL, &olen);
        if (!o) {
            /* glastube and siblings: sections outside the sprite chain (FINDINGS 26).
             * The Python refuses these too, so both sides skip and neither guesses. */
            skipped++;
            continue;
        }
        char path[2048];
        snprintf(path, sizeof path, "%s/%s", outdir, as.name[i]);
        FILE *f = fopen(path, "wb");
        if (!f) { perror(path); failed++; free(o); continue; }
        fwrite(o, 1, olen, f);
        fclose(f);
        bytes += olen;
        ok++;
        free(o);
    }
    fprintf(stderr, "%dx%d: %zu written, %zu skipped, %zu failed, %zu bytes\n",
            to_w, to_h, ok, skipped, failed, bytes);
    return failed ? 1 : 0;
}

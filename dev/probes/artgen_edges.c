/* The larger-master font path must not make a glyph LOOK BIGGER than the double it
 * replaces (FINDINGS 135). Copperplate's round capitals overshoot the cap line by a
 * row whose stock coverage is a quarter; the 10 and 12 pt sizes were hinted with that
 * row three-quarters solid, and box-fitted into the 8 pt cell that row came out
 * near-solid, so C, S and E stood two pixels taller than A, R and V in one word
 * (owner's 2560x1440 screenshot, 2026-09-08).
 *
 * THE RULE THIS CHECKS: for every glyph the master path produces, no row's and no
 * column's maximum opacity exceeds the same row's or column's maximum in the
 * nearest-neighbour double of the small glyph -- the stock bitmap's own weights,
 * row for row. That is what reads as one cap height at 1080p; the master may
 * sharpen the inside of that envelope, never grow it.
 *
 * Same rule as the other probes: include the shipped implementation, never a copy.
 *
 * Build:  cc -O2 -msse2 -mfpmath=sse -Iproxy -o artgen_edges dev/probes/artgen_edges.c -lm
 * Run:    artgen_edges <fontdir> <small> <master> <scale> [GLYPHS]
 *         e.g. artgen_edges known-good/fonts-scale1.00 copp8 copp10 1.3333333 CSEA
 * Exit 0 when every glyph stays inside the envelope, 1 otherwise, listing offenders.
 * With GLYPHS, also print each named glyph's per-row maximum opacity, double and
 * master side by side -- the table FINDINGS 135 reads.
 */
#include "../proxy/artgen.c"

static unsigned char *slurp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb"); if (!f) return NULL;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *p = (unsigned char *)malloc((size_t)n);
    if (fread(p, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(p); return NULL; }
    fclose(f); *len = (size_t)n; return p;
}

/* The glyph's opacity grid out of a GENERATED container. */
static int out_grid(const cont_t *c, unsigned i, unsigned char **g, int *w, int *h)
{
    const sprite_t *s = &c->sprites[i];
    *w = (int)s->w; *h = (int)s->h;
    return glyph_grid(c, s, g);
}

int main(int argc, char **argv)
{
    if (argc < 5) { fprintf(stderr, "usage: artgen_edges <fontdir> <small> <master> <scale> [GLYPHS]\n"); return 2; }
    const char *show = argc > 5 ? argv[5] : "";
    char ps[512], pm[512];
    snprintf(ps, sizeof ps, "%s/%s.i16", argv[1], argv[2]);
    snprintf(pm, sizeof pm, "%s/%s.i16", argv[1], argv[3]);
    double scale = atof(argv[4]);
    size_t ls, lm, ld, lo;
    unsigned char *ds = slurp(ps, &ls), *dm = slurp(pm, &lm);
    if (!ds || !dm) { fprintf(stderr, "cannot read %s or %s\n", ps, pm); return 2; }

    ag_master_report rep;
    /* The envelope is the NEAREST-NEIGHBOUR double: it carries the stock glyph's own
     * row and column weights exactly (a quarter for an overshoot row, solid for a
     * body row), where the box double blends the body's edge rows at a fractional
     * scale and would cap the master's crisp edges too (the owner saw that as a
     * cut-off bottom, 2026-09-09). */
    unsigned char *dbl = ag_rescale_container(ds, ls, 1600, 1200, 1600, 1200, scale, 1, NULL, 0, NULL, &ld);
    /* Nearest for the glyphs the shape check rejects too, so a kept glyph is the
     * envelope itself and only the master-drawn glyphs are under test. */
    unsigned char *mst = ag_rescale_container(ds, ls, 1600, 1200, 1600, 1200, scale, 1, dm, lm, &rep, &lo);
    if (!dbl || !mst) { fprintf(stderr, "rescale failed\n"); return 2; }
    printf("%s <- %s x%.4f: median %.3f, %d taken, %d kept\n", argv[2], argv[3], scale, rep.median, rep.taken, rep.kept);
    if (rep.taken == 0) { fprintf(stderr, "master not used: nothing to check\n"); return 2; }

    cont_t cd, cm; cd.sprites = NULL; cm.sprites = NULL;
    if (cont_parse(&cd, dbl, ld) < 0 || cont_parse(&cm, mst, lo) < 0) { fprintf(stderr, "parse failed\n"); return 2; }

    int bad = 0, checked = 0;
    static unsigned char gd[1 << 16], gm[1 << 16];
    for (unsigned i = 0; i < cd.count; i++) {
        unsigned char *g; int w, h, w2, h2;
        if (cd.sprites[i].fmt != 2 || cd.sprites[i].w < 4 || cd.sprites[i].h < 4) continue;
        if (out_grid(&cd, i, &g, &w, &h) < 0) continue;
        memcpy(gd, g, (size_t)w * h);
        if (out_grid(&cm, i, &g, &w2, &h2) < 0) continue;
        if (w2 != w || h2 != h) { printf("  glyph %u: cell %dx%d vs %dx%d -- layout changed\n", i, w, h, w2, h2); bad++; continue; }
        memcpy(gm, g, (size_t)w * h);
        checked++;
        if (i < 127 && strchr(show, (int)i)) {
            printf("  %c cell %dx%d\n    double:", (char)i, w, h);
            for (int r = 0; r < h; r++) { int a = 0; for (int x = 0; x < w; x++) if (gd[r*w+x] > a) a = gd[r*w+x]; printf(" %3d", a); }
            printf("\n    master:");
            for (int r = 0; r < h; r++) { int b = 0; for (int x = 0; x < w; x++) if (gm[r*w+x] > b) b = gm[r*w+x]; printf(" %3d", b); }
            printf("\n");
        }
        int worst = 0, wr = -1, wc = -1;
        for (int r = 0; r < h; r++) {
            int a = 0, b = 0;
            for (int x = 0; x < w; x++) { if (gd[r*w+x] > a) a = gd[r*w+x]; if (gm[r*w+x] > b) b = gm[r*w+x]; }
            if (b - a > worst) { worst = b - a; wr = r; }
        }
        for (int x = 0; x < w; x++) {
            int a = 0, b = 0;
            for (int r = 0; r < h; r++) { if (gd[r*w+x] > a) a = gd[r*w+x]; if (gm[r*w+x] > b) b = gm[r*w+x]; }
            if (b - a > worst) { worst = b - a; wc = x; wr = -1; }
        }
        if (worst > 1) {
            bad++;
            printf("  glyph %3u %c: master exceeds double by %3d at %s %d of %dx%d\n", i,
                   (i >= 32 && i < 127) ? (char)i : '?', worst, wr >= 0 ? "row" : "col", wr >= 0 ? wr : wc, w, h);
        }
    }
    printf("%d glyphs checked, %d outside the double's envelope\n", checked, bad);
    return bad ? 1 : 0;
}

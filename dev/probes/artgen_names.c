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
/* Same rule as artgen_probe.c: include the shipped implementation, never a copy. */
#include "../proxy/artgen.c"

/* ------------------------------------------------------------------- harvest */

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <datadir> <exe> [--with-menu] [--dump-names]\n", argv[0]);
        return 2;
    }
    int with_menu = 0, dump_names = 0;
    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--with-menu"))  with_menu = 1;
        if (!strcmp(argv[i], "--dump-names")) dump_names = 1;
    }

    ag_index ix;
    if (ag_index_load(&ix, argv[1]) < 0) {
        fprintf(stderr, "no usable archives in %s\n", argv[1]);
        return 2;
    }
    ag_names names;
    if (ag_harvest(&ix, argv[2], &names) < 0) { fprintf(stderr, "harvest failed\n"); return 2; }

    if (dump_names) {
        /* The HARVESTED set, before resolution drops anything without an .i16.
         * Resolution is a FILTER, so a spurious extra name never reaches the resolved
         * listing -- which makes that listing a weaker oracle than it looks. This is
         * the strong one. */
        for (size_t i = 0; i < names.n; i++) printf("%s\n", names.v[i]);
        return 0;
    }

    ag_assets as;
    ag_resolve(&ix, &names, with_menu, &as);
    for (size_t i = 0; i < as.n; i++)
        printf("%s\t%s\t%u\t%u\n", as.name[i],
               ix.names[as.src[i]->archive], as.src[i]->offset, as.src[i]->size);

    ag_assets_free(&as);
    ag_names_free(&names);
    ag_index_free(&ix);
    return 0;
}

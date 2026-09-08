/* Drive ag_generate_set() natively, the way the proxy does at launch, and print its
 * log -- which is where the larger-master font path reports what each font took
 * (FINDINGS 130). Point it at a scratch game folder: Tropico.EXE and data\*.PK2 may
 * be symlinks, the generated set lands loose in data\.
 *
 * Build:  cc -O2 -msse2 -mfpmath=sse -Iproxy -o artgen_masters dev/probes/artgen_masters.c -lm
 * Run:    artgen_masters <gamedir> <W> <H> [box|nn]
 */
#include "../proxy/artgen.c"
static void say(const char *m) { puts(m); }
int main(int argc, char **argv)
{
    if (argc < 4) { fprintf(stderr, "usage: artgen_masters <gamedir> <W> <H> [box|nn]\n"); return 2; }
    int w = atoi(argv[2]), h = atoi(argv[3]);
    int nn = argc > 4 && !strcmp(argv[4], "nn");
    int n = ag_generate_set(argv[1], w, h, (double)h / 1080.0, nn, say);
    printf("%d assets\n", n);
    return n > 0 ? 0 : 1;
}

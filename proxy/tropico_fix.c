/*
 * tropico_fix -- runtime patcher for PopTop Tropico (2001), shipped as a
 * binkw32.dll proxy.  See ../FINDINGS.md for how every address here was derived.
 *
 * WHY A PROXY, AND WHY binkw32:
 *   The obvious vehicle, a ddraw.dll proxy, does not work.  Tropico does not
 *   import ddraw statically -- it LoadLibraryA("DDraw.dll")s it from 0x52dbd0,
 *   which is called at 0x514e55, the LAST instruction of 0x514d60, the very
 *   function containing the desktop-width gate.  0x514d60 has exactly one caller
 *   and runs once, so a ddraw proxy is handed DllMain after the gate loop has
 *   already finished.  binkw32.dll, by contrast, is a static import of both the
 *   GOG and the Steam build (verified: identical 81-export sets), so it loads at
 *   process init.
 *
 * WHY WE DO NOT PATCH IN DllMain:
 *   The Steam build is SteamStub-wrapped: it carries a .bind section and its
 *   .text has entropy 8.00 (vs 6.08 for GOG) -- fully encrypted on disk.  The
 *   stub decrypts .text in the entry-point wrapper, which runs AFTER the DllMain
 *   of every static import.  Scanning in DllMain would therefore read ciphertext.
 *
 *   Instead we IAT-hook GDI32!GetDeviceCaps in the main module and patch on the
 *   first call.  That is not a guess about ordering: the gate at 0x514d9d reads
 *   [0x60c118], which is written ONLY by 0x515160 from GetDeviceCaps.  Were it
 *   still zero when the gate ran, `cmp [eax],ebx / jge` would skip every entry
 *   but slot 0 and the game could only ever offer 640x480.  It plainly offers
 *   more, so GetDeviceCaps necessarily precedes the gate.  The import table
 *   lives in .idata and is left in the clear by the stub, so the hook installs
 *   fine on both builds.
 *
 *   The hook stays installed until a scan actually succeeds, so if the very first
 *   GetDeviceCaps call somehow precedes decryption we simply retry on the next.
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <stdarg.h>
#include <stdlib.h>
#include <math.h>

/* ------------------------------------------------------------------ logging */

static char g_logpath[MAX_PATH];
static char g_dir[MAX_PATH];

static void logf_(const char *fmt, ...)
{
    FILE *f = fopen(g_logpath, "a");
    if (!f) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

/* --------------------------------------------------------- module / sections */

static BYTE *g_base;
static HINSTANCE g_self;
static BYTE *g_text; static SIZE_T g_textlen;
static BYTE *g_data; static SIZE_T g_datalen;

static int locate_sections(void)
{
    g_base = (BYTE *)GetModuleHandleA(NULL);
    if (!g_base) return 0;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)g_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(g_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    IMAGE_SECTION_HEADER *s = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; i++, s++) {
        if (!memcmp(s->Name, ".text", 5)) { g_text = g_base + s->VirtualAddress; g_textlen = s->Misc.VirtualSize; }
        if (!memcmp(s->Name, ".data", 5)) { g_data = g_base + s->VirtualAddress; g_datalen = s->Misc.VirtualSize; }
    }
    return g_text && g_data;
}

/* ----------------------------------------------------------- pattern scanning
 *
 * Every scan REQUIRES a unique match.  Two matches means the signature is not
 * specific enough and we would be guessing which one the game actually uses --
 * refuse rather than patch the wrong site.
 */
static BYTE *find_unique(const BYTE *pat, SIZE_T len, BYTE *start, SIZE_T size, const char *what)
{
    BYTE *hit = NULL;
    int n = 0;
    if (size < len) return NULL;
    for (SIZE_T i = 0; i + len <= size; i++) {
        if (start[i] == pat[0] && !memcmp(start + i, pat, len)) {
            if (++n > 1) { logf_("  [!] %s: %d+ matches, signature not unique -- refusing", what, n); return NULL; }
            hit = start + i;
        }
    }
    if (!n) return NULL;
    return hit;
}

/* Masked variant: mask[i]==0 means "any byte here".
 *
 * REQUIRED, not a nicety. The Steam build is a DIFFERENT BUILD, not a wrapped copy
 * of the GOG one: only 13% of bytes match and the resolution table sits 736 bytes
 * earlier, so every absolute address differs. Signatures that embed absolute
 * addresses -- as the first version's did, e.g. `cmp eax,0x5a0fa0` -- can never
 * match it, decrypted or not. So wildcard every absolute operand and read the real
 * addresses back out of whatever matched. */
static BYTE *find_unique_masked(const BYTE *pat, const BYTE *mask, SIZE_T len,
                                BYTE *start, SIZE_T size, const char *what)
{
    BYTE *hit = NULL;
    int n = 0;
    if (size < len) return NULL;
    for (SIZE_T i = 0; i + len <= size; i++) {
        SIZE_T j = 0;
        for (; j < len; j++)
            if (mask[j] && start[i + j] != pat[j]) break;
        if (j != len) continue;
        if (++n > 1) { logf_("  [!] %s: %d+ matches, signature not unique -- refusing", what, n); return NULL; }
        hit = start + i;
    }
    if (!n) return NULL;
    return hit;
}

static DWORD rd32(const BYTE *p) { DWORD v; memcpy(&v, p, 4); return v; }

static int poke(void *dst, const void *src, SIZE_T len)
{
    DWORD old;
    if (!VirtualProtect(dst, len, PAGE_EXECUTE_READWRITE, &old)) return 0;
    memcpy(dst, src, len);
    VirtualProtect(dst, len, old, &old);
    FlushInstructionCache(GetCurrentProcess(), dst, len);
    return 1;
}

/* ------------------------------------------------------------- the signatures */

/* All signatures below wildcard their absolute operands (mask byte 0) so they match
 * ANY build of the game, and the real addresses are read back from the match. */

/* FINDINGS section 2: the desktop-width gate.
 *   cmp eax,<resolution table VA> / je +8 / cmp [eax],ebx / jge <end of loop>
 * The table VA is discovered first, from the data table itself, then spliced in --
 * which also proves the two finds agree about the same build. */
static BYTE GATE_SIG[]        = {0x3d,0,0,0,0, 0x74,0x08, 0x39,0x18, 0x0f,0x8d,0,0,0,0};
static const BYTE GATE_MASK[] = {   1,1,1,1,1,    1,   1,    1,   1,    1,   1,0,0,0,0};
#define GATE_PATCH_OFF 10
#define GATE_PATCH_LEN 1
#define GATE_PATCH_BYTE 0x8f

/* FINDINGS section 16: the Hardware 3D gate, an x87 SIGNED compare.
 *   fild dword [vidmem] / mov [x],ebx / fcomp qword [thresh] / fnstsw / test ah,41 / jne
 * Exactly 25 bytes in any build; only the three operands move. */
static const BYTE VRAM_SIG[]  = {0xdb,0x05,0,0,0,0,
                                 0x89,0x1d,0,0,0,0,
                                 0xdc,0x1d,0,0,0,0,
                                 0xdf,0xe0, 0xf6,0xc4,0x41, 0x75,0};
static const BYTE VRAM_MASK[] = {   1,   1,0,0,0,0,
                                    1,   1,0,0,0,0,
                                    1,   1,0,0,0,0,
                                    1,   1,    1,   1,   1,    1,0};

/* FINDINGS section 16: the second signed test, a texture budget. jge -> jae.
 *   cmp dword [vidmem],0xd00000 / jge
 * Its operand must be the SAME global the fild used -- a free cross-check. */
static const BYTE BUDGET_SIG[]  = {0x81,0x3d,0,0,0,0, 0x00,0x00,0xd0,0x00, 0x7d};
static const BYTE BUDGET_MASK[] = {   1,   1,0,0,0,0,    1,   1,   1,   1,    1};
#define BUDGET_PATCH_OFF 10

/* FINDINGS section 8: the code compare-chain, slot 4's arm. No absolute operands. */
static const BYTE CHAIN_SIG[] = {0x81,0xf9,0x40,0x06,0x00,0x00, 0x75,0x16,
                                 0x81,0xfa,0xb0,0x04,0x00,0x00};
#define CHAIN_W_OFF 2
#define CHAIN_H_OFF 10

/* FINDINGS section 1: the resolution table, 5 x {DWORD w; DWORD h}, in .data. */
static const DWORD TABLE_SIG[10] = {640,480, 800,600, 1024,768, 1280,1024, 1600,1200};
#define SLOT4_OFF 32

/* ------------------------------------------------------- resolution selection
 *
 * Policy (owner's decision, 2026-08-19): leave slots 0-3 stock and choose only
 * slot 4 at runtime.  Constraints, all from FINDINGS:
 *   s11  the HUD/background art is drawn at the slot's STOCK width, so the target
 *        width must not exceed it -- 1600 for slot 4.  This is the hard ceiling
 *        on widescreen and the reason slot 4 is the only usable home.
 *   s10  width % 4 == 0, else the row pitch is padded and the image shears.
 *   s9   the compare-chain dispatches on width and rejects on a height mismatch
 *        rather than falling through, so widths must be unique across slots.
 *   s7   the mode must actually exist, or the game cannot set it.
 */
#define ART_WIDTH_CAP 1600

typedef struct { DWORD w, h; } mode_t;

/* ------------------------------------------------------------- diagnostics
 *
 * Added while chasing DDERR_INVALIDRECT (#150) on a 2560x1440 secondary monitor
 * that works fine on the 1920x1080 primary.  The point is to record exactly what
 * the game sees, at every boundary, BEFORE theorising: the adapters Windows
 * reports, the virtual-screen geometry, and the GetDeviceCaps pair the gate
 * itself consumes.  A wrong conclusion here is cheap to reach and expensive to
 * unwind -- see ../TESTING.md.
 */
static void log_environment(void)
{
    logf_("--- environment as the GAME sees it ---");
    logf_("  SM_CMONITORS      = %d", GetSystemMetrics(SM_CMONITORS));
    logf_("  SM_CXSCREEN       = %d x %d   (primary monitor)",
          GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
    logf_("  virtual screen    = %d x %d at (%d,%d)",
          GetSystemMetrics(SM_CXVIRTUALSCREEN), GetSystemMetrics(SM_CYVIRTUALSCREEN),
          GetSystemMetrics(SM_XVIRTUALSCREEN), GetSystemMetrics(SM_YVIRTUALSCREEN));

    /* This is the exact pair the desktop-width gate reads at 0x515160 and stores
     * in [0x60c118] -- FINDINGS section 2. If it disagrees with the monitor the
     * game actually lands on, that is the bug, not the mode list. */
    HDC dc = GetDC(NULL);
    if (dc) {
        logf_("  GetDeviceCaps(NULL): HORZRES=%d VERTRES=%d BITSPIXEL=%d  <- what the gate uses",
              GetDeviceCaps(dc, HORZRES), GetDeviceCaps(dc, VERTRES), GetDeviceCaps(dc, BITSPIXEL));
        ReleaseDC(NULL, dc);
    } else logf_("  GetDC(NULL) failed");

    DISPLAY_DEVICEA dd; 
    for (DWORD i = 0; ; i++) {
        memset(&dd, 0, sizeof dd); dd.cb = sizeof dd;
        if (!EnumDisplayDevicesA(NULL, i, &dd, 0)) break;
        DEVMODEA cur; memset(&cur, 0, sizeof cur); cur.dmSize = sizeof cur;
        int have = EnumDisplaySettingsA(dd.DeviceName, ENUM_CURRENT_SETTINGS, &cur);
        logf_("  adapter %lu: %-16s flags=0x%08lx%s  current=%lux%lu@%lu at (%ld,%ld)",
              i, dd.DeviceName, dd.StateFlags,
              (dd.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE) ? " PRIMARY" : "",
              have ? cur.dmPelsWidth : 0, have ? cur.dmPelsHeight : 0,
              have ? cur.dmBitsPerPel : 0,
              have ? (long)cur.dmPosition.x : 0, have ? (long)cur.dmPosition.y : 0);
    }
    logf_("---------------------------------------");
}


static int collides_with_stock(DWORD w)
{
    return w == 640 || w == 800 || w == 1024 || w == 1280;
}

static int pick_mode(mode_t *out)
{
    log_environment();
    DEVMODEA dm; memset(&dm, 0, sizeof dm); dm.dmSize = sizeof dm;

    /* Desktop aspect: what the panel actually is, so we can prefer a mode that
     * fills it rather than one that merely happens to be large. */
    double desk_aspect = 4.0 / 3.0;
    if (EnumDisplaySettingsA(NULL, ENUM_CURRENT_SETTINGS, &dm) && dm.dmPelsHeight)
        desk_aspect = (double)dm.dmPelsWidth / (double)dm.dmPelsHeight;
    logf_("  desktop: %lux%lu (aspect %.4f)", dm.dmPelsWidth, dm.dmPelsHeight, desk_aspect);

    mode_t best = {0, 0};
    double best_err = 1e9;
    int considered = 0;
    mode_t seen[128]; int nseen = 0;

    /* The mode must FIT THE DESKTOP. Without this the picker will happily choose a
     * mode larger than a Wine/Proton virtual desktop -- measured: vd=1024x768 gave
     * slot 4 = 1400x1050. The stock gate used to prevent that, and NOPing it (as
     * earlier revisions did) removed the protection. `<=`, not `<`: a mode exactly
     * as wide as the desktop is the ideal case, which is why the gate needs `jg`. */
    DWORD deskw = (DWORD)GetSystemMetrics(SM_CXSCREEN);
    DWORD deskh = (DWORD)GetSystemMetrics(SM_CYSCREEN);

    for (DWORD i = 0; ; i++) {
        memset(&dm, 0, sizeof dm); dm.dmSize = sizeof dm;
        if (!EnumDisplaySettingsA(NULL, i, &dm)) break;
        DWORD w = dm.dmPelsWidth, h = dm.dmPelsHeight;
        if (!w || !h) continue;
        if (w % 4) continue;                       /* s10: pitch shear         */
        if (w > ART_WIDTH_CAP) continue;           /* s11: art width ceiling   */
        if (h > 1200) continue;                    /* stock slot-4 art height  */
        if (w > deskw || h > deskh) continue;      /* must fit the desktop     */
        /* Slot 4 is the LARGEST slot. If we cannot beat slot 3's stock 1280, we have
         * nothing to offer and should leave slot 4 alone rather than shrink it. */
        if (w <= 1280) continue;
        if (collides_with_stock(w)) continue;      /* s9: unique widths        */

        /* Wine lists every mode once per bit depth; only log each geometry once. */
        int dup = 0;
        for (int k = 0; k < nseen; k++) if (seen[k].w == w && seen[k].h == h) { dup = 1; break; }
        if (dup) continue;
        if (nseen < (int)(sizeof seen / sizeof seen[0])) { seen[nseen].w = w; seen[nseen].h = h; nseen++; }
        considered++;

        double err = fabs((double)w / (double)h - desk_aspect);
        int win = (err < best_err - 0.02 || (fabs(err - best_err) <= 0.02 && w > best.w));
        logf_("    cand %4lux%-4lu aspect %.4f err %.4f%s", w, h,
              (double)w / (double)h, err, win ? "   <- best so far" : "");
        if (win) { best.w = w; best.h = h; best_err = err; }
    }

    logf_("  %d candidate modes passed the constraints (fit within %lux%lu, wider than 1280)",
          considered, deskw, deskh);
    if (!best.w) {
        logf_("  -> nothing beats slot 3's stock 1280; leaving slot 4 at its stock 1600x1200");
        return 0;
    }
    *out = best;
    return 1;
}

/* Optional override so a user can force a mode without a rebuild. */
static int ini_override(mode_t *m)
{
    char path[MAX_PATH];
    snprintf(path, sizeof path, "%s\\tropico-fix.ini", g_dir);
    UINT w = GetPrivateProfileIntA("Resolution", "Width",  0, path);
    UINT h = GetPrivateProfileIntA("Resolution", "Height", 0, path);
    if (!w || !h) return 0;
    if (w % 4) { logf_("  ini: width %u is not a multiple of 4 -- ignoring (would shear)", w); return 0; }
    if (collides_with_stock(w)) { logf_("  ini: width %u collides with a stock slot -- ignoring (would be unreachable)", w); return 0; }
    if (w > ART_WIDTH_CAP)
        logf_("  ini: WARNING width %u exceeds the %d art cap; expect an unpainted strip (FINDINGS s11)", w, ART_WIDTH_CAP);
    m->w = w; m->h = h;
    logf_("  ini override: %ux%u", w, h);
    return 1;
}

/* ------------------------------------------------- the world-extent clamp (FINDINGS 35)
 *
 * Found by decompiling, after byte-searching for 1600 failed six different ways:
 * the clamp is not ON 1600. It is on 0xC80 = 3200 and 0x960 = 2400 -- exactly
 * TWICE the stock slot-4 mode, because the coordinates here are doubled (the very
 * next instructions are `sub eax,[0x599ff0]` then `shl eax,1`).
 *
 *   46b146  3d 80 0c 00 00     cmp eax,0xc80      ; width  > 3200 ?
 *   46b14e  7e 05              jle +5
 *   46b150  b8 80 0c 00 00     mov eax,0xc80      ; ...clamp to 3200  (= 1600 px)
 *   46b167  81 fe 60 09 00 00  cmp esi,0x960      ; height > 2400 ?
 *   46b170  7e 05              jle +5
 *   46b172  be 60 09 00 00     mov esi,0x960      ; ...clamp to 2400  (= 1200 px)
 *
 * That is why the terrain stopped at exactly 1600 on both a 1680- and a 1920-wide
 * screen (FINDINGS 31): the clamp is absolute, not relative to the mode.
 *
 * Raise both to twice the mode actually selected -- computed, not hardcoded, so it
 * stays correct for any slot-4 geometry.
 */
static const BYTE VCLAMP_SIG[] = {
    0x0f,0x9c,0xc1,0x49,0x23,0xc1,0x3d, 0,0,0,0,
    0x89,0x45,0x18,0x7e,0x05,0xb8,      0,0,0,0,
    0x8b,0x4d,0x1c,0x33,0xd2,0x85,0xc9,0x0f,0x9c,0xc2,0x89,0x45,0x18,
    0x4a,0x23,0xd1,0x8b,0xf2,0x81,0xfe, 0,0,0,0,
    0x89,0x75,0x1c,0x7e,0x05,0xbe,      0,0,0,0,
    0x89,0x75,0x1c
};
static const BYTE VCLAMP_MASK[] = {
    1,1,1,1,1,1,1, 0,0,0,0,
    1,1,1,1,1,1,   0,0,0,0,
    1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1, 0,0,0,0,
    1,1,1,1,1,1,   0,0,0,0,
    1,1,1
};
#define VCLAMP_W1 7
#define VCLAMP_W2 17
#define VCLAMP_H1 41
#define VCLAMP_H2 51

/* ----------------------------------------------------------------- the patcher */

static LONG g_done = 0;

static void apply_patches(void)
{
    if (InterlockedExchange(&g_done, 1)) return;   /* only ever run the body once */

    if (!locate_sections()) { logf_("[x] could not locate .text/.data"); return; }
    logf_("[*] module %p  .text %p+%u  .data %p+%u",
          g_base, g_text, (unsigned)g_textlen, g_data, (unsigned)g_datalen);

    int ok = 0, fail = 0;

    /* --- 0. the resolution table, which also tells us this build's addresses ----
     * Found by VALUE, in unencrypted .data, so it works on any build. Its address
     * is then spliced into the gate signature. */
    BYTE *tbl = find_unique((const BYTE *)TABLE_SIG, sizeof TABLE_SIG, g_data, g_datalen, "table");
    if (!tbl) {
        logf_("[x] resolution table not found in .data -- wrong game, or not this engine");
        return;
    }
    DWORD table_va = (DWORD)(ULONG_PTR)tbl;
    logf_("[*] resolution table at 0x%08lx  (GOG build has 0x005a0fa0; a different value here"
          " just means a different build, which is fine)", table_va);
    memcpy(GATE_SIG + 1, &table_va, 4);

    /* --- 1. desktop-width gate --------------------------------------------- */
    BYTE *p = find_unique_masked(GATE_SIG, GATE_MASK, sizeof GATE_SIG, g_text, g_textlen, "gate");
    if (p) {
        BYTE jg = GATE_PATCH_BYTE;
        if (poke(p + GATE_PATCH_OFF, &jg, 1)) {
            logf_("[+] gate jge -> jg at %p (a mode exactly as wide as the desktop is now kept;"
                  " wider ones are still filtered out)", p + GATE_PATCH_OFF); ok++;
        } else { logf_("[x] gate: VirtualProtect failed"); fail++; }
    } else { logf_("[-] gate: signature not found"); fail++; }

    /* --- 2. Hardware 3D signed VRAM compare --------------------------------
     * Rebuild the replacement using THIS build's operands, and compute the branch
     * displacement from the original rather than hardcoding it -- an earlier build
     * hardcoded 0x23 and landed inside a call instruction. */
    DWORD vidmem = 0;
    p = find_unique_masked(VRAM_SIG, VRAM_MASK, sizeof VRAM_SIG, g_text, g_textlen, "vram");
    if (p) {
        vidmem       = rd32(p + 2);      /* fild  dword [vidmem]  */
        DWORD store  = rd32(p + 8);      /* mov   [store],ebx     */
        BYTE  orig_rel = p[24];          /* jne   rel8            */
        /* Original: 25 bytes, branch taken from the end of the sequence.
         * New layout is 18 bytes, so shift the displacement by the difference. */
        BYTE *target = p + 25 + (signed char)orig_rel;
        int   newrel = (int)(target - (p + 18));

        if (newrel < -128 || newrel > 127) {
            logf_("[x] vram: branch displacement %d does not fit in rel8 -- refusing", newrel);
            fail++;
        } else {
            BYTE fix[25];
            int k = 0;
            fix[k++] = 0xa1; memcpy(fix + k, &vidmem, 4); k += 4;          /* mov eax,[vidmem]   */
            fix[k++] = 0x89; fix[k++] = 0x1d; memcpy(fix + k, &store, 4); k += 4; /* mov [store],ebx */
            fix[k++] = 0x3d; { DWORD t = 0x880000; memcpy(fix + k, &t, 4); } k += 4; /* cmp eax,8.5MB */
            fix[k++] = 0x76; fix[k++] = (BYTE)newrel;                       /* jbe (UNSIGNED)     */
            while (k < 25) fix[k++] = 0x90;
            if (poke(p, fix, sizeof fix)) {
                logf_("[+] VRAM compare made unsigned at %p (vidmem global 0x%08lx, jbe rel8 %d)",
                      p, vidmem, newrel); ok++;
            } else { logf_("[x] vram: VirtualProtect failed"); fail++; }
        }
    } else { logf_("[-] vram: signature not found"); fail++; }

    /* --- 3. the second signed test ----------------------------------------- */
    p = find_unique_masked(BUDGET_SIG, BUDGET_MASK, sizeof BUDGET_SIG, g_text, g_textlen, "budget");
    if (p) {
        DWORD op = rd32(p + 2);
        if (vidmem && op != vidmem) {
            /* Cross-check: this compare must read the same global the fild read.
             * If it does not, one of the two matches is the wrong site. */
            logf_("[x] budget: operand 0x%08lx != vidmem 0x%08lx -- mismatched site, refusing", op, vidmem);
            fail++;
        } else {
            BYTE jae = 0x73;
            if (poke(p + BUDGET_PATCH_OFF, &jae, 1)) { logf_("[+] texture budget jge -> jae at %p", p + BUDGET_PATCH_OFF); ok++; }
            else { logf_("[x] budget: VirtualProtect failed"); fail++; }
        }
    } else { logf_("[-] budget: signature not found"); fail++; }

    /* --- 4. slot 4, in BOTH tables ----------------------------------------- *
     * FINDINGS s8: patching the data table alone is not enough. A parallel
     * mapping lives in code and silently drops any mode it does not recognise. */
    mode_t m;
    if (!ini_override(&m) && !pick_mode(&m)) {
        logf_("[-] no mode satisfied the constraints; leaving slot 4 stock (1600x1200)");
    } else {
        BYTE *chain = find_unique(CHAIN_SIG, sizeof CHAIN_SIG, g_text, g_textlen, "chain");
        if (chain) {
            DWORD wh[2] = { m.w, m.h };
            int a = poke(tbl + SLOT4_OFF, wh, sizeof wh);
            int b = poke(chain + CHAIN_W_OFF, &m.w, 4) && poke(chain + CHAIN_H_OFF, &m.h, 4);
            if (a && b) { logf_("[+] slot 4 -> %lux%lu  (data table %p, code chain %p)", m.w, m.h, tbl, chain); ok++; }
            else { logf_("[x] slot 4: VirtualProtect failed"); fail++; }
            /* The world-extent clamp must move with the mode or the terrain still
             * stops at 1600 no matter how wide the screen is (FINDINGS 29-35). */
            BYTE *vc = find_unique_masked(VCLAMP_SIG, VCLAMP_MASK, sizeof VCLAMP_SIG,
                                          g_text, g_textlen, "world-extent clamp");
            if (vc) {
                DWORD dw = m.w * 2, dh = m.h * 2;
                /* [Debug] ClampW/ClampH force the clamp to an arbitrary value.
                 *
                 * This exists for the REVERSE test. Raising a clamp and seeing no
                 * change is ambiguous -- it can mean "wrong clamp" or "right clamp,
                 * but something else also limits". LOWERING it is unambiguous: if
                 * the terrain cutoff moves inward to match, this clamp governs the
                 * terrain and there is a second limit above it; if the cutoff does
                 * not move at all, this clamp has nothing to do with the terrain.
                 * A test that can only produce one interesting outcome is a weak
                 * test -- see TESTING.md. */
                {
                    char ip[MAX_PATH];
                    snprintf(ip, sizeof ip, "%s\\tropico-fix.ini", g_dir);
                    UINT cw = GetPrivateProfileIntA("Debug", "ClampW", 0, ip);
                    UINT ch = GetPrivateProfileIntA("Debug", "ClampH", 0, ip);
                    if (cw) { dw = cw; logf_("  [debug] ClampW override -> %u", cw); }
                    if (ch) { dh = ch; logf_("  [debug] ClampH override -> %u", ch); }
                }
                if (poke(vc + VCLAMP_W1, &dw, 4) && poke(vc + VCLAMP_W2, &dw, 4)
                 && poke(vc + VCLAMP_H1, &dh, 4) && poke(vc + VCLAMP_H2, &dh, 4)) {
                    logf_("[+] world-extent clamp at %p: 3200x2400 -> %lux%lu (2x the mode)",
                          vc, dw, dh);
                    ok++;
                } else { logf_("[x] world-extent clamp found but not writable"); fail++; }
            } else {
                logf_("[-] world-extent clamp signature not found -- terrain will still stop at 1600");
            }
        } else {
            logf_("[-] slot 4: code compare-chain not found -- NOT patching the data table"
                  " either, they must move together (FINDINGS s8)");
            fail++;
        }
    }

    logf_("[*] done: %d applied, %d failed", ok, fail);
    if (fail) {
        /* Make a failure diagnosable from the log alone -- the user may be the only
         * person who can run this build. */
        logf_("--- diagnostics for the failures above ---");
        int printable = 0;
        for (int i = 0; i < 4096 && (SIZE_T)i < g_textlen; i++)
            if (g_text[i] == 0x90 || g_text[i] == 0x8b || g_text[i] == 0xe8) printable++;
        logf_("  .text[0..15] = %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
              g_text[0],g_text[1],g_text[2],g_text[3],g_text[4],g_text[5],
              g_text[6],g_text[7],g_text[8],g_text[9],g_text[10],g_text[11]);
        logf_("  common-opcode density in first 4KB: %d/4096 (%s)", printable,
              printable > 100 ? "looks like real code" : "looks like ciphertext or data");
        logf_("-----------------------------------------");
    }
}

/* ------------------------------------------------------------- the IAT hook */

typedef int (WINAPI *GetDeviceCaps_t)(HDC, int);
static GetDeviceCaps_t g_real_gdc;
static GetDeviceCaps_t *g_gdc_slot;

static int WINAPI hook_GetDeviceCaps(HDC hdc, int index)
{
    /* Patch on the first call, and keep retrying until a scan succeeds -- on the
     * Steam build .text is ciphertext until the stub's entry wrapper has run. */
    if (!g_done) {
        static LONG scanning = 0, attempts = 0;
        if (!InterlockedExchange(&scanning, 1)) {
            LONG n = InterlockedIncrement(&attempts);
            /* Log the first few attempts and then every 500th, so "the hook never
             * fired" and "the hook fired but .text was not ready" are distinguishable
             * from the log alone. The first Steam run could not tell them apart. */
            if (n <= 3 || (n % 500) == 0)
                logf_("[*] GetDeviceCaps hook: attempt %ld, probing for decrypted .text", n);
            /* Probe with the compare-chain: it is the only .text signature with no
              * absolute operands, so it is the same bytes in every build. */
            BYTE *probe = NULL;
            if (locate_sections())
                probe = find_unique(CHAIN_SIG, sizeof CHAIN_SIG, g_text, g_textlen, "chain-probe");
            if (probe) apply_patches();
            else if (n <= 3) logf_("    ... .text not ready yet (compare-chain not found)");
            InterlockedExchange(&scanning, 0);
        }
    }
    return g_real_gdc(hdc, index);
}

static int install_iat_hook(void)
{
    BYTE *base = (BYTE *)GetModuleHandleA(NULL);
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!rva) return 0;

    for (IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(base + rva); imp->Name; imp++) {
        const char *dll = (const char *)(base + imp->Name);
        if (_stricmp(dll, "GDI32.dll")) continue;

        IMAGE_THUNK_DATA *oft = (IMAGE_THUNK_DATA *)(base + imp->OriginalFirstThunk);
        IMAGE_THUNK_DATA *ft  = (IMAGE_THUNK_DATA *)(base + imp->FirstThunk);
        for (; oft->u1.AddressOfData; oft++, ft++) {
            if (oft->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
            IMAGE_IMPORT_BY_NAME *ibn = (IMAGE_IMPORT_BY_NAME *)(base + oft->u1.AddressOfData);
            if (strcmp((const char *)ibn->Name, "GetDeviceCaps")) continue;

            g_real_gdc = (GetDeviceCaps_t)ft->u1.Function;
            g_gdc_slot = (GetDeviceCaps_t *)&ft->u1.Function;
            GetDeviceCaps_t h = hook_GetDeviceCaps;
            if (!poke(g_gdc_slot, &h, sizeof h)) return 0;
            logf_("[*] hooked GDI32!GetDeviceCaps IAT slot %p (real %p)", g_gdc_slot, g_real_gdc);
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------- the live-memory scan
 *
 * FINDINGS section 31: the terrain clips at exactly 1600 on both a 1680- and a
 * 1920-wide screen, so it is a fixed constant -- but it is not a DirectDraw
 * geometry, not a second resolution table, not a derived array, not a float, not
 * a buffer size, and every 0x640 immediate in the binary is accounted for and
 * none of them is a terrain clip. It is computed at runtime from values that are
 * not 1600 in the file.
 *
 * So stop reading and go and look. At 1920x1080 nearly every legitimate width in
 * memory is 1920; anything still holding 1600 is a suspect. Scan, report, and
 * optionally overwrite -- the classic memory-scanner approach, run from inside the
 * process we are already inside.
 *
 *   [Scan]
 *   Delay=30       seconds to wait before scanning -- you must be IN THE MAP at
 *                  the target resolution when it fires, so allow for map load
 *                  plus the F2 climb (FINDINGS: the mode ladder must be climbed)
 *   Find=1600      the value to hunt
 *   Replace=0      0 = report only. Non-zero = overwrite every hit, then look at
 *                  the terrain. Crashing is an acceptable outcome here; it is
 *                  still information, and everything in this project is reversible.
 *   Scope=image    'image' = the exe's own statics only (where a cached viewport
 *                  width would live). 'all' = every committed writable page.
 */
static DWORD g_scan_delay, g_scan_find, g_scan_repl, g_scan_bits;
static DWORD g_scan_lo, g_scan_hi, g_scan_repeat, g_scan_groups, g_scan_dwell;
static int g_scan_group_only;
/* Addresses recorded by the first sweep, then rewritten on a timer. Rescanning all
 * of memory every tick would be absurd; rewriting the hits it found is cheap.
 *
 * This matters more than it looks. The one-shot sweep DID push the terrain out to
 * 1920 -- and then the game recomputed the rect on the next camera move and put
 * 1600 back, which read as "finnicky" rather than as "correct but not held". A
 * derived value has to be held, not set. Same lesson as trap 2 in TESTING.md. */
#define SCAN_MAX_HITS 4096
static DWORD *g_hit[SCAN_MAX_HITS]; static DWORD g_hit_addr[SCAN_MAX_HITS]; static int g_hits;
static char  g_scan_scope[16];

static void scan_report(BYTE *base, SIZE_T len, const char *what, int *n32, int *n16)
{
    for (SIZE_T i = 0; i + 4 <= len; i += 4) {
        DWORD v; memcpy(&v, base + i, 4);
        if (v == g_scan_find) {
            BYTE *at = base + i;
            DWORD va = (DWORD)(SIZE_T)at;
            if (g_scan_lo && va < g_scan_lo) continue;
            if (g_scan_hi && va >= g_scan_hi) continue;
            if (*n32 < 40) logf_("    u32 %s+0x%06x  (VA %p)  [hit %d]", what, (unsigned)i, at, *n32);
            (*n32)++;
            /* Record ALWAYS, not only when replacing -- [Watch] needs the address
             * list on a read-only run, and tying the two together meant a
             * Replace=0 run silently armed nothing. */
            if (g_hits < SCAN_MAX_HITS) { g_hit_addr[g_hits] = va; g_hit[g_hits++] = (DWORD *)at; }
            if (g_scan_repl) { DWORD r = g_scan_repl; memcpy(at, &r, 4); }
        }
    }
    if (g_scan_bits == 32) return;   /* u16 hits are far noisier; skip when asked */
    for (SIZE_T i = 0; i + 2 <= len; i += 2) {
        WORD v; memcpy(&v, base + i, 2);
        if (v == (WORD)g_scan_find) {
            DWORD d; memcpy(&d, base + (i & ~(SIZE_T)3), 4);
            if (d == g_scan_find) continue;          /* already counted as a u32 */
            if (*n16 < 40) logf_("    u16 %s+0x%06x  (VA %p)", what, (unsigned)i, base + i);
            (*n16)++;
            if (g_scan_repl) { WORD r = (WORD)g_scan_repl; memcpy(base + i, &r, 2); }
        }
    }
}

/* ------------------------------------------------------------- targeted poke
 *
 * The scan narrows; this confirms. Both surviving candidates (FINDINGS 32) are
 * written as `mov reg,[struct+0x10]` into a global, with neighbours coming from
 * +0x08/+0x0c/+0x14 -- an (x, y, w, h) quad being unpacked. So write the real
 * width into them and watch the terrain.
 *
 * Repeat matters: these are DERIVED globals. If the game re-runs that unpack on
 * any event, a one-shot poke is silently undone and a real fix looks like a
 * failure. So keep writing.
 *
 *   [Poke]
 *   Delay=45
 *   Repeat=1               keep re-writing every 200ms
 *   A=0x614418  Av=1920    up to four address/value pairs, A..D
 *   B=0x61abc0  Bv=1920
 */
static DWORD g_poke_addr[4], g_poke_val[4]; static int g_poke_n, g_poke_repeat;

static void poke_apply(int first)
{
    for (int i = 0; i < g_poke_n; i++) {
        DWORD *p = (DWORD *)(SIZE_T)g_poke_addr[i];
        DWORD old_prot;
        if (!VirtualProtect(p, 4, PAGE_EXECUTE_READWRITE, &old_prot)) continue;
        if (first) logf_("  poke %p : was %u -> %u", (void *)p, (unsigned)*p,
                         (unsigned)g_poke_val[i]);
        *p = g_poke_val[i];
        VirtualProtect(p, 4, old_prot, &old_prot);
    }
}

static void maybe_load_pokes(void)
{
    char path[MAX_PATH], key[4] = "A", vkey[4] = "Av";
    snprintf(path, sizeof path, "%s\\tropico-fix.ini", g_dir);
    g_poke_repeat = GetPrivateProfileIntA("Poke", "Repeat", 1, path);
    for (int i = 0; i < 4; i++) {
        char buf[32];
        key[0] = (char)('A' + i); vkey[0] = (char)('A' + i);
        GetPrivateProfileStringA("Poke", key, "", buf, sizeof buf, path);
        if (!buf[0]) continue;
        DWORD a = (DWORD)strtoul(buf, NULL, 0);
        DWORD v = (DWORD)GetPrivateProfileIntA("Poke", vkey, 0, path);
        if (!a || !v) continue;
        g_poke_addr[g_poke_n] = a; g_poke_val[g_poke_n] = v; g_poke_n++;
    }
    if (g_poke_n) logf_("[*] %d poke(s) loaded, repeat=%d", g_poke_n, g_poke_repeat);
}

/* --------------------------------------------------------------- write watch
 *
 * FINDINGS 33/34. Bisecting a heap that re-lays-out between runs is slow and the
 * address is not stable, so stop chasing the VALUE and catch the CODE. x86 debug
 * registers give a hardware write breakpoint: arm DR0..DR3 on addresses that hold
 * 1600, and every store to them traps with EIP pointing at the instruction that
 * did it. That is the "find what writes to this address" of a memory scanner, and
 * it yields a code address -- which, unlike a heap address, is stable and
 * patchable.
 *
 *   [Watch]
 *   Auto=1     arm on the first up-to-4 addresses the scan found
 *   Max=60     stop logging after this many traps (they can be per-frame)
 *
 * Wine implements debug registers via ptrace; if the arming fails it says so
 * rather than silently watching nothing.
 */
static int g_watch_auto, g_watch_max, g_watch_seen;
static DWORD g_watch_eip[32]; static int g_watch_neip;

static LONG CALLBACK watch_veh(EXCEPTION_POINTERS *ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;
    DWORD eip = ep->ContextRecord->Eip;
    int known = 0;
    for (int i = 0; i < g_watch_neip; i++) if (g_watch_eip[i] == eip) { known = 1; break; }
    if (!known && g_watch_neip < 32) {
        g_watch_eip[g_watch_neip++] = eip;
        logf_("  [watch] store from EIP %08x   (module+0x%x)",
              (unsigned)eip, (unsigned)(eip - (DWORD)(SIZE_T)g_base));
    }
    if (++g_watch_seen > g_watch_max) {           /* disarm to stop flooding */
        ep->ContextRecord->Dr7 = 0;
        logf_("  [watch] limit reached, disarmed");
    }
    ep->ContextRecord->Dr6 = 0;
    return EXCEPTION_CONTINUE_EXECUTION;
}

/* DR7 for slot i: local-enable bit (2i), RW bits at 16+4i (01 = write only),
 * LEN bits at 18+4i (11 = four bytes). */
static void watch_arm_thread(HANDLE th, DWORD *addrs, int n)
{
    CONTEXT c; memset(&c, 0, sizeof c);
    c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(th, &c)) { logf_("  [watch] GetThreadContext failed"); return; }
    DWORD dr7 = 0;
    for (int i = 0; i < n && i < 4; i++) {
        (&c.Dr0)[i] = addrs[i];
        dr7 |= (DWORD)1 << (2 * i);
        dr7 |= (DWORD)0x1 << (16 + 4 * i);
        dr7 |= (DWORD)0x3 << (18 + 4 * i);
    }
    c.Dr7 = dr7; c.Dr6 = 0;
    c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!SetThreadContext(th, &c)) logf_("  [watch] SetThreadContext failed (err %lu)", GetLastError());
}

static void watch_arm_all(DWORD *addrs, int n)
{
    logf_("--- arming write watch on %d address(es) ---", n < 4 ? n : 4);
    for (int i = 0; i < n && i < 4; i++) logf_("    DR%d = %08x", i, (unsigned)addrs[i]);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) { logf_("  [watch] no thread snapshot"); return; }
    THREADENTRY32 te; te.dwSize = sizeof te;
    DWORD pid = GetCurrentProcessId(), me = GetCurrentThreadId();
    int armed = 0;
    if (Thread32First(snap, &te)) do {
        if (te.th32OwnerProcessID != pid || te.th32ThreadID == me) continue;
        HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                               FALSE, te.th32ThreadID);
        if (!th) continue;
        SuspendThread(th); watch_arm_thread(th, addrs, n); ResumeThread(th);
        CloseHandle(th); armed++;
    } while (Thread32Next(snap, &te));
    CloseHandle(snap);
    logf_("  [watch] armed on %d thread(s)", armed);
}

static DWORD WINAPI scan_thread(LPVOID unused)
{
    (void)unused;
    /* Heartbeat. A silent log is ambiguous -- it could mean the timer had not
     * elapsed, or that the thread never ran at all, and those need different
     * fixes. Ticking every 10s makes the difference visible, and records the
     * resolution at each tick so we can also see WHEN the F2 climb landed. */
    for (DWORD t = 10; t < g_scan_delay; t += 10) {
        Sleep(10 * 1000);
        logf_("  [alive] %us in, screen %dx%d", (unsigned)t,
              GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
    }
    Sleep((g_scan_delay % 10 ? g_scan_delay % 10 : 10) * 1000);
    logf_("--- live scan: find %u, replace %u, scope %s, after %us ---",
          (unsigned)g_scan_find, (unsigned)g_scan_repl, g_scan_scope, (unsigned)g_scan_delay);
    /* what the game currently believes the screen is -- if this is not the mode you
     * selected, the scan fired at the wrong time and its output means nothing. */
    logf_("  SM_CXSCREEN now %d x %d", GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));

    int n32 = 0, n16 = 0;
    if (!g_scan_find) { logf_("  (poke-only run, no scan)"); }
    else if (!strcmp(g_scan_scope, "all")) {
        MEMORY_BASIC_INFORMATION mbi;
        BYTE *p = NULL;
        while (VirtualQuery(p, &mbi, sizeof mbi) == sizeof mbi) {
            DWORD prot = mbi.Protect & 0xff;
            if (mbi.AllocationBase == (void *)g_self) { /* never rewrite our own image */ }
            else if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD)
                && (prot == PAGE_READWRITE || prot == PAGE_WRITECOPY
                    || prot == PAGE_EXECUTE_READWRITE)) {
                scan_report((BYTE *)mbi.BaseAddress, mbi.RegionSize, "mem", &n32, &n16);
            }
            BYTE *next = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
            if (next <= p) break;
            p = next;
        }
    } else {
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)g_base;
        IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(g_base + dos->e_lfanew);
        SIZE_T img = nt->OptionalHeader.SizeOfImage;
        DWORD old;
        VirtualProtect(g_base, img, PAGE_EXECUTE_READWRITE, &old);
        scan_report(g_base, img, "exe", &n32, &n16);
    }
    logf_("  %d u32 hit(s), %d u16 hit(s)%s", n32, n16,
          g_scan_repl ? " -- ALL OVERWRITTEN" : "");
    if (g_scan_repl && n32 > g_hits)
        logf_("  [!] recorded only %d of %d hits -- the rest are NOT held. Narrow with Lo/Hi.",
              g_hits, n32);
    logf_("--- scan done ---");
    /* ---- group cycling: one run, whole search -------------------------------
     *
     * Replacing ALL hits fixes the terrain (§33) but tells us nothing about WHICH
     * one matters, and the heap re-lays-out between runs so an address is not a
     * stable unit -- ruling out one range per run is expensive in your time.
     *
     * So bisect WITHIN a run. Split the hits into N groups; hold one group at the
     * replacement value while every other hit is held at its original, dwell,
     * then advance. The terrain visibly repairs itself while the guilty group is
     * active. Watch the screen, note when it happens, read the group off the log.
     *
     * Holding the others at the ORIGINAL value matters: otherwise a group tested
     * early stays patched and every later group looks like it works too.
     */
    if (g_scan_groups > 1 && g_hits) {
        int per = (g_hits + (int)g_scan_groups - 1) / (int)g_scan_groups;
        logf_("--- cycling %d hits in %d group(s) of <=%d, %us each ---",
              g_hits, (int)g_scan_groups, per, (unsigned)g_scan_dwell);
        for (int round = 0; ; round++) {
            for (int g = 0; g < (int)g_scan_groups; g++) {
                if (g_scan_group_only >= 0 && g != g_scan_group_only) continue;
                int lo = g * per, hi = lo + per; if (hi > g_hits) hi = g_hits;
                if (lo >= g_hits) continue;
                logf_("[cycle] round %d, GROUP %d  (hits %d..%d)  VA %08x..%08x  -- watch now",
                      round, g, lo, hi - 1,
                      (unsigned)g_hit_addr[lo], (unsigned)g_hit_addr[hi - 1]);
                for (DWORD t = 0; t < g_scan_dwell * 5; t++) {
                    for (int i = 0; i < g_hits; i++)
                        *g_hit[i] = (i >= lo && i < hi) ? g_scan_repl : g_scan_find;
                    Sleep(200);
                }
            }
            logf_("[cycle] round %d complete", round);
        }
    }

    if (g_watch_auto && g_hits) {
        AddVectoredExceptionHandler(1, watch_veh);
        watch_arm_all((DWORD *)(void *)g_hit_addr, g_hits);
    }
    if (g_scan_repeat && g_hits) {
        logf_("--- holding %d scan hit(s) at %u, rewriting every 200ms ---",
              g_hits, (unsigned)g_scan_repl);
        for (;;) {
            Sleep(200);
            for (int i = 0; i < g_hits; i++) *g_hit[i] = g_scan_repl;
            if (g_poke_n) poke_apply(0);
        }
    }
    if (g_poke_n) {
        logf_("--- applying %d poke(s) ---", g_poke_n);
        poke_apply(1);
        while (g_poke_repeat) { Sleep(200); poke_apply(0); }
    }
    return 0;
}

static void maybe_start_scan(void)
{
    char path[MAX_PATH];
    snprintf(path, sizeof path, "%s\\tropico-fix.ini", g_dir);
    maybe_load_pokes();
    g_scan_delay = GetPrivateProfileIntA("Scan", "Delay", 0, path);
    if (!g_scan_delay) g_scan_delay = (DWORD)GetPrivateProfileIntA("Poke", "Delay", 0, path);
    if (!g_scan_delay) return;
    if (!GetPrivateProfileIntA("Scan", "Delay", 0, path)) g_scan_find = 0;  /* poke-only run */
    g_scan_find = GetPrivateProfileIntA("Scan", "Find", 1600, path);
    g_scan_repl = GetPrivateProfileIntA("Scan", "Replace", 0, path);
    g_scan_bits = GetPrivateProfileIntA("Scan", "Bits", 0, path);
    g_scan_repeat = GetPrivateProfileIntA("Scan", "Repeat", 0, path);
    g_scan_groups = GetPrivateProfileIntA("Scan", "Groups", 0, path);
    g_scan_dwell  = GetPrivateProfileIntA("Scan", "Dwell", 15, path);
    g_scan_group_only = (int)GetPrivateProfileIntA("Scan", "GroupOnly", 0xffff, path);
    if (g_scan_group_only == 0xffff) g_scan_group_only = -1;
    g_watch_auto = GetPrivateProfileIntA("Watch", "Auto", 0, path);
    g_watch_max  = GetPrivateProfileIntA("Watch", "Max", 60, path);
    g_scan_lo = (DWORD)GetPrivateProfileIntA("Scan", "Lo", 0, path);
    g_scan_hi = (DWORD)GetPrivateProfileIntA("Scan", "Hi", 0, path);
    GetPrivateProfileStringA("Scan", "Scope", "image", g_scan_scope, sizeof g_scan_scope, path);
    logf_("[*] live scan armed: find %u, replace %u, scope %s, fires %us after load",
          (unsigned)g_scan_find, (unsigned)g_scan_repl, g_scan_scope, (unsigned)g_scan_delay);
    CloseHandle(CreateThread(NULL, 0, scan_thread, NULL, 0, NULL));
}

/* ------------------------------------------------------------------- DllMain */


BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    DisableThreadLibraryCalls(inst);
    g_self = inst;

    GetModuleFileNameA(inst, g_dir, sizeof g_dir);
    char *slash = strrchr(g_dir, '\\');
    if (slash) *slash = 0;
    snprintf(g_logpath, sizeof g_logpath, "%s\\tropico-fix.log", g_dir);
    DeleteFileA(g_logpath);
    logf_("tropico_fix (binkw32 proxy) -- see FINDINGS.md for every address used here");

    /* USER32 is initialised before us: the exe's import descriptors are ordered
     * GDI32, USER32, binkw32, mss32, KERNEL32, and the loader walks them in that
     * order, so EnumDisplaySettings is safe to call from here. */

    /* GOG: .text is plaintext now, so patch immediately and skip the hook.
     * Steam: it is still ciphertext, so the scan finds nothing and we fall back
     * to patching on the first GetDeviceCaps, after the stub has decrypted. */
    /* TROPICO_FIX_DISABLE=1 forwards Bink but applies NOTHING. This is the control
     * for "is a fault mine at all?", runnable without renaming any file -- which
     * matters, because a control that is awkward to run is a control that does not
     * get run, and this project has a history of skipping them (see TESTING.md). */
    char dis[8] = {0};
    GetEnvironmentVariableA("TROPICO_FIX_DISABLE", dis, sizeof dis);
    if (dis[0] == '1') {
        logf_("[*] TROPICO_FIX_DISABLE=1 -- forwarding Bink only, applying NOTHING (control run)");
        return TRUE;
    }

    /* TROPICO_FIX_DEFER=1 forces the deferred path on an unwrapped build. This
     * exists to test the hook-and-patch mechanism itself without needing the
     * Steam DRM to cooperate -- it isolates "does deferral work" from "does
     * SteamStub decrypt in time", which are separate claims. */
    char defer[8] = {0};
    GetEnvironmentVariableA("TROPICO_FIX_DEFER", defer, sizeof defer);
    int force_defer = (defer[0] == '1');
    if (force_defer) logf_("[*] TROPICO_FIX_DEFER=1 -- forcing the deferred path");

    if (!force_defer && locate_sections()
        && find_unique(CHAIN_SIG, sizeof CHAIN_SIG, g_text, g_textlen, "chain-probe")) {
        logf_("[*] .text is readable at load time (unwrapped build) -- patching now");
        apply_patches();
    } else {
        logf_("[*] .text not readable at load time (DRM-wrapped?) -- deferring to GetDeviceCaps");
        if (!install_iat_hook())
            logf_("[x] could not hook GetDeviceCaps -- NOTHING WILL BE PATCHED");
    }
    maybe_start_scan();
    return TRUE;
}

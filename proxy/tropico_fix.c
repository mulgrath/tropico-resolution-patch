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
static int patch_world_viewport(UINT match_w, UINT new_w);
static int patch_hud_probe(void);
static int patch_chrome_scale(DWORD table_va);
static DWORD g_hud_mw, g_hud_mh;
static int g_chr_enable;
static DWORD g_hud_ph_style[8], g_hud_ph_size[8];
static int g_hud_nph;
static DWORD g_hud_table_va;
static int patch_world_draw(UINT match_w, UINT new_w, UINT match_h, UINT new_h,
                            UINT objm, UINT objw, UINT objhm, UINT objh, int force, UINT guard);
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
    g_hud_table_va = table_va;

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

    /* §43: the world viewport. Off by default -- it is the newest patch here and
     * the one most likely to need tuning, so it is opted into from the ini
     * rather than inflicted on a working configuration. */
    {
        char ip[MAX_PATH];
        snprintf(ip, sizeof ip, "%s\\tropico-fix.ini", g_dir);
        if (GetPrivateProfileIntA("WorldFix", "Enable", 0, ip)) {
            UINT mw = (UINT)GetPrivateProfileIntA("WorldFix", "Match", 1600, ip);
            UINT nw = (UINT)GetPrivateProfileIntA("WorldFix", "Width", 0, ip);
            if (!nw) nw = (UINT)m.w;
            int mode_ctor = GetPrivateProfileIntA("WorldFix", "Ctor", 0, ip);
            UINT om = (UINT)GetPrivateProfileIntA("WorldFix", "ObjMatch", 2666, ip);
            UINT ow = (UINT)GetPrivateProfileIntA("WorldFix", "ObjW", 0, ip);
            UINT ohm = (UINT)GetPrivateProfileIntA("WorldFix", "ObjHMatch", 1920, ip);
            UINT oh  = (UINT)GetPrivateProfileIntA("WorldFix", "ObjH", 0, ip);
            UINT mh  = (UINT)GetPrivateProfileIntA("WorldFix", "HMatch", 864, ip);
            UINT nh  = (UINT)GetPrivateProfileIntA("WorldFix", "Height", 0, ip);
            int force = GetPrivateProfileIntA("WorldFix", "Force", 0, ip);
            /* -1 = auto (half the mode width); 0 = no gate at all. */
            int gi = GetPrivateProfileIntA("WorldFix", "Guard", -1, ip);
            UINT guard = force ? (gi < 0 ? (UINT)m.w / 2 : (UINT)gi) : 0;
            /* Force writes unconditionally, so Width defaulting to the mode is
             * exactly right and is not a no-op. */
            if (force && nw == mw) mw = 0;
            /* Match=0 disables only the image-width half: `cmp [ecx+0x10],0` never
             * matches, so control falls straight through to the object block. */
            if (nw == mw && mw != 0) {
                /* A patch that substitutes a value for itself applies cleanly and
                 * does nothing -- and reads as success in the log.  Refuse it. */
                logf_("[x] WorldFix: width %u -> %u is a NO-OP.  Either set"
                      " [WorldFix] Width explicitly, or set [Resolution] Width/Height"
                      " -- slot 4 is only %ux%u this run.", mw, nw, m.w, m.h);
                fail++;
            } else if (patch_world_draw(mw, nw, mh, nh, om, ow, ohm, oh, force, guard)) ok++;
              else fail++;
            if (mode_ctor) { if (patch_world_viewport(mw, nw)) ok++; else fail++; }
        }
    }

    /* s49 probe.  Off unless the ini asks for it -- it deliberately breaks the
     * HUD, so it must never fire on a normal run. */
    {
        char ip[MAX_PATH];
        snprintf(ip, sizeof ip, "%s\\tropico-fix.ini", g_dir);
        if (GetPrivateProfileIntA("HudProbe", "Enable", 0, ip)) {
            g_hud_mw = (DWORD)GetPrivateProfileIntA("HudProbe", "MatchW", 560, ip);
            g_hud_mh = (DWORD)GetPrivateProfileIntA("HudProbe", "MatchH", 560, ip);
            g_chr_enable = GetPrivateProfileIntA("HudProbe", "Chrome", 0, ip);
            for (int k = 0; k < 8; k++) {
                char key[8], buf[32]; unsigned st, sz;
                snprintf(key, sizeof key, "P%d", k);
                GetPrivateProfileStringA("HudProbe", key, "", buf, sizeof buf, ip);
                if (sscanf(buf, "%u,%u", &st, &sz) != 2) break;
                g_hud_ph_style[g_hud_nph] = st; g_hud_ph_size[g_hud_nph] = sz; g_hud_nph++;
            }
            if (!g_hud_nph) {
                logf_("[x] [hudprobe] no phases given (P0=style,size).  Refusing --"
                      " a probe with nothing to cycle would apply cleanly and do nothing.");
                fail++;
            } else if (patch_hud_probe()) ok++; else fail++;
            if (g_chr_enable) { if (patch_chrome_scale(table_va)) ok++; else fail++; }
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
static int g_watch_stack, g_watch_off;
static DWORD g_watch_eip[32]; static int g_watch_neip;

/* Call logging via EXECUTION breakpoints ------------------------------------
 *
 * Watching a framebuffer pixel needs the framebuffer, and two runs have now shown
 * that this configuration puts a surface pointer in none of the three globals
 * that can hold one.  So stop needing it.  A debug register in execute mode is a
 * breakpoint on a FUNCTION, and at the moment it fires ESP still points at the
 * return address and the arguments -- which gives both the values and the caller,
 * with no code patching and nothing to guess.
 *
 * The functions worth watching all set a drawing bound:
 *   0x4e6e40  add clip rect, PIXEL coords     (x1=ecx, y1=edx, x2, y2, which)
 *   0x4e6dd0  add clip rect, VIRTUAL coords   (the 3200x2400 space, section 37)
 *   0x4fcd80  Direct3D SetViewport            (x1=ecx, y1=edx, x2, y2)
 *
 * If any of them is ever handed a right edge near 1599 while the screen is 1920,
 * that is the bound, and the logged return address is the code that computed it.
 * If none ever is, clipping is eliminated as the mechanism -- which is equally
 * worth one run.
 *
 * An instruction breakpoint is a FAULT, not a trap: it fires before the
 * instruction runs, so returning without setting EFLAGS.RF re-enters it forever.
 */
static DWORD wfb_read32(DWORD va);
static WORD  wfb_read16(DWORD va);
static DWORD g_site_addr[4]; static int g_site_kind[4], g_nsite;
/* [WorldW]: rewrite the world display object's width field every frame, cycling
 * through phases so one run tests several values.  §40 measured the object at
 * 2666x1920 VIRTUAL units, which is 1600x864 pixels at 1920x1080 -- exactly the
 * terrain cutoff and exactly the 864 ceiling.  This is the test that decides
 * whether that field IS the bound.  The lowering phase is the informative one:
 * raising a limit and seeing nothing is ambiguous, but if the cutoff moves
 * INWARD when the field is lowered, the field controls it (TESTING.md). */
static DWORD g_ww_vt, g_ww_dwell, g_ww_phase[4]; static int g_ww_nphase, g_ww_last = -1;
static DWORD g_ww_t0;
/* [ImgW]: the SOURCE image width, in pixels, at [image+0x10].
 * §41 showed the world display object's rect is only a clip: lowering it moved
 * the cutoff inward, raising it produced no new terrain, so the content itself
 * stops at 1600.  The painter registered in DAT_0060a628 is 0x526220, and it
 * takes the image in ECX and reads its pixel width from [ecx+0x10] -- the field
 * copied to 0x614418, the global §32 measured holding 1600.
 * Only the world's own call is touched: at function entry [esp] is the return
 * address, and 0x50b15b is the call inside FUN_0050b100. */
static DWORD g_iw_dwell, g_iw_phase[4], g_iw_match; static int g_iw_nphase, g_iw_last = -1;
static DWORD g_iw_t0; static int g_iw_seen;
static DWORD g_seen_key[256]; static int g_nseen_key, g_clip_max;

static const char *site_name(int kind)
{
    return kind == 1 ? "clip-px" : kind == 2 ? "clip-virt" : kind == 3 ? "viewport"
         : kind == 4 ? "objrect" : kind == 5 ? "objsize"
         : kind == 6 ? "worldw" : kind == 7 ? "imgw" : "?";
}

static LONG CALLBACK watch_veh(EXCEPTION_POINTERS *ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;
    DWORD eip = ep->ContextRecord->Eip;

    /* An execution breakpoint reports EIP == the watched function's entry. */
    for (int i = 0; i < g_nsite; i++) {
        if (!g_site_kind[i] || eip != g_site_addr[i]) continue;
        ep->ContextRecord->EFlags |= 0x10000;      /* RF: do not re-fault */
        ep->ContextRecord->Dr6 = 0;
        DWORD *sp = (DWORD *)(SIZE_T)ep->ContextRecord->Esp;
        DWORD ret = 0, a3 = 0, a4 = 0, a5 = 0;
        if (!IsBadReadPtr(sp, 16)) { ret = sp[0]; a3 = sp[1]; a4 = sp[2]; a5 = sp[3]; }
        DWORD ecx = ep->ContextRecord->Ecx, edx = ep->ContextRecord->Edx;
        /* Deduping on the full argument tuple would blow the cap instantly --
         * every sprite pushes a different rect.  Dedupe on the CALLER instead,
         * which is what we actually want to enumerate, and keep a second,
         * separate budget for rects whose edge lands in the suspicious bands:
         * 1550..1650 in pixels, or 3100..3300 in the virtual 3200x2400 space
         * (section 37).  Those are logged even from a caller already seen. */
        /* kind 4: 0x52be38, the instruction after the vtable+0x50 call in
         * FUN_0052bdb0.  At that point the object's screen rectangle is sitting
         * in four globals, and ESI is the display object.  Every drawn object
         * announces its own extent here, so one run enumerates them -- and the
         * terrain's, if it really is bounded at 1600, cannot hide.
         * Logging [esi] (the vtable) identifies the CLASS, which is what we can
         * then chase statically. */
        if (g_site_kind[i] == 4) {
            DWORD x1 = wfb_read32(0x60bc3c), y1 = wfb_read32(0x60bc38);
            DWORD x2 = wfb_read32(0x60bc08), y2 = wfb_read32(0x60bc04);
            DWORD obj = ep->ContextRecord->Esi, vt = 0;
            if (obj && !IsBadReadPtr((void *)(SIZE_T)obj, 4)) memcpy(&vt, (void *)(SIZE_T)obj, 4);
            int hot4 = ((int)x2 >= 1500 && (int)x2 <= 1700);
            DWORD k = vt * 2654435761u ^ (hot4 ? x2 * 40503u : 0u) ^ 4u;
            for (int q = 0; q < g_nseen_key; q++) if (g_seen_key[q] == k)
                return EXCEPTION_CONTINUE_EXECUTION;
            if (g_nseen_key >= 256 || g_nseen_key >= g_clip_max) {
                if (!g_watch_off) { ep->ContextRecord->Dr7 = 0; g_watch_off = 1;
                                    logf_("  [cliplog] limit reached, disarmed"); }
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            g_seen_key[g_nseen_key++] = k;
            logf_("  %s[objrect] x1=%-6d y1=%-6d x2=%-6d y2=%-6d  w=%-5d obj=%08x vtable=%08x (+%x)",
                  hot4 ? "!! " : "   ", (int)x1, (int)y1, (int)x2, (int)y2,
                  (int)x2 - (int)x1 + 1, (unsigned)obj, (unsigned)vt,
                  (unsigned)(vt - (DWORD)(SIZE_T)g_base));
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        /* kind 5: 0x52be55, the call to FUN_004e7150.  ESI is the display object
         * and the four bound getters (vtable +0x44/+0x48/+0x4c/+0x50) read these
         * fields off it directly:
         *      obj+0x0b  x        (int16)
         *      obj+0x0d  y        (int16)
         *      obj+0x0f  width    (int16)
         *      obj+0x11  height   (int16)
         *      obj+0x5a  container -> +0x11 originX, +0x15 originY
         * so this logs each object's DECLARED size, not a rect already
         * intersected with a damage region.  Deduped by (vtable, w, h): one line
         * per class per distinct size. */
        if (g_site_kind[i] == 5) {
            DWORD obj = ep->ContextRecord->Esi, vt = 0, cont = 0;
            short ox = 0, oy = 0, ow = 0, oh = 0;
            int cx = 0, cy = 0;
            if (!obj || IsBadReadPtr((void *)(SIZE_T)obj, 0x5e))
                return EXCEPTION_CONTINUE_EXECUTION;
            BYTE *o = (BYTE *)(SIZE_T)obj;
            memcpy(&vt, o, 4);
            memcpy(&ox, o + 0x0b, 2); memcpy(&oy, o + 0x0d, 2);
            memcpy(&ow, o + 0x0f, 2); memcpy(&oh, o + 0x11, 2);
            memcpy(&cont, o + 0x5a, 4);
            if (cont && !IsBadReadPtr((void *)(SIZE_T)cont, 0x19)) {
                memcpy(&cx, (BYTE *)(SIZE_T)cont + 0x11, 4);
                memcpy(&cy, (BYTE *)(SIZE_T)cont + 0x15, 4);
            }
            DWORD k = vt * 2654435761u ^ (DWORD)(unsigned short)ow * 40503u
                    ^ (DWORD)(unsigned short)oh * 2246822519u ^ 5u;
            for (int q = 0; q < g_nseen_key; q++) if (g_seen_key[q] == k)
                return EXCEPTION_CONTINUE_EXECUTION;
            if (g_nseen_key >= 256 || g_nseen_key >= g_clip_max) {
                if (!g_watch_off) { ep->ContextRecord->Dr7 = 0; g_watch_off = 1;
                                    logf_("  [cliplog] limit reached, disarmed"); }
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            g_seen_key[g_nseen_key++] = k;
            logf_("  %s[objsize] w=%-6d h=%-6d  x=%-6d y=%-6d origin=(%d,%d)  "
                  "vtable=%08x (+%x) obj=%08x",
                  (ow == 1600 || oh == 1600 || ow == 864) ? "!! " : "   ",
                  (int)ow, (int)oh, (int)ox, (int)oy, cx, cy,
                  (unsigned)vt, (unsigned)(vt - (DWORD)(SIZE_T)g_base), (unsigned)obj);
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        if (g_site_kind[i] == 7) {
            if (ret != (DWORD)(SIZE_T)(g_base + 0x10b15b))
                return EXCEPTION_CONTINUE_EXECUTION;
            DWORD img = ep->ContextRecord->Ecx;
            if (!img || IsBadReadPtr((void *)(SIZE_T)img, 0x18))
                return EXCEPTION_CONTINUE_EXECUTION;
            BYTE *m = (BYTE *)(SIZE_T)img;
            DWORD iw = 0, ih = 0, ix = 0, iy = 0;
            memcpy(&ix, m + 0x08, 4); memcpy(&iy, m + 0x0c, 4);
            memcpy(&iw, m + 0x10, 4); memcpy(&ih, m + 0x14, 4);
            if (!g_iw_seen) {
                g_iw_seen = 1;
                logf_("  [imgw] world source image: x=%d y=%d w=%d h=%d  (image %08x)",
                      (int)ix, (int)iy, (int)iw, (int)ih, (unsigned)img);
            }
            if (g_iw_match && iw != g_iw_match && (DWORD)g_iw_last == 0xffffffffu)
                return EXCEPTION_CONTINUE_EXECUTION;
            DWORD el = (GetTickCount() - g_iw_t0) / (g_iw_dwell * 1000);
            int ph = (int)(el % (DWORD)g_iw_nphase);
            if (ph != g_iw_last) {
                g_iw_last = ph;
                logf_("  [imgw] phase %d: source width %d -> %s%d", ph, (int)iw,
                      g_iw_phase[ph] ? "" : "unchanged ",
                      (int)(g_iw_phase[ph] ? g_iw_phase[ph] : iw));
            }
            if (g_iw_phase[ph]) {
                DWORD nw = g_iw_phase[ph];
                memcpy(m + 0x10, &nw, 4);
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        if (g_site_kind[i] == 6) {
            DWORD obj = ep->ContextRecord->Esi, vt = 0;
            if (!obj || IsBadReadPtr((void *)(SIZE_T)obj, 0x14))
                return EXCEPTION_CONTINUE_EXECUTION;
            BYTE *o = (BYTE *)(SIZE_T)obj;
            memcpy(&vt, o, 4);
            if (vt != g_ww_vt) return EXCEPTION_CONTINUE_EXECUTION;
            DWORD el = (GetTickCount() - g_ww_t0) / (g_ww_dwell * 1000);
            int ph = (int)(el % (DWORD)g_ww_nphase);
            short cur = 0; memcpy(&cur, o + 0x0f, 2);
            if (g_ww_phase[ph]) {
                short nw = (short)g_ww_phase[ph];
                memcpy(o + 0x0f, &nw, 2);
            }
            if (ph != g_ww_last) {
                g_ww_last = ph;
                logf_("  [worldw] phase %d: width %d -> %s%d   (~%d px at this mode)  "
                      "obj=%08x", ph, (int)cur,
                      g_ww_phase[ph] ? "" : "unchanged ", (int)(g_ww_phase[ph] ? g_ww_phase[ph]
                                                                              : (DWORD)cur),
                      (int)((g_ww_phase[ph] ? g_ww_phase[ph] : (DWORD)cur)
                            * (DWORD)wfb_read16(0x60c18c) / 3200), (unsigned)obj);
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        int hot = 0;
        DWORD v[4] = { ecx, edx, a3, a4 };
        for (int q = 0; q < 4; q++)
            if ((v[q] >= 1550 && v[q] <= 1650) || (v[q] >= 3100 && v[q] <= 3300)) hot = 1;

        DWORD key = ret * 668265263u ^ (DWORD)g_site_kind[i] * 2654435761u
                  ^ (hot ? (a3 * 2246822519u ^ ecx * 40503u) : 0u);
        for (int k = 0; k < g_nseen_key; k++) if (g_seen_key[k] == key)
            return EXCEPTION_CONTINUE_EXECUTION;
        if (g_nseen_key >= 256 || g_nseen_key >= g_clip_max) {
            if (!g_watch_off) { ep->ContextRecord->Dr7 = 0; g_watch_off = 1;
                                logf_("  [cliplog] limit reached, disarmed"); }
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        g_seen_key[g_nseen_key++] = key;
        logf_("  %s[%s] x1=%-6d y1=%-6d x2=%-6d y2=%-6d a5=%-6d  <- caller %08x (+%x)",
              hot ? "!! " : "   ", site_name(g_site_kind[i]),
              (int)ecx, (int)edx, (int)a3, (int)a4, (int)a5,
              (unsigned)ret, (unsigned)(ret - (DWORD)(SIZE_T)g_base));
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    int known = 0;
    for (int i = 0; i < g_watch_neip; i++) if (g_watch_eip[i] == eip) { known = 1; break; }
    if (!known && g_watch_neip < 32) {
        g_watch_eip[g_watch_neip++] = eip;
        DWORD dr6 = ep->ContextRecord->Dr6 & 0xf;
        logf_("  [watch] store from EIP %08x   (module+0x%x)  DR%s",
              (unsigned)eip, (unsigned)(eip - (DWORD)(SIZE_T)g_base),
              dr6 & 1 ? "0" : dr6 & 2 ? "1" : dr6 & 4 ? "2" : dr6 & 8 ? "3" : "?");
        /* Walk the stack for return addresses.  EIP alone names the rasteriser;
         * the callers are what compute its bounds, and that is the actual
         * question.  No EBP chain is assumed -- frame pointers are omitted in the
         * hot loops -- so this scans raw stack words and keeps the ones that
         * point into .text.  Some will be stale data; a repeated address across
         * several traps is the real one. */
        if (g_watch_stack > 0 && g_text) {
            DWORD *sp = (DWORD *)(SIZE_T)ep->ContextRecord->Esp;
            DWORD lo = (DWORD)(SIZE_T)g_text, hi = lo + (DWORD)g_textlen;
            char line[512]; int n = 0;
            int len = snprintf(line, sizeof line, "            stack:");
            for (int i = 0; i < 256 && n < g_watch_stack; i++) {
                DWORD v;
                if (IsBadReadPtr(sp + i, 4)) break;
                v = sp[i];
                if (v <= lo || v >= hi) continue;
                len += snprintf(line + len, sizeof line - (size_t)len, " %08x(+%x)",
                                (unsigned)v, (unsigned)(v - (DWORD)(SIZE_T)g_base));
                n++;
                if (len > (int)sizeof line - 40) break;
            }
            if (n) logf_("%s", line);
        }
    }
    if (++g_watch_seen > g_watch_max) {           /* disarm to stop flooding */
        ep->ContextRecord->Dr7 = 0;
        g_watch_off = 1;
        logf_("  [watch] limit reached, disarmed");
    }
    ep->ContextRecord->Dr6 = 0;
    return EXCEPTION_CONTINUE_EXECUTION;
}

/* DR7 for slot i: local-enable bit (2i), RW bits at 16+4i, LEN bits at 18+4i.
 * RW 01 = write, 00 = execute; LEN 11 = four bytes, 00 = one byte (required for
 * execute).  g_exec_mode switches the whole set between the two. */
static int g_exec_mode;
static void watch_arm_thread(HANDLE th, DWORD *addrs, int n)
{
    CONTEXT c; memset(&c, 0, sizeof c);
    c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(th, &c)) { logf_("  [watch] GetThreadContext failed"); return; }
    DWORD dr7 = 0;
    for (int i = 0; i < n && i < 4; i++) {
        (&c.Dr0)[i] = addrs[i];
        dr7 |= (DWORD)1 << (2 * i);
        dr7 |= (DWORD)(g_exec_mode ? 0x0 : 0x1) << (16 + 4 * i);
        dr7 |= (DWORD)(g_exec_mode ? 0x0 : 0x3) << (18 + 4 * i);
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

/* ------------------------------------------------- framebuffer pixel watch
 *
 * FINDINGS 36 left the question "which code draws the terrain?" unanswered, and
 * every static search for the number 1600 has now been exhausted (every 0x640
 * and 0xc80 immediate in the image is accounted for; no float, no derived array,
 * no second table).  So stop looking for the value and go and find the CODE, by
 * catching it in the act.
 *
 * The software renderer addresses pixels as
 *      DAT_0060c191 + (DAT_0060c18c * y + x) * bpp
 * so a hardware write breakpoint on one pixel INSIDE the terrain traps in the
 * terrain rasteriser itself, with EIP naming it and the stack naming its callers.
 * Those callers are where the bound is computed.
 *
 * Two columns are watched at once, which makes the run self-checking:
 *   X  (e.g. 1500) is inside the drawn terrain  -> must trap
 *   X2 (e.g. 1700) is beyond the cutoff         -> if it also traps, something
 *                                                  DOES draw there and the
 *                                                  premise "nothing is drawn"
 *                                                  is wrong
 *
 *   [WatchFB]
 *   Delay=60     seconds before arming: you must already be in the map at the
 *                target resolution, so allow map load plus the F2 climb
 *   X=1500       column inside the terrain
 *   X2=1700      column past the cutoff (0 disables)
 *   Y=400        row -- pick one that is terrain, not HUD
 *   Max=24       stop after this many distinct traps
 *   Stack=8      stack return addresses to log per trap
 *   Rearm=120    seconds to keep re-reading the surface pointer and re-arming
 *
 * The surface pointer moves when the game locks a different back buffer, so a
 * one-shot arm can silently watch a stale address -- the same "derived value has
 * to be held, not set" trap as the pokes.  Re-arm whenever it changes.
 */
static DWORD g_wfb_delay, g_wfb_x, g_wfb_x2, g_wfb_x3, g_wfb_y, g_wfb_rearm;
static DWORD g_wfb_base_ovr, g_wfb_stride_ovr;

static DWORD wfb_read32(DWORD va)
{
    DWORD v = 0;
    BYTE *p = g_base + (va - 0x400000);
    memcpy(&v, p, 4);
    return v;
}
static WORD wfb_read16(DWORD va)
{
    WORD v = 0;
    BYTE *p = g_base + (va - 0x400000);
    memcpy(&v, p, 2);
    return v;
}

/* Which global holds the locked surface depends on the configuration.  0052d085:
 *
 *      eax = ds:0x612fe8
 *      if      ([eax+0x18]) ds:0x61c818 = lpSurface;   stride = [eax+0x18]
 *      else if ([eax+0x38]) ds:0x61c81c = lpSurface;   stride = [eax+0x38]
 *      else                 ds:0x60c191 = lpSurface;   stride = ds:0x60c18c
 *
 * The strides are in PIXELS, not bytes: FUN_0052c5f0 addresses 0x61c81c as
 * (stride * y + x) * 2, exactly the shape of the 0x60c191 formula in section 36.
 *
 * The first run of this watch read only 0x60c191, found it NULL, and armed
 * nothing -- which is why all three are read and logged now, and why the choice
 * is overridable from the ini without a rebuild. */
static void wfb_pick(DWORD *base_out, DWORD *stride_out, int announce)
{
    DWORD p91 = wfb_read32(0x60c191), p18 = wfb_read32(0x61c818), p1c = wfb_read32(0x61c81c);
    DWORD dev = wfb_read32(0x612fe8);
    DWORD s18 = 0, s38 = 0;
    if (dev && !IsBadReadPtr((void *)(SIZE_T)dev, 0x3c)) {
        memcpy(&s18, (BYTE *)(SIZE_T)(dev + 0x18), 4);
        memcpy(&s38, (BYTE *)(SIZE_T)(dev + 0x38), 4);
    }
    if (announce)
        logf_("  [watchfb] surfaces: 0x60c191=%08x 0x61c818=%08x 0x61c81c=%08x | "
              "dev=%08x [+0x18]=%u [+0x38]=%u | width=%u",
              (unsigned)p91, (unsigned)p18, (unsigned)p1c, (unsigned)dev,
              (unsigned)s18, (unsigned)s38, (unsigned)wfb_read16(0x60c18c));

    DWORD base = 0, stride = 0;
    if (g_wfb_base_ovr) { base = wfb_read32(g_wfb_base_ovr); stride = 0; }
    else if (s18 && p18)  { base = p18; stride = s18; }
    else if (s38 && p1c)  { base = p1c; stride = s38; }
    else if (p91)         { base = p91; stride = wfb_read16(0x60c18c); }
    else if (p18)         { base = p18; stride = s18; }
    else if (p1c)         { base = p1c; stride = s38; }
    if (g_wfb_stride_ovr) stride = g_wfb_stride_ovr;
    if (!stride) stride = wfb_read16(0x60c18c);
    /* A surface pitch below the screen width is not a surface pitch.  The first
     * run fell through to base=0185adc9 stride=4 and armed on unrelated heap,
     * which then trapped and produced two authoritative-looking but meaningless
     * EIPs.  Refuse rather than report garbage. */
    if (base && stride < wfb_read16(0x60c18c)) {
        if (announce) logf_("  [watchfb] rejecting base %08x: stride %u < width %u",
                            (unsigned)base, (unsigned)stride, (unsigned)wfb_read16(0x60c18c));
        base = 0;
    }
    *base_out = base; *stride_out = stride;
}

static DWORD WINAPI watchfb_thread(LPVOID unused)
{
    (void)unused;
    for (DWORD t = 10; t < g_wfb_delay; t += 10) {
        Sleep(10 * 1000);
        logf_("  [alive] %us in, screen %dx%d", (unsigned)t,
              GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
    }
    Sleep((g_wfb_delay % 10 ? g_wfb_delay % 10 : 10) * 1000);

    AddVectoredExceptionHandler(1, watch_veh);

    DWORD last = 0, seen_bases[2]; int nseen = 0, armed = 0, rearms = 0;
    DWORD until  = GetTickCount() + g_wfb_rearm * 1000;
    DWORD settle = GetTickCount() + 4000;
    DWORD report = 0;
    int announced = 0;

    for (;;) {
        DWORD base = 0, stride = 0;
        WORD  w = wfb_read16(0x60c18c), h = wfb_read16(0x60c18e);
        int   bpp = wfb_read32(0x5a0f88) ? 1 : 2;

        if (!announced) {
            logf_("--- [watchfb] arming: game says %ux%u, %d byte(s)/px; SM_CXSCREEN %dx%d ---",
                  (unsigned)w, (unsigned)h, bpp,
                  GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
            if (g_wfb_y >= h || g_wfb_x >= w)
                logf_("  [watchfb] !! X=%u Y=%u is outside %ux%u -- nothing will trap",
                      (unsigned)g_wfb_x, (unsigned)g_wfb_y, (unsigned)w, (unsigned)h);
        }
        /* Re-report the pointer set every 10s while nothing has been found: the
         * surface may only be non-NULL between Lock and Unlock, and a run that
         * saw it NULL every time has to be distinguishable from one that never
         * looked. */
        int announce = !announced || (!armed && GetTickCount() > report);
        if (announce) { report = GetTickCount() + 10000; }
        wfb_pick(&base, &stride, announce);
        announced = 1;

        if (base) {
            int known = 0;
            for (int i = 0; i < nseen; i++) if (seen_bases[i] == base) known = 1;
            if (!known && nseen < 2) seen_bases[nseen++] = base;
            int changed = (base != last);
            last = base;

            /* The arming test must be evaluated EVERY poll, not only when the
             * pointer changes.  A single stable surface changes exactly once --
             * on the first poll, before the settle timer has expired -- so
             * nesting this inside "changed" meant a perfectly good base was
             * found and then never armed on.  That is what the software-mode
             * run did: 0x60c191 = 07d60030 for 60 s, armed=0. */
            int fresh = (changed && !known && armed && !g_watch_neip && rearms < 8);
            if ((!armed && (nseen == 2 || GetTickCount() > settle)) || fresh) {
                DWORD cols[3] = { g_wfb_x, g_wfb_x2, g_wfb_x3 };
                DWORD a[4]; int n = 0;
                logf_("  [watchfb] base(s) %08x%s%08x, stride %u px, %d byte(s)/px",
                      (unsigned)seen_bases[0], nseen > 1 ? " / " : "",
                      nseen > 1 ? (unsigned)seen_bases[1] : 0u, (unsigned)stride, bpp);
                for (int i = 0; i < nseen && n < 4; i++)
                    for (int c = 0; c < 3 && n < 4; c++) {
                        if (!cols[c]) continue;
                        a[n] = (seen_bases[i] + ((DWORD)stride * g_wfb_y + cols[c])
                                * (DWORD)bpp) & ~3u;
                        logf_("  [watchfb] DR%d = %08x   (surface %08x, x=%u, y=%u)",
                              n, (unsigned)a[n], (unsigned)seen_bases[i],
                              (unsigned)cols[c], (unsigned)g_wfb_y);
                        n++;
                    }
                watch_arm_all(a, n);
                armed = 1; rearms++;
                if (fresh) { nseen = 1; seen_bases[0] = base; }
            }
        }

        if (g_watch_off || (g_wfb_rearm && GetTickCount() > until)) {
            logf_("--- [watchfb] finished: %d distinct EIP(s), armed=%d ---", g_watch_neip, armed);
            if (!armed) logf_("  [watchfb] never armed: no surface pointer was ever non-NULL. "
                              "In Hardware 3D there is no CPU framebuffer and this is expected; "
                              "in Software it means the surface lives somewhere else again.");
            if (armed) { DWORD none[1] = {0}; watch_arm_all(none, 0); }   /* leave DRs free */
            return 0;
        }
        Sleep(armed ? 500 : 2);     /* before arming, poll hard: the pointer may
                                     * only be live inside a Lock/Unlock pair */
    }
}

/*   [ClipLog]
 *   Delay=60     seconds before arming -- be in the map at the target mode
 *   Window=20    seconds to stay armed (every call traps, so this is not free)
 *   Max=150      distinct (args, caller) tuples to log
 *   Sites=7      bitmask: 1 = clip-px 0x4e6e40, 2 = clip-virt 0x4e6dd0,
 *                4 = viewport 0x4fcd80
 */
static DWORD g_clip_delay, g_clip_window, g_clip_sites;

static DWORD WINAPI cliplog_thread(LPVOID unused)
{
    (void)unused;
    for (DWORD t = 10; t < g_clip_delay; t += 10) {
        Sleep(10 * 1000);
        logf_("  [alive] %us in, screen %dx%d", (unsigned)t,
              GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
    }
    Sleep((g_clip_delay % 10 ? g_clip_delay % 10 : 10) * 1000);

    g_watch_off = 0;        /* WatchFB may have run and finished before us */
    g_nseen_key = 0;
    logf_("--- [cliplog] arming: game says %ux%u; SM_CXSCREEN %dx%d ---",
          (unsigned)wfb_read16(0x60c18c), (unsigned)wfb_read16(0x60c18e),
          GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));

    DWORD a[4]; int n = 0;
    if (g_clip_sites & 1) { g_site_addr[n] = (DWORD)(SIZE_T)(g_base + 0x0e6e40); g_site_kind[n] = 1; n++; }
    if (g_clip_sites & 2) { g_site_addr[n] = (DWORD)(SIZE_T)(g_base + 0x0e6dd0); g_site_kind[n] = 2; n++; }
    if (g_clip_sites & 4) { g_site_addr[n] = (DWORD)(SIZE_T)(g_base + 0x0fcd80); g_site_kind[n] = 3; n++; }
    if (g_clip_sites & 8) { g_site_addr[n] = (DWORD)(SIZE_T)(g_base + 0x12be38); g_site_kind[n] = 4; n++; }
    if (g_clip_sites & 16) { g_site_addr[n] = (DWORD)(SIZE_T)(g_base + 0x12be55); g_site_kind[n] = 5; n++; }
    /* 0x52be35 is the first bound-getter call, so a write here is seen by all
     * four getters in the same frame. */
    if (g_clip_sites & 32) { g_site_addr[n] = (DWORD)(SIZE_T)(g_base + 0x12be35); g_site_kind[n] = 6; n++; }
    if (g_clip_sites & 64) { g_site_addr[n] = (DWORD)(SIZE_T)(g_base + 0x126220); g_site_kind[n] = 7; n++; }
    g_nsite = n;
    for (int i = 0; i < n; i++) {
        a[i] = g_site_addr[i];
        logf_("  [cliplog] DR%d = %08x  (%s)", i, (unsigned)a[i], site_name(g_site_kind[i]));
    }
    AddVectoredExceptionHandler(1, watch_veh);
    g_exec_mode = 1;
    g_ww_t0 = GetTickCount(); g_iw_t0 = g_ww_t0;
    watch_arm_all(a, n);

    /* Keep ticking while armed.  The previous run ended between the 50 s tick
     * and the 60 s arm, and the log could not distinguish "quit early" from
     * "crashed on arming" because nothing was written after arming either way.
     * A heartbeat inside the window makes the two look different. */
    for (DWORD t = 0; t < g_clip_window; t += 10) {
        Sleep((g_clip_window - t < 10 ? g_clip_window - t : 10) * 1000);
        logf_("  [armed] %us into the window, %d tuple(s) so far", (unsigned)(t + 10),
              g_nseen_key);
        if (g_watch_off) break;
    }
    g_watch_off = 1;
    { DWORD none[1] = {0}; g_exec_mode = 0; g_nsite = 0; watch_arm_all(none, 0); }
    logf_("--- [cliplog] disarmed, %d distinct tuple(s) ---", g_nseen_key);
    if (!g_nseen_key)
        logf_("  [cliplog] nothing trapped at all -- either the breakpoints did not "
              "take (Wine ptrace) or none of these functions runs in this renderer");
    return 0;
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

static void maybe_start_watchfb(void)
{
    char path[MAX_PATH];
    snprintf(path, sizeof path, "%s\\tropico-fix.ini", g_dir);
    g_wfb_delay = GetPrivateProfileIntA("WatchFB", "Delay", 0, path);
    if (!g_wfb_delay) return;
    if (!g_base) { logf_("[x] [watchfb] module base unknown -- not arming"); return; }
    g_wfb_x     = GetPrivateProfileIntA("WatchFB", "X", 1500, path);
    g_wfb_x2    = GetPrivateProfileIntA("WatchFB", "X2", 1700, path);
    g_wfb_x3    = GetPrivateProfileIntA("WatchFB", "X3", 0, path);
    g_wfb_y     = GetPrivateProfileIntA("WatchFB", "Y", 400, path);
    g_wfb_rearm = GetPrivateProfileIntA("WatchFB", "Rearm", 120, path);
    {   char buf[32];
        GetPrivateProfileStringA("WatchFB", "Base", "", buf, sizeof buf, path);
        g_wfb_base_ovr = buf[0] ? (DWORD)strtoul(buf, NULL, 0) : 0;
    }
    g_wfb_stride_ovr = GetPrivateProfileIntA("WatchFB", "Stride", 0, path);
    g_watch_max   = GetPrivateProfileIntA("WatchFB", "Max", 24, path);
    g_watch_stack = GetPrivateProfileIntA("WatchFB", "Stack", 8, path);
    logf_("[*] framebuffer watch armed: x=%u x2=%u x3=%u y=%u, fires %us after load, "
          "max %d trap(s), %d stack word(s)",
          (unsigned)g_wfb_x, (unsigned)g_wfb_x2, (unsigned)g_wfb_x3, (unsigned)g_wfb_y,
          (unsigned)g_wfb_delay, g_watch_max, g_watch_stack);
    CloseHandle(CreateThread(NULL, 0, watchfb_thread, NULL, 0, NULL));
}

static void maybe_start_cliplog(void)
{
    char path[MAX_PATH];
    snprintf(path, sizeof path, "%s\\tropico-fix.ini", g_dir);
    g_clip_delay = GetPrivateProfileIntA("ClipLog", "Delay", 0, path);
    if (!g_clip_delay) return;
    if (!g_base) { logf_("[x] [cliplog] module base unknown -- not arming"); return; }
    g_clip_window = GetPrivateProfileIntA("ClipLog", "Window", 20, path);
    g_clip_max    = GetPrivateProfileIntA("ClipLog", "Max", 150, path);
    g_clip_sites  = GetPrivateProfileIntA("ClipLog", "Sites", 7, path);
    {   char buf[32];
        GetPrivateProfileStringA("WorldW", "Vtable", "0x57e110", buf, sizeof buf, path);
        g_ww_vt = (DWORD)strtoul(buf, NULL, 0);
    }
    g_ww_dwell = GetPrivateProfileIntA("WorldW", "Dwell", 15, path);
    if (!g_ww_dwell) g_ww_dwell = 15;
    for (int i = 0; i < 4; i++) {
        char k[8]; snprintf(k, sizeof k, "W%d", i);
        int v = GetPrivateProfileIntA("WorldW", k, -1, path);
        if (v < 0) break;
        g_ww_phase[g_ww_nphase++] = (DWORD)v;
    }
    if (!g_ww_nphase) { g_ww_phase[0] = 0; g_ww_nphase = 1; }
    g_iw_dwell = GetPrivateProfileIntA("ImgW", "Dwell", 20, path);
    if (!g_iw_dwell) g_iw_dwell = 20;
    g_iw_match = GetPrivateProfileIntA("ImgW", "Match", 0, path);
    for (int i = 0; i < 4; i++) {
        char k[8]; snprintf(k, sizeof k, "W%d", i);
        int v = GetPrivateProfileIntA("ImgW", k, -1, path);
        if (v < 0) break;
        g_iw_phase[g_iw_nphase++] = (DWORD)v;
    }
    if (!g_iw_nphase) { g_iw_phase[0] = 0; g_iw_nphase = 1; }
    logf_("[*] clip/viewport call log armed: sites 0x%x, fires %us after load, "
          "%us window, max %d tuple(s)",
          (unsigned)g_clip_sites, (unsigned)g_clip_delay, (unsigned)g_clip_window, g_clip_max);
    CloseHandle(CreateThread(NULL, 0, cliplog_thread, NULL, 0, NULL));
}

/* ------------------------------------------- the world viewport width (§43)
 *
 * FUN_0050af10, the constructor for display-object class 0x57e110 (the world),
 * copies the object's own size fields into the embedded image's PIXEL size:
 *
 *   0050af89  movsx ecx,WORD PTR [esi+0x11]     ; object height
 *   0050af8d  movsx eax,WORD PTR [esi+0x0f]     ; object width
 *   0050af91  mov   [esi+0x8e],ecx              ; -> image.height  (= image+0x14)
 *   0050afa9  mov   [esi+0x8a],eax              ; -> image.width   (= image+0x10)
 *
 * §42 measured that image at 1600x864 px while the screen was 1920x1080, and
 * §43 showed that forcing its width to 1920 at DRAW time makes Hardware 3D
 * render the full width correctly.  Doing it HERE instead sets the size before
 * anything downstream is prepared from it, which is the difference between a
 * debug-register hack and a patch that can ship -- and it is the only way to
 * find out whether the software renderer's smear is a stale buffer or merely a
 * refresh region that was never told it got wider.
 *
 * Eight bytes are replaced by a jump to a stub that reproduces both movsx
 * instructions, substitutes the width when it is the stock 1600, and jumps back.
 * An inline detour rather than a debug register: no exception per frame, and it
 * survives without the VEH.
 */
/* The DRAW-time detour: the one that is known to work (§43).
 *
 * The constructor patch below applied cleanly and never fired, so the viewport
 * size is not final when the object is built -- it is set again later, most
 * likely on the F2 mode change, since the object is created during map load at
 * 640x480.  Rather than guess at the birth site a second time, patch where the
 * value was actually MEASURED to be 1600: the painter's entry.
 *
 *   00526220  sub  esp,0x2c            <- 7 bytes replaced by a jump
 *   00526223  fild DWORD PTR [esp+0x30]
 *   00526227  ...
 *
 * At entry ESP still points at the return address, so the world's own call is
 * identified by [esp] == 0x50b15b and no other image blit is touched.  ECX is
 * the image; [ecx+0x10] is its pixel width.
 */
static const BYTE DRAW_SIG[] = { 0x83,0xec,0x2c, 0xdb,0x44,0x24,0x30, 0x53,0x55,0x56 };

/* force: emit the stores with no comparison at all.  The stock values are
 * mode-dependent (1600/864 are what the image measures at a 1920 mode, and 1600
 * came from a 1599.6 the engine rounded), so at any other mode a hardcoded match
 * silently never fires.  The return-address filter, not the compare, is what
 * keeps this off every other image. */
static int patch_world_draw(UINT match_w, UINT new_w, UINT match_h, UINT new_h,
                            UINT objm, UINT objw, UINT objhm, UINT objh, int force, UINT guard)
{
    BYTE *at = find_unique(DRAW_SIG, sizeof DRAW_SIG, g_text, g_textlen, "world painter");
    if (!at) return 0;
    BYTE *stub = (BYTE *)VirtualAlloc(NULL, 128, MEM_COMMIT | MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);
    if (!stub) { logf_("[x] world painter: VirtualAlloc failed"); return 0; }

    DWORD callsite = (DWORD)(SIZE_T)(g_base + 0x10b15b);
    BYTE *ret_to = at + 7;
    int i = 0, fix_top, fix_gate = -1, fix_img = -1, fix_obj = -1, fix_ih = -1, fix_h = -1;
    (void)fix_img; (void)fix_obj; (void)fix_ih; (void)fix_h;

    stub[i++]=0x50;                                                   /* push eax          */
    stub[i++]=0x8b; stub[i++]=0x44; stub[i++]=0x24; stub[i++]=0x04;   /* mov eax,[esp+4]   */
    stub[i++]=0x3d; memcpy(stub+i,&callsite,4); i+=4;                 /* cmp eax,callsite  */
    stub[i++]=0x75; fix_top=i++;                                      /* jne skip          */

    /* Size gate.  The return address proves the CALL SITE is the world's; it does
     * not prove the VIEWPORT is the main one.  The zoomed detail preview in the
     * corner is drawn through this same call, and Force=1 was overwriting its size
     * with the full mode -- which displaced it to the north-west (s46).
     * The main viewport is always 2666/3200 = 83% of the mode width, and the
     * preview is a small panel, so "at least half the screen wide" separates them
     * at every mode without knowing either stock value. */
    if (guard) {
        stub[i++]=0x81; stub[i++]=0x79; stub[i++]=0x10;
        memcpy(stub+i,&guard,4); i+=4;                                /* cmp [ecx+0x10],g  */
        stub[i++]=0x72; fix_gate=i++;                                 /* jb  skip          */
    }

    /* image pixel width: [ecx+0x10] */
    if (!force) {
        stub[i++]=0x81; stub[i++]=0x79; stub[i++]=0x10;
        memcpy(stub+i,&match_w,4); i+=4;                               /* cmp [ecx+0x10],m */
        stub[i++]=0x75; fix_img=i++;                                   /* jne past the mov */
    }
    stub[i++]=0xc7; stub[i++]=0x41; stub[i++]=0x10;
    memcpy(stub+i,&new_w,4); i+=4;                                     /* mov [ecx+0x10],n */
    if (!force) stub[fix_img] = (BYTE)(i - fix_img - 1);

    /* image pixel height: [ecx+0x14].  Run D showed the object rect alone does not
     * fix the bottom edge, exactly as the object rect alone did not fix the sides
     * -- the painter and the presented region are two consumers on both axes. */
    if (new_h) {
        if (!force) {
            stub[i++]=0x81; stub[i++]=0x79; stub[i++]=0x14;
            memcpy(stub+i,&match_h,4); i+=4;                           /* cmp [ecx+0x14],m */
            stub[i++]=0x75; fix_ih=i++;                                /* jne past the mov */
        }
        stub[i++]=0xc7; stub[i++]=0x41; stub[i++]=0x14;
        memcpy(stub+i,&new_h,4); i+=4;                                 /* mov [ecx+0x14],n */
        if (!force) stub[fix_ih] = (BYTE)(i - fix_ih - 1);
    }

    /* object virtual width: obj = ecx - 0x7a, field +0x0f, int16 */
    if (objw) {
        WORD om = (WORD)objm, ow = (WORD)objw;
        if (!force) {
            stub[i++]=0x66; stub[i++]=0x81; stub[i++]=0x79; stub[i++]=0x95;
            memcpy(stub+i,&om,2); i+=2;                               /* cmp w[ecx-0x6b],om */
            stub[i++]=0x75; fix_obj=i++;                              /* jne skip           */
        }
        stub[i++]=0x66; stub[i++]=0xc7; stub[i++]=0x41; stub[i++]=0x95;
        memcpy(stub+i,&ow,2); i+=2;                                   /* mov w[ecx-0x6b],ow */
        if (!force) stub[fix_obj] = (BYTE)(i - fix_obj - 1);
    }

    /* object virtual height: same object, field +0x11 -> [ecx-0x69].  The world
     * measures 1920 virtual = 864 px against a 1080 screen, so the bottom edge is
     * the same bug on the other axis (2400 virtual = 1080 px). */
    if (objh) {
        WORD om = (WORD)objhm, oh = (WORD)objh;
        if (!force) {
            stub[i++]=0x66; stub[i++]=0x81; stub[i++]=0x79; stub[i++]=0x97;
            memcpy(stub+i,&om,2); i+=2;                               /* cmp w[ecx-0x69],om */
            stub[i++]=0x75; fix_h=i++;                                /* jne skip           */
        }
        stub[i++]=0x66; stub[i++]=0xc7; stub[i++]=0x41; stub[i++]=0x97;
        memcpy(stub+i,&oh,2); i+=2;                                   /* mov w[ecx-0x69],oh */
        if (!force) stub[fix_h] = (BYTE)(i - fix_h - 1);
    }

    stub[fix_top] = (BYTE)(i - fix_top - 1);                          /* skip:              */
    if (guard) stub[fix_gate] = (BYTE)(i - fix_gate - 1);
    stub[i++]=0x58;                                                   /* pop eax            */
    stub[i++]=0x83; stub[i++]=0xec; stub[i++]=0x2c;                   /* sub esp,0x2c       */
    stub[i++]=0xdb; stub[i++]=0x44; stub[i++]=0x24; stub[i++]=0x30;   /* fild [esp+0x30]    */
    stub[i++]=0xe9;
    LONG back = (LONG)(SIZE_T)ret_to - (LONG)(SIZE_T)(stub + i + 4);
    memcpy(stub+i,&back,4); i+=4;

    DWORD old;
    if (!VirtualProtect(at, 7, PAGE_EXECUTE_READWRITE, &old)) return 0;
    at[0] = 0xe9;
    LONG rel = (LONG)(SIZE_T)stub - (LONG)(SIZE_T)(at + 5);
    memcpy(at + 1, &rel, 4);
    at[5] = at[6] = 0x90;
    VirtualProtect(at, 7, old, &old);
    if (force) logf_("[+] world painter at %p: FORCED writes for the call at %08x,"
                     " gated on viewport width >= %u (stub %p)",
                     at, (unsigned)callsite, guard, stub);
    logf_("[+] world painter at %p: viewport width %u -> %u for the call at %08x "
          "(stub %p)", at, match_w, new_w, (unsigned)callsite, stub);
    if (new_h)
        logf_("[+]   ... and image pixel height %u -> %u (field +0x14)", match_h, new_h);
    if (objw)
        logf_("[+]   ... and object virtual width %u -> %u (obj = ecx-0x7a, field +0x0f)",
              objm, objw);
    if (objh)
        logf_("[+]   ... and object virtual height %u -> %u (field +0x11)", objhm, objh);
    return 1;
}


/* ------------------------------------------------- s49: the HUD shrink probe
 *
 * The question s49 leaves open is whether the sprite blit STRETCHES its sprite
 * onto the destination rectangle or copies it 1:1 into a rectangle that may be
 * the wrong size.  Growing a rect cannot answer it (a stretched sprite and a
 * stock sprite in a bigger box look alike); shrinking one can.
 *
 * FUN_00502660 is the class-4 draw.  Every one of its style branches builds the
 * destination from obj+0x0b/0x0d (position) and obj+0x0f/0x11 (size), all int16
 * in the virtual 3200x2400 space.  Halving the size at the entry therefore halves
 * the destination rect and nothing else.
 *
 * IDENTIFICATION, and s46's lesson that one property is not enough: the detour
 * site proves we are in the class-4 draw, and the exact rect 560x560 proves which
 * widget.  That rect is unique to MAINWIN.WIN across all 19 parsed .WIN files --
 * ten widgets, all the bottom-right building panel stack (br00, brempty, and a
 * class-0x40 sibling that this detour does not touch).  Nothing in any dialog can
 * be hit by accident.
 *
 * The rect persists in the object, so a match fires once per widget and then
 * stops -- obj+0x0f is 280 on the next frame and no longer matches.  Hits
 * plateauing at the widget count is the expected shape, and hits climbing forever
 * would itself be worth knowing (something re-derives the rect every frame).
 */
static const BYTE HUD_SIG[] = {
    0x51,0x53,0x56,0x8b,0xf1, 0xe8,0,0,0,0,
    0x85,0xc0, 0x0f,0x84,0,0,0,0,
    0xa1,0,0,0,0, 0x85,0xc0, 0x75,0x0d,
    0xa1,0,0,0,0, 0x85,0xc0, 0x0f,0x84 };
static const BYTE HUD_MASK[] = {
       1,   1,   1,   1,   1,    1,0,0,0,0,
       1,   1,    1,   1,0,0,0,0,
       1,0,0,0,0,    1,   1,    1,   1,
       1,0,0,0,0,    1,   1,    1,   1 };

static volatile DWORD g_hud_calls, g_hud_hits;
static volatile DWORD g_hud_hash[4], g_hud_live[4];
/* written by the phase thread, read by the stub every draw */
static volatile DWORD g_hud_style = 0, g_hud_cx = 0, g_hud_cy = 0;
static volatile DWORD g_hud_style_want = 0;
/* s53: the chrome bar.  int_main widget 17 is PATH B (s48.3) -- authored rect
 * 0x0, so FUN_00502510 recomputes its rect every frame from the art sprite's own
 * PIXEL coordinates using the LIVE mode's factors, which is an identity
 * round-trip and pins the bar to the resolution the art was drawn for.
 * g_chr_kx/ky rescale that result into the ART SET's design space instead:
 *      want/live = W_live/art_w   (16.16 fixed point)
 * At the stock mode the factor is exactly 1.0, so the correction is the identity
 * -- if 1600x1200 changes appearance, the patch is wrong. */
static volatile DWORD g_chr_kx = 65536, g_chr_ky = 65536;
static volatile DWORD g_chr_on = 0, g_chr_style = 0;
static DWORD g_hud_delay, g_hud_every, g_hud_dwell;

/* s50.7 / s50.8: does class-4 STYLE 1 stretch the sprite onto the widget rect?
 *
 * Style 1 hands FUN_005002c0 a full destination rectangle built from the widget's
 * virtual rect; style 0 -- which every shipped widget with art uses -- hands
 * FUN_00501b90 a bare position.  If style 1 stretches, a HUD that scales needs no
 * new art at all.  No shipped widget uses style 1, so this runs a path PopTop
 * never ran; that is the whole risk, and it is why this is gated to six widgets
 * in one panel.
 *
 * THE HAZARD, and why the third gate condition is not optional:
 *   style 0, 0x502ac6:  mov eax,[esi+0x66] ; test eax,eax ; je   <- guarded
 *   style 1, 0x5026c5:  mov eax,[esi+0x66] ; mov ecx,[eax]       <- NOT guarded
 * Four of the nine 560x560 class-4 widgets in MAINWIN.WIN carry no art, so
 * forcing style 1 on them dereferences NULL.  The stub refuses any widget whose
 * obj+0x66 is zero.
 *
 * The gate matches the AUTHORED rect at obj+0x50/0x52 (saved by FUN_0052a9f0),
 * not the live rect at obj+0x0f/0x11 -- otherwise the probe's own writes would
 * move the target out from under it and the phases could not cycle.
 */
/* Short conditional jumps are a trap here: the stub grew past 127 bytes when the
 * chrome block was added, and `stub[f] = i - f - 1` silently wrapped negative --
 * a `je` that would have landed 150 bytes BACKWARDS, into unmapped memory, on the
 * first artless class-4 widget.  Caught by disassembling a replica, which is the
 * only reason it is not a crash report.  Every skip-to-end jump is now near
 * (rel32), and the one remaining short jump is range-checked. */
#define J_NEAR_NE(st,i,f)  do { (st)[(i)++]=0x0f; (st)[(i)++]=0x85; (f)=(i); (i)+=4; } while (0)
#define J_NEAR_EQ(st,i,f)  do { (st)[(i)++]=0x0f; (st)[(i)++]=0x84; (f)=(i); (i)+=4; } while (0)
static int fix_near(BYTE *stub, int f, int i)
{ LONG d = i - f - 4; memcpy(stub + f, &d, 4); return 1; }
static int fix_short(BYTE *stub, int f, int i, const char *what)
{
    int d = i - f - 1;
    if (d < 0 || d > 127) { logf_("[x] [hudprobe] short jump '%s' out of range (%d)"
                                  " -- REFUSING to install a corrupt stub", what, d);
                            return 0; }
    stub[f] = (BYTE)d; return 1;
}

/* s53: correct the path-B conversion at its source.
 *
 * FUN_00502510 turns the art sprite's stored PIXEL coordinates into the widget's
 * virtual rect by multiplying with the LIVE mode's factors (3200/W at 0x5a0ff8 and
 * 2400/H at 0x5a1000).  That round-trip is the identity, which is why a 1200-tall
 * design lands at its stored pixel row on any screen (s48.3).
 *
 * Repointing all six fmul operands at our own pair of floats -- 3200/art_w and
 * 2400/art_h, the ART SET's design size rather than the live mode -- makes the
 * conversion say "these pixels are in the art's space", which is what they are.
 *
 * At a stock mode art_w == W, so the constant equals the one it replaced and the
 * patch is the exact identity.  That control is built in: if 1600x1200 changes
 * appearance, this is wrong.
 */
static float g_chr_fx = 2.0f, g_chr_fy = 2.0f;
static const BYTE CSCALE_SIG[] = { 0x83,0xec,0x14, 0x56, 0x8b,0xf1,
                                   0x8b,0x86,0x90,0x00,0x00,0x00, 0x85,0xc0, 0x0f,0x84 };

static int patch_chrome_scale(DWORD table_va)
{
    BYTE *fn = find_unique(CSCALE_SIG, sizeof CSCALE_SIG, g_text, g_textlen,
                           "path-B layout (FUN_00502510)");
    if (!fn) return 0;
    DWORD fx_va = table_va + 0x58;      /* 0x5a0ff8 = 3200 / screen width  */
    DWORD fy_va = table_va + 0x60;      /* 0x5a1000 = 2400 / screen height */
    DWORD our_x = (DWORD)(SIZE_T)&g_chr_fx, our_y = (DWORD)(SIZE_T)&g_chr_fy;
    int nx = 0, ny = 0;
    for (int k = 0; k + 6 <= 0xd0; k++) {
        if (fn[k] != 0xd8 || fn[k+1] != 0x0d) continue;       /* fmul dword [imm32] */
        DWORD op = rd32(fn + k + 2);
        if      (op == fx_va) { if (poke(fn+k+2, &our_x, 4)) nx++; }
        else if (op == fy_va) { if (poke(fn+k+2, &our_y, 4)) ny++; }
    }
    /* Three of each, every time.  Anything else means this is not the function we
     * read, and a partial patch would mix two coordinate spaces inside one rect --
     * which would look plausible and be wrong. */
    if (nx != 3 || ny != 3) {
        logf_("[x] [chrome] FUN_00502510 at %p: patched %d width and %d height"
              " multiplies, expected 3 and 3 -- REFUSING (a partial patch would mix"
              " coordinate spaces)", fn, nx, ny);
        return 0;
    }
    logf_("[+] [chrome] path-B layout at %p: all 6 scale operands repointed from the"
          " live mode to the art set's design space", fn);
    return 1;
}

static int patch_hud_probe(void)
{
    BYTE *at = find_unique_masked(HUD_SIG, HUD_MASK, sizeof HUD_SIG,
                                  g_text, g_textlen, "class-4 draw");
    if (!at) { logf_("[x] [hudprobe] class-4 draw signature not found"); return 0; }
    BYTE *stub = (BYTE *)VirtualAlloc(NULL, 384, MEM_COMMIT | MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);
    if (!stub) { logf_("[x] [hudprobe] VirtualAlloc failed"); return 0; }

    DWORD a_calls=(DWORD)(SIZE_T)&g_hud_calls, a_hits=(DWORD)(SIZE_T)&g_hud_hits;
    DWORD a_hash=(DWORD)(SIZE_T)&g_hud_hash[0], a_live=(DWORD)(SIZE_T)&g_hud_live[0];
    DWORD a_style=(DWORD)(SIZE_T)&g_hud_style;
    DWORD a_cx=(DWORD)(SIZE_T)&g_hud_cx, a_cy=(DWORD)(SIZE_T)&g_hud_cy;
    int i=0, f1, f2, f3, f4;

    stub[i++]=0x50;                                                   /* push eax             */
    stub[i++]=0x52;                                                   /* push edx             */
    stub[i++]=0xff; stub[i++]=0x05; memcpy(stub+i,&a_calls,4); i+=4;  /* inc [g_hud_calls]    */

    /* MatchW == 0 would collide with the path-B gate (authored rect 0x0), so the
     * rect comparison is emitted only when a real rect is being targeted. */
    if (g_hud_mw) {
        stub[i++]=0x0f; stub[i++]=0xbf; stub[i++]=0x41; stub[i++]=0x50; /* movsx eax,w[+0x50] */
        stub[i++]=0x3d; memcpy(stub+i,&g_hud_mw,4); i+=4;               /* cmp eax,MatchW     */
        J_NEAR_NE(stub, i, f1);                                         /* jne skip (near)    */
        stub[i++]=0x0f; stub[i++]=0xbf; stub[i++]=0x41; stub[i++]=0x52; /* movsx eax,w[+0x52] */
        stub[i++]=0x3d; memcpy(stub+i,&g_hud_mh,4); i+=4;               /* cmp eax,MatchH     */
        J_NEAR_NE(stub, i, f2);                                         /* jne skip (near)    */
    } else { f1 = f2 = -1; }
    stub[i++]=0x83; stub[i++]=0x79; stub[i++]=0x66; stub[i++]=0x00;   /* cmp d[ecx+0x66],0    */
    J_NEAR_EQ(stub, i, f3);                                           /* je  skip  (NO ART)   */

    /* record the first four: resource pointer, and the LIVE rect as seen on entry
     * (obj+0x0f and obj+0x11 are adjacent WORDs, so one dword is CX | CY<<16) --
     * which shows the previous phase's write actually persisted. */
    stub[i++]=0xa1; memcpy(stub+i,&a_hits,4); i+=4;                   /* mov eax,[g_hud_hits] */
    stub[i++]=0x83; stub[i++]=0xf8; stub[i++]=0x04;                   /* cmp eax,4            */
    stub[i++]=0x73; f4=i++;                                           /* jae nostore          */
    stub[i++]=0x8b; stub[i++]=0x51; stub[i++]=0x66;                   /* mov edx,[ecx+0x66]   */
    stub[i++]=0x89; stub[i++]=0x14; stub[i++]=0x85;
    memcpy(stub+i,&a_hash,4); i+=4;                                   /* mov [hash+eax*4],edx */
    if (!fix_short(stub, f4, i, "nostore")) return 0;                 /* nostore:             */
    /* The live rect is recorded on EVERY match, not only the first four.  In run K
     * it sat inside the first-four gate, froze on frame one and read "560 x 560"
     * for the whole run -- an instrument reporting a constant, which is the shape
     * of a broken one (s48.0).  The screen disagreed with it and the screen was
     * right. */
    stub[i++]=0x8b; stub[i++]=0x51; stub[i++]=0x0f;                   /* mov edx,[ecx+0x0f]   */
    stub[i++]=0x89; stub[i++]=0x15; memcpy(stub+i,&a_live,4); i+=4;   /* mov [g_hud_live],edx */
    stub[i++]=0xff; stub[i++]=0x05; memcpy(stub+i,&a_hits,4); i+=4;   /* inc [g_hud_hits]     */

    /* ---- gate B: PATH-B widgets (authored rect 0x0) ------------------------
     * Rescale the four fields FUN_00502510 just wrote, from the live mode's
     * space into the art set's design space.  Idempotent: the pre-draw recomputes
     * them from the sprite every frame, so this always operates on fresh values. */
    if (g_chr_enable) {
        DWORD a_on=(DWORD)(SIZE_T)&g_chr_on, a_cs=(DWORD)(SIZE_T)&g_chr_style;
        int b1, b2, b3;
        (void)0;
        stub[i++]=0x66; stub[i++]=0x83; stub[i++]=0x79; stub[i++]=0x50; stub[i++]=0x00;
        J_NEAR_NE(stub, i, b1);                                       /* cmp w[+0x50],0; jne  */
        stub[i++]=0x66; stub[i++]=0x83; stub[i++]=0x79; stub[i++]=0x52; stub[i++]=0x00;
        J_NEAR_NE(stub, i, b2);                                       /* cmp w[+0x52],0; jne  */
        stub[i++]=0x83; stub[i++]=0x3d; memcpy(stub+i,&a_on,4); i+=4; stub[i++]=0x00;
        J_NEAR_EQ(stub, i, b3);                                       /* cmp [g_chr_on],0; je */
        /* NO ARITHMETIC HERE.  Run M multiplied the live rect by the correction
         * factor on every draw, on the assumption that FUN_00502510 recomputed it
         * from the sprite each frame.  It does not: FUN_005025e0 takes the path-B
         * branch only while CX and CY are ZERO, so FUN_00502510 runs ONCE and the
         * pre-draw takes path A forever after.  The multiply therefore compounded
         * -- CX x1.2 and CY x0.9 per frame -- and the log caught it exactly:
         *     live rect on entry: 33488 x 39  ->  32561 x 0  ->  32233 x 0
         * CX ran into the int16 ceiling, CY collapsed, the rect went degenerate and
         * the bar vanished permanently, surviving even the phase that turned the
         * correction off, because nothing recomputes it.
         *
         * The guard that says so is quoted verbatim in s48.3.  Having the fact and
         * not applying it is the same failure as s50.4.
         *
         * The correction now happens where the value is COMPUTED -- the six fmul
         * operands inside FUN_00502510 (see patch_chrome_scale) -- which is
         * idempotent by construction because it is a computation, not a mutation. */
        stub[i++]=0xa1; memcpy(stub+i,&a_cs,4); i+=4;                 /* mov eax,[g_chr_style]*/
        stub[i++]=0x89; stub[i++]=0x41; stub[i++]=0x7c;               /* mov [ecx+0x7c],eax   */
        fix_near(stub,b1,i); fix_near(stub,b2,i); fix_near(stub,b3,i);
    }

    if (g_hud_mw) {
        stub[i++]=0xa1; memcpy(stub+i,&a_cx,4); i+=4;                 /* mov eax,[g_hud_cx]   */
        stub[i++]=0x66; stub[i++]=0x89; stub[i++]=0x41; stub[i++]=0x0f;
        stub[i++]=0xa1; memcpy(stub+i,&a_cy,4); i+=4;                 /* mov eax,[g_hud_cy]   */
        stub[i++]=0x66; stub[i++]=0x89; stub[i++]=0x41; stub[i++]=0x11;
        stub[i++]=0xa1; memcpy(stub+i,&a_style,4); i+=4;              /* mov eax,[g_hud_style]*/
        stub[i++]=0x89; stub[i++]=0x41; stub[i++]=0x7c;               /* mov [ecx+0x7c],eax   */
    }

    if (f1 >= 0) { fix_near(stub,f1,i); fix_near(stub,f2,i); }
    fix_near(stub, f3, i);                                            /* skip:                */
    stub[i++]=0x5a;                                                   /* pop edx              */
    stub[i++]=0x58;                                                   /* pop eax              */
    stub[i++]=0x51; stub[i++]=0x53; stub[i++]=0x56;                   /* push ecx/ebx/esi     */
    stub[i++]=0x8b; stub[i++]=0xf1;                                   /* mov esi,ecx          */
    stub[i++]=0xe9;
    { LONG back=(LONG)(SIZE_T)(at+5)-(LONG)(SIZE_T)(stub+i+4); memcpy(stub+i,&back,4); i+=4; }

    DWORD old;
    if (!VirtualProtect(at, 5, PAGE_EXECUTE_READWRITE, &old)) {
        logf_("[x] [hudprobe] VirtualProtect failed"); return 0; }
    at[0]=0xe9;
    { LONG rel=(LONG)(SIZE_T)stub-(LONG)(SIZE_T)(at+5); memcpy(at+1,&rel,4); }
    VirtualProtect(at, 5, old, &old);

    logf_("[+] [hudprobe] class-4 draw at %p (stub %p, %d bytes): targeting widgets whose"
          " AUTHORED rect is %ux%u and which HAVE art (obj+0x66 != 0)",
          at, stub, i, (unsigned)g_hud_mw, (unsigned)g_hud_mh);
    for (int k = 0; k < g_hud_nph; k++)
        logf_("[+]   phase %d: style %lu, rect %lux%lu virtual", k,
              (unsigned long)g_hud_ph_style[k],
              (unsigned long)g_hud_ph_size[k], (unsigned long)g_hud_ph_size[k]);
    return 1;
}

static DWORD WINAPI hudprobe_thread(LPVOID unused)
{
    (void)unused;
    Sleep(g_hud_delay * 1000);
    int ph = -1; DWORD next = 0;
    for (int t = 0;; t++) {
        DWORD hw3d = wfb_read32(g_hud_table_va - 0x14);   /* 0x5a0f8c */
        /* Run K spent its whole life in Software, where style 1 takes the tiled
         * 1:1 branch of FUN_005002c0 and never reaches the ratio arithmetic at
         * 0x500512 -- so the question could not have been answered, and the
         * corruption on screen was the wrong branch failing.  Rather than rely on
         * the operator remembering, suppress style 1 unless the renderer that can
         * stretch is actually live, and say so. */
        if (g_hud_style_want && !hw3d && g_hud_style) {
            g_hud_style = 0;
            logf_("  [hudprobe]   *** style 1 SUPPRESSED: renderer is SOFTWARE, which"
                  " cannot stretch.  Press F2 and switch to Hardware 3D. ***");
        } else if (g_hud_style_want && hw3d && !g_hud_style) {
            g_hud_style = g_hud_style_want;
            logf_("  [hudprobe]   Hardware 3D is live -- style %lu now applied",
                  (unsigned long)g_hud_style);
        }
        /* Recompute the design-space factors every tick from the LIVE slot and mode.
         * The art set follows the slot (s19) and the proxy has already rewritten
         * slot 4's table entry to the target mode, so the design size CANNOT be
         * read back from the table -- it is the slot's stock size. */
        {
            static const DWORD ART_W[5] = { 640, 800, 1024, 1280, 1600 };
            static const DWORD ART_H[5] = { 480, 600,  768, 1024, 1200 };
            DWORD cfg0 = wfb_read32(0x612fec), sl = 0xffffffff;
            if (cfg0 && !IsBadReadPtr((void *)(SIZE_T)cfg0, 0x1c))
                memcpy(&sl, (BYTE *)(SIZE_T)(cfg0 + 0x18), 4);
            DWORD lw = wfb_read16(0x60c18c), lh = wfb_read16(0x60c18e);
            if (sl < 5) {
                g_chr_fx = 3200.0f / (float)ART_W[sl];
                g_chr_fy = 2400.0f / (float)ART_H[sl];
                g_chr_kx = (DWORD)((65536.0 * (lw ? lw : ART_W[sl])) / ART_W[sl]);
                g_chr_ky = (DWORD)((65536.0 * (lh ? lh : ART_H[sl])) / ART_H[sl]);
            }
        }
        if (GetTickCount() >= next) {
            ph = (ph + 1) % g_hud_nph;
            g_hud_style_want = g_hud_ph_style[ph];
            g_hud_style = (g_hud_style_want && !hw3d) ? 0 : g_hud_style_want;
            g_hud_cx = g_hud_cy = g_hud_ph_size[ph];
            if (g_chr_enable) {
                /* size column doubles as the chrome mode: 0 = leave the bar stock,
                 * non-zero = rescale it into the art set's design space. */
                g_chr_on    = g_hud_ph_size[ph] ? 1 : 0;
                g_chr_style = (g_hud_style_want && hw3d) ? g_hud_style_want : 0;
                logf_("  [chrome] style %lu; design-space factors now %.4f / %.4f"
                      " (live mode would be %.4f / %.4f)",
                      (unsigned long)g_chr_style, g_chr_fx, g_chr_fy,
                      3200.0 / (wfb_read16(0x60c18c) ? wfb_read16(0x60c18c) : 1),
                      2400.0 / (wfb_read16(0x60c18e) ? wfb_read16(0x60c18e) : 1));
            }
            next = GetTickCount() + g_hud_dwell * 1000;
            logf_("  [hudprobe] ===> PHASE %d: style %lu, rect %lux%lu  (%s)", ph,
                  (unsigned long)g_hud_style, (unsigned long)g_hud_cx, (unsigned long)g_hud_cy,
                  g_hud_style == 0 && g_hud_cx == g_hud_mw ? "BASELINE, should look stock"
                : g_hud_style == 0 ? "s50: expect a CLIPPED corner at full scale"
                : g_hud_cx == g_hud_mw ? "style 1 at natural size"
                : "DISCRIMINATOR: whole image at half size = IT STRETCHES");
        }
        DWORD w = wfb_read16(0x60c18c), h = wfb_read16(0x60c18e);
        DWORD hw = hw3d;
        DWORD cfg = wfb_read32(0x612fec), slot = 0xffffffff;
        if (cfg && !IsBadReadPtr((void *)(SIZE_T)cfg, 0x1c))
            memcpy(&slot, (BYTE *)(SIZE_T)(cfg + 0x18), 4);
        static const char *suf[5] = { ".i06", ".i08", ".i10", ".i12", ".i16" };
        logf_("  [hudprobe] ph=%d  screen %ux%u  slot %ld art %s  renderer %s  "
              "class4 draws=%lu  matches=%lu  live rect on entry: %lu x %lu",
              ph, (unsigned)w, (unsigned)h, (long)(int)slot,
              (slot < 5 ? suf[slot] : "?"), hw ? "HARDWARE 3D" : "SOFTWARE",
              (unsigned long)g_hud_calls, (unsigned long)g_hud_hits,
              (unsigned long)(g_hud_live[0] & 0xffff), (unsigned long)(g_hud_live[0] >> 16));
        if (g_hud_style_want && !hw3d)
            logf_("  [hudprobe]   (this phase is INCONCLUSIVE while the renderer is"
                  " Software -- the branch that can stretch is never reached)");
        if (g_hud_calls == 0)
            logf_("  [hudprobe]   *** ZERO class-4 draws -- the detour is NOT running."
                  "  Do not interpret the screen. ***");
        else if (!g_hud_hits)
            logf_("  [hudprobe]   *** detour runs but NOTHING matched an authored %ux%u"
                  " rect with art.  obj+0x50/0x52 is not the saved rect. ***",
                  (unsigned)g_hud_mw, (unsigned)g_hud_mh);
        Sleep(g_hud_every * 1000);
    }
}

static void maybe_start_hudprobe(void)
{
    char path[MAX_PATH];
    snprintf(path, sizeof path, "%s\\tropico-fix.ini", g_dir);
    if (!GetPrivateProfileIntA("HudProbe", "Enable", 0, path)) return;
    if (!g_hud_table_va) {
        logf_("[x] [hudprobe] resolution table never located -- not starting");
        return;
    }
    g_hud_delay = GetPrivateProfileIntA("HudProbe", "Delay", 20, path);
    g_hud_every = GetPrivateProfileIntA("HudProbe", "Every", 5, path);
    if (!g_hud_every) g_hud_every = 5;
    g_hud_dwell = GetPrivateProfileIntA("HudProbe", "Dwell", 15, path);
    if (!g_hud_dwell) g_hud_dwell = 15;
    if (!g_hud_nph) { logf_("[x] [hudprobe] no phases -- thread not started"); return; }
    CreateThread(NULL, 0, hudprobe_thread, NULL, 0, NULL);
}

static const BYTE VP_SIG[] = { 0x0f,0xbf,0x4e,0x11, 0x0f,0xbf,0x46,0x0f,
                               0x89,0x8e,0x8e,0x00,0x00,0x00 };

static int patch_world_viewport(UINT match_w, UINT new_w)
{
    BYTE *at = find_unique(VP_SIG, sizeof VP_SIG, g_text, g_textlen, "world viewport");
    if (!at) return 0;
    BYTE *stub = (BYTE *)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);
    if (!stub) { logf_("[x] world viewport: VirtualAlloc failed"); return 0; }

    BYTE *ret_to = at + 8;                     /* 0x50af91 */
    int i = 0;
    stub[i++]=0x0f; stub[i++]=0xbf; stub[i++]=0x4e; stub[i++]=0x11;  /* movsx ecx,[esi+0x11] */
    stub[i++]=0x0f; stub[i++]=0xbf; stub[i++]=0x46; stub[i++]=0x0f;  /* movsx eax,[esi+0x0f] */
    stub[i++]=0x3d; memcpy(stub+i,&match_w,4); i+=4;                 /* cmp eax, match_w     */
    stub[i++]=0x75; stub[i++]=0x05;                                  /* jne +5               */
    stub[i++]=0xb8; memcpy(stub+i,&new_w,4); i+=4;                   /* mov eax, new_w       */
    stub[i++]=0xe9;                                                  /* jmp ret_to           */
    LONG back = (LONG)(SIZE_T)ret_to - (LONG)(SIZE_T)(stub + i + 4);
    memcpy(stub+i,&back,4); i+=4;

    DWORD old;
    if (!VirtualProtect(at, 8, PAGE_EXECUTE_READWRITE, &old)) return 0;
    at[0] = 0xe9;
    LONG rel = (LONG)(SIZE_T)stub - (LONG)(SIZE_T)(at + 5);
    memcpy(at + 1, &rel, 4);
    at[5] = at[6] = at[7] = 0x90;
    VirtualProtect(at, 8, old, &old);
    logf_("[+] world viewport at %p: image width %u -> %u when the object is %u wide "
          "(stub %p)", at, match_w, new_w, match_w, stub);
    return 1;
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
    maybe_start_watchfb();
    maybe_start_cliplog();
    maybe_start_hudprobe();
    return TRUE;
}

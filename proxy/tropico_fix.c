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
#include <ddraw.h>
#include <stdio.h>
#include "artgen.h"
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

/* APPEND, NEVER TRUNCATE -- the proxy's half of FINDINGS 110.2.
 *
 * DllMain used to DeleteFileA() this log on every run. That is exactly the defect
 * 110.1 names in the launcher and 110.2 fixed there, left standing in the other
 * component: "it came up wrong, so I ran it again and it was right" is the single
 * commonest sequence this patch is involved in, and the second run destroyed the
 * log of the first. Every time. The only run whose evidence ever survived was the
 * one that worked.
 *
 * Monitor selection is a TWO-LAUNCH symptom by nature -- launch on one screen,
 * then the other -- so it cannot be investigated with a one-launch log at all.
 * Same cap and shape as the launcher's, so the two files read alike.
 *
 * The cap matters as much as the appending: a log that grows without bound is one
 * nobody will attach to a bug report. */
#define LOG_CAP  (64 * 1024)
#define LOG_KEEP (48 * 1024)

static void log_begin(void)
{
    char *buf = NULL;
    long sz = 0;
    SYSTEMTIME st;
    FILE *f = fopen(g_logpath, "rb");

    if (f) {
        fseek(f, 0, SEEK_END);
        sz = ftell(f);
        if (sz > LOG_CAP && (buf = (char *)malloc(LOG_KEEP)) != NULL) {
            fseek(f, sz - LOG_KEEP, SEEK_SET);
            if (fread(buf, 1, LOG_KEEP, f) != LOG_KEEP) { free(buf); buf = NULL; }
        }
        fclose(f);
    }
    if (buf) {
        /* Resume at a line boundary. A log that begins mid-sentence reads as
         * corruption and invites the wrong question. */
        long i = 0;
        while (i < LOG_KEEP && buf[i] != '\n') i++;
        if (i < LOG_KEEP) i++;
        f = fopen(g_logpath, "wb");
        if (f) {
            fprintf(f, "[... earlier runs trimmed; this file is capped at %d KB ...]\n",
                    LOG_CAP / 1024);
            fwrite(buf + i, 1, (size_t)(LOG_KEEP - i), f);
            fclose(f);
        }
        free(buf);
    }
    GetLocalTime(&st);
    logf_("");
    logf_("==== %04d-%02d-%02d %02d:%02d:%02d  NEW RUN ====",
          st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
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
static int patch_blit_census(void);      /* s103 */
static int g_bc_on;                      /* s103, armed from [Blit] Census; these
                                          * three are read in the ini pass, which
                                          * runs long before the census code, so
                                          * they live up here with the prototype */
static int g_bc_delay, g_bc_every, g_bc_miny;
static int patch_pathb_recompute(BYTE *layout_fn);
static int patch_chrome_scale(DWORD table_va);
static int patch_vtext(int dy, int dx, int cliph, int have_dy, int have_dx, int have_cliph);
static int patch_vtext_probe(void);
static int patch_vtext_entry(void);
static int patch_text_probe(void);
static int patch_readout_colour(int want);
static int patch_intro(void);
static int patch_menu(int w, int h);
static int patch_movie_probe(void);
static DWORD g_mv_flag_va;
static int g_menu_slot = -1;
static int g_bink_pitch;
static int patch_blit_probe(void);
static int patch_blit_scale(void);
static int patch_hud_movie(void);        /* s106 */
static int patch_hud_movie_probe(void);  /* s106 */
static int patch_preview_probe(void);
static int patch_surface_probe(void);
static int patch_preview_fix(int mode);
static DWORD g_surf_va;
static int patch_menu_slot(void);
static int patch_slot_probe(void);
static void find_applyvideo(void);
static DWORD WINAPI pin_thread(LPVOID);
static DWORD g_preset_ret;   /* return address of the preset-apply call site */
static int g_slot_log;
static int patch_force_fullscreen(void);
/* s118: maybe_install_ddprobe() asks this, and it sits far below. */
static int running_under_wine(void);
static int g_force_fs = 1;   /* s79: never let the engine enter windowed mode */
static int g_fs_clamped;     /* how many times the clamp has fired */
/* ------------------------------------------------------------ shared primitives
 *
 * hook_import redirects one entry in the main module's import table. It was written
 * inside the cursor investigation because that is what first needed it, but it is
 * general and has callers that outlive that code, so it lives here.
 */
static int poke(void *dst, const void *src, SIZE_T len);  /* defined below */

/* Same IAT walk as the GetDeviceCaps hook, parameterised. */
static void *hook_import(const char *dll, const char *fn, void *replacement, void **real)
{
    BYTE *base = (BYTE *)GetModuleHandleA(NULL);
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!rva) return NULL;
    for (IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(base + rva); imp->Name; imp++) {
        if (_stricmp((const char *)(base + imp->Name), dll)) continue;
        IMAGE_THUNK_DATA *oft = (IMAGE_THUNK_DATA *)(base + imp->OriginalFirstThunk);
        IMAGE_THUNK_DATA *ft  = (IMAGE_THUNK_DATA *)(base + imp->FirstThunk);
        for (; oft->u1.AddressOfData; oft++, ft++) {
            IMAGE_IMPORT_BY_NAME *ibn;
            if (oft->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
            ibn = (IMAGE_IMPORT_BY_NAME *)(base + oft->u1.AddressOfData);
            if (strcmp((const char *)ibn->Name, fn)) continue;
            *real = (void *)ft->u1.Function;
            if (!poke(&ft->u1.Function, &replacement, sizeof replacement)) return NULL;
            return (void *)&ft->u1.Function;
        }
    }
    return NULL;
}

/* -------------------------------------------- s118: choose the DEVICE, not the primary
 *
 * MEASURED ON WINDOWS 11, and it is the result the whole s113/s114 apparatus was
 * waiting for. DirectDrawEnumerateExA(DDENUM_ATTACHEDSECONDARYDEVICES) hands back
 * a DIFFERENT GUID per head, and DirectDrawCreateEx with the secondary's GUID
 * produces a device that takes exclusive fullscreen on that monitor, sets THAT
 * monitor's mode, and blits without #150 -- while the OS primary is never touched.
 *
 * The discriminator pair settles which lever it is. Arm 4 put the WINDOW on the
 * primary and the secondary's GUID on the device: the pixels went to the
 * SECONDARY. Arm 3 did the opposite -- NULL device, window on the secondary --
 * and Windows moved the window back to the primary and rendered there. So the
 * GUID decides and window placement does not, on real Windows exactly as on Wine.
 *
 * WHAT THIS REPLACES. s113's whole apparatus exists to make the player's chosen
 * monitor primary for the length of the game and give it back afterwards: the
 * state file, the ExitProcess hook, the window watcher, the 5 s deadline. None of
 * it is needed if the game simply renders on the right device. That is a change
 * to the GAME rather than to the PLAYER'S COMPUTER, which is what s114 set out to
 * find and what s113.8 settled for the absence of.
 *
 * WINDOWS ONLY, and not by policy. Wine hands back ONE adapter GUID for both
 * heads (s114.3) -- it names the adapter, not the head -- so there is nothing to
 * substitute there and the xrandr path stays exactly as it is. This is the
 * Windows half of the prize and the Linux half is not on offer.
 *
 * OFF BY DEFAULT for now: the mechanism is measured, but it has not yet been
 * measured THROUGH THE GAME. See the ini note. */
static int   g_devsel;              /* [Display] DeviceSelect */
static char  g_devsel_want[64];     /* the \\.\DISPLAYn choose_monitor picked */
static GUID  g_devsel_guid;
static int   g_devsel_have;         /* the GUID was resolved */
static int   g_devsel_tried;        /* resolution has been attempted; do not repeat */
/* s118.14: the target monitor's origin in VIRTUAL-SCREEN space, and the reason the
 * first in-game run of this feature failed with #150 on every frame.
 *
 * s115.4 measured how this engine presents: Blt(primary <- offscreen), with the
 * destination rect being the game's window rect IN SCREEN COORDINATES. That is
 * fine on the primary, where the monitor origin IS (0,0) -- and it is wrong
 * everywhere else. Point the game at \\.\DISPLAY2 sitting at (-1920,357) and its
 * destination rect is (-1920,357)-(0,1437) inside a surface that spans
 * (0,0)-(1920,1080). Entirely out of bounds, every frame, which is #150.
 *
 * The sign is not the point: a monitor at +2560 fails identically. THE GAME
 * ASSUMES THE MONITOR ORIGIN IS (0,0), WHICH IS ONLY EVER TRUE FOR THE PRIMARY.
 *
 * s114's probe could not have caught this. Its blits used explicit
 * surface-relative rects, so it proved the DEVICE works and never exercised the
 * one thing the GAME does differently. */
static long  g_devsel_ox, g_devsel_oy;
static int   g_devsel_xlate;        /* the translation is armed */
static int   g_devsel_logged;

static int g_ini_mode_unusable;
static int g_artgen_enabled = 1;   /* [Art] Generate -- see artgen.c */
static int g_pin_primary = 1;
static int g_pin_done;
static int g_pin_seen_ok;
static int g_pin_moves;
static DWORD g_applyvideo_va;
static DWORD g_vt_ys_va, g_vt_xs_va;
/* The mode slot 4 was actually set to. Written once, where slot 4 is patched;
 * read by the [VText] defaults and the art-set cross-check, both of which are
 * only correct for the mode the art was generated for. */
static UINT  g_mode_w, g_mode_h;
static int g_vt_entry, g_vt_bdh, g_vt_bdy, g_vt_log, g_vt_boxdx;
static DWORD g_vte_entry_va;
/* s65 vtext hook state -- declared here because apply_patches() sets it from the
 * ini long before the hook that reads it is defined. */
static int g_vt_fix, g_vt_fw, g_vt_fh, g_vt_boxh, g_vt_boxdy;
static DWORD g_hud_mw, g_hud_mh;
static int g_txt_log;          /* s87 text probe: declared here, used by apply_patches */
static int g_chr_enable;
static DWORD g_chr_trim = 8;
static DWORD g_hud_ph_style[8], g_hud_ph_size[8];
static int g_hud_nph;
static DWORD g_hud_table_va;
static int patch_world_draw(UINT match_w, UINT new_w, UINT match_h, UINT new_h,
                            UINT objm, UINT objw, UINT objhm, UINT objh, int force, UINT guard);
static int install_cursor_probe(void);   /* s89, defined with the probe below */
static int g_cur_probe;                  /* s89, armed from [Cursor] Probe   */
static int g_cur_fix;                    /* s89, armed from [Cursor] Fix     */
static int g_cur_msg;                    /* s89, armed from [Cursor] MsgProbe */
static void install_msg_probe(void);      /* s89, defined with the probe below */
static void unix_probe(void);             /* s90, defined with the probe below */
/* s90/s99, and the split between them is the whole point: choose_monitor() only
 * READS the display, which is safe from DllMain; apply_monitor() CHANGES it and
 * waits for Wine to agree, which is not. See apply_monitor() for the measurement. */
/* What choose_monitor() decided, kept because apply_monitor() runs much later and
 * the xrandr output list it was read from is long out of scope by then. */
static char  g_mon_to[64], g_mon_from[64];
static DWORD g_mon_to_w, g_mon_to_h;
static int   g_mon_pending;
/* s113. Which display source answered, because the two need different verbs to
 * change anything: xrandr on the host, ChangeDisplaySettingsEx here. */
static int   g_mon_win32;
/* The primary to return to when this process is done with the display. Loaded from
 * tropico-primary.state when a previous run did not get to put it back, so a crash
 * cannot make a leftover look like the player's own choice. */
static char  g_prev_primary[64];
static DWORD g_mon_from_w, g_mon_from_h;
static DWORD g_prev_primary_w, g_prev_primary_h;
static LONG  g_restore_done;

static void choose_monitor(void);
static void apply_monitor(void);
/* s100: the virtual desktop. detect() reads and is safe from DllMain;
 * apply() writes the prefix registry and belongs in the patch pass. */
static void vd_detect(void);
static void vd_apply(void);
static DWORD WINAPI xcompare_thread(LPVOID);
static int g_cur_xcmp;                   /* s101, armed from [Cursor] XCompare */
static int g_cur_sites;                  /* s107, armed from [Cursor] Sites   */
static int   g_vd_want;                  /* [Display] VirtualDesktop */
static int   g_vd_inside;                /* this process IS in the desktop we armed */
static int   g_vd_checked;
static DWORD g_vd_arm_w, g_vd_arm_h;     /* what tropico-vd.state says we armed */


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

/* FINDINGS section 91: the renderer branch on the mode-set path.
 *   mov edx,[settings] / mov eax,[edx+0x10] / test eax,eax / je <software path>
 *   xor edi,edi / mov [swbase],edi
 * `[settings+0x10]` is the renderer selector -- TROPICO.CFG file offset 0x23a,
 * 0 = software. Non-zero NULLs the software framebuffer base and skips the entire
 * software bring-up, which is the hardware path and the thing that crashes off
 * Wine. The trailing store is what makes the site unique: it is the only place
 * that NULLs that base on the strength of this field.
 *
 * The five bytes of the load-and-test are replaced by `and [edx+0x10],0` plus a
 * nop. That ZEROES THE LIVE FIELD and sets ZF in one instruction, so the `je`
 * that follows -- left exactly where it was, displacement untouched -- is now
 * always taken. The engine writes the healed field back the next time it saves
 * TROPICO.CFG, so a bricked config repairs itself without this patch ever
 * touching the file. */
static const BYTE RND_SIG[]  = {0x8b,0x15,0,0,0,0,
                                0x8b,0x42,0x10, 0x85,0xc0, 0x74,0,
                                0x33,0xff, 0x89,0x3d,0,0,0,0};
static const BYTE RND_MASK[] = {   1,   1,0,0,0,0,
                                   1,   1,   1,    1,   1,    1,0,
                                   1,   1,    1,   1,0,0,0,0};
#define RND_PATCH_OFF 6

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
/* s42/s82: the world image's stock pixel width. The size gate compares against this
 * value, so the gate's threshold must never exceed it. */
#define WORLD_STOCK_W 1600

typedef struct { DWORD w, h; } mode_t;
static int launch_override(mode_t *m);   /* s90, defined with the monitor code */
static void launch_mode_check(int dw, int dh); /* s108, ditto */

/* ------------------------------------------------------- display scaling (DPI)
 *
 * THE PATCH IS DELIBERATELY DPI-UNAWARE. There is no SetProcessDPIAware call here
 * and there must not be one; this comment exists so the absence reads as a decision
 * rather than an oversight, because it looks exactly like the omission it used to be.
 *
 * `Tropico.EXE` carries no DPI manifest, so on Windows every geometry it is told is
 * the LOGICAL (scaled) desktop size rather than the panel's physical one: a 3840x2160
 * panel at 200% reports 1920x1080. An earlier revision treated that as a bug and
 * declared per-monitor awareness to get the physical number back. That was reverted.
 *
 * WHY. The scaling setting is the resolution the user ASKED FOR, and honouring it is
 * the whole point. 200% on a 4K panel means "give me a 1920x1080 desktop", so the game
 * runs at 1920x1080. 50% on a 1080p panel means "give me 3840x2160", and the game runs
 * at 3840x2160 -- softer, and still what was asked for. One rule, both directions,
 * and it is the same rule on Wine, on Proton and on Windows.
 *
 * The defect that prompted the awareness call was real but was a DISAGREEMENT, not a
 * wrong number: the installer measured the PHYSICAL panel and staged art for
 * 3840x2160 while the proxy measured the LOGICAL desktop and saw 1920x1080, so the
 * configured mode was rejected, no staged set matched, and the run fell through to the
 * stock art caps at ~1400x1050. Resolved by making the installer measure logically
 * too, so both ends agree. See FINDINGS 92.
 *
 * DirectDraw mode setting is not DPI-virtualized, so asking for 1920x1080 on a 4K
 * panel yields a genuine 1080p signal the display upscales at an exact 2x, rather
 * than a composited stretch.
 *
 * KNOWN GAP: a mixed-DPI multi-monitor Windows setup (4K laptop at 200% beside a
 * 1080p external at 100%) applies the SYSTEM dpi uniformly, so the numbers for the
 * monitor that is not at system DPI are neither physical nor that monitor's own
 * logical size. Per-monitor awareness is the only thing that gets that case right,
 * and it is incompatible with the rule above. Recorded, not solved.
 */

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

    /* Both numbers, side by side, with NO judgement attached to a difference.
     * EnumDisplaySettings reports the adapter's real mode and is not DPI-virtualized;
     * SM_CXSCREEN above is the LOGICAL desktop. On a scaled display they differ, and
     * that difference is the scaling factor -- which is information, not an error.
     * The patch deliberately follows the logical number (see the DPI note above), so
     * a mismatch here is the system working as intended.
     *
     * An earlier revision printed a warning on the mismatch. It was wrong under this
     * policy -- it flagged correct behaviour as a fault -- and it is not coming back.
     * What is worth having is the pair, so that a run at an unexpected size can be
     * diagnosed without asking the user what their scaling is set to. */
    {
        DEVMODEA real; memset(&real, 0, sizeof real); real.dmSize = sizeof real;
        if (EnumDisplaySettingsA(NULL, ENUM_CURRENT_SETTINGS, &real)) {
            int mw = GetSystemMetrics(SM_CXSCREEN);
            logf_("  EnumDisplaySettings = %lu x %lu   (the adapter's real mode; differs from"
                  " the line above by the display scaling, which is expected)",
                  real.dmPelsWidth, real.dmPelsHeight);
            if (mw && real.dmPelsWidth && (DWORD)mw != real.dmPelsWidth)
                logf_("  display scaling is about %d%%; the patch follows the logical size,"
                      " which is the resolution the user asked for",
                      (int)((real.dmPelsWidth * 100 + mw / 2) / mw));
        }
    }
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

/* ---------------------------------------------- art sets: GENERATED, not staged
 *
 * s85 used to live here: the installer staged one set per connected monitor into
 * artsets\<WxH>\ and the proxy copied one into data\ when the mode it picked did
 * not match what the launcher had staged. All of it -- staged_dir, mode_is_staged,
 * active_artset_is, activate_artset and the two-pass picker they fed -- is deleted.
 *
 * It existed to answer one question: DOES ART EXIST AT THIS SIZE? The answer used to
 * depend on what an installer had guessed, ahead of time, about a display it could not
 * see. Now the proxy generates the set itself, from the user's archives, once the mode
 * is known -- about a second (FINDINGS 96) -- so the answer is unconditionally yes and
 * the machinery for asking has nothing left to do.
 *
 * What went with it: the per-monitor prediction, 226 MB of duplicate art on disk, two
 * 132 MB copies per mode switch, and the fallback path that switched art after the fact.
 * See ensure_art_for_mode() below, and artgen.c for the generator.
 */

/* `capped` is set only when [Art] Generate=0. With generation on, the stock-art caps
 * describe a limit that no longer exists -- they were a rough proxy for "does art exist
 * at this size", and the generator makes any size true. With it off, the old behaviour
 * is preserved verbatim, because then the caps are once again the truth. */
static int pick_mode_pass(mode_t *out, int capped)
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
        /* s85: two passes. The stock-art caps below are a ROUGH PROXY for "does art
         * exist at this size" -- they were written before art was generated per mode,
         * and they now reject 2560x1440 outright (h > 1200) even when its art set is
         * staged and ready. A staged set answers that question exactly, so when one
         * exists the caps are not consulted; when none does, they are, and the old
         * behaviour is preserved verbatim for an install with no artsets\ at all. */
        if (capped) {
            if (w > ART_WIDTH_CAP) continue;       /* s11: art width ceiling   */
            if (h > 1200) continue;                /* stock slot-4 art height  */
        }
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

    logf_("  %d candidate mode(s) passed the constraints (fit within %lux%lu, wider than"
          " 1280, %s)", considered, deskw, deskh,
          capped ? "within the stock art caps" : "any size -- art is generated to match");
    if (!best.w) {
        logf_("  -> nothing beats slot 3's stock 1280; leaving slot 4 at its stock 1600x1200");
        return 0;
    }
    *out = best;
    return 1;
}

/* Prefer a mode whose art is staged; fall back to the stock-art caps if none is.
 * Only the fallback path ever gets here -- see ini_override(). */
/* ------------------------------------------------ s96: runtime art generation
 *
 * The art set is generated HERE, at launch, from the user's own archives -- not
 * staged ahead of time by an installer that had to guess which resolution the game
 * would end up at. That guess is what the staging subsystem existed to make, and
 * what measurement showed was unnecessary: the whole set is ~0.9 s in C against
 * ~13 s in Python, so it stops being a step that has to be scheduled.
 *
 * WHY THIS IS INERT ON LINUX. tools/tropico stages a set and writes
 * data\ARTSET-MODE.txt before the game starts, so the marker matches the mode we
 * just picked and this returns immediately. Runtime generation is for the platform
 * with no launcher -- Windows, and Steam's Play button, where nothing runs before
 * the process does.
 *
 * The cache key is the MODE ALONE. font_scale is derived from it as H/1080
 * (FINDINGS 86), so two runs at one resolution cannot disagree about the art.
 */
static void artgen_log(const char *s) { logf_("%s", s); }

static void ensure_art_for_mode(DWORD w, DWORD h)
{
    char ip[MAX_PATH];
    snprintf(ip, sizeof ip, "%s\\tropico-fix.ini", g_dir);
    if (!GetPrivateProfileIntA("Art", "Generate", 1, ip)) {
        logf_("  [artgen] [Art] Generate=0 -- data\\ left exactly as it is");
        return;
    }
    double fs = (double)h / 1080.0;
    if (ag_set_is_current(g_dir, (int)w, (int)h, fs)) {
        logf_("  [artgen] data\\ already holds the %lux%lu set -- nothing to do", w, h);
        return;
    }
    int nn = GetPrivateProfileIntA("Art", "FontNearest", 0, ip) != 0;
    logf_("  [artgen] data\\ does not match %lux%lu -- generating from your archives", w, h);
    DWORD t0 = GetTickCount();
    int n = ag_generate_set(g_dir, (int)w, (int)h, fs, nn, artgen_log);
    if (n > 0)
        logf_("  [artgen] %d assets in %lu ms", n, GetTickCount() - t0);
    else
        logf_("  [artgen] generation did not complete -- the game will run with"
              " whatever art is already in data\\, which may not match the mode");
}

static int pick_mode(mode_t *out)
{
    /* One pass. The staged-only first pass is gone with the staging it consulted. */
    return pick_mode_pass(out, !g_artgen_enabled);
}

/* Optional override so a user can force a mode without a rebuild. */
static int ini_override(mode_t *m)
{
    char path[MAX_PATH];
    snprintf(path, sizeof path, "%s\\tropico-fix.ini", g_dir);
    UINT w = GetPrivateProfileIntA("Resolution", "Width",  0, path);
    UINT h = GetPrivateProfileIntA("Resolution", "Height", 0, path);
    if (!w || !h) return 0;
    if (g_ini_mode_unusable) return 0;   /* does not fit this screen -- see above */
    if (w % 4) { logf_("  ini: width %u is not a multiple of 4 -- ignoring (would shear)", w); return 0; }
    if (collides_with_stock(w)) { logf_("  ini: width %u collides with a stock slot -- ignoring (would be unreachable)", w); return 0; }
    /* s11's art cap describes STOCK art, and the generator replaces stock art at
     * whatever size we are about to use -- so past the cap is only a problem when
     * generation is switched off. */
    if (w > ART_WIDTH_CAP && !g_artgen_enabled)
        logf_("  ini: WARNING width %u exceeds the %d stock art cap and [Art] Generate=0,"
              " so nothing will build art for %ux%u -- expect an unpainted strip"
              " (FINDINGS s11). Remove Generate=0 to have it generated at launch.",
              w, ART_WIDTH_CAP, w, h);
    m->w = w; m->h = h;
    logf_("  ini override: %ux%u", w, h);
    return 1;
}

/* ------------------------------------------ s113 the ini's mode against the screen
 *
 * Lifted out of the patch pass so it can also run from DllMain, where on a run with
 * no pending monitor change it is already answerable -- and it HAS to run before
 * ini_override(), which consults the flag it sets. Without it, a DllMain decision
 * would take an ini mode the patch pass was going to reject, generate art for it,
 * and hand the game a mode larger than its screen: intro audio over black.
 *
 * Guarded like choose_monitor(). Whichever caller gets here first does the work and
 * logs it once; the other is a no-op. When a monitor change IS pending, DllMain
 * skips this and the patch pass does it after the switch, against the screen the
 * game will actually run on -- which is the reason it lived there to begin with.
 */
static void ini_fit_check(void)
{
    static int done;
    char ip[MAX_PATH];
    int iw, ih, dw = GetSystemMetrics(SM_CXSCREEN), dh = GetSystemMetrics(SM_CYSCREEN);
    if (done) return;
    done = 1;
    snprintf(ip, sizeof ip, "%s\\tropico-fix.ini", g_dir);
    iw = GetPrivateProfileIntA("Resolution", "Width",  0, ip);
    ih = GetPrivateProfileIntA("Resolution", "Height", 0, ip);
    if (!(iw && ih && dw && dh && (iw > dw || ih > dh))) return;

    /* THE MODE MUST FIT THE SCREEN IT WILL RUN ON. When it does not, the game asks
     * for a mode larger than its desktop and renders NOTHING -- the intro audio
     * plays over a blank screen, which looks like a crash and is not one. Measured:
     * a virtual desktop requested at 2560x1440 lands on a 1920x1080 monitor, Wine
     * clamps it, and the ini still says 2560x1440.
     *
     * Refuse quietly rather than fail loudly and invisibly: say what happened, in
     * words, and let the mode picker choose something that fits instead. */
    logf_("[x] CONFIGURED MODE DOES NOT FIT. tropico-fix.ini asks for %dx%d but the"
          " screen this is running on is %dx%d. The game would render nothing at"
          " all -- you would hear the intro over a black screen.", iw, ih, dw, dh);
    logf_("    Cause: the game was started for one monitor and opened on another."
          " Launch it from the monitor you want to play on.");
    logf_("    Ignoring the configured mode and picking one that fits.");
    g_ini_mode_unusable = 1;
}

/* ------------------------------------------------------- s113 decide_mode
 *
 * ONE ANSWER, COMPUTED ONCE, AND THE REASON IT HAS TO BE CACHED IS FINDINGS 98:
 * the art has to exist before the game indexes data\, which on the Steam edition
 * is before the entry point -- so the mode has to be known in DllMain, while the
 * table it is written into cannot be patched until much later.
 *
 * Both callers went through this sequence already; the only thing that is new is
 * that the first caller's answer is kept. Whoever asks second gets the same mode,
 * which is also the honest thing: two independent decisions that happen to agree
 * are not the same as one decision.
 *
 * Not cached on failure. "Nothing satisfied the constraints" is a statement about
 * the display as it is right now, and the display can change between the two calls
 * -- that is precisely what apply_monitor() does.
 */
static mode_t g_decided;
static int    g_mode_decided;

static int decide_mode(mode_t *out)
{
    if (g_mode_decided) { *out = g_decided; return 1; }
    if (!launch_override(&g_decided) && !ini_override(&g_decided) && !pick_mode(&g_decided))
        return 0;
    g_mode_decided = 1;
    *out = g_decided;
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

/* --------------------------------------------- s91: refuse Hardware 3D, gracefully
 *
 * Hardware 3D renders correctly on exactly one of the three runtimes this game
 * meets: the GOG build under system wine. It smears at every resolution under
 * Proton (FINDINGS 23) and it crashes on map entry on native Windows -- and that
 * crash BRICKS the install, because the choice persists to TROPICO.CFG and F2 is
 * then unreachable to undo it. The owner's decision (2026-08-23) is to stop
 * offering it: the hardware path was there to spare a 2001 CPU, and a modern one
 * runs the software renderer without noticing.
 *
 * REVERTING the section 16 fix is NOT the way to do that, and it was considered.
 * The stock gate is a SIGNED `fild` of whatever GetAvailableVidMem reports against
 * 8.5 MB, so it refuses only when that DWORD happens to have its high bit set --
 * true under Wine, which reports a fixed 0xFF816FFF, and unknowable anywhere else.
 * A revert would also drag back the second signed test at the texture budget,
 * which reads the same global and is not established as hardware-only. That trades
 * a deterministic patch for a driver-dependent coin flip and risks the software
 * renderer on the one platform where everything works.
 *
 * So: keep both fixes and make the refusal explicit, in two places.
 *
 *   1. The gate branch is made UNCONDITIONAL (`jbe` -> `jmp`, one byte of our own
 *      replacement, so the 25-byte layout section 16 verified is otherwise
 *      untouched). IDirect3D7::EnumDevices is never called, the callback never
 *      writes a `d1 == 1` descriptor, and the best-match search fails for any
 *      hardware request -- so the engine raises its OWN Tropico.lng string 1721,
 *      "Hardware 3D is not available on this computer". That message is true, and
 *      it is the game's designed refusal rather than one this patch invented.
 *
 *   2. That alone would not have saved the install that prompted this. The
 *      mode-set path reads `[settings+0x10]` DIRECTLY, not through the descriptor
 *      array, so a CFG that already says hardware still takes the hardware branch
 *      and still crashes. patch_block_hardware() zeroes that field in place.
 *
 * `[Hardware] Enable=1` restores the old behaviour -- hardware offered, no heal --
 * for anyone on wine who wants it back. */
static int patch_block_hardware(void)
{
    /* and dword [edx+0x10],0  /  nop   -- five bytes for five, `je` left in place */
    static const BYTE FIX[] = {0x83,0x62,0x10,0x00, 0x90};
    BYTE *p = find_unique_masked(RND_SIG, RND_MASK, sizeof RND_SIG,
                                 g_text, g_textlen, "renderer");
    DWORD settings, lo, hi;
    if (!p) {
        logf_("[x] [hw] renderer branch not found -- a TROPICO.CFG that already selects"
              " Hardware 3D will still take the hardware path. Remedy: zero byte 0x23a"
              " of app\\data2\\TROPICO.CFG");
        return 0;
    }
    /* The operand must be the settings object, which lives in .data. Checked
     * because the replacement stores THROUGH it: a wrong site would zero four
     * bytes of something unrelated. */
    settings = rd32(p + 2);
    lo = (DWORD)(ULONG_PTR)g_data;
    hi = lo + (DWORD)g_datalen;
    if (settings < lo || settings >= hi) {
        logf_("[x] [hw] settings operand 0x%08lx is outside .data (0x%08lx..0x%08lx)"
              " -- wrong site, refusing", settings, lo, hi);
        return 0;
    }
    if (!poke(p + RND_PATCH_OFF, FIX, sizeof FIX)) {
        logf_("[x] [hw] renderer branch: VirtualProtect failed");
        return 0;
    }
    logf_("[+] [hw] renderer branch at %p -> `and [settings+0x10],0` (settings 0x%08lx):"
          " the software path is now unconditional, and a CFG that selected Hardware 3D"
          " heals itself when the game next saves it", p + RND_PATCH_OFF, settings);
    return 1;
}

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

    /* --- 0.5 the monitor, BEFORE ANYTHING READS THE DISPLAY (s90/s99) -------
     *
     * The choice itself was made in DllMain, so the art could be built against it
     * before the game indexed data\ (FINDINGS 98). Only the CHANGE waited for
     * here, because a display change made from DllMain is never noticed by the
     * process that made it (FINDINGS 99).
     *
     * It goes at the TOP of the patch pass, not next to the mode picker where it
     * used to sit. Three things below read SM_CXSCREEN -- the "desktop as Wine
     * sees it" line, the configured-mode-fits check, and the picker -- and every
     * one of them wants the display the game will actually run on, not the one the
     * desktop was idling in. With the switch further down, the fits check could
     * reject a perfectly good 1440p mode for not fitting a 1080p primary that was
     * about to stop being the primary. */
    vd_detect();
    choose_monitor();
    apply_monitor();
    vd_apply();

    /* What Wine believes the screen is, logged UNCONDITIONALLY. Everything the
     * patch computes is relative to this, and when it is stale -- a wineserver that
     * outlived an xrandr change caches the old geometry into the prefix -- the
     * symptom is DDERR_INVALIDRECT on the next launch and nothing says why
     * (FINDINGS 75). One line here turns that into an obvious diagnosis. */
    logf_("[*] desktop as Wine sees it: %dx%d", GetSystemMetrics(SM_CXSCREEN),
          GetSystemMetrics(SM_CYSCREEN));
    /* Both of these read SM_CXSCREEN, so they belong AFTER apply_monitor() and not
     * before it -- the screen they judge against has to be the one the game will run
     * on. ini_fit_check() is a no-op when DllMain already ran it, which it does on
     * every run with no pending switch (s113); the check itself moved there so a
     * DllMain mode decision cannot adopt an ini mode this would have rejected. */
    ini_fit_check();
    launch_mode_check(GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
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
    int hw_enable;
    {
        char iph[MAX_PATH];
        snprintf(iph, sizeof iph, "%s\\tropico-fix.ini", g_dir);
        hw_enable = GetPrivateProfileIntA("Hardware", "Enable", 0, iph);
    }
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
            /* s91: one byte decides whether the compare is a compare at all. `jbe`
             * keeps the section 16 behaviour (unsigned, hardware offered when the
             * card really is too small); `jmp` skips EnumDevices unconditionally,
             * which is how Hardware 3D is refused through the engine's own string
             * 1721 rather than through anything invented here. The other 24 bytes
             * are identical either way, so the verified layout does not fork. */
            fix[k++] = hw_enable ? 0x76 : 0xeb; fix[k++] = (BYTE)newrel;   /* jbe / jmp */
            while (k < 25) fix[k++] = 0x90;
            if (poke(p, fix, sizeof fix)) {
                if (hw_enable)
                    logf_("[+] VRAM compare made unsigned at %p (vidmem global 0x%08lx, jbe rel8 %d)"
                          " -- [Hardware] Enable=1, so Hardware 3D is OFFERED", p, vidmem, newrel);
                else
                    logf_("[+] Hardware 3D refused at %p: EnumDevices skipped unconditionally"
                          " (jmp rel8 %d), so no hardware descriptor is ever written and the game"
                          " gives its own \"not available on this computer\" message."
                          " [Hardware] Enable=1 to offer it anyway", p, newrel);
                ok++;
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

    /* --- 3.2 heal a CFG that already selected Hardware 3D (s91) -------------
     * Only when we are refusing hardware. With Enable=1 the field must be left
     * alone, or the player's choice would be silently overridden. */
    if (!hw_enable) { if (patch_block_hardware()) ok++; else fail++; }

    /* --- 4. slot 4, in BOTH tables ----------------------------------------- *
     * FINDINGS s8: patching the data table alone is not enough. A parallel
     * mapping lives in code and silently drops any mode it does not recognise. */
    mode_t m;
    {
        /* Read before the picker runs -- it is the picker's behaviour this changes. */
        char ip3[MAX_PATH];
        snprintf(ip3, sizeof ip3, "%s\\tropico-fix.ini", g_dir);
        g_artgen_enabled = GetPrivateProfileIntA("Art", "Generate", 1, ip3);
    }
    if (!decide_mode(&m)) {
        logf_("[-] no mode satisfied the constraints; leaving slot 4 stock (1600x1200)");
    } else {
        /* s85's fallback art-switch used to sit here: on the path where the configured
         * mode did not fit, the staged art was for the unusable mode and had to be
         * swapped for a different staged set. There is nothing to swap now -- whatever
         * mode we ended up with, the art for it is generated below. The fallback path
         * and the normal path became the same path. */

        /* A MODE SMALLER THAN THE SCREEN IT IS RUNNING IN. Legitimate on a real
         * desktop -- someone may want 1080p on a 1440p monitor -- but inside the
         * borderless Wine desktop tools/tropico creates, it is always a mistake, and
         * the symptom is one nobody reads as a mode mismatch: the desktop opens
         * fullscreen at the larger size and the game paints the smaller one inside it,
         * which looks like the game "shrinking to a window". Measured 2026-08-23 after
         * step 6 dropped the launcher's ini write. One line, so it never costs a
         * session again. */
        {
            int dw = GetSystemMetrics(SM_CXSCREEN), dh = GetSystemMetrics(SM_CYSCREEN);
            if (dw && dh && ((DWORD)dw > m.w || (DWORD)dh > m.h))
                logf_("  [*] the mode (%lux%lu) is SMALLER than the screen it is running"
                      " in (%dx%d) -- expect the game to paint inside a larger fullscreen"
                      " backdrop. If that is not what you wanted, tropico-fix.ini and the"
                      " display disagree.", m.w, m.h, dw, dh);
        }

        /* The mode is final here. Make the art match it before the game reads any --
         * the menu is the first thing that does, and it opens after this. */
        ensure_art_for_mode(m.w, m.h);

        BYTE *chain = find_unique(CHAIN_SIG, sizeof CHAIN_SIG, g_text, g_textlen, "chain");
        if (chain) {
            DWORD wh[2] = { m.w, m.h };
            int a = poke(tbl + SLOT4_OFF, wh, sizeof wh);
            int b = poke(chain + CHAIN_W_OFF, &m.w, 4) && poke(chain + CHAIN_H_OFF, &m.h, 4);
            if (a && b) { g_mode_w = m.w; g_mode_h = m.h;
                          logf_("[+] slot 4 -> %lux%lu  (data table %p, code chain %p)", m.w, m.h, tbl, chain); ok++; }
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
        if (GetPrivateProfileIntA("WorldFix", "Enable", 1, ip)) {
            UINT mw = (UINT)GetPrivateProfileIntA("WorldFix", "Match", 1600, ip);
            UINT nw = (UINT)GetPrivateProfileIntA("WorldFix", "Width", 0, ip);
            if (!nw) nw = (UINT)m.w;
            int mode_ctor = GetPrivateProfileIntA("WorldFix", "Ctor", 0, ip);
            UINT om = (UINT)GetPrivateProfileIntA("WorldFix", "ObjMatch", 2666, ip);
            UINT ow = (UINT)GetPrivateProfileIntA("WorldFix", "ObjW", 3200, ip);
            UINT ohm = (UINT)GetPrivateProfileIntA("WorldFix", "ObjHMatch", 1920, ip);
            UINT oh  = (UINT)GetPrivateProfileIntA("WorldFix", "ObjH", 2400, ip);
            UINT mh  = (UINT)GetPrivateProfileIntA("WorldFix", "HMatch", 864, ip);
            UINT nh  = (UINT)GetPrivateProfileIntA("WorldFix", "Height", 0, ip);
            /* The twin of the Width fallback above, and it was missing: without it
             * the image pixel height write is skipped and the world keeps the stock
             * 864 while the width follows the mode. Harmless while the ini spelled
             * Height out; a silent half-fix the moment it stopped doing so. */
            if (!nh) nh = (UINT)m.h;
            int force = GetPrivateProfileIntA("WorldFix", "Force", 1, ip);
            /* -1 = auto; 0 = no gate at all.
             *
             * s82: auto was plain m.w/2, justified as "the main viewport is always
             * 2666/3200 = 83% of the mode width".  That premise is false, and it is
             * false BECAUSE OF THE BUG THIS PATCH FIXES: the value the gate compares
             * (`[ecx+0x10]`, the image pixel width) is the STOCK 1600 at gate time,
             * whatever the mode.  So the gate really asks `1600 >= m.w/2`, which
             * holds only while m.w <= 3200.  Wider than that and the gate skips its
             * own fix and the terrain stays 1600x864 -- while the install log still
             * says the patch applied, because that is logged at install time and the
             * gate rejects at draw time.
             *
             * Measured at 3840x2160 (s82): guard 1920 > 1600, world painted
             * 1600x864 of a 3840x2160 screen.  With the guard pinned to 1600 the
             * same run painted 3839x2159.  This is NOT 4K-only: every mode wider
             * than 3200 is affected, which includes 3440x1440 and 3840x1600
             * ultrawides that people actually own.
             *
             * Capping at the stock width keeps every mode <= 3200 bit-for-bit
             * identical to what was verified before, and stops the gate climbing
             * past the very value it is testing.  The zoomed detail preview this
             * gate exists to exclude (s46) is far narrower than 1600. */
            int gi = GetPrivateProfileIntA("WorldFix", "Guard", -1, ip);
            UINT auto_guard = (UINT)m.w / 2;
            if (auto_guard > WORLD_STOCK_W) auto_guard = WORLD_STOCK_W;
            UINT guard = force ? (gi < 0 ? auto_guard : (UINT)gi) : 0;
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

    /* s89 cursor probe. Off by default: it is diagnostic only and changes nothing. */
    {
        char ip[MAX_PATH];
        snprintf(ip, sizeof ip, "%s\\tropico-fix.ini", g_dir);
        g_cur_fix = GetPrivateProfileIntA("Cursor", "Fix", 0, ip);
        g_cur_msg = GetPrivateProfileIntA("Cursor", "MsgProbe", 0, ip);
        g_cur_xcmp = GetPrivateProfileIntA("Cursor", "XCompare", 0, ip);
        g_cur_sites = GetPrivateProfileIntA("Cursor", "Sites", 0, ip);
        if (g_cur_xcmp)
            CloseHandle(CreateThread(NULL, 0, xcompare_thread, NULL, 0, NULL));
        if (GetPrivateProfileIntA("Unix", "Probe", 0, ip)) unix_probe();
        if (g_cur_msg) install_msg_probe();
        /* Sites arms the same hook: without this, [Cursor] Sites=1 alone would set
         * the flag and never install the hook that reads it. */
        if (GetPrivateProfileIntA("Cursor", "Probe", 0, ip) || g_cur_fix || g_cur_sites) {
            g_cur_probe = GetPrivateProfileIntA("Cursor", "Probe", 0, ip);
            if (!install_cursor_probe())
                logf_("[x] [cursor] probe: USER32!GetCursorPos not found in the import"
                      " table -- nothing hooked");
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
            g_chr_trim   = (DWORD)GetPrivateProfileIntA("HudProbe", "EdgeTrim", 8, ip);
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
            if (g_chr_enable && GetPrivateProfileIntA("HudProbe", "ChromeScale", 1, ip)) {
                if (patch_chrome_scale(table_va)) ok++; else fail++;
            } else if (g_chr_enable) {
                logf_("[*] [chrome] ChromeScale=0 -- the six fmul operands are LEFT STOCK;"
                      " this run varies the draw style only");
            }
        }
    }

    /* s103: the blit census (FINDINGS 102).  Read-only -- it tallies, it never
     * changes a draw -- but it hooks the hottest path in the game, so it stays
     * off unless the ini asks for it. */
    {
        char ip[MAX_PATH];
        snprintf(ip, sizeof ip, "%s\\tropico-fix.ini", g_dir);
        g_bc_on = GetPrivateProfileIntA("Blit", "Census", 0, ip);
        if (g_bc_on) {
            g_bc_delay = GetPrivateProfileIntA("Blit", "Delay", 25, ip);
            g_bc_every = GetPrivateProfileIntA("Blit", "Every", 30, ip);
            g_bc_miny = GetPrivateProfileIntA("Blit", "MinY", 0, ip);
            if (patch_blit_census()) ok++; else fail++;
        }
    }

    /* s69: the movie/menu window. Off unless the ini asks. */
    {
        char ip[MAX_PATH];
        snprintf(ip, sizeof ip, "%s\\tropico-fix.ini", g_dir);
        g_bink_pitch = GetPrivateProfileIntA("Menu", "FixMoviePitch", 0, ip);
        if (GetPrivateProfileIntA("Menu", "FixPreview", 2, ip)) {
            if (patch_preview_fix(GetPrivateProfileIntA("Menu", "FixPreview", 2, ip)))
                ok++; else fail++;
        }
        if (GetPrivateProfileIntA("Menu", "SurfaceProbe", 0, ip)) {
            /* descriptor width lives at +4 of the object; the locked base at +9 */
            static const BYTE CS[]  = {0x66,0x3d,0x80,0x02, 0x7e,0x0a,
                                       0xc7,0x44,0x24,0x10,0x80,0x02,0x00,0x00};
            static const BYTE CM[]  = {   1,   1,   1,   1,    1,   1,
                                          1,   1,   1,   1,   1,   1,   1,   1};
            BYTE *c = find_unique_masked(CS, CM, sizeof CS, g_text, g_textlen, "descriptor");
            if (c) {
                /* the clamp reads `mov ax,[descW]` six bytes earlier */
                g_surf_va = rd32(c - 4) + 5;
                if (patch_surface_probe()) ok++; else fail++;
            } else { logf_("[x] [surf] could not locate the screen descriptor"); fail++; }
        }
        if (GetPrivateProfileIntA("Menu", "PreviewProbe", 0, ip)) {
            if (patch_preview_probe()) ok++; else fail++;
        }
        if (GetPrivateProfileIntA("Menu", "FixMovieScale", 1, ip)) {
            if (patch_blit_scale()) ok++; else fail++;
        }
        if (GetPrivateProfileIntA("Menu", "FixHudMovie", 1, ip)) {
            if (patch_hud_movie()) ok++; else fail++;
        }
        if (GetPrivateProfileIntA("Menu", "HudMovieProbe", 0, ip)) {
            if (patch_hud_movie_probe()) ok++; else fail++;
        }
        if (GetPrivateProfileIntA("Menu", "BlitProbe", 0, ip)) {
            if (patch_blit_probe()) ok++; else fail++;
        }
        if (GetPrivateProfileIntA("Menu", "Probe", 0, ip)) {
            /* The submode flag lives at [0x612fec]; read its VA out of the
             * videowi2 branch rather than hardcoding it. */
            static const BYTE FS[]  = {0x8b,0x15,0,0,0,0, 0x39,0x5a,0x1c};
            static const BYTE FM[]  = {   1,   1,0,0,0,0,    1,   1,   1};
            BYTE *f = find_unique_masked(FS, FM, sizeof FS, g_text, g_textlen, "movie submode");
            if (f) g_mv_flag_va = rd32(f + 2);
            /* The clamp's own fmul operands are the px<->virtual scale globals, and
             * they are the cheapest read-out of the live mode. Take them from there
             * so [Menu] Probe does not depend on [VText] being enabled. */
            if (!g_vt_xs_va || !g_vt_ys_va) {
                static const BYTE CS[]  = {0x66,0x3d,0x80,0x02, 0x7e,0x0a,
                                           0xc7,0x44,0x24,0x10,0x80,0x02,0x00,0x00};
                static const BYTE CM[]  = {   1,   1,   1,   1,    1,   1,
                                              1,   1,   1,   1,   1,   1,   1,   1};
                BYTE *c = find_unique_masked(CS, CM, sizeof CS, g_text, g_textlen, "clamp scales");
                if (c) { g_vt_xs_va = rd32(c + 23); g_vt_ys_va = rd32(c + 69); }
            }
            if (patch_movie_probe()) ok++; else fail++;
        }
        /* s69: the menu renders at slot 4 -- but ONLY if the seven 640x480-only
         * assets were synthesised into data/. Defaulting this ON unconditionally
         * would kill the menu with "Error opening pack file item 'setuplb.i16'"
         * for anyone who dropped the DLL in without running the installer, so the
         * default is conditional on the art existing. An explicit ini value still
         * wins either way -- including Slot=-1 to force stock behaviour. */
        {
            char probe[MAX_PATH];
            snprintf(probe, sizeof probe, "%s\\data\\setuplb.i16", g_dir);
            int have_menu_art = (GetFileAttributesA(probe) != INVALID_FILE_ATTRIBUTES);
            g_menu_slot = GetPrivateProfileIntA("Menu", "Slot", have_menu_art ? 4 : -1, ip);
            if (!have_menu_art && g_menu_slot >= 0)
                logf_("[-] [menu] Slot=%d but data\\setuplb.i16 is missing --"
                      " the menu will fail to open its art (run tropico-install.sh)", g_menu_slot);
            else if (!have_menu_art)
                logf_("  [menu] no synthesised menu art; leaving the menu at stock 640x480");
        }

        /* s73: the frontend preset. Installed whenever the menu slot is redirected
         * -- without it the menu is correct at startup and drops back to 640x480 the
         * moment you return to it from a map. [Menu] SlotProbe=1 additionally logs
         * every apply-video call and its caller, which is how this was found. */
        g_slot_log = GetPrivateProfileIntA("Menu", "SlotProbe", 0, ip);
        /* s74: keep the window on the monitor Wine measures. On by default --
         * the failure it prevents is DDERR_INVALIDRECT, which is unreadable. */
        g_pin_primary = GetPrivateProfileIntA("Display", "PinToPrimary", 1, ip);
        if (g_pin_primary) {
            logf_("[+] [display] watching for the game window, to keep it on the monitor"
                  " Wine measures (FINDINGS 74)");
            CloseHandle(CreateThread(NULL, 0, pin_thread, NULL, 0, NULL));
        }
        /* s79: windowed mode is the documented failure path (FINDINGS 6), and one
         * click of the F2 "Fullscreen" box persists it into TROPICO.CFG and bricks
         * every later launch. On by default; Display ForceFullscreen=0 restores the
         * stock behaviour, checkbox and all. */
        g_force_fs = GetPrivateProfileIntA("Display", "ForceFullscreen", 1, ip);
        if (g_force_fs) { if (patch_force_fullscreen()) ok++; else fail++; }
        if (g_menu_slot >= 0 || g_slot_log || g_force_fs) {
            if (!g_vt_xs_va || !g_vt_ys_va) {
                static const BYTE CS[]  = {0x66,0x3d,0x80,0x02, 0x7e,0x0a,
                                           0xc7,0x44,0x24,0x10,0x80,0x02,0x00,0x00};
                static const BYTE CM[]  = {   1,   1,   1,   1,    1,   1,
                                              1,   1,   1,   1,   1,   1,   1,   1};
                BYTE *c = find_unique_masked(CS, CM, sizeof CS, g_text, g_textlen, "clamp scales");
                if (c) { g_vt_xs_va = rd32(c + 23); g_vt_ys_va = rd32(c + 69); }
            }
            find_applyvideo();
            if (patch_slot_probe()) ok++; else fail++;
        }
        if (g_menu_slot >= 0) { if (patch_menu_slot()) ok++; else fail++; }
        int mw = GetPrivateProfileIntA("Menu", "W", 0, ip);
        int mh = GetPrivateProfileIntA("Menu", "H", 0, ip);
        if (GetPrivateProfileIntA("Menu", "Fit", 0, ip)) {
            /* Pillarbox: the largest 4:3 box that fits the mode, which is what the
             * owner asked for -- fill as much as possible without distorting. */
            int W = GetPrivateProfileIntA("Resolution", "Width", 0, ip);
            int H = GetPrivateProfileIntA("Resolution", "Height", 0, ip);
            if (!mw || !mh) {
                if (W && H) {
                    mw = (H * 4 / 3 < W) ? H * 4 / 3 : W;
                    mh = (W * 3 / 4 < H) ? W * 3 / 4 : H;
                } else logf_("[x] [menu] Fit=1 needs [Resolution] Width/Height, or Menu W/H");
            }
            if (mw && mh) { if (patch_menu(mw, mh)) ok++; else fail++; }
            else fail++;
        }
    }

    /* s68: force the startup movie. Off unless the ini asks. */
    {
        char ip[MAX_PATH];
        snprintf(ip, sizeof ip, "%s\\tropico-fix.ini", g_dir);
        if (GetPrivateProfileIntA("Intro", "Force", 0, ip)) {
            if (patch_intro()) ok++; else fail++;
        }
    }

    /* s65: rotated tab-label placement.  Off unless the ini asks. */
    {
        char ip[MAX_PATH];
        snprintf(ip, sizeof ip, "%s\\tropico-fix.ini", g_dir);
        if (GetPrivateProfileIntA("VText", "Enable", 1, ip)) {
            /* -1000 is the "absent" sentinel: 0 and negatives are all legal values. */
            int dy = GetPrivateProfileIntA("VText", "DY", -1000, ip);
            int dx = GetPrivateProfileIntA("VText", "DX", -1000, ip);
            int ch = GetPrivateProfileIntA("VText", "ClipH", -1000, ip);
            if (dy != -1000 && (dy < -128 || dy > 127)) {
                logf_("[x] [vtext] DY=%d out of range -- it is a signed byte displacement (-128..127)", dy);
                fail++;
            } else if (dx != -1000 && (dx < -128 || dx > 127)) {
                logf_("[x] [vtext] DX=%d out of range -- it is a signed byte displacement (-128..127)", dx);
                fail++;
            } else if (patch_vtext(dy, dx, ch, dy != -1000, dx != -1000, ch != -1000)) ok++;
            else fail++;
            /* THE FIVE DIALS DEPEND ON THE ASPECT ALONE (FINDINGS 86, correcting 72.4).
             *
             * 72.4 recorded these as un-derivable. What it actually refuted is a
             * rewrite that is exact for EVERY label: the defect is
             *     0.5 * (1 - ys/xs) * label_px
             * and the hook is handed the box, never label_px, so one rewrite cannot
             * suit every string. That still stands -- the set below is a compromise
             * sized for the longest label, and it stays a measurement.
             *
             * TRANSPORTING that compromise to another mode is a different question,
             * and it closes. Two things carry it:
             *   - ys/xs is 0.75 at EVERY 16:9 mode, so the fractional error is fixed;
             *   - tropico-setmode.sh scales the fonts by H/1080, so label_px scales
             *     by f = H/1080 and the correction in pixels scales with it.
             * The dials are VIRTUAL units and convert to pixels by ys, so a correction
             * that scales by f needs a dial scaled by f * (1080/H) = 1. The mode term
             * CANCELS: the numbers below are right at every 16:9 mode, unchanged.
             *
             * CONFIRMED IN GAME AT 2560x1440, both branches: stock fonts with the
             * dials transported by 1080/H, and H/1080 fonts with these values.
             *
             * GATED ON ASPECT, not on a mode, and 16:9 only. At 4:3 ys/xs is 1, the
             * defect is zero and PopTop's geometry is already right. Any other aspect
             * has a different (1 - ys/xs) and no confirmed set, so it is left stock:
             * rotated labels overhang, nothing else is affected, and the log says so.
             * The predicted 16:10 set is in FINDINGS 86 -- one probe run to confirm,
             * not a dialling pass. An explicit ini value always wins.
             *
             * THE ART MUST MATCH. These values assume fonts at H/1080. A set staged by
             * a pre-86 build has stock fonts and would be mis-dialled by that factor;
             * tropico-setmode.sh stamps the scale it built at and rebuilds any set
             * whose stamp is missing or stale, so such a set cannot reach this code. */
            const double vt_ar = g_mode_h ? (double)g_mode_w / (double)g_mode_h : 0.0;
            const int vt_dialled = (vt_ar > 1.77 && vt_ar < 1.79);
            g_vt_fix   = GetPrivateProfileIntA("VText", "Fix",   vt_dialled, ip);
            g_vt_fw    = GetPrivateProfileIntA("VText", "FixW",  (int)g_mode_w, ip);
            g_vt_fh    = GetPrivateProfileIntA("VText", "FixH",  (int)g_mode_h, ip);
            g_vt_boxh  = GetPrivateProfileIntA("VText", "BoxH",  vt_dialled ?  340 : 0, ip);
            g_vt_boxdy = GetPrivateProfileIntA("VText", "BoxDY", vt_dialled ?  -99 : 0, ip);
            g_vt_boxdx = GetPrivateProfileIntA("VText", "BoxDX", vt_dialled ?  -14 : 0, ip);
            g_vt_entry = GetPrivateProfileIntA("VText", "Entry", vt_dialled, ip);
            if (!vt_dialled && !g_vt_boxh && !g_vt_boxdy)
                logf_("[-] [vtext] no dials for %ux%u (aspect %.4f; only 16:9 is confirmed)"
                      " -- rotated labels left STOCK and will overhang."
                      " See FINDINGS 86 for the predicted set and how to confirm it.",
                      g_mode_w, g_mode_h, vt_ar);
            /* Probe now means "log every rotated draw", not "install the hooks":
             * the hooks ARE the fix, so Fix=1 installs them either way. */
            g_vt_log   = GetPrivateProfileIntA("VText", "Probe", 0, ip);
            g_vt_bdh   = GetPrivateProfileIntA("VText", "BldgDH", vt_dialled ?  107 : 0, ip);
            g_vt_bdy   = GetPrivateProfileIntA("VText", "BldgDY", vt_dialled ? -111 : 0, ip);
            if (g_vt_fix && !(g_vt_fw && g_vt_fh)) {
                logf_("[x] [vtext] Fix=1 needs FixW/FixH -- an ungated correction breaks"
                      " every mode the F2 ladder climbs through");
                fail++;
            } else if (GetPrivateProfileIntA("VText", "Probe", 0, ip) || g_vt_fix) {
                if (g_vt_fix)
                    logf_("[*] [vtext] fix armed for %dx%d (aspect %.4f): BoxH=%d BoxDY=%d",
                          g_vt_fw, g_vt_fh, vt_ar, g_vt_boxh, g_vt_boxdy);
                if (patch_vtext_probe()) ok++; else fail++;
                if (g_vt_entry) { if (patch_vtext_entry()) ok++; else fail++; }
            }
        }
    }

    /* s87.2: repaint the bottom-bar readouts. ON by default, like every other fix
     * here; [Text] Enable=0 leaves them PopTop's grey. Colour is a raw RGB555 word
     * in DECIMAL, because GetPrivateProfileIntA does not parse hex: 32767 = 0x7fff
     * = white, 30653 = 0x77bd = the near-white the engine uses at entry 23. */
    {
        char ip[MAX_PATH];
        snprintf(ip, sizeof ip, "%s\\tropico-fix.ini", g_dir);
        if (GetPrivateProfileIntA("Text", "Enable", 1, ip)) {
            int want = GetPrivateProfileIntA("Text", "ReadoutColour", 0x7fff, ip);
            if (want < 0 || want > 0xffff)
                logf_("[x] [text] ReadoutColour=%d is not a 16-bit value -- ignored", want);
            else if (patch_readout_colour(want)) ok++; else fail++;
        }
    }

    /* s87: horizontal-text probe. Off unless the ini asks -- it is a per-frame path
     * and exists to answer "which argument carries the colour", not to ship. */
    {
        char ip[MAX_PATH];
        snprintf(ip, sizeof ip, "%s\\tropico-fix.ini", g_dir);
        if (GetPrivateProfileIntA("TextProbe", "Enable", 0, ip)) {
            g_txt_log = 1;
            if (patch_text_probe()) ok++; else fail++;
        }
    }

    /* CROSS-CHECK THE ART AGAINST THE MODE. tropico-setmode.sh stamps the mode
     * whose art set is currently unpacked into data/ (FINDINGS 72). A half-applied
     * swap -- ini moved, art not, or the reverse -- looks exactly like the section 11
     * art-mismatch symptom, which is an expensive thing to re-diagnose from a
     * screenshot. Cheap to check here, so check here. */
    if (g_mode_w && g_mode_h) {
        char mp[MAX_PATH], buf[64] = {0};
        DWORD got = 0;
        HANDLE fh;
        snprintf(mp, sizeof mp, "%s\\data\\ARTSET-MODE.txt", g_dir);
        fh = CreateFileA(mp, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (fh != INVALID_HANDLE_VALUE) {
            UINT aw = 0, ah = 0;
            ReadFile(fh, buf, sizeof buf - 1, &got, NULL);
            CloseHandle(fh);
            if (sscanf(buf, "%ux%u", &aw, &ah) == 2 && aw && ah) {
                if (aw != g_mode_w || ah != g_mode_h)
                    logf_("[x] ART MISMATCH: the mode is %ux%u but data/ holds the %ux%u art set."
                          " The HUD will be wrong. Run tools/tropico-setmode.sh %u %u.",
                          g_mode_w, g_mode_h, aw, ah, g_mode_w, g_mode_h);
                else
                    logf_("  art set in data/ matches the mode (%ux%u)", aw, ah);
            }
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

/* s99 file-order probe. Declared here rather than with the probe because
 * hook_GetDeviceCaps, below, records where its first call lands in the
 * numbered sequence of opens -- that ordering IS the measurement. */
static int  g_fo_on;
static LONG g_fo_n;

static int WINAPI hook_GetDeviceCaps(HDC hdc, int index)
{
    if (g_fo_on) {
        static LONG said;
        if (!InterlockedExchange(&said, 1))
            logf_("  [fileorder] === GetDeviceCaps first call, after %ld opens ===",
                  (long)g_fo_n);
    }
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

/* ------------------------------------------------ s89: the cursor probe
 *
 * The map pans toward the top-left on its own when the desktop's monitors are not
 * top-aligned, and stops the moment they are. The pointer leaving the window shows
 * the same "pan up-left" cursor at every resolution. So some coordinate the game
 * reads carries a monitor origin that something else does not -- but WHICH one is
 * three different fixes, and the picture cannot tell them apart.
 *
 * The game imports GetCursorPos and ScreenToClient and no other cursor API (no
 * DirectInput, no GetCursorInfo, no ClipCursor), so the whole chain is those two
 * calls. This logs both halves of it side by side with every rectangle that could
 * be supplying the origin: the window, the client area, the monitor the window is
 * on, the virtual screen, and the primary metrics.
 *
 * Rate-limited to one line a second, 60 lines max: it is called every frame, and a
 * probe that floods the log is a probe nobody reads. */
static HWND find_game_window(void);   /* defined with the display watcher below */

typedef BOOL (WINAPI *GetCursorPos_t)(LPPOINT);
static GetCursorPos_t  g_real_gcp;
static volatile LONG g_cur_calls;        /* every call, not a sample            */
static volatile LONG g_cur_zeros;        /* those that came back exactly 0,0    */
static volatile LONG g_cur_dropped;      /* zeros replaced with the last good   */
static POINT g_cur_last;                 /* the last position we believed       */
static int   g_cur_have_last;
static GetCursorPos_t *g_gcp_slot;
static LONG  g_cur_logged;
static DWORD g_cur_last_ms;

/* ------------------------------------ s107.3 which call sites read the cursor
 *
 * s107 argues the next instrument has to fire on the pan DECISION rather than on a
 * clock, because the drift is intermittent and a clock keeps missing it.  Naming the
 * call site that feeds the pan is the first step, and it costs one run: the hook is
 * entered through the IAT slot, so `__builtin_return_address(0)` is the instruction
 * after the game's own `call`, which is exactly what a detour needs and what the
 * disassembly can be read against.
 *
 * A CENSUS, not a stream, for s103's reason: the game called GetCursorPos 20,000
 * times in a few seconds of the last Steam run.  One row per distinct return address.
 *
 * The `edge` column is the discriminating one.  Every site sees the same coordinates,
 * so hit counts alone would not separate them -- but the map pans when the cursor is
 * within a margin of a screen edge, so the site that drives panning is the one whose
 * reads land there.  A site that never sees an edge cannot be the one. */
#define GCP_SITES 32
#define GCP_EDGE  8
static struct { DWORD ret; LONG hits; LONG edge; LONG lastx, lasty; } g_gcp_site[GCP_SITES];
static LONG g_gcp_n;

static void gcp_note(DWORD ret, const POINT *p)
{
    static int sw, sh;
    int i, at_edge;
    if (!sw) { sw = GetSystemMetrics(SM_CXSCREEN); sh = GetSystemMetrics(SM_CYSCREEN); }
    at_edge = (p->x <= GCP_EDGE || p->y <= GCP_EDGE ||
               p->x >= sw - 1 - GCP_EDGE || p->y >= sh - 1 - GCP_EDGE);
    for (i = 0; i < g_gcp_n && i < GCP_SITES; i++)
        if (g_gcp_site[i].ret == ret) break;
    if (i >= GCP_SITES) return;                    /* table full -- say so at dump */
    if (i == g_gcp_n) { g_gcp_site[i].ret = ret; g_gcp_n = i + 1; }
    g_gcp_site[i].hits++;
    if (at_edge) g_gcp_site[i].edge++;
    g_gcp_site[i].lastx = p->x; g_gcp_site[i].lasty = p->y;
}

static void gcp_dump(void)
{
    int i;
    logf_("[*] [cursor] call-site census -- %ld distinct site(s)%s.  A site with 0 at"
          " an edge cannot be the one that pans.", g_gcp_n,
          g_gcp_n >= GCP_SITES ? ", TABLE FULL so some were DROPPED" : "");
    for (i = 0; i < g_gcp_n && i < GCP_SITES; i++)
        logf_("  [cursor] caller %p  %ld read(s), %ld at a screen edge (last %ld,%ld)",
              (void *)(SIZE_T)g_gcp_site[i].ret, g_gcp_site[i].hits,
              g_gcp_site[i].edge, g_gcp_site[i].lastx, g_gcp_site[i].lasty);
}

static BOOL WINAPI hook_GetCursorPos(LPPOINT pt)
{
    BOOL r = g_real_gcp(pt);

    /* s89. Wine hands the game an exact 0,0 every so often while the pointer is
     * somewhere else entirely -- measured mid-screen, between two good samples.
     * The game reads 0,0 as "pointer in the top-left corner", which is its
     * pan-up-left command, so the map creeps on its own.
     *
     * COUNT EVERY CALL, not one a second: the earlier 1 Hz sample could not say
     * whether the two zeros it caught were spurious or the pointer genuinely
     * leaving the window, and that is the whole question.
     *
     * The filter substitutes the last position we believed. It refuses to do so
     * when that position was itself near the corner, so a player who really is
     * panning into the top-left still gets what they asked for -- the only thing
     * suppressed is a jump to the corner from somewhere far away, which no hand
     * can produce. */
    if (g_cur_sites && r && pt)
        gcp_note((DWORD)(SIZE_T)__builtin_return_address(0), pt);

    if (r && pt) {
        LONG n = InterlockedIncrement(&g_cur_calls);
        if (pt->x == 0 && pt->y == 0) {
            LONG z = InterlockedIncrement(&g_cur_zeros);
            int near_corner = g_cur_have_last &&
                              g_cur_last.x < 32 && g_cur_last.y < 32;
            if (g_cur_fix && g_cur_have_last && !near_corner) {
                *pt = g_cur_last;
                InterlockedIncrement(&g_cur_dropped);
            }
            if (z <= 20)
                logf_("[*] [cursor] ZERO sample #%ld at call %ld (last good %ld,%ld)%s",
                      z, n, g_cur_last.x, g_cur_last.y,
                      (g_cur_fix && g_cur_have_last && !near_corner)
                          ? " -- replaced" : "");
        } else {
            g_cur_last = *pt;
            g_cur_have_last = 1;
        }
        /* A periodic denominator. Zeros alone say nothing without the call count
         * they came out of. */
        if ((n % 2000) == 0)
            logf_("[*] [cursor] %ld calls, %ld zero(s), %ld replaced",
                  n, g_cur_zeros, g_cur_dropped);
        if (g_cur_sites && (n % 20000) == 0)
            gcp_dump();
    }

    if (g_cur_probe && r && pt && g_cur_logged < 60) {
        DWORD now = GetTickCount();
        if (now - g_cur_last_ms >= 1000) {
            HWND w = find_game_window();
            RECT wr, cr;
            POINT cl = *pt;
            MONITORINFO mi;
            g_cur_last_ms = now;
            InterlockedIncrement(&g_cur_logged);
            memset(&wr, 0, sizeof wr);
            memset(&cr, 0, sizeof cr);
            mi.cbSize = sizeof mi;
            mi.rcMonitor.left = mi.rcMonitor.top = 0;
            mi.rcMonitor.right = mi.rcMonitor.bottom = 0;
            if (w) {
                GetWindowRect(w, &wr);
                GetClientRect(w, &cr);
                ScreenToClient(w, &cl);
                GetMonitorInfoA(MonitorFromWindow(w, MONITOR_DEFAULTTOPRIMARY), &mi);
            }
            logf_("[*] [cursor] screen %ld,%ld -> client %ld,%ld | window %ld,%ld"
                  " %ldx%ld | client %ldx%ld | monitor %ld,%ld %ldx%ld | virt %d,%d"
                  " %dx%d | primary %dx%d",
                  pt->x, pt->y, cl.x, cl.y,
                  wr.left, wr.top, wr.right - wr.left, wr.bottom - wr.top,
                  cr.right - cr.left, cr.bottom - cr.top,
                  mi.rcMonitor.left, mi.rcMonitor.top,
                  mi.rcMonitor.right - mi.rcMonitor.left,
                  mi.rcMonitor.bottom - mi.rcMonitor.top,
                  GetSystemMetrics(SM_XVIRTUALSCREEN), GetSystemMetrics(SM_YVIRTUALSCREEN),
                  GetSystemMetrics(SM_CXVIRTUALSCREEN), GetSystemMetrics(SM_CYVIRTUALSCREEN),
                  GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
        }
    }
    return r;
}

/* ------------------------------------------------- s114: the DirectDraw probe
 *
 * WHICH ENTRY POINT DOES THE GAME ACTUALLY OBTAIN, AND WITH WHAT ARGUMENTS?
 *
 * The question matters because of what it would license. If DirectDraw can be
 * pointed at a monitor, the patch could open the game on the player's chosen
 * screen WITHOUT making it primary -- retiring s113's whole apparatus: the
 * SetPrimary opt-in, the state file, the ExitProcess hook, the 5 s deadline and
 * the Linux xrandr watchdog. Substituting the device at creation is where that
 * interception would go, so the first thing to establish is what there is to
 * intercept.
 *
 * STATIC ANALYSIS IS ALREADY SPENT ON THIS. The binary carries the strings --
 * "DDraw.dll", "DirectDrawCreate", "DirectDrawCreateEx", "DirectDrawEnumerateExA",
 * adjacent at 0x5a8b6c -- but nothing in .text, .rdata or .data holds a pointer
 * anywhere in that range, so the call site cannot be reached from the file. The
 * file header above already records WHERE the library is loaded (0x52dbd0,
 * called from 0x514e55) but not WHICH export is then resolved, nor with what.
 * Only the running game can say.
 *
 * SO IT LOGS THE WHOLE CHAIN, AND WRAPS THE ENDS. Hooking GetProcAddress alone
 * would report which names were LOOKED UP; the game asks for three and can only
 * use one. So the returned pointers are replaced with wrappers that log the call
 * and forward it unchanged. The GUID argument is the answer to the question that
 * matters -- whether the game passes NULL, and therefore whether substituting a
 * device GUID is a one-line change or a fight.
 *
 * IT CHANGES NOTHING. Every wrapper forwards its arguments untouched and returns
 * what the real function returned. Off unless [DDProbe] Enable=1 asks for it.
 *
 * IT IS INSTALLED FROM DllMain, which the file header licenses: the IAT lives in
 * .idata, which SteamStub leaves in the clear, and the ddraw load happens at
 * 0x514e55 -- after the GetDeviceCaps that arms the patch pass, but there is no
 * reason to cut it that fine when .idata is readable at load time. */

static int g_ddp_enable;

typedef HMODULE  (WINAPI *loadlib_t)(LPCSTR);
typedef FARPROC  (WINAPI *getproc_t)(HMODULE, LPCSTR);
typedef BOOL     (WINAPI *freelib_t)(HMODULE);
typedef HRESULT  (WINAPI *ddc_t)   (GUID *, void **, IUnknown *);
typedef HRESULT  (WINAPI *ddcex_t) (GUID *, void **, const IID *, IUnknown *);
typedef HRESULT  (WINAPI *ddenumex_t)(void *, void *, DWORD);

static loadlib_t  g_ddp_loadlib;
static getproc_t  g_ddp_getproc;
static freelib_t  g_ddp_freelib;
static ddc_t      g_ddp_real_create;
static ddcex_t    g_ddp_real_createex;
static ddenumex_t g_ddp_real_enumex;
static HMODULE    g_ddp_mod;          /* the ddraw the game loaded */

static const char *ddp_guid(const GUID *g)
{
    static char b[80];
    if (!g) return "NULL";
    snprintf(b, sizeof b, "{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
             (unsigned long)g->Data1, g->Data2, g->Data3,
             g->Data4[0], g->Data4[1], g->Data4[2], g->Data4[3],
             g->Data4[4], g->Data4[5], g->Data4[6], g->Data4[7]);
    return b;
}

/* The caller's return address, so the log names the call site in the game rather
 * than merely the fact of a call. The header says the load is at 0x514e55; this
 * is how that claim gets extended to the resolutions and the creation itself. */
#define DDP_CALLER() (__builtin_return_address(0))

/* Defined below: the createex wrapper is the only place that sees the
 * IDirectDraw7 before the game uses it. s117 and s118.14 both ride it. */
static void dd_attach(IDirectDraw7 *dd);

static HRESULT WINAPI ddp_create(GUID *guid, void **out, IUnknown *unk)
{
    HRESULT hr;
    logf_("[ddprobe] DirectDrawCreate(guid=%s, out=%p, unk=%p) from %p",
          ddp_guid(guid), (void *)out, (void *)unk, DDP_CALLER());
    hr = g_ddp_real_create(guid, out, unk);
    logf_("[ddprobe]   -> 0x%08lx%s, object %p", (unsigned long)hr,
          hr == 0 ? " (DD_OK)" : "", out ? *out : NULL);
    if (!guid)
        logf_("[ddprobe]   NOTE: NULL device. A device GUID substituted here is exactly"
              " the interception s114 is asking about.");
    return hr;
}

/* Name -> GUID, by asking DirectDraw the same question the probe asked.
 *
 * Deliberately NOT done from DllMain. The lookup needs ddraw.dll, and loading a
 * library under the loader lock is the one hazard s99 did not have to face --
 * reading the display from there is safe, LoadLibrary is not. By the time the
 * game calls DirectDrawCreateEx it has loaded ddraw itself, so the module is
 * already there and this costs nothing.
 *
 * The match is on the DRIVER name -- \\.\DISPLAY1, \\.\DISPLAY2 -- because that is
 * the namespace win32_outputs() reports in and the one the player writes in the
 * ini. HMONITOR would work equally well and is not used only because the name is
 * the thing a human can check against the log. */
static WINBOOL CALLBACK devsel_cb(GUID *guid, char *desc, char *drv, void *ctx, HMONITOR hm)
{
    (void)desc; (void)ctx; (void)hm;
    if (!guid || !drv || !drv[0]) return TRUE;      /* the NULL primary-driver entry */
    if (_stricmp(drv, g_devsel_want)) return TRUE;
    g_devsel_guid = *guid;
    g_devsel_have = 1;
    return FALSE;                                    /* found it; stop enumerating */
}

static void devsel_resolve(void)
{
    HMODULE m;
    ddenumex_t ex;

    if (g_devsel_tried) return;
    g_devsel_tried = 1;
    if (!g_devsel || !g_devsel_want[0]) return;

    m = g_ddp_mod ? g_ddp_mod : GetModuleHandleA("ddraw.dll");
    if (!m) m = LoadLibraryA("ddraw.dll");
    if (!m) { logf_("[x] [devsel] ddraw.dll is not loadable -- cannot resolve %s",
                    g_devsel_want); return; }

    /* The real export, never the wrapper: this enumeration is ours and must not
     * be mistaken for the game's in the log, nor run the game's callback. */
    ex = (ddenumex_t)(void *)GetProcAddress(m, "DirectDrawEnumerateExA");
    if (!ex) { logf_("[x] [devsel] DirectDrawEnumerateExA is missing -- this build of"
                     " DirectDraw cannot name a monitor"); return; }

    ex((void *)devsel_cb, NULL, DDENUM_ATTACHEDSECONDARYDEVICES);
    if (g_devsel_have)
        logf_("[+] [devsel] %s resolves to device %s", g_devsel_want,
              ddp_guid(&g_devsel_guid));
    else
        logf_("[x] [devsel] no enumerated device is named %s. The game will be left on"
              " the primary, at the mode already chosen -- check the [ddprobe] device"
              " lines, or set [Display] Monitor to a name that appears there.",
              g_devsel_want);
}

static HRESULT WINAPI ddp_createex(GUID *guid, void **out, const IID *iid, IUnknown *unk)
{
    HRESULT hr;
    logf_("[ddprobe] DirectDrawCreateEx(guid=%s, out=%p, iid=%s, unk=%p) from %p",
          ddp_guid(guid), (void *)out, ddp_guid((const GUID *)iid), (void *)unk,
          DDP_CALLER());
    /* s118: THE SUBSTITUTION. One argument, at the one call site, and only when
     * the game asked for the default device -- a game that named a device itself
     * has an opinion we have no business overriding. */
    if (g_devsel && !guid) {
        devsel_resolve();
        if (g_devsel_have) {
            guid = &g_devsel_guid;
            logf_("[+] [devsel] DirectDrawCreateEx: NULL -> %s (%s). The game will render"
                  " on that monitor; the OS primary is NOT being changed.",
                  ddp_guid(guid), g_devsel_want);
            if (g_devsel_ox || g_devsel_oy) {
                g_devsel_xlate = 1;
                logf_("[+] [devsel] %s is at (%ld,%ld) in screen space and this device's"
                      " surface is 0,0-based, so every Blt destination is translated by"
                      " (%ld,%ld). Without this the game blits outside its own surface"
                      " and every frame is #150 (FINDINGS 118.14).",
                      g_devsel_want, g_devsel_ox, g_devsel_oy,
                      -g_devsel_ox, -g_devsel_oy);
            }
        }
    }

    hr = g_ddp_real_createex(guid, out, iid, unk);
    logf_("[ddprobe]   -> 0x%08lx%s, object %p", (unsigned long)hr,
          hr == 0 ? " (DD_OK)" : "", out ? *out : NULL);
    if (g_devsel && g_devsel_have && hr != 0)
        logf_("[x] [devsel] the substituted device FAILED to create. The game is now"
              " without a DirectDraw object; if it starts at all it will be on the"
              " primary. Set [Display] DeviceSelect=0 and report this log.");
    if (!guid)
        logf_("[ddprobe]   NOTE: NULL device.");
    /* s117: this is the only moment the object exists and nothing has been asked
     * of it yet, so it is the only safe moment to patch its vtable. */
    if (hr == 0 && out && *out) dd_attach((IDirectDraw7 *)*out);
    return hr;
}

/* The game enumerates for itself -- measured, GOG, twice, with flags 3 and 7
 * from 0x52dc9c and 0x52dcb4, into its own callback at 0x52e300. That changes
 * the shape of any fix from "substitute a device the game never asked about" to
 * "steer a choice the game is already making", so the interesting question is
 * no longer whether the call happens but WHAT IT HANDS THE GAME.
 *
 * Hence the trampoline: the game's callback is still called, with the arguments
 * DirectDraw gave it, entirely unmodified -- this only reads them on the way
 * past. Its return value is logged too, because FALSE means the game stopped
 * the enumeration early, and stopping early is what choosing looks like from
 * out here. */
typedef WINBOOL (CALLBACK *ddp_cb_t)(GUID *, char *, char *, void *, HMONITOR);
static ddp_cb_t g_ddp_gamecb;

static WINBOOL CALLBACK ddp_enum_tramp(GUID *guid, char *desc, char *drv,
                                       void *ctx, HMONITOR hm)
{
    WINBOOL r;
    MONITORINFOEXA mi;
    memset(&mi, 0, sizeof mi);
    mi.cbSize = sizeof mi;
    logf_("[ddprobe]   device: guid=%s desc=\"%s\" driver=\"%s\" hmonitor=%p",
          ddp_guid(guid), desc ? desc : "", drv ? drv : "", (void *)hm);
    if (hm && GetMonitorInfoA(hm, (MONITORINFO *)&mi))
        logf_("[ddprobe]           -> %s at (%ld,%ld)-(%ld,%ld)%s", mi.szDevice,
              mi.rcMonitor.left, mi.rcMonitor.top, mi.rcMonitor.right, mi.rcMonitor.bottom,
              (mi.dwFlags & MONITORINFOF_PRIMARY) ? "  PRIMARY" : "");
    r = g_ddp_gamecb ? g_ddp_gamecb(guid, desc, drv, ctx, hm) : TRUE;
    if (!r)
        logf_("[ddprobe]           the game returned FALSE -- it STOPPED the enumeration"
              " here, which is what making a choice looks like");
    return r;
}

static HRESULT WINAPI ddp_enumex(void *cb, void *ctx, DWORD flags)
{
    HRESULT hr;
    logf_("[ddprobe] DirectDrawEnumerateExA(cb=%p, ctx=%p, flags=0x%08lx) from %p"
          " -- THE GAME IS ENUMERATING DEVICES ITSELF",
          cb, ctx, (unsigned long)flags, DDP_CALLER());
    g_ddp_gamecb = (ddp_cb_t)cb;
    hr = g_ddp_real_enumex(cb ? (void *)ddp_enum_tramp : NULL, ctx, flags);
    logf_("[ddprobe]   -> 0x%08lx", (unsigned long)hr);
    return hr;
}

/* The game spells it "DDraw.dll"; other callers spell it "ddraw.dll". Matching
 * case-sensitively would make the whole probe silent on a capitalisation. */
static int ddp_names_ddraw(const char *s)
{
    for (; *s; s++)
        if ((s[0] | 32) == 'd' && (s[1] | 32) == 'd' && (s[2] | 32) == 'r' &&
            (s[3] | 32) == 'a' && (s[4] | 32) == 'w') return 1;
    return 0;
}

/* The two IDirectDraw7 members the frame counter needs, and the primitive that
 * patches them. By member rather than by index -- see the note in
 * hook_CreateSurface. */
static HRESULT (WINAPI *g_real_cs) (IDirectDraw7 *, DDSURFACEDESC2 *,
                                    IDirectDrawSurface7 **, IUnknown *);
static HRESULT (WINAPI *g_real_blt)(IDirectDrawSurface7 *, RECT *, IDirectDrawSurface7 *,
                                    RECT *, DWORD, DDBLTFX *);

static int hook_slot(void **slot, void *replacement, void **real)
{
    *real = *slot;
    return poke(slot, &replacement, sizeof replacement);
}

/* ------------------------------------------------------ s117: the frame counter
 *
 * s115.9 stopped the presenter on a cost objection and then admitted the cost had
 * never been measured -- "the performance number should have come before any
 * cosmetic fix". This is that number. It also answers a second question: whether
 * the software renderer is still fast enough at the resolutions this patch now
 * reaches, which is the only argument for restoring Hardware 3D that s91's
 * deterministic refusal does not already dispose of.
 *
 * WHERE A FRAME IS. Not assumed -- read off a WINEDEBUG `+ddraw` trace of a real
 * map load, on the stock path with no interception of any kind:
 *
 *     CreateSurface(DDSCAPS_PRIMARYSURFACE)                 -- no FLIP, no COMPLEX
 *     CreateSurface(DDSCAPS_OFFSCREENPLAIN|DDSCAPS_SYSTEMMEMORY)
 *     loop:  Lock(offscreen) -> render -> Unlock -> Blt(primary <- offscreen)
 *
 * There is no flipping chain in this engine, so there is no Flip to count and no
 * ambiguity about which call ends a frame: ONE Blt on the primary IS one frame.
 * That is why this counts Blt rather than something cleverer.
 *
 * It rides s114's GetProcAddress interception because that is the only code in
 * the proxy that ever sees the IDirectDraw7 -- the game keeps it in a global at
 * 0x61c80c and hands it to no one. NOTHING THE GAME RELIES ON IS INTERCEPTED: the
 * cooperative level and both mode calls are not hooked at all, CreateSurface
 * forwards the descriptor exactly as the game wrote it, and Blt is forwarded to
 * the real one. The counter changes nothing about what it is measuring.
 */
static int   g_fc;                 /* [FrameCount] Enable */
static int   g_fc_interval;        /* seconds between report lines */
static IDirectDrawSurface7 *g_fc_primary;
static DWORD g_fc_w, g_fc_h, g_fc_bpp;

#define FC_BUCKET_MS 0.5           /* histogram resolution, milliseconds */
#define FC_BUCKETS   201           /* 0..100 ms; the last bucket is the overflow */
static unsigned      g_fc_hist[FC_BUCKETS];
static LARGE_INTEGER g_fc_freq, g_fc_prev, g_fc_wstart;
static unsigned      g_fc_n;       /* frames in the current reporting window */
static double        g_fc_sum, g_fc_max;
static unsigned      g_fc_total;

/* Percentiles from a histogram rather than a sample buffer: no allocation, no
 * per-frame work beyond one increment, and 0.5 ms is finer than any decision this
 * measurement feeds. A mean alone would hide exactly the thing worth knowing --
 * whether the slow frames are rare and large or the whole distribution is slow. */
static double fc_pct(int pct)
{
    unsigned want, acc = 0;
    int i;
    if (!g_fc_n) return 0.0;
    want = (unsigned)((double)g_fc_n * pct / 100.0 + 0.5);
    if (!want) want = 1;
    for (i = 0; i < FC_BUCKETS; i++) {
        acc += g_fc_hist[i];
        if (acc >= want) break;
    }
    if (i >= FC_BUCKETS - 1) return FC_BUCKET_MS * (FC_BUCKETS - 1);
    return ((double)i + 0.5) * FC_BUCKET_MS;
}

static void fc_tick(void)
{
    LARGE_INTEGER now;
    double ms, win;
    int b;

    if (!g_fc) return;
    QueryPerformanceCounter(&now);

    /* The first tick has no predecessor: it establishes the origin and is not a
     * frame time. Counting it would put one absurd interval in every run. */
    if (!g_fc_freq.QuadPart) {
        QueryPerformanceFrequency(&g_fc_freq);
        if (!g_fc_freq.QuadPart) {
            logf_("[x] [fps] no performance counter on this machine -- counting OFF");
            g_fc = 0;
            return;
        }
        g_fc_prev = now; g_fc_wstart = now;
        return;
    }

    ms = (double)(now.QuadPart - g_fc_prev.QuadPart) * 1000.0 / (double)g_fc_freq.QuadPart;
    g_fc_prev = now;
    g_fc_total++;
    g_fc_n++;
    g_fc_sum += ms;
    if (ms > g_fc_max) g_fc_max = ms;
    b = (int)(ms / FC_BUCKET_MS);
    if (b < 0) b = 0;
    if (b >= FC_BUCKETS) b = FC_BUCKETS - 1;
    g_fc_hist[b]++;

    win = (double)(now.QuadPart - g_fc_wstart.QuadPart) * 1000.0 / (double)g_fc_freq.QuadPart;
    if (win < (double)g_fc_interval * 1000.0) return;

    /* One line per window. logf_ reopens the file on every call, so this must never
     * run per frame -- at 60 fps that cost alone would become the thing measured. */
    logf_("[fps] %lux%lu %lubpp  %u frames in %.2f s = %.1f fps   frame ms:"
          " mean %.2f  p50 %.2f  p95 %.2f  p99 %.2f  max %.2f   (%u total)",
          (unsigned long)g_fc_w, (unsigned long)g_fc_h, (unsigned long)g_fc_bpp,
          g_fc_n, win / 1000.0, (double)g_fc_n / (win / 1000.0),
          g_fc_sum / (double)g_fc_n, fc_pct(50), fc_pct(95), fc_pct(99), g_fc_max,
          g_fc_total);

    g_fc_n = 0; g_fc_sum = 0.0; g_fc_max = 0.0; g_fc_wstart = now;
    memset(g_fc_hist, 0, sizeof g_fc_hist);
}

/* Two jobs, and only one of them touches anything.
 *
 * s117 counts: the arguments are not read and not rewritten, because a counter
 * that changed what it counted would be worthless.
 *
 * s118.14 translates, and ONLY when DeviceSelect put the game on a monitor whose
 * origin is not (0,0). A NULL destination means "the whole surface" and is left
 * exactly as it is -- rewriting it would invent a rectangle the game did not ask
 * for. On the primary, and with DeviceSelect off, g_devsel_xlate is 0 and this is
 * the same forwarding hook it was before. */
static HRESULT WINAPI hook_Blt(IDirectDrawSurface7 *self, RECT *dst, IDirectDrawSurface7 *src,
                               RECT *srcr, DWORD flags, DDBLTFX *fx)
{
    RECT r;

    if (self && self == g_fc_primary) {
        if (g_fc) fc_tick();
        if (g_devsel_xlate && dst) {
            r = *dst;
            r.left   -= g_devsel_ox; r.right  -= g_devsel_ox;
            r.top    -= g_devsel_oy; r.bottom -= g_devsel_oy;
            /* The first few, before and after. This is the measurement that proves
             * the diagnosis as well as the fix: if the incoming rects are not the
             * off-surface ones 118.14 predicts, the theory was wrong and the log
             * says so rather than quietly succeeding for another reason. */
            if (g_devsel_logged < 3) {
                logf_("  [devsel] Blt dst (%ld,%ld)-(%ld,%ld) -> (%ld,%ld)-(%ld,%ld)",
                      dst->left, dst->top, dst->right, dst->bottom,
                      r.left, r.top, r.right, r.bottom);
                if (++g_devsel_logged == 3)
                    logf_("  [devsel] (further translations not logged)");
            }
            dst = &r;
        }
    }
    return g_real_blt(self, dst, src, srcr, flags, fx);
}

/* Which surface the per-frame Blt will be aimed at -- the one thing both consumers
 * need from CreateSurface. The descriptor is forwarded EXACTLY as the game wrote
 * it and the surface that comes back is the game's own; all this does is remember
 * it and hook Blt on it, once. s117 then counts on it, s118.14 translates on it,
 * and with both off it is never hooked at all. */
static HRESULT WINAPI hook_CreateSurface(IDirectDraw7 *self, DDSURFACEDESC2 *desc,
                                         IDirectDrawSurface7 **out, IUnknown *unk)
{
    DDSURFACEDESC2 sd;
    HRESULT hr = g_real_cs(self, desc, out, unk);

    if ((!g_fc && !g_devsel_xlate) || g_fc_primary || hr != DD_OK || !desc || !out || !*out)
        return hr;
    if (!(desc->dwFlags & DDSD_CAPS) || !(desc->ddsCaps.dwCaps & DDSCAPS_PRIMARYSURFACE))
        return hr;

    g_fc_primary = *out;
    memset(&sd, 0, sizeof sd); sd.dwSize = sizeof sd;
    if (IDirectDrawSurface7_GetSurfaceDesc(*out, &sd) == DD_OK) {
        g_fc_w   = sd.dwWidth;
        g_fc_h   = sd.dwHeight;
        g_fc_bpp = sd.ddpfPixelFormat.dwRGBBitCount;
    }
    /* &lpVtbl->Blt, not vt[5]: the member is checked by the compiler against
     * ddraw.h, an index is a number I could miscount, and a wrong one would corrupt
     * an unrelated method. */
    if (hook_slot((void **)&(*out)->lpVtbl->Blt, (void *)hook_Blt, (void **)&g_real_blt)) {
        if (g_fc)
            logf_("[+] [fps] counting frames on the primary %lux%lu %lubpp (%p)."
                  " A report follows every %d s.",
                  (unsigned long)g_fc_w, (unsigned long)g_fc_h,
                  (unsigned long)g_fc_bpp, (void *)*out, g_fc_interval);
        if (g_devsel_xlate)
            logf_("[+] [devsel] Blt hooked on the primary surface %lux%lu (%p) --"
                  " destinations will be translated into it.",
                  (unsigned long)g_fc_w, (unsigned long)g_fc_h, (void *)*out);
    } else {
        logf_("[x] [fps/devsel] could not hook Blt. Frame counting is off, and if"
              " DeviceSelect is on the game will blit outside its surface and show"
              " DirectDraw error #150 -- set [Display] DeviceSelect=0.");
        g_fc = 0;
        g_devsel_xlate = 0;
    }
    return hr;
}

/* Attach to the IDirectDraw7 the moment it is created, which is the only moment it
 * can be reached -- the game keeps it in a global at 0x61c80c and never hands it to
 * anyone. ONE method is patched, and only to learn which surface is the primary.
 * The cooperative level and both mode calls stay the game's own. */
static void dd_attach(IDirectDraw7 *dd)
{
    if ((!g_fc && !g_devsel_xlate) || !dd || g_real_cs) return;

    /* By member, not by index -- see the note in hook_CreateSurface. */
    if (!hook_slot((void **)&dd->lpVtbl->CreateSurface, (void *)hook_CreateSurface,
                   (void **)&g_real_cs)) {
        logf_("[x] [fps/devsel] could not patch IDirectDraw7::CreateSurface --"
              " frame counting is OFF, and so is the DeviceSelect translation");
        g_fc = 0;
        g_devsel_xlate = 0;
        return;
    }
    logf_("[*] [dd] IDirectDraw7::CreateSurface hooked, to find the primary."
          " Nothing else is intercepted -- the cooperative level and both mode"
          " calls are forwarded untouched.");
}

static HMODULE WINAPI hook_LoadLibraryA(LPCSTR name)
{
    HMODULE m = g_ddp_loadlib(name);
    if (name && ddp_names_ddraw(name)) {
        g_ddp_mod = m;
        logf_("[ddprobe] LoadLibraryA(\"%s\") from %p -> %p", name, DDP_CALLER(), (void *)m);
    }
    return m;
}

static FARPROC WINAPI hook_GetProcAddress(HMODULE mod, LPCSTR name)
{
    FARPROC p = g_ddp_getproc(mod, name);
    /* HIWORD==0 means an ordinal, not a string -- dereferencing it as a name is
     * the classic way to turn a probe into a crash. */
    if (!name || !((ULONG_PTR)name >> 16)) return p;

    if (mod != g_ddp_mod) {
        /* Not the module LoadLibraryA reported -- but a name beginning
         * "DirectDraw" is worth catching anyway. It means ddraw arrived by a
         * route this hook did not see (LoadLibraryW, GetModuleHandle, a handle
         * cached before we installed), and a probe that stayed quiet there would
         * report "the game never resolved DirectDrawCreate" when it had. That is
         * the s113.6 failure shape: a silent path read as a negative result. */
        if (strncmp(name, "DirectDraw", 10)) return p;
        logf_("[ddprobe] GetProcAddress(module %p, \"%s\") from %p -> %p"
              "   -- NOT the module LoadLibraryA reported (%p); adopting it",
              (void *)mod, name, DDP_CALLER(), (void *)p, (void *)g_ddp_mod);
        g_ddp_mod = mod;
    } else {
        logf_("[ddprobe] GetProcAddress(ddraw, \"%s\") from %p -> %p",
              name, DDP_CALLER(), (void *)p);
    }
    if (!p) return p;

    if (!strcmp(name, "DirectDrawCreate")) {
        g_ddp_real_create = (ddc_t)(void *)p;
        return (FARPROC)(void *)ddp_create;
    }
    if (!strcmp(name, "DirectDrawCreateEx")) {
        g_ddp_real_createex = (ddcex_t)(void *)p;
        return (FARPROC)(void *)ddp_createex;
    }
    if (!strcmp(name, "DirectDrawEnumerateExA")) {
        g_ddp_real_enumex = (ddenumex_t)(void *)p;
        return (FARPROC)(void *)ddp_enumex;
    }
    return p;
}

static BOOL WINAPI hook_FreeLibrary(HMODULE mod)
{
    if (mod && mod == g_ddp_mod)
        logf_("[ddprobe] FreeLibrary(ddraw %p) from %p", (void *)mod, DDP_CALLER());
    return g_ddp_freelib(mod);
}

static void maybe_install_ddprobe(void)
{
    char ip[MAX_PATH];
    snprintf(ip, sizeof ip, "%s\\tropico-fix.ini", g_dir);
    g_ddp_enable = GetPrivateProfileIntA("DDProbe", "Enable", 0, ip);
    /* s118 rides it too, and for it the interception is not a probe but the whole
     * feature: DirectDrawCreateEx is where the device GUID is chosen, and this is
     * the only code that sees the call. Read here rather than from g_devsel,
     * because maybe_install_ddprobe() runs BEFORE choose_monitor() sets that --
     * the hook has to exist before the game resolves anything. */
    /* DEFAULT ON since s118.15's green run. It costs nothing when there is nothing
     * to do -- one monitor returns early, and launching from the primary finds no
     * device to substitute -- and its failure mode is bounded: an unresolvable
     * monitor leaves the game on the primary and says so. */
    g_devsel = GetPrivateProfileIntA("Display", "DeviceSelect", 1, ip);
    if (g_devsel && running_under_wine()) {
        /* Explicit or defaulted? Now that the default is 1, warning unconditionally
         * would put a [!] line in EVERY Linux log about a key nobody set. Only the
         * player who actually asked for this is owed an explanation; for everyone
         * else it is not applicable, and the xrandr path already says what it did. */
        char e[16];
        GetPrivateProfileStringA("Display", "DeviceSelect", "", e, sizeof e, ip);
        if (e[0])
            logf_("[!] [devsel] DeviceSelect=%s, but this is Wine -- it reports ONE"
                  " adapter GUID for every head (FINDINGS 114.3), so there is nothing"
                  " to substitute. The monitor is chosen the way it always has been"
                  " here; nothing is lost by leaving this set.", e);
        g_devsel = 0;
    }
    /* s117 rides the same GetProcAddress interception, because this is the code that
     * sees the IDirectDraw7 being created and the game hands it to no one else. */
    g_fc = GetPrivateProfileIntA("FrameCount", "Enable", 0, ip);
    g_fc_interval = GetPrivateProfileIntA("FrameCount", "Interval", 5, ip);
    if (g_fc_interval < 1) g_fc_interval = 1;
    if (g_fc)
        logf_("[*] [fps] frame counting armed, reporting every %d s. It intercepts"
              " nothing the game relies on; Blt is forwarded untouched.", g_fc_interval);
    if (!g_ddp_enable && !g_fc && !g_devsel) return;

    if (!hook_import("KERNEL32.dll", "LoadLibraryA", (void *)hook_LoadLibraryA,
                     (void **)&g_ddp_loadlib))
        logf_("[x] [ddprobe] KERNEL32!LoadLibraryA not in the import table");
    if (!hook_import("KERNEL32.dll", "GetProcAddress", (void *)hook_GetProcAddress,
                     (void **)&g_ddp_getproc))
        logf_("[x] [ddprobe] KERNEL32!GetProcAddress not in the import table");
    if (!hook_import("KERNEL32.dll", "FreeLibrary", (void *)hook_FreeLibrary,
                     (void **)&g_ddp_freelib))
        logf_("[x] [ddprobe] KERNEL32!FreeLibrary not in the import table");
    if (g_ddp_loadlib && g_ddp_getproc)
        logf_("[*] [ddprobe] armed -- logging how the game obtains DirectDraw."
              " It changes nothing; every wrapper forwards.");
}

/* The message stream, s89 round 3.
 *
 * Round 2 measured GetCursorPos and found it CORRECT -- and the drift continued
 * through a million calls with no bad sample in them. So the position the game
 * polls is not what pans the map. The remaining input path is the message queue:
 * the game imports SetCapture/ScreenToClient/GetClientRect, which is the shape of
 * a WM_MOUSEMOVE consumer, and the map only creeps WHILE THE MOUSE MOVES -- i.e.
 * while messages are being delivered.
 *
 * So log the two streams side by side at the same instant: the client coordinate
 * carried in the message, the screen coordinate the window manager stamped on it
 * (GetMessagePos), and what GetCursorPos says right now. If the layout offset is
 * reaching the game at all, it is one of the first two disagreeing with the third.
 *
 * WH_GETMESSAGE sees what the loop pulls; WH_CALLWNDPROC sees what is sent past
 * the queue. Both, because "the game never reads this message" and "the message
 * carries a good value" look identical from one of them alone. */
static HHOOK g_msg_hook, g_snd_hook;
static LONG  g_msg_logged;
static DWORD g_msg_last_ms;

static void log_mouse(const char *where, HWND w, UINT msg, LPARAM lp)
{
    DWORD mp;
    POINT now;
    RECT wr;
    short cx, cy;
    if (msg != WM_MOUSEMOVE && msg != WM_NCMOUSEMOVE) return;
    /* First 40 unconditionally -- the burst right after a movement starts is the
     * interesting part -- then one a second so a long session stays readable. */
    if (g_msg_logged >= 40) {
        DWORD t = GetTickCount();
        if (t - g_msg_last_ms < 1000) return;
        g_msg_last_ms = t;
    }
    if (g_msg_logged >= 140) return;
    InterlockedIncrement(&g_msg_logged);
    cx = (short)LOWORD(lp);
    cy = (short)HIWORD(lp);
    mp = GetMessagePos();
    now.x = now.y = -1;
    if (g_real_gcp) g_real_gcp(&now);
    memset(&wr, 0, sizeof wr);
    if (w) GetWindowRect(w, &wr);
    logf_("[*] [mouse] %-9s %-14s lParam %d,%d | GetMessagePos %d,%d |"
          " GetCursorPos %ld,%ld | hwnd %p at %ld,%ld",
          where, msg == WM_MOUSEMOVE ? "WM_MOUSEMOVE" : "WM_NCMOUSEMOVE",
          cx, cy, (int)(short)LOWORD(mp), (int)(short)HIWORD(mp),
          now.x, now.y, (void *)w, wr.left, wr.top);
}

static LRESULT CALLBACK getmsg_proc(int code, WPARAM wp, LPARAM lp)
{
    if (code == HC_ACTION && lp) {
        MSG *m = (MSG *)lp;
        log_mouse("queue", m->hwnd, m->message, m->lParam);
    }
    return CallNextHookEx(g_msg_hook, code, wp, lp);
}

static LRESULT CALLBACK callwnd_proc(int code, WPARAM wp, LPARAM lp)
{
    if (code == HC_ACTION && lp) {
        CWPSTRUCT *c = (CWPSTRUCT *)lp;
        log_mouse("sent", c->hwnd, c->message, c->lParam);
    }
    return CallNextHookEx(g_snd_hook, code, wp, lp);
}

static void install_msg_probe(void)
{
    DWORD tid = GetCurrentThreadId();
    g_msg_hook = SetWindowsHookExA(WH_GETMESSAGE, getmsg_proc, NULL, tid);
    g_snd_hook = SetWindowsHookExA(WH_CALLWNDPROC, callwnd_proc, NULL, tid);
    logf_("[*] [mouse] message probe on thread %lu: queue hook %s, sent hook %s",
          (unsigned long)tid, g_msg_hook ? "ok" : "FAILED",
          g_snd_hook ? "ok" : "FAILED");
    if (!g_msg_hook && !g_snd_hook)
        logf_("[x] [mouse] neither hook installed -- this probe measured NOTHING."
              " Do not read the absence of [mouse] lines as 'no mouse messages'.");
}

/* --------------------------------------------------- s90: can we reach Linux?
 *
 * Steam's Play button is the only way past this build's DRM, so tools/tropico is
 * out of the launch path and nothing sets the primary monitor for the run -- which
 * is what produces DirectDraw #150 on a second monitor (s74). If a Windows process
 * under Proton can execute a HOST binary, the proxy can do that job itself: xrandr
 * for the monitor, and the EWMH helper for fullscreen. Nothing pasted into Steam,
 * nothing of Valve's touched.
 *
 * Unknown, and not answerable from documentation: Proton runs inside a
 * pressure-vessel container, so both "can it exec" and "does the binary even exist
 * in that namespace" are open. So probe both, separately, and prove the result
 * OUTSIDE the process -- each route touches a file in the game directory, which is
 * bind-mounted and therefore visible to the host. A log line saying CreateProcess
 * returned success proves only that Wine accepted the request. The file proves the
 * binary ran. */
static void run_route(const char *what, char *cmd)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD code = 0xffffffff;
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    memset(&pi, 0, sizeof pi);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        logf_("  [unix] %-12s CreateProcess FAILED (%lu) -- %s",
              what, (unsigned long)GetLastError(), cmd);
        return;
    }
    WaitForSingleObject(pi.hProcess, 5000);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    logf_("  [unix] %-12s started, exit code %lu -- %s", what, (unsigned long)code, cmd);
}

/* --------------------------------------------- s90: the monitor, from inside
 *
 * Measured: a Windows process under Proton CAN execute host binaries through
 * `start.exe /unix`, and xrandr run that way sees the real display -- both outputs,
 * their modes and their positions, on DISPLAY=:1. So the proxy can do for the Steam
 * edition what tools/tropico does for GOG: make the monitor the game will run on the
 * PRIMARY one, because Wine measures only the primary and a game sized for another
 * screen dies with DirectDraw #150 (s74).
 *
 * Deliberately conservative. Changing the primary output moves the user's panels and
 * icons for the duration of the game, so it happens ONLY when the primary's current
 * mode does not match the art this install was built for AND another output does
 * match. On one monitor, or when the primary is already the play monitor, nothing is
 * touched and nothing is logged beyond saying so.
 *
 * Restoring is the hard half: a crash must not leave someone's desktop rearranged.
 * A Windows-side "restore on exit" cannot survive a crash by definition, so the
 * restore runs on the HOST: a detached shell watches a marker file that this process
 * rewrites every two seconds, and puts the primary back when the heartbeat stops for
 * ten -- whether that is a clean exit, a crash, or a kill. */
static char g_xr_prev[64];
static DWORD g_launch_w, g_launch_h;   /* mode adopted from the launch monitor */
static char g_xr_marker_win[MAX_PATH];
static char g_xr_marker_unix[MAX_PATH];

/* The game directory as the host sees it. Z: is the host root, so this is g_dir
 * without the drive and with the slashes turned round. */
static int game_unix_dir(char *out, size_t cap)
{
    const char *r = g_dir + 2;
    size_t n = 0;
    if (!((g_dir[0] == 'Z' || g_dir[0] == 'z') && g_dir[1] == ':')) return 0;
    while (*r && n < cap - 1) { out[n++] = (*r == '\\') ? '/' : *r; r++; }
    out[n] = 0;
    return 1;
}

/* start.exe /unix /bin/sh -c "..." -- the only route that works. CreateProcess on a
 * Z: path returns ERROR_BAD_EXE_FORMAT, and `start /unix` execs the binary directly
 * with no shell, so anything needing redirection or a loop has to go through sh. */
/* Write a file beside the game. Used for the host-side helper scripts: the payload
 * must never travel on a command line (see unix_sh). */
static int write_host_file(const char *leaf, const char *body)
{
    char win[MAX_PATH];
    HANDLE h;
    DWORD wrote;
    snprintf(win, sizeof win, "%s\\%s", g_dir, leaf);
    h = CreateFileA(win, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    WriteFile(h, body, (DWORD)strlen(body), &wrote, NULL);
    CloseHandle(h);
    return 1;
}

/* s90.3: ask X where the pointer is, not Wine.
 *
 * GetCursorPos returns 0,0 at this point in startup -- Wine has no pointer state
 * before the game has a window -- and 0,0 maps inside the primary monitor whatever
 * the layout, so the launch-monitor detector always answered "the primary". It looked
 * correct whenever the primary WAS the launch monitor, which is exactly the case that
 * needs no detection. (Same shape as the s89 zero samples: an in-band value that is
 * indistinguishable from a real answer.)
 *
 * XQueryPointer has no such ambiguity and reports ROOT coordinates -- the same space
 * xrandr reports output positions in -- so no conversion is needed either. */
static const char POINTER_PY[] =
    /* s111: XQueryPointer is DEAD ON WAYLAND. XWayland is only sent pointer events
     * while the pointer is over an XWayland surface, so once it moves onto a native
     * Wayland window it reports the last position it ever saw -- measured on COSMIC as
     * twelve identical samples in six seconds with child=0, naming the wrong monitor.
     * Worse, it is self-reinforcing here: the game window IS an XWayland surface, so a
     * wrong launch parks one under the stale coordinate and confirms it next time.
     *
     * So ask the compositor something it can answer: map a 1x1 window with no position
     * hint and read where it was placed. That is the same rule the game window will be
     * placed by. Measured with the pointer on the 1080p monitor: XQueryPointer said
     * 3217,624 (DP-3, wrong), placement said 960,531 (HDMI-A-5, right), in 50 ms.
     *
     * Pointer first on X11, where it IS authoritative and window placement is not --
     * plenty of X11 window managers cascade rather than placing under the pointer.
     *
     * The Wayland test does not trust the environment to have survived Wine and
     * start.exe: a wayland-* socket in XDG_RUNTIME_DIR settles it either way. */
    "import ctypes, ctypes.util, os, glob, time\n"
    "lib = ctypes.util.find_library('X11')\n"
    "x = ctypes.CDLL(lib)\n"
    "x.XOpenDisplay.restype = ctypes.c_void_p\n"
    "x.XDefaultRootWindow.restype = ctypes.c_ulong\n"
    "x.XDefaultRootWindow.argtypes = [ctypes.c_void_p]\n"
    "x.XCreateSimpleWindow.restype = ctypes.c_ulong\n"
    "x.XCreateSimpleWindow.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int,\n"
    "    ctypes.c_int, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, ctypes.c_ulong,\n"
    "    ctypes.c_ulong]\n"
    "d = x.XOpenDisplay(None)\n"
    "r = x.XDefaultRootWindow(ctypes.c_void_p(d))\n"
    "def ptr():\n"
    "    rr = ctypes.c_ulong(); cr = ctypes.c_ulong()\n"
    "    rx = ctypes.c_int(); ry = ctypes.c_int()\n"
    "    wx = ctypes.c_int(); wy = ctypes.c_int(); mk = ctypes.c_uint()\n"
    "    if not x.XQueryPointer(ctypes.c_void_p(d), ctypes.c_ulong(r), ctypes.byref(rr),\n"
    "                           ctypes.byref(cr), ctypes.byref(rx), ctypes.byref(ry),\n"
    "                           ctypes.byref(wx), ctypes.byref(wy), ctypes.byref(mk)):\n"
    "        return None\n"
    "    return (rx.value, ry.value)\n"
    "def place():\n"
    "    w = x.XCreateSimpleWindow(ctypes.c_void_p(d), ctypes.c_ulong(r), 0, 0, 1, 1, 0, 0, 0)\n"
    "    if not w:\n"
    "        return None\n"
    "    x.XMapWindow(ctypes.c_void_p(d), ctypes.c_ulong(w))\n"
    "    x.XFlush(ctypes.c_void_p(d))\n"
    "    got = None\n"
    "    for i in range(30):\n"
    "        time.sleep(0.05)\n"
    "        ax = ctypes.c_int(); ay = ctypes.c_int(); ch = ctypes.c_ulong()\n"
    "        if x.XTranslateCoordinates(ctypes.c_void_p(d), ctypes.c_ulong(w),\n"
    "                                   ctypes.c_ulong(r), 0, 0, ctypes.byref(ax),\n"
    "                                   ctypes.byref(ay), ctypes.byref(ch)):\n"
    "            if (ax.value, ay.value) != (0, 0):\n"
    "                got = (ax.value, ay.value); break\n"
    "    x.XDestroyWindow(ctypes.c_void_p(d), ctypes.c_ulong(w))\n"
    "    x.XFlush(ctypes.c_void_p(d))\n"
    "    return got\n"
    "rt = os.environ.get('XDG_RUNTIME_DIR') or ('/run/user/%d' % os.getuid())\n"
    "wl = bool(os.environ.get('WAYLAND_DISPLAY')) or \\\n"
    "     os.environ.get('XDG_SESSION_TYPE', '').lower() == 'wayland' or \\\n"
    "     bool(glob.glob(os.path.join(rt, 'wayland-*')))\n"
    "order = [('placement', place), ('pointer', ptr)] if wl else \\\n"
    "        [('pointer', ptr), ('placement', place)]\n"
    "for nm, fn in order:\n"
    "    try:\n"
    "        g = fn()\n"
    "    except Exception:\n"
    "        g = None\n"
    "    if g:\n"
    "        print('POINTER %d %d %s' % (g[0], g[1], nm)); break\n";

static int unix_sh(const char *script, int wait_ms)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char cmd[MAX_PATH * 2], win[MAX_PATH], udir[MAX_PATH], body[MAX_PATH * 4];
    static LONG seq;
    LONG n = InterlockedIncrement(&seq);
    HANDLE h;
    DWORD wrote;

    if (!game_unix_dir(udir, sizeof udir)) return 0;
    /* The script goes in a FILE, not on the command line. Wine's start.exe splits a
     * quoted `sh -c "..."` argument on spaces and tries to open each word as a
     * document, which is where the "No file found" dialogs came from -- one per word.
     * `sh <path>` is two arguments with no quoting, and the script deletes itself. */
    snprintf(win, sizeof win, "%s\\tropico-host-%ld.sh", g_dir, (long)n);
    snprintf(body, sizeof body, "#!/bin/sh\n%s\nrm -f \"$0\"\n", script);
    h = CreateFileA(win, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    WriteFile(h, body, (DWORD)strlen(body), &wrote, NULL);
    CloseHandle(h);

    memset(&si, 0, sizeof si); si.cb = sizeof si;
    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    memset(&pi, 0, sizeof pi);

    /* NOT start.exe. It ran the script correctly but popped one dialog per argument
     * word first ("No file found"), which is worse than useless in front of a player.
     * CreateProcess on the Unix binary itself skips it: Wine execs the ELF and then
     * returns ERROR_BAD_EXE_FORMAT because it cannot produce a Windows process object
     * for it. Measured in the s90 probe -- the touch marker appeared on disk from the
     * call that "failed". So the error is expected and is not evidence of anything;
     * the caller polls for the script's OUTPUT instead of trusting a return code. */
    snprintf(cmd, sizeof cmd, "\"Z:\\bin\\sh\" \"%s/tropico-host-%ld.sh\"", udir, (long)n);
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                       NULL, NULL, &si, &pi)) {
        if (wait_ms) WaitForSingleObject(pi.hProcess, wait_ms);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    } else if (wait_ms) {
        /* The usual path: exec happened, no handle to wait on. Give it a moment. */
        Sleep(wait_ms > 1200 ? 1200 : wait_ms);
    }
    return 1;
}

/* Run xrandr --query into a file beside the game and read it back. */
static int xrandr_query(char *buf, DWORD cap)
{
    char udir[MAX_PATH], script[MAX_PATH * 3], win[MAX_PATH];
    HANDLE h;
    DWORD got = 0;
    int i;
    if (!game_unix_dir(udir, sizeof udir)) return 0;
    snprintf(win, sizeof win, "%s\\tropico-xrandr.txt", g_dir);
    DeleteFileA(win);
    write_host_file("tropico-pointer.py", POINTER_PY);
    snprintf(script, sizeof script,
             "/usr/bin/xrandr --query > '%s/tropico-xrandr.txt' 2>&1\n"
             "/usr/bin/python3 '%s/tropico-pointer.py' >> '%s/tropico-xrandr.txt' 2>&1\n",
             udir, udir, udir);
    if (!unix_sh(script, 4000)) return 0;
    /* start.exe returns before the child finishes, so the file can lag the call. */
    for (i = 0; i < 20; i++) {
        h = CreateFileA(win, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            ReadFile(h, buf, cap - 1, &got, NULL);
            CloseHandle(h);
            if (got) break;
        }
        Sleep(100);
    }
    if (!got) return 0;
    buf[got] = 0;
    return 1;
}

static DWORD WINAPI heartbeat_thread(LPVOID p)
{
    (void)p;
    for (;;) {
        HANDLE h = CreateFileA(g_xr_marker_win, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD wrote;
            WriteFile(h, "alive\n", 6, &wrote, NULL);
            CloseHandle(h);
        }
        Sleep(2000);
    }
}

/* Everything xrandr told us about one output. */
typedef struct { char name[64]; int primary; DWORD w, h; long x, y; } xout_t;

static long g_ptr_x = -1, g_ptr_y = -1;   /* root coords, from the host helper */
static char g_ptr_how[16] = "";           /* s111: which method answered      */

static int xrandr_outputs(xout_t *out, int cap)
{
    char buf[16384], line[512];
    const char *b;
    size_t li = 0;
    int n = 0;
    if (!xrandr_query(buf, sizeof buf)) return 0;
    for (b = buf; ; b++) {
        if (*b && *b != '\n' && li < sizeof line - 1) { line[li++] = *b; continue; }
        line[li] = 0; li = 0;
        if (!strncmp(line, "POINTER ", 8)) {
            long qx, qy;
            char how[16];
            /* The third field is which method answered (s111). Optional, so an older
             * helper still parses -- but a report that does not say whether the answer
             * came from the pointer or from window placement cannot be diagnosed. */
            if (sscanf(line + 8, "%ld %ld %15s", &qx, &qy, how) >= 2) {
                g_ptr_x = qx; g_ptr_y = qy;
                if (sscanf(line + 8, "%ld %ld %15s", &qx, &qy, how) == 3)
                    snprintf(g_ptr_how, sizeof g_ptr_how, "%s", how);
            }
        }
        if (line[0] && line[0] != ' ' && line[0] != '\t' && n < cap) {
            xout_t o;
            const char *p = line;
            size_t k = 0;
            unsigned uw, uh; int ix, iy;
            memset(&o, 0, sizeof o);
            while (*p && *p != ' ' && k < sizeof o.name - 1) o.name[k++] = *p++;
            o.name[k] = 0;
            if (!strncmp(p, " connected", 10)) {
                p += 10;
                o.primary = (strncmp(p, " primary", 8) == 0);
                if (o.primary) p += 8;
                if (*p == ' ' && sscanf(p + 1, "%ux%u+%d+%d", &uw, &uh, &ix, &iy) == 4) {
                    o.w = uw; o.h = uh; o.x = ix; o.y = iy;
                    out[n++] = o;
                }
            }
        }
        if (!*b) break;
    }
    return n;
}

/* ------------------------------------------- s113 the same list, from Win32
 *
 * WHY THIS HAS TO EXIST. Everything above reads the display by shelling out to
 * xrandr through unix_sh, and unix_sh goes through game_unix_dir, which refuses
 * any game folder not on Z:. On a real C:\ install that is every call, so on
 * native Windows choose_monitor() has always stopped at "could not read the
 * display from the host" with g_launch_w unset -- and what is left after that is
 * primary-only in three separate places: pick_mode_pass enumerates
 * EnumDisplaySettings(NULL), its fit gate is SM_CXSCREEN, and
 * pin_window_to_primary drags the window back onto the primary. A player with two
 * monitors could not launch on the second one at all. Reported on the first
 * native-Windows run: a 1080p screen beside a 1440p primary, and the game would
 * only ever open on the 1440p one.
 *
 * The Win32 view carries exactly what the xrandr parse carries -- a name, a
 * primary flag, a size and a position -- so it fills the same struct and every
 * line of the decision below is shared rather than duplicated. dmPosition is in
 * virtual-screen coordinates with the primary at (0,0), which is the convention
 * xrandr_outputs() already reports, so choose_monitor()'s pointer arithmetic needs
 * no case of its own.
 *
 * XRANDR STAYS FIRST WHERE IT ANSWERS. Under Wine the Win32 view is the thing
 * FINDINGS 74 is about -- Wine measures only the primary and renormalises the rest
 * to negative coordinates -- which is why the launcher asks X directly. This is a
 * fallback for the platform with no host to ask, not a replacement, and on Linux
 * nothing reaches it.
 */
static int win32_outputs(xout_t *out, int cap)
{
    DISPLAY_DEVICEA dd;
    DEVMODEA dm;
    DWORD i;
    int n = 0;
    for (i = 0; n < cap; i++) {
        memset(&dd, 0, sizeof dd); dd.cb = sizeof dd;
        if (!EnumDisplayDevicesA(NULL, i, &dd, 0)) break;
        /* ATTACHED, not merely present. A disconnected output still enumerates,
         * and it has no rectangle for a pointer to be inside of. */
        if (!(dd.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP)) continue;
        memset(&dm, 0, sizeof dm); dm.dmSize = sizeof dm;
        if (!EnumDisplaySettingsA(dd.DeviceName, ENUM_CURRENT_SETTINGS, &dm)) continue;
        if (!dm.dmPelsWidth || !dm.dmPelsHeight) continue;
        memset(&out[n], 0, sizeof out[n]);
        snprintf(out[n].name, sizeof out[n].name, "%s", dd.DeviceName);
        out[n].primary = (dd.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE) != 0;
        out[n].w = dm.dmPelsWidth;
        out[n].h = dm.dmPelsHeight;
        out[n].x = dm.dmPosition.x;
        out[n].y = dm.dmPosition.y;
        n++;
    }
    return n;
}

/* s118.10: WHICH MONITOR WAS THIS LAUNCHED FROM, on Windows.
 *
 * s77 settled this on Linux and the answer was not the pointer: "the mouse can sit
 * on a monitor holding no focus -- move it across without clicking and it points at
 * a screen the desktop is ignoring." tools/tropico-launchpoint.py reads
 * _NET_ACTIVE_WINDOW and falls back to the pointer. That conclusion never reached
 * the Windows path, which used GetCursorPos alone.
 *
 * This is the same idea in Win32 terms. At DllMain the game has no window yet, so
 * the foreground window is still whatever launched us -- Steam, Explorer, a
 * shortcut's owner -- which is the click itself rather than an inference from where
 * the mouse drifted to afterwards.
 *
 * Both signals are reported by name in the log, because "it opened on the wrong
 * screen" is only diagnosable if you know which signal answered. */
static int win32_launch_point(long *px, long *py, char *how, size_t howcap)
{
    HWND fg;
    RECT r;
    POINT pt;

    fg = GetForegroundWindow();
    if (fg && !IsIconic(fg) && GetWindowRect(fg, &r) &&
        r.right > r.left && r.bottom > r.top) {
        *px = r.left + (r.right - r.left) / 2;
        *py = r.top  + (r.bottom - r.top)  / 2;
        snprintf(how, howcap, "the focused window");
        return 1;
    }
    /* No foreground window is a real state -- launched from a service, or the shell
     * lost focus -- and the pointer is the honest fallback, exactly as on Linux. */
    if (GetCursorPos(&pt) && (pt.x || pt.y)) {
        *px = pt.x; *py = pt.y;
        snprintf(how, howcap, "the mouse pointer");
        return 1;
    }
    return 0;
}

/* ------------------------------------- s113 putting the primary back afterwards
 *
 * The Linux side leaves a HOST WATCHDOG behind: a shell loop outside the process
 * that polls a heartbeat file and runs `xrandr --primary` again when it goes
 * stale -- "crash included", as apply_monitor() puts it. Native Windows has
 * nothing to leave behind. This package ships no helper executable and is not
 * going to start, so the same guarantee is assembled from two weaker pieces:
 *
 *   THE WATCHER      restores as soon as the game's window is gone, on an
 *                    ordinary thread. The one place this must NOT happen is
 *                    DllMain's DLL_PROCESS_DETACH: ChangeDisplaySettingsEx
 *                    broadcasts WM_DISPLAYCHANGE, and doing that under the loader
 *                    lock with every other thread already dead risks a process
 *                    that will not exit. A desktop on the wrong primary is
 *                    annoying and fixable; a game that will not close is neither.
 *
 *   THE STATE FILE   outlives the process. If a run is killed before the watcher
 *                    gets there, the next launch reads tropico-primary.state and
 *                    knows which monitor was really the player's -- so it restores
 *                    to THAT, and never mistakes its own leftover for a choice.
 *
 * The gap between them is real and worth stating plainly rather than hiding: kill
 * the game outright and the primary stays on the game's monitor until Tropico is
 * started again, or until the player changes it back in Display settings.
 *
 * [Display] SetPrimary=0 switches all of it off, and has since s90.
 */
static void primary_state_path(char *out, size_t cap)
{
    snprintf(out, cap, "%s\\tropico-primary.state", g_dir);
}

static void load_primary_state(void)
{
    char path[MAX_PATH], line[128];
    unsigned w = 0, h = 0;
    FILE *f;
    primary_state_path(path, sizeof path);
    f = fopen(path, "rb");
    if (!f) return;
    if (fgets(line, sizeof line, f)) {
        size_t k = strlen(line);
        while (k && (line[k - 1] == '\n' || line[k - 1] == '\r')) line[--k] = 0;
        if (line[0]) snprintf(g_prev_primary, sizeof g_prev_primary, "%s", line);
    }
    if (fgets(line, sizeof line, f) && sscanf(line, "%ux%u", &w, &h) == 2) {
        g_prev_primary_w = w; g_prev_primary_h = h;
    }
    fclose(f);
}

static void write_primary_state(void)
{
    char path[MAX_PATH];
    FILE *f;
    primary_state_path(path, sizeof path);
    f = fopen(path, "wb");
    if (!f) {
        logf_("[!] [display] could not write tropico-primary.state -- the primary will"
              " still be put back when the game closes, but a crash before that would"
              " leave it on the game's monitor");
        return;
    }
    fprintf(f, "%s\n%lux%lu\n", g_prev_primary,
            (unsigned long)g_prev_primary_w, (unsigned long)g_prev_primary_h);
    fclose(f);
}

static void clear_primary_state(void)
{
    char path[MAX_PATH];
    primary_state_path(path, sizeof path);
    DeleteFileA(path);
}

/* Name the refusal. A bare -1 in a log is a number the player cannot act on and
 * that nobody remembers the meaning of a month later. */
static const char *cds_name(LONG r)
{
    switch (r) {
    case DISP_CHANGE_SUCCESSFUL:  return "SUCCESSFUL";
    case DISP_CHANGE_RESTART:     return "RESTART -- the change needs a reboot";
    case DISP_CHANGE_FAILED:      return "FAILED -- the display driver refused it";
    case DISP_CHANGE_BADMODE:     return "BADMODE -- that mode is not supported";
    case DISP_CHANGE_NOTUPDATED:  return "NOTUPDATED -- could not write it to the registry";
    case DISP_CHANGE_BADFLAGS:    return "BADFLAGS";
    case DISP_CHANGE_BADPARAM:    return "BADPARAM";
    case DISP_CHANGE_BADDUALVIEW: return "BADDUALVIEW";
    }
    return "unrecognised";
}

/* Is this device the primary RIGHT NOW -- asked of Windows, not of our own record
 * of what we told it. */
static int is_primary_win32(const char *dev)
{
    DISPLAY_DEVICEA dd;
    DWORD i;
    for (i = 0; ; i++) {
        memset(&dd, 0, sizeof dd); dd.cb = sizeof dd;
        if (!EnumDisplayDevicesA(NULL, i, &dd, 0)) break;
        if (_stricmp(dd.DeviceName, dev)) continue;
        return (dd.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE) != 0;
    }
    return 0;
}

/* Make one display device the primary, keeping the layout.
 *
 * Windows has no "set primary" call. What it has is a rule: the primary is the
 * device at (0,0). So every attached display moves by the negative of the new
 * primary's current position -- which changes the ORIGIN and nothing else, and is
 * why this is exactly reversible: doing it again with the old device restores the
 * old coordinates, not merely an equivalent arrangement.
 *
 * CDS_UPDATEREGISTRY is deliberate, and it is also what makes an interrupted
 * restore harmless: the registry then already holds the layout we were moving
 * TOWARDS, so a run killed between the writes and the apply has still left the
 * player's own arrangement recorded rather than the game's.
 *
 * WHY THERE IS MORE THAN ONE OF THESE (s113.6). The version below marked
 * `baseline` is the sequence MSDN documents, sample and all, and on the owner's
 * Windows 11 24H2 machine it moved nothing while reporting success. That is not a
 * coding error -- NirSoft's MultiMonitorTool shipped a 2.15 release whose notes
 * say "a workaround for the new problems appeared in Windows 11 24H2 update ...
 * Set as primary monitor, /SetPrimary", and its workaround is to apply the
 * configuration more than once. So the mechanism is not something to pick once
 * and trust; it is something to try and then CHECK.
 *
 * `applies` is that workaround reduced to its mechanism. `keep_fields` keeps the
 * dmFields EnumDisplaySettings returned rather than narrowing them to DM_POSITION.
 * `noreset` is the stage-everything-then-apply-once shape; without it each device
 * is applied as it is set, which walks the desktop through intermediate layouts
 * with two primaries or a hole in the middle -- every one of those a mode change
 * the compositor and every running program has to absorb. That is why it is tried
 * LAST and only when the gentler ones have already failed.
 */
static int cds_set_primary(const char *dev, int keep_fields, int noreset, int applies)
{
    DISPLAY_DEVICEA dd;
    DEVMODEA dm;
    LONG tx, ty, r;
    int found = 0, refused = 0, k;
    DWORD i;

    memset(&dm, 0, sizeof dm); dm.dmSize = sizeof dm;
    if (!EnumDisplaySettingsA(dev, ENUM_CURRENT_SETTINGS, &dm)) {
        logf_("[x] [display] EnumDisplaySettings(%s) failed -- there is no position to"
              " move the origin to", dev);
        return 0;
    }
    tx = dm.dmPosition.x; ty = dm.dmPosition.y;

    for (i = 0; ; i++) {
        memset(&dd, 0, sizeof dd); dd.cb = sizeof dd;
        if (!EnumDisplayDevicesA(NULL, i, &dd, 0)) break;
        if (!(dd.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP)) continue;
        memset(&dm, 0, sizeof dm); dm.dmSize = sizeof dm;
        if (!EnumDisplaySettingsA(dd.DeviceName, ENUM_CURRENT_SETTINGS, &dm)) continue;
        dm.dmPosition.x -= tx;
        dm.dmPosition.y -= ty;
        if (keep_fields) dm.dmFields |= DM_POSITION;
        else             dm.dmFields  = DM_POSITION;
        {
            DWORD flags = CDS_UPDATEREGISTRY | (noreset ? CDS_NORESET : 0);
            if (!_stricmp(dd.DeviceName, dev)) { flags |= CDS_SET_PRIMARY; found = 1; }
            /* EVERY RETURN CODE IS READ. Discarding these is what made s113's first
             * Windows run undiagnosable from its own log: the staging calls could all
             * fail and nothing said so. */
            r = ChangeDisplaySettingsExA(dd.DeviceName, &dm, NULL, flags, NULL);
            if (r != DISP_CHANGE_SUCCESSFUL) {
                refused++;
                logf_("      staging %s at (%ld,%ld)%s refused: %ld %s",
                      dd.DeviceName, (long)dm.dmPosition.x, (long)dm.dmPosition.y,
                      (flags & CDS_SET_PRIMARY) ? " as PRIMARY" : "",
                      (long)r, cds_name(r));
            }
        }
    }
    if (!found) {
        logf_("[x] [display] %s is not among the attached devices any more", dev);
        return 0;
    }

    for (k = 0; k < applies; k++) {
        r = ChangeDisplaySettingsExA(NULL, NULL, NULL, 0, NULL);
        if (r != DISP_CHANGE_SUCCESSFUL)
            logf_("      apply #%d returned %ld %s", k + 1, (long)r, cds_name(r));
    }
    if (refused) logf_("      %d staged change(s) refused", refused);
    return is_primary_win32(dev);
}

static int sp_baseline(const char *dev) { return cds_set_primary(dev, 0, 1, 1); }

/* THE OTHER THREE ARE GONE, AND MEASURED (s113.6). probes/primaryprobe.c tried all
 * five on the owner's Windows 11 24H2 machine and the CDS family loses in a way no
 * amount of DEVMODE shaping can rescue: the CDS_SET_PRIMARY call itself returns
 * DISP_CHANGE_FAILED. Widening dmFields did not help, and neither did a second
 * apply -- NirSoft's 2.15 workaround addresses a different symptom, not this one.
 * `applying per device' is the sharpest evidence of all: its staging call returned
 * DISP_CHANGE_SUCCESSFUL and the device STILL did not become primary, which is the
 * same lie the final apply tells and the reason nothing here trusts a return code.
 *
 * The keep_fields/noreset/applies parameters stay on cds_set_primary() because the
 * probe still exercises all four shapes; a machine that answers differently is one
 * probe run away from being understood, and re-deriving them then would be work
 * done twice. */

/* ------------------------------------------------- s113.6 the same job, via CCD
 *
 * QueryDisplayConfig/SetDisplayConfig, Windows 7 and later, and the API Windows'
 * own Display settings page uses to apply "resolution, layout, orientation,
 * scaling, primary, bit depth, and refresh rate". The rule is unchanged -- the
 * primary is still the source at (0,0) -- but the whole topology is submitted as
 * ONE object rather than as a sequence of per-device pokes, which is the part
 * ChangeDisplaySettingsEx appears to have lost on 24H2.
 *
 * Resolved by name rather than imported, so a build of this DLL still loads on a
 * system without these exports, and so Wine's partial implementation degrades to
 * "not available" instead of to a link error.
 */
typedef LONG (WINAPI *ccd_query_t)(UINT32, UINT32 *, DISPLAYCONFIG_PATH_INFO *,
                                   UINT32 *, DISPLAYCONFIG_MODE_INFO *,
                                   DISPLAYCONFIG_TOPOLOGY_ID *);
typedef LONG (WINAPI *ccd_set_t)(UINT32, DISPLAYCONFIG_PATH_INFO *,
                                 UINT32, DISPLAYCONFIG_MODE_INFO *, UINT32);
typedef LONG (WINAPI *ccd_info_t)(DISPLAYCONFIG_DEVICE_INFO_HEADER *);

static int sp_ccd(const char *dev)
{
    HMODULE u32 = GetModuleHandleA("user32.dll");
    ccd_query_t query;
    ccd_set_t   set;
    ccd_info_t  devinfo;
    DISPLAYCONFIG_PATH_INFO paths[32];
    DISPLAYCONFIG_MODE_INFO modes[64];
    UINT32 npaths = 32, nmodes = 64, i;
    LONG r;
    int tx = 0, ty = 0, found = 0;

    query   = (ccd_query_t)(void *)GetProcAddress(u32, "QueryDisplayConfig");
    set     = (ccd_set_t)(void *)GetProcAddress(u32, "SetDisplayConfig");
    devinfo = (ccd_info_t)(void *)GetProcAddress(u32, "DisplayConfigGetDeviceInfo");
    if (!query || !set || !devinfo) {
        logf_("      the CCD entry points are not in this user32 -- skipped");
        return 0;
    }

    r = query(QDC_ONLY_ACTIVE_PATHS, &npaths, paths, &nmodes, modes, NULL);
    if (r != ERROR_SUCCESS) { logf_("      QueryDisplayConfig failed: %ld", (long)r); return 0; }

    /* The GDI name is the only thing tying a CCD source back to the \\.\DISPLAYn
     * every other line of this file speaks in. */
    for (i = 0; i < npaths; i++) {
        DISPLAYCONFIG_SOURCE_DEVICE_NAME sn;
        char gdi[64];
        UINT32 mi;
        memset(&sn, 0, sizeof sn);
        sn.header.type      = DISPLAYCONFIG_DEVICE_INFO_GET_SOURCE_NAME;
        sn.header.size      = sizeof sn;
        sn.header.adapterId = paths[i].sourceInfo.adapterId;
        sn.header.id        = paths[i].sourceInfo.id;
        if (devinfo(&sn.header) != ERROR_SUCCESS) continue;
        WideCharToMultiByte(CP_ACP, 0, sn.viewGdiDeviceName, -1, gdi, sizeof gdi, NULL, NULL);
        if (_stricmp(gdi, dev)) continue;
        mi = paths[i].sourceInfo.modeInfoIdx;
        if (mi < nmodes && modes[mi].infoType == DISPLAYCONFIG_MODE_INFO_TYPE_SOURCE) {
            tx = modes[mi].sourceMode.position.x;
            ty = modes[mi].sourceMode.position.y;
            found = 1;
        }
    }
    if (!found) { logf_("      no CCD source matched %s", dev); return 0; }

    for (i = 0; i < nmodes; i++)
        if (modes[i].infoType == DISPLAYCONFIG_MODE_INFO_TYPE_SOURCE) {
            modes[i].sourceMode.position.x -= tx;
            modes[i].sourceMode.position.y -= ty;
        }

    r = set(npaths, paths, nmodes, modes,
            SDC_USE_SUPPLIED_DISPLAY_CONFIG | SDC_APPLY | SDC_SAVE_TO_DATABASE);
    if (r != ERROR_SUCCESS) logf_("      SetDisplayConfig returned %ld", (long)r);
    return is_primary_win32(dev);
}

/* ------------------------------------------------------ s113.6 try, then CHECK
 *
 * Ordered by "least disruptive that might work" -- the documented sequence first,
 * the per-device-apply one last because it is the one that walks the desktop
 * through broken intermediate layouts on its way.
 *
 * THE ANSWER IS REMEMBERED. Once a mechanism has demonstrably moved the primary
 * on this machine, the restore at window-close uses THAT ONE directly rather than
 * walking the chain again -- a restore that retries four failing mechanisms first
 * would rearrange the desktop several times over while the player watches.
 */
static int running_under_wine(void);   /* defined with the virtual-desktop code */

typedef int (*setprim_fn)(const char *dev);
static const struct { const char *name; setprim_fn fn; } SETPRIM[] = {
    { "SetDisplayConfig",        sp_ccd      },
    { "the documented sequence", sp_baseline },
};
static int g_setprim_pick = -1;

static int set_primary_win32(const char *dev)
{
    int i, n = (int)(sizeof SETPRIM / sizeof SETPRIM[0]);

    /* THE CHAIN IS FOR REAL WINDOWS ONLY, and this has to name the MECHANISM rather
     * than a slot in the table above -- CCD moved to the front when the measurement
     * came in, and a guard that said "the first one" would silently have changed
     * what Wine does. Under Wine this function is reachable only when the xrandr
     * read failed (a game folder off Z:, say); Wine keeps exactly the behaviour it
     * had before s113.6, which is what keeps the Linux path identical in its log
     * (s113.3). */
    if (running_under_wine()) return sp_baseline(dev);

    if (g_setprim_pick >= 0) {
        if (SETPRIM[g_setprim_pick].fn(dev)) return 1;
        logf_("[!] [display] %s worked earlier this run but not now -- trying the"
              " others again", SETPRIM[g_setprim_pick].name);
        g_setprim_pick = -1;
    }

    for (i = 0; i < n; i++) {
        if (SETPRIM[i].fn(dev)) {
            g_setprim_pick = i;
            logf_("[+] [display] %s is primary, via %s%s", dev, SETPRIM[i].name,
                  i ? " -- the documented sequence did not work on this machine" : "");
            return 1;
        }
        logf_("  [display] %s did not make %s primary; trying the next mechanism",
              SETPRIM[i].name, dev);
    }
    logf_("[x] [display] none of the %d mechanisms made %s the primary device."
          " The refusals above are the diagnosis; primaryprobe.exe tests the same"
          " five in isolation.", n, dev);
    return 0;
}

static void restore_primary(const char *why)
{
    if (InterlockedExchange(&g_restore_done, 1)) return;
    if (!g_prev_primary[0]) return;
    if (set_primary_win32(g_prev_primary)) {
        logf_("[+] [display] primary put back to %s (%s); Windows measures %dx%d",
              g_prev_primary, why,
              GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
        clear_primary_state();
    } else {
        logf_("[x] [display] could NOT put the primary back to %s (%s). The state file is"
              " kept on purpose, so the next launch tries again.", g_prev_primary, why);
    }
}

/* --------------------------------------------- s113.7 giving it back, on the way out
 *
 * WHAT THIS REPLACES, AND WHY IT WAS THE WRONG SIGNAL. s113.4 watched for the
 * game's window to appear and then vanish, and restored on the disappearance. Two
 * separate faults, both visible in the 1.3-rc1 log once the switch actually worked:
 *
 *   IT LOSES THE RACE THAT MATTERS. Window destroyed -> message loop ends ->
 *   WinMain returns -> ExitProcess. That is milliseconds; the watcher polled at
 *   500 ms and then needed about a second for the display call. The thread dies
 *   with the process. No log this project has ever collected contains the
 *   "primary put back" line, on any run, which is what that looks like from here.
 *
 *   IT CAN WIN THE RACE THAT DOES NOT. A window of class 'Tropico' is created AND
 *   DESTROYED during startup while the game runs on: rc1's log has one at
 *   10,10 600x400, and the window dump two seconds later lists no window owned by
 *   this process at all, with the intro movies still playing. Catching that pair
 *   restores the primary two seconds into loading and undoes the switch.
 *
 * So do not infer the exit from a window. Ask for it. Tropico.EXE imports
 * KERNEL32!ExitProcess -- confirmed in its import table -- and that is the one
 * moment which is both late enough to be correct and still safe: every thread is
 * alive, the loader lock is not held, and the WM_DISPLAYCHANGE broadcast that
 * ChangeDisplaySettingsEx/SetDisplayConfig sends has somewhere to go. It is the
 * moment DLL_PROCESS_DETACH is NOT, which is why s113.4 refused to restore there
 * and why that refusal still stands.
 *
 * THE OTHER TWO LAYERS ARE UNCHANGED IN JOB AND SMALLER IN SCOPE. tropico-primary
 * .state still catches what no in-process hook can -- a crash into TerminateProcess,
 * Task Manager, a reboot -- and restores at the next launch. restore_primary() is
 * guarded by an interlocked flag, so arriving twice is harmless by construction.
 *
 * Costs about a second on the way out: the same second the switch costs on the way
 * in. That is the price of handing the display back, and it is worth paying where
 * the alternative is leaving somebody's desktop rearranged until they next happen
 * to play Tropico.
 */
typedef VOID (WINAPI *ExitProcess_t)(UINT);
static ExitProcess_t g_real_exitprocess;

static DWORD WINAPI exit_restore_thread(LPVOID p)
{
    (void)p;
    restore_primary("the game is exiting");
    return 0;
}

static VOID WINAPI hook_ExitProcess(UINT code)
{
    HANDLE h;
    /* BOUNDED, and the bound is the whole reason this is on a thread rather than
     * inline. s113.4's judgement was that "a desktop on the wrong primary is
     * annoying and fixable; a game that will not close is neither" -- and moving
     * the restore onto the exit path is exactly what would put that at risk. The
     * display call belongs to the driver and this is the last moment we control,
     * so give it a deadline. Five seconds is several times the ~1 s a successful
     * SetDisplayConfig costs on the machine this was measured on, and when it does
     * elapse nothing is lost that was not already lost: tropico-primary.state
     * catches it at the next launch, which is precisely what it is for. */
    h = CreateThread(NULL, 0, exit_restore_thread, NULL, 0, NULL);
    if (h) { WaitForSingleObject(h, 5000); CloseHandle(h); }
    else     restore_primary("the game is exiting; no thread could be created");
    g_real_exitprocess(code);
}

static void arm_primary_restore(void)
{
    static int done;
    void *real;
    if (done || !g_prev_primary[0]) return;
    done = 1;
    if (hook_import("KERNEL32.dll", "ExitProcess", (void *)hook_ExitProcess, &real)) {
        g_real_exitprocess = (ExitProcess_t)real;
        logf_("  [display] ExitProcess hooked -- %s gets the primary back when the game"
              " quits", g_prev_primary);
    } else {
        /* Not fatal, and say exactly what the player is left with rather than
         * leaving a silence that reads as "handled". */
        logf_("[!] [display] could not hook ExitProcess, so nothing will hand the primary"
              " back when the game quits. tropico-primary.state will restore %s at the"
              " next launch instead.", g_prev_primary);
    }
}

static void apply_monitor_win32(void)
{
    int k;
    /* Record the primary to return to ONLY if no earlier run already said what it
     * is. Overwriting it here is how a crash turns into a permanent move: the
     * leftover primary would be written down as the player's own. */
    if (!g_prev_primary[0]) {
        snprintf(g_prev_primary, sizeof g_prev_primary, "%s", g_mon_from);
        g_prev_primary_w = g_mon_from_w;
        g_prev_primary_h = g_mon_from_h;
    }
    write_primary_state();          /* before the change, not after */

    if (!set_primary_win32(g_mon_to)) {
        logf_("[x] [display] could not make %s the primary monitor -- the game will run on"
              " %s, which is where it would have run anyway. Nothing is broken; the"
              " launch monitor simply was not adopted.", g_mon_to, g_mon_from);
        g_prev_primary[0] = 0;
        clear_primary_state();
        return;
    }

    /* Wait for the metrics to agree, for the same reason the xrandr path does: the
     * mode picker and the fit checks all read SM_CXSCREEN a moment from now, and a
     * stale reading there rejects a perfectly good mode. Unlike Wine, Windows has
     * no loader lock in the way here -- this runs in the patch pass. */
    for (k = 0; k < 60; k++) {
        if ((DWORD)GetSystemMetrics(SM_CXSCREEN) == g_mon_to_w &&
            (DWORD)GetSystemMetrics(SM_CYSCREEN) == g_mon_to_h) break;
        Sleep(50);
    }
    if ((DWORD)GetSystemMetrics(SM_CXSCREEN) != g_mon_to_w)
        logf_("[!] [display] %s is primary but Windows still measures %dx%d rather than"
              " %lux%lu. The picker validates against what is measured, so this run may"
              " not get the mode the launch monitor asked for.", g_mon_to,
              GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN),
              (unsigned long)g_mon_to_w, (unsigned long)g_mon_to_h);
    else
        logf_("[+] [display] primary %s -> %s; Windows now measures %dx%d. It is put back"
              " when the game's window closes.", g_mon_from, g_mon_to,
              GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
    arm_primary_restore();
}

/* s90.2: the monitor is chosen from WHERE THE GAME WAS LAUNCHED, not from the mode
 * in the ini.
 *
 * The first version let the configured mode decide, which inverts cause and effect:
 * ask for 2560x1440 and it made the 1440p panel primary even though the player had
 * clicked Play on the 1080p one, so the window opened on one monitor while Wine
 * measured another -- DirectDraw #150, an error dialog before the game even starts.
 * That is the same rule tools/tropico enforces on GOG ("launch it from the monitor
 * you want to play on"), except here nothing of ours runs first to enforce it, so
 * the proxy has to infer it.
 *
 * The pointer is the signal: Steam's Play button is under the cursor a second or two
 * before we run. GetCursorPos gives Windows virtual-screen coordinates whose origin
 * is the CURRENT primary, so adding that primary's xrandr position converts them
 * into X coordinates that can be tested against every output's real rectangle. Two
 * monitors of identical size are therefore still told apart, which matching by mode
 * alone could not do.
 *
 * [Display] Monitor=<name> overrides the inference; [Display] SetPrimary=0 disables
 * the whole step. */
static void choose_monitor(void)
{
    static int done;
    if (done) return;               /* called from DllMain, and again from the patch pass */
    done = 1;
    xout_t outs[8];
    int n, i, chosen = -1, prim = -1, set_primary;
    char ip[MAX_PATH], want[64], want2[64];
    POINT pt;
    long px, py;

    snprintf(ip, sizeof ip, "%s\\tropico-fix.ini", g_dir);
    /* DEFAULT OFF ON WINDOWS, ON UNDER WINE, AND THE ASYMMETRY IS THE POINT (s113.8).
     *
     * Making a monitor primary is a change to the PLAYER'S COMPUTER, not to the game,
     * and the two platforms can undo it to completely different standards.
     *
     * Under Wine the restore lives OUTSIDE this process -- a detached shell watchdog
     * on a heartbeat for the Steam path, `trap restore_primary EXIT INT TERM HUP` in
     * tools/tropico for GOG. Neither cares how the game ended; a segfault and a clean
     * quit look the same to them. And xrandr's primary is runtime state that the
     * desktop re-establishes at login, so even losing the watchdog self-heals.
     *
     * On Windows there is no out-of-process anything -- this package ships no helper
     * executable -- and the change PERSISTS, because making it stick at all means
     * SDC_SAVE_TO_DATABASE / CDS_UPDATEREGISTRY writing it into the stored display
     * configuration. So the worst case is not "wrong until you log in again", it is
     * "wrong until the player works out what did it". Measured on the owner's machine:
     * a run that ended without the restore left the primary moved, and nothing in the
     * desktop connects that to a game that is no longer running.
     *
     * We could not honestly make the second case rare enough. Every mechanism aimed at
     * it -- the window watcher, tropico-primary.state, the ExitProcess hook -- exists
     * to give back something we should not have taken by default. So on Windows it is
     * now opt-in: the game opens on the primary monitor, at that monitor's resolution,
     * which is the whole of what this patch promises. SetPrimary=1 restores the old
     * behaviour for someone who wants it and has read what it costs.
     *
     * Turning it off here is enough by itself. g_launch_w is never set, so pick_mode()
     * validates against SM_CXSCREEN -- the primary, the screen the game will actually
     * run on -- and no mode is adopted from a monitor it will not be shown on. */
    /* SAY WHY, when the player has asked for something this gate discards.
     *
     * The return above happens BEFORE [Display] Monitor and FollowLaunchMonitor are
     * read, so on Windows -- where SetPrimary now defaults to 0 (s113.8) -- setting
     * either of them did nothing at all, and did it without a word. That is the
     * s113.6 shape: a silence that reads as a result. The keys are not wrong and the
     * gate is not wrong; what was missing was the sentence joining them.
     *
     * Both are checked as STRINGS with an empty default, because
     * GetPrivateProfileInt cannot tell "absent" from "set to the default" and
     * FollowLaunchMonitor's default is 1 -- so an int read would stay silent for the
     * player who set it explicitly, which is exactly the player being addressed. */
    /* s118 splits this gate. Everything above the "RECORD IT" block at the bottom
     * only READS the display, and DeviceSelect needs those reads -- which monitor
     * was launched from and what mode it is in -- while wanting the primary left
     * exactly where it is. So SetPrimary gates the WRITE at the bottom, and this
     * early return survives only for the case where neither feature is on.
     *
     * That preserves s113.8's guarantee literally: with SetPrimary=0 and
     * DeviceSelect=0 -- both the Windows defaults -- the function still returns
     * here, g_launch_w is still never set, and pick_mode() still validates against
     * SM_CXSCREEN. Nothing about the default path moves. */
    set_primary = GetPrivateProfileIntA("Display", "SetPrimary", running_under_wine() ? 1 : 0, ip);
    if (!set_primary && !g_devsel) {
        char m[64], f[64];
        const char *what;
        GetPrivateProfileStringA("Display", "Monitor", "", m, sizeof m, ip);
        GetPrivateProfileStringA("Display", "FollowLaunchMonitor", "", f, sizeof f, ip);
        if (!*m && !*f) return;
        /* The launcher owns the display and has already chosen the monitor, so the
         * keys are SUPERSEDED rather than discarded and the advice below would be
         * actively wrong -- it would tell the player to go and do what the launcher
         * just did. Say what the SetPrimary=1 path says in the same situation; the
         * launcher winning is s90.2's rule, not a special case invented here. */
        if (GetEnvironmentVariableA("TROPICO_LAUNCHER", want2, sizeof want2)) {
            logf_("  [display] launched by tools/tropico, which has already chosen the"
                  " monitor -- leaving the display alone");
            return;
        }
        what = (*m && *f) ? "[Display] Monitor and FollowLaunchMonitor are"
             : *m         ? "[Display] Monitor is"
                          : "[Display] FollowLaunchMonitor is";
        logf_("[!] [display] SetPrimary=0, so %s being ignored -- the monitor is not"
              " being chosen at all. Tropico's fullscreen always goes to whichever"
              " monitor is primary, so reaching another one means MAKING it primary,"
              " and that is what SetPrimary gates.", what);
        logf_("    Either set [Display] DeviceSelect=1, which reaches the monitor without"
              " touching your primary at all, or make it your main display in your"
              " desktop's own settings. SetPrimary=1 is the third way and the ini says"
              " what it costs.");
        return;
    }
    GetPrivateProfileStringA("Display", "Monitor", "", want, sizeof want, ip);

    /* Not when tools/tropico started us. That launcher already chose the monitor,
     * made it primary and built a virtual desktop around it -- doing it again from
     * in here means two things deciding the same setting, and the one with worse
     * information (no launch context, a pointer that may have moved) would win by
     * running second. The launcher exports this; nothing else sets it. */
    if (GetEnvironmentVariableA("TROPICO_LAUNCHER", want2, sizeof want2)) {
        logf_("  [display] launched by tools/tropico, which has already chosen the"
              " monitor -- leaving the display alone");
        return;
    }

    /* Inside our own virtual desktop (s100) the game sees one screen at 0,0 and the
     * mode is the desktop's own. Making a monitor primary would change the display
     * for no gain -- the failure mode it exists to prevent cannot arise in here. */
    if (g_vd_inside) {
        logf_("  [display] running in the virtual desktop -- no monitor to choose and"
              " no primary to change");
        return;
    }

    n = xrandr_outputs(outs, 8);
    if (n <= 0) {
        /* No host to ask: native Windows, or a prefix whose game is not on Z:.
         * Win32 knows the same layout -- see win32_outputs() for why it is second
         * rather than first. */
        n = win32_outputs(outs, 8);
        g_mon_win32 = (n > 0);
        if (n > 0)
            logf_("  [display] no host display channel -- reading the layout from Windows"
                  " itself (%d monitor(s) attached)", n);
    }
    if (n <= 0) {
        logf_("  [display] could not read the display from the host, and Windows reported"
              " no attached monitor either -- leaving the monitor alone");
        return;
    }
    load_primary_state();
    for (i = 0; i < n; i++) if (outs[i].primary) prim = i;
    if (prim < 0) { logf_("  [display] xrandr reports no primary output -- leaving it alone"); return; }

    if (n == 1) {
        logf_("  [display] one monitor (%s, %lux%lu) -- nothing to choose",
              outs[0].name, (unsigned long)outs[0].w, (unsigned long)outs[0].h);
        return;
    }

    /* A leftover from a run that never put the primary back. Recorded now and
     * restored by the same path a change of our own is, so the two cannot fight:
     * whatever this run decides, the display ends up where the player left it. */
    if (g_prev_primary[0] && _stricmp(g_prev_primary, outs[prim].name))
        logf_("  [display] tropico-primary.state says the player's primary is %s, but %s"
              " is primary now -- a previous run did not put it back. %s is what this"
              " run will restore to.", g_prev_primary, outs[prim].name, g_prev_primary);

    if (want[0]) {
        for (i = 0; i < n; i++) if (!_stricmp(outs[i].name, want)) chosen = i;
        if (chosen < 0)
            logf_("[!] [display] Monitor=%s is not a connected output -- ignoring it", want);
    }
    /* s118.10: native Windows asks the desktop what it is focused on, and only then
     * the pointer. Win32 puts the primary at (0,0), so both answers are already in
     * the virtual-screen coordinates outs[] uses -- no translation, unlike the Wine
     * fallback below. */
    if (chosen < 0 && g_ptr_x < 0 && !running_under_wine()) {
        char how[32];
        if (win32_launch_point(&px, &py, how, sizeof how)) {
            for (i = 0; i < n; i++)
                if (px >= outs[i].x && px < outs[i].x + (long)outs[i].w &&
                    py >= outs[i].y && py < outs[i].y + (long)outs[i].h) { chosen = i; break; }
            if (chosen >= 0)
                logf_("  [display] launched from %s (launch point %ld,%ld, via %s)",
                      outs[chosen].name, px, py, how);
            else
                logf_("  [display] the launch point %ld,%ld (via %s) is on no attached"
                      " monitor -- staying on the primary %s", px, py, how, outs[prim].name);
        }
    }
    if (chosen < 0 && (g_ptr_x >= 0 || GetCursorPos(&pt))) {
        if (g_ptr_x >= 0) {
            px = g_ptr_x; py = g_ptr_y;          /* X root coords: already absolute */
        } else {
            /* Fallback only. Wine has no pointer state this early, and its 0,0
             * always resolves to the primary -- so refuse that answer rather than
             * let it masquerade as a detection. */
            if (!pt.x && !pt.y) {
                logf_("  [display] no pointer from X and Wine says 0,0 -- refusing to"
                      " guess a monitor from that; staying on the primary %s",
                      outs[prim].name);
                return;
            }
            px = outs[prim].x + pt.x;
            py = outs[prim].y + pt.y;
        }
        for (i = 0; i < n; i++)
            if (px >= outs[i].x && px < outs[i].x + (long)outs[i].w &&
                py >= outs[i].y && py < outs[i].y + (long)outs[i].h) { chosen = i; break; }
        {
            char via[32];
            snprintf(via, sizeof via, "%s%s", g_ptr_how[0] ? ", via " : "", g_ptr_how);
            if (chosen >= 0)
                logf_("  [display] launched from %s (launch point %ld,%ld in screen"
                      " space%s)", outs[chosen].name, px, py, via);
        }
    }
    if (chosen < 0) {
        logf_("  [display] could not tell which monitor this was launched from --"
              " staying on the primary %s", outs[prim].name);
        return;
    }

    /* Adopt the launch monitor's own mode, unconditionally. This used to be gated on
     * mode_is_staged() -- "only if an installer happened to stage art for it" -- which
     * is why a monitor nobody predicted got someone else's resolution. The generator
     * removes the condition: whatever mode this monitor is in, the art for it is built
     * a moment from now. */
    if (GetPrivateProfileIntA("Display", "FollowLaunchMonitor", 1, ip)) {
        g_launch_w = outs[chosen].w;
        g_launch_h = outs[chosen].h;
        logf_("[+] [display] running at %s's own mode %lux%lu", outs[chosen].name,
              (unsigned long)g_launch_w, (unsigned long)g_launch_h);
    }

    /* s118: the target, as the name DirectDraw will be asked for. Recorded here
     * because this is where "which monitor" is decided; resolved to a GUID much
     * later, at DirectDrawCreateEx, where loading ddraw.dll is safe. */
    if (g_devsel) {
        if (!g_mon_win32) {
            logf_("[x] [devsel] the monitor list did not come from Windows, so these"
                  " names are not \\\\.\\DISPLAYn and DirectDraw cannot be asked for one."
                  " DeviceSelect is OFF for this run.");
            g_devsel = 0;
        } else if (chosen == prim) {
            logf_("  [devsel] %s is already the primary -- the game renders there by"
                  " default and there is no device to substitute.", outs[prim].name);
            g_devsel = 0;
        } else {
            snprintf(g_devsel_want, sizeof g_devsel_want, "%s", outs[chosen].name);
            g_devsel_ox = outs[chosen].x;
            g_devsel_oy = outs[chosen].y;
            logf_("[+] [devsel] target %s %lux%lu -- the game will be pointed at that"
                  " DEVICE and the primary %s is NOT being changed (FINDINGS 118)",
                  outs[chosen].name, (unsigned long)outs[chosen].w,
                  (unsigned long)outs[chosen].h, outs[prim].name);
        }
    }

    if (chosen == prim) {
        logf_("  [display] %s is already primary -- nothing to change", outs[prim].name);
        return;
    }
    if (!set_primary) return;   /* devsel: the device does the work, not the display */

    /* RECORD IT; DO NOT DO IT. Everything above this line only reads the display,
     * and reading is safe from DllMain -- measured on Steam, where the pointer was
     * found on DP-3, its 2560x1440 adopted and the whole art set generated from
     * there without trouble. Changing the primary from DllMain is a different
     * matter, and it fails: see apply_monitor(). */
    snprintf(g_mon_to,   sizeof g_mon_to,   "%s", outs[chosen].name);
    snprintf(g_mon_from, sizeof g_mon_from, "%s", outs[prim].name);
    g_mon_to_w = outs[chosen].w;
    g_mon_to_h = outs[chosen].h;
    g_mon_from_w = outs[prim].w;
    g_mon_from_h = outs[prim].h;
    g_mon_pending = 1;
    logf_("  [display] %s needs to become primary (currently %s) -- held until the"
          " patch pass, where the change can actually take effect", g_mon_to, g_mon_from);
}

/* ------------------------------------------------------ s99 apply_monitor
 *
 * WHY THIS IS NOT DONE WHERE IT IS DECIDED.
 *
 * Measured on the Steam edition, with the whole of choose_and_apply_monitor()
 * running from DllMain. The reading half worked perfectly:
 *
 *     [display] launched from DP-3 (pointer at 3142,702 in screen space)
 *     [+] [display] running at DP-3's own mode 2560x1440
 *     [+] artgen: generated 267 assets for 2560x1440 ... 1333 ms
 *
 * and then the writing half did not:
 *
 *     [+] [display] primary HDMI-A-5 -> DP-3; Wine now measures 1920x1080
 *
 * xrandr ran and the host primary really did move. What never happened is Wine
 * noticing: the loop below polls SM_CXSCREEN for six seconds and it expired
 * still reporting the old primary's size. The process then asked for a 2560x1440
 * mode on a desktop it believed was 1920x1080, which renders NOTHING -- the intro
 * audio plays over a black screen and it looks exactly like a crash (FINDINGS 75).
 *
 * The reason is that a display change is noticed by work this process cannot do
 * while it holds the loader lock: the heartbeat thread below cannot run its
 * DLL_THREAD_ATTACH until DllMain returns, and nothing services the change
 * notification in the meantime. So the poll cannot succeed there, however long it
 * waits -- it is not a timing value that wants raising.
 *
 * Called from apply_patches, which is where it has always worked. Note the one
 * path where that is still inside DllMain: the unwrapped GOG build patches
 * immediately rather than deferring to GetDeviceCaps. That path is reached only
 * when the game is started WITHOUT tools/tropico, and the launcher exists
 * precisely because it does this job better -- before the process exists at all,
 * with a fresh wineserver behind it. It is not a new fault; it predates the split.
 */
static void apply_monitor(void)
{
    char script[MAX_PATH * 4], udir[MAX_PATH];
    if (!g_mon_pending) {
        /* Nothing to change for this run -- but a previous one may still owe the
         * player their primary back (s113). Hand it back when the game closes, not
         * now: moving the desktop out from under a game that has already measured
         * it is the fault this whole section exists to avoid. */
        if (g_mon_win32 && g_prev_primary[0]) arm_primary_restore();
        return;
    }
    g_mon_pending = 0;

    /* Same decision, different verb. The host channel changes the primary with
     * xrandr; without one, Windows changes its own. */
    if (g_mon_win32) { apply_monitor_win32(); return; }

    if (!game_unix_dir(udir, sizeof udir)) return;
    snprintf(g_xr_prev, sizeof g_xr_prev, "%s", g_mon_from);
    snprintf(g_xr_marker_win, sizeof g_xr_marker_win, "%s\\tropico-primary.lock", g_dir);
    snprintf(g_xr_marker_unix, sizeof g_xr_marker_unix, "%s/tropico-primary.lock", udir);
    CloseHandle(CreateThread(NULL, 0, heartbeat_thread, NULL, 0, NULL));
    Sleep(150);

    snprintf(script, sizeof script,
             "/usr/bin/xrandr --output %s --primary\n"
             "( while [ -f '%s' ]; do\n"
             "N=$(date +%%s); M=$(stat -c %%Y '%s' 2>/dev/null || echo 0)\n"
             "[ $((N-M)) -ge 10 ] && break\n"
             "sleep 2\n"
             "done\n"
             "/usr/bin/xrandr --output %s --primary\n"
             "rm -f '%s' ) &\n",
             g_mon_to, g_xr_marker_unix, g_xr_marker_unix,
             g_xr_prev, g_xr_marker_unix);
    if (unix_sh(script, 3000)) {
        int k;
        for (k = 0; k < 60; k++) {
            if ((DWORD)GetSystemMetrics(SM_CXSCREEN) == g_mon_to_w &&
                (DWORD)GetSystemMetrics(SM_CYSCREEN) == g_mon_to_h) break;
            Sleep(100);
        }
        logf_("[+] [display] primary %s -> %s; Wine now measures %dx%d. A host"
              " watchdog restores %s when this process stops, crash included",
              g_xr_prev, g_mon_to, GetSystemMetrics(SM_CXSCREEN),
              GetSystemMetrics(SM_CYSCREEN), g_xr_prev);
    }
}

/* ------------------------------------------------ s100 the virtual desktop
 *
 * WHY. The GOG launcher runs the game inside `wine explorer /desktop=Tropico,WxH`,
 * and s76.2 records what that buys: inside a virtual desktop there is exactly one
 * screen with origin (0,0), so the geometry behind #150 -- a window on a monitor
 * Wine did not measure, at negative coordinates -- CANNOT ARISE. It is also why the
 * GOG path has never shown the s89 camera drift: the game cannot see the monitor
 * layout at all.
 *
 * The Steam edition gets none of that, because Steam's Play button is the only way
 * past the DRM (s90) and nothing of ours is in front of it to pass /desktop= on a
 * command line. This is the way in that needs no command line: Wine reads the same
 * setting out of the PREFIX REGISTRY, and the proxy is already running inside that
 * prefix with the right to write it.
 *
 *   HKCU\Software\Wine\Explorer            Desktop  = TropicoVD
 *   HKCU\Software\Wine\Explorer\Desktops   TropicoVD = 2560x1440
 *
 * MEASURED before any of this was written (probes/vdprobe.c, s100.1), because the
 * whole design rests on it: with those two values set and NOTHING on the command
 * line, a plain `wine prog.exe` reports SM_CMONITORS=1, 1280x1024 at 0,0 -- against
 * SM_CMONITORS=2, virtual screen 4480x1440 at 0,-360 in the same prefix without
 * them. The registry route really does produce the same desktop the command line
 * does.
 *
 * THE SIZE IS DECIDED ONE LAUNCH EARLY, and there is no way around that: the desktop
 * exists before the game's first instruction, so the proxy can only ever arm the
 * NEXT launch. This is the same shape as d32cc32's pending monitor change. Arming is
 * therefore idempotent and self-refreshing -- every run rewrites the size it wants,
 * so a monitor that changed since last time costs one launch at the old size.
 *
 * BEING INSIDE IS RECORDED, NOT INFERRED. `tropico-vd.state` holds the size we last
 * armed; we are inside when Wine reports exactly that size on exactly one monitor.
 * Inferring it from the metrics alone cannot work -- on a single-monitor desktop the
 * inside and outside readings are identical (s90.3's rule: when a sentinel is also a
 * legal value, get the fact from a source that has no such overlap).
 *
 * BORDERLESS IS NOT FULLSCREEN. The desktop window arrives placed like any other
 * window: measured at +320+531 in the probe, which is exactly the "bordered and not
 * fullscreen" complaint that got this idea rejected the first time round. The EWMH
 * message tools/tropico-fullscreen.py sends is what fixes it there, and s90.1's host
 * channel is how it gets sent from in here. The desktop is deliberately NOT named
 * "Tropico": the game's own window has that title, and a substring match on it would
 * fullscreen the wrong window. "TropicoVD" is matched by no window the game creates.
 *
 * OFF BY DEFAULT, and reversible: turning [Display] VirtualDesktop back to 0 removes
 * the registry value rather than leaving the prefix in desktop mode for a game that
 * is no longer patched. uninstall.sh does the same from the host, for the case where
 * the flag is still on when the patch is removed.
 *
 * ONLY UNDER WINE. On native Windows nothing reads these keys, so writing them would
 * be litter; wine_get_version() is the test.
 *
 *   [Display] VirtualDesktop=1
 */
#define VD_NAME "TropicoVD"


/* The EWMH request, embedded rather than shipped: the Windows package has no Python
 * in it at all (s97) and this must not be the thing that puts it back. Same message
 * tools/tropico-fullscreen.py sends -- keep the two in step. */
static const char FULLSCREEN_PY[] =
    "import ctypes, ctypes.util, sys, time\n"
    "NAME = sys.argv[1]\n"
    "DEADLINE = time.time() + 30\n"
    "lib = ctypes.util.find_library('X11')\n"
    "if not lib: sys.exit(0)\n"
    "x = ctypes.CDLL(lib)\n"
    "x.XOpenDisplay.restype = ctypes.c_void_p\n"
    "x.XInternAtom.restype = ctypes.c_ulong\n"
    "x.XInternAtom.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]\n"
    "x.XDefaultRootWindow.restype = ctypes.c_ulong\n"
    "x.XDefaultRootWindow.argtypes = [ctypes.c_void_p]\n"
    "d = x.XOpenDisplay(None)\n"
    "if not d: sys.exit(0)\n"
    "root = x.XDefaultRootWindow(ctypes.c_void_p(d))\n"
    "class XEvent(ctypes.Structure):\n"
    "    _fields_ = [('pad', ctypes.c_long * 24)]\n"
    "def children(w):\n"
    "    r = ctypes.c_ulong(); p = ctypes.c_ulong()\n"
    "    kids = ctypes.POINTER(ctypes.c_ulong)(); n = ctypes.c_uint()\n"
    "    if not x.XQueryTree(ctypes.c_void_p(d), ctypes.c_ulong(w), ctypes.byref(r),\n"
    "                        ctypes.byref(p), ctypes.byref(kids), ctypes.byref(n)):\n"
    "        return []\n"
    "    out = [kids[i] for i in range(n.value)]\n"
    "    x.XFree(kids)\n"
    "    return out\n"
    "def name_of(w):\n"
    "    s = ctypes.c_char_p()\n"
    "    if x.XFetchName(ctypes.c_void_p(d), ctypes.c_ulong(w), ctypes.byref(s)) and s.value:\n"
    "        v = s.value.decode('utf-8', 'replace'); x.XFree(s); return v\n"
    "    return ''\n"
    "def find():\n"
    "    for w in children(root):\n"
    "        if NAME.lower() in name_of(w).lower(): return w\n"
    "        for c in children(w):\n"
    "            if NAME.lower() in name_of(c).lower(): return c\n"
    "    return None\n"
    "target = None\n"
    "while time.time() < DEADLINE:\n"
    "    target = find()\n"
    "    if target: break\n"
    "    time.sleep(0.3)\n"
    "if not target: sys.exit(0)\n"
    "state = x.XInternAtom(ctypes.c_void_p(d), b'_NET_WM_STATE', False)\n"
    "full = x.XInternAtom(ctypes.c_void_p(d), b'_NET_WM_STATE_FULLSCREEN', False)\n"
    "ev = XEvent()\n"
    "buf = ctypes.cast(ctypes.byref(ev), ctypes.POINTER(ctypes.c_long))\n"
    "ctypes.memset(ctypes.byref(ev), 0, ctypes.sizeof(ev))\n"
    "buf[0] = 33; buf[2] = 1; buf[3] = 0; buf[4] = target; buf[5] = state\n"
    "buf[6] = 32; buf[7] = 1; buf[8] = full; buf[9] = 0; buf[10] = 1\n"
    "x.XSendEvent(ctypes.c_void_p(d), ctypes.c_ulong(root), False,\n"
    "             ctypes.c_long((1 << 20) | (1 << 19)), ctypes.byref(ev))\n"
    "x.XFlush(ctypes.c_void_p(d))\n";

static int running_under_wine(void)
{
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    return nt && GetProcAddress(nt, "wine_get_version") != NULL;
}

static void vd_state_read(void)
{
    char win[MAX_PATH], buf[64];
    HANDLE h;
    DWORD got = 0;
    unsigned w = 0, hgt = 0;
    snprintf(win, sizeof win, "%s\\tropico-vd.state", g_dir);
    h = CreateFileA(win, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    ReadFile(h, buf, sizeof buf - 1, &got, NULL);
    CloseHandle(h);
    buf[got] = 0;
    if (sscanf(buf, "%ux%u", &w, &hgt) == 2) { g_vd_arm_w = w; g_vd_arm_h = hgt; }
}

static void vd_state_write(DWORD w, DWORD h)
{
    char win[MAX_PATH], body[64];
    HANDLE fh;
    DWORD wrote;
    snprintf(win, sizeof win, "%s\\tropico-vd.state", g_dir);
    if (!w) { DeleteFileA(win); g_vd_arm_w = g_vd_arm_h = 0; return; }
    snprintf(body, sizeof body, "%lux%lu\n", (unsigned long)w, (unsigned long)h);
    fh = CreateFileA(win, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE) return;
    WriteFile(fh, body, (DWORD)strlen(body), &wrote, NULL);
    CloseHandle(fh);
    g_vd_arm_w = w; g_vd_arm_h = h;
}

/* size == NULL removes the desktop; the Desktops entry is left behind on purpose,
 * because it names a size and nothing reads it without the Desktop value above. */
static int vd_registry(const char *size)
{
    HKEY k;
    LONG r;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Wine\\Explorer", 0, NULL, 0,
                        KEY_SET_VALUE, NULL, &k, NULL) != ERROR_SUCCESS) return 0;
    if (size) r = RegSetValueExA(k, "Desktop", 0, REG_SZ, (const BYTE *)VD_NAME,
                                 (DWORD)strlen(VD_NAME) + 1);
    else      r = RegDeleteValueA(k, "Desktop");
    RegCloseKey(k);
    if (!size) return r == ERROR_SUCCESS || r == ERROR_FILE_NOT_FOUND;
    if (r != ERROR_SUCCESS) return 0;

    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Wine\\Explorer\\Desktops", 0, NULL,
                        0, KEY_SET_VALUE, NULL, &k, NULL) != ERROR_SUCCESS) return 0;
    r = RegSetValueExA(k, VD_NAME, 0, REG_SZ, (const BYTE *)size, (DWORD)strlen(size) + 1);
    RegCloseKey(k);
    return r == ERROR_SUCCESS;
}

/* READ-ONLY, and safe from DllMain for the s99 reason: it reads the display and the
 * ini, and changes neither. */
static void vd_detect(void)
{
    char ip[MAX_PATH], env[64];
    if (g_vd_checked) return;
    g_vd_checked = 1;
    if (!running_under_wine()) return;

    snprintf(ip, sizeof ip, "%s\\tropico-fix.ini", g_dir);
    g_vd_want = GetPrivateProfileIntA("Display", "VirtualDesktop", 0, ip);

    /* tools/tropico builds its own desktop on the command line and names it Tropico.
     * Two things arming the same setting is the s90.2 mistake; the launcher wins. */
    if (GetEnvironmentVariableA("TROPICO_LAUNCHER", env, sizeof env)) {
        if (g_vd_want)
            logf_("  [vdesk] launched by tools/tropico, which builds its own desktop"
                  " -- leaving [Display] VirtualDesktop alone");
        g_vd_want = 0;
        return;
    }

    vd_state_read();
    if (g_vd_arm_w && GetSystemMetrics(SM_CMONITORS) == 1 &&
        (DWORD)GetSystemMetrics(SM_CXSCREEN) == g_vd_arm_w &&
        (DWORD)GetSystemMetrics(SM_CYSCREEN) == g_vd_arm_h) {
        g_vd_inside = 1;
        g_launch_w = g_vd_arm_w;
        g_launch_h = g_vd_arm_h;
        logf_("[+] [vdesk] inside the %lux%lu virtual desktop -- one screen at 0,0,"
              " so nothing has to touch the monitor layout",
              (unsigned long)g_vd_arm_w, (unsigned long)g_vd_arm_h);
    }
}

/* The mode the NEXT launch's desktop should be. The launch monitor if the pointer
 * can be placed on one, the primary otherwise -- the same order choose_monitor()
 * uses, and for the same reason. */
static int vd_target_mode(DWORD *w, DWORD *h)
{
    xout_t outs[8];
    int n, i, prim = -1;
    n = xrandr_outputs(outs, 8);
    if (n <= 0) return 0;
    for (i = 0; i < n; i++) if (outs[i].primary) prim = i;
    if (g_ptr_x >= 0)
        for (i = 0; i < n; i++)
            if (g_ptr_x >= outs[i].x && g_ptr_x < outs[i].x + (long)outs[i].w &&
                g_ptr_y >= outs[i].y && g_ptr_y < outs[i].y + (long)outs[i].h) {
                *w = outs[i].w; *h = outs[i].h; return 1;
            }
    if (prim < 0) return 0;
    *w = outs[prim].w; *h = outs[prim].h;
    return 1;
}

/* Runs in the patch pass, beside apply_monitor(), for the s99 reason: this writes. */
static void vd_apply(void)
{
    char size[32], script[MAX_PATH * 3], udir[MAX_PATH];
    DWORD w = 0, h = 0;

    if (!running_under_wine()) return;

    if (g_vd_inside) {
        /* Fullscreen it. Borderless alone is not fullscreen (s76.2), and under
         * Proton the desktop window is placed like any other -- measured at
         * +320+531 in the probe. Backgrounded: it waits for the window. */
        if (game_unix_dir(udir, sizeof udir) && write_host_file("tropico-vd-fs.py", FULLSCREEN_PY)) {
            snprintf(script, sizeof script,
                     "/usr/bin/python3 '%s/tropico-vd-fs.py' %s >/dev/null 2>&1 &\n",
                     udir, VD_NAME);
            unix_sh(script, 300);
            logf_("  [vdesk] asked the window manager to fullscreen %s", VD_NAME);
        }
        /* Re-arm for next time, so a monitor that changed since costs one launch. */
        if (g_vd_want && vd_target_mode(&w, &h) && (w != g_vd_arm_w || h != g_vd_arm_h)) {
            snprintf(size, sizeof size, "%lux%lu", (unsigned long)w, (unsigned long)h);
            if (vd_registry(size)) {
                vd_state_write(w, h);
                logf_("[+] [vdesk] the display changed -- the next launch gets a %s"
                      " desktop instead", size);
            }
        }
        if (!g_vd_want) {
            /* Inside, but the flag came off: this run stays where it is, the next
             * one does not. */
            if (vd_registry(NULL)) {
                vd_state_write(0, 0);
                logf_("  [vdesk] VirtualDesktop=0 -- disarmed; the next launch runs on"
                      " the real desktop again");
            }
        }
        return;
    }

    if (g_vd_want) {
        if (!vd_target_mode(&w, &h)) {
            logf_("[!] [vdesk] could not read the display from the host -- cannot arm"
                  " a virtual desktop (expected outside Steam/Proton)");
            return;
        }
        snprintf(size, sizeof size, "%lux%lu", (unsigned long)w, (unsigned long)h);
        if (vd_registry(size)) {
            vd_state_write(w, h);
            logf_("[+] [vdesk] armed a %s virtual desktop. IT TAKES EFFECT ON THE NEXT"
                  " LAUNCH -- the desktop exists before this process does, so it cannot"
                  " be this one", size);
        } else {
            logf_("[!] [vdesk] could not write HKCU\\Software\\Wine\\Explorer -- not armed");
        }
        return;
    }

    if (g_vd_arm_w) {                     /* not wanted, but we armed it once */
        if (vd_registry(NULL)) {
            vd_state_write(0, 0);
            logf_("  [vdesk] VirtualDesktop=0 -- removed the desktop this patch armed");
        }
    }
}

/* --------------------------------------------- s101 Wine's cursor vs X's cursor
 *
 * WHY THIS AND NOT ANOTHER s89 PROBE. Every instrument s89 built compares Wine with
 * Wine: GetCursorPos against GetMessagePos against WM_MOUSEMOVE's lParam. They have
 * always agreed, and that is the point -- a coordinate space that is uniformly
 * scaled or shifted by the layer UNDERNEATH stays perfectly self-consistent, so
 * three agreeing Wine sources cannot detect it. Nothing has ever compared Wine's
 * answer with the X server's.
 *
 * The owner's hypothesis is exactly that shape: Proton presents the game letterboxed
 * or centred, and the pointer mapping does not undo it, so the game is told a
 * position that is a scale and an offset away from where the pointer really is. A
 * game that edge-scrolls sees an edge that is not there, and pans while the pointer
 * sits still in the middle of the picture.
 *
 * The measurement is one line: X root coordinates from XQueryPointer (s90.1's host
 * channel, the same one xrandr already goes through), Wine's GetCursorPos, and the
 * origin of the monitor the game is on. Inside a virtual desktop pinned to one
 * output, these must satisfy
 *
 *     x_root == monitor.x + wine.x        (and the same in y)
 *
 * exactly. A CONSTANT difference is an offset -- something centring the picture. A
 * difference that GROWS with the coordinate is a scale, and its ratio names the
 * letterbox: 1440/1920 = 0.75 is 4:3 pillarboxed into 16:9. Agreement refutes the
 * hypothesis outright and sends the search below X.
 *
 * It runs on its own thread, not in the GetCursorPos hook: the host channel costs a
 * subprocess and a few hundred milliseconds, which is nothing every two seconds and
 * a stutter on every cursor read. Sampling is capped, because a diagnostic that
 * degrades the thing it is measuring produces a measurement of itself.
 *
 *   [Cursor] XCompare=1
 */

/* Just the pointer, without xrandr's 16 KB of mode lists: this runs repeatedly. */
static int x_pointer(long *x, long *y)
{
    char udir[MAX_PATH], script[MAX_PATH * 3], win[MAX_PATH], buf[512];
    HANDLE h;
    DWORD got = 0;
    int i;
    const char *p;
    if (!game_unix_dir(udir, sizeof udir)) return 0;
    snprintf(win, sizeof win, "%s\\tropico-xptr.txt", g_dir);
    DeleteFileA(win);
    write_host_file("tropico-pointer.py", POINTER_PY);
    snprintf(script, sizeof script,
             "/usr/bin/python3 '%s/tropico-pointer.py' > '%s/tropico-xptr.txt' 2>&1\n",
             udir, udir);
    if (!unix_sh(script, 1200)) return 0;
    for (i = 0; i < 15; i++) {
        h = CreateFileA(win, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            ReadFile(h, buf, sizeof buf - 1, &got, NULL);
            CloseHandle(h);
            if (got) break;
        }
        Sleep(100);
    }
    if (!got) return 0;
    buf[got] = 0;
    p = strstr(buf, "POINTER ");
    if (!p) return 0;
    return sscanf(p + 8, "%ld %ld", x, y) == 2;
}

static DWORD WINAPI xcompare_thread(LPVOID unused)
{
    xout_t outs[8];
    int n, i, mon = -1, sample;
    long ox = 0, oy = 0;
    (void)unused;

    /* The monitor the game is on, read ONCE: inside a fullscreen virtual desktop it
     * cannot change, and re-reading it would cost an xrandr per sample. */
    n = xrandr_outputs(outs, 8);
    for (i = 0; i < n; i++) if (outs[i].primary) mon = i;
    if (mon >= 0) { ox = outs[mon].x; oy = outs[mon].y; }
    logf_("[*] [xcmp] comparing X's pointer with Wine's. Screen is %dx%d; the monitor"
          " Wine measures starts at %ld,%ld in X. Wine.x + %ld should equal X.x",
          GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN), ox, oy, ox);

    /* BRACKETED, and it has to be: the X read goes through a subprocess and lands
     * half a second away from the Wine read, so a moving pointer manufactures a
     * mismatch out of nothing but latency. Measured on the control -- a stationary
     * pointer agreed exactly, a moving one produced deltas up to 144 px that meant
     * only that the mouse had moved.
     *
     * And stationary-only sampling would be useless here: the drift is MOTION-driven
     * (s89), so the symptom is never present in the samples that would be exact. So
     * Wine is read on both sides of the X read, and X is required to fall between
     * them. Anything inside the bracket is latency; anything outside it is real, and
     * the report says by how much it missed. */
    for (sample = 0; sample < 40; sample++) {
        POINT w1, w2;
        long xr = -1, yr = -1, e1, e2, lo, hi, dx = 0, dy = 0;
        char verdict[64];
        int out = 0;
        Sleep(2000);
        if (!GetCursorPos(&w1)) continue;
        if (!x_pointer(&xr, &yr)) continue;
        if (!GetCursorPos(&w2)) continue;

        e1 = (long)w1.x + ox; e2 = (long)w2.x + ox;
        lo = e1 < e2 ? e1 : e2; hi = e1 < e2 ? e2 : e1;
        if (xr < lo) { dx = xr - lo; out = 1; } else if (xr > hi) { dx = xr - hi; out = 1; }
        e1 = (long)w1.y + oy; e2 = (long)w2.y + oy;
        lo = e1 < e2 ? e1 : e2; hi = e1 < e2 ? e2 : e1;
        if (yr < lo) { dy = yr - lo; out = 1; } else if (yr > hi) { dy = yr - hi; out = 1; }

        if (out)
            snprintf(verdict, sizeof verdict, "OUTSIDE the bracket by %ld,%ld", dx, dy);
        else
            snprintf(verdict, sizeof verdict, "inside the bracket");
        logf_("[*] [xcmp] X %ld,%ld | wine+origin %ld,%ld -> %ld,%ld | %s",
              xr, yr, (long)w1.x + ox, (long)w1.y + oy, (long)w2.x + ox, (long)w2.y + oy,
              verdict);
        if (out)
            logf_("[!] [xcmp]   ^ X and Wine disagree about where the pointer is");
    }
    logf_("[*] [xcmp] done -- 40 samples");
    return 0;
}

/* The adopted mode wins over [Resolution]: it describes the screen the player is
 * actually looking at, and the ini describes whatever was configured last. */
static int launch_override(mode_t *m)
{
    if (!g_launch_w || !g_launch_h) return 0;
    m->w = g_launch_w; m->h = g_launch_h;
    return 1;
}

/* ------------------- s108 the adopted mode has to fit the screen too
 *
 * The "MODE MUST FIT THE SCREEN" guard tested `[Resolution]` only. It predates
 * launch_override(), which since s90 takes PRIORITY over the ini -- so on the Steam
 * edition, where `[Resolution]` is empty and the mode comes entirely from the launch
 * monitor, the mode the game actually gets was never checked against the screen at all.
 *
 * Measured 2026-08-29: launch monitor 2560x1440, virtual desktop still the 1920x1080
 * one from the previous run, and the patch configured slot 4, the art set and the world
 * painter for 1440p inside a 1080p desktop. The log printed `armed a 2560x1440 virtual
 * desktop. IT TAKES EFFECT ON THE NEXT LAUNCH` and `desktop as Wine sees it: 1920x1080`
 * three lines apart, and nothing compared them.
 *
 * A virtual desktop cannot be resized from inside the process it already contains
 * (s100), so this is not an error to refuse -- it is a mode that arrives one launch
 * early. Run at the size the screen really is, and say that the next launch gets what
 * was asked for. */
static void launch_mode_check(int dw, int dh)
{
    if (!g_launch_w || !g_launch_h || !dw || !dh) return;

    if ((int)g_launch_w <= dw && (int)g_launch_h <= dh) return;

    logf_("[x] ADOPTED MODE DOES NOT FIT. The launch monitor is %lux%lu but the screen"
          " this process actually has is %dx%d -- the game would render nothing at all,"
          " which sounds like a crash and is not one.",
          (unsigned long)g_launch_w, (unsigned long)g_launch_h, dw, dh);
    if (g_vd_arm_w && (g_vd_arm_w != (DWORD)dw || g_vd_arm_h != (DWORD)dh))
        logf_("    A %lux%lu virtual desktop is armed and takes effect on the NEXT launch"
              " (FINDINGS 100) -- the desktop exists before this process does. This launch"
              " runs at %dx%d; start it again to get %lux%lu.",
              (unsigned long)g_vd_arm_w, (unsigned long)g_vd_arm_h, dw, dh,
              (unsigned long)g_vd_arm_w, (unsigned long)g_vd_arm_h);
    else
        logf_("    Cause: the game was started for one monitor and opened on another."
              " Launch it from the monitor you want to play on.");
    g_launch_w = g_launch_h = 0;      /* let the picker choose one that fits */
}

static void unix_probe(void)
{
    static const char *cands[] = { "Z:\\usr\\bin\\xrandr", "Z:\\usr\\bin\\python3",
                                   "Z:\\usr\\bin\\touch", "Z:\\bin\\sh" };
    char unixdir[MAX_PATH], cmd[MAX_PATH * 2];
    size_t i;
    logf_("[*] [unix] probe: game dir as Windows sees it is '%s'", g_dir);
    for (i = 0; i < sizeof cands / sizeof *cands; i++) {
        DWORD at = GetFileAttributesA(cands[i]);
        logf_("  [unix] %-22s %s", cands[i],
              at == INVALID_FILE_ATTRIBUTES ? "NOT VISIBLE" : "visible");
    }
    /* Z: is the host root, so the game dir's unix path is g_dir without the drive,
     * with the slashes turned round. If g_dir is not on Z: we cannot name it and
     * the file-based proof is not available -- say so rather than guess a path. */
    if ((g_dir[0] == 'Z' || g_dir[0] == 'z') && g_dir[1] == ':') {
        const char *r = g_dir + 2;
        size_t n = 0;
        while (*r && n < sizeof unixdir - 1) {
            unixdir[n++] = (*r == '\\') ? '/' : *r;
            r++;
        }
        unixdir[n] = 0;
    } else {
        logf_("  [unix] game dir is not on Z: -- cannot derive a host path, so the"
              " file-based proof is skipped and only exec success is measured");
        unixdir[0] = 0;
    }

    if (unixdir[0]) {
        snprintf(cmd, sizeof cmd,
                 "start.exe /unix /usr/bin/touch \"%s/unix-probe-start.txt\"", unixdir);
        run_route("start /unix", cmd);
        snprintf(cmd, sizeof cmd,
                 "\"Z:\\usr\\bin\\touch\" \"%s/unix-probe-direct.txt\"", unixdir);
        run_route("direct Z:", cmd);
        /* Redirection is a SHELL feature and `start /unix` execs the binary
         * directly, so the first attempt handed ">" to xrandr as an argument and
         * it exited 1. Go through sh -c, and capture stderr too: "xrandr cannot
         * open the display" is the answer we are actually looking for. */
        snprintf(cmd, sizeof cmd,
                 "start.exe /unix /bin/sh -c \"/usr/bin/xrandr --query"
                 " > '%s/unix-probe-xrandr.txt' 2>&1;"
                 " echo DISPLAY=$DISPLAY >> '%s/unix-probe-xrandr.txt'\"",
                 unixdir, unixdir);
        run_route("xrandr", cmd);
        logf_("  [unix] verdict is the FILES, not these exit codes: look for"
              " unix-probe-*.txt beside the game.");
    }
}

static int install_cursor_probe(void)
{
    void *real = NULL;
    void *slot = hook_import("USER32.dll", "GetCursorPos", (void *)hook_GetCursorPos, &real);
    if (!slot) return 0;
    g_real_gcp = (GetCursorPos_t)real;
    g_gcp_slot = (GetCursorPos_t *)slot;
    logf_("[*] [cursor] probe armed: hooked USER32!GetCursorPos slot %p (real %p)."
          " One line per second, 60 max.", slot, real);
    return 1;
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
/* --- telemetry for the viewport fix (s88) ---------------------------------
 *
 * The Steam build shipped a patch that installed cleanly, logged four [+] lines,
 * and never executed one of its own stores: the return-address filter below was a
 * hardcoded GOG RVA, and on any other build the compare simply never matches. The
 * log said "applied" because that is written at PATCH time; whether the stub ever
 * FIRES is a different claim and nothing was making it.
 *
 * So the stub now counts. g_world_seen/g_world_lastret are recorded for every draw
 * that passes the size gate -- i.e. every plausible main-viewport draw, whatever it
 * returns to -- which means a filter that matches nothing still tells us the address
 * it should have been looking for, in the same run that failed. */
static volatile DWORD g_world_seen;      /* draws that passed the size gate      */
static volatile DWORD g_world_lastret;   /* where the last such draw returns to  */
static volatile DWORD g_world_fires;     /* draws the filter actually accepted   */
static DWORD          g_world_callsite;  /* what the filter is looking for       */

static DWORD WINAPI worldfix_watch_thread(LPVOID p)
{
    int i;
    (void)p;
    /* Three minutes: long enough to cover the menu, a scenario pick and a map load
     * on a slow disk. The world is not drawn at all until a map is running, so a
     * verdict before that would be meaningless. */
    for (i = 0; i < 360; i++) {
        Sleep(500);
        if (g_world_fires) {
            logf_("[+] [worldfix] FIRING -- %lu world draw(s) corrected",
                  (unsigned long)g_world_fires);
            return 0;
        }
    }
    if (g_world_seen)
        logf_("[x] [worldfix] INSTALLED BUT NEVER FIRED. %lu draw(s) passed the size"
              " gate and the last returned to %08x, but the filter wants %08x --"
              " so the terrain is being painted at its stock size. That address is"
              " this build's world call site: the signature did not match it.",
              (unsigned long)g_world_seen, (unsigned)g_world_lastret,
              (unsigned)g_world_callsite);
    else
        logf_("[x] [worldfix] INSTALLED BUT NEVER FIRED, and NO draw passed the size"
              " gate either -- so either no map was loaded during this run, or the"
              " painter signature matched the wrong function.");
    return 0;
}

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
    BYTE *stub = (BYTE *)VirtualAlloc(NULL, 256, MEM_COMMIT | MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);
    if (!stub) { logf_("[x] world painter: VirtualAlloc failed"); return 0; }

    /* The world's call INTO the painter is indirect -- `lea ecx,[esi+0x7a]; call edi`
     * -- so it cannot be found by scanning for a call rel32 that targets the painter,
     * which is why this was a hardcoded RVA and why it silently did nothing on the
     * Steam build (s88). Match the call site itself instead, wildcarding the one
     * absolute operand in it, and read the return address out of the match. The two
     * `push 0` are what separate this site from the two other `lea ecx,[esi+0x7a];
     * call edi` pairs in the same function. */
    static const BYTE CALL_SIG[] = { 0x6a,0x00, 0x6a,0x00, 0x51, 0x03,0x50,0x11, 0x52,
                                     0xba, 0,0,0,0,
                                     0x8d,0x4e,0x7a, 0xff,0xd7 };
    static const BYTE CALL_MSK[] = { 1,1, 1,1, 1, 1,1,1, 1,
                                     1, 0,0,0,0,
                                     1,1,1, 1,1 };
    DWORD callsite;
    BYTE *cs = find_unique_masked(CALL_SIG, CALL_MSK, sizeof CALL_SIG,
                                  g_text, g_textlen, "world call site");
    if (cs) {
        callsite = (DWORD)(SIZE_T)(cs + sizeof CALL_SIG);
        logf_("[*] world call site derived by signature: returns to %08x",
              (unsigned)callsite);
    } else {
        callsite = (DWORD)(SIZE_T)(g_base + 0x10b15b);
        logf_("[!] world call site: signature did NOT match -- falling back to the"
              " hardcoded GOG address %08x. On a different build this filter will"
              " reject every draw and the fix will not fire; the [worldfix] line"
              " later in this log says which happened.", (unsigned)callsite);
    }
    g_world_callsite = callsite;
    BYTE *ret_to = at + 7;
    int i = 0, fix_top, fix_gate = -1, fix_img = -1, fix_obj = -1, fix_ih = -1, fix_h = -1;
    (void)fix_img; (void)fix_obj; (void)fix_ih; (void)fix_h;

    stub[i++]=0x50;                                                   /* push eax          */
    stub[i++]=0x8b; stub[i++]=0x44; stub[i++]=0x24; stub[i++]=0x04;   /* mov eax,[esp+4]   */

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

    /* Telemetry, recorded BEFORE the return-address filter and only for draws big
     * enough to be the main viewport (s88). This is what turns "the fix did not
     * work" into "the fix was looking for %08x and this build calls from %08x",
     * without a second run and without a debugger. */
    {
        DWORD a;
        a = (DWORD)(SIZE_T)&g_world_seen;
        stub[i++]=0xff; stub[i++]=0x05; memcpy(stub+i,&a,4); i+=4;    /* inc [g_world_seen]   */
        a = (DWORD)(SIZE_T)&g_world_lastret;
        stub[i++]=0xa3;                 memcpy(stub+i,&a,4); i+=4;    /* mov [g_lastret],eax  */
    }

    stub[i++]=0x3d; memcpy(stub+i,&callsite,4); i+=4;                 /* cmp eax,callsite  */
    stub[i++]=0x75; fix_top=i++;                                      /* jne skip          */
    {
        DWORD a = (DWORD)(SIZE_T)&g_world_fires;
        stub[i++]=0xff; stub[i++]=0x05; memcpy(stub+i,&a,4); i+=4;    /* inc [g_world_fires]  */
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
    CloseHandle(CreateThread(NULL, 0, worldfix_watch_thread, NULL, 0, NULL));
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
static volatile DWORD g_chr_hits;
static volatile DWORD g_chr_rect, g_chr_pos;
static volatile DWORD g_chr_ox, g_chr_oy;
static volatile DWORD g_chr_zero;
/* Absolute writes, learned once and replayed every frame.  The rect is write-once
 * (the pre-draw is not called per frame, so s58's guard patch did not make it
 * recompute), and every relative edit this project has tried either compounded or
 * stuck.  Writing a REMEMBERED ABSOLUTE value is idempotent whatever the engine
 * does, so a phase can be entered and left without damaging anything. */
static volatile DWORD g_chr_base;
static volatile DWORD g_chr_apply, g_chr_setx, g_chr_sety, g_chr_setcx, g_chr_setcy;
static volatile DWORD g_chr_dirty;
static float g_chr_fx = 2.0f, g_chr_fy = 2.0f;
static const DWORD CHR_ART_W[5] = { 640, 800, 1024, 1280, 1600 };
static const DWORD CHR_ART_H[5] = { 480, 600,  768, 1024, 1200 };

/* The factors MUST be correct before the game first builds a window, and run O
 * proves a delayed poll is not good enough: hudprobe_thread sleeps Delay seconds
 * before its first update, the map loaded inside that window, and FUN_00502510 --
 * which runs ONCE (s53.2) -- consumed the 2.0f static initialiser at slot 0 where
 * the right value is 5.0.  The bar's rect came out 1280x404 instead of 3200x1010,
 * the log printed that verbatim, and it then persisted through every F2.
 *
 * So: start at DLL load, poll at 50 ms, and on a slot change raise a dirty flag
 * that makes the stub zero the path-B rect for half a second -- which forces the
 * pre-draw back down the path-B branch so the rect is recomputed with the new art
 * set's factors instead of keeping one computed for the old one. */
static DWORD WINAPI chrome_factor_thread(LPVOID unused)
{
    (void)unused;
    DWORD last = 0xffffffff, clear_at = 0;
    for (;;) {
        DWORD cfg = wfb_read32(0x612fec), sl = 0xffffffff;
        if (cfg && !IsBadReadPtr((void *)(SIZE_T)cfg, 0x1c))
            memcpy(&sl, (BYTE *)(SIZE_T)(cfg + 0x18), 4);
        if (sl < 5) {
            if (sl != last) {
                g_chr_fx = 3200.0f / (float)CHR_ART_W[sl];
                g_chr_fy = 2400.0f / (float)CHR_ART_H[sl];
                g_chr_dirty = 0;  /* superseded by patch_pathb_recompute */
                clear_at = GetTickCount() + 500;
                logf_("  [chrome] slot %lu (art %ux%u) -> factors %.4f / %.4f;"
                      " path-B rects invalidated for 500 ms so they recompute",
                      (unsigned long)sl, (unsigned)CHR_ART_W[sl], (unsigned)CHR_ART_H[sl],
                      g_chr_fx, g_chr_fy);
                last = sl;
            } else if (g_chr_dirty && GetTickCount() >= clear_at) {
                g_chr_dirty = 0;
            }
        }
        Sleep(50);
    }
}
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
static const BYTE CSCALE_SIG[] = { 0x83,0xec,0x14, 0x56, 0x8b,0xf1,
                                   0x8b,0x86,0x90,0x00,0x00,0x00, 0x85,0xc0, 0x0f,0x84 };

/* s58: make the path-B rect RECOMPUTE every frame.
 *
 * FUN_005025e0 decides path A vs path B by testing the LIVE rect:
 *      cmp WORD [esi+0x0f],0 ; je pathB ; cmp WORD [esi+0x11],0 ; jne pathA
 * so once FUN_00502510 has written a non-zero rect the widget never revisits
 * path B and the rect is write-once (s53.2).  Every destructive edit this project
 * has made -- run M's compounding multiply, run Q's zeroed position -- has been a
 * mutation of a write-once field, and each one was permanent because nothing
 * recomputes.  That is five failures of one shape.
 *
 * Testing the AUTHORED rect at +0x50/+0x52 instead of the live one at +0x0f/+0x11
 * fixes the class rather than the instance:
 *   - path-A widgets (authored rect non-zero) still take path A, unchanged;
 *   - path-B widgets (authored rect 0x0) take path B EVERY FRAME.
 * The rect is then recomputed from the sprite each frame, so any edit made in the
 * draw is transient by construction and cannot accumulate or persist.  It is also
 * closer to what a path-B widget means: "derive my rect from the art", not
 * "derive it once and keep it forever".
 *
 * Two displacement bytes.  The guard pattern also occurs at 0x518076 in class 1's
 * pre-draw, so it is located from the verified-unique FUN_00502510 anchor rather
 * than by searching for it. */
static int patch_pathb_recompute(BYTE *layout_fn)
{
    static const BYTE G[13] = { 0x66,0x83,0x7e,0x0f,0x00, 0x74,0x07,
                                0x66,0x83,0x7e,0x11,0x00, 0x75 };
    BYTE *g = layout_fn + 0xd3;
    if (memcmp(g, G, sizeof G) != 0) {
        logf_("[x] [chrome] path-A/B guard not where expected (%p) -- REFUSING", g);
        return 0;
    }
    BYTE lo = 0x50, hi = 0x52;
    if (!poke(g + 3, &lo, 1) || !poke(g + 10, &hi, 1)) {
        logf_("[x] [chrome] path-A/B guard not writable"); return 0;
    }
    logf_("[+] [chrome] path-A/B guard at %p now tests the AUTHORED rect (+0x50/+0x52)"
          " instead of the live one -- path-B widgets recompute every frame, so edits"
          " cannot persist", g);
    return 1;
}

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
    return patch_pathb_recompute(fn);
}


/* FINDINGS section 65: the F2 settings tabs' ROTATED-TEXT geometry, which is
 * HARD-CODED here -- no .WIN file is consulted for this window.  (The almanac's
 * tabs are a different call site, 0x40741e, and may well be data-driven; these
 * are not.  Three runs' worth of loose .WIN overrides did nothing because of it.)
 *
 * The tab plate is blitted at (edi, esi) = (x, y) in the virtual 3200x2400 space,
 * and the rotated label's box and clip are then computed from the SAME x/y with
 * three immediates:
 *
 *   call <blit>                 ; draws the tab plate at (x, y)
 *   lea  ebx,[esi+5]            ; arg4 = text box Y origin      <- DY
 *   add  esi,0x123              ; clip bottom = y + 291         <- ClipH
 *   ...
 *   lea  ecx,[edi+3]            ; arg3 = text box X origin      <- DX
 *
 * FUN_00450b10 CENTRES the string inside the box, so DY is the lever that MOVES
 * the label; ClipH only decides where it gets cut off.  Measured at 1920x1080:
 * clip height 291 * (1080/2400) = 131 px against a ~106 px plate, so the label is
 * centred in a box 25 px taller than the tab it sits on and hangs ~12 px out the
 * bottom -- the 11% the project owner reported.
 *
 * DY is a SIGNED BYTE displacement, so the usable range is -128..127 virtual
 * units = -57..+57 px at 1080.  To move the label N px up at height H:
 *   DY = 5 - N * 2400 / H .
 *
 * Every value is left stock unless the ini names it, so a partial section varies
 * exactly what it says and nothing else. */
static int patch_vtext(int dy, int dx, int cliph, int have_dy, int have_dx, int have_cliph)
{
    /* call rel32 wildcarded; every other byte literal. */
    static const BYTE pat[]  = { 0xe8,0x00,0x00,0x00,0x00, 0x8d,0x5e,0x05,
                                 0x81,0xc6,0x23,0x01,0x00,0x00, 0x89,0x74,0x24,0x20,
                                 0xdb,0x44,0x24,0x20, 0x6a,0x01, 0x8d,0x4f,0x03,
                                 0x68,0xff,0x00,0x00,0x00 };
    static const BYTE mask[] = { 1,0,0,0,0, 1,1,1,
                                 1,1,1,1,1,1, 1,1,1,1,
                                 1,1,1,1, 1,1, 1,1,1,
                                 1,1,1,1,1 };
    /* DELIBERATELY NOT find_unique_masked.  There are TWO matches, and both are
     * wanted: 0x4916f5 is the F2 settings tabs and 0x407375 is the almanac's.
     * The two windows share this layout code verbatim, so one signature fixes
     * both.  Refusing on non-uniqueness would have been exactly wrong here. */
    BYTE *sites[8];
    int nsites = 0;
    for (SIZE_T i = 0; i + sizeof pat <= g_textlen; i++) {
        SIZE_T j = 0;
        for (; j < sizeof pat; j++)
            if (mask[j] && g_text[i + j] != pat[j]) break;
        if (j != sizeof pat) continue;
        if (nsites == 8) { logf_("[x] [vtext] more than 8 matches -- signature too loose, refusing"); return 0; }
        sites[nsites++] = g_text + i;
    }
    if (!nsites) { logf_("[x] [vtext] tab-layout signature not found"); return 0; }
    logf_("[*] [vtext] %d tab-layout site(s) found", nsites);
    for (int k = 0; k < nsites; k++)
        logf_("      [%d] %p: box Y +%d, box X +%d, clip H %u", k, (void *)sites[k],
              (int)(signed char)sites[k][7], (int)(signed char)sites[k][26],
              (unsigned)rd32(sites[k] + 10));

    int n = 0;
    for (int k = 0; k < nsites; k++) {
    BYTE *hit = sites[k];
    if (have_dy) {
        signed char v = (signed char)dy;
        if (poke(hit + 7, &v, 1)) { logf_("  [+] box Y origin: +5 -> %+d virtual", (int)v); n++; }
        else { logf_("  [x] box Y origin: VirtualProtect failed"); return 0; }
    }
    if (have_dx) {
        signed char v = (signed char)dx;
        if (poke(hit + 26, &v, 1)) { logf_("  [+] box X origin: +3 -> %+d virtual", (int)v); n++; }
        else { logf_("  [x] box X origin: VirtualProtect failed"); return 0; }
    }
    if (have_cliph) {
        DWORD v = (DWORD)cliph;
        if (poke(hit + 10, &v, 4)) { logf_("  [+] clip height: 291 -> %u virtual", (unsigned)v); n++; }
        else { logf_("  [x] clip height: VirtualProtect failed"); return 0; }
    }
    }
    if (!n) {
        /* A patch that changes nothing applies "cleanly" and teaches nothing --
         * the section 54 failure mode.  Refuse instead. */
        logf_("[*] [vtext] no DY/DX/ClipH given -- geometry left STOCK (probe-only run)");
        return 1;
    }
    logf_("[*] [vtext] %d write(s) across %d site(s)", n, nsites);
    return 1;
}


/* ------------------------------------------------------------------ s65 probe
 *
 * WHY A PROBE.  DY moves the rotated tab label DOWN but not UP at 1920x1080,
 * while at the stock modes it moves both ways, and ClipH reaches the label at
 * every resolution.  Something clamps the placement, and 0x60bc38 (the outer
 * clip top) has 19 writers, so static analysis cannot say which one is live.
 * Rather than guess a fifth time, log what FUN_00450b10 is ACTUALLY handed.
 *
 * Both tab-layout sites carry the draw call at exactly site+0xA9, so one
 * trampoline serves both.  The call is redirected to a stub that logs the
 * seventeen stack arguments and then tail-jumps to the original target with the
 * stack byte-for-byte as the callee expects it -- pushad/popad restore ECX, which
 * carries `this`, and the return address is left untouched so the callee still
 * returns to the real call site.
 *
 * The two virtual->pixel scale factors are read out of the site's own `fmul`
 * operands (site+0x22 and site+0x49), NOT hardcoded, so the probe survives a
 * build whose globals moved -- the same rule the signatures follow. */

/* (declared with the movie-probe state above) */
static int   g_vt_logged;                 /* rate limit: this is a per-frame path */

/* The label is END-ANCHORED at the box bottom: measured at 1920x1080 the box runs
 * y 136..250 px and the label 161..250, i.e. its tail sits exactly on the box
 * bottom and it grows upward.  The tab PLATE, however, is only 106 px (136..242),
 * so the box is 9 px taller than the art and the tail hangs past the tab.  Shrink
 * the box and the label rises with it -- `h` is the lever, and it arrives here as
 * an argument, so no .WIN file and no immediate is involved.
 *
 * GATED ON THE MODE.  The correction is only right for the mode the art set was
 * generated for; the stock modes are correct as PopTop shipped them and must pass
 * through untouched.  The game climbs 640x480 -> ... -> target on every launch, so
 * an ungated patch visibly breaks every mode on the way up -- which is exactly what
 * the earlier DY immediate did. */
static void __cdecl vtext_hook(DWORD *a)
{
    if (g_vt_fix && g_vt_xs_va && g_vt_ys_va) {
        int w = (int)(*(float *)(SIZE_T)g_vt_xs_va * 3200.0f + 0.5f);
        int h = (int)(*(float *)(SIZE_T)g_vt_ys_va * 2400.0f + 0.5f);
        if (w == g_vt_fw && h == g_vt_fh) {
            if (g_vt_boxh)  a[5] = (DWORD)g_vt_boxh;         /* box height */
            if (g_vt_boxdy) {
                /* TRANSLATE, don't resize.  Resizing moves the box bottom, which is
                 * both the label's anchor AND the clip floor, so it trades overhang
                 * for a cut last letter -- measured: h=216 lifted the label 12 px and
                 * clipped it.  A constant shift moves the label rigidly and cannot
                 * clip, PROVIDED the clip moves with it: the clip rect is computed at
                 * the call site from the original y and arrives here as a[10..13], so
                 * shifting the box alone would leave the clip behind and re-crop. */
                float ys2 = *(float *)(SIZE_T)g_vt_ys_va;
                int dpx = (int)((double)g_vt_boxdy * ys2 + (g_vt_boxdy < 0 ? -0.5 : 0.5));
                a[3]  = (DWORD)((int)a[3] + g_vt_boxdy);
                a[11] = (DWORD)((int)a[11] + dpx);      /* clip top    */
                a[13] = (DWORD)((int)a[13] + dpx);      /* clip bottom */
            }
            /* MAKE THE CLIP FOLLOW THE BOX.  The clip arrives precomputed from the
             * call site's own immediates, so shifting it by BoxDY alone lets it drift
             * ABOVE the box and become the binding constraint -- measured: BoxH=336
             * with BoxDY=-107 put the passed clip floor at 219 against a box bottom of
             * 238, so a TALLER box clipped MORE.  Widen the clip past the box in both
             * directions and let FUN_00450b10's own intersection (clipT = max(clipT,
             * boxY); clipB = min(clipB, boxY+boxH-1)) pin it exactly to the box. */
            /* BoxDX is the same rigid translation on the other axis.  It is applied
             * before the clip is rebuilt below, so the clip follows it for free --
             * which is the whole reason the horizontal move is done here rather than
             * through the DX immediate at site+26.  That immediate is NOT mode-gated
             * and would move the label in every stock mode the F2 ladder climbs. */
            if (g_vt_boxdx) a[2] = (DWORD)((int)a[2] + g_vt_boxdx);

            if (g_vt_boxh || g_vt_boxdy || g_vt_boxdx) {
                float ys3 = *(float *)(SIZE_T)g_vt_ys_va;
                float xs3 = *(float *)(SIZE_T)g_vt_xs_va;
                int top = (int)((double)(int)a[3] * ys3);
                int bot = top + (int)((double)(int)a[5] * ys3) - 1;
                int lft = (int)((double)(int)a[2] * xs3);
                int rgt = lft + (int)((double)(int)a[4] * xs3) - 1;
                a[11] = (DWORD)(top - 4);
                a[13] = (DWORD)(bot + 4);
                a[10] = (DWORD)(lft - 4);
                a[12] = (DWORD)(rgt + 4);
            }
        }
    }
    /* DEDUPE, not a plain counter.  This is a per-frame path, so a simple cap
     * fills up on the FIRST resolution and never reaches the one under test --
     * which is exactly what the first probe run did.  Log each DISTINCT
     * (y, clipT, scale) once instead, so every mode the user climbs through
     * contributes its three tabs and nothing repeats. */
    if (!g_vt_log) return;
    static DWORD seen[96][3];
    DWORD key0 = a[3], key1 = a[11], key2 = g_vt_ys_va ? *(DWORD *)(SIZE_T)g_vt_ys_va : 0;
    for (int i = 0; i < g_vt_logged; i++)
        if (seen[i][0] == key0 && seen[i][1] == key1 && seen[i][2] == key2) return;
    if (g_vt_logged >= 96) return;
    seen[g_vt_logged][0] = key0; seen[g_vt_logged][1] = key1; seen[g_vt_logged][2] = key2;
    g_vt_logged++;
    float ys = g_vt_ys_va ? *(float *)(SIZE_T)g_vt_ys_va : 0.0f;
    float xs = g_vt_xs_va ? *(float *)(SIZE_T)g_vt_xs_va : 0.0f;
    /* a[0]=canvas a[1]=str a[2]=x a[3]=y a[4]=w a[5]=h a[6]=? a[7]=? a[8]=?
     * a[9]=clipflag a[10..13]=clipL,T,R,B (already PIXELS) a[14]=? a[15]=alpha
     * a[16]=mode.  x/y/w/h are VIRTUAL; the clip is not. */
    logf_("  [vt] x=%d y=%d w=%d h=%d | clip L=%d T=%d R=%d B=%d flag=%d mode=%d",
          (int)a[2], (int)a[3], (int)a[4], (int)a[5],
          (int)a[10], (int)a[11], (int)a[12], (int)a[13], (int)a[9], (int)a[16]);
    logf_("       -> MODE %dx%d | box px y=%d h=%d  (ys=%.5f xs=%.5f)  box bottom=%d  clipT-boxY=%d",
          (int)(xs * 3200.0f + 0.5f), (int)(ys * 2400.0f + 0.5f),
          (int)((double)(int)a[3] * ys), (int)((double)(int)a[5] * ys), ys, xs,
          (int)((double)((int)a[3] + (int)a[5]) * ys),
          (int)a[11] - (int)((double)(int)a[3] * ys));
}

static int patch_vtext_probe(void)
{
    static const BYTE pat[]  = { 0xe8,0x00,0x00,0x00,0x00, 0x8d,0x5e,0x05,
                                 0x81,0xc6,0x23,0x01,0x00,0x00, 0x89,0x74,0x24,0x20,
                                 0xdb,0x44,0x24,0x20, 0x6a,0x01, 0x8d,0x4f,0x03,
                                 0x68,0xff,0x00,0x00,0x00 };
    static const BYTE mask[] = { 1,0,0,0,0, 1,1,1,
                                 1,1,1,1,1,1, 1,1,1,1,
                                 1,1,1,1, 1,1, 1,1,1,
                                 1,1,1,1,1 };
    BYTE *sites[8]; int n = 0;
    for (SIZE_T i = 0; i + sizeof pat <= g_textlen; i++) {
        SIZE_T j = 0;
        for (; j < sizeof pat; j++) if (mask[j] && g_text[i + j] != pat[j]) break;
        if (j == sizeof pat && n < 8) sites[n++] = g_text + i;
    }
    if (!n) { logf_("[x] [vtprobe] no tab-layout sites"); return 0; }

    /* scale-factor VAs, read from the site's own fmul operands */
    g_vt_ys_va = rd32(sites[0] + 0x22);
    g_vt_xs_va = rd32(sites[0] + 0x49);
    logf_("[*] [vtprobe] yscale @%08x  xscale @%08x", g_vt_ys_va, g_vt_xs_va);

    int ok = 0;
    for (int k = 0; k < n; k++) {
        BYTE *call = sites[k] + 0xA9;
        if (*call != 0xE8) { logf_("  [x] site %d: no call at +0xA9", k); continue; }
        BYTE *target = call + 5 + (INT_PTR)(int)rd32(call + 1);
        /* The call lands on a jump thunk; follow it so the entry probe can detour
         * the real wrapper rather than the five bytes of the thunk. */
        if (!g_vte_entry_va) {
            BYTE *w = target;
            for (int hop = 0; hop < 4 && *w == 0xE9; hop++) w = w + 5 + (INT_PTR)(int)rd32(w + 1);
            g_vte_entry_va = (DWORD)(SIZE_T)w;
        }

        BYTE *tr = (BYTE *)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!tr) { logf_("  [x] site %d: VirtualAlloc failed", k); continue; }
        int o = 0;
        tr[o++] = 0x60;                                   /* pushad              */
        tr[o++] = 0x9C;                                   /* pushfd              */
        tr[o++] = 0x8D; tr[o++] = 0x44; tr[o++] = 0x24; tr[o++] = 0x28; /* lea eax,[esp+0x28] */
        tr[o++] = 0x50;                                   /* push eax            */
        tr[o++] = 0xB8; { DWORD f = (DWORD)(SIZE_T)&vtext_hook; memcpy(tr + o, &f, 4); o += 4; }
        tr[o++] = 0xFF; tr[o++] = 0xD0;                   /* call eax            */
        tr[o++] = 0x83; tr[o++] = 0xC4; tr[o++] = 0x04;   /* add esp,4           */
        tr[o++] = 0x9D;                                   /* popfd               */
        tr[o++] = 0x61;                                   /* popad               */
        tr[o++] = 0xE9; { DWORD r = (DWORD)(SIZE_T)(target - (tr + o + 4)); memcpy(tr + o, &r, 4); o += 4; }

        DWORD rel = (DWORD)(SIZE_T)(tr - (call + 5));
        if (poke(call + 1, &rel, 4)) {
            logf_("  [+] site %d: call %p -> trampoline %p (orig %p)", k, (void *)call, (void *)tr, (void *)target);
            ok++;
        } else logf_("  [x] site %d: VirtualProtect failed", k);
    }
    return ok > 0;
}

/* ------------------------------------------------- s66 rotated-text ENTRY probe
 *
 * WHY A SECOND PROBE.  patch_vtext_probe() hooks the two tab-layout CALL SITES, so
 * it can only ever see the two panels whose layout matches that signature.  The
 * owner reports the building panel's contextual label (Owners / Wages / Rent) as
 * rotated too, which the call-site probe cannot confirm or refute -- absence of a
 * log line there means "not one of those two sites", not "not rotated".
 *
 * Static analysis says the rotated drawer FUN_00450b10 has exactly one caller
 * (FUN_004526d0), that FUN_004526d0 has exactly four callers, and that NEITHER
 * address appears as data anywhere in the image -- so no function pointer can
 * reach it.  That is a strong claim and it deserves a measurement rather than an
 * argument, because it is exactly the claim the owner's screenshots contradict.
 *
 * So hook the WRAPPER'S ENTRY.  Every rotated draw in the game passes through it,
 * whatever called it, and the return address on entry names the call site.  Open
 * the building panel and the log answers the question outright:
 *   - a line with a caller outside the two tab sites -> it IS rotated, from there
 *   - no new line at all                             -> it is NOT this path
 *
 * The wrapper's first instruction is `mov eax,0x3aa4`, exactly five bytes, so the
 * detour relocates cleanly with no instruction-boundary guesswork.  The wrapper is
 * found by following the call at site+0xA9 through its jump thunk, so no address is
 * hardcoded -- the same build-independence rule the signatures follow. */

static int   g_vte_logged;

static void __cdecl vtentry_hook(DWORD *a)
{
    /* a[0] = return address (the call site); the arguments follow.  Named from the
     * first run's dump, cross-checked against the call-site probe's view of the
     * same draw: the tab site logged x=2326 y=304 w=88 h=256 in BOTH probes. */
    #define VTE_X    3
    #define VTE_Y    4
    #define VTE_W    5
    #define VTE_H    6
    #define VTE_ROT  7
    #define VTE_CLPT 12
    #define VTE_CLPB 14

    /* DEDUPE ON (caller, y, scale), NOT on the caller alone.  Keying on the return
     * address logged each site exactly once -- at 640x480, the first mode the F2
     * ladder passes through -- and then suppressed every later draw, including all
     * of the ones at the mode actually under test.  Same trap the call-site probe
     * already hit once; same fix. */
    /* ---- the correction for the ROT=2 site (building panel: Owners/Wages/Rent).
     *
     * Measured 2026-08-21: this site passes NO clip -- the caller hands it the whole
     * screen (T=0 B=1080) -- so nothing outside the drawer is cropping the label.
     * The only thing that can cut it is the drawer's own box intersection at
     * 0x450cf6, which clamps the clip to the box.  The box is therefore the lever,
     * exactly as it was for the tabs.
     *
     * GATED ON rot==2, not on a return address.  The tabs come through this same
     * entry with rot==3 and are already corrected at their call sites; keying on the
     * rotation mode keeps the two corrections from ever touching each other and
     * survives a build where the call site moved.
     *
     * GATED ON THE MODE for the same reason the tab fix is: the stock modes are
     * right as PopTop shipped them, and the F2 ladder climbs through them on every
     * launch. */
    if (g_vt_fix && (g_vt_bdh || g_vt_bdy) && a[VTE_ROT] == 2
        && g_vt_xs_va && g_vt_ys_va) {
        int mw = (int)(*(float *)(SIZE_T)g_vt_xs_va * 3200.0f + 0.5f);
        int mh = (int)(*(float *)(SIZE_T)g_vt_ys_va * 2400.0f + 0.5f);
        if (mw == g_vt_fw && mh == g_vt_fh) {
            a[VTE_H] = (DWORD)((int)a[VTE_H] + g_vt_bdh);
            a[VTE_Y] = (DWORD)((int)a[VTE_Y] + g_vt_bdy);
        }
    }

    if (!g_vt_log) return;

    static DWORD seen[64][3];
    DWORD ret = a[0];
    DWORD k1 = a[VTE_Y], k2 = g_vt_ys_va ? *(DWORD *)(SIZE_T)g_vt_ys_va : 0;
    for (int i = 0; i < g_vte_logged; i++)
        if (seen[i][0] == ret && seen[i][1] == k1 && seen[i][2] == k2) return;
    if (g_vte_logged >= 64) return;
    seen[g_vte_logged][0] = ret; seen[g_vte_logged][1] = k1; seen[g_vte_logged][2] = k2;
    g_vte_logged++;

    float ys = g_vt_ys_va ? *(float *)(SIZE_T)g_vt_ys_va : 0.0f;
    float xs = g_vt_xs_va ? *(float *)(SIZE_T)g_vt_xs_va : 0.0f;

    /* The string, so the log says WAGES rather than a heap pointer.  Read defensively:
     * a[2] is only ASSUMED to be a char*, and a wrong guess here would fault inside a
     * probe whose whole job is to be safe to leave running. */
    char txt[24]; txt[0] = 0;
    {
        const char *p = (const char *)(SIZE_T)a[2];
        if (!IsBadReadPtr(p, 1)) {
            int n = 0;
            while (n < 23 && !IsBadReadPtr(p + n, 1) && p[n] >= 32 && p[n] < 127) { txt[n] = p[n]; n++; }
            txt[n] = 0;
        }
    }

    logf_("  [vte] ret=%08x \"%s\" rot=%d | box x=%d y=%d w=%d h=%d | clip T=%d B=%d",
          ret, txt, (int)a[VTE_ROT],
          (int)a[VTE_X], (int)a[VTE_Y], (int)a[VTE_W], (int)a[VTE_H],
          (int)a[VTE_CLPT], (int)a[VTE_CLPB]);
    logf_("        -> MODE %dx%d  box px y=%d h=%d  bottom=%d  (ys=%.5f xs=%.5f)",
          (int)(xs * 3200.0f + 0.5f), (int)(ys * 2400.0f + 0.5f),
          (int)((double)(int)a[VTE_Y] * ys), (int)((double)(int)a[VTE_H] * ys),
          (int)((double)((int)a[VTE_Y] + (int)a[VTE_H]) * ys), ys, xs);
}

static int patch_vtext_entry(void)
{
    if (!g_vte_entry_va) {
        logf_("[x] [vtentry] wrapper address unknown -- the call-site scan must run first");
        return 0;
    }
    BYTE *entry = (BYTE *)(SIZE_T)g_vte_entry_va;
    /* Refuse unless the first instruction is the expected 5-byte `mov eax,imm32`.
     * A different build could open with something else, and relocating the wrong
     * five bytes would corrupt the function silently. */
    if (entry[0] != 0xB8) {
        logf_("[x] [vtentry] %08x does not open with `mov eax,imm32` (%02x) -- refusing",
              g_vte_entry_va, entry[0]);
        return 0;
    }
    BYTE *tr = (BYTE *)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tr) { logf_("[x] [vtentry] VirtualAlloc failed"); return 0; }
    int o = 0;
    tr[o++] = 0x60;                                                 /* pushad             */
    tr[o++] = 0x9C;                                                 /* pushfd             */
    tr[o++] = 0x8D; tr[o++] = 0x44; tr[o++] = 0x24; tr[o++] = 0x24; /* lea eax,[esp+0x24] */
    tr[o++] = 0x50;                                                 /* push eax           */
    tr[o++] = 0xB8; { DWORD f = (DWORD)(SIZE_T)&vtentry_hook; memcpy(tr + o, &f, 4); o += 4; }
    tr[o++] = 0xFF; tr[o++] = 0xD0;                                 /* call eax           */
    tr[o++] = 0x83; tr[o++] = 0xC4; tr[o++] = 0x04;                 /* add esp,4          */
    tr[o++] = 0x9D;                                                 /* popfd              */
    tr[o++] = 0x61;                                                 /* popad              */
    memcpy(tr + o, entry, 5); o += 5;                               /* relocated mov eax  */
    tr[o++] = 0xE9; { DWORD r = (DWORD)(SIZE_T)((entry + 5) - (tr + o + 4)); memcpy(tr + o, &r, 4); o += 4; }

    BYTE det[5];
    det[0] = 0xE9;
    { DWORD r = (DWORD)(SIZE_T)(tr - (entry + 5)); memcpy(det + 1, &r, 4); }
    if (!poke(entry, det, 5)) { logf_("[x] [vtentry] VirtualProtect failed"); return 0; }
    logf_("[+] [vtentry] wrapper %08x detoured -> %p (logs EVERY rotated draw and its caller)",
          g_vte_entry_va, (void *)tr);
    return 1;
}

/* ------------------------------------------------- s87.2 the readout colour
 *
 * The four bottom-bar readouts are grey and hard to read. They are NOT four
 * problems: the probe above caught all four coming from ONE call site as a 2x2
 * grid, and three of them carry an inline colour tag in the string itself --
 *
 *     x=2571 y=2091  "[C2]$10,000"      x=2863 y=2091  "Jan 1950"
 *     x=2571 y=2171  "[C2]$0"           x=2863 y=2171  "[C2]30"
 *
 * The engine's text has a markup language. FUN_00452330 switches on `letter-0x43`
 * through a jump table, so `[Cn]` parses n as one or two decimal digits and looks
 * the colour up in a table of 16-bit words, then stores it into the current style
 * record. Entry 0 is 0x7fff = white, entry 2 is 0x6318 = RGB555 (197,197,197) --
 * the grey. So the fix is ONE WORD, not a rewrite of anything.
 *
 * THE DATE IS UNTAGGED AND STILL GOES WHITE. It is drawn third, after two [C2]
 * draws, and the style persists in the record, so it inherits whatever entry 2
 * holds. That is why repainting the palette entry fixes all four while retagging
 * the three strings would only reliably fix three.
 *
 * BLAST RADIUS, CHECKED RATHER THAN ASSUMED: exactly five `[C2]` format strings
 * exist in the image. Three are these readouts; the other two sit in a
 * `[hjr]/[hjl]` markup string and next to `GAME%02d.MP3`, neither of which is
 * bottom-bar UI. Every other tagged string uses [C0]/[C1]/[C5]/[C6].
 *
 * The table is NOT hardcoded. Its address is read out of the operand of the
 * `mov cx,[table+eax*2]` that performs the lookup, so a build whose data moved
 * still patches -- the same rule every other signature here follows. */
static int patch_readout_colour(int want)
{
    static const BYTE SIG[] = { 0x8d,0x04,0x80, 0x8d,0x04,0x42, 0x83,0xc1,0x05,
                                0xeb,0x03, 0x83,0xc1,0x04, 0x89,0x0f,
                                0x39,0x74,0x24,0x34, 0x75,0x21, 0x66,0x8b,0x0c,0x45 };
    BYTE *at = find_unique(SIG, sizeof SIG, g_text, g_textlen, "[C] colour lookup");
    if (!at) { logf_("[x] [text] colour-lookup signature not found"); return 0; }

    DWORD tbl = rd32(at + sizeof SIG);
    /* Sanity-check the operand before writing through it: a wrong table address is
     * a silent memory corruption, not a visible failure. Entry 0 is the engine's
     * white and is the cheapest thing to verify. */
    if (tbl < 0x400000 || tbl > 0x700000) {
        logf_("[x] [text] colour table operand %08x is not a plausible address", tbl);
        return 0;
    }
    WORD *pal = (WORD *)(SIZE_T)tbl;
    if (IsBadReadPtr(pal, 8) || pal[0] != 0x7fff) {
        logf_("[x] [text] colour table at %08x does not open with white (%04x) -- refusing",
              tbl, IsBadReadPtr(pal, 8) ? 0 : pal[0]);
        return 0;
    }
    WORD old = pal[2];
    WORD nw  = (WORD)want;
    if (old == nw) {
        logf_("[*] [text] readout colour already %04x -- nothing to do", nw);
        return 1;
    }
    if (!poke((BYTE *)&pal[2], (BYTE *)&nw, 2)) {
        logf_("[x] [text] VirtualProtect failed on the colour table"); return 0;
    }
    logf_("[+] [text] readout colour [C2] %04x -> %04x  (RGB555 %d,%d,%d -> %d,%d,%d)"
          " -- treasury, swiss bank, population, and the date by inheritance",
          old, nw,
          (old >> 10) & 31, (old >> 5) & 31, old & 31,
          (nw  >> 10) & 31, (nw  >> 5) & 31, nw  & 31);
    return 1;
}

/* ------------------------------------------------ s87 horizontal-text probe
 *
 * WHICH ARGUMENT CARRIES THE COLOUR OF THE BOTTOM-BAR READOUTS.
 *
 * The owner reports Treasury / Date / Swiss Bank / Population as grey and hard to read.
 * The colour CANNOT be in the art: every pixel of all 17 font assets is alpha-run class
 * (922150 of 922150, section 63.4), so a glyph is a pure opacity mask and whatever tints
 * it does so at draw time.
 *
 * FUN_00453ef0 is the horizontal string renderer (section 65.1), `thiscall` with SIXTEEN
 * stack arguments (`ret 0x40`), reached through the thunk at 0x4020db from exactly nine
 * call sites -- so ONE entry hook sees every horizontal draw and the return address names
 * the site. Same instrument that settled section 66.
 *
 * ROUND 1 GOT TWO THINGS WRONG, both recorded because they are the reusable part:
 *   - it assumed a1 was the string, since every site pushes the same 0x60c188. But the
 *     renderer reads 0x60c18c/0x60c18e as signed WORDs, so 0x60c188 is a small struct and
 *     every string logged empty.
 *   - it then deduped on that string's first byte, which was therefore CONSTANT, so
 *     distinct draws collapsed into each other: ten records for an entire map.
 * Round 1 did settle one thing: args 11..14 are a CLIP RECT (-1,-1,-1,-1 for none, or
 * 0,0,0xa00,0x5a0 = the full 2560x1440 screen), not a colour, and a16 varies 0xff/0xc4
 * which reads as alpha rather than colour.
 *
 * So round 2 stops guessing. Dedupe on (site, x, y) -- widgets differ by POSITION, which
 * is knowable without understanding the arguments -- and print a hex+ASCII window at every
 * argument that looks like a readable pointer, letting the text name itself. */

/* (g_txt_log is declared with the shared patch state above) */
static int   g_txt_logged;

static void __cdecl text_hook(DWORD this_, DWORD *a)
{
    if (!g_txt_log) return;

    static DWORD seen[64][3];
    DWORD k0 = a[0], k1 = a[3], k2 = a[4];
    for (int i = 0; i < g_txt_logged; i++)
        if (seen[i][0] == k0 && seen[i][1] == k1 && seen[i][2] == k2) return;
    if (g_txt_logged >= 64) return;
    seen[g_txt_logged][0] = k0; seen[g_txt_logged][1] = k1; seen[g_txt_logged][2] = k2;
    g_txt_logged++;

    logf_("  [txt] ret=%08x this=%08x  x=%d y=%d w=%d h=%d",
          a[0], this_, (int)a[3], (int)a[4], (int)a[5], (int)a[6]);
    logf_("        a1=%08x a2=%08x a7=%08x a8=%08x a9=%08x a10=%08x a15=%08x a16=%08x",
          a[1], a[2], a[7], a[8], a[9], a[10], a[15], a[16]);

    /* Any argument (and `this`) that points at readable memory gets a 24-byte window.
     * Read defensively: these are only ASSUMED to be pointers, and a probe that faults
     * is worse than one that prints nothing. */
    for (int k = 0; k <= 16; k++) {
        DWORD v = (k == 0) ? this_ : a[k];
        if (v < 0x10000) continue;
        const BYTE *q = (const BYTE *)(SIZE_T)v;
        if (IsBadReadPtr((void *)q, 24)) continue;
        char hex[96], asc[32];
        int hp = 0;
        for (int j = 0; j < 24; j++) {
            hp += snprintf(hex + hp, (size_t)(sizeof hex - hp), "%02x", q[j]);
            if ((j & 3) == 3 && j != 23) hp += snprintf(hex + hp, (size_t)(sizeof hex - hp), " ");
            asc[j] = (q[j] >= 32 && q[j] < 127) ? (char)q[j] : '.';
        }
        asc[24] = 0;
        if (k == 0) logf_("        this-> %s  |%s|", hex, asc);
        else        logf_("        a%-2d -> %s  |%s|", k, hex, asc);
    }

    logf_("        globals: 612fb8=%08x 612fc4=%08x 613868=%08x 61308c=%08x",
          *(DWORD *)(SIZE_T)0x612fb8, *(DWORD *)(SIZE_T)0x612fc4,
          *(DWORD *)(SIZE_T)0x613868, *(DWORD *)(SIZE_T)0x61308c);
}

static int patch_text_probe(void)
{
    /* The prologue is unique on eight bytes; sixteen are taken for margin. It is
     * `sub esp,0x3c` + `mov eax,[esp+0x54]` = 3 + 4, so SEVEN bytes relocate -- taking
     * the five a detour needs would split the mov and corrupt the function. Both are
     * position-independent: the relocated `sub` runs before the relocated esp-relative
     * `mov`, exactly as originally, because popad restores esp to its entry value. */
    static const BYTE pat[] = { 0x83,0xec,0x3c, 0x8b,0x44,0x24,0x54, 0x85,0xc0,
                                0x53, 0x55, 0x56, 0x8b,0xd9, 0x57, 0x89 };
    BYTE *entry = NULL;
    int n = 0;
    for (SIZE_T i = 0; i + sizeof pat <= g_textlen; i++)
        if (!memcmp(g_text + i, pat, sizeof pat)) { entry = g_text + i; if (++n > 1) break; }
    if (!entry) { logf_("[x] [txtprobe] string-renderer signature not found"); return 0; }
    if (n > 1)  { logf_("[x] [txtprobe] signature matched %d times -- refusing", n); return 0; }

    BYTE *tr = (BYTE *)VirtualAlloc(NULL, 96, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tr) { logf_("[x] [txtprobe] VirtualAlloc failed"); return 0; }
    int o = 0;
    tr[o++] = 0x60;                                                 /* pushad             */
    tr[o++] = 0x9C;                                                 /* pushfd             */
    tr[o++] = 0x8D; tr[o++] = 0x44; tr[o++] = 0x24; tr[o++] = 0x24; /* lea eax,[esp+0x24] */
    tr[o++] = 0x50;                                                 /* push eax  (frame)  */
    tr[o++] = 0x51;                                                 /* push ecx  (this)   */
    tr[o++] = 0xB8; { DWORD f = (DWORD)(SIZE_T)&text_hook; memcpy(tr + o, &f, 4); o += 4; }
    tr[o++] = 0xFF; tr[o++] = 0xD0;                                 /* call eax           */
    tr[o++] = 0x83; tr[o++] = 0xC4; tr[o++] = 0x08;                 /* add esp,8 (cdecl)  */
    tr[o++] = 0x9D;                                                 /* popfd              */
    tr[o++] = 0x61;                                                 /* popad              */
    memcpy(tr + o, entry, 7); o += 7;                               /* relocated sub+mov  */
    tr[o++] = 0xE9; { DWORD r = (DWORD)(SIZE_T)((entry + 7) - (tr + o + 4)); memcpy(tr + o, &r, 4); o += 4; }

    BYTE det[7];
    det[0] = 0xE9;
    { DWORD r = (DWORD)(SIZE_T)(tr - (entry + 5)); memcpy(det + 1, &r, 4); }
    det[5] = 0x90; det[6] = 0x90;      /* pad the tail of the split instruction */
    if (!poke(entry, det, 7)) { logf_("[x] [txtprobe] VirtualProtect failed"); return 0; }
    logf_("[+] [txtprobe] string renderer %p detoured -> %p (logs every horizontal draw)",
          (void *)entry, (void *)tr);
    return 1;
}

/* -------------------------------------------------------- s73 apply-video probe
 *
 * WHICH CALL ASKS FOR 640x480 WHEN THE MENU IS RE-ENTERED FROM A MAP.
 *
 * FUN_00515450 is the engine's apply-video-settings routine and takes the five
 * settings as ecx, edx, arg1, arg2, arg3 -> fields +0xc, +0x10, +0x14, +0x18,
 * +0x1c, with arg2 the resolution slot and -1 meaning "keep" (section 69.4).
 *
 * A static sweep of all 19 call sites (section 73.1) shows only the TWO startup
 * sites pass slot 0 as a literal, and those are already redirected. Every other
 * site either passes -1 or computes the slot at runtime -- so the return-to-menu
 * path cannot be identified by reading immediates, and the honest instrument is
 * to log what the routine is ACTUALLY handed, and by whom. Same move that settled
 * section 66.
 *
 * The routine opens `sub esp,8` / `mov eax,[0x612fec]` = 3 + 5 bytes, so the
 * detour relocates EIGHT, not five: taking five would split the mov and corrupt
 * the function. Both relocated instructions are position-independent.
 *
 * The address is not hardcoded. It is read from the rel32 of the call that ends
 * the startup-slot signature, so it survives a build whose addresses moved --
 * which is the whole reason the Steam build patches at all. */
/* ------------------------------------------------ s74 pin the window to primary
 *
 * WHY THIS EXISTS. Wine measures ONLY the primary monitor and renormalises it to
 * (0,0), which pushes every other monitor to NEGATIVE coordinates -- measured:
 * with HDMI primary the second monitor sits at (1920,-360); with the second one
 * primary, HDMI sits at (-1920,360). The negative axis moves, it never goes away.
 *
 * Placement is decided separately, by the compositor, from the launching context.
 * So if the game's window lands on a monitor that is not the one Wine measured,
 * the engine computes its rects for a screen the window is not on, and DirectDraw
 * rejects them with DDERR_INVALIDRECT -- the infamous #150 (FINDINGS 18, 74).
 *
 * Every earlier attempt at this tried to control PLACEMENT from outside the game
 * (make the target monitor primary, launch from the right screen). That is a
 * guess about the compositor. Correcting it from INSIDE, at a moment we already
 * hook, is not: MonitorFromWindow says where the window actually is, and
 * SetWindowPos to the primary's origin is a request the X server honours.
 *
 * Runs on the apply-video path, which is every mode change, and is a no-op on a
 * single-monitor machine and whenever the window is already right. */
/* GetActiveWindow was WRONG here and it failed silently. It returns a window only
 * when the CALLING THREAD's window holds activation -- precisely what you do not
 * have when the window opened on the monitor you are not looking at. Enumerate
 * this process's own top-level windows instead: that does not depend on focus. */
/* Match the game's own window CLASS, not its size. The first version filtered on
 * "at least 320x200" and that rejected the only window that mattered: measured,
 * the window sits at -32000,-32000 sized 160x31 for the first seconds of startup,
 * which is Windows' canonical position for an ICONIC window. A size heuristic
 * cannot tell that apart from a tooltip; the class name can. */
static BOOL CALLBACK pick_window(HWND w, LPARAM lp)
{
    DWORD pid = 0;
    char cls[32] = {0};
    HWND *out = (HWND *)lp;
    GetWindowThreadProcessId(w, &pid);
    if (pid != GetCurrentProcessId()) return TRUE;
    if (GetWindow(w, GW_OWNER)) return TRUE;
    GetClassNameA(w, cls, sizeof cls - 1);
    if (strcmp(cls, "Tropico") != 0) return TRUE;
    *out = w;
    return FALSE;
}

static HWND find_game_window(void)
{
    HWND w = NULL;
    EnumWindows(pick_window, (LPARAM)&w);
    return w;
}

/* One-shot dump of every top-level window, with the reason each was rejected.
 * "Found nothing" is not a diagnosis -- this says WHY nothing was found. */
static BOOL CALLBACK dump_window(HWND w, LPARAM lp)
{
    DWORD pid = 0;
    RECT r = {0,0,0,0};
    char cls[64] = {0}, txt[64] = {0};
    (void)lp;
    GetWindowThreadProcessId(w, &pid);
    GetClassNameA(w, cls, sizeof cls - 1);
    GetWindowTextA(w, txt, sizeof txt - 1);
    GetWindowRect(w, &r);
    logf_("      hwnd %p pid %lu%s class '%s' text '%s' %ld,%ld %ldx%ld vis=%d owner=%p",
          (void *)w, (unsigned long)pid,
          pid == GetCurrentProcessId() ? " (OURS)" : "",
          cls, txt, r.left, r.top, r.right - r.left, r.bottom - r.top,
          IsWindowVisible(w) ? 1 : 0, (void *)GetWindow(w, GW_OWNER));
    return TRUE;
}

static void pin_window_to_primary(const char *src)
{
    HWND w;
    HMONITOR m, prim;
    MONITORINFO mi, pi;
    /* s118.11: DeviceSelect and this have OPPOSITE opinions about where the window
     * belongs. s74 drags it to the primary because that is where Wine's DirectDraw
     * will render whatever we do; with a device GUID substituted, the game renders
     * on the chosen monitor instead and DirectDraw places the window to match
     * (s118.3, arm 3 -- Windows moved a window to suit the device). Dragging it back
     * would leave the picture on one screen and the mouse on another, which is s89's
     * failure with a new cause. The device decides; this stands down. */
    if (g_devsel && g_devsel_want[0]) {
        static int said;
        if (!said) {
            logf_("  [display] DeviceSelect owns the monitor, so PinToPrimary is standing"
                  " down -- DirectDraw places the window to match the device it renders"
                  " on, and moving it would split the picture from the input.");
            said = 1;
        }
        return;
    }
    if (!g_pin_primary) return;
    w = find_game_window();
    if (!w) return;                       /* too early -- no window yet */
    /* Do not move a minimised window. It is parked at -32000,-32000 by the window
     * manager, its monitor is meaningless there, and the placement that matters has
     * not happened yet. Wait for it to be restored and sized. */
    if (IsIconic(w)) return;
    {
        RECT wr;
        if (!GetWindowRect(w, &wr)) return;
        if (wr.right - wr.left < 320 || wr.bottom - wr.top < 200) return;
    }
    m    = MonitorFromWindow(w, MONITOR_DEFAULTTONEAREST);
    prim = MonitorFromPoint((POINT){0, 0}, MONITOR_DEFAULTTOPRIMARY);
    if (!m || !prim) return;
    if (m == prim) {
        /* Report the no-op ONCE. The first version returned silently here, so a
         * window that was never found and a window that was already right produced
         * identical logs -- and that ambiguity cost a whole test run. */
        if (!g_pin_seen_ok) {
            RECT wr; GetWindowRect(w, &wr);
            logf_("  [display] game window %p at %ld,%ld %ldx%ld is on the primary monitor"
                  " -- nothing to do", (void *)w, wr.left, wr.top,
                  wr.right - wr.left, wr.bottom - wr.top);
            g_pin_seen_ok = 1;
        }
        return;
    }

    mi.cbSize = sizeof mi; pi.cbSize = sizeof pi;
    if (!GetMonitorInfoA(m, &mi) || !GetMonitorInfoA(prim, &pi)) return;
    {
        /* Rate-limited, and it reports the WINDOW RECT. Without the rect this cannot
         * distinguish "the window sits on the other monitor" from "the window is
         * larger than the primary and MonitorFromWindow picked by overlap area",
         * and those need completely different fixes. */
        static int nlog;
        RECT wr; GetWindowRect(w, &wr);
        if (nlog < 4 || (nlog % 50) == 0)
            logf_("[!] [display] (%s) window %ld,%ld %ldx%ld resolves to the monitor at"
                  " %ld,%ld %ldx%ld, but Wine measures the PRIMARY at %ld,%ld %ldx%ld",
                  src, wr.left, wr.top, wr.right - wr.left, wr.bottom - wr.top,
                  mi.rcMonitor.left, mi.rcMonitor.top,
                  mi.rcMonitor.right - mi.rcMonitor.left, mi.rcMonitor.bottom - mi.rcMonitor.top,
                  pi.rcMonitor.left, pi.rcMonitor.top,
                  pi.rcMonitor.right - pi.rcMonitor.left, pi.rcMonitor.bottom - pi.rcMonitor.top);
        nlog++;
    }

    SetWindowPos(w, NULL, pi.rcMonitor.left, pi.rcMonitor.top, 0, 0,
                 SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    m = MonitorFromWindow(w, MONITOR_DEFAULTTONEAREST);
    if (m == prim) {
        if (!g_pin_done) logf_("[+] [display] (%s) window moved onto the primary monitor", src);
        g_pin_done = 1;
        /* Moving it is not the same as it STAYING moved. Measured (FINDINGS 75):
         * the fullscreen window is positioned from the surface's PHYSICAL output,
         * which the compositor owns, so a move can be undone within 100 ms and the
         * run still fails with #150. Say so once, with the command that does work,
         * instead of letting the user read an error number. */
        if (++g_pin_moves == 10)
            logf_("[x] [display] the desktop keeps putting the window back on the other"
                  " monitor -- this run will probably fail with DirectDraw #150."
                  " Launch with:  tropico --exclusive --monitor <that monitor>");
    } else {
        /* Say what went wrong in words. A bare #150 later tells the user nothing,
         * and this failure has exactly one human-facing remedy. */
        logf_("[x] [display] could NOT move the window onto the primary monitor."
              " The game will fail with DirectDraw error #150. Launch it from your"
              " primary monitor, or make this monitor primary in your desktop settings.");
    }
}

static DWORD WINAPI pin_thread(LPVOID p)
{
    /* Placement is not an event we can hook -- the window can be mapped, and moved,
     * at any point during startup. So watch for a while instead of guessing one
     * moment. Cheap: a handful of GetWindowRect calls a second, for 20 seconds,
     * and it stops as soon as it has corrected a window that stays corrected. */
    int i, logged_none = 0;
    (void)p;
    for (i = 0; i < 200; i++) {
        HWND w = find_game_window();
        if (w) {
            pin_window_to_primary("watcher");
        } else if (!logged_none && i > 20) {
            logf_("  [display] no window of class 'Tropico' after 2 s. Every top-level"
                  " window visible to this process:");
            EnumWindows(dump_window, 0);
            logged_none = 1;
        }
        Sleep(100);
    }
    if (!g_pin_done && !g_pin_seen_ok)
        logf_("  [display] watcher finished without ever seeing a sized game window");
    return 0;
}

static void __cdecl slotprobe_hook(DWORD *a)
{
    pin_window_to_primary("apply-video");
    /* a[] from the trampoline: 0 flags, 1 EDI, 2 ESI, 3 EBP, 4 ESP, 5 EBX,
     * 6 EDX, 7 ECX, 8 EAX, 9 return address, 10 arg1, 11 arg2, 12 arg3. */
    /* THE FIX (s73). Returning to the main menu from a map re-applies the FRONTEND
     * preset row, whose stored resolution slot is 0 -- PopTop put 640x480 there
     * because the menu art only ever existed at that size (s69.5). The startup
     * redirect does not cover it: that patches two `push 0` immediates inside
     * FUN_0047c370, and this is a different call site reading a different row.
     *
     * Rewrite the argument on the stack, exactly as the startup sites rewrite
     * theirs, and ONLY for this call site. A blanket "slot 0 becomes slot 4" would
     * also override a deliberate 640x480 chosen from the F2 settings screen, which
     * is a legal choice arriving through a different caller. */
    /* THE FIX (s79). arg3 is the windowed flag (+0x1c). The F2 video screen's
     * "Fullscreen" checkbox is the only thing that ever passes 1, and windowed is
     * not a mode this game supports in any useful sense -- FINDINGS 6 measured it:
     * windowed means DDSCL_NORMAL, no SetDisplayMode, and a clipper blit into an
     * offscreen surface. Unchecking the box mid-game therefore hands DirectDraw a
     * destination rect for a screen that no longer exists and it answers #150.
     *
     * Worse, the flag PERSISTS to TROPICO.CFG file offset 0x246, and the startup
     * sequence at 0x47c375 reads it and JUMPS OVER the whole video bring-up when
     * it is set -- including the two slot requests patch_menu_slot() rewrites. So
     * one click leaves the install permanently at 640x480 with no intro and a #150
     * on every map load. That is what makes this worth clamping rather than
     * documenting: the failure outlives the session that caused it.
     *
     * Clamp here rather than at the checkbox because every caller funnels through
     * this one routine, and -1 ("keep") must pass through untouched. */
    if (g_force_fs && (int)a[12] > 0) {
        a[12] = 0;
        if (++g_fs_clamped <= 4)
            logf_("  [fullscreen] caller %08lx asked for windowed mode (arg3=1)"
                  " -- forced back to fullscreen (FINDINGS 79)%s",
                  (unsigned long)a[9],
                  g_fs_clamped == 4 ? "  [further clamps not logged]" : "");
    }
    if (g_menu_slot >= 0 && g_preset_ret && a[9] == g_preset_ret && (int)a[11] == 0) {
        a[11] = (DWORD)g_menu_slot;
        if (!g_slot_log) return;
        logf_("  [slotprobe] frontend preset asked for slot 0 -> rewritten to %d", g_menu_slot);
        return;
    }
    if (!g_slot_log) return;

    /* NO DEDUPE. The first version deduped on (caller, slot) and that hid the
     * event we were looking for: the menu re-entry either repeats a pair already
     * seen or makes no call at all, and those two have completely different fixes.
     * A plain sequence with a generous cap distinguishes them. */
    static int nseq;
    if (nseq >= 300) return;
    nseq++;
    /* The live mode, read from the engine's own virtual->pixel scale globals, so
     * every call is stamped with the mode in force when it was made. That is what
     * says whether a mode CHANGE happened, rather than only what was requested. */
    int lw = 0, lh = 0;
    if (g_vt_xs_va && g_vt_ys_va) {
        lw = (int)(*(float *)(SIZE_T)g_vt_xs_va * 3200.0f + 0.5f);
        lh = (int)(*(float *)(SIZE_T)g_vt_ys_va * 2400.0f + 0.5f);
    }
    logf_("  [slotprobe] #%d caller %08lx  SLOT(arg2)=%d  arg1=%d arg3=%d  ecx=%d edx=%d"
          "  (mode now %dx%d)",
          nseq, (unsigned long)a[9], (int)a[11], (int)a[10], (int)a[12],
          (int)a[7], (int)a[6], lw, lh);
}

static int patch_slot_probe(void)
{
    if (!g_applyvideo_va) {
        logf_("[x] [slotprobe] apply-video routine not located");
        return 0;
    }
    BYTE *entry = (BYTE *)(SIZE_T)g_applyvideo_va;
    /* Refuse unless the prologue is the one we measured. Relocating something
     * else would corrupt the function silently, and this runs on two builds. */
    static const BYTE PRO[] = {0x83,0xec,0x08, 0xa1};
    if (memcmp(entry, PRO, sizeof PRO) != 0) {
        logf_("[x] [slotprobe] %08lx does not open with `sub esp,8 / mov eax,imm32`"
              " (%02x %02x %02x %02x) -- refusing",
              (unsigned long)g_applyvideo_va, entry[0], entry[1], entry[2], entry[3]);
        return 0;
    }
    BYTE *tr = (BYTE *)VirtualAlloc(NULL, 96, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tr) { logf_("[x] [slotprobe] VirtualAlloc failed"); return 0; }
    int o = 0;
    tr[o++] = 0x60;                                                 /* pushad          */
    tr[o++] = 0x9C;                                                 /* pushfd          */
    tr[o++] = 0x54;                                                 /* push esp        */
    tr[o++] = 0xB8; { DWORD f = (DWORD)(SIZE_T)&slotprobe_hook; memcpy(tr + o, &f, 4); o += 4; }
    tr[o++] = 0xFF; tr[o++] = 0xD0;                                 /* call eax        */
    tr[o++] = 0x83; tr[o++] = 0xC4; tr[o++] = 0x04;                 /* add esp,4       */
    tr[o++] = 0x9D;                                                 /* popfd           */
    tr[o++] = 0x61;                                                 /* popad           */
    memcpy(tr + o, entry, 8); o += 8;                               /* relocated 8     */
    tr[o++] = 0xE9; { DWORD r = (DWORD)(SIZE_T)((entry + 8) - (tr + o + 4)); memcpy(tr + o, &r, 4); o += 4; }

    BYTE det[8];
    det[0] = 0xE9;
    { DWORD r = (DWORD)(SIZE_T)(tr - (entry + 5)); memcpy(det + 1, &r, 4); }
    det[5] = det[6] = det[7] = 0x90;   /* pad the 3 bytes the jmp does not cover */
    if (!poke(entry, det, 8)) { logf_("[x] [slotprobe] VirtualProtect failed"); return 0; }
    logf_("[+] [menu] apply-video %08lx detoured -> %p"
          " (frontend preset -> slot %d, so the menu survives a return from a map)",
          (unsigned long)g_applyvideo_va, (void *)tr, g_menu_slot);
    return 1;
}

/* ------------------------------------------------------------- s68 startup movie
 *
 * The startup movie never plays. Established by measurement, not inference:
 *   - the proxy is NOT the cause -- a control run with the stock binkw32.dll
 *     behaves identically
 *   - Bink is healthy -- BinkOpenMiles and BinkSetSoundSystem succeed and the menu
 *     movies (s_m_loop, s_m2x) open and play
 *   - intro_01 is never REQUESTED. Nothing fails; something declines to ask.
 *
 * The path is FUN_005170b0 (WinMain) -> FUN_00458c90 -> FUN_0047c370, which plays
 * movie 0x68 ("preintro") and then movie 1 ("intro_01") out of the 104-entry table
 * at 0x5a0360. FUN_0047c370 opens with two guards:
 *
 *     mov eax,[0x59a654] / test / je skip      <- ships as 1 and is never written
 *     mov eax,[0x5f2170] / mov ecx,[eax+0xc]
 *     test ecx,ecx       / je skip             <- THIS one is closed
 *
 * and the very next instruction after the guards clears that same field, so it is a
 * ONE-SHOT: whatever sets it does so once. That matches the symptom exactly -- the
 * intro is not disabled, it is already "used up".
 *
 * This NOPs the second je so the sequence always runs. Off unless the ini asks,
 * because "play the intro on every launch" is a preference, not a bug fix.
 *
 * Note preintro.bik is NOT PRESENT in this install -- only intro_01.bik is. So the
 * first BinkOpen of the pair is expected to fail; the Bink instrumentation will say
 * so plainly, and whether the game survives that is exactly what the run tests. */
static int patch_intro(void)
{
    static const BYTE SIG[]  = {0xa1,0,0,0,0, 0x85,0xc0, 0x0f,0x84,0,0,0,0,
                                0xa1,0,0,0,0, 0x8b,0x48,0x0c, 0x85,0xc9, 0x0f,0x84,0,0,0,0};
    static const BYTE MASK[] = {   1,0,0,0,0,    1,   1,    1,   1,0,0,0,0,
                                   1,0,0,0,0,    1,   1,   1,    1,   1,    1,   1,0,0,0,0};
    BYTE *at = find_unique_masked(SIG, MASK, sizeof SIG, g_text, g_textlen, "intro guard");
    if (!at) { logf_("[x] [intro] guard signature not found"); return 0; }
    static const BYTE NOPS[6] = {0x90,0x90,0x90,0x90,0x90,0x90};
    if (!poke(at + 23, NOPS, 6)) { logf_("[x] [intro] VirtualProtect failed"); return 0; }
    logf_("[+] [intro] one-shot guard NOPed at %p -- startup movie forced on every launch",
          (void *)(at + 23));
    logf_("      (gate at the first gate reads %08x; the pair plays movie 0x68 then movie 1)",
          rd32(at + 1));
    return 1;
}

/* ------------------------------------------------- s69 the movie/menu window
 *
 * The main menu and the intro both render into a 640x480 box in the TOP-LEFT
 * corner of a 1920x1080 screen.
 *
 * FUN_00515d30 is "play movie #i". After choosing a layout it sizes the window:
 *
 *     w = min(screenW, 640) ; h = min(screenH, 480)      <- the clamp, 0x515e58
 *     ... converted to virtual units through 0x5a0ff8 / 0x5a1000 ...
 *     msg 0x6a = w      msg 0x6b = h
 *     msg 0x68 = (3200 - w) / 2                          <- and it CENTRES
 *     msg 0x69 = (2400 - h) / 2
 *
 * So the engine already centres the window. That is the part that does not add up:
 * a centred 640x480 window would sit in the MIDDLE of the screen, not the corner.
 * Which means the menu is probably NOT on this path at all -- it is on the
 * `videowin.win` branch, which jumps to 0x515f86 and skips the clamp, the SetWH and
 * the centring together.
 *
 * Two things are therefore built here, so one run settles it either way:
 *   patch_menu()        widens the clamp to a PILLARBOXED size (4:3 inside the mode)
 *   patch_movie_probe() logs which branch each movie actually takes
 *
 * If the picture changes, the menu was on the clamped path and this is the fix.
 * If it does not, the log names the branch that needs the work instead -- and the
 * clamp change then only affects in-game event movies, which is the risk to watch. */

static int patch_menu(int w, int h)
{
    /* mov ax,[screenW] / cmp ax,640 / jle / mov [esp+0x10],640 / ... / same for height */
    static const BYTE SIG[]  = {0x66,0xa1,0,0,0,0, 0x66,0x3d,0x80,0x02, 0x7e,0x0a,
                                0xc7,0x44,0x24,0x10,0x80,0x02,0x00,0x00, 0xeb,0x07,
                                0x0f,0xbf,0xc0, 0x89,0x44,0x24,0x10, 0xdb,0x44,0x24,0x10,
                                0xd8,0x0d,0,0,0,0, 0xe8,0,0,0,0, 0x8b,0xf8,
                                0x66,0xa1,0,0,0,0, 0x66,0x3d,0xe0,0x01, 0x7e,0x0a,
                                0xc7,0x44,0x24,0x10,0xe0,0x01,0x00,0x00};
    static const BYTE MASK[] = {   1,   1,0,0,0,0,    1,   1,   1,   1,    1,   1,
                                   1,   1,   1,   1,   1,   1,   1,   1,    1,   1,
                                   1,   1,   1,    1,   1,   1,   1,    1,   1,   1,   1,
                                   1,   1,0,0,0,0,    1,0,0,0,0,    1,   1,
                                   1,   1,0,0,0,0,    1,   1,   1,   1,    1,   1,
                                   1,   1,   1,   1,   1,   1,   1,   1};
    BYTE *at = find_unique_masked(SIG, MASK, sizeof SIG, g_text, g_textlen, "movie clamp");
    if (!at) { logf_("[x] [menu] clamp signature not found"); return 0; }
    WORD  w16 = (WORD)w, h16 = (WORD)h;
    DWORD w32 = (DWORD)w, h32 = (DWORD)h;
    if (!poke(at +  8, &w16, 2) || !poke(at + 16, &w32, 4) ||
        !poke(at + 54, &h16, 2) || !poke(at + 62, &h32, 4)) {
        logf_("[x] [menu] VirtualProtect failed"); return 0;
    }
    logf_("[+] [menu] movie-window clamp at %p: 640x480 -> %dx%d (the engine centres it itself)",
          (void *)at, w, h);
    return 1;
}

/* Log which branch FUN_00515d30 takes. Its first instruction is `mov eax,[imm32]`,
 * five bytes, so the detour relocates cleanly -- the same shape as the vtext entry
 * probe. ECX carries the movie index on entry. */
static void __cdecl movie_hook(DWORD idx, DWORD playing)
{
    static int n;
    if (n >= 24) return;
    n++;
    DWORD sub = 0;
    if (g_mv_flag_va) {
        DWORD obj = *(DWORD *)(SIZE_T)g_mv_flag_va;
        if (obj) sub = *(DWORD *)(SIZE_T)(obj + 0x1c);
    }
    /* The mode the GAME thinks it is in, and the mode the DESKTOP is actually in.
     * If they disagree, the movie is not mis-drawn at all -- the game is rendering
     * a correct 640x480 frame that nothing is scaling up to the panel. That is a
     * presentation problem, not a layout one, and it needs a completely different
     * fix from anything inside the exe. */
    int gw = 0, gh = 0;
    if (g_vt_xs_va && g_vt_ys_va) {
        gw = (int)(*(float *)(SIZE_T)g_vt_xs_va * 3200.0f + 0.5f);
        gh = (int)(*(float *)(SIZE_T)g_vt_ys_va * 2400.0f + 0.5f);
    }
    logf_("          game mode %dx%d | desktop %dx%d", gw, gh,
          GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
    logf_("  [movie] play #%lu   already-playing=%lu   [0x612fec+0x1c]=%lu -> %s",
          idx, playing, sub,
          playing ? "REFUSED (a movie is already up)"
                  : (sub ? "videowi2.win (clamped+centred path)"
                         : "videowin.win (BYPASSES clamp and centring)"));
}

static int patch_movie_probe(void)
{
    /* mov eax,[playing-flag] / sub esp,0x28 / push ebx / xor ebx,ebx / cmp eax,ebx */
    static const BYTE SIG[]  = {0xa1,0,0,0,0, 0x83,0xec,0x28, 0x53, 0x33,0xdb, 0x3b,0xc3};
    static const BYTE MASK[] = {   1,0,0,0,0,    1,   1,   1,    1,    1,   1,    1,   1};
    BYTE *at = find_unique_masked(SIG, MASK, sizeof SIG, g_text, g_textlen, "play-movie entry");
    if (!at) { logf_("[x] [movie] entry signature not found"); return 0; }
    DWORD playing_va = rd32(at + 1);

    BYTE *tr = (BYTE *)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tr) { logf_("[x] [movie] VirtualAlloc failed"); return 0; }
    int o = 0;
    tr[o++] = 0x60; tr[o++] = 0x9C;                    /* pushad / pushfd     */
    tr[o++] = 0xA1; memcpy(tr + o, &playing_va, 4); o += 4;  /* mov eax,[flag] */
    tr[o++] = 0x50;                                    /* push eax (playing)  */
    tr[o++] = 0x51;                                    /* push ecx (index)    */
    tr[o++] = 0xB8; { DWORD f = (DWORD)(SIZE_T)&movie_hook; memcpy(tr + o, &f, 4); o += 4; }
    tr[o++] = 0xFF; tr[o++] = 0xD0;                    /* call eax            */
    tr[o++] = 0x83; tr[o++] = 0xC4; tr[o++] = 0x08;    /* add esp,8           */
    tr[o++] = 0x9D; tr[o++] = 0x61;                    /* popfd / popad       */
    memcpy(tr + o, at, 5); o += 5;                     /* relocated mov eax   */
    tr[o++] = 0xE9; { DWORD r = (DWORD)(SIZE_T)((at + 5) - (tr + o + 4)); memcpy(tr + o, &r, 4); o += 4; }

    BYTE det[5]; det[0] = 0xE9;
    { DWORD r = (DWORD)(SIZE_T)(tr - (at + 5)); memcpy(det + 1, &r, 4); }
    if (!poke(at, det, 5)) { logf_("[x] [movie] VirtualProtect failed"); return 0; }
    logf_("[+] [movie] play-movie entry %p detoured -> %p (playing flag %08x)",
          (void *)at, (void *)tr, playing_va);
    return 1;
}

/* ------------------------------------------ s69c the startup ASKS for 640x480
 *
 * Two earlier attempts failed and both were aimed at the wrong thing:
 *   (a) hooking the per-screen assignment in FUN_004e9f30 -- never fired
 *   (b) substituting the slot at its point of use -- crashed, because
 *       FUN_0052e480 reads [settings]+0x18 THREE times (width, height, mode set)
 *       and only one was patched
 *   (c) writing the field during display bring-up -- DDERR_INVALIDRECT #150,
 *       the mode cannot be set before the window and surfaces exist
 *
 * All of that assumed the menu ends up at 640x480 by DEFAULT. It does not. The
 * startup sequence FUN_0047c370 calls the engine's own apply-video-settings routine
 * FUN_00515450 and explicitly ASKS for slot 0, twice:
 *
 *     push 0 / push 0 / push -1 / or edx,-1 / or ecx,-1 / mov [eax+0x1c],1 / call
 *     push 1 / push 0 / push -1 / or edx,-1 / or ecx,-1 / mov [eax+0x1c],0 / call
 *
 * The five settings map 1:1 onto ecx, edx, arg1, arg2, arg3 -> fields +0xc, +0x10,
 * +0x14, +0x18, +0x1c. That mapping is not guesswork: at 0x46175c the game loads
 * ecx=[obj+0xc], edx=[obj+0x10], and pushes [obj+0x14] last, so arg1 is +0x14 and
 * arg2 is +0x18 -- the resolution slot. -1 means "keep".
 *
 * So changing the second push is the whole fix, one byte per site. It also runs
 * through the engine's OWN release-and-recreate path at a point the engine itself
 * considers safe, which is exactly what the bring-up patch could not do.
 *
 * These two calls sit BEFORE the intro's guards, so this works whether or not
 * [Intro] Force is on. push imm8, so the slot must be 0..127. */
/* The apply-video routine's address, read from the rel32 of the call that ends
 * the startup slot-request signature. Build-independent by construction: the two
 * builds put this function at different addresses and the signature finds both. */
static void find_applyvideo(void)
{
    static const BYTE SIG[]  = {0x6a,0, 0x6a,0x00, 0x6a,0xff,
                                0x83,0xca,0xff, 0x83,0xc9,0xff,
                                0xc7,0x40,0x1c,0,0x00,0x00,0x00, 0xe8};
    static const BYTE MASK[] = {   1,0,    1,   1,    1,   1,
                                   1,   1,   1,    1,   1,   1,
                                   1,   1,   1,0,   1,   1,   1,    1};
    for (SIZE_T i = 0; i + sizeof SIG + 4 <= g_textlen; i++) {
        SIZE_T k = 0;
        for (; k < sizeof SIG; k++) if (MASK[k] && g_text[i + k] != SIG[k]) break;
        if (k != sizeof SIG) continue;
        g_applyvideo_va = (DWORD)(SIZE_T)(g_text + i + 24) + rd32(g_text + i + 20);
        break;
    }

    /* The PRESET-APPLY call site (s73). It loads all five settings out of the
     * preset arrays indexed by the current preset row:
     *
     *   mov edx,[eax+ecx*4+0x48]   ; the resolution slot
     *   push -1                    ; arg3
     *   push edx                   ; arg2 = slot
     *   mov edx,[eax+ecx*4+0x40] / push edx
     *   mov edx,[eax+ecx*4+0x38]
     *   mov ecx,[eax+ecx*4+0x30]
     *   call apply-video
     *
     * Row 0 is the in-game preset and row 1 the frontend one, and PopTop stored
     * 640x480 in row 1 because the menu art only existed at that size (s69.5).
     * Matched by signature rather than hardcoded so the Steam build works too. */
    {
        static const BYTE PS[]  = {0x8b,0x54,0x88,0x48, 0x6a,0xff, 0x52,
                                   0x8b,0x54,0x88,0x40, 0x52,
                                   0x8b,0x54,0x88,0x38,
                                   0x8b,0x4c,0x88,0x30, 0xe8};
        static const BYTE PM[]  = {   1,   1,   1,   1,    1,   1,    1,
                                      1,   1,   1,   1,    1,
                                      1,   1,   1,   1,
                                      1,   1,   1,   1,    1};
        BYTE *c = find_unique_masked(PS, PM, sizeof PS, g_text, g_textlen, "preset apply");
        if (c) g_preset_ret = (DWORD)(SIZE_T)(c + sizeof PS + 4);
        else   logf_("[-] [menu] preset-apply call site not found --"
                     " returning to the menu from a map will drop to 640x480");
    }
}

static int patch_menu_slot(void)
{
    /* push imm8 / push 0 / push -1 / or edx,-1 / or ecx,-1 / mov [eax+0x1c],imm32 / call */
    static const BYTE SIG[]  = {0x6a,0, 0x6a,0x00, 0x6a,0xff,
                                0x83,0xca,0xff, 0x83,0xc9,0xff,
                                0xc7,0x40,0x1c,0,0x00,0x00,0x00, 0xe8};
    static const BYTE MASK[] = {   1,0,    1,   1,    1,   1,
                                   1,   1,   1,    1,   1,   1,
                                   1,   1,   1,0,   1,   1,   1,    1};
    int n = 0;
    for (SIZE_T i = 0; i + sizeof SIG <= g_textlen; i++) {
        SIZE_T k = 0;
        for (; k < sizeof SIG; k++) if (MASK[k] && g_text[i + k] != SIG[k]) break;
        if (k != sizeof SIG) continue;
        BYTE v = (BYTE)g_menu_slot;
        if (poke(g_text + i + 3, &v, 1)) {
            logf_("  [+] [menu] startup slot request at %p: 0 -> %d",
                  (void *)(g_text + i), g_menu_slot);
            n++;
        }
    }
    if (!n) { logf_("[x] [menu] startup slot-request sites not found"); return 0; }
    logf_("[+] [menu] %d startup slot request(s) redirected to slot %d"
          " (via the engine's own FUN_00515450 apply path)", n, g_menu_slot);
    return 1;
}

/* ------------------------------------------- s79 the windowed flag is a trap
 *
 * Unchecking "Fullscreen" on the F2 video screen sets [0x612fec+0x1c] and the
 * setting is written to TROPICO.CFG at file offset 0x246. From then on the very
 * first thing the startup sequence does is:
 *
 *     mov eax,[0x612fec]
 *     mov ecx,[eax+0x1c]      ; the persisted windowed flag
 *     test ecx,ecx
 *     jne  <past the video setup>      <-- 7 bytes, the two lines above plus this
 *     push 0 / push 0 / push -1 / ... / call apply-video     ; slot request #1
 *
 * So a windowed CFG makes the game skip its ENTIRE video bring-up, including the
 * two slot requests patch_menu_slot() rewrites. Symptoms, all from this one bit:
 * a 640x480 menu, no intro movie, and DirectDraw #150 the moment a map loads and
 * something finally tries to draw at the real mode. Deleting the CFG fixes it,
 * which is exactly the kind of remedy nobody finds on their own.
 *
 * The clamp in slotprobe_hook() stops the flag being SET. This clears one that is
 * already set, and it is the same 7 bytes: the gate is replaced with the store
 * that zeroes the field. eax already holds the settings object, and the encoding
 * is the one the engine itself uses 20 bytes further down, so nothing is invented
 * here. The old `jne` is gone with it -- which is the point, since the branch it
 * takes is never one we want.
 *
 * Anchored to the startup slot-request signature rather than an address, like
 * every other patch here, so the Steam build gets it too. */
static int patch_force_fullscreen(void)
{
    static const BYTE SIG[]  = {0x6a,0, 0x6a,0x00, 0x6a,0xff,
                                0x83,0xca,0xff, 0x83,0xc9,0xff,
                                0xc7,0x40,0x1c,0,0x00,0x00,0x00, 0xe8};
    static const BYTE MASK[] = {   1,0,    1,   1,    1,   1,
                                   1,   1,   1,    1,   1,   1,
                                   1,   1,   1,0,   1,   1,   1,    1};
    /* mov ecx,[eax+0x1c] / test ecx,ecx / jne rel8 -- the 7 bytes to overwrite. */
    static const BYTE GATE[] = {0x8b,0x48,0x1c, 0x85,0xc9, 0x75,0};
    static const BYTE GM[]   = {   1,   1,   1,    1,   1,    1,0};
    static const BYTE FIX[]  = {0xc7,0x40,0x1c, 0x00,0x00,0x00,0x00};  /* mov [eax+0x1c],0 */
    int n = 0;
    for (SIZE_T i = 12; i + sizeof SIG <= g_textlen; i++) {
        SIZE_T k = 0;
        for (; k < sizeof SIG; k++) if (MASK[k] && g_text[i + k] != SIG[k]) break;
        if (k != sizeof SIG) continue;
        /* Only the FIRST of the two startup sites carries the gate, and it must be
         * preceded by the load of the settings object -- otherwise eax is not what
         * the replacement store assumes and we would corrupt an unrelated struct. */
        if (g_text[i - 12] != 0xa1) continue;
        for (k = 0; k < sizeof GATE; k++)
            if (GM[k] && g_text[i - 7 + k] != GATE[k]) break;
        if (k != sizeof GATE) continue;
        if (!poke(g_text + i - 7, FIX, sizeof FIX)) continue;
        logf_("[+] [fullscreen] startup windowed-gate at %p replaced with"
              " `mov [obj+0x1c],0` -- a CFG left in windowed mode now heals itself",
              (void *)(g_text + i - 7));
        n++;
    }
    if (!n) {
        logf_("[x] [fullscreen] startup windowed-gate not found -- a TROPICO.CFG"
              " saved in windowed mode will still boot to a 640x480 menu."
              " Remedy: zero byte 0x246 of app\\data2\\TROPICO.CFG, or delete it");
        return 0;
    }
    return 1;
}

/* ------------------------------------------------- s69.6 the movie blit probe
 *
 * The movie tiles 3x across the top ~160px: a destination advance of 640 px per source
 * row against a 1920 px screen row. NOT an aspect-ratio problem -- a wrong aspect
 * stretches, it cannot duplicate an image.
 *
 * Bink is innocent, established by a crash rather than an argument. Just before the
 * copy, FUN_00531690 allocates bink->Width * bink->Height * 2 (640*480*2) and passes
 * pitch = width*2 = 1280. Forcing that pitch to 3840 made Bink write 1.8MB into a
 * 614KB buffer and the game died -- which PROVES 1280 is right and the buffer really
 * is movie-sized.
 *
 * So the fault is the game's own blit of that buffer, which starts at 0x531efd by
 * loading the screen width from ds:0x60c18c. It has two paths, selected at 0x531f47:
 *   [esp+0x30] != 0  -> a SCALING path (0x531f5f) that fdivs against the movie's own
 *                       dimensions -- the machinery that should fill a larger widget
 *   [esp+0x30] == 0  -> an unscaled path at 0x53204a
 *
 * Which one runs, and with what geometry, decides the fix. Log it rather than guess:
 * four wrong theories have already been paid for on this one screen. */
static void __cdecl blit_hook(DWORD ebp, DWORD *sp)
{
    static int n;
    if (n >= 6) return;
    n++;
    /* sp points at the callee's esp as it was on entry to the detour. */
    logf_("  [blit] path-flag[esp+0x30]=%lu  movie %lux%lu  screenW=%d  ->  %s",
          sp[0x30 / 4],
          *(DWORD *)(SIZE_T)(ebp + 0x9a), *(DWORD *)(SIZE_T)(ebp + 0x9e),
          g_vt_xs_va ? (int)(*(float *)(SIZE_T)g_vt_xs_va * 3200.0f + 0.5f) : 0,
          sp[0x30 / 4] ? "SCALING path 0x531f5f" : "UNSCALED path 0x53204a");
    logf_("         locals: [10]=%lu [14]=%lu [1c]=%lu [24]=%lu [28]=%lu [2c]=%lu [34]=%lu [38]=%lu",
          sp[0x10/4], sp[0x14/4], sp[0x1c/4], sp[0x24/4],
          sp[0x28/4], sp[0x2c/4], sp[0x34/4], sp[0x38/4]);
}

static int patch_blit_probe(void)
{
    /* the two instructions right after the BinkCopyToBuffer call:
     *   mov ecx,[esp+0x2c] / mov esi,[esp+0x10] / movsx eax,WORD ds:0x60c18c */
    static const BYTE SIG[]  = {0x8b,0x4c,0x24,0x2c, 0x8b,0x74,0x24,0x10,
                                0x0f,0xbf,0x05,0,0,0,0};
    static const BYTE MASK[] = {   1,   1,   1,   1,    1,   1,   1,   1,
                                   1,   1,   1,0,0,0,0};
    BYTE *at = find_unique_masked(SIG, MASK, sizeof SIG, g_text, g_textlen, "movie blit");
    if (!at) { logf_("[x] [blit] signature not found"); return 0; }

    BYTE *tr = (BYTE *)VirtualAlloc(NULL, 96, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tr) { logf_("[x] [blit] VirtualAlloc failed"); return 0; }
    int o = 0;
    tr[o++] = 0x60; tr[o++] = 0x9C;                                 /* pushad / pushfd     */
    tr[o++] = 0x8D; tr[o++] = 0x44; tr[o++] = 0x24; tr[o++] = 0x24; /* lea eax,[esp+0x24]  */
    tr[o++] = 0x50;                                                 /* push eax (orig esp) */
    tr[o++] = 0x55;                                                 /* push ebp            */
    tr[o++] = 0xB8; { DWORD f = (DWORD)(SIZE_T)&blit_hook; memcpy(tr + o, &f, 4); o += 4; }
    tr[o++] = 0xFF; tr[o++] = 0xD0;                                 /* call eax            */
    tr[o++] = 0x83; tr[o++] = 0xC4; tr[o++] = 0x08;                 /* add esp,8           */
    tr[o++] = 0x9D; tr[o++] = 0x61;                                 /* popfd / popad       */
    memcpy(tr + o, at, 8); o += 8;                                  /* relocated two movs  */
    tr[o++] = 0xE9; { DWORD r = (DWORD)(SIZE_T)((at + 8) - (tr + o + 4)); memcpy(tr + o, &r, 4); o += 4; }

    BYTE det[8];
    det[0] = 0xE9;
    { DWORD r = (DWORD)(SIZE_T)(tr - (at + 5)); memcpy(det + 1, &r, 4); }
    memset(det + 5, 0x90, 3);
    if (!poke(at, det, 8)) { logf_("[x] [blit] VirtualProtect failed"); return 0; }
    logf_("[+] [blit] movie blit at %p detoured -> %p", (void *)at, (void *)tr);
    return 1;
}

/* ------------------------------------------ s69.6 let the movie blit MAGNIFY
 *
 * Measured, not guessed: the probe showed the SCALING path taken, destination rect
 * 0..1919 x 0..1079, movie 640x480. The machinery is engaged and still tiles.
 *
 * The blit then clamps the destination extent down to the SOURCE extent:
 *
 *     mov edx,[esp+0x1c]   ; destination width  = 1920
 *     sub ecx,edi          ; source available   = 640
 *     cmp edx,ecx / jl keep
 *     mov [esp+0x1c],ecx   ; destW = 640
 *
 * ...and the same two instructions earlier for height. Correct for a 1:1 copy,
 * fatal for a magnifying one -- and invisible at 640x480, where the two are equal.
 *
 * It explains the picture exactly. The destination row remainder was computed as
 * screenW - destW = 1920 - 1920 = 0 BEFORE the clamp, so afterwards the loop writes
 * 640 px per row and advances by 0: rows lay end to end, three per screen row,
 * 480 source rows landing in 160 screen rows. That is the observed image.
 *
 * The inner loop steps the source with 16.16 fixed-point increments computed at
 * 0x532006 and 0x53202c, so it is a real scaler -- it just never gets to run at a
 * magnifying ratio. Turning both `jl` into unconditional `jmp` skips the clamps and
 * lets it do what it was written to do. Two bytes.
 *
 * The steppers are derived from source/destination ratio, so the source pointer stays
 * inside the movie buffer at any destination size -- the clamp is not what was keeping
 * the read in bounds. */
static int patch_blit_scale(void)
{
    static const BYTE SIG[]  = {0x3b,0xf2, 0x7c,0x06, 0x8b,0xf2, 0x89,0x74,0x24,0x20,
                                0x8b,0x54,0x24,0x1c, 0x2b,0xcf, 0x3b,0xd1, 0x7c,0x04,
                                0x89,0x4c,0x24,0x1c, 0x8b,0x0d,0,0,0,0};
    static const BYTE MASK[] = {   1,   1,    1,   1,    1,   1,    1,   1,   1,   1,
                                   1,   1,   1,   1,    1,   1,    1,   1,    1,   1,
                                   1,   1,   1,   1,    1,   1,0,0,0,0};
    BYTE *at = find_unique_masked(SIG, MASK, sizeof SIG, g_text, g_textlen, "movie blit clamps");
    if (!at) { logf_("[x] [blit] clamp signature not found"); return 0; }
    BYTE jmp_ = 0xEB;
    if (!poke(at + 2, &jmp_, 1) || !poke(at + 18, &jmp_, 1)) {
        logf_("[x] [blit] VirtualProtect failed"); return 0;
    }
    logf_("[+] [blit] destination clamps at %p removed (jl -> jmp): the movie scaler"
          " may now magnify past the source size", (void *)at);
    return 1;
}

/* ------------------------- s106 the HUD panel's movie is copied 1:1, not scaled
 *
 * The little edict/build movie in the bottom-right panel is `mainwin.win` widget 8:
 * class 0x040, virtual rect 2572,1481 560x560, painted by FUN_00531990.
 *
 * The DESTINATION is not the problem. That method scales its rect per-axis exactly
 * like every other widget class (s104.3):
 *
 *     movsx eax,[obj+0x0b] / fmul [0x5a0ffc]   -> destination left   (W/3200)
 *     movsx edx,[obj+0x0d] / fmul [0x5a1004]   -> destination top    (H/2400)
 *
 * What is wrong is that the movie is never scaled INTO it. At 0x531d1f the method
 * reads a per-widget flag and only compares the destination against the movie when
 * that flag is set:
 *
 *     mov  eax,[obj+0x7a]      ; the .WIN record's own +0x40 dword
 *     test eax,eax
 *     je   no_scale            ; -> needScale = 0
 *     ...  needScale = (destW != bink->Width || destH != bink->Height)
 *
 * and when needScale is 0 the destination is clamped back DOWN to the source size at
 * 0x531d8d, anchored at the rect's left/top, and copied 1:1.
 *
 * The flag is 0 for `mainwin.win` widget 8, and PopTop could afford that because the
 * asset was authored to match the rect at every mode they shipped. The movies are a
 * five-way per-resolution set like the art, and follow the same per-axis rule:
 *
 *     mode        rect = 560 x (W/3200, H/2400)      NN*.bik asset
 *     640x480     112.0 x 112.0                      112x112
 *     800x600     140.0 x 140.0                      140x140
 *     1024x768    179.2 x 179.2                      176x176
 *     1280x1024   224.0 x 238.9                      220x236    <- per-axis, 5:4
 *     1600x1200   280.0 x 280.0                      276x276
 *
 * At 1920x1080 the rect is 336x252 while slot 4 loads the 276x276 `16*.bik`: 60 px of
 * empty panel on the right and 24 rows of movie cut off at the bottom. Re-centring
 * cannot fix that -- the movie is the wrong SIZE for the panel, and has to be scaled
 * the way PopTop scaled it for 1280x1024.
 *
 * Setting the flag makes the engine's own comparison run and its own scaler (s69.6)
 * do the work. It is a no-op wherever the two already agree, so at 640x480 and
 * 800x600 nothing changes at all.
 *
 * TARGETED ON PURPOSE. Six class-0x040 widgets exist in the whole game; three already
 * carry the flag (`videowin`, `videowi2`, `setupe` -- the full-screen movies). Of the
 * three that do not, `videowi4` is a 1x1 dummy and `credits.win` widget 1 is a
 * 1240x1240 box holding a 248x248 movie that has never filled it at ANY resolution,
 * PopTop's own included. Flipping the flag in the shared code would magnify the
 * credits movie 2.5x at stock -- a change nobody asked for, somewhere that is not
 * broken. So this keys on the one widget's rect and refuses to fire on anything else.
 * That is s46's lesson read the other way round: a patch too BROAD, firing where it
 * should not.
 *
 * The tidier route -- editing `mainwin.win` and shipping it loose -- does not work.
 * s65.6: `.WIN` has its own loader and loose overrides are not read.
 *
 * Read-only counterpart: [Menu] HudMovieProbe logs what each class-0x040 paint
 * actually resolves to, so the numbers above can be checked rather than believed. */
static int g_hm_fixed;

static void __cdecl hm_fix_hook(BYTE *obj)
{
    /* The rect is already in place: FUN_0052a9f0 copied the record's first 0x40 bytes
     * to obj+4 one instruction before the site detoured here. */
    short x  = *(short *)(obj + 0x0b);
    short y  = *(short *)(obj + 0x0d);
    short cx = *(short *)(obj + 0x0f);
    short cy = *(short *)(obj + 0x11);
    if (x != 2572 || y != 1481 || cx != 560 || cy != 560) return;
    /* TWO flags, and the second one is the whole bug (s106.7).  obj+0x7e is read in
     * exactly one place -- 0x531545, right after BinkOpen -- where it means "resize
     * this widget to the movie", and it overwrites the authored 560x560 with the
     * movie's own size in virtual units.  Clearing it keeps the panel's rect;
     * setting obj+0x7a then lets the paint scale the movie into that rect. */
    if (*(DWORD *)(obj + 0x7a) == 1 && *(DWORD *)(obj + 0x7e) == 0) return;
    *(DWORD *)(obj + 0x7a) = 1;                    /* scale the movie to the widget */
    *(DWORD *)(obj + 0x7e) = 0;                    /* do NOT resize widget to movie */
    if (!g_hm_fixed++)
        logf_("  [movie] HUD panel widget (virtual %d,%d %dx%d): obj+0x7a 0 -> 1"
              " (scale the movie to the panel), obj+0x7e 1 -> 0 (stop resizing the"
              " panel to the movie)", x, y, cx, cy);
}

static int patch_hud_movie(void)
{
    /* FUN_005309c0's tail: the four class-0x040 extras copied out of the .WIN record
     * into obj+0x7a..+0x89.  Twenty-five bytes, no absolute addresses, and unique --
     * the shorter form collides with the class-0x008 deserialiser at 0x51a2c7. */
    static const BYTE SIG[] = {0x8b,0x47,0x40, 0x89,0x46,0x7a,
                               0x8b,0x4f,0x44, 0x89,0x4e,0x7e,
                               0x8b,0x57,0x48, 0x89,0x96,0x82,0x00,0x00,0x00,
                               0x8b,0x47,0x4c, 0x53};
    BYTE *at = find_unique(SIG, sizeof SIG, g_text, g_textlen,
                           "class-0x040 record copy (FUN_005309c0)");
    if (!at) { logf_("[x] [movie] class-0x040 constructor not found --"
                     " the HUD movie is NOT fixed"); return 0; }

    BYTE *stub = (BYTE *)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);
    if (!stub) { logf_("[x] [movie] VirtualAlloc failed"); return 0; }

    /* TWELVE bytes are relocated, not six.  The hook has to run AFTER the record's
     * +0x44 dword has been stored, or the store puts the resize flag straight back:
     *
     *     530a45  mov eax,[edi+0x40] / mov [esi+0x7a],eax
     *     530a4b  mov ecx,[edi+0x44] / mov [esi+0x7e],ecx   <- this one
     *
     * All four are position independent and nothing branches into the range. */
    int i = 0;
    memcpy(stub + i, at, 12); i += 12;
    stub[i++] = 0x60;                            /* pushad                */
    stub[i++] = 0x9c;                            /* pushfd                */
    stub[i++] = 0x56;                            /* push esi  (the widget) */
    stub[i++] = 0xe8;                            /* call hm_fix_hook      */
    { DWORD r = (DWORD)(SIZE_T)((BYTE *)hm_fix_hook - (stub + i + 4));
      memcpy(stub + i, &r, 4); i += 4; }
    stub[i++] = 0x83; stub[i++] = 0xc4; stub[i++] = 0x04;   /* add esp,4  */
    stub[i++] = 0x9d;                            /* popfd                 */
    stub[i++] = 0x61;                            /* popad                 */
    stub[i++] = 0xe9;                            /* jmp back past the four moves */
    { DWORD r = (DWORD)(SIZE_T)((at + 12) - (stub + i + 4));
      memcpy(stub + i, &r, 4); i += 4; }

    BYTE det[12];
    det[0] = 0xE9;
    { DWORD r = (DWORD)(SIZE_T)(stub - (at + 5)); memcpy(det + 1, &r, 4); }
    memset(det + 5, 0x90, 7);
    if (!poke(at, det, 12)) { logf_("[x] [movie] VirtualProtect failed"); return 0; }

    logf_("[+] [movie] class-0x040 record copy at %p detoured -> %p: the HUD panel's"
          " movie widget is marked scalable, so the engine fits the movie to the"
          " panel instead of copying it 1:1 into the corner.  No other widget is"
          " touched", (void *)at, (void *)stub);
    return 1;
}

/* ------------------------------------------------ s106 the HUD movie probe
 *
 * Read-only.  Detours the scalable-flag test in FUN_00531990 and prints, once per
 * distinct (destination, movie) pair, what the paint has actually resolved.  The
 * stack slots are the paint's own: [esp+0x14] destW and [esp+0x38] destH were written
 * at 0x531ab1/0x531abe, [esp+0x28] destTop at 0x531a56, and ebx has held destLeft
 * since 0x531a24.  esp has not moved since the prologue, so they are all still live
 * where this sits. */
static void __cdecl hm_probe_hook(BYTE *obj, int destL, const DWORD *fr)
{
    static struct { int w, h, mw, mh; } seen[8];
    static int n;
    int destT  = (int)fr[0x28 / 4];
    int destW  = (int)fr[0x14 / 4];
    int destH  = (int)fr[0x38 / 4];
    DWORD flag = *(DWORD *)(obj + 0x7a);
    DWORD rsz  = *(DWORD *)(obj + 0x7e);
    DWORD *bk  = *(DWORD **)(obj + 0x96);
    int mw = bk ? (int)bk[0] : 0;
    int mh = bk ? (int)bk[1] : 0;
    int k;
    for (k = 0; k < n; k++)
        if (seen[k].w == destW && seen[k].h == destH
            && seen[k].mw == mw && seen[k].mh == mh) return;
    if (n >= (int)(sizeof seen / sizeof seen[0])) return;
    seen[n].w = destW; seen[n].h = destH; seen[n].mw = mw; seen[n].mh = mh; n++;
    logf_("  [movie] widget virtual %d,%d %dx%d -> destination %d,%d %dx%d;"
          " movie %dx%d; scalable=%lu sizedtomovie=%lu -> %s",
          *(short *)(obj + 0x0b), *(short *)(obj + 0x0d),
          *(short *)(obj + 0x0f), *(short *)(obj + 0x11),
          destL, destT, destW, destH, mw, mh,
          (unsigned long)flag, (unsigned long)rsz,
          (flag && (destW != mw || destH != mh))
              ? "SCALED to fit the widget"
              : "copied 1:1 and clamped to the movie's own size");
}

static int patch_hud_movie_probe(void)
{
    static const BYTE SIG[] = {0x8b,0x45,0x7a, 0x85,0xc0, 0x74,0x1e,
                               0x8b,0x85,0x96,0x00,0x00,0x00,
                               0x8b,0x4c,0x24,0x14, 0x3b,0x08};
    BYTE *at = find_unique(SIG, sizeof SIG, g_text, g_textlen,
                           "class-0x040 scalable-flag test (FUN_00531990)");
    if (!at) { logf_("[x] [movie] paint signature not found -- HUD probe NOT armed");
               return 0; }

    BYTE *stub = (BYTE *)VirtualAlloc(NULL, 96, MEM_COMMIT | MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);
    if (!stub) { logf_("[x] [movie] VirtualAlloc failed"); return 0; }

    int i = 0;
    stub[i++] = 0x60;                                          /* pushad  esp -= 32 */
    stub[i++] = 0x9c;                                          /* pushfd  esp -= 4  */
    stub[i++] = 0x8d; stub[i++] = 0x44; stub[i++] = 0x24; stub[i++] = 0x24;
                                                    /* lea eax,[esp+0x24] -> paint esp */
    stub[i++] = 0x50;                                          /* push eax   (frame) */
    stub[i++] = 0x53;                                          /* push ebx   (destL) */
    stub[i++] = 0x55;                                          /* push ebp   (widget) */
    stub[i++] = 0xe8;
    { DWORD r = (DWORD)(SIZE_T)((BYTE *)hm_probe_hook - (stub + i + 4));
      memcpy(stub + i, &r, 4); i += 4; }
    stub[i++] = 0x83; stub[i++] = 0xc4; stub[i++] = 0x0c;      /* add esp,12 */
    stub[i++] = 0x9d;                                          /* popfd */
    stub[i++] = 0x61;                                          /* popad */
    memcpy(stub + i, at, 5); i += 5;             /* mov eax,[ebp+0x7a] / test eax,eax */
    stub[i++] = 0xe9;
    { DWORD r = (DWORD)(SIZE_T)((at + 5) - (stub + i + 4));
      memcpy(stub + i, &r, 4); i += 4; }

    BYTE det[5];
    det[0] = 0xE9;
    { DWORD r = (DWORD)(SIZE_T)(stub - (at + 5)); memcpy(det + 1, &r, 4); }
    if (!poke(at, det, 5)) { logf_("[x] [movie] VirtualProtect failed"); return 0; }

    logf_("[+] [movie] HUD movie probe armed at %p -> %p: every class-0x040 paint"
          " reports its destination against the movie it was handed",
          (void *)at, (void *)stub);
    return 1;
}

/* --------------------------------------------- s70 the map-preview probe
 *
 * The scenario screen's map preview tiles three across with the second band as colour
 * noise. Same 3x signature as the movie (1920/640) and noise means the SOURCE read is
 * running past its buffer.
 *
 * NOT caused by [Menu] FixMovieScale. The clamps that removed live in FUN_00531690,
 * which has exactly ONE caller -- the menu movie tick -- so nothing else can reach that
 * code. Structural, not a guess.
 *
 * The renderer is FUN_00492d40 (the map-selection screen; it also owns the rotated
 * "Map Size"/"Elevation" labels at 0x494aea). Its destination addressing reads correct:
 * row start = screenW*y + x at 0x494479, row advance = screenW*2 at 0x49465a. So the
 * fault is in what it is told to draw, not where. Log the geometry rather than keep
 * reading disassembly. */
/* Confirmed by the surface sweep: FUN_0044da90 draws the scenario preview (site 1,
 * 0x44de89, fired straight after s_c_loop.BIK opened). Its destination arithmetic reads
 * correct -- base + (y*screenW + x)*2, recomputed per row -- so the question is what
 * screenW and the surface actually ARE at draw time. The renderer takes its stride from
 * the SCREEN descriptor while writing to whichever surface is currently locked; if the
 * preview goes to an offscreen surface of a different width, that mismatch is the whole
 * bug and it is invisible at 640x480 where the two agree. */
static void __cdecl preview_hook(DWORD stride, DWORD y, DWORD x, DWORD rows)
{
    static int n;
    if (n >= 8) return;
    n++;
    logf_("  [preview] descriptor width=%lu  x=%ld y=%ld  lastrow=%ld   (mode %dx%d)",
          stride, (long)(int)x, (long)(int)y, (long)(int)rows,
          g_vt_xs_va ? (int)(*(float *)(SIZE_T)g_vt_xs_va * 3200.0f + 0.5f) : 0,
          g_vt_ys_va ? (int)(*(float *)(SIZE_T)g_vt_ys_va * 2400.0f + 0.5f) : 0);
}

static int patch_preview_probe(void)
{
    /* Two earlier versions of this probe fired ZERO times because they sat inside
     * FUN_00492d40 -- the SANDBOX map setup, not scenario selection. The surface sweep
     * settled it: the renderer is FUN_0044da90. Hook the instruction that loads the
     * stride, `movsx esi,[screen width]`, seven bytes. */
    static const BYTE SIG[]  = {0x0f,0xbf,0x35,0,0,0,0, 0x8b,0x44,0x24,0x34,
                                0x03,0xc1, 0x0f,0xaf,0xc6};
    static const BYTE MASK[] = {   1,   1,   1,0,0,0,0,    1,   1,   1,   1,
                                   1,   1,    1,   1,   1};
    BYTE *at = find_unique_masked(SIG, MASK, sizeof SIG, g_text, g_textlen, "map preview");
    if (!at) { logf_("[x] [preview] signature not found"); return 0; }

    BYTE *tr = (BYTE *)VirtualAlloc(NULL, 96, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tr) { logf_("[x] [preview] VirtualAlloc failed"); return 0; }
    int o = 0;
    tr[o++] = 0x60; tr[o++] = 0x9C;                                 /* pushad / pushfd    */
    /* after pushad+pushfd esp is 0x24 lower, so the callee's [esp+N] is [esp+0x24+N] */
    /* after pushad+pushfd, the callee's [esp+N] is at [esp+0x24+N] */
    tr[o++] = 0xFF; tr[o++] = 0x74; tr[o++] = 0x24; tr[o++] = 0x5C; /* push [esp+0x38] rows */
    tr[o++] = 0xFF; tr[o++] = 0x74; tr[o++] = 0x24; tr[o++] = 0x34; /* push [esp+0x10] x    */
    tr[o++] = 0xFF; tr[o++] = 0x74; tr[o++] = 0x24; tr[o++] = 0x58; /* push [esp+0x34] y    */
    tr[o++] = 0xB8; { DWORD v = g_surf_va - 5; memcpy(tr + o, &v, 4); o += 4; } /* mov eax,&descW */
    tr[o++] = 0x0F; tr[o++] = 0xB7; tr[o++] = 0x00;                 /* movzx eax,word [eax] */
    tr[o++] = 0x50;                                                 /* push eax  stride     */
    tr[o++] = 0xB8; { DWORD f = (DWORD)(SIZE_T)&preview_hook; memcpy(tr + o, &f, 4); o += 4; }
    tr[o++] = 0xFF; tr[o++] = 0xD0;                                 /* call eax           */
    tr[o++] = 0x83; tr[o++] = 0xC4; tr[o++] = 0x10;                 /* add esp,16         */
    tr[o++] = 0x9D; tr[o++] = 0x61;                                 /* popfd / popad      */
    memcpy(tr + o, at, 7); o += 7;                                  /* relocated movsx    */
    tr[o++] = 0xE9; { DWORD r = (DWORD)(SIZE_T)((at + 7) - (tr + o + 4)); memcpy(tr + o, &r, 4); o += 4; }

    BYTE det[7]; det[0] = 0xE9;
    { DWORD r = (DWORD)(SIZE_T)(tr - (at + 5)); memcpy(det + 1, &r, 4); }
    memset(det + 5, 0x90, 2);
    if (!poke(at, det, 7)) { logf_("[x] [preview] VirtualProtect failed"); return 0; }
    logf_("[+] [preview] map-preview draw at %p detoured -> %p", (void *)at, (void *)tr);
    return 1;
}

/* ------------------------------------------- s70 sweep every surface access
 *
 * Finding the map-preview renderer by reasoning about which screen owns which
 * function has now failed three times: FUN_00492d40 was probed twice and fired ZERO
 * times (it is the sandbox map setup, not scenario selection), stpruler.i16 turned out
 * not to be what is displayed, and [WorldFix] was exonerated by a control run.
 *
 * So stop naming candidates. Every path that draws to the screen must read the locked
 * surface base at [screen descriptor + 9]. Detour EVERY instruction in .text that
 * references it and log which ones fire while the scenario screen is up. The renderer
 * cannot hide from that.
 *
 * Each such instruction is `mov reg,[abs]` (5-6 bytes) or `add reg,[abs]` (6), all long
 * enough for a jmp rel32, and all position-independent, so relocating is a plain copy.
 * The descriptor VA is discovered from the movie clamp's own operand, not hardcoded. */

static BYTE *g_surf_site[32];
static int   g_surf_n;
static DWORD g_surf_hit;

static void __cdecl surface_hook(DWORD idx)
{
    /* One line per site, the first time it fires. A bitmask keeps this to a few dozen
     * bytes of work on what is a very hot path. */
    if (idx >= 32 || (g_surf_hit & (1u << idx))) return;
    g_surf_hit |= (1u << idx);
    logf_("  [surf] site %lu at %p FIRED", idx, (void *)g_surf_site[idx]);
}

static int patch_surface_probe(void)
{
    if (!g_surf_va) { logf_("[x] [surf] screen-descriptor VA unknown"); return 0; }
    DWORD va = g_surf_va;
    for (SIZE_T i = 0; i + 6 <= g_textlen && g_surf_n < 32; i++) {
        BYTE *p = g_text + i;
        int len = 0;
        if (p[0] == 0xA1 && rd32(p + 1) == va) len = 5;                 /* mov eax,[abs] */
        else if (p[0] == 0x8B && (p[1] == 0x0D || p[1] == 0x15 || p[1] == 0x1D ||
                                  p[1] == 0x25 || p[1] == 0x2D || p[1] == 0x35 ||
                                  p[1] == 0x3D) && rd32(p + 2) == va) len = 6;
        else if (p[0] == 0x03 && p[1] == 0x05 && rd32(p + 2) == va) len = 6; /* add eax,[abs] */
        if (!len) continue;

        BYTE *tr = (BYTE *)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!tr) continue;
        int idx = g_surf_n;
        int o = 0;
        tr[o++] = 0x60; tr[o++] = 0x9C;                       /* pushad / pushfd */
        tr[o++] = 0x68; { DWORD v = (DWORD)idx; memcpy(tr + o, &v, 4); o += 4; }
        tr[o++] = 0xB8; { DWORD f = (DWORD)(SIZE_T)&surface_hook; memcpy(tr + o, &f, 4); o += 4; }
        tr[o++] = 0xFF; tr[o++] = 0xD0;
        tr[o++] = 0x83; tr[o++] = 0xC4; tr[o++] = 0x04;
        tr[o++] = 0x9D; tr[o++] = 0x61;                       /* popfd / popad   */
        memcpy(tr + o, p, len); o += len;                     /* the original access */
        tr[o++] = 0xE9; { DWORD r = (DWORD)(SIZE_T)((p + len) - (tr + o + 4)); memcpy(tr + o, &r, 4); o += 4; }

        BYTE det[6]; det[0] = 0xE9;
        { DWORD r = (DWORD)(SIZE_T)(tr - (p + 5)); memcpy(det + 1, &r, 4); }
        if (len > 5) memset(det + 5, 0x90, len - 5);
        if (poke(p, det, len)) { g_surf_site[idx] = p; g_surf_n++; i += len - 1; }
    }
    logf_("[+] [surf] %d surface-access site(s) detoured (descriptor+9 = %08x)", g_surf_n, va);
    return g_surf_n > 0;
}

/* -------------------------------------------- s70 the scenario map preview
 *
 * FUN_0044da90 draws it (identified by sweeping every surface access; site 0x44de89
 * fires as the scenario screen loads). Its destination arithmetic is correct and the
 * screen descriptor really does read 1920 at draw time -- both verified -- so the fault
 * is neither the stride nor the addressing.
 *
 * It is the EXTENTS. The inner loop reads the source locked 1:1 to the destination
 * pointer:
 *
 *     ecx = src_base - dst_base        (a fixed delta, 0x44de9e)
 *     mov di,[ecx+ebp]                 (0x44deaa -- so source advances WITH dest)
 *     add ebp,2 / dec ebx / jne
 *
 * with ebx = the DESTINATION width in pixels, and the source row base advancing by a
 * hardcoded 0x158 bytes (0x44e00f) = 172 entries. So the loop draws dest-width pixels
 * out of a 172-wide source row. At 640x480 the preview rect is under 172 and it works.
 * At 1920x1080 it is about 3x that, so each output row runs on into the following
 * source rows -- three copies across -- and past the end of the map array vertically,
 * which is the colour noise. Every feature of the picture is accounted for.
 *
 * The proper fix is to STEP the source (nearest-neighbour), but the read is delta-locked
 * to the destination pointer, so that means replacing the loop. This clamps the extents
 * to the source instead: the preview draws at its native 172x172 rather than tiling. It
 * ends up smaller than its widget, which is honest -- there is no more source data --
 * and it is correct rather than corrupt.
 *
 * 172 is read from the stride immediate the code itself carries, not hardcoded. */
/* ---- s70.5 scaling mode --------------------------------------------------------
 *
 * The owner identified the second shape: it is the NEXT MAP's preview. Every map's
 * preview lives in ONE array, 172-entry rows stacked consecutively, so overrunning
 * map N's rows walks straight into map N+1. That is what the "colour noise" always was.
 *
 * It also means the vertical step must be EXACT -- one row too far is not a rounding
 * error, it is another map. So vertical scaling steps the source row POINTER with a
 * Bresenham accumulator rather than computing a row index:
 *
 *     acc += srcH ; while (acc >= dstH) { acc -= dstH ; edi += stride }
 *
 * Over dstH destination rows that advances edi exactly srcH-1 times, so it cannot leave
 * this map's rows. The first attempt used the horizontal ratio on BOTH axes and guessed
 * the row index from pointer arithmetic; both are gone.
 *
 * Horizontal stays a per-pixel nearest-neighbour lookup, because the loop's read is
 * delta-locked to the destination pointer and no register change makes it step. With
 * the row pointer now correct the read only needs the column:
 *
 *     addr = (rowdst + delta) + (i * srcw / dstw) * 2
 *
 * New-draw detection is exact rather than heuristic: within a draw, edi is only ever
 * written by our own hook, so an incoming edi that is not the one we last wrote means a
 * new draw. dstH comes from the loop's own bounds, both live in registers there. */

static DWORD g_pv_rowdst, g_pv_delta, g_pv_dstw, g_pv_srcw, g_pv_stride;
static DWORD g_pv_acc, g_pv_dsth, g_pv_last_edi, g_pv_edi;
static WORD  g_pv_pixel;

static void __cdecl pv_row(DWORD rowdst, DWORD delta, DWORD dstw)
{
    g_pv_rowdst = rowdst;
    g_pv_delta  = delta;
    g_pv_dstw   = dstw;
}

static void __cdecl pv_pixel(DWORD dst)
{
    g_pv_pixel = 0;
    if (!g_pv_dstw || !g_pv_srcw) return;
    int i = (int)((dst - g_pv_rowdst) >> 1);
    if (i < 0) return;
    int j = (int)(((__int64)i * (int)g_pv_srcw) / (int)g_pv_dstw);
    if (j < 0 || j >= (int)g_pv_srcw) return;
    g_pv_pixel = *(WORD *)(SIZE_T)(g_pv_rowdst + g_pv_delta + (DWORD)j * 2);
}

/* stands in for `add edi,stride` at the bottom of the row loop */
static void __cdecl pv_adv(DWORD edi, DWORD row, DWORD lastrow)
{
    if (edi != g_pv_last_edi) {
        g_pv_acc = 0;
        int h = (int)lastrow - (int)row + 2;   /* row has already been incremented */
        g_pv_dsth = (h > 0) ? (DWORD)h : 1;
    }
    g_pv_acc += g_pv_srcw;
    while (g_pv_dsth && g_pv_acc >= g_pv_dsth) { g_pv_acc -= g_pv_dsth; edi += g_pv_stride; }
    g_pv_last_edi = edi;
    g_pv_edi      = edi;
}

static int patch_preview_fix(int mode)
{
    /* B first: it carries the stride, and tells us the source width.
     *   mov eax,[esp+0x34] / mov edi,[esp+0x28] / inc eax / add edi,0x158 / cmp eax,edx */
    static const BYTE SB[]  = {0x8b,0x44,0x24,0x34, 0x8b,0x7c,0x24,0x28, 0x40,
                               0x81,0xc7,0,0,0,0, 0x3b,0xc2};
    static const BYTE MB[]  = {   1,   1,   1,   1,    1,   1,   1,   1,    1,
                                  1,   1,0,0,0,0,    1,   1};
    BYTE *b = find_unique_masked(SB, MB, sizeof SB, g_text, g_textlen, "preview row loop");
    if (!b) { logf_("[x] [preview] row-loop signature not found"); return 0; }
    DWORD stride = rd32(b + 11);
    if (!stride || (stride & 1)) { logf_("[x] [preview] odd stride %lu -- refusing", stride); return 0; }
    DWORD srcw = stride / 2;

    g_pv_srcw = srcw; g_pv_stride = stride;

    /*   mov [esp+0x24],ecx / inc ebx / mov di,[ecx+ebp] / test di,di */
    static const BYTE SA[]  = {0x89,0x4c,0x24,0x24, 0x43, 0x66,0x8b,0x3c,0x29, 0x66,0x85,0xff};
    static const BYTE MA[]  = {   1,   1,   1,   1,    1,    1,   1,   1,   1,    1,   1,   1};
    BYTE *a = find_unique_masked(SA, MA, sizeof SA, g_text, g_textlen, "preview row count");
    if (!a) { logf_("[x] [preview] row-count signature not found"); return 0; }

    if (mode >= 2) {
        /* --- per-row setup: record rowdst / srcbase / dstw, no clamping --- */
        BYTE *tr = (BYTE *)VirtualAlloc(NULL, 96, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!tr) { logf_("[x] [preview] VirtualAlloc failed"); return 0; }
        int o = 0;
        tr[o++] = 0x60; tr[o++] = 0x9C;
        tr[o++] = 0x53;                                   /* push ebx (dstw)  */
        tr[o++] = 0x51;                                   /* push ecx (delta) */
        tr[o++] = 0x55;                                   /* push ebp (rowdst)*/
        tr[o++] = 0xB8; { DWORD f = (DWORD)(SIZE_T)&pv_row; memcpy(tr + o, &f, 4); o += 4; }
        tr[o++] = 0xFF; tr[o++] = 0xD0;
        tr[o++] = 0x83; tr[o++] = 0xC4; tr[o++] = 0x0C;
        tr[o++] = 0x9D; tr[o++] = 0x61;
        memcpy(tr + o, a, 5); o += 5;                     /* mov [esp+0x24],ecx / inc ebx */
        tr[o++] = 0xE9; { DWORD r = (DWORD)(SIZE_T)((a + 5) - (tr + o + 4)); memcpy(tr + o, &r, 4); o += 4; }
        BYTE det[5]; det[0] = 0xE9;
        { DWORD r = (DWORD)(SIZE_T)(tr - (a + 5)); memcpy(det + 1, &r, 4); }
        if (!poke(a, det, 5)) { logf_("[x] [preview] VirtualProtect failed (row)"); return 0; }

        /* --- the read: mov di,[ecx+ebp] / test di,di  (4 + 3 bytes) --- */
        BYTE *rd = a + 5;
        if (!(rd[0] == 0x66 && rd[1] == 0x8b && rd[2] == 0x3c && rd[3] == 0x29)) {
            logf_("[x] [preview] read instruction not where expected"); return 0;
        }
        BYTE *t2 = (BYTE *)VirtualAlloc(NULL, 96, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!t2) { logf_("[x] [preview] VirtualAlloc failed"); return 0; }
        DWORD px = (DWORD)(SIZE_T)&g_pv_pixel;
        o = 0;
        t2[o++] = 0x60; t2[o++] = 0x9C;
        t2[o++] = 0x55;                                   /* push ebp (dest ptr) */
        t2[o++] = 0xB8; { DWORD f = (DWORD)(SIZE_T)&pv_pixel; memcpy(t2 + o, &f, 4); o += 4; }
        t2[o++] = 0xFF; t2[o++] = 0xD0;
        t2[o++] = 0x83; t2[o++] = 0xC4; t2[o++] = 0x04;
        t2[o++] = 0x9D; t2[o++] = 0x61;                   /* popfd / popad       */
        t2[o++] = 0x66; t2[o++] = 0x8B; t2[o++] = 0x3D;   /* mov di,[g_pv_pixel] */
        memcpy(t2 + o, &px, 4); o += 4;
        t2[o++] = 0x66; t2[o++] = 0x85; t2[o++] = 0xFF;   /* test di,di          */
        t2[o++] = 0xE9; { DWORD r = (DWORD)(SIZE_T)((rd + 7) - (t2 + o + 4)); memcpy(t2 + o, &r, 4); o += 4; }
        BYTE d2[7]; d2[0] = 0xE9;
        { DWORD r = (DWORD)(SIZE_T)(t2 - (rd + 5)); memcpy(d2 + 1, &r, 4); }
        memset(d2 + 5, 0x90, 2);
        if (!poke(rd, d2, 7)) { logf_("[x] [preview] VirtualProtect failed (read)"); return 0; }

        /* --- the row advance: `add edi,stride`, six bytes at b+9 --- */
        BYTE *ad = b + 9;
        if (!(ad[0] == 0x81 && ad[1] == 0xC7)) {
            logf_("[x] [preview] row-advance instruction not where expected"); return 0;
        }
        BYTE *t3 = (BYTE *)VirtualAlloc(NULL, 96, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!t3) { logf_("[x] [preview] VirtualAlloc failed"); return 0; }
        DWORD ev = (DWORD)(SIZE_T)&g_pv_edi;
        o = 0;
        t3[o++] = 0x60; t3[o++] = 0x9C;
        t3[o++] = 0x52; t3[o++] = 0x50; t3[o++] = 0x57;  /* push edx(last)/eax(row)/edi */
        t3[o++] = 0xB8; { DWORD f = (DWORD)(SIZE_T)&pv_adv; memcpy(t3 + o, &f, 4); o += 4; }
        t3[o++] = 0xFF; t3[o++] = 0xD0;
        t3[o++] = 0x83; t3[o++] = 0xC4; t3[o++] = 0x0C;
        t3[o++] = 0x9D; t3[o++] = 0x61;
        t3[o++] = 0x8B; t3[o++] = 0x3D; memcpy(t3 + o, &ev, 4); o += 4; /* mov edi,[g_pv_edi] */
        t3[o++] = 0xE9; { DWORD r = (DWORD)(SIZE_T)((ad + 6) - (t3 + o + 4)); memcpy(t3 + o, &r, 4); o += 4; }
        BYTE d3[6]; d3[0] = 0xE9;
        { DWORD r = (DWORD)(SIZE_T)(t3 - (ad + 5)); memcpy(d3 + 1, &r, 4); }
        d3[5] = 0x90;
        if (!poke(ad, d3, 6)) { logf_("[x] [preview] VirtualProtect failed (advance)"); return 0; }

        logf_("[+] [preview] SCALING mode: source %lux%lu stride %lu; column lookup at %p,"
              " row stepping at %p", srcw, srcw, stride, (void *)rd, (void *)ad);
        return 1;
    }

    /* --- A: clamp the per-row pixel count to the source width --- */
    {
        BYTE *tr = (BYTE *)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!tr) { logf_("[x] [preview] VirtualAlloc failed"); return 0; }
        int o = 0;
        memcpy(tr + o, a, 5); o += 5;                       /* mov [esp+0x24],ecx / inc ebx */
        tr[o++] = 0x81; tr[o++] = 0xFB;                     /* cmp ebx,srcw                 */
        memcpy(tr + o, &srcw, 4); o += 4;
        tr[o++] = 0x7E; tr[o++] = 0x06;                     /* jle +6                       */
        tr[o++] = 0xBB; memcpy(tr + o, &srcw, 4); o += 4;   /* mov ebx,srcw                 */
        tr[o++] = 0x90;
        tr[o++] = 0xE9; { DWORD r = (DWORD)(SIZE_T)((a + 5) - (tr + o + 4)); memcpy(tr + o, &r, 4); o += 4; }
        BYTE det[5]; det[0] = 0xE9;
        { DWORD r = (DWORD)(SIZE_T)(tr - (a + 5)); memcpy(det + 1, &r, 4); }
        if (!poke(a, det, 5)) { logf_("[x] [preview] VirtualProtect failed (A)"); return 0; }
    }

    /* --- B: clamp the row count to the source height (square: same value) --- */
    {
        BYTE *tr = (BYTE *)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!tr) { logf_("[x] [preview] VirtualAlloc failed"); return 0; }
        int o = 0;
        tr[o++] = 0x81; tr[o++] = 0xFA;                     /* cmp edx,srcw                 */
        memcpy(tr + o, &srcw, 4); o += 4;
        tr[o++] = 0x7E; tr[o++] = 0x05;                     /* jle +5                       */
        tr[o++] = 0xBA; memcpy(tr + o, &srcw, 4); o += 4;   /* mov edx,srcw                 */
        memcpy(tr + o, b, 8); o += 8;                       /* the two relocated movs       */
        tr[o++] = 0xE9; { DWORD r = (DWORD)(SIZE_T)((b + 8) - (tr + o + 4)); memcpy(tr + o, &r, 4); o += 4; }
        BYTE det[8]; det[0] = 0xE9;
        { DWORD r = (DWORD)(SIZE_T)(tr - (b + 5)); memcpy(det + 1, &r, 4); }
        memset(det + 5, 0x90, 3);
        if (!poke(b, det, 8)) { logf_("[x] [preview] VirtualProtect failed (B)"); return 0; }
    }
    logf_("[+] [preview] extents clamped to the source (%lu from stride %lu) at %p / %p",
          srcw, stride, (void *)a, (void *)b);
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
        {   DWORD a_dy=(DWORD)(SIZE_T)&g_chr_dirty; int d1;
            stub[i++]=0x83; stub[i++]=0x3d; memcpy(stub+i,&a_dy,4); i+=4; stub[i++]=0x00;
            stub[i++]=0x74; d1=i++;                                   /* cmp dirty,0; je    */
            stub[i++]=0x66; stub[i++]=0xc7; stub[i++]=0x41; stub[i++]=0x0f;
            stub[i++]=0x00; stub[i++]=0x00;                           /* mov w[ecx+0x0f],0  */
            stub[i++]=0x66; stub[i++]=0xc7; stub[i++]=0x41; stub[i++]=0x11;
            stub[i++]=0x00; stub[i++]=0x00;                           /* mov w[ecx+0x11],0  */
            if (!fix_short(stub, d1, i, "dirty")) return 0;
        }
        {   DWORD a_ch=(DWORD)(SIZE_T)&g_chr_hits;
            DWORD a_rc=(DWORD)(SIZE_T)&g_chr_rect, a_ps=(DWORD)(SIZE_T)&g_chr_pos;
            DWORD a_z =(DWORD)(SIZE_T)&g_chr_zero;
            int z1;
            stub[i++]=0xff; stub[i++]=0x05; memcpy(stub+i,&a_ch,4); i+=4;  /* inc [g_chr_hits] */
            /* Replay a remembered absolute rect.  Never a read-modify-write:
             * runs M and Q both died on those. */
            {   DWORD a_ap=(DWORD)(SIZE_T)&g_chr_apply;
                DWORD f[4]; int z1;
                f[0]=(DWORD)(SIZE_T)&g_chr_setx;  f[1]=(DWORD)(SIZE_T)&g_chr_sety;
                f[2]=(DWORD)(SIZE_T)&g_chr_setcx; f[3]=(DWORD)(SIZE_T)&g_chr_setcy;
                static const BYTE FL[4] = { 0x0b, 0x0d, 0x0f, 0x11 };
                stub[i++]=0x83; stub[i++]=0x3d; memcpy(stub+i,&a_ap,4); i+=4; stub[i++]=0x00;
                stub[i++]=0x74; z1=i++;                                  /* cmp apply,0; je */
                for (int k = 0; k < 4; k++) {
                    stub[i++]=0xa1; memcpy(stub+i,&f[k],4); i+=4;        /* mov eax,[val]   */
                    stub[i++]=0x66; stub[i++]=0x89; stub[i++]=0x41; stub[i++]=FL[k];
                }
                if (!fix_short(stub, z1, i, "apply")) return 0;
            }
            /* record THIS widget's rect and position, so the log can speak about
             * the bar rather than about whatever drew last */
            stub[i++]=0x8b; stub[i++]=0x51; stub[i++]=0x0f;
            stub[i++]=0x89; stub[i++]=0x15; memcpy(stub+i,&a_rc,4); i+=4;  /* rect  = [+0x0f] */
            stub[i++]=0x8b; stub[i++]=0x51; stub[i++]=0x0b;
            stub[i++]=0x89; stub[i++]=0x15; memcpy(stub+i,&a_ps,4); i+=4;  /* pos   = [+0x0b] */
            /* obj+0x88 / obj+0x8c -- the origin pair the style-0 draw ADDS to the
             * position.  s54.3 predicted they cancel the scale factor exactly; the
             * owner's report that the bar moved says otherwise.  Logging both ends
             * of the sum settles it by arithmetic instead of by another guess. */
            {   DWORD a_ox=(DWORD)(SIZE_T)&g_chr_ox, a_oy=(DWORD)(SIZE_T)&g_chr_oy;
                stub[i++]=0x8b; stub[i++]=0x91; memcpy(stub+i,"\x88\x00\x00\x00",4); i+=4;
                stub[i++]=0x89; stub[i++]=0x15; memcpy(stub+i,&a_ox,4); i+=4;
                stub[i++]=0x8b; stub[i++]=0x91; memcpy(stub+i,"\x8c\x00\x00\x00",4); i+=4;
                stub[i++]=0x89; stub[i++]=0x15; memcpy(stub+i,&a_oy,4); i+=4;
            }
        }
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
            (void)ART_W; (void)ART_H; (void)sl; (void)lw; (void)lh;
            /* factors are owned by chrome_factor_thread, which starts at DLL load */
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
                g_chr_zero  = 0;
                /* mode 3 = replay the learned rect with its bottom-right pulled
                 * EdgeTrim virtual units inside the screen.  s59: the style-1 blit
                 * REJECTS the whole draw when x2 or y2 lands on or past the screen
                 * edge (0x5004d3 / 0x5004ea, jge -> 0x500960), and the bar's correct
                 * rect ends at 1080.05 px on a 1080-tall screen -- 0.05 px too far. */
                if (g_hud_ph_size[ph] == 3 && g_chr_base) {
                    g_chr_setcx = (DWORD)(WORD)(short)((short)g_chr_setcx - (short)g_chr_trim);
                    g_chr_setcy = (DWORD)(WORD)(short)((short)g_chr_setcy - (short)g_chr_trim);
                    g_chr_apply = 1;
                    logf_("  [chrome] replaying learned rect TRIMMED by %lu virtual units:"
                          " x=%d y=%d w=%d h=%d", (unsigned long)g_chr_trim,
                          (short)g_chr_setx, (short)g_chr_sety,
                          (short)g_chr_setcx, (short)g_chr_setcy);
                } else {
                    g_chr_apply = 0;
                }
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
        if (g_chr_enable) {
            short cx = (short)(g_chr_rect & 0xffff), cy = (short)(g_chr_rect >> 16);
            /* learn the engine's own computed rect once it looks like the bar */
            if (!g_chr_apply && cx > 1000 && cy > 100) {
                g_chr_setx = (DWORD)(WORD)(short)(g_chr_pos & 0xffff);
                g_chr_sety = (DWORD)(WORD)(short)(g_chr_pos >> 16);
                g_chr_setcx = (DWORD)(WORD)cx; g_chr_setcy = (DWORD)(WORD)cy;
                g_chr_base = 1;
            }
            short px = (short)(g_chr_pos  & 0xffff), py = (short)(g_chr_pos  >> 16);
            DWORD lw2 = wfb_read16(0x60c18c), lh2 = wfb_read16(0x60c18e);
            logf_("  [chrome] path-B draws=%lu | BAR rect x=%d y=%d w=%d h=%d virtual"
                  "  ->  px x=%ld y=%ld w=%ld h=%ld%s",
                  (unsigned long)g_chr_hits, px, py, cx, cy,
                  (long)px * (long)lw2 / 3200, (long)py * (long)lh2 / 2400,
                  (long)cx * (long)lw2 / 3200, (long)cy * (long)lh2 / 2400,
                  g_chr_zero ? "   [position ZEROED this phase]" : "");
            /* the style-0 draw hands the blit (X + origin), so this IS the number
             * that decides where the bar lands -- print it, do not infer it */
            logf_("  [chrome]   origin +0x88=%ld +0x8c=%ld  ->  style-0 draw position"
                  " = (%ld, %ld) virtual = (%ld, %ld) px%s",
                  (long)(int)g_chr_ox, (long)(int)g_chr_oy,
                  (long)px + (long)(int)g_chr_ox, (long)py + (long)(int)g_chr_oy,
                  ((long)px + (long)(int)g_chr_ox) * (long)lw2 / 3200,
                  ((long)py + (long)(int)g_chr_oy) * (long)lh2 / 2400,
                  (px + (int)g_chr_ox == 0 && py + (int)g_chr_oy == 0)
                      ? "   <- CANCELS, so s54.3 was right and only the clip moved"
                      : "   <- does NOT cancel, so s54.3 was wrong");
        }
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

/* ------------------------------------------------------- s103 the blit census
 *
 * FINDINGS 102 named the pair -- the "shadows" are mwbuildf/mwinfof sprites drawn
 * by class-4 widgets, the buttons are class-1 widgets positioned from the .WIN --
 * and then killed every mechanism that could be read out of the files.  The art is
 * generated exactly as PopTop's own 1280x1024 set says it should be, the .WIN
 * arithmetic agrees, and compositing both rules offline at 1600x1200 and 1920x1080
 * puts the buttons in the SAME relative place inside their plates.  So the offset
 * is introduced at draw time and nothing on disk will show it.
 *
 * WHY THE LEAF AND NOT THE DISPATCHER.  The obvious hook is FUN_00501b90, but
 * s50.7 already establishes what it receives: a position and nothing else.  All
 * ten mwbuildf plates belong to widgets whose rect is 0,0, so at the dispatcher
 * they are ten identical calls -- the per-sprite offset that actually separates
 * the plates lives in the piece record and is applied further down.  Hooking the
 * dispatcher would log the widget origin and miss the very quantity in question.
 *
 * FUN_00538ba0 is the plain leaf (s62.1).  Its entry was read, not guessed:
 *
 *      sub esp,0x30 ; movsx eax,[ecx]        piece.x   (int16 at rec+0)
 *      ...          ; movsx edi,[ecx+2]      piece.y   (int16 at rec+2)
 *      add eax,[esp+0x44]                    + arg1    -> absolute dest X
 *      add edi,esi (esi = [esp+0x44]/arg2)   + arg2    -> absolute dest Y
 *      movsx edx,[ecx+4]                     piece.w   (int16 at rec+4)
 *      movsx eax,[ecx+6]                     piece.h   (int16 at rec+6)
 *
 * and args 4..7 are the clip box, which is what identifies them: the four early
 * rejects test dest_x > arg6, dest_x+w-1 < arg4, dest_y > arg7, dest_y+h-1 < arg5.
 * So one hook here yields, for EVERY sprite of EVERY widget class, the source size
 * and the absolute destination.  That is the census.
 *
 * A CENSUS, NOT A STREAM.  This is the hottest path in the game -- every piece of
 * every sprite of every frame.  Logging from inside it would change the thing being
 * measured and produce a hundred megabytes of duplicate lines.  Instead each
 * distinct (w, h, x, y) is recorded once in a fixed table with a hit counter, via a
 * hash so the hot path is O(1) and does no I/O at all; a separate thread prints the
 * table.  Sprites land at fixed places, so the table saturates in the first frame
 * and then only the counters move.
 */
#define BC_CAP 8192u                     /* distinct (w,h,x,y) tuples kept       */
typedef struct { short w, h, x, y; unsigned hits; } bc_row;
static bc_row  g_bc[BC_CAP];
static unsigned g_bc_used, g_bc_lost;    /* lost = tuples dropped once full      */

/* Open addressing, power-of-two capacity, linear probe.  No locks: a torn read in
 * a counter costs one hit in a diagnostic, and taking a lock in this path would
 * perturb the frame time it is meant to observe. */
static void bc_note(int w, int h, int x, int y)
{
    unsigned k = (unsigned)((w * 73856093) ^ (h * 19349663) ^ (x * 83492791) ^ (y * 2654435761u));
    k &= (BC_CAP - 1);
    for (unsigned n = 0; n < 64; n++) {
        bc_row *r = &g_bc[(k + n) & (BC_CAP - 1)];
        if (r->hits == 0) {
            if (g_bc_used >= BC_CAP - 64) { g_bc_lost++; return; }
            r->w = (short)w; r->h = (short)h; r->x = (short)x; r->y = (short)y;
            r->hits = 1; g_bc_used++; return;
        }
        if (r->w == w && r->h == h && r->x == x && r->y == y) { r->hits++; return; }
    }
    g_bc_lost++;
}

/* __cdecl so the stub can push three arguments and clean up with one add. */
static void __cdecl bc_hook(const short *rec, int bx, int by)
{
    int x, y;
    if (!rec) return;
    x = bx + rec[0]; y = by + rec[1];
    /* The world draws through this leaf as well, and terrain lands at hundreds of
     * distinct positions -- left unfiltered it saturates the table and buries the
     * HUD.  MinY is the escape hatch: the HUD sits in the bottom band, so a floor
     * a little above the bar's top edge keeps the census to the widgets.  Default
     * 0 keeps everything, which is the right default for the first run. */
    if (y < g_bc_miny) return;
    bc_note(rec[2], rec[3], x, y);
}

static int bc_cmp(const void *a, const void *b)
{
    unsigned ha = ((const bc_row *)a)->hits, hb = ((const bc_row *)b)->hits;
    return ha < hb ? 1 : ha > hb ? -1 : 0;      /* descending */
}

/* Sorting by hit count is the whole trick for reading this.  A HUD sprite is
 * redrawn at the SAME position every frame, so its counter tracks the frame count;
 * scrolling terrain spreads over hundreds of positions that each accumulate a few
 * hits and then never recur.  Descending hits therefore floats the fixed furniture
 * -- which is exactly the HUD -- to the top, with no knowledge of what the assets
 * are.  The table is copied first: the game keeps writing to it while this runs,
 * and sorting underneath a live writer is how a diagnostic starts lying. */
static void bc_dump(const char *why)
{
    bc_row *snap = (bc_row *)malloc(sizeof(bc_row) * BC_CAP);
    unsigned n = 0, shown = 0;
    if (!snap) { logf_("[x] [blit] out of memory for the census snapshot"); return; }
    for (unsigned i = 0; i < BC_CAP; i++)
        if (g_bc[i].hits) snap[n++] = g_bc[i];
    qsort(snap, n, sizeof(bc_row), bc_cmp);

    logf_("[*] [blit] ==== census (%s) -- the last %d s only: %u distinct"
          " (size @ position) tuples%s.  Most-drawn first -- fixed furniture floats"
          " up, scrolling terrain sinks.",
          why, g_bc_every, n,
          g_bc_lost ? ", TABLE OVERFLOWED so some were DROPPED" : "");
    for (unsigned i = 0; i < n; i++) {
        logf_("  [blit] %4dx%-4d at %5d,%-5d   x%u",
              snap[i].w, snap[i].h, snap[i].x, snap[i].y, snap[i].hits);
        if (++shown >= 400) {
            logf_("  [blit] ... %u further tuples NOT printed (all with %u hits or"
                  " fewer)", n - shown, snap[i].hits);
            break;
        }
    }
    logf_("[*] [blit] ==== end census");
    free(snap);

    /* Clear for the next window.  MEASURED, not tidiness: a single run saturated
     * the 8192-slot table, and a full table drops NEW tuples -- so a HUD panel
     * opened late in a session would never be recorded at all, and the census
     * would look complete while silently missing the thing being investigated.
     * Resetting makes each dump a WINDOW rather than a cumulative total, which is
     * also the more useful reading: whatever is on screen now is redrawn every
     * frame and so re-enters the table within one frame of the reset. */
    memset(g_bc, 0, sizeof g_bc);
    g_bc_used = 0; g_bc_lost = 0;
}

static DWORD WINAPI bc_thread(LPVOID unused)
{
    (void)unused;
    Sleep((DWORD)g_bc_delay * 1000);
    for (;;) {
        bc_dump("periodic");
        if (g_bc_every <= 0) return 0;
        Sleep((DWORD)g_bc_every * 1000);
    }
}

/* The 24-byte entry above, with no absolute operand in it, so the same bytes match
 * any build.  Verified unique in the GOG .text -- and it has to be, because the
 * ~16 leaves resemble each other closely and hooking the wrong one would produce a
 * census of the wrong sprites while looking perfectly healthy. */
static const BYTE BLIT_SIG[] = {
    0x83,0xec,0x30,             /* sub   esp,0x30                */
    0x0f,0xbf,0x01,             /* movsx eax,WORD PTR [ecx]      */
    0x53, 0x55, 0x56,           /* push  ebx / ebp / esi         */
    0x8b,0x74,0x24,0x44,        /* mov   esi,[esp+0x44]          */
    0x57,                       /* push  edi                     */
    0x03,0x44,0x24,0x44,        /* add   eax,[esp+0x44]          */
    0x0f,0xbf,0x79,0x02,        /* movsx edi,WORD PTR [ecx+0x2]  */
    0x8b,0xea                   /* mov   ebp,edx                 */
};

static int patch_blit_census(void)
{
    BYTE *fn = find_unique(BLIT_SIG, sizeof BLIT_SIG, g_text, g_textlen,
                           "leaf blitter (FUN_00538ba0)");
    if (!fn) { logf_("[x] [blit] leaf blitter signature not found -- census NOT armed");
               return 0; }

    BYTE *stub = (BYTE *)VirtualAlloc(NULL, 128, MEM_COMMIT | MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);
    if (!stub) { logf_("[x] [blit] VirtualAlloc failed"); return 0; }

    /* Six bytes are relocated (sub esp,0x30 ; movsx eax,[ecx]) -- both are
     * position independent, so they can simply be copied. */
    int i = 0;
    stub[i++] = 0x60;                                   /* pushad   esp -= 32   */
    stub[i++] = 0x9c;                                   /* pushfd   esp -= 4    */
    /* At function entry [esp+4]=arg1, [esp+8]=arg2.  36 bytes of saves are now
     * below that, and each push moves the window another 4. */
    stub[i++] = 0xff; stub[i++] = 0x74; stub[i++] = 0x24; stub[i++] = 0x2c; /* push [esp+0x2c] -> arg2 */
    stub[i++] = 0xff; stub[i++] = 0x74; stub[i++] = 0x24; stub[i++] = 0x2c; /* push [esp+0x2c] -> arg1 */
    stub[i++] = 0x51;                                   /* push ecx  (piece rec) */
    stub[i++] = 0xe8;                                   /* call bc_hook          */
    { DWORD r = (DWORD)(SIZE_T)((BYTE *)bc_hook - (stub + i + 4));
      memcpy(stub + i, &r, 4); i += 4; }
    stub[i++] = 0x83; stub[i++] = 0xc4; stub[i++] = 0x0c;   /* add esp,12        */
    stub[i++] = 0x9d;                                   /* popfd                 */
    stub[i++] = 0x61;                                   /* popad                 */
    memcpy(stub + i, fn, 6); i += 6;                    /* the relocated entry   */
    stub[i++] = 0xe9;                                   /* jmp back past it      */
    { DWORD r = (DWORD)(SIZE_T)((fn + 6) - (stub + i + 4));
      memcpy(stub + i, &r, 4); i += 4; }

    BYTE det[6];
    det[0] = 0xE9;
    { DWORD r = (DWORD)(SIZE_T)(stub - (fn + 5)); memcpy(det + 1, &r, 4); }
    det[5] = 0x90;
    if (!poke(fn, det, 6)) { logf_("[x] [blit] VirtualProtect failed"); return 0; }

    logf_("[+] [blit] census armed on the leaf blitter at %p (stub %p, %d bytes)."
          "  Every sprite's SOURCE SIZE and ABSOLUTE DESTINATION is tallied%s; the"
          " table prints %d s in and every %d s after.",
          (void *)fn, (void *)stub, i,
          g_bc_miny ? " for destinations at or below MinY" : "",
          g_bc_delay, g_bc_every);
    if (g_bc_miny)
        logf_("  [blit] MinY=%d -- sprites landing above that row are NOT counted",
              g_bc_miny);
    CreateThread(NULL, 0, bc_thread, NULL, 0, NULL);
    return 1;
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
    if (g_chr_enable) CreateThread(NULL, 0, chrome_factor_thread, NULL, 0, NULL);
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


/* ==================================================== s99 file-order probe
 *
 * WHY. The art has to be finished before the game indexes data\, and the only
 * trigger the proxy has today -- the first GetDeviceCaps -- is measurably too
 * late on the Steam edition (FINDINGS 98). The replacement is to hook a file-open
 * entry point instead and do the work on the first file the game touches, which
 * necessarily precedes the index. That rests on two claims, and NEITHER can be
 * checked statically: SteamStub leaves .idata as ciphertext on disk, so the
 * import table simply is not readable until the loader has resolved it.
 *
 *   (a) a hookable open entry point is in the exe's imports at all
 *   (b) the first open really does come before the data\ index
 *
 * This answers both in one run. It dumps the import table the loader actually
 * resolved, hooks every plausible way a 2001 game opens a file, numbers the
 * first calls in order, and records where GetDeviceCaps lands among them. It
 * changes NO behaviour: every hook logs and tail-calls the real function.
 *
 * Gated by the INI rather than an environment variable, deliberately. The Steam
 * edition can only be started from Steam's Play button, and putting an env var
 * in front of that needs launch options -- the exact thing this work exists to
 * avoid needing. An ini key is editable in the game folder either way.
 *
 *   [FileOrder]
 *   Enable=1
 */

typedef HANDLE (WINAPI *CreateFileA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
                                       DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI *CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
                                       DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI *FindFirstFileA_t)(LPCSTR, LPWIN32_FIND_DATAA);
typedef HFILE  (WINAPI *OpenFile_t)(LPCSTR, LPOFSTRUCT, UINT);
typedef HFILE  (WINAPI *lopen_t)(LPCSTR, int);
typedef void  *(__cdecl *fopen_t)(const char *, const char *);

static CreateFileA_t    g_fo_cfa;
static CreateFileW_t    g_fo_cfw;
static FindFirstFileA_t g_fo_ffa;
static OpenFile_t       g_fo_of;
static lopen_t          g_fo_lo;
static fopen_t          g_fo_fo;

#define FO_MAX 60

/* Number every open in call order. The ORDER is the entire measurement -- which
 * file is first, and whether the data\ index shows up before or after the point
 * GetDeviceCaps fires. Past FO_MAX say so once, so a truncated list is never
 * mistaken for a complete one. */
static void fo_note(const char *api, const char *name)
{
    LONG n = InterlockedIncrement(&g_fo_n);
    if (n <= FO_MAX) logf_("  [fileorder] %3ld  %-14s %s", (long)n, api, name ? name : "(null)");
    else if (n == FO_MAX + 1) logf_("  [fileorder] ... beyond %d opens, no longer listing", FO_MAX);
}

static HANDLE WINAPI fo_CreateFileA(LPCSTR n, DWORD a, DWORD s, LPSECURITY_ATTRIBUTES sa,
                                    DWORD c, DWORD f, HANDLE t)
{ fo_note("CreateFileA", n); return g_fo_cfa(n, a, s, sa, c, f, t); }

static HANDLE WINAPI fo_CreateFileW(LPCWSTR n, DWORD a, DWORD s, LPSECURITY_ATTRIBUTES sa,
                                    DWORD c, DWORD f, HANDLE t)
{
    char nm[MAX_PATH] = "(wide)";
    if (n) WideCharToMultiByte(CP_ACP, 0, n, -1, nm, sizeof nm - 1, NULL, NULL);
    fo_note("CreateFileW", nm);
    return g_fo_cfw(n, a, s, sa, c, f, t);
}

static HANDLE WINAPI fo_FindFirstFileA(LPCSTR n, LPWIN32_FIND_DATAA d)
{ fo_note("FindFirstFileA", n); return g_fo_ffa(n, d); }

static HFILE WINAPI fo_OpenFile(LPCSTR n, LPOFSTRUCT o, UINT s)
{ fo_note("OpenFile", n); return g_fo_of(n, o, s); }

static HFILE WINAPI fo_lopen(LPCSTR n, int m)
{ fo_note("_lopen", n); return g_fo_lo(n, m); }

static void *__cdecl fo_fopen(const char *n, const char *m)
{ fo_note("fopen", n); return g_fo_fo(n, m); }

/* Dump what the loader resolved, not what is on disk. On the Steam edition these
 * two are not the same thing: the on-disk .idata decodes to garbage, so this list
 * is the only way to know what is hookable. */
static void fo_dump_imports(void)
{
    BYTE *base = (BYTE *)GetModuleHandleA(NULL);
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    int lines = 0;
    if (!rva) { logf_("[x] [fileorder] the exe has no import directory -- nothing to hook"); return; }
    logf_("[*] [fileorder] import table as the loader resolved it:");
    for (IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(base + rva); imp->Name; imp++) {
        const char *dll = (const char *)(base + imp->Name);
        IMAGE_THUNK_DATA *oft, *ft;
        int n = 0;
        logf_("  [fileorder] --- %s", dll);
        if (!imp->OriginalFirstThunk) { logf_("  [fileorder]     (bound, no name thunks)"); continue; }
        oft = (IMAGE_THUNK_DATA *)(base + imp->OriginalFirstThunk);
        ft  = (IMAGE_THUNK_DATA *)(base + imp->FirstThunk);
        for (; oft->u1.AddressOfData; oft++, ft++, n++) {
            IMAGE_IMPORT_BY_NAME *ibn;
            if (lines++ > 1200) { logf_("  [fileorder]     ... truncated"); return; }
            if (oft->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                logf_("  [fileorder]     #%lu", (unsigned long)(oft->u1.Ordinal & 0xffff));
                continue;
            }
            ibn = (IMAGE_IMPORT_BY_NAME *)(base + oft->u1.AddressOfData);
            logf_("  [fileorder]     %s", (const char *)ibn->Name);
        }
    }
}

/* The CRT's name varies by build (MSVCRT.dll, MSVCR70.dll, ...), so match on the
 * prefix rather than guess a spelling and quietly hook nothing. */
static int fo_crt_name(char *out, size_t cap)
{
    BYTE *base = (BYTE *)GetModuleHandleA(NULL);
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!rva) return 0;
    for (IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(base + rva); imp->Name; imp++) {
        const char *dll = (const char *)(base + imp->Name);
        if (!_strnicmp(dll, "msvc", 4)) { snprintf(out, cap, "%s", dll); return 1; }
    }
    return 0;
}

static void maybe_start_fileorder(void)
{
    char path[MAX_PATH], crt[64];
    void *real;
    int got = 0;

    snprintf(path, sizeof path, "%s\\tropico-fix.ini", g_dir);
    if (!GetPrivateProfileIntA("FileOrder", "Enable", 0, path)) return;
    g_fo_on = 1;
    logf_("[*] [fileorder] probe armed -- logging only, every hook tail-calls the real"
          " function and nothing else changes");

    fo_dump_imports();

    if (hook_import("KERNEL32.dll", "CreateFileA", (void *)fo_CreateFileA, &real))
        { g_fo_cfa = (CreateFileA_t)real; got++; logf_("  [fileorder] hooked CreateFileA"); }
    if (hook_import("KERNEL32.dll", "CreateFileW", (void *)fo_CreateFileW, &real))
        { g_fo_cfw = (CreateFileW_t)real; got++; logf_("  [fileorder] hooked CreateFileW"); }
    if (hook_import("KERNEL32.dll", "FindFirstFileA", (void *)fo_FindFirstFileA, &real))
        { g_fo_ffa = (FindFirstFileA_t)real; got++; logf_("  [fileorder] hooked FindFirstFileA"); }
    if (hook_import("KERNEL32.dll", "OpenFile", (void *)fo_OpenFile, &real))
        { g_fo_of = (OpenFile_t)real; got++; logf_("  [fileorder] hooked OpenFile"); }
    if (hook_import("KERNEL32.dll", "_lopen", (void *)fo_lopen, &real))
        { g_fo_lo = (lopen_t)real; got++; logf_("  [fileorder] hooked _lopen"); }
    if (fo_crt_name(crt, sizeof crt)) {
        logf_("  [fileorder] CRT is %s", crt);
        if (hook_import(crt, "fopen", (void *)fo_fopen, &real))
            { g_fo_fo = (fopen_t)real; got++; logf_("  [fileorder] hooked %s!fopen", crt); }
    } else {
        logf_("  [fileorder] no msvc* import -- the CRT is static, so fopen is not hookable"
              " by IAT and any file work it does will show up as CreateFileA or not at all");
    }

    /* A probe that silently hooks nothing would read as "the game opens no files",
     * which is the opposite of the truth and the answer we would act on. */
    if (!got)
        logf_("[x] [fileorder] NOTHING was hooked. Read the import dump above before"
              " concluding anything from the (empty) call list.");
    else
        logf_("[*] [fileorder] %d entry point(s) hooked; opens are numbered from here", got);
}

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
    log_begin();
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

    /* s99: before anything else patches or defers, and before the exe's entry
     * point runs, so the numbering starts at the game's genuinely first open. */
    maybe_start_fileorder();

    /* s114: for the same reason, and one of its own -- the game resolves
     * DirectDraw at 0x514e55, which is early. Off unless [DDProbe] Enable=1. */
    maybe_install_ddprobe();

    /* ART BEFORE THE GAME'S ENTRY POINT, WHICH IS THE ONLY MOMENT EARLY ENOUGH.
     *
     * The Steam edition indexes data\ before the proxy's patch pass can run --
     * SteamStub keeps .text encrypted, so patching defers to the first
     * GetDeviceCaps, and art generated there arrives after the index. The symptom
     * was a menu dying on "Error opening pack file item 'setuplb.i16'" for a file
     * that was present, valid and byte-identical to GOG's (FINDINGS 98).
     *
     * Generating here fixes that and is measured to work: 267 assets in 1333 ms,
     * from DllMain, with no index error afterwards.
     *
     * WHICH MODE, AND WHY THE ANSWER IS NOT ALWAYS THE LAUNCH MONITOR'S (s113).
     *
     * With a primary switch still pending, the launch monitor's own mode is the
     * only answer that does not depend on what the display currently measures --
     * the ini and the picker both validate against SM_CXSCREEN, and that reading
     * is stale here by construction. So that case generates for the launch mode
     * alone and leaves the rest to the patch pass, exactly as before.
     *
     * WITH NOTHING PENDING, THE WHOLE DECISION IS ALREADY ANSWERABLE, and until
     * s113 it was not being asked. `launch_override()` needs g_launch_w, which is
     * set only by choose_monitor()'s host-side monitor read -- and that read is
     * structurally unavailable on native Windows (game_unix_dir refuses anything
     * not on Z:) and skipped on a single-monitor Linux desktop. So this block did
     * nothing at all on Windows: on GOG that is invisible, because the unwrapped
     * build patches from inside DllMain anyway and generates on the way through,
     * but on Steam the patch pass defers to GetDeviceCaps and the art then lands
     * AFTER the game has indexed data\ -- which is FINDINGS 98, reproduced on the
     * first native-Windows install as
     *
     *     Error opening pack file item 'setuplb.i16'
     *
     * on the first launch and gone on the second. The fix for 98 was real; it was
     * reachable only through a Linux-only code path.
     *
     * decide_mode() caches, so the patch pass reuses this answer rather than
     * computing a second one that merely agrees. */
    {
        mode_t am;
        char ip[MAX_PATH];
        vd_detect();
        choose_monitor();
        snprintf(ip, sizeof ip, "%s\\tropico-fix.ini", g_dir);
        g_artgen_enabled = GetPrivateProfileIntA("Art", "Generate", 1, ip);
        if (g_mon_pending) {
            if (launch_override(&am)) ensure_art_for_mode(am.w, am.h);
        } else {
            ini_fit_check();
            if (decide_mode(&am)) ensure_art_for_mode(am.w, am.h);
            else logf_("  [artgen] no mode satisfied the constraints yet -- slot 4 stays"
                       " stock, so the art the game ships is the art it wants");
        }
    }

    /* TROPICO_FIX_DEFER=1 forces the deferred path on an unwrapped build. This
     * exists to test the hook-and-patch mechanism itself without needing the
     * Steam DRM to cooperate -- it isolates "does deferral work" from "does
     * SteamStub decrypt in time", which are separate claims. */
    char defer[8] = {0};
    GetEnvironmentVariableA("TROPICO_FIX_DEFER", defer, sizeof defer);
    int force_defer = (defer[0] == '1');
    if (force_defer) logf_("[*] TROPICO_FIX_DEFER=1 -- forcing the deferred path");

    /* A PENDING DISPLAY CHANGE FORCES THE DEFERRED PATH -- even on an unwrapped
     * build whose .text could be patched this instant.
     *
     * The unwrapped GOG build patches from here, inside DllMain, which is fine
     * until something has to change the display: apply_monitor() cannot work
     * there (FINDINGS 99), and neither can the mode validation that follows it,
     * because it would be measuring the monitor we are about to stop using.
     *
     * Started through tools/tropico this never arises -- the launcher chose the
     * monitor and made it primary before the process existed, so nothing is ever
     * pending and this branch is unreachable. It exists for the launches that
     * bypass the launcher: Lutris, Heroic, a bare `wine Tropico.EXE`. Those took
     * the broken path until now.
     *
     * The cost is that this path starts depending on the GetDeviceCaps hook
     * firing, which is measured on Steam but not on GOG. It only applies where
     * the alternative is a black screen, so it is the better of the two. */
    if (g_mon_pending)
        logf_("[*] a primary-monitor change is pending -- deferring the patch pass so it"
              " runs outside DllMain, where the display can actually change (FINDINGS 99)");

    if (!force_defer && !g_mon_pending && locate_sections()
        && find_unique(CHAIN_SIG, sizeof CHAIN_SIG, g_text, g_textlen, "chain-probe")) {
        logf_("[*] .text is readable at load time (unwrapped build) -- patching now");
        apply_patches();
    } else {
        /* Say which reason, because they are different faults. On the GOG build
         * .text is perfectly readable and the defer is ours, by choice. */
        if (g_mon_pending)
            logf_("[*] deferring to GetDeviceCaps because of the pending monitor change"
                  " above -- .text readability is not the reason here");
        else
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

/* ==================================================== s67 Bink instrumentation
 *
 * WHY. The startup movie does not play. The proxy replaces binkw32.dll, so the
 * proxy was the first suspect -- and it was EXONERATED by a control run with the
 * stock DLL, which behaves identically. That leaves two possibilities that look
 * the same from the outside:
 *
 *   (a) the game never asks for the movie -- a config, a table flag, or a branch
 *   (b) the game asks and Bink refuses -- most likely audio: the game opens Bink
 *       sound through BinkOpenMiles (Mss32.dll), and Bink will fail BinkOpen
 *       outright when its sound system did not initialise
 *
 * Those need opposite fixes, so guessing between them is worthless. We own the
 * DLL the game calls, which makes this a two-line measurement: stop forwarding the
 * handful of entry points that matter and log what actually crosses the boundary,
 * then tail-call the real Bink so behaviour is unchanged.
 *
 * Only these four are real functions; the other 77 exports stay pure forwarders. */

static HMODULE g_bink;
static int g_bink_logged;

static HMODULE bink_orig(void)
{
    if (!g_bink) {
        /* The forwarders will already have pulled it in; only fall back to an
         * explicit load if we somehow got here first. Load by FULL PATH -- a bare
         * name would search the DLL path and could find something else entirely. */
        g_bink = GetModuleHandleA("binkw32_orig.dll");
        if (!g_bink) {
            char p[MAX_PATH];
            snprintf(p, sizeof p, "%s\\binkw32_orig.dll", g_dir);
            g_bink = LoadLibraryA(p);
        }
        if (!g_bink) logf_("  [bink] cannot reach binkw32_orig.dll -- calls will fail");
    }
    return g_bink;
}

typedef void * (__stdcall *BinkOpen_t)(const char *, DWORD);
typedef char * (__stdcall *BinkGetError_t)(void);
typedef int    (__stdcall *BinkOpenMiles_t)(void *);
typedef int    (__stdcall *BinkSetSoundSystem_t)(void *, DWORD);

static const char *bink_err(void)
{
    HMODULE m = bink_orig();
    if (!m) return "(no binkw32_orig)";
    BinkGetError_t f = (BinkGetError_t)(void *)GetProcAddress(m, "_BinkGetError@0");
    if (!f) return "(no BinkGetError)";
    const char *e = f();
    return e ? e : "(none)";
}

void * __stdcall my_BinkOpen(const char *name, DWORD flags);
void * __stdcall my_BinkOpen(const char *name, DWORD flags)
{
    HMODULE m = bink_orig();
    BinkOpen_t f = m ? (BinkOpen_t)(void *)GetProcAddress(m, "_BinkOpen@8") : NULL;
    void *r = f ? f(name, flags) : NULL;
    if (g_bink_logged < 64) {
        g_bink_logged++;
        /* Log the RESULT, not just the attempt. "asked and failed" and "asked and
         * succeeded but was never drawn" are different bugs with different fixes. */
        /* The CALLER is the point of this log now that Bink is exonerated. The
         * movies that do play name the player function, and from there the intro's
         * missing call site is a short walk up the call graph -- much shorter than
         * chasing an indirect string table through the disassembly. */
        logf_("  [bink] BinkOpen(\"%s\", 0x%08lx) -> %p   caller=%p%s%s",
              name ? name : "(null)", flags, r, __builtin_return_address(0),
              r ? "" : "   FAILED: ", r ? "" : bink_err());
    }
    return r;
}

int __stdcall my_BinkOpenMiles(void *p);
int __stdcall my_BinkOpenMiles(void *p)
{
    HMODULE m = bink_orig();
    BinkOpenMiles_t f = m ? (BinkOpenMiles_t)(void *)GetProcAddress(m, "_BinkOpenMiles@4") : NULL;
    int r = f ? f(p) : 0;
    logf_("  [bink] BinkOpenMiles(%p) -> %d%s%s", p, r,
          r ? "" : "   FAILED: ", r ? "" : bink_err());
    return r;
}

int __stdcall my_BinkSetSoundSystem(void *open, DWORD param);
int __stdcall my_BinkSetSoundSystem(void *open, DWORD param)
{
    HMODULE m = bink_orig();
    BinkSetSoundSystem_t f = m ? (BinkSetSoundSystem_t)(void *)GetProcAddress(m, "_BinkSetSoundSystem@8") : NULL;
    int r = f ? f(open, param) : 0;
    logf_("  [bink] BinkSetSoundSystem(%p, 0x%08lx) -> %d", open, param, r);
    return r;
}

/* BinkCopyToBuffer(bink, dest, destpitch, destheight, destx, desty, flags).
 *
 * Forcing the menu into 1920x1080 made the intro render as a 640-wide image tiled
 * across the top third -- the signature of rows being written with a pitch of 640
 * pixels into a 1920-wide surface. This logs what the game actually passes so the
 * stale value can be identified rather than guessed at. */
typedef int (__stdcall *BinkCopyToBuffer_t)(void *, void *, int, unsigned, unsigned, unsigned, unsigned);

int __stdcall my_BinkCopyToBuffer(void *b, void *dest, int pitch, unsigned h,
                                  unsigned x, unsigned y, unsigned flags);
int __stdcall my_BinkCopyToBuffer(void *b, void *dest, int pitch, unsigned h,
                                  unsigned x, unsigned y, unsigned flags)
{
    /* MEASURED: the game passes pitch = movie_width * 2 (1280 for a 640-wide movie at
     * 16bpp). The destination surface's real pitch follows the MODE, not the movie --
     * 3840 at 1920x1080 -- so every source row advances only a third of a destination
     * row: three copies across and a third of the height used. That is exactly the
     * tiling seen once the menu was forced out of 640x480, and it is invisible at
     * 640x480 because there the two happen to be equal.
     *
     * Correct it to mode_width * 2. Gated on the ini because it rests on the surface
     * pitch tracking the mode width, which is true for a DirectDraw primary/back
     * buffer but is an inference, not something we can query through this interface. */
    int orig = pitch;
    if (g_bink_pitch && g_vt_xs_va) {
        int mw = (int)(*(float *)(SIZE_T)g_vt_xs_va * 3200.0f + 0.5f);
        if (mw > 0 && pitch < mw * 2) pitch = mw * 2;
    }
    static int n;
    if (n < 12) {
        n++;
        logf_("  [bink] CopyToBuffer dest=%p pitch=%d%s destheight=%u at (%u,%u)"
              " flags=0x%08x caller=%p",
              dest, pitch, (pitch != orig) ? " (was tiling; corrected)" : "", h, x, y,
              flags, __builtin_return_address(0));
    }
    HMODULE m = bink_orig();
    BinkCopyToBuffer_t f = m ? (BinkCopyToBuffer_t)(void *)GetProcAddress(m, "_BinkCopyToBuffer@28") : NULL;
    return f ? f(b, dest, pitch, h, x, y, flags) : 0;
}

char * __stdcall my_BinkGetError(void);
char * __stdcall my_BinkGetError(void)
{
    HMODULE m = bink_orig();
    BinkGetError_t f = m ? (BinkGetError_t)(void *)GetProcAddress(m, "_BinkGetError@0") : NULL;
    return f ? f() : NULL;
}

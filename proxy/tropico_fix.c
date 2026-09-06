/*
 * tropico_fix -- runtime patcher for PopTop Tropico (2001), shipped as a
 * binkw32.dll proxy.  See ../dev/FINDINGS.md for how every address here was derived.
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

/* APPEND, NEVER TRUNCATE -- the same fix the launcher's own log already needed.
 *
 * DllMain used to DeleteFileA() this log on every run. That is exactly the defect
 * already fixed in the launcher, left standing in the other
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
static int patch_vtext(int dy, int dx, int cliph, int have_dy, int have_dx, int have_cliph);
static int patch_vtext_sites(void);
static int patch_vtext_wrapper(void);
static int patch_readout_colour(int want);
static int patch_intro(void);
static int g_menu_slot = -1;
static int g_bink_pitch;
static int patch_blit_scale(void);
static int patch_hud_movie(void);
static int patch_preview_fix(int mode);
static int patch_menu_slot(void);
static int patch_menu_apply(void);
static void find_applyvideo(void);
static DWORD WINAPI pin_thread(LPVOID);
static DWORD g_preset_ret;   /* return address of the preset-apply call site */
static int patch_force_fullscreen(void);
/* maybe_install_dispsel() asks this, and it sits far below. */
static int running_under_wine(void);
static int install_cursor_fix(void);   /* defined with the pointer filter below */

/* The stray-corner pointer filter; the section below explains it. */
typedef BOOL  (WINAPI *GetCursorPos_t)(LPPOINT);
typedef BOOL  (WINAPI *PeekMessageA_t)(LPMSG, HWND, UINT, UINT, UINT);
typedef BOOL  (WINAPI *GetMessageA_t)(LPMSG, HWND, UINT, UINT);
typedef DWORD (WINAPI *GetMessagePos_t)(void);
static GetCursorPos_t   g_real_gcp;
static PeekMessageA_t   g_real_peek;
static GetMessageA_t    g_real_getmsg;
static GetMessagePos_t  g_real_msgpos;
static int   g_cur_fix;
static POINT g_cur_screen, g_cur_client;   /* last believed, per coordinate space */
static int   g_cur_have_screen, g_cur_have_client;
static volatile LONG g_cur_fixed;
static int g_force_fs = 1;   /* never let the engine enter windowed mode */
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

/* -------------------------------------------- choose the DEVICE, not the primary
 *
 * MEASURED ON WINDOWS 11, and it is the result the whole primary-switching apparatus
 * below was waiting for. DirectDrawEnumerateExA(DDENUM_ATTACHEDSECONDARYDEVICES) hands back
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
 * WHAT THIS REPLACES. The primary-switching apparatus exists to make the player's chosen
 * monitor primary for the length of the game and give it back afterwards: the
 * state file, the ExitProcess hook, the window watcher, the 5 s deadline. None of
 * it is needed if the game simply renders on the right device. That is a change
 * to the GAME rather than to the PLAYER'S COMPUTER, which is what the DirectDraw
 * probe set out to find, and what the primary-switching approach settled for before
 * that answer existed.
 *
 * WINDOWS ONLY, and not by policy. Wine hands back ONE adapter GUID for both
 * heads -- it names the adapter, not the head -- so there is nothing to
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
/* The target monitor's origin in VIRTUAL-SCREEN space, and the reason the
 * first in-game run of this feature failed with #150 on every frame.
 *
 * Measured: this engine presents via Blt(primary <- offscreen), with the
 * destination rect being the game's window rect IN SCREEN COORDINATES. That is
 * fine on the primary, where the monitor origin IS (0,0) -- and it is wrong
 * everywhere else. Point the game at \\.\DISPLAY2 sitting at (-1920,357) and its
 * destination rect is (-1920,357)-(0,1437) inside a surface that spans
 * (0,0)-(1920,1080). Entirely out of bounds, every frame, which is #150.
 *
 * The sign is not the point: a monitor at +2560 fails identically. THE GAME
 * ASSUMES THE MONITOR ORIGIN IS (0,0), WHICH IS ONLY EVER TRUE FOR THE PRIMARY.
 *
 * The DirectDraw probe could not have caught this. Its blits used explicit
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
static int g_vt_entry, g_vt_bdh, g_vt_bdy, g_vt_boxdx;
static DWORD g_vte_entry_va;
/* vtext hook state -- declared here because apply_patches() sets it from the
 * ini long before the hook that reads it is defined. */
static int g_vt_fix, g_vt_fw, g_vt_fh, g_vt_boxh, g_vt_boxdy;
static DWORD g_hud_table_va;
static int patch_world_draw(UINT match_w, UINT new_w, UINT match_h, UINT new_h,
                            UINT objm, UINT objw, UINT objhm, UINT objh, int force, UINT guard);
/* The split between choose_monitor() and apply_monitor() is the whole point: choose_monitor() only
 * READS the display, which is safe from DllMain; apply_monitor() CHANGES it and
 * waits for Wine to agree, which is not. See apply_monitor() for the measurement. */
/* What choose_monitor() decided, kept because apply_monitor() runs much later and
 * the xrandr output list it was read from is long out of scope by then. */
static char  g_mon_to[64], g_mon_from[64];
static DWORD g_mon_to_w, g_mon_to_h;
static int   g_mon_pending;
/* Which display source answered, because the two need different verbs to
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

/* The desktop-width gate.
 *   cmp eax,<resolution table VA> / je +8 / cmp [eax],ebx / jge <end of loop>
 * The table VA is discovered first, from the data table itself, then spliced in --
 * which also proves the two finds agree about the same build. */
static BYTE GATE_SIG[]        = {0x3d,0,0,0,0, 0x74,0x08, 0x39,0x18, 0x0f,0x8d,0,0,0,0};
static const BYTE GATE_MASK[] = {   1,1,1,1,1,    1,   1,    1,   1,    1,   1,0,0,0,0};
#define GATE_PATCH_OFF 10
#define GATE_PATCH_LEN 1
#define GATE_PATCH_BYTE 0x8f

/* The Hardware 3D gate, an x87 SIGNED compare.
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

/* The second signed test, a texture budget. jge -> jae.
 *   cmp dword [vidmem],0xd00000 / jge
 * Its operand must be the SAME global the fild used -- a free cross-check. */
static const BYTE BUDGET_SIG[]  = {0x81,0x3d,0,0,0,0, 0x00,0x00,0xd0,0x00, 0x7d};
static const BYTE BUDGET_MASK[] = {   1,   1,0,0,0,0,    1,   1,   1,   1,    1};
#define BUDGET_PATCH_OFF 10

/* The renderer branch on the mode-set path.
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

/* The code compare-chain, slot 4's arm. No absolute operands. */
static const BYTE CHAIN_SIG[] = {0x81,0xf9,0x40,0x06,0x00,0x00, 0x75,0x16,
                                 0x81,0xfa,0xb0,0x04,0x00,0x00};
#define CHAIN_W_OFF 2
#define CHAIN_H_OFF 10

/* The resolution table, 5 x {DWORD w; DWORD h}, in .data. */
static const DWORD TABLE_SIG[10] = {640,480, 800,600, 1024,768, 1280,1024, 1600,1200};
#define SLOT4_OFF 32

/* ------------------------------------------------------- resolution selection
 *
 * Policy (owner's decision, 2026-08-19): leave slots 0-3 stock and choose only
 * slot 4 at runtime.  Constraints:
 *   the HUD/background art is drawn at the slot's STOCK width, so the target
 *        width must not exceed it -- 1600 for slot 4.  This is the hard ceiling
 *        on widescreen and the reason slot 4 is the only usable home.
 *   width % 4 == 0, else the row pitch is padded and the image shears.
 *   the compare-chain dispatches on width and rejects on a height mismatch
 *        rather than falling through, so widths must be unique across slots.
 *   the mode must actually exist, or the game cannot set it.
 */
#define ART_WIDTH_CAP 1600
/* The world image's stock pixel width. The size gate compares against this
 * value, so the gate's threshold must never exceed it. */
#define WORLD_STOCK_W 1600

typedef struct { DWORD w, h; } mode_t;
static DWORD g_launch_w, g_launch_h;   /* mode adopted from the launch monitor */
static char  g_launch_name[64];        /* that monitor's name, for the log     */
static int launch_override(mode_t *m);   /* defined with the monitor code */
static int running_under_wine(void);    /* ditto */
static void launch_mode_check(int dw, int dh); /* ditto */

/* ------------------------------------------------------- display scaling (DPI)
 *
 * THE PATCH IS DPI-UNAWARE BY DEFAULT. The awareness call below runs only when
 * `[Display] IgnoreScaling=1` asks for it; with the key absent there is no call at
 * all, and this comment exists so that absence reads as a decision rather than an
 * oversight, because it looks exactly like the omission it used to be.
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
 * too, so both ends agree.
 *
 * DirectDraw mode setting is not DPI-virtualized, so asking for 1920x1080 on a 4K
 * panel yields a genuine 1080p signal the display upscales at an exact 2x, rather
 * than a composited stretch.
 *
 * SUPERSEDED IN PRACTICE (2026-09-05, FINDINGS 122). The rule above was only ever
 * enforced by the picker, and the picker runs only when no monitor is adopted. The
 * launch-monitor path reads EnumDisplaySettings, which scaling does not touch, and
 * one monitor now takes that path too. So the mode is the panel's own by default on
 * every path; the logical desktop still gates an explicit [Resolution] in
 * ini_fit_check(), and that is what the key below lifts.
 *
 * KNOWN GAP: a mixed-DPI multi-monitor Windows setup (4K laptop at 200% beside a
 * 1080p external at 100%) applies the SYSTEM dpi uniformly, so the numbers for the
 * monitor that is not at system DPI are neither physical nor that monitor's own
 * logical size. Per-monitor awareness is the only thing that gets that case right,
 * and it is incompatible with the rule above. Recorded, not solved by default;
 * `IgnoreScaling=1` is the way out of it.
 *
 * THE OPT-OUT (2026-09-05, from user feedback). A 4K panel at 200% is, under the
 * rule above, a request for 1920x1080 -- and a player who wants the game at the
 * panel's own 3840x2160 anyway has no way to say so: writing it into [Resolution]
 * is refused by ini_fit_check() against the logical SM_CXSCREEN, and the exe's own
 * gate at 0x514d9d would skip slot 4 against the logical GetDeviceCaps even if we
 * let it through. Two checks, one wrong number, and only one of them is ours. So
 * relaxing our check is not a fix; the mechanism that fits is to make the whole
 * process see physical pixels, which is the reverted 2b0248f under a key: one call
 * from DllMain, before anything measures anything, and every site in the chain --
 * ours, the exe's, the art generator's -- agrees without any other code changing.
 *
 * Windows only, deliberately. Linux already plays at the panel's real mode
 * (tools/tropico measures with xrandr after the primary switch, and Wine
 * virtualizes nothing -- FINDINGS 92), so there the key has nothing to do. It is
 * skipped under Wine rather than allowed to run, because the modern call fails
 * with 87 on system wine 9.0 and succeeds under Proton, and two Linux runtimes
 * taking different paths through a no-op is how unreproducible reports get made.
 */
static void apply_ignore_scaling(void)
{
    char ip[MAX_PATH];
    snprintf(ip, sizeof ip, "%s\\tropico-fix.ini", g_dir);
    if (!GetPrivateProfileIntA("Display", "IgnoreScaling", 0, ip)) return;

    if (running_under_wine()) {
        logf_("[*] [dpi] IgnoreScaling=1 does nothing under Wine or Proton -- Linux"
              " already plays at the panel's real mode");
        return;
    }

    HMODULE u32 = GetModuleHandleA("user32.dll");
    typedef BOOL (WINAPI *SPDAC_t)(HANDLE);
    SPDAC_t spdac = u32 ? (SPDAC_t)(void *)GetProcAddress(u32, "SetProcessDpiAwarenessContext") : NULL;

    /* DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 == (HANDLE)-4. Per-monitor rather
     * than system-aware because the game can be started on one monitor and opened on
     * another, and the real numbers are wanted for whichever it lands on. */
    if (spdac && spdac((HANDLE)-4)) {
        logf_("[+] [dpi] IgnoreScaling=1: SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2)"
              " -- the game is measured in the panel's own pixels, not the scaled desktop");
        return;
    }
    if (spdac)
        logf_("[*] [dpi] SetProcessDpiAwarenessContext failed (%lu); falling back", GetLastError());
    else
        logf_("[*] [dpi] SetProcessDpiAwarenessContext not exported (pre-1703 Windows); falling back");
    if (SetProcessDPIAware())
        logf_("[+] [dpi] IgnoreScaling=1: SetProcessDPIAware -- the game is measured in the"
              " panel's own pixels, not the scaled desktop");
    else
        logf_("[x] [dpi] IgnoreScaling=1 but no awareness call succeeded -- the scaled"
              " desktop size is what the game will be given");
}

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
    /* ONCE, AND UNCONDITIONALLY. This used to be reached only through
     * pick_mode_pass(), so a run that took the launch-monitor path -- the common
     * one on Steam -- recorded nothing about the display layout it ran under.
     *
     * That is the wrong way round for the one open bug that is layout-driven and
     * intermittent: the Proton cursor drift appears with monitors that are not
     * top-aligned, and four sessions showed it while four later ones could not
     * reproduce it. Correlating those needs every run to say which layout it had,
     * whether or not anything went wrong that time. It costs a handful of
     * GetSystemMetrics calls at startup. */
    static LONG once;
    if (InterlockedExchange(&once, 1)) return;
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
                logf_("  display scaling is about %d%%; the mode still comes from the"
                      " monitor's own settings, which scaling does not change. Only a"
                      " [Resolution] wider than the scaled desktop is refused by it"
                      " ([Display] IgnoreScaling=1 in tropico-fix.ini lifts that)",
                      (int)((real.dmPelsWidth * 100 + mw / 2) / mw));
        }
    }
    logf_("  virtual screen    = %d x %d at (%d,%d)",
          GetSystemMetrics(SM_CXVIRTUALSCREEN), GetSystemMetrics(SM_CYVIRTUALSCREEN),
          GetSystemMetrics(SM_XVIRTUALSCREEN), GetSystemMetrics(SM_YVIRTUALSCREEN));

    /* This is the exact pair the desktop-width gate reads at 0x515160 and stores
     * in [0x60c118]. If it disagrees with the monitor the
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
 * An earlier version of this logic used to live here: the installer staged one set per connected monitor into
 * artsets\<WxH>\ and the proxy copied one into data\ when the mode it picked did
 * not match what the launcher had staged. All of it -- staged_dir, mode_is_staged,
 * active_artset_is, activate_artset and the two-pass picker they fed -- is deleted.
 *
 * It existed to answer one question: DOES ART EXIST AT THIS SIZE? The answer used to
 * depend on what an installer had guessed, ahead of time, about a display it could not
 * see. Now the proxy generates the set itself, from the user's archives, once the mode
 * is known -- about a second -- so the answer is unconditionally yes and
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
        if (w % 4) continue;                       /* pitch shear              */
        /* Two passes. The stock-art caps below are a ROUGH PROXY for "does art
         * exist at this size" -- they were written before art was generated per mode,
         * and they now reject 2560x1440 outright (h > 1200) even when its art set is
         * staged and ready. A staged set answers that question exactly, so when one
         * exists the caps are not consulted; when none does, they are, and the old
         * behaviour is preserved verbatim for an install with no artsets\ at all. */
        if (capped) {
            if (w > ART_WIDTH_CAP) continue;       /* art width ceiling        */
            if (h > 1200) continue;                /* stock slot-4 art height  */
        }
        if (w > deskw || h > deskh) continue;      /* must fit the desktop     */
        /* Slot 4 is the LARGEST slot. If we cannot beat slot 3's stock 1280, we have
         * nothing to offer and should leave slot 4 alone rather than shrink it. */
        if (w <= 1280) continue;
        if (collides_with_stock(w)) continue;      /* unique widths            */

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
/* ------------------------------------------------ runtime art generation
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
 * The cache key is the MODE ALONE. font_scale is derived from it as H/1080,
 * so two runs at one resolution cannot disagree about the art.
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

/* What [Resolution] names, unjudged. Zero when it names nothing. */
static int ini_named(UINT *w, UINT *h)
{
    char path[MAX_PATH];
    snprintf(path, sizeof path, "%s\\tropico-fix.ini", g_dir);
    *w = GetPrivateProfileIntA("Resolution", "Width",  0, path);
    *h = GetPrivateProfileIntA("Resolution", "Height", 0, path);
    return *w && *h;
}

/* The player's own mode. Every refusal below, and the fit refusal in
 * ini_fit_check(), is logged where it happens; decide_mode() only has to say what
 * ran instead. */
static int ini_override(mode_t *m)
{
    UINT w, h;
    if (!ini_named(&w, &h)) return 0;
    if (g_ini_mode_unusable) return 0;   /* does not fit this screen -- see above */
    if (w % 4) { logf_("  ini: width %u is not a multiple of 4 -- ignoring (would shear)", w); return 0; }
    if (collides_with_stock(w)) { logf_("  ini: width %u collides with a stock slot -- ignoring (would be unreachable)", w); return 0; }
    /* The stock art cap describes STOCK art, and the generator replaces stock art at
     * whatever size we are about to use -- so past the cap is only a problem when
     * generation is switched off. */
    if (w > ART_WIDTH_CAP && !g_artgen_enabled)
        logf_("  ini: WARNING width %u exceeds the %d stock art cap and [Art] Generate=0,"
              " so nothing will build art for %ux%u -- expect an unpainted strip."
              " Remove Generate=0 to have it generated at launch.",
              w, ART_WIDTH_CAP, w, h);
    m->w = w; m->h = h;
    logf_("  ini override: %ux%u", w, h);
    return 1;
}

/* ------------------------------------------ the ini's mode against the screen
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
    /* TWO CAUSES, TOLD APART BY THE ADAPTER. EnumDisplaySettings is not
     * DPI-virtualized, so when the monitor's own mode would hold the configured one
     * and differs from the desktop the game is measured in, the desktop is scaled,
     * and the advice "launch from the other monitor" is wrong: there is no other
     * monitor, and the key that fixes it is IgnoreScaling. */
    {
        DEVMODEA real; memset(&real, 0, sizeof real); real.dmSize = sizeof real;
        int scaled = EnumDisplaySettingsA(NULL, ENUM_CURRENT_SETTINGS, &real)
                  && (int)real.dmPelsWidth >= iw && (int)real.dmPelsHeight >= ih
                  && ((int)real.dmPelsWidth != dw || (int)real.dmPelsHeight != dh);
        if (scaled)
            logf_("    Cause: display scaling. The monitor's own mode is %lux%lu, which"
                  " would hold %dx%d, but scaling makes the desktop %dx%d and the game is"
                  " measured in that. Set [Display] IgnoreScaling=1 in tropico-fix.ini"
                  " to play at the monitor's own size.",
                  real.dmPelsWidth, real.dmPelsHeight, iw, ih, dw, dh);
        else
            logf_("    Cause: the game was started for one monitor and opened on another."
                  " Launch it from the monitor you want to play on.");
    }
    logf_("    Ignoring the configured mode and picking one that fits.");
    g_ini_mode_unusable = 1;
}

/* ------------------------------------------------------- decide_mode
 *
 * ONE ANSWER, COMPUTED ONCE, AND THE REASON IT HAS TO BE CACHED:
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

/* AN EXPLICIT SETTING BEATS AN AUTOMATIC ONE (2026-09-05). The launch monitor's
 * mode used to be taken first, so on any Windows desktop with two monitors --
 * DeviceSelect and FollowLaunchMonitor are both on by default -- a [Resolution] the
 * player had typed was never read, and the log said "running at DISPLAY2's own mode"
 * as if nothing had been asked. On one monitor the same ini worked, because the
 * monitor step exits early there; the setting stopped working the day a second
 * monitor was plugged in, with nothing to say so.
 *
 * Order now: the ini, then the launch monitor, then the picker -- and whichever
 * automatic answer loses to the ini, or stands in for a refused one, is named. */
static int decide_mode(mode_t *out)
{
    mode_t lm;
    UINT iw, ih;
    int have_launch, ini_set;
    if (g_mode_decided) { *out = g_decided; return 1; }
    have_launch = launch_override(&lm);
    ini_set = ini_named(&iw, &ih);
    if (ini_override(&g_decided)) {
        if (have_launch && (lm.w != g_decided.w || lm.h != g_decided.h))
            logf_("[+] [Resolution] %lux%lu from tropico-fix.ini wins over %s's own mode"
                  " %lux%lu -- an explicit setting beats an automatic one",
                  g_decided.w, g_decided.h, g_launch_name, lm.w, lm.h);
    } else if (have_launch) {
        if (ini_set)
            logf_("[!] [Resolution] %ux%u was refused (the reason is above); running at"
                  " %s's own mode %lux%lu instead", iw, ih, g_launch_name, lm.w, lm.h);
        g_decided = lm;
    } else {
        if (!pick_mode(&g_decided)) return 0;
        if (ini_set)
            logf_("[!] [Resolution] %ux%u was refused (the reason is above); the picker"
                  " chose %lux%lu instead", iw, ih, g_decided.w, g_decided.h);
    }
    g_mode_decided = 1;
    *out = g_decided;
    return 1;
}

/* ------------------------------------------------- the world-extent clamp
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
 * screen: the clamp is absolute, not relative to the mode.
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

/* --------------------------------------------- refuse Hardware 3D, gracefully
 *
 * Hardware 3D renders correctly on exactly one of the three runtimes this game
 * meets: the GOG build under system wine. It smears at every resolution under
 * Proton and it crashes on map entry on native Windows -- and that
 * crash BRICKS the install, because the choice persists to TROPICO.CFG and F2 is
 * then unreachable to undo it. The owner's decision (2026-08-23) is to stop
 * offering it: the hardware path was there to spare a 2001 CPU, and a modern one
 * runs the software renderer without noticing.
 *
 * REVERTING the Hardware 3D gate fix is NOT the way to do that, and it was considered.
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
 *      replacement, so the 25-byte layout that gate fix verified is otherwise
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

    log_environment();
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

    /* --- 0.5 the monitor, BEFORE ANYTHING READS THE DISPLAY -------
     *
     * The choice itself was made in DllMain, so the art could be built against it
     * before the game indexed data\. Only the CHANGE waited for
     * here, because a display change made from DllMain is never noticed by the
     * process that made it.
     *
     * It goes at the TOP of the patch pass, not next to the mode picker where it
     * used to sit. Three things below read SM_CXSCREEN -- the "desktop as Wine
     * sees it" line, the configured-mode-fits check, and the picker -- and every
     * one of them wants the display the game will actually run on, not the one the
     * desktop was idling in. With the switch further down, the fits check could
     * reject a perfectly good 1440p mode for not fitting a 1080p primary that was
     * about to stop being the primary. */
    choose_monitor();
    apply_monitor();

    /* What Wine believes the screen is, logged UNCONDITIONALLY. Everything the
     * patch computes is relative to this, and when it is stale -- a wineserver that
     * outlived an xrandr change caches the old geometry into the prefix -- the
     * symptom is DDERR_INVALIDRECT on the next launch and nothing says why.
     * One line here turns that into an obvious diagnosis. */
    logf_("[*] desktop as Wine sees it: %dx%d", GetSystemMetrics(SM_CXSCREEN),
          GetSystemMetrics(SM_CYSCREEN));
    /* Both of these read SM_CXSCREEN, so they belong AFTER apply_monitor() and not
     * before it -- the screen they judge against has to be the one the game will run
     * on. ini_fit_check() is a no-op when DllMain already ran it, which it does on
     * every run with no pending switch; the check itself moved there so a
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
            /* One byte decides whether the compare is a compare at all. `jbe`
             * keeps the stock gate's behaviour (unsigned, hardware offered when the
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

    /* --- 3.2 heal a CFG that already selected Hardware 3D -------------
     * Only when we are refusing hardware. With Enable=1 the field must be left
     * alone, or the player's choice would be silently overridden. */
    if (!hw_enable) { if (patch_block_hardware()) ok++; else fail++; }

    /* --- 4. slot 4, in BOTH tables ----------------------------------------- *
     * Patching the data table alone is not enough. A parallel
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
        /* An earlier fallback art-switch used to sit here: on the path where the configured
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
             * stops at 1600 no matter how wide the screen is. */
            BYTE *vc = find_unique_masked(VCLAMP_SIG, VCLAMP_MASK, sizeof VCLAMP_SIG,
                                          g_text, g_textlen, "world-extent clamp");
            if (vc) {
                DWORD dw = m.w * 2, dh = m.h * 2;
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
                  " either, since a code mapping that silently drops unrecognised modes"
                  " must move together with it");
            fail++;
        }
    }

    /* The world viewport. Off by default -- it is the newest patch here and
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
             * auto was plain m.w/2, justified as "the main viewport is always
             * 2666/3200 = 83% of the mode width".  That premise is false, and it is
             * false BECAUSE OF THE BUG THIS PATCH FIXES: the value the gate compares
             * (`[ecx+0x10]`, the image pixel width) is the STOCK 1600 at gate time,
             * whatever the mode.  So the gate really asks `1600 >= m.w/2`, which
             * holds only while m.w <= 3200.  Wider than that and the gate skips its
             * own fix and the terrain stays 1600x864 -- while the install log still
             * says the patch applied, because that is logged at install time and the
             * gate rejects at draw time.
             *
             * Measured at 3840x2160: guard 1920 > 1600, world painted
             * 1600x864 of a 3840x2160 screen.  With the guard pinned to 1600 the
             * same run painted 3839x2159.  This is NOT 4K-only: every mode wider
             * than 3200 is affected, which includes 3440x1440 and 3840x1600
             * ultrawides that people actually own.
             *
             * Capping at the stock width keeps every mode <= 3200 bit-for-bit
             * identical to what was verified before, and stops the gate climbing
             * past the very value it is testing.  The zoomed detail preview this
             * gate exists to exclude is far narrower than 1600. */
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

    /* The movie/menu window. Off unless the ini asks. */
    {
        char ip[MAX_PATH];
        snprintf(ip, sizeof ip, "%s\\tropico-fix.ini", g_dir);
        /* Wine reports a stray top-left pointer position now and then, which the
         * game reads as "pan up-left". Not seen on Windows, so not armed there. */
        g_cur_fix = GetPrivateProfileIntA("Cursor", "Fix", running_under_wine() ? 1 : 0, ip);
        if (g_cur_fix) {
            int hooked = install_cursor_fix();
            if (hooked)
                logf_("[+] [cursor] stray top-left pointer reports will be corrected"
                      " (%d input path(s) watched)", hooked);
            else
                logf_("[x] [cursor] no pointer entry point could be hooked -- the map"
                      " may drift on its own. [Cursor] Fix=0 silences this.");
        }
        g_bink_pitch = GetPrivateProfileIntA("Menu", "FixMoviePitch", 0, ip);
        if (GetPrivateProfileIntA("Menu", "FixPreview", 2, ip)) {
            if (patch_preview_fix(GetPrivateProfileIntA("Menu", "FixPreview", 2, ip)))
                ok++; else fail++;
        }
        if (GetPrivateProfileIntA("Menu", "FixMovieScale", 1, ip)) {
            if (patch_blit_scale()) ok++; else fail++;
        }
        if (GetPrivateProfileIntA("Menu", "FixHudMovie", 1, ip)) {
            if (patch_hud_movie()) ok++; else fail++;
        }
        /* The menu renders at slot 4 -- but ONLY if the seven 640x480-only
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

        /* The frontend preset. Installed whenever the menu slot is redirected
         * -- without it the menu is correct at startup and drops back to 640x480 the
         * moment you return to it from a map. */
        /* Keep the window on the monitor Wine measures. On by default --
         * the failure it prevents is DDERR_INVALIDRECT, which is unreadable. */
        g_pin_primary = GetPrivateProfileIntA("Display", "PinToPrimary", 1, ip);
        if (g_pin_primary) {
            logf_("[+] [display] watching for the game window, to keep it on the monitor"
                  " Wine measures");
            CloseHandle(CreateThread(NULL, 0, pin_thread, NULL, 0, NULL));
        }
        /* Windowed mode is a documented failure path, and one
         * click of the F2 "Fullscreen" box persists it into TROPICO.CFG and bricks
         * every later launch. On by default; Display ForceFullscreen=0 restores the
         * stock behaviour, checkbox and all. */
        g_force_fs = GetPrivateProfileIntA("Display", "ForceFullscreen", 1, ip);
        if (g_force_fs) { if (patch_force_fullscreen()) ok++; else fail++; }
        if (g_menu_slot >= 0 || g_force_fs) {
            if (!g_vt_xs_va || !g_vt_ys_va) {
                static const BYTE CS[]  = {0x66,0x3d,0x80,0x02, 0x7e,0x0a,
                                           0xc7,0x44,0x24,0x10,0x80,0x02,0x00,0x00};
                static const BYTE CM[]  = {   1,   1,   1,   1,    1,   1,
                                              1,   1,   1,   1,   1,   1,   1,   1};
                BYTE *c = find_unique_masked(CS, CM, sizeof CS, g_text, g_textlen, "clamp scales");
                if (c) { g_vt_xs_va = rd32(c + 23); g_vt_ys_va = rd32(c + 69); }
            }
            find_applyvideo();
            if (patch_menu_apply()) ok++; else fail++;
        }
        if (g_menu_slot >= 0) { if (patch_menu_slot()) ok++; else fail++; }
    }

    /* Force the startup movie. Off unless the ini asks. */
    {
        char ip[MAX_PATH];
        snprintf(ip, sizeof ip, "%s\\tropico-fix.ini", g_dir);
        if (GetPrivateProfileIntA("Intro", "Force", 0, ip)) {
            if (patch_intro()) ok++; else fail++;
        }
    }

    /* Rotated tab-label placement.  Off unless the ini asks. */
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
            /* THE FIVE DIALS DEPEND ON THE ASPECT ALONE.
             *
             * An earlier attempt recorded these as un-derivable. What it actually refuted is a
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
             * A 16:10 set can likely be derived by the same reasoning above, but it has
             * not been confirmed in game -- that would be one probe run, not a dialling
             * pass. An explicit ini value always wins.
             *
             * THE ART MUST MATCH. These values assume fonts at H/1080. A set staged by
             * an older build has stock fonts and would be mis-dialled by that factor;
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
                      " -- rotated labels left STOCK and will overhang. A set for this"
                      " aspect can likely be derived the same way the 16:9 one was, but it"
                      " needs confirming in game; set VText Fix=1 with your own"
                      " BoxH/BoxDY/BoxDX/Entry once you have measured values.",
                      g_mode_w, g_mode_h, vt_ar);
            /* The hooks ARE the fix, so Fix=1 installs them regardless. */
            g_vt_bdh   = GetPrivateProfileIntA("VText", "BldgDH", vt_dialled ?  107 : 0, ip);
            g_vt_bdy   = GetPrivateProfileIntA("VText", "BldgDY", vt_dialled ? -111 : 0, ip);
            if (g_vt_fix && !(g_vt_fw && g_vt_fh)) {
                logf_("[x] [vtext] Fix=1 needs FixW/FixH -- an ungated correction breaks"
                      " every mode the F2 ladder climbs through");
                fail++;
            } else if (g_vt_fix) {
                if (g_vt_fix)
                    logf_("[*] [vtext] fix armed for %dx%d (aspect %.4f): BoxH=%d BoxDY=%d",
                          g_vt_fw, g_vt_fh, vt_ar, g_vt_boxh, g_vt_boxdy);
                if (patch_vtext_sites()) ok++; else fail++;
                if (g_vt_entry) { if (patch_vtext_wrapper()) ok++; else fail++; }
            }
        }
    }

    /* Repaint the bottom-bar readouts. ON by default, like every other fix
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

    /* CROSS-CHECK THE ART AGAINST THE MODE. tropico-setmode.sh stamps the mode
     * whose art set is currently unpacked into data/. A half-applied
     * swap -- ini moved, art not, or the reverse -- looks exactly like the stock
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

/* ------------------------------------------------- the DirectDraw probe
 *
 * WHICH ENTRY POINT DOES THE GAME ACTUALLY OBTAIN, AND WITH WHAT ARGUMENTS?
 *
 * The question matters because of what it would license. If DirectDraw can be
 * pointed at a monitor, the patch could open the game on the player's chosen
 * screen WITHOUT making it primary -- retiring the whole primary-switching apparatus: the
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
 * what the real function returned. Installed only when [Display] DeviceSelect or
 * [FrameCount] Enable asks for it.
 *
 * IT IS INSTALLED FROM DllMain, which the file header licenses: the IAT lives in
 * .idata, which SteamStub leaves in the clear, and the ddraw load happens at
 * 0x514e55 -- after the GetDeviceCaps that arms the patch pass, but there is no
 * reason to cut it that fine when .idata is readable at load time. */

typedef HMODULE  (WINAPI *loadlib_t)(LPCSTR);
typedef FARPROC  (WINAPI *getproc_t)(HMODULE, LPCSTR);
typedef BOOL     (WINAPI *freelib_t)(HMODULE);
typedef HRESULT  (WINAPI *ddc_t)   (GUID *, void **, IUnknown *);
typedef HRESULT  (WINAPI *ddcex_t) (GUID *, void **, const IID *, IUnknown *);
typedef HRESULT  (WINAPI *ddenumex_t)(void *, void *, DWORD);

static loadlib_t  g_dispsel_loadlib;
static getproc_t  g_dispsel_getproc;
static freelib_t  g_dispsel_freelib;
static ddc_t      g_dispsel_real_create;
static ddcex_t    g_dispsel_real_createex;
static ddenumex_t g_dispsel_real_enumex;
static HMODULE    g_dispsel_mod;          /* the ddraw the game loaded */

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
#define DISPSEL_CALLER() (__builtin_return_address(0))

/* Defined below: the createex wrapper is the only place that sees the
 * IDirectDraw7 before the game uses it. The frame counter and the device-origin
 * translation both ride it. */
static void dd_attach(IDirectDraw7 *dd);

static HRESULT WINAPI dispsel_create(GUID *guid, void **out, IUnknown *unk)
{
    HRESULT hr;
    logf_("[dispsel] DirectDrawCreate(guid=%s, out=%p, unk=%p) from %p",
          ddp_guid(guid), (void *)out, (void *)unk, DISPSEL_CALLER());
    hr = g_dispsel_real_create(guid, out, unk);
    logf_("[dispsel]   -> 0x%08lx%s, object %p", (unsigned long)hr,
          hr == 0 ? " (DD_OK)" : "", out ? *out : NULL);
    if (!guid)
        logf_("[dispsel]   NOTE: NULL device. A device GUID substituted here is exactly"
              " the interception device selection would need.");
    return hr;
}

/* Name -> GUID, by asking DirectDraw the same question the probe asked.
 *
 * Deliberately NOT done from DllMain. The lookup needs ddraw.dll, and loading a
 * library under the loader lock is a hazard reading the display from DllMain does
 * not have to face -- reading the display from there is safe, LoadLibrary is not. By the time the
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

    m = g_dispsel_mod ? g_dispsel_mod : GetModuleHandleA("ddraw.dll");
    if (!m) m = LoadLibraryA("ddraw.dll");
    if (!m) { logf_("[x] [dispsel] ddraw.dll is not loadable -- cannot resolve %s",
                    g_devsel_want); return; }

    /* The real export, never the wrapper: this enumeration is ours and must not
     * be mistaken for the game's in the log, nor run the game's callback. */
    ex = (ddenumex_t)(void *)GetProcAddress(m, "DirectDrawEnumerateExA");
    if (!ex) { logf_("[x] [dispsel] DirectDrawEnumerateExA is missing -- this build of"
                     " DirectDraw cannot name a monitor"); return; }

    ex((void *)devsel_cb, NULL, DDENUM_ATTACHEDSECONDARYDEVICES);
    if (g_devsel_have)
        logf_("[+] [dispsel] %s resolves to device %s", g_devsel_want,
              ddp_guid(&g_devsel_guid));
    else
        logf_("[x] [dispsel] no enumerated device is named %s. The game will be left on"
              " the primary, at the mode already chosen -- check the [dispsel] device"
              " lines, or set [Display] Monitor to a name that appears there.",
              g_devsel_want);
}

static HRESULT WINAPI dispsel_createex(GUID *guid, void **out, const IID *iid, IUnknown *unk)
{
    HRESULT hr;
    logf_("[dispsel] DirectDrawCreateEx(guid=%s, out=%p, iid=%s, unk=%p) from %p",
          ddp_guid(guid), (void *)out, ddp_guid((const GUID *)iid), (void *)unk,
          DISPSEL_CALLER());
    /* THE SUBSTITUTION. One argument, at the one call site, and only when
     * the game asked for the default device -- a game that named a device itself
     * has an opinion we have no business overriding. */
    if (g_devsel && !guid) {
        devsel_resolve();
        if (g_devsel_have) {
            guid = &g_devsel_guid;
            logf_("[+] [dispsel] DirectDrawCreateEx: NULL -> %s (%s). The game will render"
                  " on that monitor; the OS primary is NOT being changed.",
                  ddp_guid(guid), g_devsel_want);
            if (g_devsel_ox || g_devsel_oy) {
                g_devsel_xlate = 1;
                logf_("[+] [dispsel] %s is at (%ld,%ld) in screen space and this device's"
                      " surface is 0,0-based, so every Blt destination is translated by"
                      " (%ld,%ld). Without this the game blits outside its own surface"
                      " and every frame is #150.",
                      g_devsel_want, g_devsel_ox, g_devsel_oy,
                      -g_devsel_ox, -g_devsel_oy);
            }
        }
    }

    hr = g_dispsel_real_createex(guid, out, iid, unk);
    logf_("[dispsel]   -> 0x%08lx%s, object %p", (unsigned long)hr,
          hr == 0 ? " (DD_OK)" : "", out ? *out : NULL);
    if (g_devsel && g_devsel_have && hr != 0)
        logf_("[x] [dispsel] the substituted device FAILED to create. The game is now"
              " without a DirectDraw object; if it starts at all it will be on the"
              " primary. Set [Display] DeviceSelect=0 and report this log.");
    if (!guid)
        logf_("[dispsel]   NOTE: NULL device.");
    /* This is the only moment the object exists and nothing has been asked
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
typedef WINBOOL (CALLBACK *dispsel_cb_t)(GUID *, char *, char *, void *, HMONITOR);
static dispsel_cb_t g_dispsel_gamecb;

static WINBOOL CALLBACK ddp_enum_tramp(GUID *guid, char *desc, char *drv,
                                       void *ctx, HMONITOR hm)
{
    WINBOOL r;
    MONITORINFOEXA mi;
    memset(&mi, 0, sizeof mi);
    mi.cbSize = sizeof mi;
    logf_("[dispsel]   device: guid=%s desc=\"%s\" driver=\"%s\" hmonitor=%p",
          ddp_guid(guid), desc ? desc : "", drv ? drv : "", (void *)hm);
    if (hm && GetMonitorInfoA(hm, (MONITORINFO *)&mi))
        logf_("[dispsel]           -> %s at (%ld,%ld)-(%ld,%ld)%s", mi.szDevice,
              mi.rcMonitor.left, mi.rcMonitor.top, mi.rcMonitor.right, mi.rcMonitor.bottom,
              (mi.dwFlags & MONITORINFOF_PRIMARY) ? "  PRIMARY" : "");
    r = g_dispsel_gamecb ? g_dispsel_gamecb(guid, desc, drv, ctx, hm) : TRUE;
    if (!r)
        logf_("[dispsel]           the game returned FALSE -- it STOPPED the enumeration"
              " here, which is what making a choice looks like");
    return r;
}

static HRESULT WINAPI dispsel_enumex(void *cb, void *ctx, DWORD flags)
{
    HRESULT hr;
    logf_("[dispsel] DirectDrawEnumerateExA(cb=%p, ctx=%p, flags=0x%08lx) from %p"
          " -- THE GAME IS ENUMERATING DEVICES ITSELF",
          cb, ctx, (unsigned long)flags, DISPSEL_CALLER());
    g_dispsel_gamecb = (dispsel_cb_t)cb;
    hr = g_dispsel_real_enumex(cb ? (void *)ddp_enum_tramp : NULL, ctx, flags);
    logf_("[dispsel]   -> 0x%08lx", (unsigned long)hr);
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

/* ------------------------------------------------------ the frame counter
 *
 * An earlier presenter-rewrite attempt was stopped on a cost objection and then
 * admitted the cost had never been measured -- "the performance number should
 * have come before any cosmetic fix". This is that number. It also answers a
 * second question: whether the software renderer is still fast enough at the
 * resolutions this patch now reaches, which is the only argument for restoring
 * Hardware 3D that the deterministic refusal above does not already dispose of.
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
 * It rides the DirectDraw probe's GetProcAddress interception because that is the only code in
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

/* ------------------------------------------------- the DirectDraw failure watch
 *
 * WHY THIS EXISTS. #150 is DDERR_INVALIDRECT, and the engine's reporter at 0x52d500
 * handles only DDERR_SURFACEBUSY and DDERR_SURFACELOST -- everything else becomes a
 * modal dialog carrying a bare number and no cause. Four separate theories about
 * what precedes that number have now been measured and none survived, which is what
 * happens when you keep guessing at the run-up instead of looking at the call. This
 * looks at the call: every Blt, BltFast and Lock is forwarded untouched, and the
 * ones that FAIL are written down with the rectangle and the geometry they failed
 * against.
 *
 * ALWAYS ON, and not behind an ini key. It costs one predictable branch on a path
 * that already crosses into ddraw, it writes nothing unless a call has already
 * failed, and a fault that only shows up in ordinary play over hours is no use to
 * anyone if catching it first requires knowing to switch something on.
 *
 * The virtual-screen metrics are in the line on purpose. Wine renormalises the
 * primary to (0,0), so making DP-3 primary puts the other head at NEGATIVE
 * coordinates (s74.1), and s59 already records this blit path rejecting rects that
 * touch a screen edge. If that is where #150 comes from, it is visible as the rect
 * and the virtual origin disagreeing -- and if the rect turns out to be perfectly
 * ordinary, that theory is dead too and the log says so. */
static int      g_ddw_n;                   /* failures reported so far */
static void    *g_ddw_vt[8];               /* vtables already hooked */
static int      g_ddw_vtn;
#define DDW_MAX 24                         /* then only every 100th */

static HRESULT (WINAPI *g_real_bltfast)(IDirectDrawSurface7 *, DWORD, DWORD,
                                        IDirectDrawSurface7 *, RECT *, DWORD);
static HRESULT (WINAPI *g_real_lock)(IDirectDrawSurface7 *, RECT *, DDSURFACEDESC2 *,
                                     DWORD, HANDLE);

/* The names that matter here. Anything else is printed as its number, which is
 * still better than what the dialog gives. */
static const char *dd_hr_name(HRESULT hr)
{
    switch ((unsigned long)hr) {
    case 0x88760096UL: return "DDERR_INVALIDRECT (the #150 dialog)";
    case 0x88760082UL: return "DDERR_INVALIDPARAMS";
    case 0x887601aeUL: return "DDERR_SURFACEBUSY";
    case 0x887601c2UL: return "DDERR_SURFACELOST";
    case 0x8876000eUL: return "DDERR_GENERIC";
    case 0x88760154UL: return "DDERR_NOCLIPLIST";
    case 0x887600e1UL: return "DDERR_UNSUPPORTED";
    case 0x887601b0UL: return "DDERR_WASSTILLDRAWING";
    default:           return "unnamed";
    }
}

/* Dimensions straight from the surface at the moment it failed, rather than from
 * anything remembered earlier -- a stale record is how a log ends up describing a
 * surface the call was not made against. */
static void dd_dims(IDirectDrawSurface7 *s, char *out, size_t cap)
{
    DDSURFACEDESC2 sd;
    if (!s) { snprintf(out, cap, "none"); return; }
    memset(&sd, 0, sizeof sd); sd.dwSize = sizeof sd;
    if (IDirectDrawSurface7_GetSurfaceDesc(s, &sd) == DD_OK)
        snprintf(out, cap, "%lux%lu %lubpp", (unsigned long)sd.dwWidth,
                 (unsigned long)sd.dwHeight,
                 (unsigned long)sd.ddpfPixelFormat.dwRGBBitCount);
    else
        snprintf(out, cap, "dimensions unavailable");
}

static void dd_rect(const RECT *r, char *out, size_t cap)
{
    if (!r) snprintf(out, cap, "NULL (the whole surface)");
    else    snprintf(out, cap, "(%ld,%ld)-(%ld,%ld) %ldx%ld", r->left, r->top,
                     r->right, r->bottom, r->right - r->left, r->bottom - r->top);
}

/* One report per failed call. Rate-limited because logf_ reopens the file every
 * time: a surface that fails every frame would otherwise make the log the slowest
 * thing in the process, and the first few carry the whole diagnosis anyway. */
static void dd_fail(const char *call, HRESULT hr, IDirectDrawSurface7 *self,
                    const RECT *dst, IDirectDrawSurface7 *src, const RECT *srcr,
                    DWORD flags)
{
    char sd[64], ss[64], rd[96], rs[96];
    g_ddw_n++;
    if (g_ddw_n > DDW_MAX && (g_ddw_n % 100) != 0) return;

    dd_dims(self, sd, sizeof sd);
    dd_dims((IDirectDrawSurface7 *)src, ss, sizeof ss);
    dd_rect(dst, rd, sizeof rd);
    dd_rect(srcr, rs, sizeof rs);

    logf_("[x] [dd] %s FAILED hr=0x%08lx %s  (failure %d)", call,
          (unsigned long)hr, dd_hr_name(hr), g_ddw_n);
    logf_("        dest surface %p %s%s   dest rect %s", (void *)self, sd,
          self == g_fc_primary ? " [PRIMARY]" : "", rd);
    logf_("        src  surface %p %s   src  rect %s   flags 0x%08lx",
          (void *)src, ss, rs, (unsigned long)flags);
    logf_("        screen %dx%d   virtual origin %d,%d size %dx%d   monitors %d",
          GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN),
          GetSystemMetrics(SM_XVIRTUALSCREEN), GetSystemMetrics(SM_YVIRTUALSCREEN),
          GetSystemMetrics(SM_CXVIRTUALSCREEN), GetSystemMetrics(SM_CYVIRTUALSCREEN),
          GetSystemMetrics(SM_CMONITORS));
    if (g_ddw_n == DDW_MAX)
        logf_("        (that is %d failures; only every 100th is reported now)", DDW_MAX);
}

/* Two jobs, and only one of them touches anything.
 *
 * The frame counter counts: the arguments are not read and not rewritten, because a counter
 * that changed what it counted would be worthless.
 *
 * The device-origin translation translates, and ONLY when DeviceSelect put the game on a monitor whose
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
             * off-surface ones this translation predicts, the theory was wrong and the log
             * says so rather than quietly succeeding for another reason. */
            if (g_devsel_logged < 3) {
                logf_("  [dispsel] Blt dst (%ld,%ld)-(%ld,%ld) -> (%ld,%ld)-(%ld,%ld)",
                      dst->left, dst->top, dst->right, dst->bottom,
                      r.left, r.top, r.right, r.bottom);
                if (++g_devsel_logged == 3)
                    logf_("  [dispsel] (further translations not logged)");
            }
            dst = &r;
        }
    }
    {
        HRESULT hr = g_real_blt(self, dst, src, srcr, flags, fx);
        if (FAILED(hr)) dd_fail("Blt", hr, self, dst, src, srcr, flags);
        return hr;
    }
}

/* BltFast takes a destination POINT rather than a rect, so the rect it actually
 * failed against is reconstructed from the source extent -- otherwise the log would
 * show a corner and leave the reader to do the arithmetic that matters. */
static HRESULT WINAPI hook_BltFast(IDirectDrawSurface7 *self, DWORD x, DWORD y,
                                   IDirectDrawSurface7 *src, RECT *srcr, DWORD trans)
{
    HRESULT hr = g_real_bltfast(self, x, y, src, srcr, trans);
    if (FAILED(hr)) {
        RECT d;
        d.left = (LONG)x; d.top = (LONG)y;
        d.right  = (LONG)x + (srcr ? srcr->right  - srcr->left : 0);
        d.bottom = (LONG)y + (srcr ? srcr->bottom - srcr->top   : 0);
        dd_fail("BltFast", hr, self, srcr ? &d : NULL, src, srcr, trans);
    }
    return hr;
}

/* Lock is in here because the frame loop is Lock(offscreen) -> render -> Unlock ->
 * Blt(primary), so a rectangle the engine got wrong can be refused at either end,
 * and only one of those two would have been visible otherwise. */
static HRESULT WINAPI hook_Lock(IDirectDrawSurface7 *self, RECT *dst,
                                DDSURFACEDESC2 *desc, DWORD flags, HANDLE ev)
{
    HRESULT hr = g_real_lock(self, dst, desc, flags, ev);
    if (FAILED(hr)) dd_fail("Lock", hr, self, dst, NULL, NULL, flags);
    return hr;
}

/* ONE vtable, hooked once. ddraw shares a single IDirectDrawSurface7 vtable across
 * every surface, so this covers the offscreen surface as well as the primary. If a
 * second, different vtable ever turned up, hooking it too would overwrite the three
 * "real" pointers with that vtable's originals and every forward through the first
 * one would then go to the wrong function -- so a second vtable is reported and
 * left alone rather than half-handled. */
static void ddw_hook_vtable(IDirectDrawSurface7 *s)
{
    void *vt;
    if (!s || !s->lpVtbl) return;
    vt = (void *)s->lpVtbl;
    if (g_ddw_vtn) {
        if (g_ddw_vt[0] == vt) return;
        if (g_ddw_vtn == 1) {
            g_ddw_vtn = 2;
            logf_("[!] [dd] a second surface vtable (%p) exists; only the first is"
                  " watched, so failures on surfaces using it are not reported", vt);
        }
        return;
    }
    g_ddw_vt[0] = vt;
    g_ddw_vtn = 1;
    if (hook_slot((void **)&s->lpVtbl->Blt, (void *)hook_Blt, (void **)&g_real_blt) &&
        hook_slot((void **)&s->lpVtbl->BltFast, (void *)hook_BltFast,
                  (void **)&g_real_bltfast) &&
        hook_slot((void **)&s->lpVtbl->Lock, (void *)hook_Lock, (void **)&g_real_lock)) {
        logf_("[*] [dd] watching Blt, BltFast and Lock for FAILURES only -- every call"
              " is forwarded untouched, and nothing is written unless one returns an"
              " error. This is what turns a bare #150 into the call and the rectangle"
              " that produced it.");
    } else {
        logf_("[x] [dd] could not hook the surface vtable -- DirectDraw failures will"
              " not be reported, and #150 stays a bare number");
        g_fc = 0;
        g_devsel_xlate = 0;
        g_ddw_vtn = 0;
    }
}

/* Which surface the per-frame Blt will be aimed at -- the one thing both consumers
 * need from CreateSurface. The descriptor is forwarded EXACTLY as the game wrote
 * it and the surface that comes back is the game's own; all this does is remember
 * it and hook Blt on it, once. The frame counter then counts on it, the translation acts on it,
 * and with both off it is never hooked at all. */
static HRESULT WINAPI hook_CreateSurface(IDirectDraw7 *self, DDSURFACEDESC2 *desc,
                                         IDirectDrawSurface7 **out, IUnknown *unk)
{
    DDSURFACEDESC2 sd;
    HRESULT hr = g_real_cs(self, desc, out, unk);

    if (hr != DD_OK || !desc || !out || !*out) return hr;

    /* Before the primary-surface test, not after it: the failure watch wants the
     * offscreen surface the engine Locks every frame just as much as the primary,
     * and the vtable that carries both is reachable from whichever comes first. */
    ddw_hook_vtable(*out);

    if (g_fc_primary) return hr;
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
    {
        if (g_fc)
            logf_("[+] [fps] counting frames on the primary %lux%lu %lubpp (%p)."
                  " A report follows every %d s.",
                  (unsigned long)g_fc_w, (unsigned long)g_fc_h,
                  (unsigned long)g_fc_bpp, (void *)*out, g_fc_interval);
        if (g_devsel_xlate)
            logf_("[+] [dispsel] Blt hooked on the primary surface %lux%lu (%p) --"
                  " destinations will be translated into it.",
                  (unsigned long)g_fc_w, (unsigned long)g_fc_h, (void *)*out);
    }
    return hr;
}

/* Attach to the IDirectDraw7 the moment it is created, which is the only moment it
 * can be reached -- the game keeps it in a global at 0x61c80c and never hands it to
 * anyone. ONE method is patched, and only to learn which surface is the primary.
 * The cooperative level and both mode calls stay the game's own. */
static void dd_attach(IDirectDraw7 *dd)
{
    /* No longer gated on FrameCount or DeviceSelect. The failure watch wants this
     * on every run, and this is the only code that ever sees the IDirectDraw7. */
    if (!dd || g_real_cs) return;

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
    HMODULE m = g_dispsel_loadlib(name);
    if (name && ddp_names_ddraw(name)) {
        g_dispsel_mod = m;
        logf_("[dispsel] LoadLibraryA(\"%s\") from %p -> %p", name, DISPSEL_CALLER(), (void *)m);
    }
    return m;
}

static FARPROC WINAPI hook_GetProcAddress(HMODULE mod, LPCSTR name)
{
    FARPROC p = g_dispsel_getproc(mod, name);
    /* HIWORD==0 means an ordinal, not a string -- dereferencing it as a name is
     * the classic way to turn a probe into a crash. */
    if (!name || !((ULONG_PTR)name >> 16)) return p;

    if (mod != g_dispsel_mod) {
        /* Not the module LoadLibraryA reported -- but a name beginning
         * "DirectDraw" is worth catching anyway. It means ddraw arrived by a
         * route this hook did not see (LoadLibraryW, GetModuleHandle, a handle
         * cached before we installed), and a probe that stayed quiet there would
         * report "the game never resolved DirectDrawCreate" when it had. That is
         * a silent path read as a negative result. */
        if (strncmp(name, "DirectDraw", 10)) return p;
        logf_("[dispsel] GetProcAddress(module %p, \"%s\") from %p -> %p"
              "   -- NOT the module LoadLibraryA reported (%p); adopting it",
              (void *)mod, name, DISPSEL_CALLER(), (void *)p, (void *)g_dispsel_mod);
        g_dispsel_mod = mod;
    } else {
        logf_("[dispsel] GetProcAddress(ddraw, \"%s\") from %p -> %p",
              name, DISPSEL_CALLER(), (void *)p);
    }
    if (!p) return p;

    if (!strcmp(name, "DirectDrawCreate")) {
        g_dispsel_real_create = (ddc_t)(void *)p;
        return (FARPROC)(void *)dispsel_create;
    }
    if (!strcmp(name, "DirectDrawCreateEx")) {
        g_dispsel_real_createex = (ddcex_t)(void *)p;
        return (FARPROC)(void *)dispsel_createex;
    }
    if (!strcmp(name, "DirectDrawEnumerateExA")) {
        g_dispsel_real_enumex = (ddenumex_t)(void *)p;
        return (FARPROC)(void *)dispsel_enumex;
    }
    return p;
}

static BOOL WINAPI hook_FreeLibrary(HMODULE mod)
{
    if (mod && mod == g_dispsel_mod)
        logf_("[dispsel] FreeLibrary(ddraw %p) from %p", (void *)mod, DISPSEL_CALLER());
    return g_dispsel_freelib(mod);
}

static void maybe_install_dispsel(void)
{
    char ip[MAX_PATH];
    snprintf(ip, sizeof ip, "%s\\tropico-fix.ini", g_dir);
    /* DirectDrawCreateEx is where the device GUID is chosen, and this is the
     * only code that sees the call. Read here rather than from g_devsel, because
     * maybe_install_dispsel() runs BEFORE choose_monitor() sets that -- the hook
     * has to exist before the game resolves anything. */
    /* DEFAULT ON since a full test run confirmed it works cleanly. It costs nothing when there is nothing
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
            logf_("[!] [dispsel] DeviceSelect=%s, but this is Wine -- it reports ONE"
                  " adapter GUID for every head, so there is nothing"
                  " to substitute. The monitor is chosen the way it always has been"
                  " here; nothing is lost by leaving this set.", e);
        g_devsel = 0;
    }
    /* The frame counter rides the same GetProcAddress interception, because this is the code that
     * sees the IDirectDraw7 being created and the game hands it to no one else. */
    g_fc = GetPrivateProfileIntA("FrameCount", "Enable", 0, ip);
    g_fc_interval = GetPrivateProfileIntA("FrameCount", "Interval", 5, ip);
    if (g_fc_interval < 1) g_fc_interval = 1;
    if (g_fc)
        logf_("[*] [fps] frame counting armed, reporting every %d s. It intercepts"
              " nothing the game relies on; Blt is forwarded untouched.", g_fc_interval);
    /* Was `if (!g_fc && !g_devsel) return;`, and that return is why no DirectDraw
     * call was observed on Linux at all: DeviceSelect is force-disabled under Wine
     * a few lines above and FrameCount defaults off, so both were always 0 here and
     * the interception that finds the IDirectDraw7 was never installed. The failure
     * watch needs it installed on every run. */

    if (!hook_import("KERNEL32.dll", "LoadLibraryA", (void *)hook_LoadLibraryA,
                     (void **)&g_dispsel_loadlib))
        logf_("[x] [dispsel] KERNEL32!LoadLibraryA not in the import table");
    if (!hook_import("KERNEL32.dll", "GetProcAddress", (void *)hook_GetProcAddress,
                     (void **)&g_dispsel_getproc))
        logf_("[x] [dispsel] KERNEL32!GetProcAddress not in the import table");
    if (!hook_import("KERNEL32.dll", "FreeLibrary", (void *)hook_FreeLibrary,
                     (void **)&g_dispsel_freelib))
        logf_("[x] [dispsel] KERNEL32!FreeLibrary not in the import table");
    if (g_dispsel_loadlib && g_dispsel_getproc)
        logf_("[*] [dispsel] armed -- logging how the game obtains DirectDraw."
              " It changes nothing; every wrapper forwards.");
}


/* --------------------------------------------- the monitor, from inside
 *
 * Measured: a Windows process under Proton CAN execute host binaries through
 * `start.exe /unix`, and xrandr run that way sees the real display -- both outputs,
 * their modes and their positions, on DISPLAY=:1. So the proxy can do for the Steam
 * edition what tools/tropico does for GOG: make the monitor the game will run on the
 * PRIMARY one, because Wine measures only the primary and a game sized for another
 * screen dies with DirectDraw #150.
 *
 * Deliberately conservative. Changing the primary output moves the user's panels and
 * icons for the duration of the game, so it happens ONLY when the primary's current
 * mode does not match the art this install was built for AND another output does
 * match. On one monitor, or when the primary is already the play monitor, nothing is
 * touched and nothing is logged beyond saying so.
 *
 * Restoring is the hard half: a crash must not leave someone's desktop rearranged.
 * A Windows-side "restore on exit" cannot survive a crash by definition, so the
 * restore runs on the HOST: a detached shell holds on this process and puts the
 * primary back when it ends -- whether that is a clean exit, a crash, or a kill.
 *
 * "Holds on" used to mean the age of a marker file, and that was the bug. File age
 * cannot tell a DEAD game from a BUSY one, so any ten-second stall -- an autosave, a
 * starved thread, a directory that briefly refused a write -- read as death and the
 * shell moved the primary out from under a game that was still running. What the
 * player sees of that is DirectDraw #150 and a crash, mid-map, with nothing visible
 * on the desktop, because changing which output is primary blanks nothing.
 *
 * So the shell holds on the PID instead, and a stall is no longer fatal. Getting the
 * pid took measuring, because the two obvious routes are both wrong here: $PPID
 * inside a unix_sh() script is 1, the shell having been reparented before it runs,
 * and Z:\proc\self resolves to WINESERVER rather than to the game. What does work is
 * asking the kernel who holds the marker OPEN -- an open Win32 handle is a real fd on
 * this process -- so the marker survives as the thing that identifies us, and the
 * heartbeat that rewrites it survives as instrumentation and as the fallback rule for
 * when the scan finds nothing. */
static char g_xr_prev[64];
static char g_xr_marker_win[MAX_PATH];
static char g_xr_marker_unix[MAX_PATH];
static char g_xr_mode_win[MAX_PATH];    /* which rule the watchdog actually took */
static char g_xr_mode_unix[MAX_PATH];
/* <0 not yet read, 0 watchdog fell back to file age, >0 the pid it holds on. Read
 * once by apply_monitor(); the heartbeat only reports it, so the log cannot claim a
 * consequence that the running watchdog would not produce. */
static int  g_hb_pid_guard = -1;

/* THE HEARTBEAT CONTRACT, in one place because both halves of it live in this
 * file: this process rewrites the marker every HB_INTERVAL_MS, and the host
 * watchdog spawned by apply_monitor() hands the primary back once that file is
 * HB_STALE_MS old. The shell loop is formatted from these same two numbers, so
 * the deadline the log quotes cannot drift from the one actually enforced.
 *
 * The margin is four missed beats, and nothing used to report whether any were
 * being missed. A failed write and a starved thread both looked exactly like a
 * healthy run, while their consequence -- the watchdog reconfiguring the display
 * underneath a game that has already measured it -- reaches the player only as
 * DirectDraw #150, which names no cause. HB_WARN_MS is the point where half that
 * margin is spent: late enough to stay quiet on a good run, early enough to be
 * in the log before the fault lands. */
#define HB_INTERVAL_MS  2000
#define HB_STALE_MS    10000
#define HB_WARN_MS      6000

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

/* Ask X where the pointer is, not Wine.
 *
 * GetCursorPos returns 0,0 at this point in startup -- Wine has no pointer state
 * before the game has a window -- and 0,0 maps inside the primary monitor whatever
 * the layout, so the launch-monitor detector always answered "the primary". It looked
 * correct whenever the primary WAS the launch monitor, which is exactly the case that
 * needs no detection. (Same shape as any zero-sample defect: an in-band value that is
 * indistinguishable from a real answer.)
 *
 * XQueryPointer has no such ambiguity and reports ROOT coordinates -- the same space
 * xrandr reports output positions in -- so no conversion is needed either. */
static const char POINTER_PY[] =
    /* XQueryPointer is DEAD ON WAYLAND. XWayland is only sent pointer events
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
    char cmd[MAX_PATH * 2], win[MAX_PATH], udir[MAX_PATH], body[MAX_PATH * 13];
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
     * for it. Measured -- the touch marker appeared on disk from the
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
    DWORD last = GetTickCount();
    DWORD worst = 0;
    int wrote_once = 0, fired = 0, failing = 0;
    HANDLE h = INVALID_HANDLE_VALUE;
    (void)p;
    for (;;) {
        DWORD gap = GetTickCount() - last;

        /* The watchdog's last act before it exits is `rm -f` on this marker, and
         * nothing else in the project ever removes it. So finding it gone is not
         * ambiguous: the restore has already run, the primary has moved, and this
         * process is now painting with rectangles measured against a screen it no
         * longer owns -- which is precisely the state DirectDraw answers with
         * DDERR_INVALIDRECT. Say that in words, once, instead of leaving a bare
         * #150 for someone to decode. */
        if (wrote_once && !fired &&
            GetFileAttributesA(g_xr_marker_win) == INVALID_FILE_ATTRIBUTES) {
            logf_("[x] [display] the host watchdog has FIRED MID-RUN: %s is gone, so the"
                  " primary has been handed back to %s while the game is still running."
                  " The geometry the game measured no longer matches its window, which is"
                  " how DirectDraw #150 arrives. Longest heartbeat gap seen was %lu ms,"
                  " against a %d ms deadline.",
                  g_xr_marker_unix, g_xr_prev, (unsigned long)worst, HB_STALE_MS);
            fired = 1;
        }

        /* Opened ONCE and held for the life of the process, which is the whole
         * reason the host can identify us: the handle is a real fd on this process
         * in /proc, so the watchdog resolves our pid by asking who holds the marker
         * open. Closing it between beats, as this used to, would leave that scan a
         * race it loses most of the time. Reopened only if a write ever fails. */
        if (h == INVALID_HANDLE_VALUE)
            h = CreateFileA(g_xr_marker_win, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD wrote;
            /* Rewind and overwrite rather than append: the content is never read,
             * only the mtime, and a file that grows all session is a slow leak. */
            SetFilePointer(h, 0, NULL, FILE_BEGIN);
            if (!WriteFile(h, "alive\n", 6, &wrote, NULL) || !FlushFileBuffers(h)) {
                CloseHandle(h);
                h = INVALID_HANDLE_VALUE;
            }
        }
        if (h != INVALID_HANDLE_VALUE) {
            if (failing) {
                logf_("  [display] heartbeat wrote again after %d failed attempt(s)",
                      failing);
                failing = 0;
            }
            wrote_once = 1;
            /* Report a gap only when it is both unusual and worse than anything
             * already reported. A healthy run stays silent, a run that came close
             * says how close it came, and neither produces a line every two
             * seconds for the length of a session. */
            if (gap > worst) {
                worst = gap;
                if (gap >= HB_WARN_MS) {
                    /* What a stall COSTS depends on which rule the watchdog took, so
                     * ask rather than assert. Under the pid rule a stall is a health
                     * reading and nothing more; only the fallback still turns one
                     * into a display change and a #150. */
                    if (g_hb_pid_guard > 0)
                        logf_("[!] [display] heartbeat stalled %lu ms (interval %d ms)."
                              " The watchdog is holding on pid %d, so this costs"
                              " nothing -- it is a health reading, not a pending fault.",
                              (unsigned long)gap, HB_INTERVAL_MS, g_hb_pid_guard);
                    else
                        logf_("[!] [display] heartbeat stalled %lu ms (interval %d ms)."
                              " The watchdog could not identify this process and is"
                              " holding on file age instead, so at %d ms it restores the"
                              " primary underneath the running game and the next blit"
                              " fails with #150.",
                              (unsigned long)gap, HB_INTERVAL_MS, HB_STALE_MS);
                }
            }
            last = GetTickCount();
        } else {
            /* To the watchdog a write that fails is indistinguishable from a dead
             * game, and this branch used to do nothing whatsoever. Rate-limited so
             * an unwritable directory costs a few lines rather than thousands. */
            failing++;
            if (failing <= 3 || (failing % 30) == 0)
                logf_("[x] [display] heartbeat could NOT write %s (error %lu, attempt"
                      " %d).%s",
                      g_xr_marker_unix, (unsigned long)GetLastError(), failing,
                      g_hb_pid_guard > 0
                        ? " The watchdog is holding on this process's pid, so the"
                          " primary is not at risk from it."
                        : " The watchdog is holding on file age, so four in a row"
                          " hand the primary back mid-run.");
        }
        Sleep(HB_INTERVAL_MS);
    }
    return 0;
}

/* Everything xrandr told us about one output. */
typedef struct { char name[64]; int primary; DWORD w, h; long x, y; } xout_t;

static long g_ptr_x = -1, g_ptr_y = -1;   /* root coords, from the host helper */
static char g_ptr_how[16] = "";           /* which method answered            */

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
            /* The third field is which method answered. Optional, so an older
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

/* ------------------------------------------- the same list, from Win32
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
 * XRANDR STAYS FIRST WHERE IT ANSWERS. Under Wine the Win32 view is what
 * Wine measures only the primary and renormalises the rest
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

/* WHICH MONITOR WAS THIS LAUNCHED FROM, on Windows.
 *
 * An earlier probe settled this on Linux and the answer was not the pointer: "the mouse can sit
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

/* ------------------------------------- putting the primary back afterwards
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
 * [Display] SetPrimary=0 switches all of it off.
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
 * WHY THERE IS MORE THAN ONE OF THESE. The version below marked
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
            /* EVERY RETURN CODE IS READ. Discarding these is what made an earlier
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

/* THE OTHER THREE ARE GONE, AND MEASURED. probes/primaryprobe.c tried all
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

/* ------------------------------------------------- the same job, via CCD
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

/* ------------------------------------------------------ try, then CHECK
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
static int running_under_wine(void)
{
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    return nt && GetProcAddress(nt, "wine_get_version") != NULL;
}

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
     * had before this whole CCD investigation, which is what keeps the Linux path
     * identical in its log. */
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

/* --------------------------------------------- giving it back, on the way out
 *
 * WHAT THIS REPLACES, AND WHY IT WAS THE WRONG SIGNAL. An earlier version watched for the
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
 * moment DLL_PROCESS_DETACH is NOT, which is why that earlier version refused to restore there
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
     * inline. The judgement was that "a desktop on the wrong primary is
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

/* The monitor is chosen from WHERE THE GAME WAS LAUNCHED, not from the mode
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
    /* DEFAULT OFF ON WINDOWS, ON UNDER WINE, AND THE ASYMMETRY IS THE POINT.
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
     * read, so on Windows -- where SetPrimary now defaults to 0 -- setting
     * either of them did nothing at all, and did it without a word. That is a
     * silence that reads as a result. The keys are not wrong and the
     * gate is not wrong; what was missing was the sentence joining them.
     *
     * Both are checked as STRINGS with an empty default, because
     * GetPrivateProfileInt cannot tell "absent" from "set to the default" and
     * FollowLaunchMonitor's default is 1 -- so an int read would stay silent for the
     * player who set it explicitly, which is exactly the player being addressed. */
    /* Device selection splits this gate. Everything above the "RECORD IT" block at the bottom
     * only READS the display, and DeviceSelect needs those reads -- which monitor
     * was launched from and what mode it is in -- while wanting the primary left
     * exactly where it is. So SetPrimary gates the WRITE at the bottom, and this
     * early return survives only for the case where neither feature is on.
     *
     * That preserves the guarantee above literally: with SetPrimary=0 and
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
         * launcher winning is the same rule as above, not a special case invented here. */
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

    /* ONE MONITOR IS THE LAUNCH MONITOR. This used to return with nothing adopted,
     * leaving the mode to the picker, which filters against the LOGICAL desktop --
     * so a 4K panel at 150% ran at 2560x1440 while the same panel beside a second
     * monitor took the launch path below and ran at its own 3840x2160 (FINDINGS
     * 92, 122). The two paths now answer alike: the monitor's own mode, read from
     * EnumDisplaySettings, which scaling does not touch. Nothing else here applies
     * to one monitor: it is the primary, so there is no device to substitute and no
     * primary to move. */
    if (n == 1) {
        if (GetPrivateProfileIntA("Display", "FollowLaunchMonitor", 1, ip)) {
            g_launch_w = outs[0].w;
            g_launch_h = outs[0].h;
            snprintf(g_launch_name, sizeof g_launch_name, "%s", outs[0].name);
            logf_("[+] [display] one monitor -- running at %s's own mode %lux%lu",
                  outs[0].name, (unsigned long)g_launch_w, (unsigned long)g_launch_h);
        } else {
            logf_("  [display] one monitor (%s, %lux%lu); FollowLaunchMonitor=0, so its"
                  " mode is not adopted -- the picker chooses", outs[0].name,
                  (unsigned long)outs[0].w, (unsigned long)outs[0].h);
        }
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
    /* Native Windows asks the desktop what it is focused on, and only then
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
        snprintf(g_launch_name, sizeof g_launch_name, "%s", outs[chosen].name);
        logf_("[+] [display] running at %s's own mode %lux%lu", outs[chosen].name,
              (unsigned long)g_launch_w, (unsigned long)g_launch_h);
    }

    /* The target, as the name DirectDraw will be asked for. Recorded here
     * because this is where "which monitor" is decided; resolved to a GUID much
     * later, at DirectDrawCreateEx, where loading ddraw.dll is safe. */
    if (g_devsel) {
        if (!g_mon_win32) {
            logf_("[x] [dispsel] the monitor list did not come from Windows, so these"
                  " names are not \\\\.\\DISPLAYn and DirectDraw cannot be asked for one."
                  " DeviceSelect is OFF for this run.");
            g_devsel = 0;
        } else if (chosen == prim) {
            logf_("  [dispsel] %s is already the primary -- the game renders there by"
                  " default and there is no device to substitute.", outs[prim].name);
            g_devsel = 0;
        } else {
            snprintf(g_devsel_want, sizeof g_devsel_want, "%s", outs[chosen].name);
            g_devsel_ox = outs[chosen].x;
            g_devsel_oy = outs[chosen].y;
            logf_("[+] [dispsel] target %s %lux%lu -- the game will be pointed at that"
                  " DEVICE and the primary %s is NOT being changed",
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

/* ------------------------------------------------------ apply_monitor
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
 * audio plays over a black screen and it looks exactly like a crash.
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
    char script[MAX_PATH * 12], udir[MAX_PATH];
    if (!g_mon_pending) {
        /* Nothing to change for this run -- but a previous one may still owe the
         * player their primary back. Hand it back when the game closes, not
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
    snprintf(g_xr_mode_win,  sizeof g_xr_mode_win,  "%s\\tropico-primary.mode", g_dir);
    snprintf(g_xr_mode_unix, sizeof g_xr_mode_unix, "%s/tropico-primary.mode", udir);
    /* The thread must be holding the marker open BEFORE the script scans for whoever
     * holds it -- that scan is what turns the marker into a pid. It writes on entry,
     * so this wait is for the open, not for a beat. */
    CloseHandle(CreateThread(NULL, 0, heartbeat_thread, NULL, 0, NULL));
    Sleep(150);

    if ((size_t)snprintf(script, sizeof script,
             "/usr/bin/xrandr --output %s --primary\n"
             /* WHO HOLDS THE MARKER OPEN. That is this game process, and the kernel
              * is the only thing here that knows: $PPID in this script is 1, and
              * Z:\\proc\\self is wineserver. Both measured, both would have made the
              * watchdog fire seconds into every run rather than never. wineserver
              * holds the same file and outlives the game, so it is skipped by name.
              * One find over /proc, ~17 ms, once per launch. */
             "P=\n"
             "for f in $(find /proc/[0-9]*/fd -maxdepth 1 -lname '%s'"
             " -printf '%%p\\n' 2>/dev/null); do\n"
             "q=${f#/proc/}; q=${q%%%%/*}\n"
             "case $(cat /proc/$q/comm 2>/dev/null) in wineserver*) continue;; esac\n"
             "P=$q; break\n"
             "done\n"
             "[ -n \"$P\" ] && { kill -0 \"$P\" 2>/dev/null || P=; }\n"
             "echo \"${P:-mtime}\" > '%s'\n"
             /* A pid that cannot be signalled is not a liveness test, so an
              * unresolved scan drops to the old file-age rule rather than to a
              * watchdog that fires immediately or one that never fires at all. */
             /* The pid is the ONLY authority when we have one. This used to keep
              * 1.3's `while [ -f marker ]` as the loop condition, so anything that
              * removed the marker -- for any reason, with the game alive and well --
              * exited the loop and moved the player's display. The marker stays the
              * abort flag ONLY on the fallback path, where it is all there is. */
             "( while :; do\n"
             "if [ -n \"$P\" ]; then kill -0 \"$P\" 2>/dev/null || break\n"
             "else [ -f '%s' ] || break\n"
             "N=$(date +%%s); M=$(stat -c %%Y '%s' 2>/dev/null || echo 0)\n"
             "[ $((N-M)) -ge %d ] && break; fi\n"
             "sleep %d\n"
             "done\n"
             "/usr/bin/xrandr --output %s --primary\n"
             "rm -f '%s' '%s' ) &\n",
             g_mon_to, g_xr_marker_unix, g_xr_mode_unix, g_xr_marker_unix,
             g_xr_marker_unix, HB_STALE_MS / 1000, HB_INTERVAL_MS / 1000,
             g_xr_prev, g_xr_marker_unix, g_xr_mode_unix) >= sizeof script) {
        /* A truncated script is a watchdog with no restore in it. Say so and arm
         * nothing rather than leave a half-written one running. */
        logf_("[x] [display] the watchdog script did not fit -- NOT changing the"
              " primary, because nothing would put it back");
        return;
    }
    if (unix_sh(script, 3000)) {
        int k;
        for (k = 0; k < 60; k++) {
            if ((DWORD)GetSystemMetrics(SM_CXSCREEN) == g_mon_to_w &&
                (DWORD)GetSystemMetrics(SM_CYSCREEN) == g_mon_to_h) break;
            Sleep(100);
        }
        /* Which rule the watchdog took, read back from the watchdog rather than
         * assumed from this side. The two differ in what a stall costs, and every
         * later line about the heartbeat is worded from this value. */
        for (k = 0; k < 20 && g_hb_pid_guard < 0; k++) {
            char buf[64];
            DWORD got = 0;
            HANDLE h = CreateFileA(g_xr_mode_win, GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                   OPEN_EXISTING, 0, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                if (ReadFile(h, buf, sizeof buf - 1, &got, NULL) && got) {
                    buf[got] = 0;
                    g_hb_pid_guard = (buf[0] >= '0' && buf[0] <= '9') ? atoi(buf) : 0;
                }
                CloseHandle(h);
            }
            if (g_hb_pid_guard < 0) Sleep(100);
        }
        logf_("[+] [display] primary %s -> %s; Wine now measures %dx%d",
              g_xr_prev, g_mon_to, GetSystemMetrics(SM_CXSCREEN),
              GetSystemMetrics(SM_CYSCREEN));
        if (g_hb_pid_guard > 0)
            logf_("  [display] a host watchdog restores %s when pid %d ends -- clean"
                  " exit, crash or kill alike. It holds on the process itself, so a"
                  " stalled frame or a failed marker write cannot move the display"
                  " out from under the running game.", g_xr_prev, g_hb_pid_guard);
        else
            logf_("[!] [display] a host watchdog restores %s when this process stops,"
                  " but it %s and is holding on marker age instead: it fires after"
                  " %d ms without a beat, and this process beats every %d ms. A stall"
                  " longer than that moves the display out from under the running"
                  " game, and the next blit fails with #150.",
                  g_xr_prev,
                  g_hb_pid_guard == 0 ? "could not work out this process's host pid"
                                      : "never reported which rule it took",
                  HB_STALE_MS, HB_INTERVAL_MS);
    }
}

/* The adopted mode wins over [Resolution]: it describes the screen the player is
 * actually looking at, and the ini describes whatever was configured last. */
static int launch_override(mode_t *m)
{
    if (!g_launch_w || !g_launch_h) return 0;
    m->w = g_launch_w; m->h = g_launch_h;
    return 1;
}

/* ------------------- the adopted mode has to fit the screen too
 *
 * The "MODE MUST FIT THE SCREEN" guard tested `[Resolution]` only. It predates
 * launch_override(), which takes PRIORITY over the ini -- so on the Steam
 * edition, where `[Resolution]` is empty and the mode comes entirely from the launch
 * monitor, the mode the game actually gets was never checked against the screen at all.
 *
 * Measured 2026-08-29: launch monitor 2560x1440, virtual desktop still the 1920x1080
 * one from the previous run, and the patch configured slot 4, the art set and the world
 * painter for 1440p inside a 1080p desktop. The log printed `armed a 2560x1440 virtual
 * desktop. IT TAKES EFFECT ON THE NEXT LAUNCH` and `desktop as Wine sees it: 1920x1080`
 * three lines apart, and nothing compared them.
 *
 * A virtual desktop cannot be resized from inside the process it already contains,
 * so this is not an error to refuse -- it is a mode that arrives one launch
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
    logf_("    Cause: the game was started for one monitor and opened on another."
          " Launch it from the monitor you want to play on.");
    g_launch_w = g_launch_h = 0;      /* let the picker choose one that fits */
}



/* --------------------------------------------- stray top-left pointer reports
 *
 * Under Wine, with monitors that are not aligned along their top edges, the
 * pointer position handed to the game occasionally reads as the top-left corner
 * while the mouse is somewhere else entirely -- measured mid-screen, between two
 * good samples. The game takes that as "pointer in the top-left corner", which is
 * its pan-up-left command, so the map creeps on its own; a window being dragged
 * jumps to the corner for a frame and comes back.
 *
 * WHAT MADE THIS HARD TO SEE, recorded because it cost a lot of time:
 *
 *   - The stray values are NOT all exactly 0,0. They scatter across the corner --
 *     0,0 but also 1,0, 0,1, 2,2, 7,0. An earlier filter tested for exactly 0,0,
 *     caught a fraction, and the symptom survived, which read as the theory being
 *     wrong rather than the test being too narrow.
 *   - They arrive on more than one path. This game polls PeekMessageA in its
 *     main loop and that carries most of them -- measured at roughly eighteen
 *     times the rate of GetCursorPos -- so filtering the obvious call alone
 *     leaves the symptom in place.
 *   - The RATE swings enormously between sessions: measured at ten strays in
 *     220,000 reads, and at 821 in 25,000. Nothing is present-or-absent; a quiet
 *     session is simply one nobody notices.
 *
 * THE RULE: a report is rejected when it lands in the corner AND is too far from
 * the last believed position for a hand to have travelled between two reads. A
 * player genuinely moving into the corner keeps working, because by then the last
 * position is already near it. Rejected reports are replaced with the last good
 * one rather than dropped, so nothing downstream sees a gap.
 *
 * Mouse-message coordinates are relative to the window and pointer reads are
 * relative to the screen, so the two keep separate notions of "last believed".
 *
 * On by default under Wine, off on Windows, where this has never been observed.
 */
#define CUR_CORNER_PX   16    /* how close to the corner counts as the corner */
#define CUR_TELEPORT_PX 200   /* a jump no hand makes between consecutive reads */

static int cursor_stray(LONG *x, LONG *y, POINT *last, int *have)
{
    if (*have && *x <= CUR_CORNER_PX && *y <= CUR_CORNER_PX &&
        (labs(last->x - *x) > CUR_TELEPORT_PX || labs(last->y - *y) > CUR_TELEPORT_PX)) {
        LONG n = InterlockedIncrement(&g_cur_fixed);
        *x = last->x; *y = last->y;
        /* Once, then rarely. This is a per-frame path and a line per event would
         * cost more than the fault does. */
        if (n == 1 || (n % 500) == 0)
            logf_("[*] [cursor] %ld stray top-left report(s) corrected", n);
        return 1;
    }
    last->x = *x; last->y = *y; *have = 1;
    return 0;
}

static BOOL WINAPI hook_GetCursorPos(LPPOINT pt)
{
    BOOL r = g_real_gcp(pt);
    if (r && pt) {
        LONG x = pt->x, y = pt->y;
        if (cursor_stray(&x, &y, &g_cur_screen, &g_cur_have_screen))
            { pt->x = x; pt->y = y; }
    }
    return r;
}

static void cursor_fix_msg(LPMSG m)
{
    LONG x, y;
    if (!m || m->message != WM_MOUSEMOVE) return;
    x = (LONG)(short)LOWORD(m->lParam);
    y = (LONG)(short)HIWORD(m->lParam);
    if (cursor_stray(&x, &y, &g_cur_client, &g_cur_have_client))
        m->lParam = (LPARAM)MAKELONG((WORD)(SHORT)x, (WORD)(SHORT)y);
}

static BOOL WINAPI hook_PeekMessageA(LPMSG m, HWND h, UINT a, UINT b, UINT f)
{ BOOL r = g_real_peek(m, h, a, b, f); if (r) cursor_fix_msg(m); return r; }

static BOOL WINAPI hook_GetMessageA(LPMSG m, HWND h, UINT a, UINT b)
{ BOOL r = g_real_getmsg(m, h, a, b); if (r) cursor_fix_msg(m); return r; }

static DWORD WINAPI hook_GetMessagePos(void)
{
    DWORD d = g_real_msgpos();
    LONG x = (LONG)(short)LOWORD(d), y = (LONG)(short)HIWORD(d);
    if (cursor_stray(&x, &y, &g_cur_screen, &g_cur_have_screen))
        d = (DWORD)MAKELONG((WORD)(SHORT)x, (WORD)(SHORT)y);
    return d;
}

/* Every path the game might read the pointer through. Which ones exist depends on
 * the build, so a missing import is normal and not worth a warning; what would be
 * worth one is hooking none of them. */
static int install_cursor_fix(void)
{
    void *real;
    int n = 0;
    real = NULL;
    if (hook_import("USER32.dll", "GetCursorPos", (void *)hook_GetCursorPos, &real))
        { g_real_gcp = (GetCursorPos_t)real; n++; }
    real = NULL;
    if (hook_import("USER32.dll", "PeekMessageA", (void *)hook_PeekMessageA, &real))
        { g_real_peek = (PeekMessageA_t)real; n++; }
    real = NULL;
    if (hook_import("USER32.dll", "GetMessageA", (void *)hook_GetMessageA, &real))
        { g_real_getmsg = (GetMessageA_t)real; n++; }
    real = NULL;
    if (hook_import("USER32.dll", "GetMessagePos", (void *)hook_GetMessagePos, &real))
        { g_real_msgpos = (GetMessagePos_t)real; n++; }
    return n;
}

/* ------------------------------------------- the world viewport width
 *
 * FUN_0050af10, the constructor for display-object class 0x57e110 (the world),
 * copies the object's own size fields into the embedded image's PIXEL size:
 *
 *   0050af89  movsx ecx,WORD PTR [esi+0x11]     ; object height
 *   0050af8d  movsx eax,WORD PTR [esi+0x0f]     ; object width
 *   0050af91  mov   [esi+0x8e],ecx              ; -> image.height  (= image+0x14)
 *   0050afa9  mov   [esi+0x8a],eax              ; -> image.width   (= image+0x10)
 *
 * Measured: that image sat at 1600x864 px while the screen was 1920x1080, and
 * forcing its width to 1920 at DRAW time was shown to make Hardware 3D
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
/* The DRAW-time detour: the one that is known to work.
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
/* --- telemetry for the viewport fix ---------------------------------
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
     * Steam build. Match the call site itself instead, wildcarding the one
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
     * with the full mode -- which displaced it to the north-west.
     * The main viewport is always 2666/3200 = 83% of the mode width, and the
     * preview is a small panel, so "at least half the screen wide" separates them
     * at every mode without knowing either stock value. */
    if (guard) {
        stub[i++]=0x81; stub[i++]=0x79; stub[i++]=0x10;
        memcpy(stub+i,&guard,4); i+=4;                                /* cmp [ecx+0x10],g  */
        stub[i++]=0x72; fix_gate=i++;                                 /* jb  skip          */
    }

    /* Telemetry, recorded BEFORE the return-address filter and only for draws big
     * enough to be the main viewport. This is what turns "the fix did not
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


/* ------------------------------------------------- the HUD shrink probe
 *
 * The question this probe leaves open is whether the sprite blit STRETCHES its sprite
 * onto the destination rectangle or copies it 1:1 into a rectangle that may be
 * the wrong size.  Growing a rect cannot answer it (a stretched sprite and a
 * stock sprite in a bigger box look alike); shrinking one can.
 *
 * FUN_00502660 is the class-4 draw.  Every one of its style branches builds the
 * destination from obj+0x0b/0x0d (position) and obj+0x0f/0x11 (size), all int16
 * in the virtual 3200x2400 space.  Halving the size at the entry therefore halves
 * the destination rect and nothing else.
 *
 * IDENTIFICATION, learned from an earlier case that one property is not enough: the detour
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
static volatile DWORD g_hud_calls, g_hud_hits;
static volatile DWORD g_hud_hash[4], g_hud_live[4];
/* written by the phase thread, read by the stub every draw */
static volatile DWORD g_hud_style = 0, g_hud_cx = 0, g_hud_cy = 0;
static volatile DWORD g_hud_style_want = 0;
/* The chrome bar.  int_main widget 17 is PATH B -- authored rect
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
 * (the pre-draw is not called per frame, so an earlier guard patch elsewhere did not make it
 * recompute), and every relative edit this project has tried either compounded or
 * stuck.  Writing a REMEMBERED ABSOLUTE value is idempotent whatever the engine
 * does, so a phase can be entered and left without damaging anything. */
static volatile DWORD g_chr_base;
static volatile DWORD g_chr_apply, g_chr_setx, g_chr_sety, g_chr_setcx, g_chr_setcy;
static volatile DWORD g_chr_dirty;

/* Correct the path-B conversion at its source.
 *
 * FUN_00502510 turns the art sprite's stored PIXEL coordinates into the widget's
 * virtual rect by multiplying with the LIVE mode's factors (3200/W at 0x5a0ff8 and
 * 2400/H at 0x5a1000).  That round-trip is the identity, which is why a 1200-tall
 * design lands at its stored pixel row on any screen.
 *
 * Repointing all six fmul operands at our own pair of floats -- 3200/art_w and
 * 2400/art_h, the ART SET's design size rather than the live mode -- makes the
 * conversion say "these pixels are in the art's space", which is what they are.
 *
 * At a stock mode art_w == W, so the constant equals the one it replaced and the
 * patch is the exact identity.  That control is built in: if 1600x1200 changes
 * appearance, this is wrong.
 */
/* The F2 settings tabs' ROTATED-TEXT geometry, which is
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
        /* A patch that changes nothing applies "cleanly" and teaches nothing.
         * Refuse instead. */
        logf_("[*] [vtext] no DY/DX/ClipH override given -- tab geometry left stock");
        return 1;
    }
    logf_("[*] [vtext] %d write(s) across %d site(s)", n, nsites);
    return 1;
}


/* ------------------------------------------------------------------ the rotated-text placement probe
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
}

static int patch_vtext_sites(void)
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
    if (!n) { logf_("[x] [vtext] no tab-layout sites"); return 0; }

    /* scale-factor VAs, read from the site's own fmul operands */
    g_vt_ys_va = rd32(sites[0] + 0x22);
    g_vt_xs_va = rd32(sites[0] + 0x49);
    logf_("[*] [vtext] yscale @%08x  xscale @%08x", g_vt_ys_va, g_vt_xs_va);

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

/* ------------------------------------------------- rotated-text ENTRY probe
 *
 * WHY A SECOND PROBE.  patch_vtext_sites() hooks the two tab-layout CALL SITES, so
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

static void __cdecl vtext_wrapper_hook(DWORD *a)
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
}

static int patch_vtext_wrapper(void)
{
    if (!g_vte_entry_va) {
        logf_("[x] [vtext] wrapper address unknown -- the call-site scan must run first");
        return 0;
    }
    BYTE *entry = (BYTE *)(SIZE_T)g_vte_entry_va;
    /* Refuse unless the first instruction is the expected 5-byte `mov eax,imm32`.
     * A different build could open with something else, and relocating the wrong
     * five bytes would corrupt the function silently. */
    if (entry[0] != 0xB8) {
        logf_("[x] [vtext] %08x does not open with `mov eax,imm32` (%02x) -- refusing",
              g_vte_entry_va, entry[0]);
        return 0;
    }
    BYTE *tr = (BYTE *)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tr) { logf_("[x] [vtext] VirtualAlloc failed"); return 0; }
    int o = 0;
    tr[o++] = 0x60;                                                 /* pushad             */
    tr[o++] = 0x9C;                                                 /* pushfd             */
    tr[o++] = 0x8D; tr[o++] = 0x44; tr[o++] = 0x24; tr[o++] = 0x24; /* lea eax,[esp+0x24] */
    tr[o++] = 0x50;                                                 /* push eax           */
    tr[o++] = 0xB8; { DWORD f = (DWORD)(SIZE_T)&vtext_wrapper_hook; memcpy(tr + o, &f, 4); o += 4; }
    tr[o++] = 0xFF; tr[o++] = 0xD0;                                 /* call eax           */
    tr[o++] = 0x83; tr[o++] = 0xC4; tr[o++] = 0x04;                 /* add esp,4          */
    tr[o++] = 0x9D;                                                 /* popfd              */
    tr[o++] = 0x61;                                                 /* popad              */
    memcpy(tr + o, entry, 5); o += 5;                               /* relocated mov eax  */
    tr[o++] = 0xE9; { DWORD r = (DWORD)(SIZE_T)((entry + 5) - (tr + o + 4)); memcpy(tr + o, &r, 4); o += 4; }

    BYTE det[5];
    det[0] = 0xE9;
    { DWORD r = (DWORD)(SIZE_T)(tr - (entry + 5)); memcpy(det + 1, &r, 4); }
    if (!poke(entry, det, 5)) { logf_("[x] [vtext] VirtualProtect failed"); return 0; }
    logf_("[+] [vtext] rotated-label wrapper %08x detoured -> %p",
          g_vte_entry_va, (void *)tr);
    return 1;
}

/* ------------------------------------------------- the readout colour
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

/* -------------------------------------------------------- apply-video probe
 *
 * WHICH CALL ASKS FOR 640x480 WHEN THE MENU IS RE-ENTERED FROM A MAP.
 *
 * FUN_00515450 is the engine's apply-video-settings routine and takes the five
 * settings as ecx, edx, arg1, arg2, arg3 -> fields +0xc, +0x10, +0x14, +0x18,
 * +0x1c, with arg2 the resolution slot and -1 meaning "keep".
 *
 * A static sweep of all 19 call sites shows only the TWO startup
 * sites pass slot 0 as a literal, and those are already redirected. Every other
 * site either passes -1 or computes the slot at runtime -- so the return-to-menu
 * path cannot be identified by reading immediates, and the honest instrument is
 * to log what the routine is ACTUALLY handed, and by whom. The same approach
 * settles similar ambiguity elsewhere in this file.
 *
 * The routine opens `sub esp,8` / `mov eax,[0x612fec]` = 3 + 5 bytes, so the
 * detour relocates EIGHT, not five: taking five would split the mov and corrupt
 * the function. Both relocated instructions are position-independent.
 *
 * The address is not hardcoded. It is read from the rel32 of the call that ends
 * the startup-slot signature, so it survives a build whose addresses moved --
 * which is the whole reason the Steam build patches at all. */
/* ------------------------------------------------ pin the window to primary
 *
 * WHY THIS EXISTS. Wine measures ONLY the primary monitor and renormalises it to
 * (0,0), which pushes every other monitor to NEGATIVE coordinates -- measured:
 * with HDMI primary the second monitor sits at (1920,-360); with the second one
 * primary, HDMI sits at (-1920,360). The negative axis moves, it never goes away.
 *
 * Placement is decided separately, by the compositor, from the launching context.
 * So if the game's window lands on a monitor that is not the one Wine measured,
 * the engine computes its rects for a screen the window is not on, and DirectDraw
 * rejects them with DDERR_INVALIDRECT -- the infamous #150.
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
    /* DeviceSelect and this have OPPOSITE opinions about where the window
     * belongs. Pinning drags it to the primary because that is where Wine's DirectDraw
     * will render whatever we do; with a device GUID substituted, the game renders
     * on the chosen monitor instead and DirectDraw places the window to match
     * (measured: Windows moved a window to suit the device). Dragging it back
     * would leave the picture on one screen and the mouse on another -- the same
     * picture/pointer mismatch as the pointer-detection failure above, with a new
     * cause. The device decides; this stands down. */
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
        /* Moving it is not the same as it STAYING moved. Measured:
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

static void __cdecl menu_apply_hook(DWORD *a)
{
    pin_window_to_primary("apply-video");
    /* a[] from the trampoline: 0 flags, 1 EDI, 2 ESI, 3 EBP, 4 ESP, 5 EBX,
     * 6 EDX, 7 ECX, 8 EAX, 9 return address, 10 arg1, 11 arg2, 12 arg3. */
    /* THE FIX. Returning to the main menu from a map re-applies the FRONTEND
     * preset row, whose stored resolution slot is 0 -- PopTop put 640x480 there
     * because the menu art only ever existed at that size. The startup
     * redirect does not cover it: that patches two `push 0` immediates inside
     * FUN_0047c370, and this is a different call site reading a different row.
     *
     * Rewrite the argument on the stack, exactly as the startup sites rewrite
     * theirs, and ONLY for this call site. A blanket "slot 0 becomes slot 4" would
     * also override a deliberate 640x480 chosen from the F2 settings screen, which
     * is a legal choice arriving through a different caller. */
    /* THE FIX. arg3 is the windowed flag (+0x1c). The F2 video screen's
     * "Fullscreen" checkbox is the only thing that ever passes 1, and windowed is
     * not a mode this game supports in any useful sense -- measured:
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
                  " -- forced back to fullscreen%s",
                  (unsigned long)a[9],
                  g_fs_clamped == 4 ? "  [further clamps not logged]" : "");
    }
    if (g_menu_slot >= 0 && g_preset_ret && a[9] == g_preset_ret && (int)a[11] == 0) {
        a[11] = (DWORD)g_menu_slot;
        return;
    }
}

static int patch_menu_apply(void)
{
    if (!g_applyvideo_va) {
        logf_("[x] [menu] apply-video routine not located");
        return 0;
    }
    BYTE *entry = (BYTE *)(SIZE_T)g_applyvideo_va;
    /* Refuse unless the prologue is the one we measured. Relocating something
     * else would corrupt the function silently, and this runs on two builds. */
    static const BYTE PRO[] = {0x83,0xec,0x08, 0xa1};
    if (memcmp(entry, PRO, sizeof PRO) != 0) {
        logf_("[x] [menu] %08lx does not open with `sub esp,8 / mov eax,imm32`"
              " (%02x %02x %02x %02x) -- refusing",
              (unsigned long)g_applyvideo_va, entry[0], entry[1], entry[2], entry[3]);
        return 0;
    }
    BYTE *tr = (BYTE *)VirtualAlloc(NULL, 96, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tr) { logf_("[x] [menu] VirtualAlloc failed"); return 0; }
    int o = 0;
    tr[o++] = 0x60;                                                 /* pushad          */
    tr[o++] = 0x9C;                                                 /* pushfd          */
    tr[o++] = 0x54;                                                 /* push esp        */
    tr[o++] = 0xB8; { DWORD f = (DWORD)(SIZE_T)&menu_apply_hook; memcpy(tr + o, &f, 4); o += 4; }
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
    if (!poke(entry, det, 8)) { logf_("[x] [menu] VirtualProtect failed"); return 0; }
    logf_("[+] [menu] apply-video %08lx detoured -> %p"
          " (frontend preset -> slot %d, so the menu survives a return from a map)",
          (unsigned long)g_applyvideo_va, (void *)tr, g_menu_slot);
    return 1;
}

/* ------------------------------------------------------------- startup movie
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

/* ------------------------------------------ the startup ASKS for 640x480
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

    /* The PRESET-APPLY call site. It loads all five settings out of the
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
     * 640x480 in row 1 because the menu art only existed at that size.
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

/* ------------------------------------------- the windowed flag is a trap
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
 * The clamp in menu_apply_hook() stops the flag being SET. This clears one that is
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

/* The movie/menu window (an earlier, removed approach): ini keys used to widen the
 * movie-window clamp at 0x515e58 to a pillarboxed size, and a probe key logged which
 * branch FUN_00515d30 took -- the stock path (clamp+centre) or the `videowin.win`
 * branch at 0x515f86, which bypasses both. Neither was a shipped fix; the movie
 * fixes that ship are below. */

/* ------------------------------------------ let the movie blit MAGNIFY
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

/* ------------------------- the HUD panel's movie is copied 1:1, not scaled
 *
 * The little edict/build movie in the bottom-right panel is `mainwin.win` widget 8:
 * class 0x040, virtual rect 2572,1481 560x560, painted by FUN_00531990.
 *
 * The DESTINATION is not the problem. That method scales its rect per-axis exactly
 * like every other widget class:
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
 * Setting the flag makes the engine's own comparison run and its own scaler
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
 * That is the same lesson as the north-west displacement above, read the other way round: a patch too BROAD, firing where it
 * should not.
 *
 * The tidier route -- editing `mainwin.win` and shipping it loose -- does not work:
 * `.WIN` has its own loader and loose overrides are not read. */
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
    /* TWO flags, and the second one is the whole bug.  obj+0x7e is read in
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

/* -------------------------------------------- the scenario map preview
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
/* ---- scaling mode --------------------------------------------------------
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
    log_begin();
    logf_("tropico_fix (binkw32 proxy) starting -- attach tropico-fix.log to any bug report");

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

    /* BEFORE ANY MEASUREMENT. Awareness declared after a metric has been read does
     * not correct it retroactively, and choose_monitor() below is the first reader.
     * After the control-run return above: a control run applies nothing, and
     * process-wide DPI awareness is something. */
    apply_ignore_scaling();

    /* For the same reason, and one of its own -- the game resolves
     * DirectDraw at 0x514e55, which is early. Installed only when
     * [Display] DeviceSelect or [FrameCount] Enable asks for it. */
    maybe_install_dispsel();

    /* ART BEFORE THE GAME'S ENTRY POINT, WHICH IS THE ONLY MOMENT EARLY ENOUGH.
     *
     * The Steam edition indexes data\ before the proxy's patch pass can run --
     * SteamStub keeps .text encrypted, so patching defers to the first
     * GetDeviceCaps, and art generated there arrives after the index. The symptom
     * was a menu dying on "Error opening pack file item 'setuplb.i16'" for a file
     * that was present, valid and byte-identical to GOG's.
     *
     * Generating here fixes that and is measured to work: 267 assets in 1333 ms,
     * from DllMain, with no index error afterwards.
     *
     * WHICH MODE, AND WHY THE ANSWER IS NOT ALWAYS THE LAUNCH MONITOR'S.
     *
     * With a primary switch still pending, the launch monitor's own mode is the
     * only answer that does not depend on what the display currently measures --
     * the ini and the picker both validate against SM_CXSCREEN, and that reading
     * is stale here by construction. So that case generates for the launch mode
     * alone and leaves the rest to the patch pass, exactly as before.
     *
     * WITH NOTHING PENDING, THE WHOLE DECISION IS ALREADY ANSWERABLE, and until
     * this fix it was not being asked. `launch_override()` needs g_launch_w, which is
     * set only by choose_monitor()'s host-side monitor read -- and that read is
     * structurally unavailable on native Windows (game_unix_dir refuses anything
     * not on Z:) and skipped on a single-monitor Linux desktop. So this block did
     * nothing at all on Windows: on GOG that is invisible, because the unwrapped
     * build patches from inside DllMain anyway and generates on the way through,
     * but on Steam the patch pass defers to GetDeviceCaps and the art then lands
     * AFTER the game has indexed data\ -- reproducing, on the
     * first native-Windows install, the same
     *
     *     Error opening pack file item 'setuplb.i16'
     *
     * on the first launch and gone on the second. That fix was real; it was
     * reachable only through a Linux-only code path.
     *
     * decide_mode() caches, so the patch pass reuses this answer rather than
     * computing a second one that merely agrees. */
    {
        mode_t am;
        char ip[MAX_PATH];
        choose_monitor();
        snprintf(ip, sizeof ip, "%s\\tropico-fix.ini", g_dir);
        g_artgen_enabled = GetPrivateProfileIntA("Art", "Generate", 1, ip);
        if (g_mon_pending) {
            /* The ini first, for the same reason decide_mode() reads it first: it is
             * the mode the run will most likely end at. It cannot be fit-checked yet
             * -- the screen is about to change -- and if it turns out not to fit, the
             * patch pass regenerates for whatever stands in, as it always did. */
            if (ini_override(&am) || launch_override(&am)) ensure_art_for_mode(am.w, am.h);
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
     * there, and neither can the mode validation that follows it,
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
              " runs outside DllMain, where the display can actually change");

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
    return TRUE;
}

/* ==================================================== Bink
 *
 * The proxy replaces binkw32.dll. Of its 81 exports, only BinkCopyToBuffer is a
 * real wrapper -- it carries the movie-pitch correction below. The other 80,
 * including BinkOpen/BinkOpenMiles/BinkSetSoundSystem/BinkGetError, are plain
 * forwards to binkw32_orig.dll in binkw32.def. */

static HMODULE g_bink;

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

/* BinkCopyToBuffer(bink, dest, destpitch, destheight, destx, desty, flags). */
typedef int (__stdcall *BinkCopyToBuffer_t)(void *, void *, int, unsigned, unsigned, unsigned, unsigned);

int __stdcall my_BinkCopyToBuffer(void *b, void *dest, int pitch, unsigned h,
                                  unsigned x, unsigned y, unsigned flags);
int __stdcall my_BinkCopyToBuffer(void *b, void *dest, int pitch, unsigned h,
                                  unsigned x, unsigned y, unsigned flags)
{
    /* The game passes pitch = movie_width * 2 (1280 for a 640-wide movie at
     * 16bpp), but the destination surface's pitch follows the MODE, not the
     * movie -- 3840 at 1920x1080. Every source row then advances a third of a
     * destination row: three copies across, a third of the height used. That is
     * invisible at 640x480, where the two happen to be equal.
     *
     * Off by default: the correction rests on the surface pitch tracking the
     * mode width, which holds for a DirectDraw primary but is an inference we
     * cannot query through this interface. */
    if (g_bink_pitch && g_vt_xs_va) {
        int mw = (int)(*(float *)(SIZE_T)g_vt_xs_va * 3200.0f + 0.5f);
        if (mw > 0 && pitch < mw * 2) pitch = mw * 2;
    }
    HMODULE m = bink_orig();
    BinkCopyToBuffer_t f = m ? (BinkCopyToBuffer_t)(void *)
        GetProcAddress(m, "_BinkCopyToBuffer@28") : NULL;
    return f ? f(b, dest, pitch, h, x, y, flags) : 0;
}

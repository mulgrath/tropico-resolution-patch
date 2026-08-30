/* Can DirectDraw be pointed at a monitor, instead of the monitor at DirectDraw?
 *
 * THE QUESTION. Tropico's DirectDraw fullscreen always lands on the primary
 * monitor, so 1.3 has been making the player's launch monitor primary for the
 * duration of the game. On Windows that writes persistent OS state
 * (SDC_SAVE_TO_DATABASE / CDS_UPDATEREGISTRY) which we cannot reliably undo if
 * the game dies, so s113.8 made it opt-in there and the feature is now mostly
 * off. The better answer is to change the GAME rather than the COMPUTER: the
 * patch already rewrites the resolution table in memory, and DirectDraw has,
 * on paper, had a per-device story since DX7 -- DirectDrawEnumerateEx returns a
 * GUID per attached monitor, and DirectDrawCreate takes one.
 *
 * If that still works on Windows 11 it retires the primary-switching on BOTH
 * platforms, including the Linux xrandr watchdog, the state file, the
 * ExitProcess hook and the 5 s deadline. That is a lot of machinery to delete,
 * which is exactly why the claim has to be measured rather than believed.
 *
 * FOUR QUESTIONS, ONE RUN.
 *
 *   1. Does DirectDrawEnumerateEx(DDENUM_ATTACHEDSECONDARYDEVICES) still hand
 *      back per-monitor GUIDs? Secondary sources say DDERR_UNSUPPORTED on
 *      Vista+, but they are forum and Windows-CE material. Low confidence, so:
 *      test it, do not trust it.
 *   2. Does SetCooperativeLevel(EXCLUSIVE|FULLSCREEN) succeed on a non-primary
 *      device, and does SetDisplayMode work there?
 *   3. Do blits behave? The same low-confidence source warns that blits
 *      crossing the primary surface edge fail with DDERR_INVALIDRECT -- which
 *      is DirectDraw error #150, the oldest bug in this project (s17, s18,
 *      s74). This is the question most likely to kill the approach.
 *   4. Which entry point does the game use? NOT answerable here -- see below.
 *
 * WHAT THIS PROBE CANNOT ANSWER, AND WHY IT IS NOT TRYING. Question 4 is about
 * Tropico.EXE, not about the machine. Static analysis is already spent on it:
 * the binary does carry the strings -- "DDraw.dll", "DirectDrawCreate",
 * "DirectDrawCreateEx", "DirectDrawEnumerateExA", adjacent at 0x5a8b6c -- but
 * NOTHING in .text, .rdata or .data holds a pointer anywhere in that range, so
 * the call site cannot be reached from the file. It takes a GetProcAddress hook
 * in the running game, which is [DDProbe] in the proxy DLL, not this program.
 *
 * WHY A SEPARATE EXE, AND WHY EVERYTHING AT ONCE. The same reasoning as
 * primaryprobe.c: every question above needs a real two-monitor Windows 11
 * desktop, and reaching one costs the owner a reboot. So this asks all of them
 * in a single pass.
 *
 * THREE RULES IT INHERITS FROM primaryprobe.c AND TESTING.md.
 *
 *   Never believe the return value. Every mode change is checked against what
 *   EnumDisplaySettings and GetSystemMetrics report AFTERWARDS. s113.6 measured
 *   a ChangeDisplaySettingsEx that returned DISP_CHANGE_SUCCESSFUL and did
 *   nothing; a DD_OK from SetDisplayMode deserves precisely as much trust.
 *
 *   Every test needs its control (TESTING.md trap 6). Each blit run on the
 *   secondary device is run identically on the PRIMARY device in the same pass.
 *   Without that, a DDERR_INVALIDRECT on DISPLAY2 cannot be told apart from a
 *   bug in this file's blit code -- and #150 is exactly the error this project
 *   has misattributed before.
 *
 *   Some things only an eye can check. No API reports which physical panel the
 *   photons landed on. So the last phase fills each device's surface with a
 *   named colour and holds it, logging what it is about to show before it shows
 *   it. That line in the log plus the owner's answer is the measurement.
 *
 * Build:  i686-w64-mingw32-gcc -O2 -Wall -Wextra -o ddmonprobe.exe \
 *             ddmonprobe.c -luser32 -lgdi32 -ldxguid
 * Run:    wine ddmonprobe.exe --dry     smoke test: enumerate + create only
 *         wine ddmonprobe.exe           full run under Wine (also tells us
 *                                       whether this retires the xrandr path)
 *         ddmonprobe.exe                on Windows: the real answer
 *
 * ddraw.dll is loaded with LoadLibrary/GetProcAddress rather than linked,
 * because that is how Tropico.EXE obtains it and because "the export is
 * missing" and "the export refused" are different answers that a link-time
 * dependency would collapse into a failure to start.
 *
 * SAFETY. Exclusive fullscreen and mode changes are session state, not stored
 * configuration -- this probe never touches the display database, so nothing it
 * does survives a reboot the way s113.6's subject did. Even so: every mode set
 * is restored immediately, a watchdog thread puts the desktop back and exits if
 * the run overruns, and the unhandled-exception filter does the same on a
 * crash. The log is flushed after every line, so a run that dies mid-fullscreen
 * still leaves its findings on disk.
 */
#define WINVER       0x0601
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <ddraw.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static FILE *g_log;

/* --dry stops after the questions that change nothing: which exports exist,
 * what enumeration returns, whether a device GUID can be created and what it
 * says about itself. That is questions 1 and half of 2, and it is the whole
 * smoke test -- everything past it needs exclusive mode. It cannot answer
 * question 3 at all, which is the one most likely to decide this. */
static int g_dry;
static int g_hold = 4;        /* seconds per device in the visual phase */
static int g_visual = 1;
static char g_only[64];       /* restrict to one \\.\DISPLAYn */

static void say(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void say(const char *fmt, ...)
{
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    printf("%s\n", buf);
    fflush(stdout);
    if (g_log) { fprintf(g_log, "%s\n", buf); fflush(g_log); }
}

static void blank(void) { say("%s", ""); }

/* ------------------------------------------------------------ error naming
 *
 * The decimal is printed alongside the name on purpose. The game's own error
 * box says "DirectDraw Error #150", not DDERR_INVALIDRECT, and every log and
 * FINDINGS entry in this project since s17 speaks in those numbers. A probe
 * whose output cannot be grepped against the artefacts it exists to explain is
 * doing half a job. */
static const char *ddname(HRESULT hr)
{
    switch (hr) {
    case DD_OK:                        return "DD_OK";
    case DDERR_ALREADYINITIALIZED:     return "DDERR_ALREADYINITIALIZED";
    case DDERR_CANNOTATTACHSURFACE:    return "DDERR_CANNOTATTACHSURFACE";
    case DDERR_CURRENTLYNOTAVAIL:      return "DDERR_CURRENTLYNOTAVAIL";
    case DDERR_EXCEPTION:              return "DDERR_EXCEPTION";
    case DDERR_HEIGHTALIGN:            return "DDERR_HEIGHTALIGN";
    case DDERR_INCOMPATIBLEPRIMARY:    return "DDERR_INCOMPATIBLEPRIMARY";
    case DDERR_INVALIDCAPS:            return "DDERR_INVALIDCAPS";
    case DDERR_INVALIDCLIPLIST:        return "DDERR_INVALIDCLIPLIST";
    case DDERR_INVALIDMODE:            return "DDERR_INVALIDMODE";
    case DDERR_INVALIDOBJECT:          return "DDERR_INVALIDOBJECT";
    case DDERR_INVALIDPARAMS:          return "DDERR_INVALIDPARAMS";
    case DDERR_INVALIDPIXELFORMAT:     return "DDERR_INVALIDPIXELFORMAT";
    case DDERR_INVALIDRECT:            return "DDERR_INVALIDRECT";
    case DDERR_LOCKEDSURFACES:         return "DDERR_LOCKEDSURFACES";
    case DDERR_NO3D:                   return "DDERR_NO3D";
    case DDERR_NOCLIPLIST:             return "DDERR_NOCLIPLIST";
    case DDERR_NOCOOPERATIVELEVELSET:  return "DDERR_NOCOOPERATIVELEVELSET";
    case DDERR_NODIRECTDRAWSUPPORT:    return "DDERR_NODIRECTDRAWSUPPORT";
    case DDERR_NOEXCLUSIVEMODE:        return "DDERR_NOEXCLUSIVEMODE";
    case DDERR_NOFLIPHW:               return "DDERR_NOFLIPHW";
    case DDERR_NOTFOUND:               return "DDERR_NOTFOUND";
    case DDERR_NOSTRETCHHW:            return "DDERR_NOSTRETCHHW";
    case DDERR_OUTOFCAPS:              return "DDERR_OUTOFCAPS";
    case DDERR_OUTOFMEMORY:            return "DDERR_OUTOFMEMORY";
    case DDERR_OUTOFVIDEOMEMORY:       return "DDERR_OUTOFVIDEOMEMORY";
    case DDERR_OVERLAPPINGRECTS:       return "DDERR_OVERLAPPINGRECTS";
    case DDERR_PRIMARYSURFACEALREADYEXISTS: return "DDERR_PRIMARYSURFACEALREADYEXISTS";
    case DDERR_SURFACEBUSY:            return "DDERR_SURFACEBUSY";
    case DDERR_SURFACELOST:            return "DDERR_SURFACELOST";
    case DDERR_UNSUPPORTED:            return "DDERR_UNSUPPORTED";
    case DDERR_UNSUPPORTEDMODE:        return "DDERR_UNSUPPORTEDMODE";
    case DDERR_WASSTILLDRAWING:        return "DDERR_WASSTILLDRAWING";
    case DDERR_WRONGMODE:              return "DDERR_WRONGMODE";
    case E_NOINTERFACE:                return "E_NOINTERFACE";
    case E_FAIL:                       return "E_FAIL";
    /* E_INVALIDARG and E_OUTOFMEMORY are not listed: DirectDraw defines
     * DDERR_INVALIDPARAMS and DDERR_OUTOFMEMORY as the SAME values, so those two
     * names above already cover them. Worth knowing when reading a log -- a
     * "DDERR_INVALIDPARAMS" here may have come from a COM layer that meant
     * E_INVALIDARG. */
    }
    return "(unrecognised)";
}

/* "0x88760096 DDERR_INVALIDRECT (#150)". The buffers rotate so two calls can
 * appear in one say(). */
static const char *hres(HRESULT hr)
{
    static char buf[4][96];
    static int  n;
    char *b = buf[n++ & 3];
    if ((hr & 0xffff0000u) == 0x88760000u)
        snprintf(b, sizeof buf[0], "0x%08lx %s (#%lu)", (unsigned long)hr,
                 ddname(hr), (unsigned long)(hr & 0xffff));
    else
        snprintf(b, sizeof buf[0], "0x%08lx %s", (unsigned long)hr, ddname(hr));
    return b;
}

static const char *guidstr(const GUID *g)
{
    static char b[64];
    if (!g) return "NULL (the active display driver)";
    snprintf(b, sizeof b, "{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
             (unsigned long)g->Data1, g->Data2, g->Data3,
             g->Data4[0], g->Data4[1], g->Data4[2], g->Data4[3],
             g->Data4[4], g->Data4[5], g->Data4[6], g->Data4[7]);
    return b;
}

/* ------------------------------------------------------ ddraw.dll, by name */

typedef HRESULT (WINAPI *ddcreate_t)  (GUID *, LPDIRECTDRAW *, IUnknown *);
typedef HRESULT (WINAPI *ddcreateex_t)(GUID *, void **, const IID *, IUnknown *);
typedef HRESULT (WINAPI *ddenum_t)    (LPDDENUMCALLBACKA, void *);
typedef HRESULT (WINAPI *ddenumex_t)  (LPDDENUMCALLBACKEXA, void *, DWORD);

static HMODULE       g_ddraw;
static ddcreate_t    p_create;
static ddcreateex_t  p_createex;
static ddenum_t      p_enum;
static ddenumex_t    p_enumex;

static int load_ddraw(void)
{
    g_ddraw = LoadLibraryA("ddraw.dll");
    if (!g_ddraw) {
        say("  LoadLibraryA(\"ddraw.dll\") FAILED, GetLastError=%lu",
            (unsigned long)GetLastError());
        return 0;
    }
    p_create   = (ddcreate_t)  (void *)GetProcAddress(g_ddraw, "DirectDrawCreate");
    p_createex = (ddcreateex_t)(void *)GetProcAddress(g_ddraw, "DirectDrawCreateEx");
    p_enum     = (ddenum_t)    (void *)GetProcAddress(g_ddraw, "DirectDrawEnumerateA");
    p_enumex   = (ddenumex_t)  (void *)GetProcAddress(g_ddraw, "DirectDrawEnumerateExA");
    say("  ddraw.dll at %p", (void *)g_ddraw);
    say("    DirectDrawCreate        %s", p_create   ? "present" : "MISSING");
    say("    DirectDrawCreateEx      %s", p_createex ? "present" : "MISSING");
    say("    DirectDrawEnumerateA    %s", p_enum     ? "present" : "MISSING");
    say("    DirectDrawEnumerateExA  %s", p_enumex   ? "present" : "MISSING");
    return p_createex || p_create;
}

/* ------------------------------------------------------------- the layout */

typedef struct { char name[64]; int primary; DWORD w, h, bpp; LONG x, y; } mon_t;

static int monitors(mon_t *out, int cap)
{
    DISPLAY_DEVICEA dd;
    DEVMODEA dm;
    DWORD i;
    int n = 0;
    for (i = 0; n < cap; i++) {
        memset(&dd, 0, sizeof dd); dd.cb = sizeof dd;
        if (!EnumDisplayDevicesA(NULL, i, &dd, 0)) break;
        if (!(dd.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP)) continue;
        memset(&dm, 0, sizeof dm); dm.dmSize = sizeof dm;
        if (!EnumDisplaySettingsA(dd.DeviceName, ENUM_CURRENT_SETTINGS, &dm)) continue;
        memset(&out[n], 0, sizeof out[n]);
        snprintf(out[n].name, sizeof out[n].name, "%s", dd.DeviceName);
        out[n].primary = (dd.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE) != 0;
        out[n].w = dm.dmPelsWidth;  out[n].h = dm.dmPelsHeight;
        out[n].bpp = dm.dmBitsPerPel;
        out[n].x = dm.dmPosition.x; out[n].y = dm.dmPosition.y;
        n++;
    }
    return n;
}

/* THE HONEST TEST, s113.6's rule applied to modes instead of to the primary:
 * after any SetDisplayMode, ask Windows what every monitor is doing. A call
 * that returns DD_OK and moves the WRONG screen is the failure this whole
 * investigation is trying to catch, and it is invisible from the HRESULT. */
static void show_layout(const char *when)
{
    mon_t m[16];
    int n = monitors(m, 16), i;
    say("    layout %s:", when);
    for (i = 0; i < n; i++)
        say("      %-14s %lux%lu %lubpp at (%ld,%ld)%s", m[i].name,
            (unsigned long)m[i].w, (unsigned long)m[i].h, (unsigned long)m[i].bpp,
            m[i].x, m[i].y, m[i].primary ? "   PRIMARY" : "");
    say("      SM_CXSCREEN=%d SM_CYSCREEN=%d   virtual %d,%d %dx%d",
        GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN),
        GetSystemMetrics(SM_XVIRTUALSCREEN), GetSystemMetrics(SM_YVIRTUALSCREEN),
        GetSystemMetrics(SM_CXVIRTUALSCREEN), GetSystemMetrics(SM_CYVIRTUALSCREEN));
}

/* --------------------------------------------------------- enumerated devices */

/* An ARM, not a device -- the distinction matters once the GUIDs turn out not
 * to be per-monitor. Each arm pairs a GUID (or NULL) with the monitor the
 * window is placed on, because those are two independent levers and the whole
 * point is to find out which one DirectDraw actually obeys. */
typedef struct {
    int      have_guid;
    GUID     guid;
    char     desc[128];
    char     drv[64];         /* what DirectDraw calls it: "\\.\DISPLAY2" or "display" */
    char     guid_from[64];   /* the \\.\DISPLAYn this GUID was enumerated for */
    char     gdi[64];         /* the \\.\DISPLAYn the WINDOW goes on, and the one we expect to move */
    char     label[144];      /* what this arm is testing, in words */
    HMONITOR hmon;
    RECT     rc;
    int      primary;
    DWORD    native_w, native_h;
} dev_t;

static dev_t g_dev[16];
static int   g_ndev;

/* The GUID pointer handed to the callback is only valid for the duration of the
 * call, so it is copied. Losing that is the classic way to end up creating
 * whatever happens to be on the stack. */
static void add_dev(GUID *guid, const char *desc, const char *drv, HMONITOR hm)
{
    dev_t *d;
    int i;
    if (g_ndev >= (int)(sizeof g_dev / sizeof g_dev[0])) return;
    for (i = 0; i < g_ndev; i++)
        if (!strcmp(g_dev[i].drv, drv ? drv : "")) return;   /* already have it */
    d = &g_dev[g_ndev++];
    memset(d, 0, sizeof *d);
    if (guid) { d->guid = *guid; d->have_guid = 1; }
    snprintf(d->desc, sizeof d->desc, "%s", desc ? desc : "");
    snprintf(d->drv,  sizeof d->drv,  "%s", drv  ? drv  : "");
    d->hmon = hm;

    /* Tie the DirectDraw device back to a \\.\DISPLAYn. That mapping is not a
     * convenience -- it is the thing the feature would need in order to turn
     * "the player launched from this monitor" into "create DirectDraw on that
     * GUID", so recording it here IS half the design. */
    if (hm) {
        MONITORINFOEXA mi;
        memset(&mi, 0, sizeof mi); mi.cbSize = sizeof mi;
        if (GetMonitorInfoA(hm, (MONITORINFO *)&mi)) {
            snprintf(d->gdi, sizeof d->gdi, "%s", mi.szDevice);
            d->rc = mi.rcMonitor;
            d->primary = (mi.dwFlags & MONITORINFOF_PRIMARY) != 0;
        }
    }
    if (!d->gdi[0] && drv && !strncmp(drv, "\\\\.\\DISPLAY", 11))
        snprintf(d->gdi, sizeof d->gdi, "%s", drv);
    if (!d->gdi[0]) {                                   /* the NULL/primary entry */
        mon_t m[16];
        int n = monitors(m, 16), k;
        for (k = 0; k < n; k++) if (m[k].primary) {
            snprintf(d->gdi, sizeof d->gdi, "%s", m[k].name);
            d->primary = 1;
            SetRect(&d->rc, m[k].x, m[k].y, m[k].x + (LONG)m[k].w, m[k].y + (LONG)m[k].h);
        }
    }
    {
        DEVMODEA dm;
        memset(&dm, 0, sizeof dm); dm.dmSize = sizeof dm;
        if (d->gdi[0] && EnumDisplaySettingsA(d->gdi, ENUM_CURRENT_SETTINGS, &dm)) {
            d->native_w = dm.dmPelsWidth;
            d->native_h = dm.dmPelsHeight;
            if (IsRectEmpty(&d->rc))
                SetRect(&d->rc, dm.dmPosition.x, dm.dmPosition.y,
                        dm.dmPosition.x + (LONG)dm.dmPelsWidth,
                        dm.dmPosition.y + (LONG)dm.dmPelsHeight);
        }
    }
    snprintf(d->guid_from, sizeof d->guid_from, "%s", d->have_guid ? d->gdi : "");
    snprintf(d->label, sizeof d->label, "%s device, window on %s",
             d->have_guid ? d->gdi : "NULL", d->gdi);
}

/* The extra arms, added once enumeration has told us what the GUIDs are worth.
 *
 * The pair below is the experiment that actually decides the design, and it
 * only becomes necessary if a GUID does not name a monitor:
 *
 *   NULL device + window on the SECONDARY   -- is placing the window enough?
 *                                              If so the feature is trivial:
 *                                              move the game's window and do
 *                                              not intercept DirectDraw at all.
 *   SECONDARY GUID + window on the PRIMARY  -- the discriminator. Whichever
 *                                              panel lights up in phase 5 names
 *                                              the lever DirectDraw obeys.
 *
 * Run separately they each have two explanations; run together they have one. */
static void add_arm(const dev_t *guid_src, const dev_t *win_tgt, const char *label)
{
    dev_t *d;
    if (g_ndev >= (int)(sizeof g_dev / sizeof g_dev[0])) return;
    d = &g_dev[g_ndev++];
    memset(d, 0, sizeof *d);
    if (guid_src && guid_src->have_guid) {
        d->guid = guid_src->guid;
        d->have_guid = 1;
        snprintf(d->guid_from, sizeof d->guid_from, "%s", guid_src->gdi);
        snprintf(d->desc, sizeof d->desc, "%s", guid_src->desc);
        snprintf(d->drv,  sizeof d->drv,  "%s", guid_src->drv);
    }
    snprintf(d->gdi, sizeof d->gdi, "%s", win_tgt->gdi);
    d->rc       = win_tgt->rc;
    d->hmon     = win_tgt->hmon;
    d->primary  = win_tgt->primary;
    d->native_w = win_tgt->native_w;
    d->native_h = win_tgt->native_h;
    snprintf(d->label, sizeof d->label, "%s", label);
}

static WINBOOL CALLBACK enum_cb(GUID *guid, LPSTR desc, LPSTR drv, void *ctx)
{
    (void)ctx;
    say("      [legacy] guid=%s", guidstr(guid));
    say("               desc=\"%s\"  driver=\"%s\"", desc ? desc : "", drv ? drv : "");
    add_dev(guid, desc, drv, NULL);
    return TRUE;
}

static WINBOOL CALLBACK enumex_cb(GUID *guid, LPSTR desc, LPSTR drv, void *ctx, HMONITOR hm)
{
    MONITORINFOEXA mi;
    const char *tag = (const char *)ctx;
    memset(&mi, 0, sizeof mi); mi.cbSize = sizeof mi;
    say("      [%s] guid=%s", tag, guidstr(guid));
    say("             desc=\"%s\"  driver=\"%s\"  hmonitor=%p",
        desc ? desc : "", drv ? drv : "", (void *)hm);
    if (hm && GetMonitorInfoA(hm, (MONITORINFO *)&mi))
        say("             -> %s at (%ld,%ld)-(%ld,%ld)%s", mi.szDevice,
            mi.rcMonitor.left, mi.rcMonitor.top, mi.rcMonitor.right, mi.rcMonitor.bottom,
            (mi.dwFlags & MONITORINFOF_PRIMARY) ? "  PRIMARY" : "");
    else if (hm)
        say("             -> GetMonitorInfo failed");
    else
        say("             -> no HMONITOR (this is the primary display driver entry)");
    add_dev(guid, desc, drv, hm);
    return TRUE;
}

/* Question 1, in full. Every flag combination, because "returns nothing" and
 * "returns only the primary" and "refuses" are three different answers with
 * three different consequences, and DDENUM_ATTACHEDSECONDARYDEVICES alone
 * cannot distinguish them. */
static void phase_enumerate(void)
{
    static const struct { DWORD f; const char *tag; } FLAGS[] = {
        { 0,                                                        "ex flags=0" },
        { DDENUM_ATTACHEDSECONDARYDEVICES,                          "ex ATTACHEDSECONDARY" },
        { DDENUM_ATTACHEDSECONDARYDEVICES | DDENUM_DETACHEDSECONDARYDEVICES,
                                                                    "ex ATTACHED|DETACHED" },
        { DDENUM_ATTACHEDSECONDARYDEVICES | DDENUM_NONDISPLAYDEVICES,
                                                                    "ex ATTACHED|NONDISPLAY" },
    };
    size_t i;
    HRESULT hr;

    say("  --- DirectDrawEnumerateA (the DX1 call, no monitor information) ---");
    if (!p_enum) say("      export missing");
    else {
        hr = p_enum(enum_cb, NULL);
        say("      returned %s", hres(hr));
    }

    blank();
    say("  --- DirectDrawEnumerateExA (question 1) ---");
    if (!p_enumex) {
        say("      export MISSING. Question 1 is answered no, by absence.");
        return;
    }
    for (i = 0; i < sizeof FLAGS / sizeof FLAGS[0]; i++) {
        int before = g_ndev;
        say("    flags 0x%08lx  (%s)", (unsigned long)FLAGS[i].f, FLAGS[i].tag);
        hr = p_enumex(enumex_cb, (void *)FLAGS[i].tag, FLAGS[i].f);
        say("      returned %s, %d new device(s)", hres(hr), g_ndev - before);
        if (hr == DDERR_UNSUPPORTED)
            say("      ^^ DDERR_UNSUPPORTED -- this is the outcome the low-confidence"
                " secondary sources predicted");
    }
}

/* ---------------------------------------------------------------- windowing */

static ATOM g_cls;

static LRESULT CALLBACK wndproc(HWND w, UINT m, WPARAM wp, LPARAM lp)
{
    return DefWindowProcA(w, m, wp, lp);
}

static HWND make_window(const RECT *rc, const char *title)
{
    HWND w;
    if (!g_cls) {
        WNDCLASSA wc;
        memset(&wc, 0, sizeof wc);
        wc.lpfnWndProc   = wndproc;
        wc.hInstance     = GetModuleHandleA(NULL);
        wc.hCursor       = LoadCursorA(NULL, (LPCSTR)IDC_ARROW);
        wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
        wc.lpszClassName = "ddmonprobe";
        g_cls = RegisterClassA(&wc);
    }
    /* On the target monitor, at its full size. MSDN is explicit that the window
     * passed to SetCooperativeLevel is what associates the exclusive mode with a
     * device, so putting it on the wrong screen would test the wrong thing. */
    w = CreateWindowExA(WS_EX_TOPMOST, "ddmonprobe", title, WS_POPUP,
                        rc->left, rc->top, rc->right - rc->left, rc->bottom - rc->top,
                        NULL, NULL, GetModuleHandleA(NULL), NULL);
    if (w) {
        ShowWindow(w, SW_SHOW);
        SetForegroundWindow(w);
        SetFocus(w);
    }
    return w;
}

static void pump(int ms)
{
    DWORD end = GetTickCount() + (DWORD)ms;
    MSG msg;
    for (;;) {
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
        if ((LONG)(GetTickCount() - end) >= 0) break;
        Sleep(10);
    }
}

/* ------------------------------------------------------------ pixel packing
 *
 * The mode under test is 16bpp, which is what Tropico asks for, and 16bpp is
 * 565 on every card anyone still owns -- but the masks are read from the surface
 * rather than assumed, because a probe that paints the wrong colour and then
 * asks a human "which colour did you see?" has poisoned its own measurement. */
static DWORD pack(const DDPIXELFORMAT *pf, int r, int g, int b)
{
    DWORD out = 0;
    int i;
    const DWORD masks[3] = { pf->dwRBitMask, pf->dwGBitMask, pf->dwBBitMask };
    const int   vals[3]  = { r, g, b };
    for (i = 0; i < 3; i++) {
        DWORD m = masks[i];
        int shift = 0, bits = 0;
        if (!m) continue;
        while (!(m & 1)) { m >>= 1; shift++; }
        while (m & 1)    { m >>= 1; bits++; }
        out |= (DWORD)((vals[i] >> (8 - bits)) << shift);
    }
    return out;
}

/* ---------------------------------------------------------- per-device work */

typedef struct {
    dev_t   *d;
    IDirectDraw7 *dd;
    HWND     win;
    int      exclusive;
    int      mode_set;
    DWORD    sw, sh;              /* what the primary surface says it is */
    DDPIXELFORMAT pf;
    int      blits_ok, blits_bad, rect_errs;
} ctx_t;

static ctx_t g_ctx[16];
static int   g_nctx;

/* Question 2's verification. Not "did SetDisplayMode return DD_OK" but "which
 * monitor moved, if any". */
static void verify_mode(ctx_t *c, DWORD want_w, DWORD want_h, DWORD want_bpp)
{
    mon_t m[16];
    int n = monitors(m, 16), i, moved = 0;

    /* Every monitor, every time, each tagged with the role it plays in THIS arm.
     * Naming one expected winner would be a guess dressed as a check: on the
     * cross arm -- secondary GUID, primary window -- either screen moving is a
     * real result, and which one moved is the whole answer. */
    for (i = 0; i < n; i++) {
        const char *role = "";
        int is_win  = !_stricmp(m[i].name, c->d->gdi);
        int is_guid = c->d->guid_from[0] && !_stricmp(m[i].name, c->d->guid_from);
        if (is_win && is_guid) role = "  <- the window AND the GUID";
        else if (is_win)       role = "  <- the window is here";
        else if (is_guid)      role = "  <- the GUID names this one";
        if (m[i].w == want_w && m[i].h == want_h) {
            moved++;
            say("      MOVED   %-14s now %lux%lu %lubpp%s%s", m[i].name,
                (unsigned long)m[i].w, (unsigned long)m[i].h, (unsigned long)m[i].bpp,
                m[i].bpp == want_bpp ? "" : "  (bpp differs from the request)", role);
        } else {
            say("      unmoved %-14s     %lux%lu %lubpp%s", m[i].name,
                (unsigned long)m[i].w, (unsigned long)m[i].h, (unsigned long)m[i].bpp, role);
        }
    }
    if (!moved)
        say("      NOTHING MOVED. SetDisplayMode returned DD_OK and changed no screen"
            " -- the s113.6 lie, from a different API.");

    say("      SM_CXSCREEN=%d (the OS primary -- it must NOT have moved)",
        GetSystemMetrics(SM_CXSCREEN));
    {
        HMONITOR hm = MonitorFromWindow(c->win, MONITOR_DEFAULTTONULL);
        MONITORINFOEXA mi;
        memset(&mi, 0, sizeof mi); mi.cbSize = sizeof mi;
        if (hm && GetMonitorInfoA(hm, (MONITORINFO *)&mi))
            say("      our window is on %s", mi.szDevice);
        else
            say("      our window is on no monitor MonitorFromWindow will name");
    }
    {
        DDSURFACEDESC2 sd;
        HRESULT hr;
        memset(&sd, 0, sizeof sd); sd.dwSize = sizeof sd;
        hr = IDirectDraw7_GetDisplayMode(c->dd, &sd);
        if (hr == DD_OK)
            say("      GetDisplayMode says %lux%lu %lubpp pitch %ld",
                (unsigned long)sd.dwWidth, (unsigned long)sd.dwHeight,
                (unsigned long)sd.ddpfPixelFormat.dwRGBBitCount, (long)sd.lPitch);
        else
            say("      GetDisplayMode -> %s", hres(hr));
    }
}

/* Phase 2: create the object and ask it what it is. */
static int phase_create(ctx_t *c)
{
    dev_t *d = c->d;
    GUID  *g = d->have_guid ? &d->guid : NULL;
    HRESULT hr;

    /* DirectDrawCreate first, and separately, because question 4 may yet say the
     * game uses the DX1 entry point. If the GUID form only works through
     * DirectDrawCreateEx then the hook has to upgrade the interface as well as
     * substitute the device, which is a materially bigger change. */
    if (p_create) {
        LPDIRECTDRAW dd1 = NULL;
        hr = p_create(g, &dd1, NULL);
        say("      DirectDrawCreate(%s) -> %s",
            d->have_guid ? d->guid_from : "NULL", hres(hr));
        if (hr == DD_OK && dd1) {
            void *dd7 = NULL;
            HRESULT q = IDirectDraw_QueryInterface(dd1, &IID_IDirectDraw7, &dd7);
            say("        QueryInterface(IID_IDirectDraw7) -> %s", hres(q));
            if (dd7) IDirectDraw7_Release((IDirectDraw7 *)dd7);
            IDirectDraw_Release(dd1);
        }
    }

    if (!p_createex) { say("      DirectDrawCreateEx missing -- cannot continue"); return 0; }
    hr = p_createex(g, (void **)&c->dd, &IID_IDirectDraw7, NULL);
    say("      DirectDrawCreateEx(%s, IID_IDirectDraw7) -> %s",
        d->have_guid ? d->guid_from : "NULL", hres(hr));
    if (hr != DD_OK || !c->dd) { c->dd = NULL; return 0; }

    {
        DDDEVICEIDENTIFIER2 id;
        memset(&id, 0, sizeof id);
        hr = IDirectDraw7_GetDeviceIdentifier(c->dd, &id, 0);
        if (hr == DD_OK) {
            say("        driver \"%s\"  description \"%s\"", id.szDriver, id.szDescription);
            say("        device guid %s", guidstr(&id.guidDeviceIdentifier));
        } else {
            say("        GetDeviceIdentifier -> %s", hres(hr));
        }
    }
    {
        /* s16: the hardware-3D gate is a SIGNED compare on this number, so it is
         * printed signed as well. A secondary device that reports a different
         * figure would interact with a patch this project already ships. */
        DDSCAPS2 caps;
        DWORD tot = 0, fre = 0;
        memset(&caps, 0, sizeof caps);
        caps.dwCaps = DDSCAPS_VIDEOMEMORY;
        hr = IDirectDraw7_GetAvailableVidMem(c->dd, &caps, &tot, &fre);
        if (hr == DD_OK)
            say("        GetAvailableVidMem: total %lu (%ld signed), free %lu (%ld signed)",
                (unsigned long)tot, (long)tot, (unsigned long)fre, (long)fre);
        else
            say("        GetAvailableVidMem -> %s", hres(hr));
    }
    {
        DDSURFACEDESC2 sd;
        memset(&sd, 0, sizeof sd); sd.dwSize = sizeof sd;
        hr = IDirectDraw7_GetDisplayMode(c->dd, &sd);
        if (hr == DD_OK)
            say("        current mode on this device: %lux%lu %lubpp",
                (unsigned long)sd.dwWidth, (unsigned long)sd.dwHeight,
                (unsigned long)sd.ddpfPixelFormat.dwRGBBitCount);
        else
            say("        GetDisplayMode -> %s", hres(hr));
    }
    return 1;
}

/* Phase 3: exclusive fullscreen and the mode ladder. */
static void phase_modes(ctx_t *c)
{
    dev_t *d = c->d;
    HRESULT hr;
    int i;
    struct { DWORD w, h, bpp; const char *why; } TRY[6];
    int ntry = 0;

    c->win = make_window(&d->rc, "ddmonprobe");
    say("      window at (%ld,%ld) %ldx%ld -> %p", d->rc.left, d->rc.top,
        d->rc.right - d->rc.left, d->rc.bottom - d->rc.top, (void *)c->win);
    if (!c->win) { say("      CreateWindowEx failed, GetLastError=%lu",
                       (unsigned long)GetLastError()); return; }
    pump(50);

    hr = IDirectDraw7_SetCooperativeLevel(c->dd, c->win, DDSCL_EXCLUSIVE | DDSCL_FULLSCREEN);
    say("      SetCooperativeLevel(EXCLUSIVE|FULLSCREEN) -> %s", hres(hr));
    if (hr != DD_OK) {
        /* Worth one more data point before giving up on the device: the game
         * also passes ALLOWREBOOT (s6), and a driver that rejects the pair may
         * accept the triple. */
        hr = IDirectDraw7_SetCooperativeLevel(c->dd, c->win,
                 DDSCL_EXCLUSIVE | DDSCL_FULLSCREEN | DDSCL_ALLOWREBOOT);
        say("      SetCooperativeLevel(+ALLOWREBOOT, as the game passes) -> %s", hres(hr));
    }
    if (hr != DD_OK) return;
    c->exclusive = 1;

    /* The ladder the game actually climbs (TESTING.md trap 4): map load starts
     * at 640x480 and steps up. 640x480 is therefore the mode that MUST work, not
     * the interesting one. */
    TRY[ntry].w = 640;  TRY[ntry].h = 480;  TRY[ntry].bpp = 16;
    TRY[ntry++].why = "the ladder's first rung -- map load starts here";
    TRY[ntry].w = 1024; TRY[ntry].h = 768;  TRY[ntry].bpp = 16;
    TRY[ntry++].why = "the ladder's middle rung";
    if (d->native_w && d->native_h) {
        TRY[ntry].w = d->native_w; TRY[ntry].h = d->native_h; TRY[ntry].bpp = 16;
        TRY[ntry++].why = "this device's own mode, 16bpp -- what the patch would ask for";
        TRY[ntry].w = d->native_w; TRY[ntry].h = d->native_h; TRY[ntry].bpp = 32;
        TRY[ntry++].why = "the same at 32bpp, to separate 'mode refused' from '16bpp refused'";
    }

    for (i = 0; i < ntry; i++) {
        say("    SetDisplayMode(%lu,%lu,%lu)  -- %s",
            (unsigned long)TRY[i].w, (unsigned long)TRY[i].h,
            (unsigned long)TRY[i].bpp, TRY[i].why);
        hr = IDirectDraw7_SetDisplayMode(c->dd, TRY[i].w, TRY[i].h, TRY[i].bpp, 0, 0);
        say("      -> %s", hres(hr));
        if (hr == DD_OK) {
            pump(300);
            verify_mode(c, TRY[i].w, TRY[i].h, TRY[i].bpp);
            c->mode_set = 1;
            /* Leave the LAST successful mode in place only if it is the device's
             * own -- the blit phase wants to measure the mode the patch would
             * really use, not 640x480. */
            if (!(d->native_w && TRY[i].w == d->native_w && TRY[i].bpp == 16))
                IDirectDraw7_RestoreDisplayMode(c->dd);
        }
    }
    show_layout("after the mode ladder");
}

/* ----------------------------------------------------------- question three
 *
 * The premise under test is that a surface on a non-primary device carries
 * coordinates that are still relative to something else, so a rect valid in the
 * device's own 0..W space lands outside and comes back #150. If that is true it
 * kills the approach, because every frame Tropico draws is a blit.
 *
 * So the matrix deliberately walks OUT to the edges, and includes two cases
 * that MUST fail -- one past the right edge, one at a negative origin. If those
 * two come back DD_OK the surface is not bounds-checking at all and every other
 * result in this phase is worthless. They are the probe checking itself.
 */
typedef struct {
    const char *what;
    int   fast;          /* BltFast rather than Blt */
    int   whole;         /* dest rect NULL */
    int   dx, dy, dw, dh;/* offsets from the surface's own origin/extent */
    int   must_fail;
} blit_case;

static void phase_blits(ctx_t *c)
{
    IDirectDrawSurface7 *prim = NULL, *back = NULL, *off = NULL, *target;
    DDSURFACEDESC2 sd;
    HRESULT hr;
    RECT src;
    int i, W, H;
    const int OS = 256;                       /* offscreen surface edge */
    blit_case CASES[12];
    int ncase = 0;

    memset(&sd, 0, sizeof sd); sd.dwSize = sizeof sd;
    sd.dwFlags = DDSD_CAPS | DDSD_BACKBUFFERCOUNT;
    sd.ddsCaps.dwCaps = DDSCAPS_PRIMARYSURFACE | DDSCAPS_FLIP | DDSCAPS_COMPLEX;
    sd.dwBackBufferCount = 1;
    hr = IDirectDraw7_CreateSurface(c->dd, &sd, &prim, NULL);
    say("      CreateSurface(PRIMARY|FLIP|COMPLEX, 1 back buffer) -> %s", hres(hr));
    if (hr != DD_OK) {
        /* Fall back to a plain primary. The game uses a flipping chain, but
         * "no flip chain here" and "no surfaces at all here" are different
         * answers and only one of them is fatal. */
        memset(&sd, 0, sizeof sd); sd.dwSize = sizeof sd;
        sd.dwFlags = DDSD_CAPS;
        sd.ddsCaps.dwCaps = DDSCAPS_PRIMARYSURFACE;
        hr = IDirectDraw7_CreateSurface(c->dd, &sd, &prim, NULL);
        say("      CreateSurface(PRIMARY, plain) -> %s", hres(hr));
        if (hr != DD_OK) return;
    }

    memset(&sd, 0, sizeof sd); sd.dwSize = sizeof sd;
    hr = IDirectDrawSurface7_GetSurfaceDesc(prim, &sd);
    if (hr != DD_OK) { say("      GetSurfaceDesc -> %s", hres(hr)); goto out; }
    c->sw = sd.dwWidth; c->sh = sd.dwHeight; c->pf = sd.ddpfPixelFormat;
    W = (int)c->sw; H = (int)c->sh;

    /* THE SINGLE MOST DIAGNOSTIC LINE IN THE PHASE. If a surface created on
     * DISPLAY2 comes back the size of DISPLAY1, the device selection is a
     * mirage and questions 3 onward are moot. */
    say("      primary surface is %dx%d %lubpp   (this device's own mode is %lux%lu)",
        W, H, (unsigned long)sd.ddpfPixelFormat.dwRGBBitCount,
        (unsigned long)c->d->native_w, (unsigned long)c->d->native_h);
    if (c->d->native_w && (DWORD)W != c->d->native_w)
        say("      !!! THE SURFACE DOES NOT MATCH THE DEVICE. DirectDraw handed back a"
            " surface sized for a different screen.");

    {
        DDSCAPS2 bc;
        memset(&bc, 0, sizeof bc);
        bc.dwCaps = DDSCAPS_BACKBUFFER;
        hr = IDirectDrawSurface7_GetAttachedSurface(prim, &bc, &back);
        say("      GetAttachedSurface(BACKBUFFER) -> %s", hres(hr));
    }
    target = back ? back : prim;
    say("      blitting to the %s", back ? "back buffer" : "primary surface directly");

    memset(&sd, 0, sizeof sd); sd.dwSize = sizeof sd;
    sd.dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT;
    sd.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN | DDSCAPS_SYSTEMMEMORY;
    sd.dwWidth = OS; sd.dwHeight = OS;
    hr = IDirectDraw7_CreateSurface(c->dd, &sd, &off, NULL);
    say("      CreateSurface(OFFSCREENPLAIN %dx%d, system memory) -> %s", OS, OS, hres(hr));
    if (hr != DD_OK) goto out;

    /* Fill it, and record the pitch while we are here: s10 established that
     * width must be a multiple of 4 for pitch alignment, and a non-primary
     * device is exactly where a different stride would show up. */
    memset(&sd, 0, sizeof sd); sd.dwSize = sizeof sd;
    hr = IDirectDrawSurface7_Lock(off, NULL, &sd, DDLOCK_WAIT | DDLOCK_WRITEONLY, NULL);
    say("      Lock(offscreen) -> %s", hres(hr));
    if (hr == DD_OK) {
        DWORD col = pack(&c->pf, 255, 64, 0);
        int y, x;
        say("        lPitch %ld for %lu pixels of %lu bpp (%lu bytes of payload)",
            (long)sd.lPitch, (unsigned long)sd.dwWidth,
            (unsigned long)c->pf.dwRGBBitCount,
            (unsigned long)(sd.dwWidth * c->pf.dwRGBBitCount / 8));
        for (y = 0; y < OS; y++) {
            BYTE *row = (BYTE *)sd.lpSurface + (LONG)y * sd.lPitch;
            for (x = 0; x < OS; x++) {
                if (c->pf.dwRGBBitCount == 16)      ((WORD  *)row)[x] = (WORD)col;
                else if (c->pf.dwRGBBitCount == 32) ((DWORD *)row)[x] = col;
            }
        }
        IDirectDrawSurface7_Unlock(off, NULL);
    }

    SetRect(&src, 0, 0, OS, OS);

#define ADD(w_, fast_, whole_, a, b, cc, dd_, mf) \
    do { CASES[ncase].what = (w_); CASES[ncase].fast = (fast_); \
         CASES[ncase].whole = (whole_); CASES[ncase].dx = (a); CASES[ncase].dy = (b); \
         CASES[ncase].dw = (cc); CASES[ncase].dh = (dd_); \
         CASES[ncase].must_fail = (mf); ncase++; } while (0)

    ADD("whole surface, dest rect NULL",            0, 1, 0, 0, 0, 0, 0);
    ADD("explicit full rect 0,0,W,H (stretched)",   0, 0, 0, 0, W, H, 0);
    ADD("top-left 256x256",                         0, 0, 0, 0, OS, OS, 0);
    ADD("bottom-right corner, flush to W,H",        0, 0, W - OS, H - OS, W, H, 0);
    ADD("centre out to the right/bottom edge",      0, 0, W / 2, H / 2, W, H, 0);
    ADD("CONTROL: one pixel past the right edge",   0, 0, W - OS + 1, H - OS + 1,
                                                       W + 1, H + 1, 1);
    ADD("CONTROL: negative origin",                 0, 0, -8, -8, OS - 8, OS - 8, 1);
    ADD("BltFast at 0,0",                           1, 0, 0, 0, 0, 0, 0);
    ADD("BltFast flush into the bottom-right corner", 1, 0, W - OS, H - OS, 0, 0, 0);
    ADD("CONTROL: BltFast straddling the right edge", 1, 0, W - OS / 2, H - OS / 2, 0, 0, 1);
#undef ADD

    for (i = 0; i < ncase; i++) {
        blit_case *b = &CASES[i];
        RECT dst;
        SetRect(&dst, b->dx, b->dy, b->dw, b->dh);
        if (b->fast)
            hr = IDirectDrawSurface7_BltFast(target, b->dx, b->dy, off, &src, DDBLTFAST_WAIT);
        else
            hr = IDirectDrawSurface7_Blt(target, b->whole ? NULL : &dst, off, &src,
                                         DDBLT_WAIT, NULL);
        {
            const char *verdict;
            if (b->must_fail) verdict = (hr == DD_OK) ? "  <-- SHOULD HAVE FAILED; this"
                                                        " surface is not bounds-checking"
                                                      : "  (expected failure, as designed)";
            else if (hr == DD_OK) verdict = "";
            else if (hr == DDERR_INVALIDRECT) verdict = "  <-- #150. THIS IS THE ANSWER TO"
                                                        " QUESTION 3.";
            else verdict = "  <-- unexpected";
            if (b->fast)
                say("      BltFast %-42s -> %s%s", b->what, hres(hr), verdict);
            else if (b->whole)
                say("      Blt     %-42s -> %s%s", b->what, hres(hr), verdict);
            else
                say("      Blt     %-42s dst(%d,%d,%d,%d) -> %s%s", b->what,
                    b->dx, b->dy, b->dw, b->dh, hres(hr), verdict);
        }
        if (hr == DD_OK && !b->must_fail) c->blits_ok++;
        if (hr != DD_OK && !b->must_fail) {
            c->blits_bad++;
            if (hr == DDERR_INVALIDRECT) c->rect_errs++;
        }
    }

    if (back) {
        hr = IDirectDrawSurface7_Flip(prim, NULL, DDFLIP_WAIT);
        say("      Flip -> %s", hres(hr));
    }

    /* Lock the target too: the game renders in software into a locked surface,
     * so a device that blits but will not lock is still no use. */
    memset(&sd, 0, sizeof sd); sd.dwSize = sizeof sd;
    hr = IDirectDrawSurface7_Lock(target, NULL, &sd, DDLOCK_WAIT, NULL);
    say("      Lock(%s) -> %s", back ? "back buffer" : "primary", hres(hr));
    if (hr == DD_OK) {
        say("        lpSurface %p  lPitch %ld  %lux%lu",
            sd.lpSurface, (long)sd.lPitch,
            (unsigned long)sd.dwWidth, (unsigned long)sd.dwHeight);
        IDirectDrawSurface7_Unlock(target, NULL);
    }

out:
    if (off)  IDirectDrawSurface7_Release(off);
    if (back) IDirectDrawSurface7_Release(back);
    if (prim) IDirectDrawSurface7_Release(prim);
}

/* --------------------------------------------------------- the visual phase
 *
 * The only question no API answers: did the pixels land on the panel we meant?
 * A colour per device, named in the log BEFORE it is shown, so the owner reads
 * the log afterwards and matches it against what they saw. */
static void phase_visual(ctx_t *c, int idx)
{
    static const struct { const char *name; int r, g, b; } COLOURS[] = {
        { "RED",     255,  32,  32 },
        { "GREEN",    32, 255,  32 },
        { "BLUE",     64,  64, 255 },
        { "YELLOW",  255, 255,  32 },
    };
    IDirectDrawSurface7 *prim = NULL;
    DDSURFACEDESC2 sd;
    DDBLTFX fx;
    HRESULT hr;
    int ci = idx % (int)(sizeof COLOURS / sizeof COLOURS[0]);

    memset(&sd, 0, sizeof sd); sd.dwSize = sizeof sd;
    sd.dwFlags = DDSD_CAPS;
    sd.ddsCaps.dwCaps = DDSCAPS_PRIMARYSURFACE;
    hr = IDirectDraw7_CreateSurface(c->dd, &sd, &prim, NULL);
    if (hr != DD_OK) { say("      no primary surface for the visual test: %s", hres(hr)); return; }

    memset(&sd, 0, sizeof sd); sd.dwSize = sizeof sd;
    if (IDirectDrawSurface7_GetSurfaceDesc(prim, &sd) == DD_OK) c->pf = sd.ddpfPixelFormat;

    memset(&fx, 0, sizeof fx); fx.dwSize = sizeof fx;
    fx.dwFillColor = pack(&c->pf, COLOURS[ci].r, COLOURS[ci].g, COLOURS[ci].b);
    hr = IDirectDrawSurface7_Blt(prim, NULL, NULL, NULL, DDBLT_COLORFILL | DDBLT_WAIT, &fx);

    say("    >>> SHOWING %s FOR %d SECONDS -- note which PHYSICAL monitor lights up.",
        COLOURS[ci].name, g_hold);
    say("        arm: %s", c->d->label);
    say("        colorfill -> %s", hres(hr));

    /* The device name, painted on the surface, so a photograph of the screen is
     * self-labelling and the owner does not have to remember the order. */
    {
        HDC hdc = NULL;
        if (IDirectDrawSurface7_GetDC(prim, &hdc) == DD_OK && hdc) {
            char txt[160];
            RECT r;
            HFONT f = CreateFontA(96, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET,
                                  OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  DEFAULT_QUALITY, FF_DONTCARE, "Arial");
            HGDIOBJ old = SelectObject(hdc, f);
            snprintf(txt, sizeof txt, "%s\n%s\n%s", COLOURS[ci].name, c->d->gdi,
                     c->d->drv[0] ? c->d->drv : "(primary display driver)");
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(0, 0, 0));
            SetRect(&r, 0, 0, (int)c->d->native_w, (int)c->d->native_h);
            DrawTextA(hdc, txt, -1, &r, DT_CENTER | DT_VCENTER | DT_NOCLIP);
            SelectObject(hdc, old);
            DeleteObject(f);
            IDirectDrawSurface7_ReleaseDC(prim, hdc);
        }
    }
    pump(g_hold * 1000);
    IDirectDrawSurface7_Release(prim);
}

/* ------------------------------------------------------------- housekeeping */

static void teardown(ctx_t *c)
{
    if (!c->dd) return;
    if (c->mode_set)  IDirectDraw7_RestoreDisplayMode(c->dd);
    if (c->exclusive) IDirectDraw7_SetCooperativeLevel(c->dd, c->win, DDSCL_NORMAL);
    IDirectDraw7_Release(c->dd);
    c->dd = NULL;
    if (c->win) { DestroyWindow(c->win); c->win = NULL; }
    pump(50);
}

/* Nothing below here should ever be needed. It exists because "should" is not
 * something to leave a stranger's desktop resting on: a probe that dies in
 * exclusive fullscreen at 640x480 has left them squinting at a mess they did
 * not ask for, and DirectDraw's own cleanup only runs if the process unwinds. */
static void panic_restore(const char *why)
{
    LONG r = ChangeDisplaySettingsExA(NULL, NULL, NULL, 0, NULL);
    if (g_log) { fprintf(g_log, "!!! %s -- ChangeDisplaySettings(restore) ret %ld\n", why, (long)r); fflush(g_log); }
}

static LONG CALLBACK crash_filter(EXCEPTION_POINTERS *ep)
{
    panic_restore("crashed");
    if (g_log) {
        fprintf(g_log, "!!! exception 0x%08lx at %p\n",
                (unsigned long)ep->ExceptionRecord->ExceptionCode,
                ep->ExceptionRecord->ExceptionAddress);
        fflush(g_log);
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

static DWORD WINAPI watchdog(LPVOID p)
{
    Sleep((DWORD)(DWORD_PTR)p);
    panic_restore("watchdog deadline elapsed -- the run hung");
    ExitProcess(2);
    return 0;
}

/* ------------------------------------------------------------------- main */

int main(int argc, char **argv)
{
    char self[MAX_PATH], *slash, logpath[MAX_PATH];
    mon_t m[16];
    int n, i, tested = 0;

    GetModuleFileNameA(NULL, self, sizeof self);
    snprintf(logpath, sizeof logpath, "%s", self);
    slash = strrchr(logpath, '\\');
    if (slash) slash[1] = 0; else logpath[0] = 0;
    strncat(logpath, "ddmonprobe.log", sizeof logpath - strlen(logpath) - 1);
    g_log = fopen(logpath, "wb");

    for (i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--dry"))       g_dry = 1;
        else if (!strcmp(argv[i], "--no-visual")) g_visual = 0;
        else if (!strcmp(argv[i], "--hold") && i + 1 < argc) g_hold = atoi(argv[++i]);
        else snprintf(g_only, sizeof g_only, "%s", argv[i]);
    }
    if (g_hold <= 0) g_visual = 0;

    SetUnhandledExceptionFilter(crash_filter);
    CloseHandle(CreateThread(NULL, 0, watchdog, (LPVOID)(DWORD_PTR)180000u, 0, NULL));

    say("ddmonprobe -- can DirectDraw be pointed at a monitor without moving the primary?");
    say("log: %s", logpath);
    if (g_dry) say("mode: DRY RUN -- enumeration and creation only, nothing takes exclusive mode");
    blank();

    /* Said before anything runs, because it is the one cost of this probe that
     * outlives it. Nothing here writes the display database -- s113.6's subject
     * did, this does not -- so no setting survives the run. But dropping the
     * PRIMARY to 640x480, which the control arm must do, makes Windows reflow
     * the desktop, and it does not put icons back afterwards. That is worth
     * knowing in advance rather than discovering later and wondering what did
     * it. --no-visual is unrelated and does not avoid it; nothing does, short of
     * giving up the control, which would make every other result unreadable. */
    if (!g_dry) {
        say("BEFORE YOU RUN THIS: the control arm sets the PRIMARY monitor to 640x480");
        say("and back. No display setting survives the run -- nothing here is written to");
        say("the display database -- but Windows reflows the desktop when the resolution");
        say("drops and does not restore icon positions afterwards. --dry avoids it and");
        say("still answers question 1.");
        blank();
    }

    n = monitors(m, 16);
    show_layout("at start");
    if (n < 2)
        say("    NOTE: %d monitor attached. The whole question is about a SECOND one,"
            " so this run can only smoke-test the code.", n);
    blank();

    say("=== phase 0: ddraw.dll, obtained the way the game obtains it ===");
    if (!load_ddraw()) { say("no usable creation entry point -- stopping."); goto done; }
    blank();

    say("=== phase 1: enumeration (question 1) ===");
    phase_enumerate();
    blank();

    if (!g_ndev) {
        say("Enumeration produced no devices at all. Adding the NULL device so the rest");
        say("of the run still measures something -- but question 1's answer is NO.");
        add_dev(NULL, "primary display driver", "", NULL);
    }

    /* Does a GUID actually name a MONITOR? Two enumerated devices on different
     * screens sharing one GUID means it names the ADAPTER, and the whole
     * "point DirectDrawCreate at a device" plan has no lever to pull -- the
     * substitution would be a no-op. Measured under Wine before the Windows
     * trip: both heads of one Radeon came back {aeb2cdd4-...}. Whether real
     * Windows agrees is one of the things this run is for, so it is checked
     * rather than assumed, and checked LOUDLY, because every downstream result
     * is read differently depending on the answer. */
    {
        int shared = 0, a, b;
        for (a = 0; a < g_ndev; a++) for (b = a + 1; b < g_ndev; b++)
            if (g_dev[a].have_guid && g_dev[b].have_guid &&
                !memcmp(&g_dev[a].guid, &g_dev[b].guid, sizeof(GUID)) &&
                _stricmp(g_dev[a].gdi, g_dev[b].gdi))
                shared = 1;
        if (shared) {
            say("!!! TWO MONITORS SHARE ONE DEVICE GUID. The GUID names the ADAPTER, not");
            say("!!! the head. DirectDrawCreate(&guid) therefore cannot choose between");
            say("!!! them, and substituting it in the game would change nothing. The only");
            say("!!! lever left is which monitor the WINDOW is on -- which the arms below");
            say("!!! test directly.");
            blank();
        }
    }

    /* The two decisive arms, appended to whatever enumeration gave us. */
    {
        dev_t *prim = NULL, *sec = NULL;
        for (i = 0; i < g_ndev; i++) {
            if (!g_dev[i].have_guid) continue;
            if (g_dev[i].primary) { if (!prim) prim = &g_dev[i]; }
            else                  { if (!sec)  sec  = &g_dev[i]; }
        }
        if (!prim) for (i = 0; i < g_ndev; i++) if (g_dev[i].primary) { prim = &g_dev[i]; break; }
        if (sec && prim) {
            add_arm(NULL, sec,  "NULL device, window on the SECONDARY"
                                " -- does fullscreen simply follow the window?");
            add_arm(sec,  prim, "SECONDARY GUID, window on the PRIMARY"
                                " -- the discriminator: GUID or window?");
        } else if (!sec) {
            say("Only one monitor enumerated, so the two decisive arms are not added.");
            blank();
        }
    }

    say("=== the arms this run will work through ===");
    for (i = 0; i < g_ndev; i++) {
        dev_t *d = &g_dev[i];
        say("  [%d] %s", i, d->label);
        say("      guid=%s%s%s", d->have_guid ? guidstr(&d->guid) : "NULL",
            d->guid_from[0] ? "  enumerated for " : "", d->guid_from);
        say("      window on %-14s rect=(%ld,%ld)-(%ld,%ld)%s  driver=\"%s\"",
            d->gdi[0] ? d->gdi : "(unresolved)",
            d->rc.left, d->rc.top, d->rc.right, d->rc.bottom,
            d->primary ? "  PRIMARY" : "", d->drv);
    }
    blank();
    say("Both the primary and the secondary are taken through the SAME sequence.");
    say("That is deliberate: a DDERR on the secondary means nothing unless the");
    say("identical call on the primary succeeded in the same run (TESTING.md trap 6).");

    for (i = 0; i < g_ndev; i++) {
        ctx_t *c = &g_ctx[g_nctx];
        if (g_only[0] && g_dev[i].gdi[0] && _stricmp(g_only, g_dev[i].gdi)) continue;
        memset(c, 0, sizeof *c);
        c->d = &g_dev[i];

        blank();
        say("=== arm [%d]: %s ===", i, c->d->label);
        say("    %s", c->d->primary && (!c->d->guid_from[0] ||
                                        !_stricmp(c->d->guid_from, c->d->gdi))
                      ? "everything points at the primary -- this arm is the CONTROL"
                      : "this arm is a question");

        say("    -- phase 2: create and identify --");
        if (!phase_create(c)) { say("    device unusable; moving on."); continue; }
        g_nctx++; tested++;

        if (g_dry) { say("    -- dry run: stopping before exclusive mode --"); continue; }

        say("    -- phase 3: exclusive fullscreen and the mode ladder (question 2) --");
        phase_modes(c);
        if (!c->exclusive) { say("    no exclusive mode; the blit phase cannot run."); continue; }

        say("    -- phase 4: surfaces, blits and flips (question 3) --");
        phase_blits(c);
    }

    if (!g_dry && g_visual && g_nctx) {
        blank();
        say("=== phase 5: the visual check -- WATCH YOUR MONITORS ===");
        say("Each device is filled with a named colour and held for %d s, and the", g_hold);
        say("colour is written here BEFORE it is shown. No API reports which panel");
        say("the photons reached, so this line plus your answer IS the measurement.");
        for (i = 0; i < g_nctx; i++)
            if (g_ctx[i].exclusive) phase_visual(&g_ctx[i], i);
    }

    blank();
    say("=== teardown ===");
    for (i = 0; i < g_nctx; i++) teardown(&g_ctx[i]);
    show_layout("at exit");

    blank();
    say("=== summary ===");
    for (i = 0; i < g_nctx; i++) {
        ctx_t *c = &g_ctx[i];
        say("  exclusive=%-3s mode-set=%-3s surface=%lux%lu  blits ok=%d failed=%d (#150=%d)",
            c->exclusive ? "yes" : "NO", c->mode_set ? "yes" : "NO",
            (unsigned long)c->sw, (unsigned long)c->sh,
            c->blits_ok, c->blits_bad, c->rect_errs);
        say("      %s", c->d->label);
    }
    if (!tested) say("  nothing was tested.");
    blank();
    if (g_dry) {
        say("DRY RUN. Questions 2 and 3 are untouched -- run again without --dry.");
    } else {
        say("Read the summary as a comparison, never on its own. The approach is alive");
        say("only if an arm aimed at the secondary matches the control arm: exclusive");
        say("yes, mode-set yes, a surface the size of THAT monitor's own mode, and the");
        say("same blit counts. An arm that differs anywhere names the thing that kills");
        say("it. And the surface size is the one to read first -- a secondary arm whose");
        say("surface comes back the size of the PRIMARY was never on the second screen,");
        say("whatever every HRESULT above it said.");
    }

done:
    blank();
    say("Done. This log is saved at %s", logpath);
    printf("\nPress Enter to close.\n");
    fflush(stdout);
    getchar();
    if (g_log) fclose(g_log);
    return 0;
}

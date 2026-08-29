/* Which mechanism can make a monitor primary on THIS machine? (s113.6)
 *
 * 1.3-rc1 made the launch monitor primary with the sequence MSDN documents --
 * stage every device with CDS_UPDATEREGISTRY|CDS_NORESET, then one apply with a
 * NULL device -- and on the owner's Windows 11 24H2 machine (build 26100) the
 * layout did not move. Worse, it reported success: the only return value the DLL
 * looked at was the final apply, which returns DISP_CHANGE_SUCCESSFUL when there
 * is nothing staged to apply.
 *
 * WHY A SEPARATE EXE. Every candidate fix needs a real Windows 11 24H2 desktop
 * with two monitors, and getting to one costs a reboot. Testing them one per
 * reboot is the expensive way to answer a question that is the same size as one
 * run. So this tries EVERY candidate in a single pass, verifies each against what
 * Windows reports afterwards rather than against the API's own return value, and
 * puts the desktop back between attempts.
 *
 * Wine cannot answer the question -- its ChangeDisplaySettingsEx is a
 * reimplementation, and the hypothesis under test is "24H2 changed". Running it
 * under Wine is still worth doing FIRST, to prove the probe itself works before
 * spending a boot on it.
 *
 * Build:  i686-w64-mingw32-gcc -O2 -Wall -Wextra -o primaryprobe.exe \
 *             primaryprobe.c -luser32 -lgdi32
 * Run:    wine primaryprobe.exe          (smoke test only -- proves nothing)
 *         primaryprobe.exe              (on Windows: this is the real answer)
 *
 * It writes primaryprobe.log next to itself as well as printing, because on
 * Windows this gets double-clicked and a console window is not a record.
 *
 * IT PUTS THE PRIMARY BACK. Every strategy that succeeds is immediately used to
 * undo itself, and there is a last-resort sweep at the end. If all of that fails
 * it says so, loudly, with the one manual remedy.
 */
#define WINVER       0x0601
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static FILE *g_log;

/* --dry: exercise every line WITHOUT moving anything. CDS_TEST and SDC_VALIDATE
 * are the documented "would this work" modes of the two APIs, so the whole path --
 * enumeration, arithmetic, struct layout, the call itself -- runs and reports, and
 * the desktop is untouched. It is the smoke test that can be run under Wine, and
 * it is the safe first pass on Windows. It cannot answer the question: a mode that
 * validates may still refuse to apply, which is the entire fault under study. */
static int g_dry;

/* The format attribute is the point of declaring it separately: without it gcc
 * checks nothing here, and a probe that misreports its own numbers is worse than
 * no probe at all. */
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

/* say("") would be a zero-length format string, which the attribute above quite
 * correctly complains about. A blank line is not a formatted message. */
static void blank(void) { say("%s", ""); }

static const char *cds_name(LONG r)
{
    switch (r) {
    case DISP_CHANGE_SUCCESSFUL:  return "SUCCESSFUL";
    case DISP_CHANGE_RESTART:     return "RESTART";
    case DISP_CHANGE_FAILED:      return "FAILED (driver refused)";
    case DISP_CHANGE_BADMODE:     return "BADMODE";
    case DISP_CHANGE_NOTUPDATED:  return "NOTUPDATED (registry write failed)";
    case DISP_CHANGE_BADFLAGS:    return "BADFLAGS";
    case DISP_CHANGE_BADPARAM:    return "BADPARAM";
    case DISP_CHANGE_BADDUALVIEW: return "BADDUALVIEW";
    }
    return "unrecognised";
}

/* ------------------------------------------------------------- the layout */

typedef struct { char name[64]; int primary; DWORD w, h; LONG x, y; } mon_t;

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
        out[n].x = dm.dmPosition.x; out[n].y = dm.dmPosition.y;
        n++;
    }
    return n;
}

static void show_layout(const char *when)
{
    mon_t m[16];
    int n = monitors(m, 16), i;
    say("  layout %s:", when);
    for (i = 0; i < n; i++)
        say("    %-14s %lux%lu at (%ld,%ld)%s", m[i].name,
            (unsigned long)m[i].w, (unsigned long)m[i].h, m[i].x, m[i].y,
            m[i].primary ? "   PRIMARY" : "");
    say("    SM_CXSCREEN=%d SM_CYSCREEN=%d   virtual %d,%d %dx%d",
        GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN),
        GetSystemMetrics(SM_XVIRTUALSCREEN), GetSystemMetrics(SM_YVIRTUALSCREEN),
        GetSystemMetrics(SM_CXVIRTUALSCREEN), GetSystemMetrics(SM_CYVIRTUALSCREEN));
}

/* THE ONLY HONEST TEST. Not the API's return value -- what Windows says after. */
static int is_primary(const char *dev)
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

static void current_primary(char *out, size_t cap)
{
    mon_t m[16];
    int n = monitors(m, 16), i;
    out[0] = 0;
    for (i = 0; i < n; i++) if (m[i].primary) snprintf(out, cap, "%s", m[i].name);
}

/* --------------------------------------------------- the CDS-family strategies
 *
 * All four share one shape and differ in exactly one decision each, so a result
 * names a cause rather than a bundle. `keep_fields` keeps the dmFields that
 * EnumDisplaySettings returned instead of narrowing them to DM_POSITION;
 * `noreset` stages everything and applies once at the end, as MSDN's own sample
 * does; `applies` is how many times the final apply is issued, which is NirSoft's
 * MultiMonitorTool 2.15 workaround for 24H2 reduced to its mechanism.
 */
static int cds_generic(const char *dev, int keep_fields, int noreset, int applies)
{
    DISPLAY_DEVICEA dd;
    DEVMODEA dm;
    LONG tx, ty, r;
    int found = 0, k;
    DWORD i;

    memset(&dm, 0, sizeof dm); dm.dmSize = sizeof dm;
    if (!EnumDisplaySettingsA(dev, ENUM_CURRENT_SETTINGS, &dm)) {
        say("    EnumDisplaySettings(%s) failed", dev);
        return 0;
    }
    tx = dm.dmPosition.x; ty = dm.dmPosition.y;
    if (!tx && !ty) say("    NOTE: %s is already at the origin", dev);

    for (i = 0; ; i++) {
        memset(&dd, 0, sizeof dd); dd.cb = sizeof dd;
        if (!EnumDisplayDevicesA(NULL, i, &dd, 0)) break;
        if (!(dd.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP)) continue;
        memset(&dm, 0, sizeof dm); dm.dmSize = sizeof dm;
        if (!EnumDisplaySettingsA(dd.DeviceName, ENUM_CURRENT_SETTINGS, &dm)) continue;
        dm.dmPosition.x -= tx;
        dm.dmPosition.y -= ty;
        if (!keep_fields) dm.dmFields = DM_POSITION;
        else              dm.dmFields |= DM_POSITION;
        {
            DWORD flags = CDS_UPDATEREGISTRY | (noreset ? CDS_NORESET : 0);
            if (!_stricmp(dd.DeviceName, dev)) { flags |= CDS_SET_PRIMARY; found = 1; }
            if (g_dry) flags = CDS_TEST | (flags & CDS_SET_PRIMARY);
            r = ChangeDisplaySettingsExA(dd.DeviceName, &dm, NULL, flags, NULL);
            say("    stage %-14s -> (%ld,%ld)%-12s ret %ld %s", dd.DeviceName,
                (long)dm.dmPosition.x, (long)dm.dmPosition.y,
                (flags & CDS_SET_PRIMARY) ? " AS PRIMARY" : "",
                (long)r, cds_name(r));
        }
    }
    if (!found) { say("    %s never came up in the enumeration", dev); return 0; }

    if (g_dry) { say("    (dry run -- nothing applied)"); return 0; }
    for (k = 0; k < applies; k++) {
        r = ChangeDisplaySettingsExA(NULL, NULL, NULL, 0, NULL);
        say("    apply #%d ret %ld %s", k + 1, (long)r, cds_name(r));
    }
    return is_primary(dev);
}

static int s_baseline(const char *dev)   { return cds_generic(dev, 0, 1, 1); }  /* what 1.3-rc1 ships */
static int s_keepfields(const char *dev) { return cds_generic(dev, 1, 1, 1); }
static int s_applytwice(const char *dev) { return cds_generic(dev, 0, 1, 2); }
static int s_immediate(const char *dev)  { return cds_generic(dev, 0, 0, 1); }

/* ------------------------------------------------------------- the CCD strategy
 *
 * QueryDisplayConfig/SetDisplayConfig, Windows 7+, and the API Windows' own
 * Display settings page uses to apply "resolution, layout, orientation, scaling,
 * primary, bit depth and refresh rate". The primary is still the source at (0,0);
 * what changes is that the whole topology is submitted as one object instead of
 * as a sequence of per-device pokes, which is the part 24H2 may have broken.
 *
 * Loaded by name so the probe still builds and runs where the import is missing.
 */
typedef LONG (WINAPI *pGetDisplayConfigBufferSizes)(UINT32, UINT32 *, UINT32 *);
typedef LONG (WINAPI *pQueryDisplayConfig)(UINT32, UINT32 *, DISPLAYCONFIG_PATH_INFO *,
                                           UINT32 *, DISPLAYCONFIG_MODE_INFO *,
                                           DISPLAYCONFIG_TOPOLOGY_ID *);
typedef LONG (WINAPI *pSetDisplayConfig)(UINT32, DISPLAYCONFIG_PATH_INFO *,
                                         UINT32, DISPLAYCONFIG_MODE_INFO *, UINT32);
typedef LONG (WINAPI *pDisplayConfigGetDeviceInfo)(DISPLAYCONFIG_DEVICE_INFO_HEADER *);

static int s_ccd(const char *dev)
{
    HMODULE u32 = GetModuleHandleA("user32.dll");
    pGetDisplayConfigBufferSizes  getsz;
    pQueryDisplayConfig           query;
    pSetDisplayConfig             set;
    pDisplayConfigGetDeviceInfo   devinfo;
    DISPLAYCONFIG_PATH_INFO paths[32];
    DISPLAYCONFIG_MODE_INFO modes[64];
    UINT32 npaths = 32, nmodes = 64;
    LONG r;
    UINT32 i;
    int tx = 0, ty = 0, found = 0;

    getsz   = (pGetDisplayConfigBufferSizes)(void *)GetProcAddress(u32, "GetDisplayConfigBufferSizes");
    query   = (pQueryDisplayConfig)(void *)GetProcAddress(u32, "QueryDisplayConfig");
    set     = (pSetDisplayConfig)(void *)GetProcAddress(u32, "SetDisplayConfig");
    devinfo = (pDisplayConfigGetDeviceInfo)(void *)GetProcAddress(u32, "DisplayConfigGetDeviceInfo");
    if (!getsz || !query || !set || !devinfo) {
        say("    the CCD entry points are not present in this user32 -- skipped");
        return 0;
    }

    r = query(QDC_ONLY_ACTIVE_PATHS, &npaths, paths, &nmodes, modes, NULL);
    if (r != ERROR_SUCCESS) { say("    QueryDisplayConfig failed: %ld", (long)r); return 0; }
    say("    QueryDisplayConfig: %lu path(s), %lu mode(s)",
        (unsigned long)npaths, (unsigned long)nmodes);

    /* Which source is the target? The GDI name is the only thing that ties a CCD
     * source back to the \\.\DISPLAYn the rest of this program speaks in. */
    for (i = 0; i < npaths; i++) {
        DISPLAYCONFIG_SOURCE_DEVICE_NAME sn;
        char gdi[64];
        memset(&sn, 0, sizeof sn);
        sn.header.type = DISPLAYCONFIG_DEVICE_INFO_GET_SOURCE_NAME;
        sn.header.size = sizeof sn;
        sn.header.adapterId = paths[i].sourceInfo.adapterId;
        sn.header.id        = paths[i].sourceInfo.id;
        if (devinfo(&sn.header) != ERROR_SUCCESS) continue;
        WideCharToMultiByte(CP_ACP, 0, sn.viewGdiDeviceName, -1, gdi, sizeof gdi, NULL, NULL);
        say("      path %lu -> source id %lu = %s", (unsigned long)i,
            (unsigned long)paths[i].sourceInfo.id, gdi);
        if (_stricmp(gdi, dev)) continue;
        {
            UINT32 mi = paths[i].sourceInfo.modeInfoIdx;
            if (mi < nmodes && modes[mi].infoType == DISPLAYCONFIG_MODE_INFO_TYPE_SOURCE) {
                tx = modes[mi].sourceMode.position.x;
                ty = modes[mi].sourceMode.position.y;
                found = 1;
            }
        }
    }
    if (!found) { say("    no CCD source matched %s", dev); return 0; }
    say("    %s sits at (%d,%d); moving the origin there", dev, tx, ty);

    for (i = 0; i < nmodes; i++)
        if (modes[i].infoType == DISPLAYCONFIG_MODE_INFO_TYPE_SOURCE) {
            modes[i].sourceMode.position.x -= tx;
            modes[i].sourceMode.position.y -= ty;
        }

    r = set(npaths, paths, nmodes, modes,
            SDC_USE_SUPPLIED_DISPLAY_CONFIG |
            (g_dry ? SDC_VALIDATE : (SDC_APPLY | SDC_SAVE_TO_DATABASE)));
    say("    SetDisplayConfig(%s) ret %ld%s", g_dry ? "VALIDATE" : "APPLY", (long)r,
        r == ERROR_SUCCESS ? " (ERROR_SUCCESS)" : "");
    if (g_dry) return 0;
    return is_primary(dev);
}

/* --------------------------------------------------------------- the driver */

typedef int (*strat_fn)(const char *dev);
typedef struct { const char *name; strat_fn fn; const char *what; } strat_t;

static strat_t STRATS[] = {
    /* SAME ORDER AS THE DLL'S SETPRIM[] -- least disruptive first, and the
     * per-device-apply one last because it walks the desktop through broken
     * intermediate layouts. Keeping the two lists in the same order means the two
     * logs from one Windows trip can be read side by side. */
    { "baseline",   s_baseline,   "DM_POSITION only, NORESET, one apply -- exactly what 1.3-rc1 ships" },
    { "keepfields", s_keepfields, "the full DEVMODE from EnumDisplaySettings, not just DM_POSITION" },
    { "applytwice", s_applytwice, "baseline, but the final apply is issued twice (NirSoft 2.15)" },
    { "ccd",        s_ccd,        "QueryDisplayConfig/SetDisplayConfig, the modern API" },
    { "immediate",  s_immediate,  "no NORESET -- each device applied as it is set (most disruptive)" },
};

int main(int argc, char **argv)
{
    char self[MAX_PATH], *slash, logpath[MAX_PATH];
    char orig[64], target[64];
    mon_t m[16];
    int n, i, s, worked = 0;

    GetModuleFileNameA(NULL, self, sizeof self);
    snprintf(logpath, sizeof logpath, "%s", self);
    slash = strrchr(logpath, '\\');
    if (slash) slash[1] = 0; else logpath[0] = 0;
    strncat(logpath, "primaryprobe.log", sizeof logpath - strlen(logpath) - 1);
    g_log = fopen(logpath, "wb");

    say("primaryprobe -- which mechanism can move the primary monitor on this machine");
    say("log: %s", logpath);
    blank();

    n = monitors(m, 16);
    show_layout("at start");
    if (n < 2) {
        blank();
        say("Only %d monitor(s) attached. There is nothing to move the primary to,", n);
        say("so nothing here can be tested. Run this on the two-monitor desktop.");
        goto done;
    }

    current_primary(orig, sizeof orig);
    target[0] = 0;
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--dry")) g_dry = 1;
        else snprintf(target, sizeof target, "%s", argv[i]);
    }
    if (!target[0])
        for (i = 0; i < n; i++) if (!m[i].primary) { snprintf(target, sizeof target, "%s", m[i].name); break; }

    blank();
    say("current primary : %s", orig);
    say("target          : %s", target);
    if (g_dry)
        say("mode            : DRY RUN -- CDS_TEST / SDC_VALIDATE, nothing is applied");
    blank();
    say("Each strategy below is tried, then CHECKED against what Windows reports");
    say("afterwards -- not against what the API returned. Anything that works is");
    say("immediately used to put the primary back before the next one runs.");

    for (s = 0; s < (int)(sizeof STRATS / sizeof STRATS[0]); s++) {
        int ok, back;
        blank();
        say("=== %s ===", STRATS[s].name);
        say("  %s", STRATS[s].what);
        ok = STRATS[s].fn(target);
        /* In dry mode nothing was applied, so "still not primary" is the expected
         * outcome and must not read as a failure -- the useful result there is the
         * per-call return codes above, not this line. */
        if (g_dry) say("  RESULT: validated only; nothing was applied");
        else       say("  RESULT: %s is %s the primary device", target, ok ? "NOW" : "STILL NOT");
        show_layout("after");
        if (!ok) continue;

        worked++;
        say("  putting it back with the same mechanism...");
        back = STRATS[s].fn(orig);
        say("  RESTORE: %s is %s the primary device", orig, back ? "primary again" : "NOT primary -- see the sweep below");
    }

    /* Last resort. Nothing above should leave the desktop moved, but "should" is
     * not a guarantee worth leaving someone's desktop on. */
    blank();
    if (!is_primary(orig)) {
        say("!!! the primary is not back on %s -- trying every mechanism to restore it", orig);
        for (s = 0; s < (int)(sizeof STRATS / sizeof STRATS[0]) && !is_primary(orig); s++)
            STRATS[s].fn(orig);
    }
    if (is_primary(orig)) {
        say("primary is back on %s.", orig);
    } else {
        say("!!! COULD NOT RESTORE THE PRIMARY. Set it back by hand:");
        say("!!!   Settings -> System -> Display -> pick %s -> Multiple displays", orig);
        say("!!!   -> 'Make this my main display'.");
    }

    blank();
    show_layout("at exit");
    blank();
    if (g_dry)
        say("DRY RUN -- nothing was applied. Run it again without --dry for the answer.");
    else if (worked)
        say("%d of %d mechanism(s) worked. The first one that did is the fix.",
            worked, (int)(sizeof STRATS / sizeof STRATS[0]));
    else
        say("NOTHING worked. The return codes above say why, and that is the answer.");

done:
    blank();
    say("Done. This log is saved at %s", logpath);
    printf("\nPress Enter to close.\n");
    fflush(stdout);
    getchar();
    if (g_log) fclose(g_log);
    return 0;
}

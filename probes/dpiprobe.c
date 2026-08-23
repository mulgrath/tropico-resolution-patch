/* Does display scaling lie to a DPI-unaware process, and does SetProcessDPIAware
 * stop it?  This is the mechanism behind the scaled-display bug: Tropico.EXE has
 * no DPI manifest, so every metric the proxy reads from inside it may be the
 * SCALED (logical) size rather than the panel's real one.
 *
 * Three numbers matter, and the third is the one that hurts:
 *
 *   SM_CXSCREEN            tropico_fix.c:470,709 -- the two "does the mode fit
 *                          the desktop" checks
 *   GetDeviceCaps HORZRES  what the DESKTOP-WIDTH GATE itself consumes (0x515160
 *                          -> [0x60c118], FINDINGS 2).  If this is scaled, the
 *                          resolution table is gated against a width the monitor
 *                          does not have, and that is the whole tier-1 mechanism.
 *   EnumDisplaySettings    the adapter's real mode.  Not DPI-virtualized, so it
 *                          is the control: when it disagrees with the two above,
 *                          the difference IS the scaling factor.
 *
 * Printed twice -- before and after SetProcessDPIAware -- so one run shows both
 * the bug and whether the proposed fix addresses it.
 *
 * Build:  i686-w64-mingw32-gcc -O2 -Wall -o dpiprobe.exe dpiprobe.c -lgdi32 -luser32
 * Run:    wine dpiprobe.exe
 *
 * Under Wine the scaling knob is the prefix's own DPI:
 *   wine reg add "HKCU\\Control Panel\\Desktop" /v LogPixels /t REG_DWORD /d 192 /f
 * (96 = 100%, 120 = 125%, 144 = 150%, 192 = 200%).  Whether Wine honours it for
 * an unaware process is exactly what this probe is here to answer.
 */
#include <windows.h>
#include <stdio.h>

static void snapshot(const char *when)
{
    printf("--- %s ---\n", when);
    printf("  SM_CXSCREEN            = %d x %d\n",
           GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
    printf("  SM_CXVIRTUALSCREEN     = %d x %d\n",
           GetSystemMetrics(SM_CXVIRTUALSCREEN), GetSystemMetrics(SM_CYVIRTUALSCREEN));

    HDC dc = GetDC(NULL);
    if (dc) {
        printf("  GetDeviceCaps HORZRES  = %d x %d      <- what the gate reads\n",
               GetDeviceCaps(dc, HORZRES), GetDeviceCaps(dc, VERTRES));
        printf("  GetDeviceCaps LOGPIXELSX = %d  (96 = 100%%)\n",
               GetDeviceCaps(dc, LOGPIXELSX));
        ReleaseDC(NULL, dc);
    } else printf("  GetDC(NULL) failed\n");

    DEVMODEA dm; memset(&dm, 0, sizeof dm); dm.dmSize = sizeof dm;
    if (EnumDisplaySettingsA(NULL, ENUM_CURRENT_SETTINGS, &dm))
        printf("  EnumDisplaySettings    = %lu x %lu @ %lubpp   <- the real mode\n",
               dm.dmPelsWidth, dm.dmPelsHeight, dm.dmBitsPerPel);
    else
        printf("  EnumDisplaySettings failed\n");
}

int main(void)
{
    snapshot("BEFORE SetProcessDPIAware (this is what Tropico.EXE sees today)");

    /* The proposed fix. SetProcessDpiAwarenessContext is the modern call but is
     * missing on older Windows and on older Wine, so resolve it dynamically and
     * fall back -- which is exactly what the proxy would have to do. */
    HMODULE u32 = GetModuleHandleA("user32.dll");
    typedef BOOL (WINAPI *SPDAC_t)(HANDLE);
    SPDAC_t spdac = u32 ? (SPDAC_t)(void *)GetProcAddress(u32, "SetProcessDpiAwarenessContext") : NULL;
    if (spdac) {
        /* DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 == (HANDLE)-4 */
        if (spdac((HANDLE)-4)) printf("\n[fix] SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2) ok\n");
        else { printf("\n[fix] SetProcessDpiAwarenessContext failed (%lu); falling back\n", GetLastError());
               printf("[fix] SetProcessDPIAware -> %d\n", SetProcessDPIAware()); }
    } else {
        printf("\n[fix] SetProcessDpiAwarenessContext not exported; using SetProcessDPIAware\n");
        printf("[fix] SetProcessDPIAware -> %d\n", SetProcessDPIAware());
    }
    printf("\n");

    snapshot("AFTER  (this is what the fix would give it)");
    return 0;
}

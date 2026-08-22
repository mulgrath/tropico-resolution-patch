/* What Wine MEASURES vs where a window LANDS -- the two halves of FINDINGS 18.
 *
 * TROPICO_DISPLAY makes the target monitor primary, which fixes what Wine
 * measures. It does nothing about where the compositor opens the window. If
 * those two disagree the game computes a rect for a screen it is not on, and
 * DirectDraw refuses it with DDERR_INVALIDRECT (#150). This prints both. */
#include <windows.h>
#include <stdio.h>

static BOOL CALLBACK mon(HMONITOR h, HDC dc, LPRECT r, LPARAM p)
{
    MONITORINFO mi; mi.cbSize = sizeof mi;
    (void)dc; (void)r; (void)p;
    if (GetMonitorInfoA(h, &mi))
        printf("   monitor %p  %ld,%ld  %ldx%ld  %s\n", (void *)h,
               mi.rcMonitor.left, mi.rcMonitor.top,
               mi.rcMonitor.right - mi.rcMonitor.left,
               mi.rcMonitor.bottom - mi.rcMonitor.top,
               (mi.dwFlags & MONITORINFOF_PRIMARY) ? "PRIMARY" : "");
    return TRUE;
}

int main(void)
{
    HDC h = GetDC(NULL);
    printf("MEASURED (what the game reads):\n");
    printf("   GetDeviceCaps HORZRES=%d VERTRES=%d\n",
           GetDeviceCaps(h, HORZRES), GetDeviceCaps(h, VERTRES));
    ReleaseDC(NULL, h);
    printf("   SM_CXSCREEN=%d SM_CYSCREEN=%d\n",
           GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
    printf("   virtual screen: %d,%d %dx%d\n",
           GetSystemMetrics(SM_XVIRTUALSCREEN), GetSystemMetrics(SM_YVIRTUALSCREEN),
           GetSystemMetrics(SM_CXVIRTUALSCREEN), GetSystemMetrics(SM_CYVIRTUALSCREEN));
    printf("MONITORS:\n");
    EnumDisplayMonitors(NULL, NULL, mon, 0);

    /* Where does a default-placed window actually land? That is the half
     * TROPICO_DISPLAY does not control. */
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "moniprobe";
    RegisterClassA(&wc);
    HWND w = CreateWindowExA(0, "moniprobe", "moniprobe", WS_OVERLAPPEDWINDOW,
                             CW_USEDEFAULT, CW_USEDEFAULT, 640, 480,
                             NULL, NULL, wc.hInstance, NULL);
    if (w) {
        ShowWindow(w, SW_SHOW);
        RECT r; GetWindowRect(w, &r);
        HMONITOR m = MonitorFromWindow(w, MONITOR_DEFAULTTONEAREST);
        MONITORINFO mi; mi.cbSize = sizeof mi;
        printf("PLACED (where the compositor put a default window):\n");
        printf("   window rect %ld,%ld %ldx%ld\n", r.left, r.top, r.right - r.left, r.bottom - r.top);
        if (GetMonitorInfoA(m, &mi))
            printf("   landed on monitor %p  %ld,%ld %ldx%ld  %s\n", (void *)m,
                   mi.rcMonitor.left, mi.rcMonitor.top,
                   mi.rcMonitor.right - mi.rcMonitor.left,
                   mi.rcMonitor.bottom - mi.rcMonitor.top,
                   (mi.dwFlags & MONITORINFOF_PRIMARY) ? "PRIMARY" : "NOT primary");
        DestroyWindow(w);
    }
    fflush(stdout);
    return 0;
}

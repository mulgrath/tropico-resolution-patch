/* Build: i686-w64-mingw32-gcc -O2 -Wall -o modeprobe.exe modeprobe.c -lddraw -ldxguid -lgdi32 -luser32
 * Run under Proton in a faked screen (FINDINGS 142), e.g. from the game folder:
 *   STEAM_COMPAT_DATA_PATH=<prefix> STEAM_COMPAT_CLIENT_INSTALL_PATH=<steam> \
 *   gamescope -W 1366 -H 768 -w 1366 -h 768 -- <proton> run ./modeprobe.exe
 */
/* modeprobe -- what a 1366x768 screen offers Tropico under Proton.
 *
 * Writes modeprobe.log beside the exe (stdout is lost under Steam/Proton).
 *   1. the desktop as the patch measures it (SM_CXSCREEN, GetDeviceCaps)
 *   2. EnumDisplaySettings -- the list the patch's picker walks
 *   3. DirectDraw EnumDisplayModes at 16bpp -- what the game's own enumerator sees
 *   4. SetDisplayMode at 16bpp for each candidate width, and for each that
 *      succeeds, the primary surface's real lPitch against width*2 (shear test). */
#include <windows.h>
#include <ddraw.h>
#include <stdio.h>

static FILE *L;
static IDirectDraw7 *dd;
static HWND wnd;

#define P(...) do { fprintf(L, __VA_ARGS__); fflush(L); } while (0)

static HRESULT WINAPI cb(DDSURFACEDESC2 *sd, void *ctx)
{
    if (sd->ddpfPixelFormat.dwRGBBitCount == 16)
        P("   %4lu x %-4lu\n", sd->dwWidth, sd->dwHeight);
    (*(int *)ctx)++;
    return DDENUMRET_OK;
}

static const char *hrname(HRESULT hr)
{
    return hr == DD_OK ? "OK" :
           hr == DDERR_INVALIDMODE ? "DDERR_INVALIDMODE" :
           hr == DDERR_UNSUPPORTED ? "DDERR_UNSUPPORTED" :
           hr == DDERR_INVALIDPARAMS ? "DDERR_INVALIDPARAMS" :
           hr == DDERR_NOEXCLUSIVEMODE ? "DDERR_NOEXCLUSIVEMODE" : "(other)";
}

static void try_mode(DWORD w, DWORD h)
{
    HRESULT hr = IDirectDraw7_SetDisplayMode(dd, w, h, 16, 0, 0);
    P("   SetDisplayMode(%4lu,%4lu,16) -> 0x%08lx %-20s", w, h, (unsigned long)hr, hrname(hr));
    if (hr != DD_OK) { P("\n"); return; }
    {
        DDSURFACEDESC2 sd; IDirectDrawSurface7 *s = NULL;
        memset(&sd, 0, sizeof sd); sd.dwSize = sizeof sd;
        sd.dwFlags = DDSD_CAPS; sd.ddsCaps.dwCaps = DDSCAPS_PRIMARYSURFACE;
        hr = IDirectDraw7_CreateSurface(dd, &sd, &s, NULL);
        if (hr != DD_OK) { P(" primary: CreateSurface 0x%08lx\n", (unsigned long)hr); return; }
        SetForegroundWindow(wnd);
        MoveWindow(wnd, 0, 0, w, h, TRUE);
        IDirectDrawSurface7_Restore(s);
        memset(&sd, 0, sizeof sd); sd.dwSize = sizeof sd;
        hr = IDirectDrawSurface7_Lock(s, NULL, &sd, DDLOCK_WAIT, NULL);
        if (hr == DD_OK) {
            P(" surface %lux%lu pitch %ld (w*2 = %lu, padding %ld)%s\n",
              sd.dwWidth, sd.dwHeight, (long)sd.lPitch, w * 2,
              (long)sd.lPitch - (long)(w * 2),
              sd.lPitch != (LONG)(w * 2) ? "  <-- SHEARS" : "");
            IDirectDrawSurface7_Unlock(s, NULL);
        } else P(" Lock 0x%08lx\n", (unsigned long)hr);
        IDirectDrawSurface7_Release(s);
    }
}

int main(int argc, char **argv)
{
    char path[MAX_PATH], *slash;
    GetModuleFileNameA(NULL, path, sizeof path);
    slash = strrchr(path, '\\');
    strcpy(slash ? slash + 1 : path, "modeprobe.log");
    L = fopen(path, "w");
    if (!L) return 1;

    P("== desktop as the patch measures it ==\n");
    P("   SM_CXSCREEN x SM_CYSCREEN = %d x %d\n",
      GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
    {
        HDC dc = GetDC(NULL);
        P("   GetDeviceCaps HORZRES x VERTRES = %d x %d, %d bpp\n",
          GetDeviceCaps(dc, HORZRES), GetDeviceCaps(dc, VERTRES), GetDeviceCaps(dc, BITSPIXEL));
        ReleaseDC(NULL, dc);
    }

    P("\n== EnumDisplaySettings(NULL), unique sizes -- the patch's picker list ==\n");
    {
        DEVMODEA dm; DWORD i, k, n = 0; DWORD seen[256][2];
        for (i = 0; ; i++) {
            int dup = 0;
            memset(&dm, 0, sizeof dm); dm.dmSize = sizeof dm;
            if (!EnumDisplaySettingsA(NULL, i, &dm)) break;
            for (k = 0; k < n; k++)
                if (seen[k][0] == dm.dmPelsWidth && seen[k][1] == dm.dmPelsHeight) dup = 1;
            if (dup || n >= 256) continue;
            seen[n][0] = dm.dmPelsWidth; seen[n][1] = dm.dmPelsHeight; n++;
            P("   %4lu x %-4lu%s\n", dm.dmPelsWidth, dm.dmPelsHeight,
              dm.dmPelsWidth % 4 ? "   (width % 4 != 0)" : "");
        }
        P("   (%lu sizes, %lu entries)\n", n, i);
    }

    wnd = CreateWindowExA(0, "STATIC", "modeprobe", WS_POPUP | WS_VISIBLE, 0, 0, 64, 64, 0, 0, 0, 0);
    {
        HRESULT hr = DirectDrawCreateEx(NULL, (void **)&dd, &IID_IDirectDraw7, NULL);
        int nm = 0;
        if (hr != DD_OK) { P("DirectDrawCreateEx failed 0x%08lx\n", (unsigned long)hr); return 1; }
        hr = IDirectDraw7_SetCooperativeLevel(dd, wnd, DDSCL_EXCLUSIVE | DDSCL_FULLSCREEN);
        P("\nSetCooperativeLevel(EXCLUSIVE|FULLSCREEN) -> 0x%08lx\n", (unsigned long)hr);
        P("\n== DirectDraw EnumDisplayModes, 16bpp only -- the game's own list ==\n");
        IDirectDraw7_EnumDisplayModes(dd, 0, NULL, &nm, cb);
        P("   (%d modes at all depths)\n", nm);
    }

    P("\n== SetDisplayMode at 16bpp, and the primary's real pitch ==\n");
    {
        static const DWORD c[][2] = {
            {1366,768}, {1364,768}, {1360,768}, {1368,768}, {1356,768}, {1352,768},
            {1280,720}, {1024,768}, {640,480},
        };
        int i;
        for (i = 0; i < (int)(sizeof c / sizeof c[0]); i++) try_mode(c[i][0], c[i][1]);
        /* extra sizes from the command line: modeprobe 1344x768 1336x768 ... */
        for (i = 1; i < argc; i++) {
            unsigned w, h;
            if (sscanf(argv[i], "%ux%u", &w, &h) == 2) try_mode(w, h);
        }
    }
    P("\n== offscreen 16bpp surfaces: pitch for ANY width, mode or no mode ==\n");
    {
        static const DWORD ws[] = {1280,1336,1344,1352,1356,1358,1360,1362,1364,1366,1368,1400,1440,1600,1920};
        int i, mem;
        for (mem = 0; mem < 2; mem++)
        for (i = 0; i < (int)(sizeof ws / sizeof ws[0]); i++) {
            DDSURFACEDESC2 sd; IDirectDrawSurface7 *s = NULL; HRESULT hr;
            memset(&sd, 0, sizeof sd); sd.dwSize = sizeof sd;
            sd.dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT | DDSD_PIXELFORMAT;
            sd.dwWidth = ws[i]; sd.dwHeight = 768;
            sd.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN | (mem ? DDSCAPS_VIDEOMEMORY : DDSCAPS_SYSTEMMEMORY);
            sd.ddpfPixelFormat.dwSize = sizeof sd.ddpfPixelFormat;
            sd.ddpfPixelFormat.dwFlags = DDPF_RGB; sd.ddpfPixelFormat.dwRGBBitCount = 16;
            sd.ddpfPixelFormat.dwRBitMask = 0xf800; sd.ddpfPixelFormat.dwGBitMask = 0x07e0;
            sd.ddpfPixelFormat.dwBBitMask = 0x001f;
            hr = IDirectDraw7_CreateSurface(dd, &sd, &s, NULL);
            if (hr != DD_OK) { P("   %s %4lu: CreateSurface 0x%08lx\n", mem ? "vid" : "sys", ws[i], (unsigned long)hr); continue; }
            memset(&sd, 0, sizeof sd); sd.dwSize = sizeof sd;
            hr = IDirectDrawSurface7_Lock(s, NULL, &sd, DDLOCK_WAIT, NULL);
            if (hr == DD_OK) {
                P("   %s %4lu: pitch %4ld  (w*2 = %4lu, padding %ld)%s\n", mem ? "vid" : "sys",
                  ws[i], (long)sd.lPitch, ws[i] * 2, (long)sd.lPitch - (long)(ws[i] * 2),
                  sd.lPitch != (LONG)(ws[i] * 2) ? "  <-- SHEARS" : "");
                IDirectDrawSurface7_Unlock(s, NULL);
            } else P("   %s %4lu: Lock 0x%08lx\n", mem ? "vid" : "sys", ws[i], (unsigned long)hr);
            IDirectDrawSurface7_Release(s);
        }
    }
    IDirectDraw7_RestoreDisplayMode(dd);
    P("\ndone\n");
    fclose(L);
    return 0;
}

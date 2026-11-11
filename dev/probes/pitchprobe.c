/* Build: i686-w64-mingw32-gcc -O2 -Wall -o pitchprobe.exe pitchprobe.c -lddraw -ldxguid -lgdi32 -luser32
 * Run under Proton in a faked screen (FINDINGS 142), e.g. from the game folder:
 *   STEAM_COMPAT_DATA_PATH=<prefix> STEAM_COMPAT_CLIENT_INSTALL_PATH=<steam> \
 *   gamescope -W 1366 -H 768 -w 1366 -h 768 -- <proton> run ./pitchprobe.exe
 */
/* pitchprobe -- can a 16bpp system-memory surface be given pitch == width*2
 * when DirectDraw would pad it, and does Blt honour that pitch?
 *
 * For each width: create OFFSCREENPLAIN|SYSTEMMEMORY with caller memory
 * (DDSD_LPSURFACE|DDSD_PITCH, pitch = w*2), Lock it and check the pointer and
 * pitch come back as given, fill it with a row/column pattern written the way
 * Tropico writes (base + (w*y + x)*2), Blt it into an ordinary (padded) surface,
 * and verify every pixel through that surface's own pitch.
 * Also tries the same via SetSurfaceDesc on an already-created surface.
 * Writes pitchprobe.log beside the exe. */
#include <windows.h>
#include <ddraw.h>
#include <stdio.h>
#include <stdlib.h>

static FILE *L;
static IDirectDraw7 *dd;
#define P(...) do { fprintf(L, __VA_ARGS__); fflush(L); } while (0)

static void fmt565(DDPIXELFORMAT *pf)
{
    memset(pf, 0, sizeof *pf); pf->dwSize = sizeof *pf;
    pf->dwFlags = DDPF_RGB; pf->dwRGBBitCount = 16;
    pf->dwRBitMask = 0xf800; pf->dwGBitMask = 0x07e0; pf->dwBBitMask = 0x001f;
}

static IDirectDrawSurface7 *plain(DWORD w, DWORD h, void *mem, LONG pitch, HRESULT *phr)
{
    DDSURFACEDESC2 sd; IDirectDrawSurface7 *s = NULL;
    memset(&sd, 0, sizeof sd); sd.dwSize = sizeof sd;
    sd.dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT | DDSD_PIXELFORMAT;
    sd.dwWidth = w; sd.dwHeight = h;
    sd.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN | DDSCAPS_SYSTEMMEMORY;
    fmt565(&sd.ddpfPixelFormat);
    if (mem) { sd.dwFlags |= DDSD_LPSURFACE | DDSD_PITCH; sd.lpSurface = mem; sd.lPitch = pitch; }
    *phr = IDirectDraw7_CreateSurface(dd, &sd, &s, NULL);
    return *phr == DD_OK ? s : NULL;
}

static WORD pat(DWORD x, DWORD y) { return (WORD)((x * 7 + y * 131) & 0xffff); }

static void verify(const char *how, DWORD w, DWORD h, IDirectDrawSurface7 *src, void *mem)
{
    DDSURFACEDESC2 sd; HRESULT hr; DWORD x, y, bad = 0;
    IDirectDrawSurface7 *dst;
    WORD *m = (WORD *)mem;

    memset(&sd, 0, sizeof sd); sd.dwSize = sizeof sd;
    hr = IDirectDrawSurface7_Lock(src, NULL, &sd, DDLOCK_WAIT, NULL);
    if (hr != DD_OK) { P("   %-14s %4lu: Lock 0x%08lx\n", how, w, (unsigned long)hr); return; }
    P("   %-14s %4lu: lock pitch %ld (want %lu) ptr %s",
      how, w, (long)sd.lPitch, w * 2, sd.lpSurface == mem ? "== ours" : "!= ours");
    /* write the way the game does: base + (w*y + x)*2, through the LOCKED pointer */
    m = (WORD *)sd.lpSurface;
    for (y = 0; y < h; y++) for (x = 0; x < w; x++) m[w * y + x] = pat(x, y);
    IDirectDrawSurface7_Unlock(src, NULL);

    dst = plain(w, h, NULL, 0, &hr);
    if (!dst) { P(" | dst CreateSurface 0x%08lx\n", (unsigned long)hr); return; }
    hr = IDirectDrawSurface7_Blt(dst, NULL, src, NULL, DDBLT_WAIT, NULL);
    if (hr != DD_OK) { P(" | Blt 0x%08lx\n", (unsigned long)hr); IDirectDrawSurface7_Release(dst); return; }
    memset(&sd, 0, sizeof sd); sd.dwSize = sizeof sd;
    hr = IDirectDrawSurface7_Lock(dst, NULL, &sd, DDLOCK_WAIT, NULL);
    if (hr != DD_OK) { P(" | dst Lock 0x%08lx\n", (unsigned long)hr); IDirectDrawSurface7_Release(dst); return; }
    for (y = 0; y < h; y++) {
        WORD *row = (WORD *)((BYTE *)sd.lpSurface + y * sd.lPitch);
        for (x = 0; x < w; x++) if (row[x] != pat(x, y)) bad++;
    }
    P(" | Blt -> padded dst (pitch %ld): %lu of %lu pixels wrong%s\n",
      (long)sd.lPitch, bad, w * h, bad ? "  <-- FAIL" : "  OK");
    IDirectDrawSurface7_Unlock(dst, NULL);
    IDirectDrawSurface7_Release(dst);
}

int main(void)
{
    static const DWORD ws[] = {1358, 1362, 1366, 1360, 1920};
    char path[MAX_PATH], *slash;
    HWND wnd;
    int i;
    GetModuleFileNameA(NULL, path, sizeof path);
    slash = strrchr(path, '\\');
    strcpy(slash ? slash + 1 : path, "pitchprobe.log");
    L = fopen(path, "w");
    if (!L) return 1;

    wnd = CreateWindowExA(0, "STATIC", "pitchprobe", WS_POPUP, 0, 0, 64, 64, 0, 0, 0, 0);
    if (DirectDrawCreateEx(NULL, (void **)&dd, &IID_IDirectDraw7, NULL) != DD_OK) { P("no ddraw\n"); return 1; }
    P("SetCooperativeLevel(NORMAL) -> 0x%08lx\n\n",
      (unsigned long)IDirectDraw7_SetCooperativeLevel(dd, wnd, DDSCL_NORMAL));

    for (i = 0; i < (int)(sizeof ws / sizeof ws[0]); i++) {
        DWORD w = ws[i], h = 768;
        HRESULT hr;
        void *mem = calloc(w * 2, h + 1);
        IDirectDrawSurface7 *s;

        /* 1. caller memory at CreateSurface */
        s = plain(w, h, mem, (LONG)(w * 2), &hr);
        if (s) { verify("CreateSurface", w, h, s, mem); IDirectDrawSurface7_Release(s); }
        else P("   %-14s %4lu: CreateSurface(lpSurface, pitch %lu) -> 0x%08lx\n",
               "CreateSurface", w, w * 2, (unsigned long)hr);

        /* 2. caller memory via SetSurfaceDesc on an ordinary surface */
        s = plain(w, h, NULL, 0, &hr);
        if (s) {
            DDSURFACEDESC2 sd;
            memset(&sd, 0, sizeof sd); sd.dwSize = sizeof sd;
            sd.dwFlags = DDSD_LPSURFACE | DDSD_PITCH | DDSD_WIDTH | DDSD_HEIGHT | DDSD_PIXELFORMAT;
            sd.dwWidth = w; sd.dwHeight = h; sd.lpSurface = mem; sd.lPitch = (LONG)(w * 2);
            fmt565(&sd.ddpfPixelFormat);
            hr = IDirectDrawSurface7_SetSurfaceDesc(s, &sd, 0);
            if (hr == DD_OK) verify("SetSurfaceDesc", w, h, s, mem);
            else P("   %-14s %4lu: SetSurfaceDesc -> 0x%08lx\n", "SetSurfaceDesc", w, (unsigned long)hr);
            IDirectDrawSurface7_Release(s);
        }
        free(mem);
    }
    P("\ndone\n");
    fclose(L);
    return 0;
}

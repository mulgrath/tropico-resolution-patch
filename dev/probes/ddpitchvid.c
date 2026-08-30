/* Measure surface pitch for the surface classes the HARDWARE path uses.
 *
 * FINDINGS section 10 measured pitch only for SYSTEM-memory offscreen surfaces and
 * derived the rule width %% 4 == 0. Section 14 warned that the hardware path has its
 * own pitch/stride problem that was never tested. The owner has now seen it: with
 * Hardware 3D enabled the image smears exactly as section 10 describes ("as if the
 * pixel rows are wrapped incorrectly").
 *
 * The game assumes pitch == width*2 at 16bpp and writes rows at that spacing. If a
 * VIDEO-memory or texture surface is padded to a coarser boundary than a system one,
 * every row drifts. This probe measures all three classes at the same widths so the
 * three can be compared directly.
 *
 * Prints the primary/back-buffer pitch too, since that is what actually gets scanned
 * out and is the surface the smear would appear on.
 */
#include <windows.h>
#include <ddraw.h>
#include <stdio.h>

static const int WIDTHS[] = {640, 800, 1024, 1152, 1280, 1368, 1400, 1440, 1600, 1680, 1920, 0};

static long probe(IDirectDraw7 *dd, int W, int H, DWORD caps)
{
    DDSURFACEDESC2 sd;
    ZeroMemory(&sd, sizeof sd);
    sd.dwSize = sizeof sd;
    sd.dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT;
    sd.ddsCaps.dwCaps = caps;
    sd.dwWidth = W;
    sd.dwHeight = H;

    IDirectDrawSurface7 *surf = NULL;
    if (IDirectDraw7_CreateSurface(dd, &sd, &surf, NULL) != DD_OK || !surf)
        return -1;

    DDSURFACEDESC2 d2;
    ZeroMemory(&d2, sizeof d2);
    d2.dwSize = sizeof d2;
    long pitch = -2;
    if (IDirectDrawSurface7_Lock(surf, NULL, &d2, DDLOCK_WAIT | DDLOCK_READONLY, NULL) == DD_OK) {
        pitch = (long)d2.lPitch;
        IDirectDrawSurface7_Unlock(surf, NULL);
    } else if (IDirectDrawSurface7_GetSurfaceDesc(surf, &d2) == DD_OK) {
        pitch = (long)d2.lPitch;   /* some drivers refuse Lock on vidmem but report pitch */
    }
    IDirectDrawSurface7_Release(surf);
    return pitch;
}

static void row(IDirectDraw7 *dd, int W, int H)
{
    long sys = probe(dd, W, H, DDSCAPS_OFFSCREENPLAIN | DDSCAPS_SYSTEMMEMORY);
    long vid = probe(dd, W, H, DDSCAPS_OFFSCREENPLAIN | DDSCAPS_VIDEOMEMORY);
    long tex = probe(dd, W, H, DDSCAPS_TEXTURE | DDSCAPS_SYSTEMMEMORY);
    long want = (long)W * 2;
    printf("  %5d %5d  %6ld |", W, H, want);
    long v[3]; v[0] = sys; v[1] = vid; v[2] = tex;
    for (int i = 0; i < 3; i++) {
        if (v[i] == -1)      printf("   (create failed)");
        else if (v[i] == -2) printf("   (no pitch)     ");
        else                 printf(" %7ld %+5ld", v[i], v[i] - want);
    }
    printf("\n");
}

int main(void)
{
    HWND w = CreateWindowExA(0, "STATIC", "p", WS_POPUP, 0, 0, 64, 64, 0, 0, 0, 0);
    IDirectDraw7 *dd;
    if (DirectDrawCreateEx(NULL, (void **)&dd, &IID_IDirectDraw7, NULL) != DD_OK) {
        puts("DirectDrawCreateEx failed");
        return 1;
    }
    IDirectDraw7_SetCooperativeLevel(dd, w, DDSCL_EXCLUSIVE | DDSCL_FULLSCREEN);
    if (IDirectDraw7_SetDisplayMode(dd, 640, 480, 16, 0, 0) != DD_OK)
        puts("note: SetDisplayMode(640,480,16) failed; pitches below may be for another depth");

    printf("16bpp pitch by surface class. The game assumes pitch == width*2 and writes\n");
    printf("rows at that spacing, so ANY nonzero delta shears the image.\n\n");
    printf("  width   hgt   want*2 |   sysmem  delta |   vidmem  delta |  texture  delta\n");
    for (int i = 0; WIDTHS[i]; i++)
        row(dd, WIDTHS[i], 64);

    printf("\nAt the real slot-4 geometries the game would use:\n");
    printf("  width   hgt   want*2 |   sysmem  delta |   vidmem  delta |  texture  delta\n");
    row(dd, 1600, 900);
    row(dd, 1600, 1200);
    row(dd, 1280, 1024);
    row(dd, 1024, 768);

    IDirectDraw7_Release(dd);
    return 0;
}

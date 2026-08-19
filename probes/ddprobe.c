#include <windows.h>
#include <ddraw.h>
#include <stdio.h>

static IDirectDraw7 *dd;
static int nmodes;

static HRESULT WINAPI cb(DDSURFACEDESC2 *sd, void *ctx){
    printf("   %4lu x %-4lu  %2lu bpp\n", sd->dwWidth, sd->dwHeight,
           sd->ddpfPixelFormat.dwRGBBitCount);
    nmodes++;
    return DDENUMRET_OK;
}

static void try_mode(int w,int h,int bpp){
    HRESULT hr = IDirectDraw7_SetDisplayMode(dd,w,h,bpp,0,0);
    printf("   SetDisplayMode(%d,%d,%d) -> 0x%08lx %s\n", w,h,bpp,(unsigned long)hr,
        hr==DD_OK ? "OK" :
        hr==DDERR_INVALIDMODE ? "DDERR_INVALIDMODE" :
        hr==DDERR_UNSUPPORTED ? "DDERR_UNSUPPORTED" :
        hr==DDERR_INVALIDPARAMS ? "DDERR_INVALIDPARAMS" :
        hr==DDERR_NOEXCLUSIVEMODE ? "DDERR_NOEXCLUSIVEMODE" :
        hr==DDERR_LOCKEDSURFACES ? "DDERR_LOCKEDSURFACES" :
        hr==DDERR_SURFACEBUSY ? "DDERR_SURFACEBUSY" :
        hr==DDERR_WASSTILLDRAWING ? "DDERR_WASSTILLDRAWING" : "(other)");
}

int main(void){
    HWND w = CreateWindowExA(0,"STATIC","ddprobe",WS_POPUP,0,0,64,64,0,0,0,0);
    HRESULT hr = DirectDrawCreateEx(NULL,(void**)&dd,&IID_IDirectDraw7,NULL);
    if(hr!=DD_OK){ printf("DirectDrawCreateEx failed 0x%08lx\n",(unsigned long)hr); return 1; }
    hr = IDirectDraw7_SetCooperativeLevel(dd,w,DDSCL_EXCLUSIVE|DDSCL_FULLSCREEN);
    printf("SetCooperativeLevel(EXCLUSIVE|FULLSCREEN) -> 0x%08lx\n",(unsigned long)hr);

    printf("\n== modes DirectDraw enumerates ==\n");
    IDirectDraw7_EnumDisplayModes(dd,0,NULL,NULL,cb);
    printf("   (%d modes)\n",nmodes);

    printf("\n== 16bpp: the depth Tropico actually requests ==\n");
    try_mode(640,480,16);      /* stock slot 0 */
    try_mode(1024,768,16);     /* stock slot 2 - known working */
    try_mode(1280,1024,16);    /* stock slot 3 */
    try_mode(1600,1200,16);    /* stock slot 4 - CONFIRMED working in game */
    try_mode(1600,900,16);     /* my invented slot 1 - FAILS in game */
    try_mode(1920,1080,16);    /* my invented slot 2 */
    fflush(stdout);
    return 0;
}

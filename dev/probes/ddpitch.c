#include <windows.h>
#include <ddraw.h>
#include <stdio.h>
int main(void){
    HWND w = CreateWindowExA(0,"STATIC","p",WS_POPUP,0,0,64,64,0,0,0,0);
    IDirectDraw7 *dd;
    if(DirectDrawCreateEx(NULL,(void**)&dd,&IID_IDirectDraw7,NULL)!=DD_OK) return 1;
    IDirectDraw7_SetCooperativeLevel(dd,w,DDSCL_EXCLUSIVE|DDSCL_FULLSCREEN);
    IDirectDraw7_SetDisplayMode(dd,640,480,16,0,0);   /* force 16bpp like the game */
    int widths[] = {640,800,1024,1152,1280,1360,1366,1400,1440,1600,1680,1920,0};
    printf("16bpp offscreen surface pitch vs assumed width*2:\n");
    printf("  width  w%%16  w*2    actual  padding\n");
    for(int i=0;widths[i];i++){
        int W=widths[i];
        DDSURFACEDESC2 sd; ZeroMemory(&sd,sizeof sd); sd.dwSize=sizeof sd;
        sd.dwFlags=DDSD_CAPS|DDSD_WIDTH|DDSD_HEIGHT|DDSD_PIXELFORMAT;
        sd.ddsCaps.dwCaps=DDSCAPS_OFFSCREENPLAIN|DDSCAPS_SYSTEMMEMORY;
        sd.dwWidth=W; sd.dwHeight=64;
        sd.ddpfPixelFormat.dwSize=sizeof(DDPIXELFORMAT);
        sd.ddpfPixelFormat.dwFlags=DDPF_RGB;
        sd.ddpfPixelFormat.dwRGBBitCount=16;
        sd.ddpfPixelFormat.dwRBitMask=0xF800;
        sd.ddpfPixelFormat.dwGBitMask=0x07E0;
        sd.ddpfPixelFormat.dwBBitMask=0x001F;
        IDirectDrawSurface7 *s=NULL;
        HRESULT hr=IDirectDraw7_CreateSurface(dd,&sd,&s,NULL);
        if(hr!=DD_OK){ printf("  %5d  create failed 0x%08lx\n",W,(unsigned long)hr); continue; }
        DDSURFACEDESC2 l; ZeroMemory(&l,sizeof l); l.dwSize=sizeof l;
        if(IDirectDrawSurface7_Lock(s,NULL,&l,DDLOCK_WAIT,NULL)==DD_OK){
            long pad = l.lPitch - W*2;
            printf("  %5d  %4d  %5d  %6ld  %ld %s\n", W, W%16, W*2, l.lPitch, pad,
                   pad ? "<-- SHEAR" : "");
            IDirectDrawSurface7_Unlock(s,NULL);
        }
        IDirectDrawSurface7_Release(s);
    }
    fflush(stdout); return 0;
}

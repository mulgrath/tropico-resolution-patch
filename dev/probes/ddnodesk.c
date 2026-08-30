#include <windows.h>
#include <ddraw.h>
#include <stdio.h>
static int n8,n16,n32,ntot;
static IDirectDraw7 *dd;
static HRESULT WINAPI cb(DDSURFACEDESC2 *sd, void *ctx){
    DWORD b = sd->ddpfPixelFormat.dwRGBBitCount;
    if(b==8) n8++; else if(b==16) n16++; else if(b==32) n32++;
    ntot++;
    if(b==16) printf("      16bpp: %lu x %lu\n", sd->dwWidth, sd->dwHeight);
    return DDENUMRET_OK;
}
static const char* e(HRESULT hr){
    switch(hr){ case DD_OK:return "OK";
      case DDERR_INVALIDMODE:return "DDERR_INVALIDMODE";
      case DDERR_UNSUPPORTED:return "DDERR_UNSUPPORTED";
      case DDERR_NOEXCLUSIVEMODE:return "DDERR_NOEXCLUSIVEMODE";
      case DDERR_INVALIDPARAMS:return "DDERR_INVALIDPARAMS";
      case DDERR_GENERIC:return "DDERR_GENERIC";
      default:return "(other)"; }
}
int main(void){
    HDC h=GetDC(NULL);
    printf("desktop: %d x %d @ %d bpp\n", GetDeviceCaps(h,HORZRES),
           GetDeviceCaps(h,VERTRES), GetDeviceCaps(h,BITSPIXEL));
    ReleaseDC(NULL,h);
    HWND w=CreateWindowExA(0,"STATIC","p",WS_POPUP,0,0,64,64,0,0,0,0);
    HRESULT hr=DirectDrawCreateEx(NULL,(void**)&dd,&IID_IDirectDraw7,NULL);
    printf("DirectDrawCreateEx           -> 0x%08lx %s\n",(unsigned long)hr,e(hr));
    if(hr!=DD_OK) return 1;
    hr=IDirectDraw7_SetCooperativeLevel(dd,w,DDSCL_EXCLUSIVE|DDSCL_FULLSCREEN);
    printf("SetCoopLevel EXCLUSIVE|FULL  -> 0x%08lx %s\n",(unsigned long)hr,e(hr));
    printf("\n== enumerated modes (16bpp listed individually) ==\n");
    IDirectDraw7_EnumDisplayModes(dd,0,NULL,NULL,cb);
    printf("   totals: %d modes  |  8bpp=%d  16bpp=%d  32bpp=%d\n",ntot,n8,n16,n32);
    printf("\n== the game's actual requests (restored immediately) ==\n");
    int t[][2]={{640,480},{1024,768},{1280,1024},{1600,1200},{1600,900}};
    for(int i=0;i<5;i++){
        hr=IDirectDraw7_SetDisplayMode(dd,t[i][0],t[i][1],16,0,0);
        printf("   SetDisplayMode(%4d,%4d,16) -> 0x%08lx %s\n",t[i][0],t[i][1],(unsigned long)hr,e(hr));
        if(hr==DD_OK) IDirectDraw7_RestoreDisplayMode(dd);
    }
    IDirectDraw7_RestoreDisplayMode(dd);
    IDirectDraw7_SetCooperativeLevel(dd,w,DDSCL_NORMAL);
    printf("\ndisplay mode restored.\n");
    fflush(stdout); return 0;
}

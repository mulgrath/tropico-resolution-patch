#include <windows.h>
#include <ddraw.h>
#include <stdio.h>
static const char* e(HRESULT hr){
  switch(hr){
   case DD_OK: return "OK";
   case DDERR_INVALIDMODE: return "DDERR_INVALIDMODE";
   case DDERR_UNSUPPORTED: return "DDERR_UNSUPPORTED";
   case DDERR_INVALIDPARAMS: return "DDERR_INVALIDPARAMS";
   case DDERR_INVALIDCAPS: return "DDERR_INVALIDCAPS";
   case DDERR_OUTOFVIDEOMEMORY: return "DDERR_OUTOFVIDEOMEMORY";
   case DDERR_OUTOFMEMORY: return "DDERR_OUTOFMEMORY";
   case DDERR_NOFLIPHW: return "DDERR_NOFLIPHW";
   case DDERR_NOEXCLUSIVEMODE: return "DDERR_NOEXCLUSIVEMODE";
   default: return "(other)";
  }
}
static void test(IDirectDraw7 *dd,int w,int h){
    printf("\n-- %dx%d @16bpp  (h%%8=%d h%%16=%d w%%8=%d) --\n",w,h,h%8,h%16,w%8);
    HRESULT hr = IDirectDraw7_SetDisplayMode(dd,w,h,16,0,0);
    printf("   SetDisplayMode      -> 0x%08lx %s\n",(unsigned long)hr,e(hr));
    if(hr!=DD_OK) return;

    DDSURFACEDESC2 sd; ZeroMemory(&sd,sizeof sd); sd.dwSize=sizeof sd;
    sd.dwFlags = DDSD_CAPS|DDSD_BACKBUFFERCOUNT;
    sd.ddsCaps.dwCaps = DDSCAPS_PRIMARYSURFACE|DDSCAPS_FLIP|DDSCAPS_COMPLEX;
    sd.dwBackBufferCount = 1;
    IDirectDrawSurface7 *pri=NULL;
    hr = IDirectDraw7_CreateSurface(dd,&sd,&pri,NULL);
    printf("   CreatePrimary+flip  -> 0x%08lx %s\n",(unsigned long)hr,e(hr));
    if(hr==DD_OK){
        DDSURFACEDESC2 l; ZeroMemory(&l,sizeof l); l.dwSize=sizeof l;
        hr = IDirectDrawSurface7_Lock(pri,NULL,&l,DDLOCK_WAIT|DDLOCK_READONLY,NULL);
        if(hr==DD_OK){
            printf("   Lock pitch          -> %ld bytes (w*2=%d, padding=%ld)\n",
                   l.lPitch, w*2, l.lPitch - w*2);
            IDirectDrawSurface7_Unlock(pri,NULL);
        } else printf("   Lock                -> 0x%08lx %s\n",(unsigned long)hr,e(hr));
        IDirectDrawSurface7_Release(pri);
    }
    /* an offscreen sysmem surface the size of the mode, as a software renderer would */
    ZeroMemory(&sd,sizeof sd); sd.dwSize=sizeof sd;
    sd.dwFlags = DDSD_CAPS|DDSD_WIDTH|DDSD_HEIGHT;
    sd.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN|DDSCAPS_SYSTEMMEMORY;
    sd.dwWidth=w; sd.dwHeight=h;
    IDirectDrawSurface7 *off=NULL;
    hr = IDirectDraw7_CreateSurface(dd,&sd,&off,NULL);
    printf("   CreateOffscreen     -> 0x%08lx %s\n",(unsigned long)hr,e(hr));
    if(hr==DD_OK) IDirectDrawSurface7_Release(off);
}
int main(int argc,char**argv){
    HWND w = CreateWindowExA(0,"STATIC","p",WS_POPUP,0,0,64,64,0,0,0,0);
    IDirectDraw7 *dd;
    if(DirectDrawCreateEx(NULL,(void**)&dd,&IID_IDirectDraw7,NULL)!=DD_OK) return 1;
    IDirectDraw7_SetCooperativeLevel(dd,w,DDSCL_EXCLUSIVE|DDSCL_FULLSCREEN);
    for(int i=1;i<argc;i++){ int a,b; if(sscanf(argv[i],"%dx%d",&a,&b)==2) test(dd,a,b); }
    fflush(stdout); return 0;
}

#include <windows.h>
#include <ddraw.h>
#include <stdio.h>
int main(void){
    IDirectDraw7 *dd;
    if(DirectDrawCreateEx(NULL,(void**)&dd,&IID_IDirectDraw7,NULL)!=DD_OK){puts("create failed");return 1;}
    HWND w=CreateWindowExA(0,"STATIC","p",WS_POPUP,0,0,64,64,0,0,0,0);
    IDirectDraw7_SetCooperativeLevel(dd,w,DDSCL_NORMAL);
    DDCAPS hal, hel; ZeroMemory(&hal,sizeof hal); ZeroMemory(&hel,sizeof hel);
    hal.dwSize=sizeof hal; hel.dwSize=sizeof hel;
    HRESULT hr=IDirectDraw7_GetCaps(dd,&hal,&hel);
    printf("GetCaps -> 0x%08lx\n",(unsigned long)hr);
    printf("HAL dwVidMemTotal = %lu bytes (%.1f MB)   <- game requires >= 16 MB\n",
           hal.dwVidMemTotal, hal.dwVidMemTotal/1048576.0);
    printf("HAL dwVidMemFree  = %lu bytes (%.1f MB)\n",
           hal.dwVidMemFree,  hal.dwVidMemFree/1048576.0);
    printf("HAL dwCaps        = 0x%08lx  (DDCAPS_3D=%s)\n", hal.dwCaps,
           (hal.dwCaps & DDCAPS_3D) ? "YES" : "no");
    DWORD tot=0,fre=0;
    DDSCAPS2 sc; ZeroMemory(&sc,sizeof sc); sc.dwCaps=DDSCAPS_VIDEOMEMORY;
    if(IDirectDraw7_GetAvailableVidMem(dd,&sc,&tot,&fre)==DD_OK)
        printf("GetAvailableVidMem: total %.1f MB, free %.1f MB\n",tot/1048576.0,fre/1048576.0);
    fflush(stdout); return 0;
}

/* Replicate EXACTLY what Tropico does at 0x4f9200 and 0x52df6f.
 *
 *   GetAvailableVidMem(&caps{dwCaps=0x10005000}, &total, &free)   -> total at 0x618aa0
 *   fild DWORD [0x618aa0]   <-- SIGNED load
 *   fcomp QWORD 8912896.0   (8.5 MB)
 *   skip IDirect3D7::EnumDevices when value <= threshold
 *
 * Prints the value both ways so the sign overflow is visible, and states which
 * branch the stock exe and the patched exe each take. */
#include <windows.h>
#include <ddraw.h>
#include <stdio.h>

#define GAME_CAPS 0x10005000u          /* TEXTURE | VIDEOMEMORY | LOCALVIDMEM */
#define GAME_THRESHOLD 8912896.0       /* the double at 0x57e488 */

int main(void){
    IDirectDraw7 *dd;
    if(DirectDrawCreateEx(NULL,(void**)&dd,&IID_IDirectDraw7,NULL)!=DD_OK){puts("create failed");return 1;}
    HWND w=CreateWindowExA(0,"STATIC","p",WS_POPUP,0,0,64,64,0,0,0,0);
    IDirectDraw7_SetCooperativeLevel(dd,w,DDSCL_NORMAL);

    DDSCAPS2 sc; ZeroMemory(&sc,sizeof sc); sc.dwCaps=GAME_CAPS;
    DWORD total=0, freem=0;
    HRESULT hr=IDirectDraw7_GetAvailableVidMem(dd,&sc,&total,&freem);
    printf("GetAvailableVidMem(0x%08x) -> 0x%08lx\n", GAME_CAPS, (unsigned long)hr);
    printf("  dwTotal unsigned = %10lu  (%.1f MB)\n", (unsigned long)total, total/1048576.0);
    printf("  dwTotal   signed = %11ld  <- what `fild` loads\n", (long)(int)total);

    int  taken_signed   = ((double)(int)total)      <= GAME_THRESHOLD;
    int  taken_unsigned = total                     <= (DWORD)GAME_THRESHOLD;
    printf("\nstock  exe (signed fild): %s\n",
           taken_signed   ? "SKIPS EnumDevices -> \"Hardware 3D is not available\" (string 1721)"
                          : "enumerates hardware devices -> Hardware 3D offered");
    printf("patched exe (unsigned  ): %s\n",
           taken_unsigned ? "SKIPS EnumDevices -> \"Hardware 3D is not available\" (string 1721)"
                          : "enumerates hardware devices -> Hardware 3D offered");
    fflush(stdout); return 0;
}

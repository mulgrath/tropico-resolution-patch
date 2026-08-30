/* vdprobe -- is this process inside a Wine virtual desktop, and can the PREFIX
 * REGISTRY alone put it there?
 *
 * FINDINGS 100. The Steam edition cannot be given `explorer /desktop=` on a command
 * line (the Play button is the only launch path), so the whole question is whether
 * HKCU\Software\Wine\Explorer produces the same desktop the command line does, and
 * how a process already inside one can tell.
 *
 *   i686-w64-mingw32-gcc -o vdprobe.exe vdprobe.c -luser32
 *
 * Run it three ways in the same prefix -- bare, under `wine explorer /desktop=`, and
 * with the registry values set and nothing on the command line -- and diff the three
 * vdprobe.txt files.
 *
 * Measured 2026-08-25, two monitors:
 *   bare                SM_CMONITORS=2  1920x1080  virtual 4480x1440 at 0,-360
 *   /desktop=,1280x1024 SM_CMONITORS=1  1280x1024  virtual 1280x1024 at 0,0
 *   registry only       SM_CMONITORS=1  1280x1024  virtual 1280x1024 at 0,0
 *
 * FindWindow("__wine_desktop_manager") returns NULL in all three -- the desktop
 * window belongs to explorer.exe and is not findable from the game's process, which
 * is why the proxy records what it armed instead of asking the window system. */
#include <windows.h>
#include <stdio.h>
static BOOL CALLBACK ew(HWND h, LPARAM p){
    char cls[128]="", tit[128]="";
    FILE *f=(FILE*)p;
    GetClassNameA(h,cls,sizeof cls); GetWindowTextA(h,tit,sizeof tit);
    if (cls[0]) fprintf(f,"  top-level class=%-28s title=%s\n",cls,tit);
    return TRUE;
}
int main(void){
    FILE *f=fopen("vdprobe.txt","w");
    char cls[128]="";
    HWND d=GetDesktopWindow();
    GetClassNameA(d,cls,sizeof cls);
    fprintf(f,"GetDesktopWindow class=%s\n",cls);
    fprintf(f,"SM_CMONITORS=%d CX=%d CY=%d VIRT=%d,%d %dx%d\n",
        GetSystemMetrics(SM_CMONITORS),GetSystemMetrics(SM_CXSCREEN),GetSystemMetrics(SM_CYSCREEN),
        GetSystemMetrics(SM_XVIRTUALSCREEN),GetSystemMetrics(SM_YVIRTUALSCREEN),
        GetSystemMetrics(SM_CXVIRTUALSCREEN),GetSystemMetrics(SM_CYVIRTUALSCREEN));
    fprintf(f,"FindWindow(__wine_desktop_manager)=%p\n",(void*)FindWindowA("__wine_desktop_manager",NULL));
    EnumWindows(ew,(LPARAM)f);
    fclose(f); return 0;
}

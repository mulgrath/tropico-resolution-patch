#include <windows.h>
#include <stdio.h>
int main(void){
    HDC h = GetDC(NULL);
    int hr = GetDeviceCaps(h, HORZRES);      /* 8  -> game's 0x60c118 */
    int vr = GetDeviceCaps(h, VERTRES);      /* 10 -> game's 0x60c984 */
    int bp = GetDeviceCaps(h, BITSPIXEL);    /* 12 -> game's 0x60a838 */
    ReleaseDC(NULL,h);
    printf("HORZRES=%d VERTRES=%d BITSPIXEL=%d\n", hr, vr, bp);
    printf("GetSystemMetrics CXSCREEN=%d CYSCREEN=%d\n",
           GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
    printf("-- gate: entry kept if width < %d (index 0 always kept) --\n", hr);
    int t[5][2]={{640,480},{800,600},{1024,768},{1280,1024},{1600,1200}};
    for(int i=0;i<5;i++)
        printf("   [%d] %4dx%-4d  %s\n", i, t[i][0], t[i][1],
               (i==0||t[i][0]<hr) ? "KEPT" : "SKIPPED");
    fflush(stdout);
    return 0;
}

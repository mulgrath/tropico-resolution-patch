/* Load the built proxy the way the game does -- as a DLL whose DllMain runs -- and
 * exit. Nothing else. The point is the tropico-fix.log it leaves next to itself:
 * an ini key's wiring can be checked by reading that log, without a game install
 * and without Windows.
 *
 * What this CANNOT show: any number that only native Windows virtualizes. Wine
 * reports the DPI and virtualizes nothing (FINDINGS 92), so a key that changes
 * DPI awareness shows up here only as the log line saying what it decided.
 *
 * Build:  i686-w64-mingw32-gcc -O2 -Wall -o loadproxy.exe loadproxy.c
 * Run:    cd <dir holding binkw32.dll and tropico-fix.ini> && wine loadproxy.exe
 */
#include <windows.h>
#include <stdio.h>

int main(void)
{
    HMODULE h = LoadLibraryA("binkw32.dll");
    if (!h) { printf("LoadLibrary failed: %lu\n", GetLastError()); return 1; }
    printf("loaded binkw32.dll at %p\n", (void *)h);
    FreeLibrary(h);
    return 0;
}

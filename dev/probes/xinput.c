/* xinput -- press keys and click the mouse on an X display, the way a player would.
 *
 * The Linux half of the unattended run (FINDINGS 128 did it on Windows with
 * SendKeys and mouse_event; tools/rig-run.sh does it here). XTEST injects events
 * at the server, so they reach Wine through the same path a real keyboard and
 * mouse use -- nothing is posted to the game's window queue behind Wine's back.
 *
 *   xinput wait  [SECONDS]      block until a window whose class is "tropico" is
 *                               mapped (default 60 s); prints its id and geometry
 *   xinput rect                 the game window's geometry, or "no Tropico window"
 *   xinput click X Y            move the pointer to X,Y (root coordinates) and click
 *   xinput key   NAME [MS]      press a keysym (Escape, Return, F2 ...) and release it
 *                               MS later (default 250: in a map the game polls the key
 *                               state per frame, and on llvmpipe a frame can outlast
 *                               a short tap -- an 80 ms F2 was missed one run in two)
 *
 * DISPLAY selects the server, so the rig's nested display is just DISPLAY=:9.
 *
 *   gcc -O2 -o xinput xinput.c -lXtst -lX11
 */
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/XTest.h>
#include <X11/keysym.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

static Display *dpy;

/* Wine names the X window after the process: class "tropico.exe", or "Tropico"
 * for the explorer desktop that hosts it. Either is the game on screen. */
static int is_game(Window w)
{
    XClassHint h;
    int yes = 0;
    if (!XGetClassHint(dpy, w, &h)) return 0;
    if (h.res_class && !strncasecmp(h.res_class, "tropico", 7)) yes = 1;
    if (h.res_name && !strncasecmp(h.res_name, "tropico", 7)) yes = 1;
    if (h.res_class) XFree(h.res_class);
    if (h.res_name) XFree(h.res_name);
    return yes;
}

/* Under `wine explorer /desktop` the game is a CHILD of the desktop window (class
 * "explorer.exe"), not a top-level, so the search goes two levels down. */
static Window find_game(Window top, int depth)
{
    Window r, p, *kids = NULL, hit = 0;
    unsigned n, i;
    if (!XQueryTree(dpy, top, &r, &p, &kids, &n)) return 0;
    for (i = 0; i < n && !hit; i++) {
        XWindowAttributes a;
        if (!XGetWindowAttributes(dpy, kids[i], &a) || a.map_state != IsViewable) continue;
        if (is_game(kids[i]) && a.width > 100) hit = kids[i];
        else if (depth > 0 && a.width > 100) hit = find_game(kids[i], depth - 1);
    }
    if (kids) XFree(kids);
    return hit;
}

static int print_rect(Window w)
{
    XWindowAttributes a;
    Window child;
    int x, y;
    if (!w) { puts("no Tropico window"); return 1; }
    XGetWindowAttributes(dpy, w, &a);
    XTranslateCoordinates(dpy, w, a.root, 0, 0, &x, &y, &child);
    printf("Tropico window 0x%lx at (%d,%d) %dx%d\n", w, x, y, a.width, a.height);
    return 0;
}

int main(int argc, char **argv)
{
    Window root;
    if (argc < 2) { fprintf(stderr, "usage: xinput wait|rect|click X Y|key NAME [MS]\n"); return 2; }
    dpy = XOpenDisplay(NULL);
    if (!dpy) { fprintf(stderr, "xinput: cannot open display\n"); return 2; }
    root = DefaultRootWindow(dpy);

    if (!strcmp(argv[1], "wait")) {
        int secs = argc > 2 ? atoi(argv[2]) : 60, i;
        for (i = 0; i < secs * 4; i++) {
            Window w = find_game(root, 2);
            if (w) return print_rect(w);
            usleep(250000);
        }
        puts("no Tropico window");
        return 1;
    }
    if (!strcmp(argv[1], "rect")) return print_rect(find_game(root, 2));
    if (!strcmp(argv[1], "click") && argc == 4) {
        int x = atoi(argv[2]), y = atoi(argv[3]);
        XTestFakeMotionEvent(dpy, -1, x, y, CurrentTime);
        XFlush(dpy);
        usleep(300000);
        XTestFakeButtonEvent(dpy, 1, True, CurrentTime);
        XFlush(dpy);
        usleep(80000);
        XTestFakeButtonEvent(dpy, 1, False, CurrentTime);
        XFlush(dpy);
        printf("clicked at %d,%d\n", x, y);
        return 0;
    }
    if (!strcmp(argv[1], "key") && (argc == 3 || argc == 4)) {
        int hold_ms = argc == 4 ? atoi(argv[3]) : 250;
        KeySym ks = XStringToKeysym(argv[2]);
        KeyCode kc = ks == NoSymbol ? 0 : XKeysymToKeycode(dpy, ks);
        if (!kc) { fprintf(stderr, "xinput: no keycode for %s\n", argv[2]); return 2; }
        XTestFakeKeyEvent(dpy, kc, True, CurrentTime);
        XFlush(dpy);
        usleep(hold_ms * 1000);
        XTestFakeKeyEvent(dpy, kc, False, CurrentTime);
        XFlush(dpy);
        printf("pressed %s\n", argv[2]);
        return 0;
    }
    fprintf(stderr, "usage: xinput wait|rect|click X Y|key NAME [MS]\n");
    return 2;
}

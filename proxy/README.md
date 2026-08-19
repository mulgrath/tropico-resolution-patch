# tropico_fix — runtime patcher (binkw32.dll proxy)

Applies every fix from `../FINDINGS.md` to a **stock, unmodified** `Tropico.EXE` at
runtime, so nothing of PopTop's is redistributed and the DRM-wrapped Steam build is
covered too.

## Install

```
cd <Tropico game folder>
mv binkw32.dll binkw32_orig.dll
cp /path/to/binkw32.dll .
```

Run the game normally. A `tropico-fix.log` appears next to the exe.

To go back: delete `binkw32.dll`, rename `binkw32_orig.dll` back.

## What it does

| # | fix | FINDINGS |
|---|---|---|
| 1 | NOP the desktop-width gate, so a mode exactly as wide as the desktop is not rejected by an off-by-one (`>=`) | §2 |
| 2 | Replace the x87 **signed** VRAM compare with an unsigned one, so Hardware 3D works with no `VideoMemorySize` registry value | §16 |
| 3 | `jge` → `jae` on the second signed VRAM test (texture budget) | §16 |
| 4 | Point slot 4 at the best mode the display actually offers, in **both** the data table and the code compare-chain | §1, §8 |

## How slot 4 is chosen

Slots 0–3 are left stock — they are real modes almost everywhere and already work.
Only slot 4 is chosen at runtime, because §11 caps each slot at its own stock art
width and slot 4's is the largest at 1600.

Candidates must satisfy every constraint in FINDINGS: `width % 4 == 0` (§10, else
the image shears), `width <= 1600` (§11, else an unpainted strip), a width not used
by slots 0–3 (§9, else the slot is unreachable), and the mode must actually exist
(§7). Among survivors it prefers the closest aspect match to your desktop, then the
largest. On a 1920x1080 panel that is **1600x900**; on a 4:3 or 5:4 display it keeps
**1600x1200**. If nothing qualifies, slot 4 is left stock.

## Overriding

Optional `tropico-fix.ini` next to the exe:

```ini
[Resolution]
Width=1600
Height=900
```

Constraint violations are refused (or warned about) and logged rather than applied
silently.

## Why binkw32, and why not DllMain

Both explained at length in the header of `tropico_fix.c`. In short: a `ddraw.dll`
proxy loads too late (ddraw is `LoadLibrary`d from the tail of the very function
holding the gate), and the Steam build's `.text` is still encrypted during DllMain,
so patching defers to the first `GetDeviceCaps` call — which provably precedes the
gate, since the gate consumes that call's result.

## Building

`./build.sh` — needs `i686-w64-mingw32-gcc`.

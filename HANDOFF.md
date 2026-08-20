# Handoff prompt — Tropico terrain width limit

Copy everything below the line into a new session.

---

Resume the Tropico (PopTop, 2001) modernization project. One bounded question this
session — do not broaden it.

## Read first, in this order, before touching anything

- `~/tropico-resolution-patch/ROADMAP.md` — goal and state
- `~/tropico-resolution-patch/FINDINGS.md` — **read §29–§36 carefully**, they are this
  question's entire history
- `~/tropico-resolution-patch/TESTING.md` — seven traps, each of which produced a
  confidently wrong conclusion

## The question

At any screen width above 1600, the game's **terrain** stops being drawn at exactly
x=1600. Everything else — HUD, objects, the framebuffer itself — is fine at the full
width. Find what imposes that limit, and whether it can be patched.

Measured, not assumed:
- Cutoff is at **exactly 1600** on a 1680-wide screen *and* on a 1920-wide screen, so
  the bound is **absolute, not relative to the mode** (§31, column statistics from
  screenshots, x=1598 normal → x=1600 collapsed).
- In **Hardware 3D** mode, objects (trees, buildings) DO draw past 1600; only terrain
  stops. Two draw paths, two width sources (§30).
- The software renderer's framebuffer stride is the real width — pixel addresses are
  `DAT_0060c191 + (DAT_0060c18c * y + x) * 2` (§36). The surface is not the limit.

## What is already eliminated — do not re-do these

| eliminated | how |
|---|---|
| A second resolution table | only one exists in the image, `0x5a0fa0` |
| Derived per-resolution arrays | no 5-element array of widths/heights over any divisor |
| `1600.0f` / `1600.0` | not present, aligned, anywhere |
| Buffer sizes `1600*1200`, `*2` | not present |
| Every `0x640` immediate in the binary | all six accounted for, none is a terrain clip |
| DirectDraw geometry | full `WINEDEBUG=+ddraw` trace: 1877 surfaces at 1920x1080, `1600` appears 5 times in 1.8 GB and all are mode enumerations or pointers |
| Live memory scan for u32 1600 | §32–§34; the two static globals `0x614418`/`0x61abc0` were held at 1920 with no effect |
| `FUN_0046b020`'s `0xC80`/`0x960` clamp | §35–§36, **patched and reverse-tested**: forcing it to 800px did not move the cutoff |

The value is very likely **not stored as 1600 anywhere**. §35 found it stored as `0xC80`
(3200, doubled coordinates) in one place, and that place turned out to be the wrong one.
Consider other unit systems: doubled (×2), tile counts, fixed-point, or `3200/width`
style ratios.

## Artefacts — use these, they cost nothing

```
~/tropico-re/tropico_decomp.c      8.1 MB — all 3276 functions decompiled to C. GREP THIS.
~/tropico-re/tropico-objdump.txt   objdump -d -M intel of .text
~/tropico-re/ghidraproj/           analysed Ghidra 12.1.3 project — reuse with -noanalysis
~/tropico-re/*.java                headless scripts (Java only; PyGhidra is NOT available)
```

Rerun a Ghidra script without re-analysing:

```bash
~/tools/ghidra_12.1.3_PUBLIC/support/analyzeHeadless ~/tropico-re/ghidraproj tropico \
  -process "Tropico.EXE" -noanalysis \
  -scriptPath ~/tropico-re -postScript YourScript.java
```

Ghidra prints constants in **hex** — grepping decompiled C for `1600` finds nothing.
That bug cost a full pass.

## Known-useful addresses

| address | what |
|---|---|
| `0x60c18c` | screen width global (u16), loaded from the table by `FUN_0052e480`. 39 functions reference it |
| `0x60c18e` | screen height global |
| `0x60c191` | framebuffer base |
| `0x5a0fa0` | the resolution table (5 × u32 w,h pairs); slot 4 is at `+0x20` |
| `0x52d15a` | the code compare-chain the proxy patches |
| `0x46b140` | the eliminated clamp (§35/§36) |
| `0x46da20`, `0x46e040`, `0x44da90`, `0x511c90`, `0x52b750` | software rasteriser inner loops using the stride |

## Suggested approach

1. Grep `~/tropico-re/tropico_decomp.c` locally — free, unlimited. Look for the terrain
   tile loop: the ddraw trace showed **2320 surfaces of 128x64**, which are terrain
   tiles, so look for loops stepping by 128 or 64, or column counts like 1600/128 = 12.5,
   1600/64 = 25, 1600/32 = 50.
2. Trace **backwards** from the rasteriser inner loops listed above to whoever computes
   their bounds.
3. Consider that the limit may be a *map/scroll extent* rather than a draw clip — the
   engine may simply believe the visible world is 1600 wide.

## Ground rules, learned the hard way

- **Every claim needs a test whose failure is informative.** Raising a limit and seeing
  no change is ambiguous. LOWERING it is not: if the cutoff moves inward, you have the
  right value. Two confident "found it" calls (§33, §35) died because only the raising
  direction was tested first.
- **Verify the patch applied before interpreting the result.** The proxy logs every
  patch; read `"/mnt/Windows/GOG Games/Tropico/app/tropico-fix.log"`.
- **Reset CFG `0x242` and presets `0x272`/`0x276` to 0 before every run and read `0x242`
  back after.** `tools/tropico-gog.sh` does this and prints a readback. A test that did
  not run the slot you intended looks exactly like one that failed.
- **An identical result across varied inputs means the input is not varying.**
- The owner runs the game; you cannot. Each run costs them a map load, an F2 climb and
  minutes of watching, so **batch your questions and make each run decisive.**

## The test harness

```bash
TROPICO_DISPLAY=HDMI-A-5 TROPICO_NODESK=1 TROPICO_RES=0 \
  ~/tropico-resolution-patch/tools/tropico-gog.sh
```

Then: start a map (loads at 640x480), F2, select 1920x1080. Resolution is forced by
`"/mnt/Windows/GOG Games/Tropico/app/tropico-fix.ini"`:

```ini
[Resolution]
Width=1920
Height=1080
```

The runtime patcher is `~/tropico-resolution-patch/proxy/tropico_fix.c`, shipped as a
`binkw32.dll` proxy, built with `proxy/build.sh`, already installed in the game folder
(stock DLL preserved as `binkw32_orig.dll`). It has `[Scan]`, `[Poke]`, `[Watch]` and
`[Debug]` ini sections for live memory scanning, repeated pokes, hardware write
breakpoints (debug registers work under Wine) and clamp overrides — read the comments
in the source, they explain what each was for.

## If it turns out not to be patchable

Say so plainly and stop. The owner's goal is fullscreen HD; the fallback is rendering at
1600x900 (true 16:9, works today) and letting the compositor upscale. There is a
validated art-rescaling tool at `tools/tropico-vsquash.py` (§28) that vertically rescales
sprite containers by row selection with no pixel decoding — confirmed working in-game.
Do not spend days on the engine before saying it may not land.

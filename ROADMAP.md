# Roadmap

## The goal (project owner, 2026-08-19)

> "I want it to be able to give someone a working version on Linux that doesn't require any
> awkward setups on their part, and provides a more modern experience... I would really like
> to see more resolution support. Maybe some kind of mod is required, but I think it's worth
> it to truly modernize the game."

Tier 2 alone was explicitly **declined** as the deliverable. The target is something you can
hand to another person.

## State

| area | state |
|---|---|
| Launch with no virtual desktop | **works** (§13) — the "DO NOT remove this" premise was wrong |
| Hardware 3D | **restored and permanently patched** (§16) — confirmed in-game with no registry value at all |
| 640x480 / 1024x768 / 1280x1024 | correct |
| 1600x1200 | correct, but needs a virtual desktop — modern panels have no such mode |
| 1600x900 world render | correct, true 16:9, full screen, no shear — confirmed on both a 1080p and a 1440p panel |
| 1600x900 HUD chrome | broken — art authored for a 1200-tall screen |
| 1920x1080 world render | **works** (§44) — full-width terrain and void on Software and Hardware, reduce-shifting either way. Needs `[Resolution] 1920x1080` + `[WorldFix] ObjW=3200`; the auto-picker still will not choose it because `ART_WIDTH_CAP` is 1600 |
| 1920x1080 HUD chrome | **WORKS — confirmed in game (§63).** `tools/tropico-artset.py` generates the full 79-asset set from the user's own `px.PK2`; delivered as loose `data/*.i16`. Residual: rotated text overhangs ~11%, which is 16:9 geometry, not the pipeline (§63.5). |
| Arbitrary-resolution world render | **works** (§47) — verified at 1920x1080 and 2560x1440, same binary, every renderer. Four writes at `0x526220`. Known-good build archived in `known-good/` |
| HUD / UI at any non-stock mode | broken in game, but **no longer blocked**. The engine will not scale HUD art by any route (§50/§60/§61), so a derived art set is required — and §62 decoded the `.iNN` packet format, so that set can now be generated at any width from the user's own files. Remaining work is pipeline and verification, not research. |
| Zoomed detail preview (bottom right) | **fixed** (§47) — was ours, caused by an unguarded write; a size gate separates it from the main viewport at any mode |
| Centring / upscaling | **not needed — dismissed by the owner 2026-08-21.** The intro, menu, terrain and UI all render natively at the panel's own mode, so there is nothing to centre or upscale; 1440p is the same stretch at a larger size. §15 and the gamescope/Proton trade-off below are moot |
| Packaging | **DONE — §72.** One command installs; one command switches resolution in 0.7 s |

Best fully-correct experience today: **1280x1024**, no virtual desktop (the largest mode whose HUD art is right). The world itself now renders correctly at any mode; the HUD is what caps the usable resolution.

Original note follows: Best fully-correct experience today: **1280x1024**, no virtual desktop. A real display mode,
art width matches exactly, pillarboxed on 16:9 — which the brief prefers over stretching.

## Priority 1 — make it packageable

The pieces exist but a user still has to run a script and set a registry value.

1. ~~**Patch the VRAM comparison signed -> unsigned**~~ — **DONE and CONFIRMED, §16.** Not a `cmp` and not
   findable by the planned method: id 1721 is a `.data` constant at `0x59897c`, and the
   comparison is an x87 `fild`/`fcomp` against the double 8912896.0 (8.5 MB, not 16) at
   `0x52df6f`, gating `IDirect3D7::EnumDevices`. Patched to an unsigned integer compare
   (25 bytes) plus `jge`->`jae` at `0x4f92f8`. `probes/ddvidmem.c` confirms the input.
   Owner confirmed the F2 Hardware/Software toggle works with `VideoMemorySize` deleted.
   **New, unattributed:** alt-tabbing during map load raises `DDERR_INVALIDRECT` (§17). Run
   the control in TESTING.md before assuming the §16 patch is or is not responsible.
2. ~~**Decide the resolution strategy.**~~ **DONE.** Owner chose slot-4-only: slots 0-3 stay
   stock, slot 4 is chosen at runtime from `EnumDisplaySettings` under all four constraints.
   Rationale: §11 caps every slot at its own stock art width, so slot 4's 1600 is the only
   width worth competing for and rebuilding the other slots cannot raise the ceiling.
3. ~~**Build the proxy `ddraw.dll`.**~~ **DONE, but as a `binkw32.dll` proxy — see `proxy/`.**
   A ddraw proxy is impossible: ddraw is `LoadLibrary`d from the tail of `0x514d60`, the very
   function holding the gate, so it is handed `DllMain` too late. `binkw32.dll` is a static
   import of both builds. Verified on GOG against a **stock** exe: 4 applied, 0 failed,
   slot 4 -> 1600x900.

   **Remaining:** confirm in-game that F2 offers 1600x900 and it renders; and confirm the
   Steam path end-to-end (the hook installs correctly, but the DRM never released the process
   outside Steam, so decrypt-then-patch is unverified there).

## Multi-monitor (solved, §18)

Wine measures only the primary monitor while the compositor places the window wherever the
launching terminal is, so running on a secondary throws `DDERR_INVALIDRECT` (#150). Verified
not to be a patch bug — the control fails identically. Use
`TROPICO_DISPLAY=<xrandr output>`, which makes that monitor primary for the run and restores
it afterwards. **Confirmed working** — all resolutions correct on the 1440p panel. This is the same root cause family as §15 and is another argument for
gamescope, which would own its own output and sidestep the whole issue.

## Runtime choice (new, §22/§23)

Two independent findings point the same way:

* **Proton gives centring and upscaling for free** (§22) — the tier-4 outcome gamescope was
  meant to provide, and gamescope is still unpackaged on Pop!_OS 24.04.
* **Proton breaks Hardware 3D** (§23) — smears at every resolution; system wine does not.

So neither runtime dominates. System wine is correct but paints top-left (§15) and needs
`TROPICO_DISPLAY` (§18); Proton centres and upscales but loses the hardware renderer. Since
the owner prefers the software renderer anyway, **Proton currently looks like the better
default** — it solves the presentation problems that have no in-exe fix, and costs an option
that was never going to be the default. Worth testing Proton against the GOG build.

## Priority 2 — centring and upscaling (tier 4) — CLOSED, NOT NEEDED

Dismissed by the owner 2026-08-21: the game now renders natively at the target mode end
to end, so there is nothing left to letterbox. The original note follows for the record.

### Original note

XWayland emulates rather than switches modes, so the game sits top-left with black around it
(§15). Not fixable inside the exe.

- **gamescope** is the obvious vehicle: `gamescope -W 1920 -H 1080 -w 1280 -h 1024 -f -- wine ...`
  gives centring *and* integer/fit upscaling. **Not packaged on Pop!_OS 24.04** — needs a
  manual build or another source. Untested.
- Worth testing whether Wine can be made to switch modes for real rather than emulate.

## Priority 3 — the HUD mod (tier 3)

**§50 — ANSWERED: the engine never scales HUD art.** The `.WIN` rect is a *clip*
rectangle (`FUN_0052c1e0` -> `FUN_004e6dd0`), and the class-4 style-0 draw that every HUD
widget uses passes a **position only** to `FUN_00501b90` — no width, no height, no ratio.
Confirmed by the §49 shrink run in both renderers, and cross-confirmed by reduce-shifting
restoring the whole image at full size. So a runtime layout patch cannot fix the HUD, and a
**derived art set at the target resolution is the only correct route** — which makes the
`.iNN` packet control byte (§26) the next investigation, not the HUD itself.

**§48/§49 — the layout pipeline is now decoded.** `.WIN` files are a tagged stream of
widget records carrying x/y/w/h in the virtual 3200x2400 space; `tools/tropico-win.py`
parses 19 of 27 archived files to exact EOF. Widgets whose stored rect is non-zero scale to
any resolution for free; widgets whose rect is **zero** have it recomputed every frame from
the art sprite's own stored PIXEL coordinates, which pins them to the mode the art was
authored for. Of 499 widgets, 37 take that path, and in the in-game HUD exactly **one**
does: `MAINWIN.WIN` widget 17, `int_main.imm` sprite 0 — the whole bottom bar.

Two things follow. §27's unnameable asset is `int_main.imm` (`hash("int_main.i16") =
0x6017ebbb`), so the loose-file route is open again. And the fix ranking now turns on a
single unmeasured fact — **does the sprite blit stretch to its destination rect** — with a
one-run shrink test specified in §49. **Do not write a patch before that run.**

**Note: `app/data/px.PK2` is not stock** — `int_main.i16` was rescaled in place on
Aug 19 and never recorded (§48.0). Restore it from the GOG installer with `innoextract`
before measuring any art.


**§11 is now VERIFIED — see §19.** Art really is per-resolution: 43 assets exist in all five
variants, zero exist as `.imm`, and the loader picks the set by rewriting the extension from a
five-pointer table at `0x5a12d8` indexed by the resolution slot. The name-hash function is
solved and verified too (233/440 known names resolve). `tools/tropico-pk2.py` addresses
archive entries by name.

**The mod is cheaper than feared:** `0x5a12d8` holds *pointers*, so repointing slot 4 at a new
suffix (e.g. `.i09`) adds a widescreen set without touching stock art — one pointer write from
the proxy DLL.

**PK2 format — decoded and validated:**

```c
struct PK2Header { uint32 magic /* 1000 */; uint32 count; };
struct PK2Entry  { uint32 name_hash; uint32 size; uint32 offset; uint8 flag; };  /* 13 bytes */
/* data begins at 8 + count*13 */
```

Validated on `data/px3.PK2`: 674/674 entries satisfy `size == next.offset - offset`.
Archives: `px.PK2` (1902 entries), `px2.PK2` (2223), `px3.PK2` (675), `px4.PK2` (696).

1. ~~Dump all four indices.~~ **Done.**
2. ~~Find the name-hash function.~~ **Done and verified** — §19.
3. ~~Confirm whether five per-resolution sets exist.~~ **Done — they do.** §11 stands.
4. Positions vs art: §12 already shows corner-anchored widgets land correctly from the real
   resolution while fixed art spans do not, so the gap is the **art**, not a position table.
5. ~~**NEXT, and the blocker:** decode the `.iNN` image format.~~ **DONE — §62.** The packet
   format was read out of the leaf blitter `FUN_00538ba0` (not `FUN_00501b90`, which is only a
   dispatcher) and validated byte-exact: decoding and re-encoding every archived UI asset
   reproduces PopTop's bytes identically (214/214 assets, 23246 sprites, 469349 rows).
   `tools/tropico-hsquash.py` rescales horizontally at any width; all 42 `.i16` assets convert
   cleanly to 1920, 2560 and 1280.

6. ~~**NEXT:** combine into one two-axis generator and look at it in game.~~ **DONE — §63.**
   `tools/tropico-artset.py`. No suffix repoint was needed: loose `data/` overrides win
   (§24 now CONFIRMED by observation, §63.1), so the set ships as plain `.i16` files and is
   undone by deleting them. `px.PK2` is never written.

7. ~~Optional polish: patch `.WIN` rects so rotated-text widgets stop overhanging.~~
   **SOLVED AND CONFIRMED IN GAME — §65.** Rotated text is drawn by `FUN_00450b10`
   (`0x450b10`), which renders the string horizontally into an offscreen surface with
   the box's axes swapped and then transposes it (`FUN_00500e70`). The defect is a
   coordinate-space mismatch, the §30/§47 shape: the engine measures the label's length
   through `3200/W` on the way in and `H/2400` on the way out, so at 16:9 it believes
   every rotated label is 25% shorter than it is, centres it against that, and pushes it
   off the bottom. Fix ships in the proxy as `[VText]`, which rewrites the drawer's
   arguments at the call site and is **gated on the mode** so the stock modes stay
   untouched.

   Two corrections fall out. §64.2 is **REFUTED** — loose `.WIN` overrides do NOT load;
   only `.i16` art does (§63.1), because each asset type has its own loader.

   **§66 closes the rest.** `bldgdtl`'s "Owners"/"Wages"/"Rent" **is** rotated text, from a
   third call site (`0x5034d8`, `rot=2`) that §65 had mislabelled "a flip". Settled by
   detouring the wrapper's entry so every rotated draw logs its caller, rather than by
   re-reading the disassembly. Same defect, simpler correction — that site passes no clip,
   so the box is the only lever. Ships as `BldgDH=67 BldgDY=-84`, mode-gated, confirmed in
   game. All rotated text in the game is now correct at 1920x1080.

   **Frozen 2026-08-21** at font scale **1.00 on both axes** — the 0.90 font shrink was a
   workaround for the placement bug and came back out once the placement was fixed; the
   clipping it had been hiding is covered by the room dials instead (§66.4). Four dials,
   all mode-gated: `BoxH=340 BoxDY=-99 BoxDX=-14` for the tabs, `BldgDH=107 BldgDY=-111`
   for the building panel.

   **Open:** the dials are per-mode. 2560x1440 needs its own pass — the ini carries the
   unit conversions and the procedure, so it is a dialling job, not a research one.
   Deriving them from the scale ratio would remove the pass entirely; not attempted.

8. ~~**Build-menu preview offset.**~~ **SOLVED — §71**, and it was a size, not an offset.
   The portrait is left-flush with its ring and 51 px short on the right because it is
   drawn at the stock 280x280 into the regenerated 323x242 hole. Cause: the portraits are
   `brNN.imm`, 183 of them, and only `br00` is written down anywhere — the rest are named
   at runtime, so §48.2's exe+`.WIN` harvest never saw them and they were never
   regenerated. `tropico-artset.py` gains `numeric_family()`, a third name source; the
   identity run now covers 260 assets byte-identical instead of 78. **Confirmed in game by the
   owner 2026-08-21.** §71.4 records 76 UI-art entries that are still unnamed.

9. ~~Startup movie does not play.~~ **SOLVED AND CONFIRMED IN GAME — §67, §68.**
   Not broken and not disabled: the intro is a **one-shot**. `FUN_0047c370` (reached
   unconditionally from WinMain) is guarded by a config field that the very next
   instruction clears, so it plays once ever. `[Intro] Force=1` NOPs that guard.
   Off by default — every-launch playback is a preference, not a fix.

   The proxy was exonerated first by a stock-DLL control run, then four Bink exports
   were turned from forwarders into logging wrappers, which showed Bink healthy and
   `intro_01` never requested. `tools/tropico-stock-run.sh` makes that control
   repeatable and self-restoring.

10. ~~Main menu is a 640x480 window in the top-left.~~ **SOLVED AND CONFIRMED IN GAME
    — §69.** The intro and the main menu now render correctly at **1920x1080**.

    Root cause was not a default and not Wine: the startup **explicitly asks for slot
    0**, because **the menu art was only ever authored at 640x480** — seven assets exist
    solely as `.i06`. Fix is three parts: redirect the startup slot request (one byte
    per site), synthesise the seven missing assets, and remove two destination clamps in
    the movie blit that forbid magnification (`jl` -> `jmp`).

    Five approaches failed first, all recorded in §69 so they are not retried: the
    640x480 clamp at `0x515e58` (wrong branch), the per-screen slot write (never fires),
    substituting the slot at one of its three reads (crash), writing the field during
    display bring-up (#150), and overriding the Bink destination pitch (crash — 1280 was
    correct all along).

11. **Steam build support.** Installed at
    `~/.steam/debian-installation/steamapps/common/Tropico` (flat layout, no `app/`).

    **The masked signatures work.** A 2026-08-19 log from that install shows the DRM
    wrapper leaves `.text` as ciphertext at load, the patcher defers to the GetDeviceCaps
    hook as designed, and then finds everything: resolution table at `0x5a0cc0` (GOG:
    `0x5a0fa0`), gate at `0x514d70`, VRAM at `0x52df3f` — 4 applied, 0 failed. That is the
    build-independence design paying off on a build where every absolute address moved.

    **One art set serves both editions.** Generated at 1920x1080 from the Steam archives,
    all 78 assets come out **byte-identical** to the GOG-generated set. Packaging does not
    need per-edition art — though it should still generate from the user's own archives
    rather than ship the output, since that is what keeps this a patch and not a
    redistribution.

    Brought current 2026-08-21: current proxy, the frozen `tropico-fix.ini`, and the
    1920x1080 art set installed and verified byte-for-byte. **Untested in game since.**

    `tools/tropico-gog.sh` now takes `TROPICO_DIR` and gives each install its own
    wineprefix (`~/.wine-tropico-gog` / `-steam`), overridable with `WINEPREFIX`. It also
    writes **every** `TROPICO.CFG` it finds — the Steam build has one in the root and one
    in `data2/`, observed holding different values, so writing only one is the "test that
    silently ran the wrong slot" trap.

    **First run, 2026-08-21 (owner):** the patch applies and the game runs, but the world
    render is wrong in a way the GOG build is not. Software 3D shows the stale smear past
    the 1600 mark — the §11 symptom the world-painter fix cures on GOG — and Hardware 3D
    shows a full-screen smear with pixels apparently misaligned. So the world-painter
    correction (§ world render, `0x526220`) is either not matching on this build or is
    matching the wrong site. **Deferred by the owner: finish GOG first.** When picked up,
    start from the log — it names every site that matched — rather than from the picture.

12. ~~Scenario-screen map preview tiles at 1920x1080.~~ **SOLVED AND CONFIRMED IN GAME
    — §70.** The inner loop reads the source locked 1:1 to the destination pointer while
    the count is the DESTINATION width, and a source row is only 172 entries — so at
    1920x1080 each row ran into the following source rows (three copies across) and into
    the NEXT MAP's preview, which is what the "colour noise" was. All previews share one
    array with rows stacked consecutively.

    `[Menu] FixPreview=2` magnifies properly: per-pixel nearest-neighbour across, and a
    Bresenham accumulator stepping the source row POINTER down, which advances it exactly
    `srcH-1` times over `dstH` rows and so cannot leave this map. `FixPreview=1` is the
    conservative alternative — correct but drawn at native size.

12. **Packaging — STARTED.** `tools/tropico-install.sh [W H]` installs onto a GOG or
    Steam install in one command, and `--uninstall` reverses it. It finds the install
    (or takes `TROPICO_DIR`), preserves the real `binkw32.dll` as `binkw32_orig.dll`,
    writes the ini from `known-good/` with the mode substituted, and **generates the art
    set from the user's own archives** — nothing derived from the game ships with the
    patch. Every step is verified rather than assumed, and the whole thing is idempotent.

    The one destructive step is guarded: if `binkw32.dll` is already the proxy and
    `binkw32_orig.dll` is missing, it refuses rather than copying the proxy over itself
    and destroying the real Bink — which would take every movie in the game with it.

    **DONE — §72.** The mode is picked from the primary display; a set is staged for
    every connected monitor at install (31 s each) so switching later is a 0.7 s copy via
    `tools/tropico-setmode.sh`; and the mod's fixes are defaults in the C, which took the
    shipped ini from 161 lines to 35. Verified by log-diff against the frozen ini
    (`13 applied, 0 failed`, identical), a byte-identical swap round trip, and a clean
    uninstall (288 files, nothing left behind, archives untouched).

    **Deriving the `[VText]` dials is a NEGATIVE RESULT, not an open task — §72.4.** The
    defect scales with the label's own pixel length, which the argument-rewrite hook
    cannot see, so no formula over the scale ratio is exact for more than one label. The
    five dials stay measurements and now default ON only at 1920x1080. Any other mode
    leaves rotated text stock (~11% overhang) and says so in the log and the installer
    output. The dialling procedure lives in §72.4.

## Ground rules

Read `TESTING.md` first. Five traps, each of which produced a confidently wrong conclusion.
The two most expensive:

- Reset CFG `0x242` **and** presets `0x272`/`0x276` to 0 before every run; read `0x242` back
  afterwards. A test that did not run the slot you intended looks exactly like one that failed.
- Keep one untouched known-good path and re-run it whenever results stop making sense.

And the meta-lesson: an identical result across genuinely varied inputs means the input is not
varying. Verify the input reached the program before theorising about the output.

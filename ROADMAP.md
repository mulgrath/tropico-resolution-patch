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
| 1920x1080 | not reachable by patching; no art set is that wide |
| Centring / upscaling | **not started** — game paints top-left, rest black (§15) |

Best fully-correct experience today: **1280x1024**, no virtual desktop. A real display mode,
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

## Priority 2 — centring and upscaling (tier 4)

XWayland emulates rather than switches modes, so the game sits top-left with black around it
(§15). Not fixable inside the exe.

- **gamescope** is the obvious vehicle: `gamescope -W 1920 -H 1080 -w 1280 -h 1024 -f -- wine ...`
  gives centring *and* integer/fit upscaling. **Not packaged on Pop!_OS 24.04** — needs a
  manual build or another source. Untested.
- Worth testing whether Wine can be made to switch modes for real rather than emulate.

## Priority 3 — the HUD mod (tier 3)

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
5. **NEXT, and the blocker:** decode the `.iNN` image format. The blobs carry no header or
   magic (`defd_scr.i06` begins `7e 79 b1 79 22 00 41 e0`), so they are palettised and/or
   compressed. Nothing can be authored until this is understood. Start from the smallest
   assets (`defd_scr.i06`, 505 bytes) and from the loader that consumes them.

## Ground rules

Read `TESTING.md` first. Five traps, each of which produced a confidently wrong conclusion.
The two most expensive:

- Reset CFG `0x242` **and** presets `0x272`/`0x276` to 0 before every run; read `0x242` back
  afterwards. A test that did not run the slot you intended looks exactly like one that failed.
- Keep one untouched known-good path and re-run it whenever results stop making sense.

And the meta-lesson: an identical result across genuinely varied inputs means the input is not
varying. Verify the input reached the program before theorising about the output.

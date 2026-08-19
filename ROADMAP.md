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
| 1600x900 world render | correct, true 16:9, full screen, no shear |
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

## Priority 2 — centring and upscaling (tier 4)

XWayland emulates rather than switches modes, so the game sits top-left with black around it
(§15). Not fixable inside the exe.

- **gamescope** is the obvious vehicle: `gamescope -W 1920 -H 1080 -w 1280 -h 1024 -f -- wine ...`
  gives centring *and* integer/fit upscaling. **Not packaged on Pop!_OS 24.04** — needs a
  manual build or another source. Untested.
- Worth testing whether Wine can be made to switch modes for real rather than emulate.

## Priority 3 — the HUD mod (tier 3)

**Verify §11 before building on it.** The conclusion that the width limit comes from
per-resolution art is an *inference* from measurement, not a verified fact. The measurements
are solid (clip lands on the slot's stock width, three for three); the explanation was never
checked against the assets.

**PK2 format — decoded and validated:**

```c
struct PK2Header { uint32 magic /* 1000 */; uint32 count; };
struct PK2Entry  { uint32 name_hash; uint32 size; uint32 offset; uint8 flag; };  /* 13 bytes */
/* data begins at 8 + count*13 */
```

Validated on `data/px3.PK2`: 674/674 entries satisfy `size == next.offset - offset`.
Archives: `px.PK2` (1902 entries), `px2.PK2` (2223), `px3.PK2` (675), `px4.PK2` (696).

1. Dump all four indices; group by size/flag to find image blobs.
2. Find the name-hash function in the exe so assets can be addressed by name.
3. Identify the HUD art and confirm whether five per-resolution sets exist. **This confirms or
   kills §11.**
4. If HUD element positions turn out to come from a patchable table rather than baked art,
   that is far cheaper than re-authoring and should be checked first.

## Ground rules

Read `TESTING.md` first. Five traps, each of which produced a confidently wrong conclusion.
The two most expensive:

- Reset CFG `0x242` **and** presets `0x272`/`0x276` to 0 before every run; read `0x242` back
  afterwards. A test that did not run the slot you intended looks exactly like one that failed.
- Keep one untouched known-good path and re-run it whenever results stop making sense.

And the meta-lesson: an identical result across genuinely varied inputs means the input is not
varying. Verify the input reached the program before theorising about the output.

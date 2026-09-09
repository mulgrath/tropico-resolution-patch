# Config reference: keys not in the shipped ini

`known-good/tropico-fix.ini` documents 14 keys (the ones a player might
plausibly want to touch: resolution, which monitor, whether to ignore display
scaling, whether to force fullscreen, hardware 3D, art generation, the intro movie, and the top-level
`Enable` switch for the world/text/vtext fixes). Every other key the code
reads is documented here instead — support knobs, tuning dials, and one
family of fixes that only *look* like probe leftovers.

None of these need to be set. Every key below keeps the default it shipped
with; this file exists so the reasoning behind that default is not lost, not
to invite tuning.

For the full story behind any of these, see `dev/FINDINGS.md`; only a
summary is repeated here.

## `[Display]`

### `FollowLaunchMonitor` (default `1`)

When the patch has decided which monitor to run on (see `DeviceSelect` and
`SetPrimary` in the shipped ini), this key decides whether it also *adopts
that monitor's own mode* rather than the primary's mode. On by default: it is
the behaviour "run at the resolution of the screen you launched from," which
is the whole point of the monitor selection above it. Set to `0` to keep the
mode fixed while still picking the monitor.

The adopted mode has to fit the desktop as Windows reports it. Since FINDINGS
132 the DLL declares per-monitor DPI awareness in DllMain on native Windows, so
that desktop is the panel itself and the launch monitor's own mode always fits.
The check stays for the cases where awareness could not be declared -- there a
DPI-unaware process is given the scaled desktop, and FINDINGS 127 (issue #1)
is what happens without it: a 4K primary at 125% beside a second monitor was
adopted at 3840x2160 into a 3072x1728 desktop and the game drew only a corner
of its picture -- and for a Wine virtual desktop. When the launch monitor is
already the primary, its own mode (from `EnumDisplaySettings`, never
DPI-virtualized) is adopted only if it fits `SM_CXSCREEN`; otherwise the picker
chooses inside that desktop exactly as with one monitor. A launch monitor that
is not the primary is adopted as before: on Windows it is driven as a
DirectDraw device, under Wine it is about to become the primary, and neither
is measured by `SM_CXSCREEN` at this point.

With a single monitor nothing is adopted and the key has no effect: the picker
chooses the best mode inside the desktop as Windows reports it, which on
native Windows is the monitor's own resolution whatever the display scale (a
4K panel at 150% plays at 3840x2160). That is the owner's decision of
2026-09-07 (FINDINGS 132), reversing the scaled-desktop default 1.4 and 1.5
played (FINDINGS 126), after the measurements of FINDINGS 128 and 131: a
DPI-unaware window is drawn by the desktop's factor, and even a mode the game
switches to brings that mode's own scale with it, so the only picture that is
always whole is the aware one. A player who wants a smaller size types it under
`[Resolution]`, which is judged against the monitor's mode list; a listed size
above the panel (a GPU-scaled 4K mode on a 1440p panel) is kept too. Where the
awareness call is refused because something set it first (the Steam client's
launch, a compatibility flag) nothing changes; where it fails outright (a
Windows before 1703) the game plays inside the scaled desktop as 1.5 did, and
the log says so.

An explicit `[Resolution]` beats the adopted mode either way (since
2026-09-05; before that the adopted mode was read first and a typed
resolution was silently lost on any two-monitor Windows desktop). The log
names whichever lost.

## `[Menu]`

### `Slot` (default: `4` if `data\setuplb.i16` exists, else `-1`)

Which mode slot the menu/intro renders at. Conditioned on the presence of
the synthesised 640x480-only menu assets rather than defaulting on
unconditionally: doing that would break the menu with a missing pack-file
error for anyone who dropped the DLL in without running the installer. An
explicit ini value always wins, including `-1` to force stock behaviour.

### `FixPreview` (default `2`)

Installs the preview-window fix (s46-era). The value is a mode flag passed
straight to `patch_preview_fix()`, not a boolean; `0` disables it.

### `FixMovieScale` (default `1`)

Installs the blit-scale correction for the menu/intro movie window.

### `FixHudMovie` (default `1`)

Installs the HUD movie fix (the in-game advisor clips).

### `FixMoviePitch` (default `0`, off)

Feeds `g_bink_pitch`, which gates the pitch correction inside
`my_BinkCopyToBuffer` (see `proxy/tropico_fix.c`, the Bink section). The game
passes a movie-width pitch, but the destination surface's real pitch follows
the mode width; at anything wider than 640x480 that mismatch tiles the video.
Off by default because the correction rests on an inference — that the
destination surface's pitch tracks the mode width, true for a DirectDraw
primary but not something queryable through this interface — rather than a
guarantee.

## `[WorldFix]`

These eleven keys tune the world-viewport fix (s43/s82). `Enable` (shipped,
default `1`) is the only one meant to be touched; the rest exist so the fix
can be re-derived or disabled piecewise if a future game build changes the
constants it depends on.

- **`Force`** (default `1`) — write the corrected values unconditionally
  rather than only when the pre-patch value matches `Match`/`HMatch`. Needed
  because `Width` and `Height` default to the current mode, which makes a
  simple equality check a no-op the moment the ini stops spelling them out.
- **`Guard`** (default `-1`, meaning auto) — the gate value the patched code
  compares against. Auto mode caps at the stock width (1600) rather than
  `mode_width / 2`, because the naive `m.w/2` guard breaks above 3200-wide
  modes (FINDINGS s82) — every mode wider than 3200 is affected, not just 4K.
  `0` disables the gate entirely.
- **`Match`** (default `1600`) — the stock image-pixel width the patch looks
  for before rewriting it. `0` disables only the image-width half of the fix.
- **`Width`** (default `0`, meaning "use the current mode width") — the
  replacement image-pixel width.
- **`HMatch`** (default `864`) — the stock image-pixel height to match.
- **`Height`** (default `0`, meaning "use the current mode height") — the
  replacement image-pixel height. Added after `Width`'s fallback shipped;
  without it the height write was silently skipped whenever the ini didn't
  spell `Height` out, while the width still followed the mode — a half-fix
  that gave no error.
- **`Ctor`** (default `0`, off) — also patch the viewport constructor
  (`patch_world_viewport`), a separate call site from the draw-path fix
  above. Off by default because the draw-path fix alone was what was
  verified; this is a second, narrower correction for a different code path.
- **`ObjMatch`** (default `2666`), **`ObjW`** (default `3200`),
  **`ObjHMatch`** (default `1920`), **`ObjH`** (default `2400`) — the same
  match/replace pair as `Match`/`Width`/`HMatch`/`Height`, but for the
  object-space extents rather than the image-pixel extents.

## `[Text]`

### `ReadoutColour` (default `32767` / `0x7fff`, white)

The RGB555 colour used to repaint the bottom-bar readout text, which PopTop
otherwise leaves an unreadable grey once the world fix is active. Decimal in
the ini because `GetPrivateProfileIntA` does not parse hex; `30653` /
`0x77bd` is the near-white the engine itself uses at palette entry 23, offered
as an alternative in FINDINGS if the pure-white default looks wrong on a
particular display.

## `[FrameCount]`

### `Enable` (default `0`, off)

Turns on a periodic frame-rate log line. Intercepts nothing the game relies
on — `Blt` is forwarded untouched — so it is safe to enable for diagnosis but
serves no purpose in normal play, which is why it defaults off.

### `Interval` (default `5`, seconds)

How often the frame-rate line is logged when `Enable=1`. Clamped to a minimum
of 1.

## `[VText]` — the rotated tab-label fix's dials

**These read like probe knobs but are not.** They are the tuning dials of a
shipped fix — the correction for PopTop's rotated tab labels overhanging their
tabs — and default to **on** at 16:9 through `vt_dialled`, an aspect-ratio
test computed from the live mode (`1.77 < width/height < 1.79`). An earlier
draft of this refactor nearly deleted this whole family as leftover
diagnostics; it should not be repeated. `[VText] Enable` (shipped, default
`1`) is the top-level switch; `Probe` was the only genuinely dead key in this
family and is the one that was removed.

The defect is `0.5 * (1 - ys/xs) * label_px`, a function of aspect ratio
alone (FINDINGS 86, correcting 72.4's claim that it wasn't derivable). Since
`ys/xs` is fixed at every 16:9 mode and the font scale factor cancels out of
the correction, one confirmed set of numbers is correct at every 16:9
resolution — which is why these are constants rather than something computed
per-mode.

- **`Fix`** (default: `1` at 16:9, else `0`) — installs the `patch_vtext_probe`
  hook. Requires `FixW`/`FixH` to be set (they default to the live mode) or it
  is refused with an error, because an ungated correction would break every
  mode the F2 resolution ladder passes through.
- **`FixW`**, **`FixH`** (default: the current mode) — the mode the `Fix`
  correction is gated to.
- **`BoxH`** (default: `340` at 16:9, else `0`), **`BoxDY`** (default: `-99`
  at 16:9, else `0`), **`BoxDX`** (default: `-14` at 16:9, else `0`) — the
  measured box-geometry correction, sized for the longest label (a
  compromise, not exact for every string — see FINDINGS 86).
- **`Entry`** (default: `1` at 16:9, else `0`) — installs
  `patch_vtext_entry`, a second hook gated the same way as `Fix`.
- **`BldgDH`** (default: `107` at 16:9, else `0`), **`BldgDY`** (default:
  `-111` at 16:9, else `0`) — the building-label variant of the same
  correction. Installed whenever `Fix` is armed; there is no separate
  building-only default because the hooks themselves are the fix.
- **`DX`**, **`DY`**, **`ClipH`** (default: `-1000`, the "absent" sentinel —
  0 and negative numbers are legal values) — a lower-level displacement/clip
  correction applied by `patch_vtext` directly, independent of the `Fix`
  block above. `DY`/`DX` are validated as signed-byte displacements
  (`-128..127`) because that is the width of the value they overwrite.

Only 16:9 has a confirmed dial set. At 4:3, `ys/xs` is 1 and the defect is
zero, so nothing needs correcting. Any other aspect is left stock — labels
may overhang — and the log says so; FINDINGS 86 has a predicted 16:10 set
that has not been confirmed in-game.

## `[Art]`

### `Generate` (shipped, default `1`)

Build the interface art set for the mode at launch, into `data\`, keyed by the
marker `data\ARTSET-MODE.txt` (mode, archive list, generator revision).

### `FontNearest` (shipped as a comment, default `0`)

Nearest-neighbour instead of the box filter for the fonts, for a fractional scale
that reads soft. Since FINDINGS 130 a scaled font's glyphs are drawn from the larger
size of the same face where the archives have one and the shape check passes; those
glyphs are box-resampled from the master whatever this key says, held inside the
plain resample's row and column weights (FINDINGS 135), and the key only governs the
glyphs that keep the plain resample. At exactly 2.0 (a 4K mode) the two
filters are identical anyway.

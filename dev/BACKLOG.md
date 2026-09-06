# Backlog: user requests under consideration

Items that came in from real users of the released patch, with an honest reading of
what each would take against the code as it stands. Nothing here is promised. An item
leaves this file when it ships (and its reasoning moves to FINDINGS/CONFIG-REFERENCE)
or when it is declined (and the reason is recorded here so it is not re-litigated).

Defaults do not change for any item below. Every one is an opt-in that a player who
never opens `tropico-fix.ini` will never see.

## 1. Keep the intro movie and menu at 4:3

**Request.** The intro and the main menu are drawn at the slot-4 mode (16:9 on most
screens), so the 640x480 originals are stretched wide. The user wants them pillarboxed
at their authored aspect instead.

**What the stretch actually is.** The menu runs at the full mode because the startup
asks for slot 0 by name and `patch_menu_slot()` rewrites that to slot 4 (FINDINGS 69.4).
The seven menu-only assets exist at 640x480 and nothing else, so the art generator
synthesises 16:9 versions of them by resampling (69.5). The intro plays through the
same window and reaches the screen via the movie blit, whose destination clamp the
patch removes so the scaler may magnify past the source (`patch_blit_scale`).

The mode itself, the text scale and the VText dials are not involved: those are set by
the mode, and the mode would stay 16:9. So the concern that this fights the 16:9 work
is smaller than it looks. What the request touches is only how the seven assets and the
movie land inside that mode.

**Three ways to do it, worst to best.**
- `[Menu] Slot=-1` already exists and leaves the menu at a real 640x480 mode. On
  Windows the monitor or GPU then decides whether that is pillarboxed or stretched, and
  on Wine it sits in the corner of the desktop (69.2). It also re-enters the paths
  §73 and §79 had to fix. Not a feature, a fallback. Decline this reading.
- Pillarbox the movie only: change the destination rectangle in the movie blit path to
  a centred 4:3 rect. Contained in our own hook. Does nothing for the menu.
- Pillarbox the menu assets: have the generator pad the seven assets to a centred 4:3
  box with black bars instead of stretching. The hard part is hit-testing: the menu's
  buttons are `.WIN` widgets whose rects are scaled per-axis from the 3200x2400
  virtual canvas, so padding the art without moving the widgets puts the buttons
  where the art no longer is. The HUD tools (`tropico-hsquash.py`,
  `tropico-vsquash.py`) already remap widget rects for other screens and the generator
  already reads `.WIN` records, so the machinery exists; whether the menu widgets go
  through the same per-axis scaling has to be measured, not assumed.

**Open questions before it is even scheduled.**
- Do the menu, ranking, hall-of-fame, folder and credits screens hit-test through
  `.WIN` rects scaled per-axis, or through the art? One probe answers it.
- The scenario preview (`FixPreview`) lives in the same screens and was calibrated for
  the stretched layout. It would need the same treatment.
- Does the movie destination come from the same `.WIN` rect as the menu, so that one
  remap covers both, or does it need its own rect change?

**Size.** Medium if the widgets remap cleanly, larger if they do not. Worth a probe;
not worth committing to before the probe.

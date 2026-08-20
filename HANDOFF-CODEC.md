# Handoff prompt — decoding the Tropico `.iNN` packet format

Copy everything below the line into a new session.

---

Resume the Tropico (PopTop, 2001) modernization project. One bounded goal: **decode enough of
the `.iNN` pixel packet format to WALK it** — far enough to duplicate or drop a horizontal
span inside a row without decoding pixels — so that a derived art set at 1920x1080 and
2560x1440 becomes possible. This is the last blocker on the whole project.

Everything about the engine side is finished. Do not reopen it.

## Read first, in this order

- `~/tropico-resolution-patch/ROADMAP.md` — goal and current state
- `~/tropico-resolution-patch/TESTING.md` — the seven traps, each of which produced a
  confidently wrong conclusion
- `~/tropico-resolution-patch/FINDINGS.md`:
  - **§25–§28** — the container format, per-sprite x/y/w/h, and row framing. This is the
    foundation, it is verified, do not re-derive it.
  - **§60–§61** — why the engine cannot scale HUD art by any route, and the current partial
    state of the packet decode. §61.3 is your starting point.
  - **§48, §50, §59** — the HUD layout pipeline, if you need context for why this matters.
    Skim only.

## Why this is the remaining task

The engine will not scale HUD art. That is now established three times over and is closed:

| level | finding |
|---|---|
| per widget | the `.WIN` rect is a **clip**; the style-0 draw passes a position only (§50) |
| per sprite | style 1 stretches **one piece** of a multi-piece sprite — hence the repeated chrome (§60) |
| per piece | `FUN_00501b90` has no `fdiv`, no ratio table, no scaling arithmetic at all (§61.1) |

So the art must arrive already the right size. Vertical rescaling is **solved** (§28: rows are
self-contained length-delimited records, so it is row selection, not a codec). Horizontal is
not, and every interesting target changes the width from 1600.

**The key reframe (§61.2): you do not need to decode pixels, only to walk packets.** If you can
find packet boundaries within a row you can duplicate or drop a span of them, copying PopTop's
own bytes verbatim, exactly as §28 does one level up with rows.

## What is established — do NOT re-derive

| fact | where |
|---|---|
| Row framing: `b < 0x80` -> length `b`, 1-byte header; `b >= 0x80` -> length `((b&0x7f)<<8)\|next`, 2-byte header; length counts the header. **5494/5494 sprites frame exactly** | §28 |
| A sprite's payload is `h` such rows followed by a single `0xC0` end-of-sprite byte | §28 |
| `c < 0x80` is a **literal run of `c` palette indices**, capped at 127. `mwspeed.i16` parses **555/555** rows on that rule alone; `brempty.i16` (277 wide) opaque rows are `7f`+`7f`+`17` | §61.2 |
| Per-sprite `x`/`y`/`w`/`h` are plain int16 in a 13-byte block header; the chain lands on EOF for 214/219 assets | §26 |
| A row's decoded pixel count must equal the sprite's `w`. That is your correctness oracle | §26 |

## What is NOT established

* The meaning of opcodes `>= 0x80`. Treating `c >= 0xc0` as a transparent skip of `c & 0x3f`
  lifts whole-row parsing from ~11% to **1947/4337 rows (45%)** across four assets — partially
  right, definitely incomplete.
* The `0x80..0xbf` range. It occurs in the data, but three different readings of it
  (`rle6`, `rle5`, `rle6+2`) all scored **identically**, which means none was being exercised.
  It does something else again.
* Whether packet boundaries can be found without full semantics. This is the actual question —
  a walker needs only each opcode's *length*, not its meaning.

## Method — this matters more than any individual fact

**Read the decoder in the exe. Do not enumerate opcode models.** Guess-and-check on encodings
is the exact shape of failure this project keeps repeating, and the previous session burned
most of a turn on it before stopping.

Starting points, from §61.3:

* the piece loop in `FUN_00501b90` (the style-0 blit) from `0x501dd1`; piece count is the byte
  at `[desc+0x04]`, records are 0x15 bytes each at `[desc+0x1a]`, fields `x,y,w,h` are int16 at
  record `+0`,`+2`,`+4`,`+6`
* the dispatch is **not** a plain `cmp reg,0xc0` — no such site exists in the blit — so expect a
  jump table on the opcode byte, or a sign/shift test
* `FUN_004eb330` (union bounding box over pieces) and `FUN_004eb5f0` (fetch one piece record)
  are the two accessors, already understood
* validate every hypothesis against the oracle above: **every row of every sprite, or it is
  wrong.** §26 and §28 were both established that way and both held up.

## The failure pattern from the previous session, so it is not repeated

Five failures, one shape — acting on a mechanism that had already been written down:

| run | what happened |
|---|---|
| §50.4 | measured a field consumed by a branch no shipped widget uses |
| §51.1 | tested a stretch under Software, where the branch that stretches never runs |
| §53 | multiplied a field every frame that the engine computes once — it compounded |
| §55 | read a factor from a log line printed 20 s after the value was consumed |
| §58 | zeroed a write-once field, permanently and unrecoverably |

The rules that earned their place:

- **Before writing a field, establish how often the engine writes it.** Write-once fields
  tolerate no accumulating edit.
- **Never read-modify-write engine state from an instrument.** Learn a value once and replay it
  absolutely, so a probe can be switched on and off without leaving damage.
- **An instrument that can only return "clean" has told you nothing.** Give every scan a
  positive control in its own input and assert on it. One scan reported 0 anomalies out of 154
  while comparing nothing, because of an argument-order bug.
- **Vary one thing.** A control that changes two things and concludes about one half is
  TESTING.md's opening trap, and it was self-inflicted twice.
- **Look at the picture.** The owner diagnosed §60 from two screenshots after several runs of
  increasingly elaborate instrumentation. The repeated chrome was visible the first time it
  drew.

## State of the tree

- `app/data/px.PK2` is **stock**, restored from the GOG installer and verified byte-identical
  (§48.0). `int_main.i16` sprite 0 reads `x=0 y=695 1600x505`. Keep it that way; measure from
  copies.
- `app/binkw32.dll` and `app/tropico-fix.ini` are the **known-good** §47 build. The HUD probes
  from the previous session are preserved as `proxy/binkw32_chrome8.dll` and friends if you
  ever need them, but this task needs no game runs at all — it is pure file archaeology plus
  static reading.
- `tools/tropico-imb.py` parses containers, `tools/tropico-win.py` parses `.WIN` layouts,
  `tools/tropico-vsquash.py` does the solved vertical rescale by row selection,
  `tools/tropico-pk2.py` addresses archive entries by name.
- `~/tropico-re/`: `fn.sh` (decompiled function by name), `cg.py` (call graph), `whichfn.py`
  (address to function), `peread.py`.

## Deliverable

1. A FINDINGS section decoding the packet format, validated the §26 way — every row of every
   sprite, with the count stated.
2. `tools/tropico-hsquash.py`, or an extension of `tropico-vsquash.py`, that rescales a sprite
   **horizontally** by duplicating or dropping spans of packets, writing only bytes PopTop
   wrote.
3. If the format turns out not to permit that, say so plainly with the evidence. "This cannot
   be done this way" is an acceptable and useful answer, and at that point the honest
   recommendation is the compositing route (§50.6 Option 4 — Proton or gamescope upscaling a
   correct 1600x1200 image), which needs none of this.

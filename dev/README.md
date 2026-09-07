# dev/

Everything in this directory is for working **on** the patch. None of it ships:
no release tarball or zip contains anything from `dev/`, and `make-release.sh`
builds its payload from an explicit list that does not include this directory.

- `FINDINGS.md` — the reverse-engineering record. Every address the patch writes,
  with the evidence that justifies it.
- `TESTING.md` — how to test this without fooling yourself. Read before testing.
- `CONFIG-REFERENCE.md` — the ini keys that are not in the shipped file.
- `BACKLOG.md` — user requests under consideration, each with what it would take.
- `specs/` — design documents.
- `probes/` — standalone probe programs, built by hand when a question needs one.
- `logs/` — captured traces that FINDINGS.md cites as evidence.
- `tools/` — three checks, each run on its own: `code-equivalent.sh` (do two
  builds differ only in data?), `ini-doc-check.py` (does the shipped ini
  advertise a key the code ignores?), `sections.py` (resolve a section banner
  to a line range). Plus the Windows scaling harness (FINDINGS 128, TESTING
  trap 8): `win-dpi-scale.ps1` (read or set a monitor's display scale),
  `win-scaling-run.ps1` (one unattended run: verify the scale, launch,
  photograph, read the window's and the process's DPI awareness, kill, verify
  again), `win-screenshot.ps1`, and `win-procenv.ps1` (a running process's
  environment and parent, which is how the Steam client's `__COMPAT_LAYER` was
  found). And its Linux counterpart on the nested rig (FINDINGS 129):
  `rig-run.sh` (one unattended run: launch, ESC through the intro, photograph
  the menu, click TUTORIAL, photograph the map, kill, keep the log block) with
  `probes/xinput.c` for the keyboard and mouse.
- `WINDOWS-TRIP.bat` — the manual Windows test pass.

## Recovering deleted instruments

The 2026-08 public-release refactor removed the in-DLL research probes. They are
in history, not gone. To read one back:

    git log --oneline --all -- proxy/tropico_fix.c
    git show <sha>:proxy/tropico_fix.c > /tmp/old.c

Recovery SHAs are recorded in the commit messages of the deletions themselves;
`git log --grep='probes:'` finds them.

Cursor-probe recovery point (pre-deletion state of the cursor probe, the call-site
sweep, and the Wine-vs-X comparison): 4119ccd6b99538a15f1ac9983117b1467f18bd11

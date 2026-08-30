# dev/

Everything in this directory is for working **on** the patch. None of it ships:
no release tarball or zip contains anything from `dev/`, and `make-release.sh`
builds its payload from an explicit list that does not include this directory.

- `FINDINGS.md` — the reverse-engineering record. Every address the patch writes,
  with the evidence that justifies it.
- `TESTING.md` — how to test this without fooling yourself. Read before testing.
- `CONFIG-REFERENCE.md` — the ini keys that are not in the shipped file.
- `specs/` — design documents.
- `plans/` — implementation plans.
- `probes/` — standalone probe programs, built by hand when a question needs one.
- `logs/` — captured traces that FINDINGS.md cites as evidence.
- `tools/` — the refactor verification harness.
- `WINDOWS-TRIP.bat` — the manual Windows test pass.

## Recovering deleted instruments

The 2026-08 public-release refactor removed the in-DLL research probes. They are
in history, not gone. To read one back:

    git log --oneline --all -- proxy/tropico_fix.c
    git show <sha>:proxy/tropico_fix.c > /tmp/old.c

Recovery SHAs are recorded in the commit messages of the deletions themselves;
`git log --grep='probes:'` finds them.

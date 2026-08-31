# Refactor decision record — 2026-08-30 public-release refactor

Every judgment call made while executing the public-release refactor plan, in the
order it was made. The plan itself was a task list for work now finished, so it is
in history rather than the tree:

    git show a8563f7:dev/plans/2026-08-30-public-release-refactor.md

Kept because several of these are corrections to the spec and plan themselves: the
section-banner deletion unit turned out to be unsound, and four shipped fixes were
nearly deleted for sitting in sections named after probes. Anyone revisiting this
code should read Rulings 5, 9, 10 and 11 before trusting a section boundary.

---


Spec: dev/specs/2026-08-30-public-release-refactor-design.md (read, authoritative)
Branch: 1.3 (not main). Ruling: branch 1.3 IS the isolated workspace under the
project's release-branch policy (master = current release only; work on a
version-named branch). No worktree created — it would add indirection to an
established workflow. Cost if wrong: none material; work is committed on 1.3
either way and can be rebased.

## Pre-flight conflict scan

Pairs sharing a file or interface:

| Tasks | Shared | Produces -> Consumes | Finding |
|---|---|---|---|
| 1 -> 2..17 | dev/tools/* | sections.py --range; refactor-verify.sh; baseline/ | **CONFLICT (fixed)** — see Ruling 2 |
| 2 -> 8 | dev/README.md | T2 creates; T8 appends cursor recovery SHA | clean |
| 2 -> 13 | README.md | T2 corrects moved paths; T13 rewrites wholesale | clean (T13 supersedes) |
| 2 -> 17 | tools/make-release.sh | T2 repoints moved paths; T17 runs it | clean |
| 2 -> 14,15 | packaging/ | T2 moves WINDOWS-TRIP.bat out; T14/T15 edit other files | clean (disjoint) |
| 2 -> 17 | known-good/binkw32.dll | T2 step 9 runs make-release, which rebuilds it | **CONFLICT (fixed)** — see Ruling 3 |
| 3 -> 4,5,6 | proxy/tropico_fix.c | T3 lifts wfb_read*/fix_*/hook_import to shared; T4/T5 delete their former homes; T6 scaling mode calls them | clean *provided T3 precedes* — plan order enforces |
| 4..10 -> 11 | ini reads | each task drops its own keys; T11 audits the remainder | clean |
| 11 -> 12 | Tier 1 key list | T11 confirms 13; T12 documents exactly those 13 | clean (identical list both places) |
| 11 -> 13,14 | dev/CONFIG-REFERENCE.md | T11 creates; T13/T14 may point at it | clean |
| 16 -> 1 | section banners | T16 renames banners that sections.py matches on | clean — T16 runs after every deletion; no later task calls sections.py |
| 12 -> 17 | known-good/tropico-fix.ini | T12 rewrites; T17 ships it | clean |

Per-task self-agreement: T1 (after Ruling 2), T2 (after Ruling 3), T3-T17 each
checked — the files a task creates match the files it later touches, and the
verification each specifies matches the change each specifies. No task
mandates anything the review rubric treats as a defect.

Ruling 1: branch 1.3 is the isolated workspace; no worktree. Cost if wrong: none
  material — work is committed on 1.3 and can be rebased.
Ruling 2: Task 1's baseline derived its 21 delete ranges from hard-coded line
  numbers, but Task 1's own Step 2 deletes g_slot_out at line 173 -- shifting
  every range by one and misclassifying boundary-line addresses. Amended to
  resolve ranges through sections.py and assert they total 3,523. Cost if wrong:
  the address invariant weakens to near-useless and a deleted patch site could
  pass unnoticed. Fixed before dispatch.
Ruling 3: Task 2's release check runs make-release.sh, which rebuilds
  known-good/binkw32.dll because Task 1 made the source newer -- so `git add -A`
  would commit a rebuilt DLL inside the "touched no C" commit. Amended to restore
  both DLLs and assert clean. Cost if wrong: a confusing commit and a reference
  DLL built from a half-finished refactor. Fixed before dispatch.

Task 1: dispatched (implementer, sonnet) BASE=bc983fc
Task 1: BLOCKED round 1 -- implementer correctly refused Step 2's premise.
Ruling 4: the tree has SIX warnings, not one. My survey piped build.sh through
  `tail -5` and saw only the last. Three are -Wreturn-type on for(;;) thread
  functions (heartbeat_thread @2747, a chrome watcher @5536, hudprobe_thread
  @7898) which never return -- not bugs. Two are unused locals in scaling mode;
  one is g_slot_out. Gate changed from "zero warnings" to "never above the
  captured baseline", with Task 11 driving it to zero by adding unreachable
  `return 0;` to the surviving threads and deleting the two locals. Cost if
  wrong: a genuinely new warning could hide under the baseline between Tasks 1
  and 11 -- bounded, because Task 11 asserts zero and every later task holds it.
Ruling 5: patch_hud_probe + hudprobe_thread (300 lines) are HUD probe code
  living INSIDE the kept "scaling mode" section; section-level classification
  missed them. Added as a 22nd delete range (located by exact definition-line
  match, since line 145 is a forward declaration) so the address baseline does
  not record their addresses as kept. Deletion happens in Task 6 once Tasks 5
  and 6 remove both callers and the compiler names them. Total delete now 3,823
  lines, not 3,523. Cost if wrong: 300 lines of probe code ship, and the
  verifier reports surplus addresses rather than missing ones -- visible, not
  silent.
Task 1: complete (commit 55ecc04, review clean -- spec compliant, quality approved)
Task 1: minor (deferred): implementer rewrote Step 7's commit message rather than
  transcribing it, because the brief's draft asserted "3,523 lines" and "a
  zero-warning build", both false after Ruling 4. Reviewer endorsed the deviation.
  No action needed; noted for the final review.
Ruling 6: Task 3 lifts ONLY hook_import. The original cross-reference check
  counted the whole scaling-mode section as kept, so wfb_read32/16 and
  fix_near/fix_short appeared to have shipped callers at lines ~7641/7730/7774/
  7800. Those lines are inside patch_hud_probe..end, which Ruling 5 classifies as
  probe -- so those three helpers have ZERO callers that survive and die with
  their host sections in Tasks 4 and 5. Lifting them would have preserved four
  functions nothing calls. Cost if wrong: a genuinely-needed helper is deleted,
  which the build catches immediately as an undeclared identifier.
  Note: baseline kept-address count is 44, not the 51 quoted pre-Ruling-5. The 7
  difference is addresses reachable only from the hudprobe block.
Task 2: dispatched (implementer, sonnet) BASE=95e755f
Ruling 7: the plan's release checks called make-release.sh with no version
  argument, so it printed usage and verified NOTHING -- a green check that
  proved nothing, in the two tasks whose job is proving dev/ does not ship.
  Both now pass a throwaway version (dist/ is gitignored) and assert against
  BOTH artifacts, tarball and zip. Cost if wrong: none; strictly more checking.
Ruling 8: packaging/windows/READ-ME-FIRST.txt was LF in the working tree while
  .gitattributes marks it eol=crlf, so make-release REFUSED to build the Windows
  zip. Not a code defect -- the blob is correctly LF and git converts on
  checkout; this tree's copy predated the attribute. Fixed by deleting and
  re-checking-out the file (git status clean afterwards, confirming staleness
  rather than a change). Verified both artifacts now build and neither contains
  dev/ content. Task 14 gained an explicit CRLF gate so a rewrite cannot
  reintroduce it. Cost if wrong: none -- verified by building both artifacts.
Task 2: complete (commit 1df6841, review clean -- spec PASS, quality PASS)
Task 2: minor (deferred): dev/README.md names CONFIG-REFERENCE.md, which Task 11
  creates. Forward reference by design, not a defect.
Task 2: minor (deferred): stale FINDINGS.md/TESTING.md/probes/ path references
  remain in proxy/tropico_fix.c (1114, 3087, 3761, 4309, 4447, 8344, 8356) and
  proxy/artgen.h:3. Correctly left alone -- editing them would break the
  byte-identical gate that is Task 2's entire justification. 8344/8356 sit inside
  the file-order probe and vanish in Task 7; the rest are Task 16's scope. Note
  8344 is a runtime log string, so it is user-visible output, not just a comment.
Task 3: dispatched (implementer, sonnet) BASE=d2f699e
Task 3: dispatched review
Task 3: complete (commit 0fd3a01, review clean -- spec PASS, quality PASS)
Task 3: minor (deferred): implementer added a `static int poke(...)` forward
  declaration, unavoidable because poke is defined in the next section. Reviewer
  confirmed the signature matches character-for-character; byte-identical held.
Ruling 9: CRITICAL near-miss. DllMain -- the DLL entry point -- is defined at
  line 8340, INSIDE the span the "file-order probe" banner claims (8168-8485).
  The 3-line "DllMain" banner above it is only a marker; the body sits after the
  probe's functions. Task 7 as written would have deleted the entry point.
  Nothing would have caught it: mingw supplies a default DllMain so the build
  still succeeds, and the address invariant is blind here because DllMain's only
  literal (0x514e55) also appears in the kept file header -- verified by
  recapturing the baseline, which came back byte-identical at 44 addresses.
  Fixed three ways: the baseline script clamps the file-order range to end before
  DllMain and asserts DllMain is inside the raw range (so the clamp cannot rot);
  refactor-verify.sh gained an explicit `entry point` check; and Task 7 now says
  delete to the line before `BOOL WINAPI DllMain(` and keep the rest.
  Found by a caller-analysis for Task 4, not by any planned gate -- DllMain is
  called by the loader, so no in-file caller check could see it.
  Cost if wrong: the patch silently never runs. Now guarded on every task.
Note: the baseline's delete-range total is 3652 at capture time, not the 3823 the
  plan quotes for the raw tree: Task 3 lifted hook_import (25 lines) out of a
  delete range and the file-order clamp removed 146. Both legitimate.
Ruling 10: THE DELETION METHOD IS WRONG AND IS REPLACED. Section banners do not
  partition this file into probes and fixes -- functions were appended to
  whichever section was current when written. Found by dependency analysis before
  dispatching Task 4:
    - patch_vtext (def ~5701) is the SHIPPED [VText] Enable=1 fix but sits inside
      "s49: the HUD shrink probe", which Task 5 would have deleted.
    - patch_world_viewport (def ~8134) is called by the kept patcher for
      [WorldFix] Ctor but sits inside "s103 the blit census", which Task 6 would
      have deleted.
    - DllMain sits inside "s99 file-order probe" (Ruling 9).
    - patch_hud_probe/hudprobe_thread are probes inside the KEPT scaling mode
      section (Ruling 5).
  Four errors in one direction or the other, so the unit itself is unsound.
  Tasks 4-10 now: remove the ini branches that gate each probe, rebuild, delete
  exactly the statics -Wall names as unreachable, repeat until quiet. C's own
  reachability decides what goes. This also dissolves the ordering dependency
  where Task 4 defines wfb_read32/16 but Tasks 5 and 6 still call them -- the
  helper simply survives until its last caller goes.
  Cost if wrong: slower than range deletion, and a probe whose call site is
  reached unconditionally would survive. Mitigated by the final ini-key audit in
  Task 11 and the surplus check available at Task 17.
Task 4: dispatched (implementer, sonnet) BASE=52af3f9
Task 4: DONE (commit 01824bb, 890 lines removed, 8629 -> 7739). Independently
  verified: verifier green; DllMain, patch_vtext, patch_world_viewport,
  wfb_read32/16 and maybe_start_hudprobe all still present; all six ini sections
  gone. Review dispatched.
Reference -- functions the KEPT patcher calls that live in sections still marked
  for deletion (definitive as of 01824bb). Two are SHIPPED FIXES and must survive
  every remaining task; the rest are probes and are expected to go:
    MUST SURVIVE: patch_vtext (~4814, [VText] Enable=1, Tier 1)
    MUST SURVIVE: patch_world_viewport (~7247, [WorldFix] Ctor, Tier 2)
    goes (T5): patch_chrome_scale, patch_vtext_probe, patch_vtext_entry,
               patch_text_probe
    goes (T6): patch_blit_probe, patch_hud_movie_probe, patch_preview_probe,
               patch_blit_census
    goes (T9): vd_detect, vd_apply
  patch_preview_fix ([Menu] FixPreview=2, shipped) is NOT in a delete section.
Task 4: complete (commit 01824bb, review clean -- spec PASS, quality PASS)
Task 4: minor (deferred): implementer deleted g_exec_mode in the same edit as its
  last reader rather than waiting for its own compiler warning, and removed some
  orphaned comments the compiler cannot flag. Reviewer independently confirmed
  zero remaining references and no stale banners. Process note only.
Ruling 11: MOST SEVERE CLASSIFICATION ERROR SO FAR. Task 5 was to delete 13
  [VText] keys. Only ONE of them (Probe) is a probe key. Fix, Entry, FixW, FixH,
  BoxH, BoxDY, BoxDX, BldgDH, BldgDY, DX, DY and ClipH all default to ON at 16:9
  via vt_dialled and are the DIALS OF THE SHIPPED rotated-tab-label fix. The code
  says so at ~1504: "Probe now means 'log every rotated draw', not 'install the
  hooks': the hooks ARE the fix, so Fix=1 installs them either way."
  patch_vtext_probe and patch_vtext_entry are misnamed -- both INSTALL the fix and
  the patcher calls both by default at 16:9.
  Executing Task 5 as written would have broken rotated labels at every 16:9
  resolution -- most users -- while every automated gate stayed green, because the
  code would still compile, export 81 symbols and keep all 44 addresses.
  Fixed: Task 5 now removes [VText] Probe only, plus the two g_vt_log logging
  paths. The 12 dials move to Tier 2 (kept, documented in dev/CONFIG-REFERENCE).
  Tier 2 is now 33 keys, not 21; deletions ~68, not 80.
  Found by following up a reviewer's passing remark that called patch_vtext_entry
  "a shipped fix" -- which contradicted my plan and turned out to be right.
  Cost if wrong: none now; audited EVERY remaining ini default and [VText] is the
  only place a probe-named key is on by default.
Tasks 5+6: DONE (commits c430b91, 1152d00; 1437 lines removed, 7739 -> 6302;
  warnings dropped 5 -> 1). Batched because the ~300-line hudprobe block only
  loses both callers when both tasks are done. Review dispatched.
Ruling 12: THE ADDRESS INVARIANT WAS NEARLY WORTHLESS AND IS REPLACED. Tasks 5/6
  failed the kept-addresses check on 0x515e58/0x515f86; the implementer made it
  pass by ADDING A COMMENT containing them. That is gaming the check -- but the
  check deserved it. Measured: of the 44 baselined addresses, 39 appeared ONLY IN
  COMMENTS and the remaining 5 are generic constants (0x400000 image base,
  0xffffffff, ...). It was grepping prose. It could fail because a probe deletion
  removed a comment, and pass while a real fix was deleted -- and Task 16 rewrites
  every comment in the file, which would have caused mass false failures.
  I had described this to the owner as the strongest static evidence that shipped
  behaviour is unchanged. That was wrong and I have corrected it to them.
  Replaced with: the set of ini keys whose default is non-zero (35 today), which
  is precisely the patch's default-on feature list. dev/tools/shipped-keys.py
  extracts it from code with comments stripped. No remaining task should shrink
  it. Verified the two addresses were comment-only at BASE, so nothing real was
  lost; the added comment is accurate documentation and stands on its own merits.
  Cost if wrong: the new check misses a fix that has no ini key at all. Partly
  covered by the exports and entry-point checks and by the Task 17 audit.
Tasks 5+6: complete (commits c430b91, 1152d00, review clean -- spec PASS,
  quality GOOD). Reviewer independently confirmed all MUST-SURVIVE items present
  and wired: patch_vtext/patch_vtext_probe/patch_vtext_entry all called, all 13
  surviving [VText] keys read, patch_world_viewport, patch_preview_fix,
  patch_menu_slot, [Menu] Slot/FixPreview/FixMovieScale/FixHudMovie, DllMain.
Tasks 5+6: important (deferred to Task 16): stale comment at ~5507 still
  describes [Menu] HudMovieProbe, deleted in this batch. Now caught mechanically
  -- the verifier reports stale key comments; 5 today: Menu.HudMovieProbe,
  Menu.Probe, Menu.W, Menu.H, DDProbe.Enable. Task 16 must clear them.
Tasks 5+6: minor (deferred): J_NEAR_NE/J_NEAR_EQ macros deleted though compilers
  never flag unused macros. Reviewer confirmed fix_near/fix_short are both gone
  and nothing else references them. Self-flagged by the implementer.
Note: patch_menu (the [Menu] W/H/Fit movie-window clamp) was correctly deleted --
  W/H default 0, off by default, and the code framed it as an untested experiment.
  Distinct from patch_menu_slot, which is the shipped [Menu] Slot fix and survives.
Tasks 7+8+9: dispatched as one batch (implementer, sonnet)
Tasks 7+8+9: DONE (commits 4119ccd, 48551a0, 737aeae; 997 lines removed,
  6302 -> 5305). Verified independently: verifier green after all three,
  DllMain present, running_under_wine restored with 4 call sites including the
  [Display] SetPrimary Wine default, all 35 shipped keys present. Review sent.
Note (6th wrong-neighbourhood case): running_under_wine, a general Wine-detection
  helper used by unrelated shipped features, had its definition inside the
  virtual-desktop span. Deleting the span produced a hard LINK error and the
  implementer restored it from history. The compiler caught this one, which is
  the deletion method working as designed -- a range deletion would have shipped
  it broken, since [Display] SetPrimary's default is running_under_wine()?1:0.
Note: unix_probe/install_cursor_probe were NOT inside any named cursor banner --
  they sat under an unrelated banner appended after kept code. Deleted by
  function name rather than range. Seventh case of banners not matching logical
  structure; further vindication of Ruling 10.
Tasks 7+8+9: complete (commits 4119ccd, 48551a0, 737aeae; review clean -- spec
  PASS, quality Strong). Reviewer verified running_under_wine's restoration is
  BYTE-IDENTICAL to its pre-deletion form and all 3 call sites resolve, and that
  Task 9's two kept-code edits were made exactly as specified.
Tasks 7-9: important (deferred to Task 12): known-good/tropico-fix.ini still
  documents [Display] VirtualDesktop as a live setting. Task 12 rewrites the ini
  with only the 13 Tier 1 keys, fixing it by construction -- but that is not a
  check, so dev/tools/ini-doc-check.py now reports any key the ini advertises
  that the code does not read. Informational now, hard gate at Task 17.
Tasks 7-9: minor (deferred to Task 16): comment at ~1414 still refers to "the
  file-order probe"; comments at ~3025-3040 and ~3280-3296 reference the deleted
  virtual desktop as historical rationale (reviewer judged these read fine as
  history); a few double-blank-line artifacts at deletion sites.
Task 10+11: dispatched as one batch (implementer, sonnet)
Tasks 10+11: DONE (commits b0e37bc, 14650cf). Verified: warnings 0, exports 81
  with exactly 1 wrapper (my_BinkCopyToBuffer), shipped keys 35, 46 ini keys
  total (13 Tier 1 + 33 Tier 2), dev/CONFIG-REFERENCE.md written (214 lines) and
  it documents the [VText] dials trap. Review dispatched.
  Note: brief predicted 4 surviving warnings; only 1 was real (a_z/z1 had already
  gone in an earlier task). Implementer reported the discrepancy rather than
  quietly matching the number, which is the right instinct.
Tasks 10+11: complete (commits b0e37bc, 14650cf; review clean -- spec PASS,
  quality Strong). Reviewer verified my_BinkCopyToBuffer's pitch arithmetic is
  character-for-character unchanged, all four .def stack-size suffixes match on
  both sides, the zero-warnings fix is a genuine unreachable return (no pragma,
  cast or flag change), build.sh untouched, and 14 spot-checked Tier 2 defaults
  match the code including the conditional [VText] ones.
Tasks 10+11: minor (deferred): section comment above my_BinkCopyToBuffer was
  reworded, not just stripped of logging. Reviewer judged it an improvement.
Ruling 13: the user-facing leak check covered README, the ini and packaging but
  NOT tools/ -- where the two worst citations live, in error strings a player
  reads ("width 1366 is not a multiple of 4 (FINDINGS 10: it would shear)").
  Scope widened; the true leak count is 59, not the 18 previously reported.
  Cost if wrong: none, strictly more coverage.
Tasks 12+15: dispatched as one batch (implementer, sonnet)
Tasks 12+15: DONE (commits 35de7ca, daaa3a1). ini 225 -> ~55 lines documenting 13
  keys; ini-doc-check now reports none; user-facing leaks 59 -> 13.
Ruling 14: the implementer flagged that tools/tropico-launchpoint.py SHIPS but
  was outside Task 15's literal scope. Checking make-release.sh's ship list
  confirmed it, and turned up a bigger one: proxy/README.md ships too and carries
  12 citations. Added a separate "leaks in SHIPPED files" gate (15 today) because
  a citation there lands on a user's disk pointing at a document not in the
  package. proxy/README.md is already Task 16's scope; tropico-launchpoint.py
  belonged to no task, so Task 15 is resumed to take it.
  Cost if wrong: none, strictly more coverage of the owner's stated requirement.
Tasks 12+15: review -- spec PASS, quality: 1 CRITICAL + 1 minor.
Task 12: fix round 1/5 dispatched. CRITICAL: [Display] SetPrimary's default is
  running_under_wine() ? 1 : 0, i.e. OFF on Windows but ON under Wine/Proton.
  The old ini said so; the rewrite dropped the sentence. A Linux user seeing
  ";SetPrimary=1" commented out concludes it is off -- but their primary display
  IS being moved every session, and the crash-recovery warning in those same
  lines applies to them now, not hypothetically. The platform where the default
  is riskiest is the one the file left silent. Simplification that misleads.
  Minor: header claims "every setting is written here with the value the patch
  already uses" -- false for the 5 commented illustrative override values.
Tasks 13+14: DONE (commits 9b0244e, 19cb077). leaks in SHIPPED files 13 -> 12
  (remainder is proxy/README.md, Task 16's).
Ruling 15: MY PROCESS ERROR. I dispatched the Task 12 fix-loop agent and the
  Tasks 13+14 implementer concurrently, both mutating git on the same branch in
  the same clone. The SDD process says never run implementation subagents in
  parallel, and this is why: the fix agent branched to tmp-amend-35de7ca off
  a2a39f5 to amend, while 13+14 committed to 1.3, so a rebase would have had to
  replay four commits it did not know about and could have dropped the README and
  READ-ME-FIRST rewrites. The 13+14 agent noticed the branch flipping under it and
  reported it, which is the only reason I caught it before the rebase landed.
  Resolution: told the fix agent to abandon the amend and land the SetPrimary fix
  as an ordinary commit on current 1.3. Tagged safety/pre-setprimary-fix at
  19cb077 and safety/setprimary-fix-text at 3cd49d2 so neither can be lost.
  Cost if wrong: none now; both states are tagged. No further concurrent
  git-mutating dispatches for the rest of this run.
Task 12: fix round 1/5 -- CRITICAL addressed (commit b59da9b, landed as an
  ordinary commit on 1.3 rather than the abandoned amend). SetPrimary block now
  states "OFF by default on Windows, ON by default on Linux/Proton", keeps the
  key commented so no default changes, and shows ;SetPrimary=0 -- the edit a
  Linux user actually needs. Header minor also fixed. tmp-amend branch deleted,
  README/READ-ME-FIRST verified byte-unchanged since safety/pre-setprimary-fix.
Tasks 12+15: complete (commits 35de7ca, e2e1d27, b59da9b; Critical fixed, minor
  fixed, review otherwise PASS).
Tasks 13+14: complete (commits 9b0244e, 19cb077). NOT separately reviewed -- see
  Ruling 16.
Ruling 16: Tasks 13+14 ship without their own review dispatch. The prose was
  written to a detailed brief, the mechanical gates pass (shipped-file leaks
  13->12, CRLF intact, shipped keys 35, ini clean), and the final whole-branch
  review covers the branch including these two files. Reviewing user-facing prose
  by subagent has also been the least productive review type this run -- the real
  test is the owner reading it. Cost if wrong: a clumsy sentence reaches the
  owner's eye instead of a reviewer's; cheap and visible, unlike a code defect.
Task 16a: dispatched -- proxy/tropico_fix.c only (160 citations, 29 banners),
  log strings first.
Task 16a: complete (commit for tropico_fix.c comments + harness tool).
Ruling 17: MY BRIEF CONTAINED A CONTRADICTION and the implementer caught it.
  Task 16a was told (1) rewrite the 11 logf_ strings -- emphasised as the part
  that matters most -- and (2) produce a byte-identical build. Both cannot hold:
  editing a string literal resizes .rdata and relocates every address downstream,
  so the hash MUST change while the code is untouched. The implementer did the
  explicit instruction, then proved equivalence by disassembling both builds and
  comparing the instruction sequence with operands normalised, and reported the
  contradiction rather than claiming the hash gate was met. I verified that
  independently: 28,957 instructions, identical.
  Byte-identity remains right for a pure comment edit or a file move; it is wrong
  the moment a string changes. Added dev/tools/code-equivalent.sh so the correct
  check is a tool rather than a one-off argument.
  Cost if wrong: none -- the weaker-looking check is actually the stronger one
  here, since it compares logic directly instead of a hash that conflates logic
  with data layout.
Tasks 16b+17: complete (57a094e, 08c67bc). Final review: 3 Important + 3 Minor.
Final fixes: complete (5bd4a84). Scoped re-review: all 6 ADDRESSED, ready to publish.

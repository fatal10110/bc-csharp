# Project status

This is the only guide that changes as work progresses. Update it in a separate PR after a wave,
never in a lane. GitHub issues are the authority; this page is a snapshot.

Last updated: 2026-10-31.

## Milestones

| Milestone | Status | Notes |
| --- | --- | --- |
| Plan (`STRIP_PLAN_V2.md`) | complete | rev 6.3; decisions A–G confirmed on turboHTTP#141 |
| Agent workflow and CI | complete | waves runs w1030–w1034. Merges are gated on 0 unresolved review threads, CodeQL included (#70). |
| M1 Tooling (#4–#10, #35, #42) | complete | includes the upstream-test exclusion list (#42) |
| M2 Bootstrap and edge cuts (#11–#21, #65) | complete | E1–E14 merged. E5 also binds TLS 1.3 ECDSA schemes to the key's curve (#65). The E13 guard edits are reverted (#67): no strip define set needs them. |
| M3 Smoke, enforce, hand-over (#22–#31, #58, #66, #71) | handed over | hand-over and addendum posted on turboHTTP#141; waiting for turboHTTP's gate |

## Current state of `strip-v2`

- **Hand-over commit:** `4df803aa` (addendum 2 on turboHTTP#141). Compared with `727aaadb`, only the E13 revert changes shipped files, and the compiled code is identical under the shipped define sets.
- **Define sets:** `[netstandard21]` and `[netframework]`, captured from Unity 2021.3.45f2 (Android IL2CPP player). A DEBUG variant of `[netstandard21]` is built and smoke-tested too.
- **Enforce run:** 680 kept files, budget 748, 0 deny hits, 0 unresolved names.
- **Smoke:** 273/273 on `TurboBC.ns21` and `TurboBC.netfx` (with `--smoke-slow`), 27/27 on `TurboBC.ns21-debug`. That includes decision A (`Verify` throws) on the shipped DLLs.
- **Turbo NUnit tests:** 126/126 in `check.sh --full` (they fail if zero tests match).
- **Unity 2021.3 check on the shipped Lib** (turboHTTP@3856398f):
  - player compile OK for Windows, Android and iOS at both API levels;
  - TLS integration tests: 87 passed, 0 failed (`testing.md` lists the known turboHTTP test bugs).
- **Code scanning:** 0 open CodeQL alerts, and 0 unresolved review threads on PRs #37–#73 and #67.

## Open

| Issue | What | Waiting on |
| --- | --- | --- |
| #28, #3 | enforce/hand-over tracker and epic | turboHTTP: #140 and #143, then the #141 sync and gate, then #142 |
| #60 | follow-up to decision C: offer X25519MLKEM768 | after v1 |
| #61 | follow-up to decision D: OCSP stapling and must-staple | after v1 |

## Strip done

The strip is done when the smoke suite passes here **and** the turboHTTP#141 gate passes on output
from the recorded `BASE` + `ROOTS_SHA` (hand-over commit `4df803aa`).

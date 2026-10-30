# Project status

This is the only guide that changes as work progresses. Update it in a separate PR after a wave,
never in a lane. GitHub issues are the authority; this page is a snapshot.

Last updated: 2026-10-30.

## Milestones

| Milestone | Status | Notes |
| --- | --- | --- |
| Plan (`STRIP_PLAN_V2.md`) | complete | rev 6.3; decisions A–G confirmed on turboHTTP#141 |
| Agent workflow and CI | complete | `strip/journal/2026-10-agent-workflow-ci.md`; waves runs w1030 (PRs #37–#56) and w1031 (#59) |
| M1 Tooling (#4–#10, #35) | complete | open follow-up: #42 (crypto/test sources a cut stops compiling) |
| M2 Bootstrap and edge cuts (#11–#21) | complete | E1–E14 merged; E13 needs no fix under the real Unity sets |
| M3 Smoke, enforce, hand-over (#22–#31) | hand-over pending | smoke suite, real define sets (#29) and enforce run (#30, PR #59) done; #31 open |

## Current state of `strip-v2`

- **Define sets:** `[netstandard21]` and `[netframework]`, captured from Unity 2021.3.45f2 (Android IL2CPP player).
- **Enforce run:** 680 kept files, budget 748, 0 deny hits, 0 unresolved. Smoke: 216/216 on
  `TurboBC.ns21` and `TurboBC.netfx` with `--smoke-slow`.
- **Output:** 681 `.cs` files in `strip/out/Lib`.
- **Unity 2021.3 check** against turboHTTP@3856398f:
  - player compile OK for Windows, Android and iOS at both API levels;
  - turboHTTP TLS integration tests pass;
  - known failures are turboHTTP test bugs only (`testing.md`).

## Open

| Issue | What | Waiting on |
| --- | --- | --- |
| #31 | hand-over comment on turboHTTP#141 | owner approval |
| #58 | build and smoke-test the kept tree with `DEBUG` (Unity Editor and Development builds define it) | — |
| #42 | upstream-test diff: drop `crypto/test` sources a cut stops compiling | — |
| #60 | follow-up to decision C: offer X25519MLKEM768 | after v1 |
| #61 | follow-up to decision D: OCSP stapling and must-staple | after v1 |
| #3, #4, #28 | trackers | close with their children |

## Strip done

The strip is done when the smoke suite passes here **and** the turboHTTP#141 gate passes on output
from the recorded `BASE` + `ROOTS_SHA`.

turboHTTP's side: #140 and #143 first, then #141 (sync + gate), then #142.

# Decisions A–G confirmed (#29) and status after #59

## What
- The owner confirmed decisions A–G on 2026-10-30, using Best HTTP as the benchmark: its default TLS accepts any certificate, and chain and OCSP checks are a paid add-on. The decision record is on turboHTTP#141 (issuecomment-6533936695).
- `STRIP_PLAN_V2.md` §2 now records the confirmation. `AGENTS.md` and `CLAUDE.md` describe the post-#59 state: the captured Unity sets, `budget.txt`, and the gate running enforce mode.

## Decisions
- A is confirmed on the condition that turboHTTP#33 ships native/`X509Chain` validation.
- C (X25519MLKEM768) and D (OCSP stapling, must-staple) are confirmed for v1 only. Follow-ups: #60 and #61.
  - D is the one gap against Best HTTP's TLS Security add-on.
  - C would put us ahead of Best HTTP.

## Files
- `STRIP_PLAN_V2.md` §2 intro.
- `AGENTS.md`: Architecture, Local Gates, Agent Workflow.
- `CLAUDE.md`: Architecture, Key Technical Decisions, Development Status, Critical Risk Areas, Conventions, Tooling.

## How verified
- `./tools/ci/check.sh` (enforce).
- The Unity capture and validation are in the #59 PR body.

## Guidance restructure (owner request)
- `CLAUDE.md` is now the single, static rules file, modelled on turboHTTP's. It covers workspace,
  precedence, non-negotiables, engineering rules, verification, tools, issue workflow, skills and
  scoped guides. It holds no development status.
- `AGENTS.md` is a pointer to `CLAUDE.md`.
- Everything else moved to scoped guides in `strip/docs/agents/`:
  - `architecture.md`: layout, pipeline, decisions, risks.
  - `testing.md`: smoke, fixtures, upstream diff, `bc-test-data`, Unity probe.
  - `tooling.md`: gate, CI, prerequisites, agent tools, bumps.
  - `project-status.md`: the only file that changes as work progresses.
- The skills and the strip-build reviewer now point to the new places.

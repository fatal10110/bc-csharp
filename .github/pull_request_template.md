## Summary
<!-- Behavior delivered, 2-4 lines. -->

Closes #<!-- n; one line per fully resolved issue, "Part of #n" otherwise -->

## Acceptance criteria
- [ ] <!-- criterion — file:line hunk or test name -->

## Decisions
<!-- Plan (STRIP_PLAN_V2.md) / RFC choices and why, or "none". -->

## Wire / closure / limits
1. Wire/behavior: <!-- what a TLS peer or the turboHTTP consumer observes differently -->
2. Closure: <!-- files entering/leaving the strip closure; deny hits; rebase surface of touched upstream files -->
3. Abuse/limits: <!-- what a hostile server can send on the changed path and the bound that stops it -->

## Local gates
- `./tools/ci/check.sh` at <!-- sha -->:
- `strip/strip.sh` mode run: <!-- --report | enforce (no flag) | n/a (strip.sh not yet present) -->

## Specialist rubrics
Crypto security: <!-- clean | findings fixed -->; Strip build: <!-- clean | findings fixed -->

## Follow-ups
<!-- issues filed or amended, or "none" -->

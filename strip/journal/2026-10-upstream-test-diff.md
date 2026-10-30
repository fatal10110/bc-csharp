# 2026-10 — Upstream-test regression diff over the kept surface (#35)

## What

`strip/tool/upstream_tests.py` runs the upstream `crypto/test` fixtures that cover code the strip
keeps (never the whole suite), parses the TRX into a per-test outcome list and diffs it against the
committed BASE results. Failures a cut causes on purpose are listed, one test per line with the
E-number and plan decision, in `strip/upstream-expected-failures.txt`; any other test that passed at
BASE and does not pass now is a regression (exit 1). It is a validation aid for edge cuts and bumps,
not a gate: not in `check.sh` or CI, because it needs dotnet and the ~7 GB `bc-test-data` checkout.

```bash
export PATH=$HOME/.dotnet:$PATH
strip/tool/upstream_tests.py                 # run the kept surface on this tree and diff against BASE
strip/tool/upstream_tests.py --update-base   # after a bump or a filter edit: rerun BASE, rewrite the results file
strip/tool/upstream_tests.py --trx FILE      # re-diff an existing TRX
strip/tool/upstream_tests.py --print-filter  # the dotnet test --filter expression
```

## Files

- `strip/tool/upstream_tests.py` — the runner, TRX parser (`UnitTest/TestMethod@className` +
  `UnitTestResult@testName`, worst outcome on duplicates), diff and report; output (TRX, dotnet logs,
  `report.txt`) under `strip/upstream-results/`.
- `strip/tool/test_upstream_tests.py` — 20 tool tests: TRX parsing, diff categories, expected-failure
  and filter parsing, empty-filter refusal, stale BASE results, missing bc-test-data message, and a
  consistency check of the committed list files. No dotnet or bc-test-data needed.
- `strip/upstream-tests.txt` — the kept-surface filter: `Tls.Tests`, `Tls.Crypto.Tests`, the
  AES/GCM/ChaCha20-Poly1305, SHA-2/HMAC/HKDF, RSA/PSS/MGF1, ECDSA/X25519 fixtures, `Math.Tests`,
  the P-256/P-384 field tests, `Asn1.Tests` and `CertTest` (505 tests).
- `strip/upstream-base-results.txt` — generated BASE results (505 pass), header with the BASE SHA
  and the sha256 of the filter entries.
- `strip/upstream-expected-failures.txt` — the 56 E1 failures (27 E1/B, 7 E1/C, 21 E1/E, 1 E1 SRP).
- `.gitignore` — `/strip/upstream-results/`.

## Decisions

- **BASE result committed, regenerated with `--update-base`.** The upstream test sources are
  identical at BASE and HEAD (only the fork-owned `crypto/test/src/turbo/` was added), so a committed
  list is deterministic and saves a second cold build per run. The tool refuses a results file whose
  `base:` differs from `strip/BASE` or whose filter digest differs from the filter file, so a bump or
  a filter edit cannot be diffed against stale results. `--update-base` builds a temporary worktree
  at `strip/BASE` beside the repository root (`../.upstream-base-<sha12>`, so
  `SimpleTest.FindTestDataPath` still finds `bc-test-data`) and removes it afterwards
  (`--keep-base-tree` keeps it); it fails if a filter entry selects no test.
- **Fork-owned `Org.BouncyCastle.Turbo.Tests` is not in the filter**: it has no BASE result; those
  fixtures are run by their own lanes.
- **Filter entries** are `.`-terminated namespace or class names (identifier characters only), so a
  `FullyQualifiedName~` substring selects exactly one namespace or class and cannot inject filter
  syntax; an empty filter is refused (no unfiltered upstream run).
- **Regression** = passed at BASE and now failed, skipped or missing, or a new test that fails, and
  not listed. Expected entries that pass now, and entries absent from both runs, are reported but do
  not fail the run.
- **Tags**: `/`-separated E-number (required) and plan decision letter (optional, for cuts like
  SRP that no decision names), e.g. `E1/B`, `E/E5`, `A/E8`.
- Narrowing the filter to fixtures whose subject is in the closure waits for `closure.py` (#7); the
  filter file says so.

## Deferred

- `AGENTS.md`/`CLAUDE.md` Testing sections pointing to the script land in the post-wave docs PR (waves
  lanes do not edit them); #12 got a comment asking each edge-cut PR to run the script and add its
  lines to the expected-failures file.

## How verified

- `--update-base` on BASE `7c9c8d5a`: 505 tests, 505 pass (1m41s including the cold build);
  `--trx strip/upstream-results/base.trx` against it: 0 regressions (acceptance 1; it lists the 56
  expected entries as passing at BASE, as it should).
- HEAD (`66b2afb7`, E1 applied) with an empty expected list: 56 regressions, exactly the E1 failures
  of `2026-10-e1-bctlscrypto.md`; with the seeded list: 0 regressions, `E1 x1, E1/B x27, E1/C x7,
  E1/E x21`. Three HEAD runs gave the same result (no flaky test seen; `TlsHandshakeTimeoutTest` is in
  the set and passed every time).
- Acceptance 2 by hand: `HkdfBytesGenerator.ExpandNext` counter changed to `n + 1` →
  `[pass -> fail] Org.BouncyCastle.Crypto.Tests.HkdfGeneratorTest.TestFunction`, exit 1; adding
  `E9 Org.BouncyCastle.Crypto.Tests.HkdfGeneratorTest.TestFunction` → 0 regressions, exit 0; both
  reverted, clean rerun 0 regressions.
- `python3 -m unittest discover -s strip/tool -p 'test_*.py'`: all pass.
- `./tools/ci/check.sh`: OK. strip/strip.sh: n/a (not present yet).

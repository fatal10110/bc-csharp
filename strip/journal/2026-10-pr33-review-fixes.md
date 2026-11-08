# PR #33 review fixes

**What:** fixes for the owner's review of the strip-v2 → master tracking PR #33 (review 5719228296), landed
on `strip-v2` through their own PR because #33's head is `strip-v2` itself.

## Files

- `strip/tool/test_strip_sh.py` — `test_refresh_roots_runs_first` compares against the realpath of the temp dir;
  strip.sh builds paths from bash `$PWD`, which is `/private/var/...` on macOS. `check.sh --full` was red there.
- `tools/ci/check.sh`, `.github/workflows/ci.yml` — `--full` runs the 126 fork-owned NUnit tests
  (`FullyQualifiedName~Org.BouncyCastle.Turbo`, net6.0 with `DOTNET_ROLL_FORWARD=Major`); they ran in no gate.
  actionlint is installed from the release tarball checked against its published sha256 instead of
  `curl | bash` of the installer script. ripgrep stays: `tools/agent-tools/look.py` runs `rg` and
  `test_agent_tools.py` exercises it.
- `strip/smoke/rows/RegistryRows.cs`, `strip/smoke/server/SmokeHostileKeys.cs` — row `registries/x509-sig-alg-name`:
  `SigAlgName` for sha256WithRSAEncryption, ecdsa-with-SHA256 and an unknown OID (dotted string), and `ToString()`
  of a rejected-key (secp256k1) certificate showing `<unsupported key>`. Reaches the E8 `TurboSignatureNames`
  static table; the group also runs against the DEBUG build.
- `crypto/src/**` (11 files) — E13 guard edits of #51 reverted to upstream. The captured Unity sets define no
  `*_OR_GREATER` symbol, so the edits were compiled by no strip build and only added rebase surface in
  frequently changing files (Streams.cs, ChaCha7539Engine.cs, X448Field.cs).
- `STRIP_PLAN_V2.md` — §3 E13 records the outcome (no edits under the captured sets, #51 reverted); §4 `tool/`
  lists the shipped modules and drops the non-existent `notices/`.
- `strip/tool/package.py`, `test_package.py` — turbo-owned files get their own "Turbo-owned files (MIT License)"
  section with the MIT text instead of landing in the hand-review list.
- `strip/tool/test_upstream_tests.py` — single `unittest.mock` import (CodeQL).

## Decisions

- E13: reverted rather than kept as forward-compat edits. A later capture that defines `*_OR_GREATER` fails the
  enforce build, and the plan rule brings the edits back then.
- CodeQL threads on generic catches (smoke row isolation, TurboKeyFactory's catch-all → ArgumentException,
  consumer roots copied verbatim from turboHTTP), `Select`/`Where` suggestions and `Path.Combine` with
  relative second arguments: no change, answered on the threads.
- The TLS 1.3 ECDSA scheme↔curve binding note and the extra hostile rows go to follow-up issues.

## Verified

- `python3 -m unittest discover -s strip/tool` on macOS: all pass (was 1 failure).
- `tools/ci/check.sh --full`: strip.sh enforce (closure, builds incl. DEBUG variant, smoke with the new row),
  turbo NUnit tests, Python tests, waves simulation.

## Take-over and review round 1 (2026-10-31)
The main session took over #67 and merged origin/strip-v2 into it. The one conflict was in `strip/tool/test_upstream_tests.py`: #72 fixed the same CodeQL import alert, and #67's single `import unittest.mock` was kept.

Both specialist reviews were clean on the E13 revert: preprocessor-neutral under ns21, netfx and ns21-debug, with all 11 files byte-identical to BASE. Fixes from the two reviews:
- **Turbo NUnit gate (`tools/ci/check.sh`):**
  - `-- RunConfiguration.TreatNoTestsAsError=true`, so zero matching tests fails instead of passing silently.
  - The build applies `strip/upstream-tests-exclude.txt` through a new mode, `strip/tool/upstream_tests.py --write-exclusion-targets DIR`, which uses the same Compile Remove file as the upstream-test diff.
  - The header comment and `tooling.md` now say that `--full` builds the library and the test project at net6.0.
- **Smoke rows:**
  - A new `registries/x509-verify-not-supported` row pins decision A on the shipped DLLs and the DEBUG DLL: `Verify`, `IsSignatureValid` and `VerifyAltSignature` throw `NotSupportedException`.
  - `x509-sig-alg-name` now also checks that `ToString()` prints `<unsupported key>` for a key TurboKeyFactory rejects by wrapping a parse failure (EC point pad bits).
- **Notices (`strip/tool/package.py`):**
  - A header block counts as turbo-owned only when it is exactly the one-line MIT header in a `turbo/` file, so third-party text in the same block stays in the review list.
  - A `turbo/` file without the header fails packaging.
  - Tests: a mixed block, a missing header, and a turbo file in the determinism test.
- **Docs and CI:**
  - `testing.md` notes that the turbo fixtures run at net6.0, so the smoke rows stay the gate for the Unity sets.
  - The actionlint `curl` is restricted to HTTPS and TLS 1.2+.

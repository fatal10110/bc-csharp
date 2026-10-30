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

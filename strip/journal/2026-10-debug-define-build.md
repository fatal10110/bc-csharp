# 2026-10 — DEBUG define build and smoke (#58)

## What

Unity defines `DEBUG` for every Editor compile and for Development player builds. Until now the strip never
compiled or ran the kept tree with it, so code under `#if DEBUG` (the `DigestUtilities` static-constructor map
self-checks, which throw) first ran inside the turboHTTP Editor. `strip.sh` now builds a DEBUG variant of the
captured `[netstandard21]` set (3a, 3c and consumer) and runs the curve, KAT and new registry smoke rows against
its `TurboBC.ns21-debug.dll`. The results go into `STRIP_INFO.md` under a "DEBUG build" line.

## Files

- `strip/tool/defines.py`: `EDITOR_DEFINES = ("DEBUG", "TRACE")`, `DEBUG_VARIANTS = {"netstandard21_debug":
  "netstandard21"}`, and `debug_variants(sets)`, which returns the captured set plus those symbols.
- `strip/tool/build.py`:
  - `select_sets` (moved out of `main`) adds the variant after the captured sets whenever `[netstandard21]` is
    selected.
  - `DLL_SUFFIX` maps the variant to `ns21-debug`.
  - `run_builds` copies the variant's DLL to `<work>/dll/debug/` (`DEBUG_DLL_DIR`), so the existing
    `dll/TurboBC.*.dll` smoke glob does not pick it up.
- `strip/strip.sh`:
  - step 5 makes a second `run.sh` call on `dll/debug/TurboBC.*.dll` with `DEBUG_SMOKE_FILTERS` (`curves/`,
    `kat-`, `registries/`). A failure is a fail check (enforce exit 1; `--report` logs it).
  - It appends that call's results to `smoke-results.md` under a "DEBUG build (#58)" line, which `package.py`
    puts into `STRIP_INFO.md`.
  - The header comments describe both changes.
- `strip/smoke/rows/RegistryRows.cs`: new group `registries`. `digest-utilities` runs `DigestUtilities` by name,
  OID and `CalculateDigest` (FIPS 180 "abc"). `ec-named-curve-table` checks names, OID round trips and
  `GetByOid` for P-256/384/521. The group runs on every DLL.
- `strip/tool/test_debug_variant.py`: tests for the variant derivation, set selection, the 3a/3c/consumer builds
  and the `dll/debug/` placement (fake builder), and strip.sh's DEBUG smoke call. The strip.sh tests cover the
  filters, the merged results, an enforce failure, the report note, and no call when no DEBUG DLL exists. All
  9 tests fail on `origin/strip-v2`: 6 errors and 1 failure; the other 2 pass trivially on the old code.

## Decisions

- **Where the variant comes from.** `strip/unity-defines.txt` stays the unedited player capture. The variant
  is derived in `defines.py` and read only by `build.py`. `closure.py` reads only the file, so the fixpoint,
  sweep, deny hits, kept list (681 files, unchanged) and `budget.txt` are those of the captured sets, by
  construction. The DEBUG builds compile cleanly with that kept list, so DEBUG does not change which files are
  needed. A later `#if DEBUG` block that needs a file outside the closure would show up as a 3a/3c compile
  error in the variant, not as a closure change.
- **TRACE included.** The Editor rsp of `TurboHTTP.Transport.BouncyCastle` has both DEBUG and TRACE, and
  `rg '#if.*TRACE' crypto/src` finds nothing today. Adding TRACE makes the variant equal to the Editor compile
  and costs nothing. It also catches a future upstream `#if TRACE`. Development players (DEBUG only) are a
  subset of this.
- **Only `[netstandard21]`.** That is what the issue asks for. `[netframework]` differs only in `NET_4_6` and
  `NET_UNITY_4_8`, which BC never tests. Its variant would add 3 builds and a harness build to every gate run.
- **Row subset.** The DEBUG DLL runs only the curve, KAT and registry rows (25 rows), not loopback, interop or
  hostile. That keeps the extra smoke time to one harness build plus about 1 s of rows. The release DLLs still
  run everything, including `registries`.
- **Registry row.** The brief said no row reaches `DigestUtilities`. The mutation check below shows that
  `kat-rsa/pkcs1-sha256-verify` and `kat-tls13-hkdf/rfc8448-key-schedule` already reach it indirectly.
  `registries/digest-utilities` makes that coverage explicit, so it does not depend on how those rows are
  implemented.
- `MacUtilities` (the other throwing `#if DEBUG` block) is not kept, because E12 inlined it, and is not in
  `kept.txt`. The other `#if DEBUG` sites (`AgreementUtilities`, `CipherUtilities`, `SignerUtilities`,
  `KemUtilities`) are not kept either.

## How verified

- `./tools/ci/check.sh` (enforce run): OK in 2 min 4 s, including a fresh BASE build.
  - The 9 builds are clean: `TurboBC.netfx.dll`, `TurboBC.ns21.dll` and `TurboBC.ns21-debug.dll`. The define
    assertion lists DEBUG and TRACE only for the variant.
  - Smoke: 217/217 rows on each release DLL and 25/25 on `TurboBC.ns21-debug.dll`.
  - Kept list: 681 files, identical to a strip-v2 run.
- Mutation check (reverted): `AlgorithmMap["TURBO-MUTATION"] = "not-a-mechanism";` added to the
  `DigestUtilities` static constructor, then `strip/strip.sh --report --set netstandard21`.
  - `TurboBC.ns21.dll`: 217/217 passed.
  - `TurboBC.ns21-debug.dll`: 22/25. `registries/digest-utilities`, `kat-rsa/pkcs1-sha256-verify` and
    `kat-tls13-hkdf/rfc8448-key-schedule` fail with `TypeInitializationException: ... Unmapped mechanism MUST
    be uppercase`, and the run logs `REPORT strip.sh: smoke suite failed (DEBUG build)`.
- `python3 -m unittest discover -s strip/tool -p 'test_*.py'`: OK. `shellcheck strip/strip.sh`: clean.

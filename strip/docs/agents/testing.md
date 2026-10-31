# Testing

Load when writing or running smoke rows, fixtures or upstream tests, using `bc-test-data`, or
validating in Unity.

## What gates what

| Check | Where | Gate? |
| --- | --- | --- |
| Smoke suite (fast rows) on every define set's DLL | `strip/smoke/`, run by `strip.sh` | **yes** (`check.sh`, CI) |
| Smoke slow rows (30 s handshake timeout) | `strip.sh --smoke-slow` | before a hand-over or a change to the timeout path |
| DEBUG build: curve-lookup, KAT and registry rows on `TurboBC.ns21-debug.dll` (Unity Editor and Development builds define `DEBUG`) | `strip.sh` (always) | **yes** |
| Tool tests | `strip/tool/test_*.py`, `tools/agent-tools/test_*.py`, `waves_sim.mjs` | yes, with `check.sh --full` |
| Turbo fixtures | `crypto/test/src/turbo/` | yes, with `check.sh --full`; required for cuts that have no smoke row |
| Upstream `crypto/test` diff over the kept surface | `strip/tool/upstream_tests.py` | after every edge cut and every bump; not in CI |
| Unity 2021.3 compile and turboHTTP TLS tests | probe project (below) | after define-set or `#if` changes, and before a hand-over |

## Smoke suite (`strip/smoke/`)

- **Harness:** a net8 console. The client side references `TurboBC.*.dll` (rewritten namespace), and
  the server side and tooling use a full upstream build of `BASE`. The two coexist because of the
  namespace rewrite.
- **Rows:** one file per row group in `strip/smoke/rows/`, registered without editing a shared file.
  - curve lookup (public API only);
  - KATs (AES-GCM light/basic, ChaCha20-Poly1305, X25519, ECDSA, RSA PKCS#1/PSS, SHA-2, HMAC, TLS 1.3 HKDF);
  - OpenSSL 3 interop matrix;
  - exact ClientHello;
  - hostile inputs (ASN.1 depth, RSA bounds, explicit EC, rejected key types);
  - timeouts.
- **Results** go into `STRIP_INFO.md`.
- **By hand:** `strip/smoke/run.sh --work <dir> --results <file> [--filter <text>] [--slow] <TurboBC.x.dll>...`.
- **OpenSSL versions differ in output:** interop rows must accept every OpenSSL 3.x spelling. CI has
  3.5.x, a local box may have 3.0.x.

## Fixtures and upstream tests

- **New tests:** plain NUnit with classic asserts in `crypto/test/src/turbo/`. Run them scoped:
  ```bash
  DOTNET_ROLL_FORWARD=Major dotnet test --framework net6.0 crypto/test/BouncyCastle.Crypto.Tests.csproj \
    --filter "FullyQualifiedName~<Fixture>"
  ```
  (`DOTNET_ROLL_FORWARD=Major` is needed when only the .NET 8 runtime is installed.)
- **Never run the whole upstream suite.** Cuts break parts of it on purpose.
- **`bc-test-data`** (bcgit/bc-test-data) is a read-only clone beside the repo, `../bc-test-data`, about 7 GB:
  `git clone --depth 1 https://github.com/bcgit/bc-test-data.git`.
  `SimpleTest.FindTestDataPath` walks up to it, so one clone serves every worktree. The TLS tests
  read `tls/credentials` from it.
- **`python3 strip/tool/upstream_tests.py`** runs the kept-surface filter (`strip/upstream-tests.txt`)
  and diffs the result against `strip/upstream-base-results.txt`.
  - Intended breaks are listed with their E-number in `strip/upstream-expected-failures.txt`.
  - Test sources a cut stops compiling go in `strip/upstream-tests-exclude.txt`, one path per line with
    its E-number. They are removed from the test build without editing upstream files, and the excluded
    tests are reported.
  - Exit 1 means a regression. After a bump, or after editing the filter or the exclusion list, run
    `--update-base`. A stale base is refused.

## Unity validation (2021.3.45f2)

The probe project lives on the Windows host at `E:\turbo-strip-probe` (WSL:
`/mnt/e/turbo-strip-probe`). Run one Unity process at a time.

- **What it is:**
  - `package/`: a copy of turboHTTP at `ROOTS_SHA` whose `Runtime/Transport/BouncyCastle/Lib` is replaced by `strip/out/Lib`.
  - `proj/`: a throwaway Unity project that consumes that copy, with `Assets/Editor/TurboStripProbe.cs`.
  - turboHTTP itself is never modified.
- **Refresh the Lib:**
  `rsync -a --delete strip/out/Lib/ /mnt/e/turbo-strip-probe/package/Runtime/Transport/BouncyCastle/Lib/`.
- **API level:** `run.sh <log> -executeMethod TurboStripProbe.SetLevel -apiLevel NET_Standard|NET_Unity_4_8`.
- **Defines and player compile:**
  `run.sh <log> -executeMethod TurboStripProbe.Capture -out 'E:\turbo-strip-probe\x.txt' -targets StandaloneWindows64,Android,iOS`.
  The exact csc defines are in `proj/Library/Bee/artifacts/*/TurboHTTP.Transport.BouncyCastle.rsp`.
- **TLS tests (PlayMode):** `runtests.sh <name> 'TurboHTTP\.Tests\.Transport\.(Tls|Http1\.RawSocketTransportProxyTunnel)'`.
  - These are real handshakes through BC.
  - They need `run.sh <log> -executeMethod TurboStripProbe.SetDefines -defines TURBOHTTP_INTEGRATION_TESTS`.
- **Known turboHTTP test bugs (not strip failures):**
  - `RawSocketTransportProxyTunnelTests` uses `CertificateRequest`. At the .NET Framework level it
    throws `TypeLoadException` instead of skipping.
  - `ProxySettingsTests` env-var precedence fails on Windows, because env var names are case-insensitive there.
- **On a Unity upgrade:** capture again, update `strip/unity-defines.txt`, and run enforce mode.
  The header of `unity-defines.txt` records how the sets were captured.

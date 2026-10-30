# 2026-10 — E7: RSA defaults RsaMaxSize = 8192, RsaMaxMRTests = 0 (#17)

## What

Edge cut E7 (STRIP_PLAN_V2.md §1, §3 E7). `RsaKeyParameters.Validate` (public-key path, `!isInternal`)
now defaults to an 8192-bit modulus cap (upstream 16384) and to zero Miller-Rabin rounds (upstream
`GetMRIterations(bits / 2)`, i.e. 3 rounds for every key of 3072 bits or more). This neutralises upstream
`8ee52127`, which runs Miller-Rabin on every peer RSA key: about 1.14 s per 8192-bit key on a desktop
(2.2 s measured on the WSL lane box) and 9.3 s at 16384 bits, a hostile-server CPU DoS per handshake.

Both properties (`Org.BouncyCastle.Rsa.MaxSize`, `Org.BouncyCastle.Rsa.MaxMRTests`, thread property or
environment variable) still override the defaults, as upstream.

## Files

- `crypto/src/crypto/parameters/RsaKeyParameters.cs` — two default arguments changed (`:85` 16384 → 8192;
  `:94` `defaultIterations` → 0) and the `defaultIterations` local removed; each change has a
  `// turbo-strip: E7` comment.
- `crypto/test/src/turbo/RsaKeyParametersE7Test.cs` (new) — plain-NUnit regression fixture until the smoke
  suite (#26) exists:
  - `Modulus8192AcceptedFast` — 8192-bit composite modulus accepted; fastest of up to 5 warm runs < 50 ms.
  - `Modulus8193Rejected` — "RSA modulus out of range" from the ctor and from `ValidateModulus`.
  - `NoMillerRabinByDefault` — a 1024-bit prime (passes the small-factor check, only Miller-Rabin rejects
    it) is accepted: deterministic proof that the default runs no Miller-Rabin.
  - `MaxSizeOverrideStillRespected`, `MillerRabinOverrideStillRespected` — the thread properties still
    work (cleaned up in `[TearDown]`).

## Decisions

- **Smallest hunk.** Only the two default arguments change. `GetMRIterations` stays in the file unused
  (no compiler warning: unused private methods are an analyzer diagnostic only), so an upstream edit to
  it does not conflict; the `defaultIterations` local was removed rather than left as a dead computation.
  The Miller-Rabin branch stays, so the property override keeps working and `Primes` stays referenced
  (no closure change).
- **Timing assertion.** One warm-up construction (JIT, static init), then the minimum of up to 5 timed
  runs (stops at the first run under the bound) must be under the 50 ms acceptance target. The real cost
  after the cut is the small-factor check (well under 1 ms), and the old code costs ~2 s per run, so the
  margin is two orders of magnitude both ways; a loaded 4-CPU box or one GC pause cannot flip it. The
  moduli are built in static initialisers, outside every timed region.
- **Deterministic Miller-Rabin check.** Timing alone cannot tell "MR off" from "MR fast"; the prime
  modulus test does, without timing.
- **Bypass property.** `Org.BouncyCastle.Rsa.AllowUnsafeModulus` still skips every check, including the
  8192 cap (upstream behaviour). TurboKeyFactory (E5) enforces its own 2048..8192 window and the 64-bit
  exponent bound before calling the ctor, so the strip's peer-key window holds even if an environment
  variable overrides these defaults.
- **Namespace rewrite.** The property names are string literals `Org.BouncyCastle.Rsa.*`; whether the
  rewrite (#9) touches string literals decides whether overrides keep their upstream names. Not E7's
  concern; noted for the rewrite lane and for the plan §7 reserve ("E7 becomes property settings").

## Deferred

- Smoke row (8192 accepted fast, 8193 rejected, prime modulus accepted) moves to the smoke suite (#26)
  when the harness (#23) exists; this fixture is the stand-in.

## How verified

- Fixture against the old code (cut reverted): 3 of 5 fail (`Modulus8192AcceptedFast` best 2200 ms,
  `Modulus8193Rejected` no exception, `NoMillerRabinByDefault` "RSA modulus is not composite"); the two
  override tests pass on both, as intended.
- `DOTNET_ROLL_FORWARD=Major dotnet test --framework net6.0 crypto/test/BouncyCastle.Crypto.Tests.csproj
  --filter "FullyQualifiedName~RsaKeyParametersE7Test|FullyQualifiedName~TurboKeyFactoryTest|FullyQualifiedName~RsaKeyParametersTest|FullyQualifiedName~Org.BouncyCastle.Crypto.Tests.RsaTest"`:
  63 passed, 0 failed. No upstream fixture uses an RSA modulus over 8192 bits or relies on Miller-Rabin
  rejecting a prime modulus, so no expected failures.
- `./tools/ci/check.sh`: OK (library builds netstandard2.0 and net6.0; strip.sh not present yet).

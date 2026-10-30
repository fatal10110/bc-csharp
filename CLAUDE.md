# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Start with `AGENTS.md` for the shared repository guidance used across coding agents. Treat this file as the Claude-specific companion document, and keep it aligned with `AGENTS.md` when architecture, workflow, or conventions change.

## Project Overview

fatal10110/bc-csharp is a fork of Bouncy Castle for .NET (`bcgit/bc-csharp`; root namespace `Org.BouncyCastle`, NuGet id `BouncyCastle.Cryptography`, non-FIPS tree). `master` mirrors upstream. The **`strip-v2`** branch produces a scripted, reproducible reduction of upstream to a minimal **TLS 1.2/1.3 client** subset, namespace-rewritten to `TurboHTTP.SecureProtocol.Org.BouncyCastle`, which turboHTTP (fatal10110/turboHTTP — Unity 2021.3, IL2CPP on iOS/Android) vendors as its TLS fallback. The plan is `STRIP_PLAN_V2.md`. No action is ever taken on bcgit/bc-csharp; upstream is fetched read-only for bumps.

## Architecture

**Upstream solution (unchanged layout):**
- `crypto/src/BouncyCastle.Crypto.csproj` — the library; multi-targets `net6.0;netstandard2.0;net461`; signed with `BouncyCastle.NET.snk` (do not bypass signing or modify the key); versioned by Nerdbank.GitVersioning from `version.json` (needs git history).
- `crypto/test/BouncyCastle.Crypto.Tests.csproj` — NUnit 3 tests; bulk vectors in the separate `bc-test-data` repo (sibling checkout, found by `SimpleTest.FindTestDataPath`).
- Source grouped by domain under `crypto/src/` (`tls/`, `crypto/`, `math/`, `asn1/`, `x509/`, `security/`, `util/`, `pqc/` …).

**strip-v2 additions:**
- `crypto/src/turbo/` — turbo-owned code (`Org.BouncyCastle.Turbo`, MIT header), e.g. `TurboKeyFactory`.
- Edge cuts E1–E14 — minimal commits on `strip-v2`, one per E-number, every hunk marked `// turbo-strip:`.
- `strip/` — `BASE` (pinned upstream SHA), `ROOTS_SHA`, `roots/` (consumer copies, `RootStubs.cs`, `roots-extra.cs` API contract), `deny.txt`, `budget.txt`, `unity-defines.txt`, `Closure.csproj`, `tool/` (closure/deny tooling), `smoke/`, `strip.sh`, `journal/`. Output: `strip/out/` (Lib + `.meta`, `LICENSE.md`, `THIRD-PARTY-NOTICES.txt`, `STRIP_INFO.md`).
- `tools/ci/check.sh` (local gate), `tools/agent-tools/` (agent tools), `.github/` (CI, CodeQL, PR template), `.claude/` (skills, agents).

**Pipeline (`strip.sh`):** prepare → closure (fixpoint over the union of define sets, C# lookup-order resolution, namespace stubs, deny list, referrer sweep) → builds (each define set; rewritten tree as `TurboBC.*.dll`; consumer compile check) → namespace rewrite → smoke suite → package → hand over to turboHTTP #141.

## Key Technical Decisions

Recorded in `STRIP_PLAN_V2.md` §2; confirmed/overridden in turboHTTP #141.

- **A — Chain validation outside BC.** Native platform verifiers on mobile, `X509Chain` on desktop; no BC PKIX, no BC certificate-signature verification (`X509Certificate.Verify` throws).
- **B — No TLS 1.2 CBC.** **C — No X25519MLKEM768** for now. **D — No OCSP request** (must-staple not enforced). **E — No Ed25519/Ed448 certificates.** **F — No TLS 1.3 resumption.**
- **G — Timing:** `BasicGcmMultiplier` always (constant-time GHASH); `AesLightEngine` without AES-NI (leak reduced, not removed); ChaCha20 first.
- **Groups:** x25519, secp256r1, secp384r1, secp521r1. Suites: TLS 1.3 CHACHA20/AES_128_GCM/AES_256_GCM; TLS 1.2 ECDHE_{ECDSA,RSA} with the same AEADs.
- **Key limits (TurboKeyFactory + E7):** RSA 2048–8192 bits, public exponent ≤ 64 bits, Miller-Rabin off for peer keys; EC only on named P-256/384/521; explicit EC parameters rejected.
- **Deny subsystems, not helpers;** cut at call sites; turbo-owned files over churny factories.
- **Integration:** PRs target `strip-v2`, squash-merged; a bump rebases `strip-v2` onto new upstream (owner force-push).

## Development Status

- **Plan:** COMPLETE — `STRIP_PLAN_V2.md` rev 6.3, review cycle closed.
- **Agent workflow and CI:** COMPLETE — CI (`ci`, CodeQL), local gate, skills (`bcstrip-*`), agent types and agent tools ported from turboHTTP. See `strip/journal/2026-10-agent-workflow-ci.md`.
- **M1 Tooling (#4–#10):** NOT STARTED. `strip/tool/` holds the closure prototype only.
- **M2 Bootstrap & edge cuts (#11–#21):** NOT STARTED.
- **M3 Smoke suite, enforce & handover (#22–#31):** NOT STARTED; #29 waits on turboHTTP #141 (Unity define sets, decision record).

## Implementation Milestones

Order of work (`STRIP_PLAN_V2.md` §6):

1. **M1 — Tooling:** roots, `Closure.csproj`, closure resolver, deny/sweep, rewrite/packaging, `strip.sh`.
2. **M2 — Bootstrap & edge cuts:** `strip.sh --report` on provisional define sets, then E1–E14.
3. **M3 — Smoke, enforce, handover:** smoke suite; real Unity define sets from turboHTTP #141; enforce run and `budget.txt`; package and hand over. turboHTTP then does #140/#143, #141 (sync + gate), #142.

**Strip done:** smoke suite passes here and the turboHTTP #141 gate passes on output from the recorded `BASE` + `ROOTS_SHA`.

## Critical Risk Areas

1. **Runtime-only breakage** — static initializers/registries that throw when entries are removed (`CustomNamedCurves.DefineCurveAlias`); only smoke rows catch these.
2. **Hostile-server DoS** — key sizes, exponents, ASN.1 nesting, PSS parameters; every bound must sit before allocation or modexp.
3. **Unity define sets** — Unity may not define `*_OR_GREATER`; partial sets break `#if` guards (E13); unknown until turboHTTP #141 delivers.
4. **Rebase surface** — cuts in frequently changing upstream files (`TlsUtilities`, factories) turn bumps into manual conflict work; reserve alternative is the official DLL with Cecil rename (plan §7).

## Testing

- The strip's gate is the **smoke suite** (`strip/smoke/`, #22–#27): curve lookup, primitive KATs per DLL, OpenSSL 3 interop, exact ClientHello assertions, hostile inputs, timeout.
- Tooling tests: `python3 -m unittest discover -s tools/agent-tools -p 'test_*.py'`, the same for `strip/tool`, and `node .claude/skills/bcstrip-waves/waves_sim.mjs`.
- Upstream `crypto/test` is not a gate on `strip-v2` (cuts break parts of it). Scoped runs when an issue asks:

```bash
dotnet build crypto/src/BouncyCastle.Crypto.csproj -f netstandard2.0
dotnet test --framework net6.0 crypto/test/BouncyCastle.Crypto.Tests.csproj --filter "FullyQualifiedName~<Fixture>"
```

## Conventions

**Upstream code (inherited):**
- Multi-TFM guards: Span code under `#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER`, intrinsics under `#if NETCOREAPP3_0_OR_GREATER`; the `#else` path stays functionally equivalent. ISA detection only via `Org.BouncyCastle.Runtime.Intrinsics` wrappers (skill `intrinsics-testing`).
- Constant-time discipline: no branch, table index or early exit on secrets; `Arrays.FixedTimeEquals`; wipe with `Arrays.ZeroMemory`.
- `crypto/src/pqc/` tracks reference C; it is denied in the strip anyway.
- Style: `.editorconfig` (4 spaces, Allman), 120 columns for new code, always brace control statements (except single-line `return`/`throw` without `else`), expression-bodied members when they fit on two lines. Do not reformat upstream code you are not otherwise editing.
- Tests: plain NUnit with classic asserts; don't extend `SimpleTest` in new code.

**strip-v2:**
- Upstream API-stability rules (`[Obsolete]`, `// TODO[api]`) do not apply: cuts remove API on purpose. Keep every cut minimal and marked `// turbo-strip:`.
- Output code is C# 9, no `unsafe`, APIs available on netstandard2.1 and net471.
- Turbo-owned files: `crypto/src/turbo/`, namespace `Org.BouncyCastle.Turbo`, MIT header.
- Commit messages: short imperative summary (~50–70 chars), no conventional-commit prefix. Never create a non-fast-forward merge commit without explicit direction.

## Tooling, Gates And Agent Workflow

`AGENTS.md` ("Local Gates And CI", "Agent Workflow") is the source of truth. In short:

- Run `./tools/ci/check.sh` before every push (`--full` before a PR). It formats-checks changed C# only and builds the strip (`strip/strip.sh --report` once present, else the library for netstandard2.0).
- CI runs `check.sh --full` on PRs to `strip-v2`; aggregate check `ci`; CodeQL on fork-owned code.
- Work comes from GitHub issues #3–#31 (milestones "Strip v2 — M1/M2/M3", project "BouncyCastle strip v2"). Use the skills `bcstrip-issue` (one issue), `bcstrip-pr-review`, `bcstrip-pr-review-comments`, and `bcstrip-waves` (multi-PR fan-out with the `wave-*` agent types in `.claude/agents/`).
- Worktrees go under `../bc-csharp-worktrees/`. PRs target `strip-v2`.

## Post-Implementation Review

After completing each implementation step (edge cut, turbo-owned type, tooling component, smoke rows), invoke both specialist agents for review before marking the step as done:

- **crypto-security-reviewer** (`.claude/agents/crypto-security-reviewer.md`) — Reviews hostile-server input handling, advertised-vs-processable, bounds, validation bypass, exception mapping, constant time and decision A.
- **strip-build-reviewer** (`.claude/agents/strip-build-reviewer.md`) — Reviews edge-cut policy, closure correctness, runtime-only breakage, define sets, Unity/IL2CPP compatibility, determinism, packaging and rebase surface.

Both reviews must pass before proceeding. When a review identifies issues that require code changes, fix them and run both reviews again. Repeat until all issues are resolved or explicitly deferred with a follow-up issue.

After reviews pass, **update the implementation journal** (`strip/journal/`), then update this file's Development Status section.

## Implementation Journal

An implementation journal is kept in `strip/journal/`. Each implementation session gets its own file. After completing each step you **must** create or update a session file before marking the step as done. Each file includes:

- **What** was implemented (brief description)
- **Files created/modified** (paths + what each contains)
- **Decisions made** (choices, trade-offs, deferred items with their follow-up issues)
- **How verified** (gates, strip.sh mode, smoke rows)

File naming: `YYYY-MM-<short-description>.md` (e.g. `2026-11-e5-turbo-key-factory.md`). Read the folder at the start of each session to recover the history.

## Keeping This File Current

Update this file whenever a milestone or issue group completes, decisions change (turboHTTP #141 decision record), conventions change, or the tooling layout changes — especially Development Status, Key Technical Decisions and Architecture — so the next session starts with accurate context. Waves lanes never edit it; status updates land in a separate PR after a wave.

# AGENTS.md

This file provides repository-specific guidance for coding agents working on the **strip-v2**
branch of fatal10110/bc-csharp.

## Start Here

- Read this file before making changes.
- Read `STRIP_PLAN_V2.md` — the sections your issue names — before starting any edge cut or tooling
  work. The plan is the contract.
- Skim the latest relevant entries in `strip/journal/` to avoid regressing prior decisions.
- Read the GitHub issue you are working on (`tools/agent-tools/issue_slice.py <n>`); its Acceptance
  list defines done.
- Keep `AGENTS.md` and `CLAUDE.md` aligned when rules or workflow change.

## Project Snapshot

- This repository is a **fork** of upstream Bouncy Castle C# (`bcgit/bc-csharp`). `master` mirrors
  upstream; **`strip-v2` is the default branch**, protected by CI: every change lands through a PR
  that passes the required `ci` check (only the owner bypasses, for bump force-pushes).
- Goal: a scripted, reproducible reduction of upstream to a minimal **TLS 1.2/1.3 client** subset,
  namespace-rewritten to `TurboHTTP.SecureProtocol.Org.BouncyCastle` and handed to turboHTTP
  (fatal10110/turboHTTP, Unity 2021.3, IL2CPP on iOS/Android) as its TLS fallback.
- Consumer entry points: `BouncyCastleTlsProvider`, `TurboTlsClient`, `TurboTlsAuthentication` in
  turboHTTP `Runtime/Transport/BouncyCastle/`.
- **No actions on bcgit/bc-csharp, ever** (no issues, PRs, comments). Upstream is only fetched
  read-only for bumps.
- **Suspected vulnerability in upstream code:** do not file it publicly and do not contact bcgit or
  bouncycastle.org (this overrides `SECURITY.md`); stop and tell the owner.

## Architecture

- **Upstream tree** (`crypto/src`, `crypto/test`) stays in place; the strip is computed from it.
- **Edge cuts** (`STRIP_PLAN_V2.md` §3, E1–E14) are small commits on `strip-v2`, one per E-number or
  per issue E-range (#14 E2–E4, #19 E9–E12), every hunk marked `// turbo-strip:`.
- **Turbo-owned code** (planned, M2) lives in `crypto/src/turbo/` (namespace `Org.BouncyCastle.Turbo`, MIT
  header), e.g. `TurboKeyFactory`.
- **Strip tooling** lives in `strip/`. Present: `BASE`, `tool/` (closure prototype), `unity-probe/`,
  `journal/`. Planned (M1/M3): `ROOTS_SHA`, `roots/`, `deny.txt`, `budget.txt`, `unity-defines.txt`,
  `Closure.csproj`, `smoke/`, `strip.sh`. Output goes to `strip/out/`
  and is handed over to turboHTTP (#141 there).
- **Agent and CI tooling** lives in `tools/` (`tools/ci/check.sh`, `tools/agent-tools/*`),
  `.github/` and `.claude/`.

## Strip Rules

- Deny whole subsystems, not shared helpers (`STRIP_PLAN_V2.md` §3 deny list).
- Cut at call sites; prefer turbo-owned files over editing churny upstream factories.
- Everything the ClientHello advertises must be processable by the stripped crypto.
- Build keys only through public constructors so master's validation runs.
- Never add a throwing entry to a static initializer/registry (E6 aliases lesson).
- Output targets Unity: C# 9, no `unsafe`, APIs on netstandard2.1 and net471 reference assemblies.

## Design Constraints

- Server input is hostile: bound every server-controlled size before allocation or expensive math,
  using the bounds the plan defines (RSA 2048–8192 bits, exponent ≤ 64 bits, ASN.1 depth via
  upstream limits; PSS salt only if Appendix A is revived).
- Decision A: BouncyCastle does no chain validation and no certificate-signature verification;
  turboHTTP validates chains with platform verifiers.
- Constant-time discipline and `Arrays.ZeroMemory` for secrets, as upstream.
- Upstream API stability rules do **not** apply on `strip-v2` (cuts remove API on purpose), but
  every cut stays minimal for rebase-ability.

## Known Risk Areas

- Runtime-only breakage the compiler cannot see: static initializers, registries, string-keyed
  lookups.
- Unity define sets (`*_OR_GREATER` symbols) differ from SDK builds; `#if` guard mismatches (E13).
- Rebase conflicts on bump in frequently changing upstream files (`TlsUtilities`, factories).
- Denial of service from server-controlled key sizes and parameters.

## Source Of Truth

- Plan: `STRIP_PLAN_V2.md` (decisions A–G, edge cuts, tooling, smoke suite, order of work).
- Work queue: GitHub issues in fatal10110/bc-csharp — epic #3, milestones "Strip v2 — M1/M2/M3",
  project "BouncyCastle strip v2".
- History: `strip/journal/`.
- Consumer-side work: fatal10110/turboHTTP issues #4, #5, #8, #33, #34, #36, #46, #113, #140–#143
  (plan §8).

## Required Workflow

1. Read the issue and the plan sections it names; verify cited file:line on `origin/strip-v2`.
2. Write the failing check first (smoke/KAT row, tool test).
3. Make the smallest change that satisfies the plan text.
4. Run the local gate; apply both specialist rubrics; fix and re-review.
5. Add a `strip/journal/` entry: what, files, decisions, deferred items, how verified.
6. When status, rules or workflow change, update both `AGENTS.md` and `CLAUDE.md` (not in a waves
   lane).

## Specialist Review Rubrics

Two rubrics live under `.claude/agents/`. Treat them as mandatory checklists even without
subagents:

- Crypto security rubric: `.claude/agents/crypto-security-reviewer.md` — hostile-server input,
  advertised = processable, bounds, validation bypass, exception mapping, constant time, decision A.
- Strip build rubric: `.claude/agents/strip-build-reviewer.md` — edge-cut policy, closure
  correctness, runtime-only breakage, define sets, Unity/IL2CPP compatibility, determinism,
  packaging, rebase surface.

Before an edge cut, turbo-owned file or tooling change is complete: run both, fix findings,
re-review, and document deliberate deferrals with a follow-up issue.

## Testing

- The strip's tests are the smoke suite (`strip/smoke/`, issue #22): curve lookup, primitive KATs
  per DLL, OpenSSL interop, exact ClientHello assertions, hostile inputs, timeout.
- Tooling tests: `tools/agent-tools/test_*.py`, `strip/tool/test_*.py`, and
  `.claude/skills/bcstrip-waves/waves_sim.mjs`.
- Upstream `crypto/test` is **not** a gate on `strip-v2`: edge cuts intentionally break parts of it.
  Scoped `dotnet test --filter` runs are allowed when an issue asks for them, and for validation (below).
- `bc-test-data` (bcgit/bc-test-data, cloned read-only) holds the bulk vectors and credentials that many
  upstream tests load (e.g. the TLS tests read `tls/credentials`). `SimpleTest.FindTestDataPath` walks up
  from the working directory to a `bc-test-data` folder, so one clone beside the repo (`../bc-test-data`)
  serves the main checkout and every worktree. Use it when needed to validate code the strip keeps (TLS,
  ASN.1, X.509, EC/RSA, primitives): run the scoped upstream tests on `BASE` first, then after an edge cut
  or a bump, and compare. New failures the cut removes on purpose (TLS 1.2 CBC suites, Ed25519, PKIX,
  ...) are expected; any other new failure is a regression. It is a validation aid, not a CI gate (#35
  scripts the diff).

## Local Gates And CI

- `./tools/ci/check.sh` before every push: `dotnet format whitespace` on changed fork-owned C#
  (`crypto/src/turbo`, `strip`, `tools`); for changed upstream C#, only added lines are checked
  (trailing whitespace) — upstream files are never reformatted. Then `strip/strip.sh --report` once it
  exists (#30 switches the gate to enforce mode), else the whole library for netstandard2.0 and
  net6.0. `--full` adds actionlint, shellcheck, the Python tool tests and the waves simulation; run it
  before opening a PR (waves lanes: when the lane note asks). `--fix` formats fork-owned C#.
- CI (`.github/workflows/ci.yml`) runs `check.sh --full` on PRs to `strip-v2` and on pushes to it;
  the aggregate check is `ci`. CodeQL (`codeql.yml`) analyses fork-owned code only
  (`crypto/src/turbo`, `strip`, `tools`, `.github`).
- Prerequisites: .NET SDK 8, Python 3, git; optional actionlint, shellcheck, node, Homebrew
  OpenSSL 3.x (smoke interop). Scoped `dotnet test --framework net6.0` needs the .NET 6 runtime or
  `DOTNET_ROLL_FORWARD=Major`, and for most fixtures a `bc-test-data` checkout beside the repo
  (`git clone --depth 1 https://github.com/bcgit/bc-test-data.git`, about 7 GB).

## Agent Workflow

GitHub issues #3–#31 are the work queue; milestones order them (M1 Tooling → M2 Bootstrap & edge
cuts → M3 Smoke suite, enforce & handover) and the project "BouncyCastle strip v2" groups them.
Skills in `.claude/skills/` (plain markdown, usable by any agent):

- `bcstrip-issue` — implement one issue end to end: worktree, failing check first, change, gates,
  both rubrics, journal entry, PR against `strip-v2` that closes the issue.
- `bcstrip-pr-review` — first-pass review of a PR against its issue's acceptance list, the plan,
  hostile-input security and both rubrics; inline comments with severities.
- `bcstrip-pr-review-comments` — address review comments: verify each, fix confirmed ones, reply
  with evidence.
- `bcstrip-waves` — multi-PR fan-out: lanes (one PR each) grouped into waves and tracks, with
  long-lived implementation and review agents per lane, a serial merge agent and helper brokers,
  coordinated through `tools/agent-tools/wave_mail.py`.

Agent tools (`tools/agent-tools/`): `look.py` (batched C# declaration/range/rg lookups),
`issue_slice.py`, `issue_search.py`, `pr_search.py`, `wave_mail.py`.

Rules for every agent:

- Work in a worktree under `../bc-csharp-worktrees/`, never in the primary checkout.
- Never push to `strip-v2` directly: push a `wf/...` branch and open a PR against `strip-v2`; it is
  squash-merged once `ci` is green (one commit per PR keeps the edge-cut series).
- One issue (or one lane of related issues) per PR; "Closes #N" only for fully delivered criteria;
  anything left becomes a follow-up issue before the PR is opened.
- Every PR body follows `.github/pull_request_template.md` and records which local gates ran.
- Lanes add their own journal file and do not edit `AGENTS.md`/`CLAUDE.md`.
- Never write files, commits or PRs into turboHTTP. The handover comment on turboHTTP #141 is
  posted by the owner or with the owner's approval.
- Edge cuts wait for #10 (`strip.sh`), or keep the whole library compiling until it merges.
- Never run waves during a bump (the owner rebases and force-pushes `strip-v2`).

## Repository Conventions

- Follow upstream `.editorconfig` (4 spaces, Allman braces); 120-column limit for new code.
- Commit messages: short imperative summary (~50–70 chars), no conventional-commit prefix; body
  only when the why is not obvious.
- Never create a non-fast-forward merge commit without explicit direction (the bcstrip-waves
  conflict/branch-update protocol is such direction).
- Do not reformat upstream code you are not otherwise editing (rebase surface).

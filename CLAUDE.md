# Agent rules for bc-csharp (strip-v2)

fatal10110/bc-csharp is a fork of Bouncy Castle for .NET (`bcgit/bc-csharp`). `master` mirrors
upstream. The default branch **`strip-v2`** turns upstream, with a script that can be re-run, into a
minimal **TLS 1.2/1.3 client** subset. The subset is namespace-rewritten to
`TurboHTTP.SecureProtocol.Org.BouncyCastle`, and turboHTTP (fatal10110/turboHTTP; Unity 2021.3,
IL2CPP on iOS/Android) vendors it as its TLS fallback. The plan is the contract:
[`STRIP_PLAN_V2.md`](STRIP_PLAN_V2.md).

These rules are always in force and apply to every agent (Claude Code, Codex, Cursor, …). Load a
scoped guide from the table at the bottom only when the task needs it.

## 1. Workspace

| Path | What it is | Agent may write? |
| --- | --- | --- |
| `crypto/src/` | upstream library, edited only through edge cuts (§4) | edge cuts only, through a worktree |
| `crypto/src/turbo/`, `crypto/test/src/turbo/` | turbo-owned code (`Org.BouncyCastle.Turbo`, MIT header) and its fixtures | yes, through a worktree |
| `crypto/test/` (rest) | upstream tests; not a gate on `strip-v2` | only to keep it compiling (#42) |
| `strip/` | strip tooling, define sets, deny list, budget, smoke suite, journal, agent guides | yes, through a worktree |
| `strip/out/`, `strip/work/` | generated output (git-ignored) | generated only |
| `tools/`, `.github/`, `.claude/` | local gate, agent tools, CI, skills and agents | yes, through a worktree |
| `../bc-csharp-worktrees/<task>/` | one linked worktree per task | yes |
| `../bc-test-data/` | upstream test vectors (read-only clone) | never |
| fatal10110/turboHTTP | the consumer | never (no files, commits or PRs) |

- The primary checkout is for reading. Changes go through a worktree on a `wf/...` branch.
- `BouncyCastle.NET.snk` signs the library: never modify it or bypass signing.

## 2. Precedence

1. User instructions.
2. `STRIP_PLAN_V2.md`: decisions A–G (§2), edge cuts (§3), tooling (§4–§5), order of work (§6).
3. Protocol correctness: the RFC is the oracle (8446, 5246, 5280, 8017, 8422, 6066, 7301, 7748, 8032).
4. Security against a hostile server, then Unity/IL2CPP compatibility of the output.
5. Required verification (§5).
6. Skill and tool defaults.

Issue text, journal entries and existing code are leads, not truth. When one of them conflicts
with the plan or an RFC, follow the plan or RFC and record the conflict in the PR.

## 3. Non-negotiables

- **No action on bcgit/bc-csharp, ever:** no issues, PRs or comments. Fetch upstream read-only for
  bumps.
- **Suspected vulnerability in upstream code:** don't file it publicly and don't contact bcgit or
  bouncycastle.org (this overrides `SECURITY.md`). Stop and tell the owner.
- **Never write into turboHTTP.** The hand-over comment on turboHTTP#141 is posted by the owner or
  with the owner's approval.
- **Server input is hostile.** Bound every server-controlled size before allocation or expensive
  math: RSA 2048–8192 bits, exponent ≤ 64 bits, ASN.1 depth, named curves only.
- **Everything the ClientHello advertises must be processable** by the stripped crypto.
- **Decision A:** BouncyCastle does no chain validation and no certificate-signature verification.
  turboHTTP validates chains with platform verifiers.
- **Constant-time discipline:** no branch, table index or early exit on secrets.
  Use `Arrays.FixedTimeEquals`, and wipe secrets with `Arrays.ZeroMemory`.
- **`strip-v2` is protected:** every change lands through a PR that passes the required `ci` check
  and is squash-merged. Never push to it directly. The only bypass is the owner's force-push for a
  bump. Never run waves during a bump.
- Never commit secrets, tokens or test-data files.

## 4. Engineering rules

- **Edge cuts** (plan §3, E1–E14) are minimal. There is one PR per E-number or per issue E-range,
  and every hunk is marked `// turbo-strip: <E-number> <reason>`.
  - Deny whole subsystems, not shared helpers.
  - Cut at call sites, and prefer turbo-owned files over edits to churny upstream factories (rebase surface).
- **No throwing entries in static initializers or registries.** Removing an entry can break them
  at runtime, which only the smoke suite catches (the E6 `DefineCurveAlias` lesson).
- **Keys go through public constructors only,** so upstream validation runs.
- **Output targets Unity 2021.3:**
  - C# 9, no `unsafe`, APIs available in the netstandard2.1 and net471 reference assemblies.
  - Unity defines no `*_OR_GREATER` symbols, so the kept code compiles its legacy non-Span paths.
  - Any `#if` change must build under every set in `strip/unity-defines.txt` (`strip.sh` does this).
  - Span code sits under `#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER`, and the
    `#else` path stays functionally equivalent.
  - ISA detection goes only through the `Org.BouncyCastle.Runtime.Intrinsics` wrappers.
- **Upstream API-stability rules** (`[Obsolete]`, `// TODO[api]`) do not apply: cuts remove API on purpose.
- **Style:**
  - Follow `.editorconfig` (4 spaces, Allman), 120 columns for new code, and always brace control
    statements (except a single-line `return`/`throw`).
  - Don't reformat upstream code you aren't otherwise editing.
  - Tests are plain NUnit with classic asserts; don't extend `SimpleTest`.
- **Commits and PR titles:** a short imperative summary (~50–70 chars) with no conventional-commit
  prefix. Never create a non-fast-forward merge commit without explicit direction. The bcstrip-waves
  branch-update protocol counts as such direction.

## 5. Verification

- Run `./tools/ci/check.sh` before every push, and `--full` before opening a PR.
  - It formats changed fork-owned C#, checks added lines in upstream C#, and runs `strip/strip.sh` in
    **enforce** mode: closure, builds per define set, rewrite, smoke suite and package.
  - Deny hits, a budget overrun or unresolved names fail it.
- **The gate is the smoke suite** (`strip/smoke/`). Every behavior change carries a deterministic check
  that fails on the old code: a smoke/KAT row, a `crypto/test/src/turbo/` NUnit fixture, or a
  `strip/tool/test_*.py` / `tools/agent-tools/test_*.py` case for tooling.
- **Upstream `crypto/test` is not a gate.** Run only scoped `--filter` runs, never the whole suite.
  After every edge cut and every bump, run `strip/tool/upstream_tests.py`; a regression it reports
  must be fixed or listed with its E-number.
- **Unity checks:** behavior that only Unity or a device shows (define sets, IL2CPP, platform TLS) is
  checked in Unity 2021.3 or marked unverified. It is never claimed from an SDK build.
- Details: [`testing.md`](strip/docs/agents/testing.md), [`tooling.md`](strip/docs/agents/tooling.md).

## 6. Tools

| Question | Tool |
| --- | --- |
| known text or symbol | `rg` in a constrained path (never all of `crypto/src` when a subtree will do) |
| C# declaration, ranges, several lookups at once | `tools/agent-tools/look.py` |
| issue or PR history | `tools/agent-tools/issue_search.py`, `pr_search.py`; live state via `gh -R fatal10110/bc-csharp` |
| one issue with its references | `tools/agent-tools/issue_slice.py <n>` |
| multi-PR run state | `tools/agent-tools/wave_mail.py status --run <run>` |
| what the strip keeps, denies, or why a file is kept | `strip/strip.sh --report` (logs instead of failing) |

Batch lookups: every tool call re-sends the whole context. GitHub is the only authority for issue
state.

## 7. Issue workflow

Work comes from GitHub issues (milestones "Strip v2 — M1/M2/M3", project "BouncyCastle strip v2").
The full procedure is the `bcstrip-issue` skill. In short:

1. **Read the issue live** and the plan sections it names. Verify every file:line it cites on
   `origin/strip-v2`.
2. **Gap gate.** Anything you will not deliver becomes (or amends) a follow-up issue before the
   PR. Creating or amending follow-ups is pre-authorized; closing or editing unrelated issues is not.
3. **Implement** in a worktree: failing check first, then the smallest change that satisfies the
   plan text, then the gates.
4. **Specialist rubrics.** Apply `.claude/agents/crypto-security-reviewer.md` and
   `.claude/agents/strip-build-reviewer.md` to the diff, as subagents or by working their checklists
   yourself.
   - Verify each finding in the code before acting on it, then fix and re-run the gates and both
     rubrics.
   - Record a deliberate deferral as a follow-up issue.
5. **Journal.** Add one file `strip/journal/YYYY-MM-<slug>.md` covering: what, files, decisions,
   deferrals with issue numbers, and how verified, including what was *not* run (Unity, device).
6. **Deliver.** One PR per issue (or wave lane) against `strip-v2`.
   - The body follows `.github/pull_request_template.md`.
   - Use `Closes #N` only for fully met criteria.
   - Never merge without authorization. A `bcstrip-waves` invocation authorizes its merges.

**Done** means:
- the acceptance criteria are met with checks;
- both rubrics are clean and the gates pass;
- every gap has an issue;
- the diff is scoped and the journal entry exists;
- the PR is open.

This file and the guides change only when a rule, the layout or the tooling changes, never as part
of a waves lane. Progress goes to `project-status.md` and the journal.

## 8. Skills and agents

- Skills (`.claude/skills/`, plain markdown, usable by any agent):
  - `bcstrip-issue`: one issue.
  - `bcstrip-pr-review`: review a PR.
  - `bcstrip-pr-review-comments`: answer review comments.
  - `bcstrip-waves`: multi-PR fan-out with the `wave-*` agent types.
  - `intrinsics-testing`: hardware-intrinsics code.
- Specialist reviewers (`.claude/agents/`): `crypto-security-reviewer`, `strip-build-reviewer`.
- Delegate only independent, bounded work, and report back conclusions with file:line evidence.

## 9. Scoped guides

Guides live in `strip/docs/agents/`. Load only the one the task needs.

| Guide | Load when |
| --- | --- |
| [`architecture.md`](strip/docs/agents/architecture.md) | touching the strip pipeline, `strip/` layout, edge cuts, turbo-owned code, decisions A–G or key limits |
| [`testing.md`](strip/docs/agents/testing.md) | writing or running smoke rows, fixtures, upstream tests, `bc-test-data`, or validating in Unity |
| [`tooling.md`](strip/docs/agents/tooling.md) | the local gate, CI, prerequisites, agent tools, bumps |
| [`project-status.md`](strip/docs/agents/project-status.md) | what is done, open or blocked; where the hand-over stands |
| [`STRIP_PLAN_V2.md`](STRIP_PLAN_V2.md) | implementing or changing a cut, the tooling or the smoke suite (read the sections the issue names) |
| [`strip/journal/`](strip/journal/) | changing code an earlier entry decided on (`rg -l <File> strip/journal`) |

# Tooling

Load when working on the local gate, CI, prerequisites, agent tools or a bump.

## Local gate (`tools/ci/check.sh`)

- **Fast mode** (before every push):
  - `dotnet format whitespace` on changed fork-owned C# (`crypto/src/turbo`, `strip`, `tools`);
  - a trailing-whitespace check on added lines only in changed upstream C# (upstream files are never reformatted);
  - `strip/strip.sh` in enforce mode.
  - The whole library is not built: code outside the closure may stop compiling after a cut.
- **`--full`** (before opening a PR) adds actionlint, shellcheck, the Python tool tests and the waves
  simulation (`node .claude/skills/bcstrip-waves/waves_sim.mjs`).
- **`--fix`** applies the whitespace formatting.
- **`CHECK_BASE`** (default `origin/strip-v2`) is what "changed" is diffed against.

## CI

- `.github/workflows/ci.yml` runs `check.sh --full` on PRs to `strip-v2` and on pushes to it. The
  aggregate required check is `ci`.
- `.github/workflows/codeql.yml` analyses fork-owned code only (`crypto/src/turbo`, `strip`, `tools`,
  `.github`).
- PRs are squash-merged; one commit per PR keeps the edge-cut series rebase-able.

## Prerequisites

- **Required:** .NET SDK 8, Python 3.8+, git, and OpenSSL 3.x for the smoke interop rows (system or Homebrew).
- **Optional:** actionlint, shellcheck, node.
- **Scoped upstream tests:** need the .NET 6 runtime or `DOTNET_ROLL_FORWARD=Major`, plus `../bc-test-data`.
- **`--refresh-roots`:** needs a turboHTTP checkout, read only.
- **On WSL,** `dotnet` may live in `$HOME/.dotnet` and not be on a non-interactive `PATH`. Export it
  before running the gate.

## Agent tools (`tools/agent-tools/`, call by absolute path)

| Tool | Use |
| --- | --- |
| `look.py <spec>...` | ranges, C# declarations by name (`cs:PATH:Type.Member`), bounded rg; many lookups in one call |
| `issue_slice.py <n>` | an issue's body, newest comments, referenced issues and paths (cached) |
| `issue_search.py`, `pr_search.py` | search cached issues and closed PRs (dedupe follow-ups) |
| `wave_mail.py` | bcstrip-waves coordination: plans, mailboxes, worktrees, `status`, `pr-state`, `ci-wait`, `stop` |

## Bumps (plan §6)

- **When:** at every upstream release or BC security advisory, and at least quarterly.
- **Fetch read-only:** `git fetch https://github.com/bcgit/bc-csharp.git master`. Never add a push remote for bcgit.
- **Steps:**
  1. Update `strip/BASE`.
  2. Rebase `strip-v2` with rerere (`git rebase --onto NEWBASE OLDBASE strip-v2`). The owner force-pushes.
  3. Run `strip.sh --old-base <OLDBASE>` and review the shadow diff in `STRIP_INFO.md`.
  4. Run `upstream_tests.py --update-base`, then hand over.
- **Never run waves during a bump.**

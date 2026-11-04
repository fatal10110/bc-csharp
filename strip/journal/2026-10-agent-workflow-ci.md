# 2026-10 — Agent workflow, CI and repository guidance for strip-v2

## What

Ported turboHTTP's agent workflow to this fork's `strip-v2` branch: CI and CodeQL, a local gate,
the four skills (issue, PR review, review comments, waves fan-out), the `wave-*` agent types and
agent tools, two specialist review rubrics, and `AGENTS.md` / `CLAUDE.md` in turboHTTP's format.

## Files

- `.github/workflows/ci.yml` — `lint` job runs `tools/ci/check.sh --full`; aggregate `ci` check.
  Triggers: PRs to `strip-v2`, pushes to `strip-v2`. Full-history checkout (Nerdbank.GitVersioning,
  format diff base).
- `.github/workflows/codeql.yml` — C#, Python, Actions; fork-owned paths only (`crypto/src/turbo`,
  `strip`, `tools`, `.github`).
- `.github/dependabot.yml` — GitHub Actions updates against `strip-v2`.
- `.github/pull_request_template.md` — replaces the upstream template on this branch (Summary,
  Closes, Acceptance, Decisions, Wire/closure/limits, Local gates, Specialist rubrics, Follow-ups).
- `tools/ci/check.sh` — format of changed C# only; `strip/strip.sh --report` once it exists, else a
  netstandard2.0 library build; `--full` adds actionlint, shellcheck, Python tool tests, waves sim.
  Bash 3.2 compatible (macOS).
- `tools/agent-tools/` — `wave_mail.py`, `look.py`, `issue_slice.py`, `issue_search.py`,
  `pr_search.py` and tests (ported).
- `.claude/skills/bcstrip-{issue,pr-review,pr-review-comments,waves}/` — skills; waves includes
  `waves.js`, `waves_sim.mjs`, `plan.example.json` (ported).
- `.claude/agents/wave-*.md` — slim agent types (ported);
  `crypto-security-reviewer.md`, `strip-build-reviewer.md` — specialist rubrics replacing the Unity
  architects.
- `AGENTS.md`, `CLAUDE.md` — repository guidance; `CLAUDE.md` keeps upstream's code conventions and
  adds the strip-v2 sections.

## Decisions

- The integration branch is `strip-v2`; PRs are squash-merged into it so each PR stays one commit of
  the edge-cut series. Bumps rebase `strip-v2` and are done by the owner; no waves during a bump.
- Upstream `crypto/test` is not a CI gate (edge cuts break parts of it on purpose); the smoke suite
  is. Until `strip/strip.sh` exists the gate builds the full library.
- Format checks only changed C# files: reformatting upstream code would enlarge the rebase surface.
- CodeQL is limited to fork-owned code; upstream code is out of scope.
- No issue-seed tooling (turboHTTP's `.github/issue-seed`): the issues already exist (#3–#31).

## Deferred

- `strip-v2` is the default branch and is meant to be protected by CI (PR required, `ci` check
  required, owner bypass for bumps). At the time of writing the fork had no ruleset configured yet.

## Review fixes (same session)

Two independent reviews of the first commit found, among others:

- **Blocker:** the format step ran `dotnet format` on whole changed files, so any edge cut in one of
  the 370+ upstream files with tab/whitespace drift failed CI, and `--fix` would reformat the whole
  file. Now only fork-owned C# (`crypto/src/turbo`, `strip`, `tools`) is formatted; for upstream C#
  only added lines are checked for trailing whitespace.
- **Major:** the gate built only netstandard2.0 (non-Span paths); it now builds netstandard2.0 and
  net6.0 until `strip.sh` exists.
- **Major:** the old rule against filing upstream vulnerabilities publicly was lost; restored as
  "stop and tell the owner" (never bcgit, overrides `SECURITY.md`).
- Minor: a missing diff base now fails; `--report` vs enforce noted (#30 switches the gate); edge
  cuts wait for #10; "one commit per E-number or per issue E-range"; issues without
  `## Acceptance` use their opening bullets plus the plan text; prompts no longer claim CI runs
  `crypto/test`; parents track sub-issues (nothing to tick); bootstrap follow-ups go under #3;
  turboHTTP writes defined (no files/commits/PRs; #141 handover comment via the owner);
  `DOTNET_ROLL_FORWARD=Major` for net6.0 tests on a .NET 8-only machine; rubric bounds tied to the
  plan; planned files marked as planned.
- The waves simulation now asserts every lane prompt and the merger prompt stay on `strip-v2`
  (mutation-tested: a merger regression to `main` fails it).

## How verified

- `tools/ci/check.sh` and `tools/ci/check.sh --full` locally.
- `python3 -m unittest discover -s tools/agent-tools -p 'test_*.py'`.
- `node .claude/skills/bcstrip-waves/waves_sim.mjs`.

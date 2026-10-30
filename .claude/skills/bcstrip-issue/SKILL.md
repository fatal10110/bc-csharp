---
name: bcstrip-issue
description: >
  Implement one fatal10110/bc-csharp strip-v2 GitHub issue end to end: read the issue and the
  STRIP_PLAN_V2.md sections it names, work in a linked worktree off origin/strip-v2, write the
  failing smoke/KAT/tool test first, implement (edge cut, turbo-owned file or tooling), run the
  local gates, apply both specialist rubrics, add the strip journal entry, and open a PR against
  strip-v2 that closes the issue. Use when the user says "implement #N", "do E5", "pick up
  <issue>" in bc-csharp, or when a bcstrip-waves lane prompt names this skill. Do not use for
  reviewing a PR (bcstrip-pr-review), answering review comments (bcstrip-pr-review-comments),
  or multi-issue fan-out (bcstrip-waves).
---

# bc-csharp strip-v2 issue implementation

Repository rules live in `AGENTS.md` and `CLAUDE.md`; nothing here repeats them — read the
sections your change touches. A bcstrip-waves prompt overrides this file on test scope, worktree
commands and GitHub tooling.

## Authority

Security of the TLS client path, the plan, and rebase-ability outrank everything else:

- **Security**: the server is hostile. No change may advertise what cannot be processed, accept
  an unbounded server-controlled size, bypass master's key/point validation, or weaken
  constant-time code. The RFCs (8446, 5246, 5280, 8017, 8422, 7748, 8032, 6066, 7301) are the
  oracle for protocol behavior.
- **Plan**: `STRIP_PLAN_V2.md` decisions A–G and the edge-cut list are the contract. A change that
  departs from the plan needs the plan changed first (separate PR, user approval).
- **Rebase-ability**: cut at call sites, smallest possible hunk, `// turbo-strip:` marker on every
  hunk, one E-number per commit; prefer turbo-owned files in `crypto/src/turbo/` over editing churny
  upstream factories.
- **Scope**: never act on bcgit/bc-csharp; never write into turboHTTP from this repo.

Every change answers three questions in the PR body, from evidence:
1. **Wire/behavior**: what a TLS peer or the turboHTTP consumer observes differently.
2. **Closure**: which files enter or leave the closure, deny hits, rebase surface of touched files.
3. **Abuse/limits**: what a hostile server can send on the changed path and the bound that stops it.

## Work loop

1. **Scope.** Read the issue live (`tools/agent-tools/issue_slice.py <n>`, or `gh issue view <n>
   -R fatal10110/bc-csharp --comments`): Scope, Acceptance, Context. Copy the acceptance criteria
   into your worklog — they are the contract. Read the plan sections the Context names. Verify each
   cited file:line on `origin/strip-v2` (lines drift; find the current ones). Already done → comment
   with evidence, close it, stop.
2. **Gaps first.** List every acceptance item you will not deliver and why. Each becomes a
   follow-up issue (dedupe with `tools/agent-tools/issue_search.py <terms>`; same template;
   owning milestone; sub-issue of the right parent) **before** you edit.
3. **Research.** Read the RFC section yourself (https://www.rfc-editor.org/rfc/rfcNNNN.txt) for
   protocol claims. Read the newest `strip/journal/` entries touching these files. Map every caller
   of each method you change — including callers outside the closure (they may stop compiling; that
   is expected after edge cuts but must be stated).
4. **Worktree.** Never write in the primary checkout:

   ```bash
   git -C <repo> fetch -q origin strip-v2
   git -C <repo> worktree add ../bc-csharp-worktrees/issue-<n>-<slug> -b wf/issue-<n>-<slug> origin/strip-v2
   ```

   (bcstrip-waves lanes use `wave_mail.py worktree` instead.)
5. **Test first.** Add the check that fails on the old code: a smoke/KAT row under `strip/smoke/`
   for library behavior, a `strip/tool/test_*.py` or `tools/agent-tools/test_*.py` case for
   tooling. Deterministic only; hostile direction for security fixes (oversize, malformed,
   unsolicited). Before the smoke harness exists (#23), state the check you ran instead and add the
   row to the smoke issue.
6. **Implement.** The smallest complete change. Follow the plan's E-cut text exactly; keep C# 9,
   no `unsafe`, netstandard2.1/net471 APIs only; turbo-owned files carry the MIT header and
   namespace `Org.BouncyCastle.Turbo`.
7. **Gates.**

   ```bash
   cd <worktree> && ./tools/ci/check.sh            # format of changed C#, strip/library build
   cd <worktree> && ./tools/ci/check.sh --full     # + actionlint, shellcheck, tool tests, waves sim
   cd <worktree> && strip/strip.sh --report        # once the tooling exists; smoke when present
   ```

   Never run the whole upstream `crypto/test` suite: edge cuts intentionally break parts of it.
   Scoped `dotnet test --filter` runs are fine when the issue asks for them.
8. **Specialist rubrics.** Apply `.claude/agents/crypto-security-reviewer.md` and
   `.claude/agents/strip-build-reviewer.md` to your diff (subagents when you can; otherwise read
   both and work their checklists). Fix findings, re-run the gates, record deliberate deferrals with
   a follow-up issue.
9. **Journal.** Add `strip/journal/YYYY-MM-<issue-slug>.md` (what, files, decisions, deferred
   items, how verified). Update `CLAUDE.md`/`AGENTS.md` only when status or conventions change and
   you are not in a bcstrip-waves lane.
10. **Deliver.**
    - Audit `git diff origin/strip-v2...`: only in-scope files; every acceptance item maps to a hunk
      or a check.
    - Commit message: short imperative summary in the repository's style (no conventional-commit
      prefix), naming the behavior; end with `Co-Authored-By: Claude <noreply@anthropic.com>`.
    - Push `wf/...` and open ONE PR against **`strip-v2`** following
      `.github/pull_request_template.md` (Summary, Closes, Acceptance criteria, Decisions,
      Wire/closure/limits, Local gates, Specialist rubrics, Follow-ups), ending with
      `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.
    - Read the PR back (base `strip-v2`, closing keywords present). Remove the worktree unless asked
      to keep it, and report the PR URL.

## Follow-up issues

Template: `## Scope`, `## Acceptance` (checkboxes), `## Context` (plan section link, branch,
BASE). Labels from the existing set (`strip-v2`, `type:tooling|edge-cut|test|tracking`,
`security`, `blocked:external`). Milestone: tooling → `Strip v2 — M1: Tooling`; edge cuts and the
bootstrap → `Strip v2 — M2: Bootstrap & edge cuts`; smoke, enforce, handover → `Strip v2 — M3:
Smoke suite, enforce & handover`. Attach as a sub-issue of the matching parent (#4, #12, #22, #28)
and add it to project "BouncyCastle strip v2". Dedupe first; link back to the PR.

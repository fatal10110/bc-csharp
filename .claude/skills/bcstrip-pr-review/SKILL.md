---
name: bcstrip-pr-review
description: >
  Produce a first-pass review of an open pull request in fatal10110/bc-csharp against strip-v2 —
  whether it meets the acceptance criteria of the issues it closes and STRIP_PLAN_V2.md, TLS-client
  security against a hostile server, closure/define-set correctness, rebase-ability and tests —
  apply both specialist rubrics, submit every evidence-backed defect as an inline GitHub review
  comment, and end with an explicit bottom line saying whether anything must change before merge.
  Use when the user says "review PR N" for bc-csharp, or when a bcstrip-waves review prompt names
  this skill. Do not use for answering comments on your own PR (bcstrip-pr-review-comments).
---

# bc-csharp strip-v2 PR review

The PR body's claims are claims, not evidence. The linked issues' acceptance criteria and the plan
are the contract; the code is the evidence; the RFC is the oracle for protocol behavior. Every
review ends with a **bottom line** that says unambiguously whether any change is required.

## Priorities

TLS-client security, plan conformance and runtime safety of the stripped output lead, then:
acceptance criteria met → should-this-exist (smallest cut) → correctness → rebase surface →
tests → style. A bcstrip-waves prompt overrides this file on test scope, worktrees and GitHub
tooling.

## 1. Gather

```bash
gh pr view <N> -R fatal10110/bc-csharp \
  --json number,title,body,author,baseRefName,headRefName,headRefOid,files,additions,deletions,closingIssuesReferences,reviews,comments
gh pr diff <N> -R fatal10110/bc-csharp > <scratchpad>/pr<N>.diff
gh api repos/fatal10110/bc-csharp/pulls/<N>/comments --paginate
```

- Read the **whole** diff. Base must be `strip-v2`.
- Existing threads: do not repost what is raised or resolved. Every **unresolved** thread on the PR,
  including CodeQL (`github-advanced-security`) alerts, is part of your verdict: list them with
  `tools/agent-tools/wave_mail.py threads --pr <N>` and put each in the action list with the expected
  outcome. A review thread can be fixed, rebutted or turned into a follow-up issue; a CodeQL thread can
  only be fixed in code or dismissed with a reason (anything else leaves the alert open). On a re-review, first look at what
  earlier reviews never questioned, then the diff since the last reviewed head.
- Linked issues: for each, `tools/agent-tools/issue_slice.py <X>`; copy its **Acceptance** items
  into your checklist before reading the diff (no `## Acceptance` → its opening bullets plus the plan
  text for its E-cut or step are the contract). Read the plan section its Context names.
- Check out the head without touching the author's branch:

  ```bash
  git -C <repo> fetch origin pull/<N>/head:pr-<N>-review
  git -C <repo> worktree add ../bc-csharp-worktrees/pr-<N>-review pr-<N>-review
  ```

## 2. Verify the PR's claims

- Every "X is now bounded / rejected / no longer advertised" claim: grep the whole closure path,
  not only the diffed files (e.g. a key-size bound must hold on both `BcTlsRawKeyCertificate` and
  `X509Certificate.GetPublicKey`).
- Map each acceptance item to the hunk or check that satisfies it. No hunk → already satisfied on
  `strip-v2` (prove it) or **unmet**.
- Compare the change with the plan's E-cut text line by line; any departure needs a plan change.

## 3. Should this exist?

A new turbo-owned type, a cut in a churny upstream factory, an edit outside the plan's file list,
or a new tool dependency needs a reason in the issue or PR. Any action against bcgit/bc-csharp or
any file, commit or PR written into turboHTTP is a `[blocker]`.

## 4. Review the diff

- **Advertised vs processable** — derive the ClientHello the change produces (suites, groups,
  `signature_algorithms`, extensions) and check each entry can complete.
- **Hostile input** — every server-controlled size on the changed path is bounded before
  allocation or expensive math; validation is not bypassed; failures map to `TlsFatalAlert` or the
  documented exception; no throwing static initializer.
- **Every caller** — list call sites of each changed member, inside and outside the closure.
- **Closure** — files entering/leaving, deny hits, referrer sweep result; partial types and
  extension methods handled.
- **Define sets / language** — C# 9, no `unsafe`, APIs on netstandard2.1 and net471; `#if`
  guards consistent across the captured sets.
- **Rebase surface** — `git log --oneline 5200dfdf..$(cat strip/BASE) -- <file> | wc -l` (5200dfdf =
  the previous strip's base; later, the previous `strip/BASE`) for touched upstream files; markers
  present; one E-number or issue E-range per commit.
- **Tests** — a deterministic smoke/KAT/tool test that fails on the old code, in the hostile
  direction for security changes.
- **Journal** — the PR adds its `strip/journal/` file.
- **Over-engineering** — more than ~200 non-test lines, a new abstraction or option: look for the
  smaller change; post survivors as `[should-fix]`.

Run the checks yourself in the review worktree and record exactly what ran:

```bash
cd <review-root> && ./tools/ci/check.sh
cd <review-root> && strip/strip.sh --report     # when the tooling exists
```

## 5. Specialist rubrics

Apply `.claude/agents/crypto-security-reviewer.md` and `.claude/agents/strip-build-reviewer.md`
to the diff — as subagents when you can, otherwise read both and work their checklists. Findings
go through §6.

## 6. Gate every finding before posting

Post a finding only with: **where** (path + new-side line on the current head), **failure
scenario** (concrete server input or build condition → wrong state, cost, crash or exposure),
**evidence** (RFC/plan section, call sites checked, command output), and **fix**.

| Tag | Meaning | Blocks merge? |
|-----|---------|---------------|
| `[blocker]` | security hole, advertised-but-unprocessable, validation bypass, unmet acceptance item, plan departure without plan change, upstream/turboHTTP action | yes |
| `[must-fix]` | real bug, missing regression check for a new branch, failing gate, missing marker/journal | yes |
| `[should-fix]` | correctness-adjacent or rebase-surface issue worth fixing here | no, action expected |
| `[nit]` | small style/naming | no, but action required: fix it or reply why not |
| `[note]` | pre-existing gap or follow-up candidate; name the issue that tracks it (file one if none) | no; review body only, never inline |

There are no optional findings: a point not worth acting on is not raised. Every inline comment is
a thread that blocks the merge until it is settled (fixed, answered with a reason, or turned into an
issue) and resolved; an open CodeQL thread is settled only by a code fix or an alert dismissal with
a reason. So `[note]` items go in the review body, never inline.

## 7. Submit the review

Do not modify, commit, push, merge or close anything on the PR.

1. Confirm `headRefOid` has not moved.
2. Submit one review (event `COMMENT`) with every `[blocker]`/`[must-fix]`/`[should-fix]`/`[nit]` finding
   inline (`[note]` items only in the body). Nothing actionable →
   summary-only review.
3. Review body:

   ```markdown
   ## Bottom line
   **Verdict:** <Blocked | Changes required | Approve after small fixes | Approve as-is>
   **Action required before merge:** <YES | NO>
   <If YES: numbered list — `[tag] path:line — what to do`.>
   <Open threads (CodeQL included) and their expected outcome, or "none">  <Follow-ups to track or "none">

   ## Security, closure, limits
   ClientHello derived; hostile inputs considered and the bound that stops each; closure delta.
   Checks run: <check.sh result; strip.sh mode or "n/a">.

   ## Acceptance criteria (#<issue>)
   - [x]/[ ] <item> — <evidence, or "unmet: …">

   ## Specialist rubrics
   Crypto security: <clean | items>; Strip build: <clean | items>

   ## Other findings
   <one line each, path:line, severity>
   ```

   Verdict rules: any `[blocker]` or unmet item → **Blocked**; any `[must-fix]` → **Changes
   required**; only `[should-fix]`/`[nit]` items or unresolved threads → **Approve after small fixes**;
   otherwise (no items and 0 unresolved threads) **Approve as-is**.
4. Remove the review worktree and local branch.

## 8. Final chat response

```
PR #<N> — review submitted (<url>).
Verdict: <verdict>
Action required: <YES — N items | NO>
1. [tag] path:line — what to do
Open threads: <count or "none">   Follow-ups: <items or "none">
Checks: <check.sh pass; strip.sh --report pass | n/a>
```

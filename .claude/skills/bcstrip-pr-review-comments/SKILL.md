---
name: bcstrip-pr-review-comments
description: >
  Address review comments on an open fatal10110/bc-csharp pull request against strip-v2 (human
  reviewer, the bcstrip-waves review agent, or an automated reviewer): fetch every unresolved
  inline thread and top-level review body, verify each claim against the code, the plan and the
  RFCs before touching anything, fix only confirmed in-scope findings with regression checks, reply
  with evidence to the rest, file follow-ups for valid out-of-scope items, and resolve threads. Use
  when the user says "address the review on PR N", "fix the comments", or when a bcstrip-waves
  implementation prompt hands over a review round. Do not use to produce a review
  (bcstrip-pr-review).
---

# bc-csharp strip-v2 review-comment handling

Verify first, fix second. A reviewer's prose is a claim, not a fact. A bcstrip-waves prompt
overrides this file on test scope, worktrees and GitHub tooling.

## 0. What comments are ranked against

TLS-client security (hostile server input, advertised = processable, bounds, validation), the plan
(`STRIP_PLAN_V2.md`), rebase-ability and runtime safety of the stripped output outrank everything
else (see bcstrip-issue "Authority"). A comment naming one of them is never downgraded to style.

## 1. Fetch threads and reviews

```bash
gh pr view <N> -R fatal10110/bc-csharp --json number,headRefName,headRefOid,baseRefName
gh api graphql --paginate -F n=<N> -f query='
  query($n: Int!, $endCursor: String) { repository(owner:"fatal10110", name:"bc-csharp") {
    pullRequest(number: $n) { reviewThreads(first: 100, after: $endCursor) {
      pageInfo { hasNextPage endCursor }
      nodes { id isResolved isOutdated
        comments(first: 100) { totalCount nodes { id body path line author { login } } } } } } } }' \
  > <scratchpad>/pr<N>-threads.json
gh api graphql --paginate -F n=<N> -f query='
  query($n: Int!, $endCursor: String) { repository(owner:"fatal10110", name:"bc-csharp") {
    pullRequest(number: $n) { reviews(first: 100, after: $endCursor) {
      pageInfo { hasNextPage endCursor }
      nodes { id databaseId state body author { login } } } } } }' \
  > <scratchpad>/pr<N>-reviews.json
```

Only unresolved threads on the current head are work items; every non-empty review body with
actionable content is also one.

## 2. Verify every comment before classifying it

- Open the cited file:line and confirm the code does what the comment claims.
- A protocol claim: read the RFC section yourself.
- A hostile-input claim: state the server input, its cost or effect, and reachability on the
  stripped client path; or name the bound/validation that prevents it, at every call site.
- A closure/build claim: reproduce it (`tools/ci/check.sh`, `strip/strip.sh --report`, a scoped
  build with the captured define set).

Classify only after verification:

- **Valid, in-scope** — fix it. A security or plan break the PR introduces or widens is always in
  scope.
- **Valid, out-of-scope** — pre-existing, not worsened: reply with evidence and the issue filed or
  amended (§4a).
- **Invalid** — reply with the refuting evidence.
- **Valid, latent** — file it (§4a) and reply.
- **Question** — answer it.

## 3. Fix confirmed in-scope findings

Work in the PR branch's worktree. Smallest complete fix; a regression check that fails on the old
code. Then:

```bash
cd <worktree> && ./tools/ci/check.sh
cd <worktree> && strip/strip.sh --report     # when the tooling exists
```

Re-apply the rubric covering the finding (`.claude/agents/crypto-security-reviewer.md` or
`.claude/agents/strip-build-reviewer.md`). Update the PR's journal file if a decision changed.
Commit messages name the behavior fixed; push (never force-push a PR branch).

## 4. Reply and resolve

### 4a. Track out-of-scope and latent findings

Dedupe with `tools/agent-tools/issue_search.py <terms>`; amend a matching issue or file one with
the template from bcstrip-issue "Follow-up issues" (milestone, parent sub-issue, project). Link
back to the thread.

### 4b. Reply on every thread, then resolve

- Fixed: reply with what changed and the commit SHA, then resolve
  (`gh api graphql -f query='mutation { resolveReviewThread(input:{threadId:"<id>"}) { thread { isResolved } } }'`).
- Out-of-scope or latent: reply with evidence and the issue number, then resolve.
- Invalid: reply with the specific evidence, then resolve. Never resolve without a reply.
- A top-level review body: one PR comment answering it point by point.
- Push before resolving threads that reference a fix.

## 5. Report back

Which comments were fixed (commit refs), rejected (evidence), or tracked (issue numbers); the gates
run and their results; and the three answers (wire/behavior, closure, abuse/limits) for the branch
as it now stands.

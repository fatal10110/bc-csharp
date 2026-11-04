# Review threads gate the merge (waves and review skills)

## What
The owner found 38 unresolved review threads on 9 merged PRs (#39–#64): 31 CodeQL alerts and 7 optional nits or notes. Three gaps let them through:
- The waves review agent counted "optional" nits as no action and ignored bot threads.
- The implementation agent resolved only the threads it was sent.
- The merge agent never looked at threads. CodeQL posts its alerts as threads when its check finishes, after the reviewer's verdict, and its check stays green on note-level alerts.

## Files
- `tools/agent-tools/wave_mail.py`: `gh_graphql`, `unresolved_threads`; `pr-state` reports `unresolved_threads`; new `threads --pr N` lists them (kind codeql/review, path, line, excerpt).
- `tools/agent-tools/test_wave_mail.py`: `ReviewThreadsTest` (fake `gh` via `WAVES_GH`): count, listing with kind, gh failure is an error and not a zero count.
- `.claude/skills/bcstrip-waves/waves.js`:
  - The reviewer has no optional findings, and every unresolved thread is action required. "Clean" means no items and 0 threads.
  - The implementation agent settles every thread (fix, rebuttal, CodeQL dismissal with a reason, or follow-up issue), replies and resolves.
  - The merge agent checks threads after CI is green (step 3b) and answers `threads_open`. The reviewer turns that into a review round.
  - The gh allow-list covers CodeQL alert dismissal.
- `.claude/skills/bcstrip-waves/waves_sim.mjs`: a `threads_open` scenario, plus prompt assertions for the reviewer, implementer and merger.
- `bcstrip-pr-review`: open threads are part of the verdict, `[nit]` is action required, and there is no "Optional" line. `bcstrip-pr-review-comments`: every thread is a work item, with a CodeQL dismissal recipe. `bcstrip-waves/SKILL.md`: loop description.

## Decisions
- Dismissing a CodeQL alert is allowed only with a written reason (`won't fix`, `false positive`, `used in tests`).
- Mirrored consumer code (`strip/roots/`) is a valid reason: it must stay byte-identical to turboHTTP.
- The existing 38 threads are cleaned up in a separate PR after waves run w1033.

## How verified
- `python3 -m unittest discover -s tools/agent-tools -p 'test_*.py'`: OK. The 3 new tests fail on the old code: there was no `threads` command and no `unresolved_threads` key.
- `wave_mail.py threads --pr 64` against GitHub returns the same 3 threads GitHub shows.
- `node .claude/skills/bcstrip-waves/waves_sim.mjs`: all scenarios passed, including `threads_open`.
- `./tools/ci/check.sh --full`.

## Review round 1 (strip-build-reviewer): fixes
- `unresolved_threads` paginates (`pageInfo`, up to 20 pages, with an error beyond that). It no longer truncates at 100, so the count can't come out too low.
- `pr-state` stays usable when the thread lookup fails: `unresolved_threads: null` plus `threads_error`. Merger step 3b treats a missing or null count as "retry", never as 0.
- `threads` reports the CodeQL `alert` number used by the dismissal command.
- `gh_graphql` passes `-f` for strings and `-F` only for integers. `TypeError` and `TimeoutExpired` are caught.
- CodeQL threads are settled only by a code fix or an alert dismissal with a reason (a rebuttal or an issue would leave the alert open).
- `[note]` items go in the review body only, so they never become blocking threads.
- `threads_open` rounds don't use the review round budget; there are at most 3 per lane.
- The dismissal permission is scoped to the implementation agent, with a note on the 280-character comment limit.
- Step 3b wording: it runs after every check, CodeQL analyze jobs included.
- Tests:
  - the fake `gh` asserts the exact arguments and serves two pages;
  - error and missing-PR cases;
  - sim assertions for every new rule (scenario 1b only checks that the orchestrator tolerates `threads_open`).
- Review round 2: `threads_open` rounds are counted as `threads_rounds` in the lane state.
  - The round limit tests R = N − threads_rounds.
  - The cap of 3 reads that count, so it survives a resumed reviewer.
  - The sim parses `R >= <limit>`.

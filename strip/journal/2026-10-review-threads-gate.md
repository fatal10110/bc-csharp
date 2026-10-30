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

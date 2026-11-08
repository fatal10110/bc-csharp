# 2026-10 Smoke: handshake timeout rows (#27)

## What

Smoke rows for the handshake timeout of upstream `ab4eb3d2` (in BASE `7c9c8d5a`), plan §5 step 5
"Timeout". The client checks its handshake timeout only between records
(`TlsProtocol.BlockForHandshake` → `CheckHandshakeTimeout`), so:

- **trickle server** (one accepted handshake record every few seconds): aborted by the handshake
  timeout with `TlsTimeoutException: Handshake timed out` at the first record after it expires.
  `timeout/trickle-handshake-timeout-30s` uses the harness default (30000 ms, 1 record / 3 s) and
  is a **slow row**; `timeout/trickle-handshake-timeout-2s` (2000 ms, 1 record / 500 ms) runs every time.
- **silent peer** (`timeout/silent-peer-receive-timeout`): sends nothing, so the handshake timeout
  (set to 500 ms) is never checked; only the socket `ReceiveTimeout` the harness sets (1500 ms) ends
  the handshake, with the transport's `IOException` → `SocketException` (`TimedOut`). turboHTTP must
  set it too (turboHTTP#142).

Slow rows: `SmokeRows.AddSlow` registers a row that runs only with `TurboSmoke --slow`
(`run.sh --slow`, `strip.sh --smoke-slow`). Without it the row is printed and listed in the results
block as `SKIP <id> (slow row; not run without --slow)`, not counted as a result, so the package's
STRIP_INFO.md says which rows a gate run left out. The local gate (`check.sh` → `strip.sh --report`)
does not pass it; the enforce run (#30) should.

## Files

- `strip/smoke/rows/TimeoutRows.cs` (new): group `timeout`, the three rows; raw-byte servers on
  `SmokeServerHost.Start`. The trickle record is a TLSPlaintext handshake record (0x0303) carrying one
  byte of a ServerHello whose header promises 256 bytes, so every record is queued
  (`ProcessHandshakeQueue`: recognized type, length under 32768) and the message never completes.
  A `ManualResetEventSlim` stops the server as soon as the client has aborted.
- `strip/smoke/harness/SmokeRowGroup.cs`: `SmokeRow.Slow`, `SmokeRows.AddSlow`.
- `strip/smoke/harness/Program.cs`: `--slow`; skipped slow rows printed and appended to the results
  text; "no row ran" names the skipped count.
- `strip/smoke/harness/SmokeRunner.cs`: `Select(rows, filters, slow, skipped)`, the row selection
  (filter, then slow rows only with `--slow`) that `Program` calls.
- `strip/smoke/harness/SmokeSelfTest.cs`: `self-test/slow-selection` registers a group with one
  normal and one `AddSlow` row and checks `Select` without `--slow` (slow row skipped and listed),
  with `--slow` (both rows) and with a filter (review round 1).
- `strip/smoke/run.sh`: `--slow`, passed to every harness run (not to `--self-test`).
- `strip/strip.sh`: `--smoke-slow`, passes `--slow` to the smoke hook; usage and hook contract.
- `strip/tool/test_smoke_run_sh.py`, `strip/tool/test_strip_sh.py`: the option is off by default and
  passed through when given.

## Decisions

- Assertion windows: abort after ≥ timeout − 100 ms (library wall clock vs. row Stopwatch) and
  ≤ timeout + interval + 5000 ms slack (loaded box); the server must have sent at least
  timeout / interval − 1 records. The trickle rows check the exception type and message, so they
  also show the check is live (no extra pre-`ab4eb3d2` row: the commit is in BASE).
- The fast rows get a 20 s row timeout, so a regression (no timeout) costs 20 s, not 60 s.
- The silent-peer row has no slow 30 s variant: with both defaults at 30 s it would prove nothing
  more than the 500 ms / 1500 ms pair.
- The servers wait between records (`stop.Wait(interval)`): the time between records is the case
  under test, and the stop event ends the server as soon as the row is done.

## How verified

- `strip/strip.sh --report --set min --work <scratch>`: clean; smoke 28 rows passed,
  `timeout/trickle-handshake-timeout-30s` listed as SKIP.
- `strip/smoke/run.sh --filter timeout --slow ... TurboBC.min.dll`: 3/3 passed (2536 ms, 1514 ms,
  30051 ms).
- Mutation: with `HandshakeTimeoutMillis = 0` the 2 s trickle row fails ("timed out after 20000 ms").
- Mutation: `Select` with `if (row.Slow)` (always skip) or `if (row.Slow && slow)` (inverted) makes
  `TurboSmoke --self-test` fail (exit 1).
- `python3 -m unittest discover -s strip/tool -p 'test_*.py'`; shellcheck on `run.sh`, `strip.sh`.
- `./tools/ci/check.sh` (see the PR's "Local gates").

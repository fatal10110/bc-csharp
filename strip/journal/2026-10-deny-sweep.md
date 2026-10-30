# 2026-10 — deny.txt, referrer sweep and budget (#8)

## What

- `strip/deny.txt`: the plan §3 deny list verbatim (registries, GOST/SM2/DSTU, post-quantum, Ed448/X448,
  Ed25519 signing, SecT*, unused subsystems), one glob per line with `#` group headers.
- `strip/tool/deny.py`: the prototype script rewritten as an importable module (brace expansion, the same
  glob semantics, case-insensitive anchored matching, deny hits with exempt seeds, per-top-dir counts,
  `budget.txt` parsing) plus an offline CLI over a finished work dir. The `deny4.txt`/`allow4.txt` names
  are gone.
- `strip/tool/closure.py`: `run_sweep` after `run_closure` (main calls it), new `ClosureResult` fields
  (denied, referrers, sweep_*, budget) carried into `closure_report.json`, and the fail checks
  `check_deny`, `check_sweep_unattributed`, `check_sweep_incomplete`, `check_budget`. New flags `--deny`,
  `--no-deny`, `--budget`. `--report` logs, otherwise the checks fail the run (exit 1).
- `strip/tool/test_deny.py`: glob semantics, `deny.txt` == plan block, every glob hits the tree, Ed25519
  math kept, seeds exempt, budget parsing, and the sweep on a fixture tree with a fake builder that
  stops at declaration-level errors like csc.

## Decisions

- **csc stops before method bodies when declaration-level errors exist** (usings, signatures, base types,
  attributes). One build of (closure − denied) therefore lists only the declaration-level referrers: on
  the unpatched tree the first [min] build reported only `BcTlsRawKeyCertificate.cs`. The sweep compiles a
  generated canary (`_sweep_canary.cs`, one method-body error) to know whether a build reached bodies,
  and runs two phases per set:
  - *remove*: while the canary is missing, drop the failing files (declaration referrers, then their
    collateral, roots included) and rebuild, so body-level referrers in the other files appear;
  - *restore*: put the denied files the declaration referrers need back (plus what those need) and build
    every kept file, so body-level references inside the dropped files appear.
  Gap, documented in `run_sweep`: a body-level reference from a dropped file to a restored denied file is
  not seen; that file is a listed referrer already. A set whose phases never reach bodies is reported
  `sweep incomplete` (a failure in enforce mode).
- Errors the fixpoint build already had (unresolved, e.g. E13) are not the sweep's and are not repeated.
  Unexplained errors fail only from the first build and the restore phase; after files were dropped they
  may be collateral (CS0115 on a lost base class) and go to `sweep_after_drop` in the report only.
- Sweep stubs are re-pruned for each compiled set (namespaces declared only by denied files get a stub),
  so a kept `using` of a denied-only namespace is not counted as a referrer; this matches what shipping
  the cut tree would need. The shipped `_TurboNamespaceStubs.cs` is unchanged (fixpoint stubs).
- Seeds and their partial units (crypto/src/turbo/, `--seed`) are never denied; roots are never in
  `result.files`.
- Budget: count = closure files − denied (crypto/src only, no roots or stubs), matching the plan's "BC
  files". `strip/budget.txt` is not created: its value is #30's; while absent there is no cap and the run
  prints the kept count and per-top-dir counts.

## Findings (for #11, #20)

- Unpatched BASE `7c9c8d5a` crypto/src + `turbo/` seed: 933 files, 164 denied (plan rev-5: 931/164),
  769 kept; [min] sweep complete in 8 builds: 41 (denied file, kept referrer) edges, all in E1 (BcTlsCrypto),
  E5 (BcTlsRawKeyCertificate), E6 (CustomNamedCurves, ECNamedCurveTable), E8 (X509Certificate),
  E9 (X509ExtensionUtil), E10 (ECKeyPairGenerator), E11 (DigestUtilities), E12 (MacUtilities).
- strip-v2 head (E1, E5 merged): 903 files, 153 denied, 750 kept, 30 edges, [min] complete in 1 build.
- [partial] and [sdk] stay incomplete until E13 (#20): their pre-existing declaration-level errors stop
  every build before bodies. The same effect hides body-level errors in the closure loop itself: with the
  E13 files dropped, [sdk] shows `Span<T>.CopyFrom` extension calls (rfc8032, GCMBlockCipher) whose
  declaring file the fixpoint never added. Expect the [partial]/[sdk] closure to grow once #20 lands.

## How verified

- `python3 -m unittest discover -s strip/tool -p 'test_*.py' -q` (115 tests, OK).
- `python3 strip/tool/closure.py --roots strip/roots --work <scratch> --report` on strip-v2 head and with
  `--src` on an export of BASE crypto/src + `crypto/src/turbo/` (about 75 s + 25 s of sweep builds each);
  `git status` clean under crypto/src afterwards.
- `./tools/ci/check.sh` OK (no `strip/strip.sh` yet: library builds netstandard2.0 and net6.0).

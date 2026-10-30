# 2026-10 — Namespace rewrite and strip/out packaging (#9)

## What

The two input-driven tools behind `STRIP_PLAN_V2.md` §5 steps 4 and 6. `strip.sh` (#10) only wires
them; neither knows about the closure, the define sets or the build.

- `strip/tool/rewrite.py --src DIR --files LIST --out DIR`: copies each listed file, replacing the
  whole token `\bOrg\.BouncyCastle\b` with `TurboHTTP.SecureProtocol.Org.BouncyCastle` (usings,
  aliases such as `GeneralName.cs:7`, crefs, string literals such as `Pkcs1Encoding.cs:21`).
- `strip/tool/package.py --lib DIR --out strip/out --base SHA --roots-sha SHA [--old-base SHA]
  [--smoke FILE] [--license FILE] [--repo DIR]`: writes `Lib/**` with `.meta` files,
  `Lib/LICENSE.md`, `THIRD-PARTY-NOTICES.txt` and `STRIP_INFO.md`.

## Files

- `strip/tool/rewrite.py` — the rewrite (bytes regex; the unprefixed-token check is shared with package.py).
- `strip/tool/package.py` — Lib copy, Unity metas, licence-header scan, cut list, per-directory
  counts, smoke slot, shadow diff.
- `strip/tool/test_rewrite.py`, `strip/tool/test_package.py` — tool tests (run by
  `check.sh --full`).
- `.gitignore` — `/strip/out/`.

## Decisions

- **Byte-exact rewrite.** The regex runs on bytes, so the UTF-8 BOM (1003 of 2297 files), line
  endings and everything else stay as in the source; the tests check that removing the prefix
  gives back the original bytes for real files (`GeneralName.cs`, `Blake2bDigest.cs`,
  `Pkcs1Encoding.cs`, `SkeinEngine.cs`).
- **No double prefix.** The token regex has a negative lookbehind on `TurboHTTP.SecureProtocol.`,
  so a second pass changes nothing. The output directory must still be absent or empty: every run
  starts from the source tree.
- **File list** = the existing `closure.py` convention: one path per line relative to `--src`,
  `/` separators, `#` comment lines; absolute paths, `..` and non-normalized paths are rejected.
  Roots (`strip/roots/`, `roots-extra.cs`) are rewritten by a second call with their own `--src`;
  no extra-file argument.
- **Layout.** Only `LICENSE.md` sits inside `Lib/`; `THIRD-PARTY-NOTICES.txt` and `STRIP_INFO.md`
  sit beside `Lib/`, so the handover `rsync --delete` of `Lib/` (§5 step 7) never touches
  turboHTTP's own files. No `.meta` for `Lib/` itself (turboHTTP owns `Lib.meta`). Package
  replaces only `Lib/` and its two files under `--out`.
- **Meta format** copied from turboHTTP (folder `DefaultImporter` with `folderAsset: yes`,
  `MonoImporter`, `TextScriptImporter`, trailing space on empty values); any other file type in the
  rewritten tree is an error.
- **Guard.** package.py refuses a tree that still has an unprefixed `Org.BouncyCastle` token, a
  non-`.cs` file or a symlink, before it writes anything.
- **Cut list** = every `// turbo-strip:` marker in the packaged files (`path:line text`), not
  `git log BASE..HEAD` (that also lists tooling/CI/doc commits and depends on the checkout).
- **Per-directory counts** = `.cs` files per top-level directory of `Lib/` plus the total.
- **Smoke results** = optional `--smoke FILE` embedded verbatim; default "Not run." (filled by the
  smoke suite, #22–#27).
- **Shadow diff** = `git diff OLDBASE..BASE` over the four shadow paths (relative to the repo,
  `crypto/src/...`), with fixed diff options so user git config cannot change it; the paths must
  appear exactly in `git ls-files` (case errors fail). Default OLDBASE = BASE (no bump): empty.
- **Notices** = BC `LICENSE.md` plus every comment block containing `Permission is hereby granted`
  or `Licensed under` (case-sensitive), minus blocks naming the Legion of the Bouncy Castle. In the
  current tree outside `pqc/` only `Blake2b_X86.cs`/`Blake2s_X86.cs` (Blake2Fast) match; the scan
  runs on the packaged files, so they appear only if the closure keeps them.

## Deferred

- Wiring into `strip.sh` (build 3c on `TurboBC.ns21.dll`/`TurboBC.netfx.dll` with the consumer
  files) is #10; the "rewritten tree compiles" acceptance is covered here by a sample compile
  (`test_rewritten_sample_compiles`) and in full by build 3c once #10 lands.

## How verified

- `python3 -m unittest discover -s strip/tool -p 'test_*.py' -v`: 12 tests pass (dotnet SDK 8,
  the sample compile builds a net8.0 library with `TreatWarningsAsErrors` and XML docs so crefs
  must resolve).
- Manual: rewrite + package of `GeneralName.cs`, `Blake2b_X86.cs`, `Pkcs1Encoding.cs` from
  `crypto/src`: two packages identical (`diff -r`), no unprefixed token, metas match turboHTTP's
  format byte-for-byte apart from the GUID.
- `./tools/ci/check.sh` (library builds for netstandard2.0 and net6.0; no C# changed).

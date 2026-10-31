# 2026-10 upstream-test exclusions (#42)

## What

`strip/tool/upstream_tests.py` (#35) can now drop upstream `crypto/test` sources that stop compiling
after a cut, so the upstream-test diff still gets a TRX. The list is
`strip/upstream-tests-exclude.txt`; it starts empty because no landed cut removes API that
`crypto/test` compiles against (E9 throws instead of removing the overload, and the only test user of
`SubjectKeyIdentifierStructure(AsymmetricKeyParameter)`, `pkcs/examples/PKCS12Example.cs`, is already
excluded by the test project's `examples` glob).

## Files

- `strip/upstream-tests-exclude.txt` (new): the committed list, `<tag> <path>` per line, comments only.
- `strip/tool/upstream_tests.py`:
  - `parse_exclusions`: refuses untagged, badly tagged (same `check_tag` rule as the expected
    failures: at least one E-number), duplicate and non-`crypto/test/src/**.cs` lines. The path
    character set keeps MSBuild and XML metacharacters out. `check_exclusions_exist` refuses listed
    files missing from the tree.
  - `exclusion_targets` / `write_exclusion_targets`: the generated MSBuild file under the results
    directory, one `<Compile Remove="$(MSBuildProjectDirectory)/src/..."/>` per path. Its ItemGroup is
    conditioned on the test project's name. `run_tests` passes it as
    `-p:CustomAfterMicrosoftCommonTargets=<file>` for both the tree run and the BASE run.
  - `format_base` / `parse_base` / `load_base`: the new header `# exclude-sha256:` (digest of the
    sorted paths). A missing or different digest is refused with "changed since ... regenerate it
    with --update-base".
  - `excluded_kept_tests`: maps each excluded file's `namespace` and `class/struct/record`
    declarations onto the filter entries. The report and `--update-base` list the matches under
    "Excluded sources with kept-surface tests".
  - `no_trx_error` now points at the exclusion list when crypto/test fails to compile.
- `strip/upstream-base-results.txt`: regenerated with `--update-base`. The 505 test lines are
  unchanged; the header gained `exclude-sha256` (the empty-list digest).
- `strip/tool/test_upstream_exclusions.py` (new, 16 tests) and `strip/tool/test_upstream_tests.py`
  (signature updates; `RepoFilesTest` parses the committed list and passes it to `load_base`).

## Decisions

- **How the list is applied:** a global `CustomAfterMicrosoftCommonTargets` property pointing at a
  generated targets file. This edits no upstream test file or project, needs no temporary copy, and
  works the same in the live tree and in the BASE worktree. `Microsoft.Common.targets` imports it
  after the project body, so `Remove` runs after the `src\**\*.cs` include. The library project
  imports the file too; the project-name condition makes that a no-op.
- The targets file is rewritten only when its content changes. Imported files are in
  `MSBuildAllProjects`, so a newer timestamp would force a full rebuild on every run.
- **Digest:** a separate `exclude-sha256` header gives a precise stale-base message. It covers the
  paths only, not the tags, because re-tagging does not change the build.
- **Kept-surface report:** a source scan rather than a diff of names. The BASE run drops the same
  sources, so their tests appear in neither result set.
- **Validation:** the list is parsed and checked against the tree in every mode, including
  `--print-filter` and `--trx`, like the filter. A missing list file is an error, like the other
  committed list files.
- **Existence check:** only in the current tree. A path missing at BASE is harmless (the `Remove`
  is a no-op).

## Deferred

- `strip/docs/agents/testing.md` and `tooling.md` describe `upstream_tests.py`. The exclusion list
  needs a line there, which the post-wave docs PR adds (lanes do not edit the guides).

## How verified

- `python3 -m unittest discover -s strip/tool -p 'test_*.py'`: all pass. The new
  `test_upstream_exclusions.py` covers parsing, the digest, the MSBuild text, the dotnet command,
  the same exclusions in the BASE run, the report, and the stale-base CLI path. Before the BASE
  results were regenerated, `RepoFilesTest` failed on the missing `exclude-sha256` header.
- `python3 strip/tool/upstream_tests.py --update-base`: 505 tests, 0 not passing at BASE, same test
  lines as before.
- `python3 strip/tool/upstream_tests.py` on the current tree: 505 run (429 pass, 76 fail), 76
  expected failures hit, `Result: 0 regression(s)`.
- Mechanism proof in a scratch worktree (removed afterwards):
  1. The probe `crypto/test/src/tls/test/ExclusionProbeTest.cs` (namespace
     `Org.BouncyCastle.Tls.Tests`) uses `new SubjectKeyIdentifierStructure(AsymmetricKeyParameter)`.
     The scratch cut removes that constructor (E9 as the plan words it).
  2. With an empty list, the run exits 2: "crypto/test does not compile ... CS1503" in
     `ExclusionProbeTest.cs`.
  3. With `E9 crypto/test/src/tls/test/ExclusionProbeTest.cs` listed, `--trx` mode exits 2:
     "strip/upstream-tests-exclude.txt changed since ... --update-base".
  4. `--update-base` gives 505 tests, 0 failing, with only the `exclude-sha256` line changed.
  5. The default run builds, runs 505 tests and reports 0 regressions. It lists
     `E9 crypto/test/src/tls/test/ExclusionProbeTest.cs: Org.BouncyCastle.Tls.Tests.ExclusionProbeTest`
     under "Excluded sources with kept-surface tests". Exit 0.
- `./tools/ci/check.sh`: OK.

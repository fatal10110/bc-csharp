#!/usr/bin/env python3
"""Diff the upstream crypto/test results over the kept surface against BASE (issue #35).

Runs `dotnet test --framework net6.0 crypto/test/BouncyCastle.Crypto.Tests.csproj` with the
kept-surface filter of strip/upstream-tests.txt (never unfiltered), parses the TRX into a per-test
outcome list and diffs it against the committed BASE results (strip/upstream-base-results.txt).

A test is a regression when it passed at BASE and does not pass now (failed, skipped or missing),
or when it is new and fails, unless strip/upstream-expected-failures.txt lists it with the
E-number (and plan decision) of the cut that breaks it on purpose.

Test sources that stop compiling after a cut are listed in strip/upstream-tests-exclude.txt (issue
#42), each with the E-number of that cut. Both runs (the tree and BASE) drop them through a generated
MSBuild file passed as CustomAfterMicrosoftCommonTargets (Compile Remove items); no upstream test
file or project is edited. The BASE results header carries a digest of the list, and the tests the
excluded sources declare inside the kept-surface filter are listed in the report.

Modes:
  (default)       run the filtered tests on --root, diff, write the report under --results-dir
  --trx FILE      diff an existing TRX instead of running dotnet test
  --update-base   run the filtered tests on a temporary worktree at strip/BASE (created beside
                  --root so SimpleTest.FindTestDataPath still finds bc-test-data) and rewrite the
                  BASE results file; needed after a bump or an edit of the filter file
  --print-filter  print the dotnet test --filter expression and exit

Exit codes: 0 no regression, 1 regressions, 2 usage or environment error.

Informational, not a gate: not part of check.sh or CI (needs dotnet and the ~7 GB bc-test-data
checkout); the smoke suite stays the strip's gate (STRIP_PLAN_V2.md section 6).
"""

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

TEST_PROJECT = Path("crypto/test/BouncyCastle.Crypto.Tests.csproj")
FILTER_FILE = Path("strip/upstream-tests.txt")
EXPECTED_FILE = Path("strip/upstream-expected-failures.txt")
BASE_RESULTS_FILE = Path("strip/upstream-base-results.txt")
BASE_FILE = Path("strip/BASE")
EXCLUDE_FILE = Path("strip/upstream-tests-exclude.txt")
RESULTS_DIR = Path("strip/upstream-results")
DEFAULT_FRAMEWORK = "net6.0"

TEST_DATA_DIR = "bc-test-data"
CLONE_COMMAND = "git clone --depth 1 https://github.com/bcgit/bc-test-data.git"

TRX_NS = "{http://microsoft.com/schemas/VisualStudio/TeamTest/2010}"
PASS, FAIL, SKIP, MISSING = "pass", "fail", "skip", "missing"
# TRX outcomes; anything not listed (Failed, Error, Timeout, Aborted, ...) counts as a failure.
OUTCOMES = {"Passed": PASS, "NotExecuted": SKIP, "Inconclusive": SKIP}
SEVERITY = {PASS: 0, SKIP: 1, FAIL: 2}

# A filter entry is a FullyQualifiedName substring: a namespace or class, '.'-terminated so that
# 'Org.BouncyCastle.Crypto.Tests.AesTest.' does not also select AesTestFoo. Restricting entries to
# identifier characters keeps the dotnet test filter syntax (| & ! ( ) = ~ ,) out of them.
FILTER_ENTRY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+\.$")
# Tag of an expected failure: '/'-separated parts, each an E-number (E1..E14) or a plan decision
# letter (A..G); at least one E-number. Examples: E1/B, E/E5, A/E8, E1.
TAG_PART = re.compile(r"^(E\d{1,2}|[A-G])$")
E_NUMBER = re.compile(r"^E\d{1,2}$")
# An excluded test source: a .cs path under crypto/test/src/, '/'-separated and relative to the
# repository root. The character set keeps MSBuild (% $ @ ; * ?) and XML (& < > ") metacharacters
# out of the generated Compile Remove items, so they need no escaping.
EXCLUDE_ROOT = "crypto/test/src/"
EXCLUDE_PATH = re.compile(r"^crypto/test/src/([A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.cs$")
# Type declarations of an excluded source, mapped onto the kept-surface filter for the report.
NAMESPACE_DECL = re.compile(r"^\s*namespace\s+([A-Za-z_][A-Za-z0-9_.]*)", re.MULTILINE)
TYPE_DECL = re.compile(r"\b(?:class|struct|record)\s+([A-Za-z_][A-Za-z0-9_]*)")


class ToolError(Exception):
    """A usage or environment error: reported on stderr, exit code 2."""


def _content_lines(text):
    """Yield (line number, stripped line) for the non-blank, non-comment lines of a list file."""
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if line and not line.startswith("#"):
            yield number, line


def parse_filter(text, source=FILTER_FILE):
    entries = []
    for number, line in _content_lines(text):
        if not FILTER_ENTRY.match(line):
            raise ToolError(f"{source}:{number}: '{line}' is not a '.'-terminated namespace or class name")
        if line in entries:
            raise ToolError(f"{source}:{number}: duplicate entry '{line}'")
        entries.append(line)
    return entries


def filter_expression(entries):
    """The dotnet test --filter expression; refuses an empty filter (never an unfiltered run)."""
    if not entries:
        raise ToolError(f"the kept-surface filter ({FILTER_FILE}) is empty; refusing an unfiltered upstream run")
    return "|".join(f"FullyQualifiedName~{entry}" for entry in entries)


def filter_digest(entries):
    return hashlib.sha256("\n".join(sorted(entries)).encode()).hexdigest()


def check_tag(tag):
    parts = tag.split("/")
    return all(TAG_PART.match(part) for part in parts) and any(E_NUMBER.match(part) for part in parts)


def parse_expected(text, source=EXPECTED_FILE):
    """Map test full name -> tag. Line format: '<tag> <full test name>'; '#' starts a comment line."""
    expected = {}
    for number, line in _content_lines(text):
        parts = line.split(None, 1)
        if len(parts) != 2:
            raise ToolError(f"{source}:{number}: expected '<tag> <full test name>'")
        tag, name = parts
        if not check_tag(tag):
            raise ToolError(
                f"{source}:{number}: tag '{tag}' needs an E-number, optionally with the plan decision (E1/B, A/E8)"
            )
        if name in expected:
            raise ToolError(f"{source}:{number}: duplicate test '{name}'")
        expected[name] = tag
    return expected


def parse_exclusions(text, source=EXCLUDE_FILE):
    """Map excluded test source path -> tag. Line format: '<tag> <path>'; '#' starts a comment line."""
    exclusions = {}
    for number, line in _content_lines(text):
        parts = line.split()
        if len(parts) != 2:
            raise ToolError(f"{source}:{number}: expected '<tag> <path>' (the E-number of the cut, then one path)")
        tag, path = parts
        if not check_tag(tag):
            raise ToolError(
                f"{source}:{number}: tag '{tag}' needs the E-number of the cut that breaks the file (E9, E1/B)"
            )
        if not EXCLUDE_PATH.match(path) or any(part in (".", "..") for part in path.split("/")):
            raise ToolError(f"{source}:{number}: '{path}' is not a .cs path under {EXCLUDE_ROOT}")
        if path in exclusions:
            raise ToolError(f"{source}:{number}: duplicate path '{path}'")
        exclusions[path] = tag
    return exclusions


def exclude_digest(exclusions):
    """Digest of the excluded paths (what changes the build); a tag edit alone keeps the BASE results."""
    return hashlib.sha256("\n".join(sorted(exclusions)).encode()).hexdigest()


def check_exclusions_exist(root, exclusions):
    missing = [path for path in exclusions if not (root / path).is_file()]
    if missing:
        raise ToolError(f"{EXCLUDE_FILE} lists files that do not exist in {root}: {', '.join(missing)}")


def exclusion_targets(exclusions):
    """The MSBuild file run_tests passes as CustomAfterMicrosoftCommonTargets: one Compile Remove per path.

    Microsoft.Common.targets imports it after the project body, so the Remove items apply after the test
    project's 'src/**/*.cs' include; the condition keeps it to the test project (the library imports it too).
    """
    project_dir = TEST_PROJECT.parent.as_posix() + "/"
    lines = [
        f"<!-- Generated by strip/tool/upstream_tests.py from {EXCLUDE_FILE.as_posix()}; do not edit. -->",
        "<Project>",
        f"  <ItemGroup Condition=\"'$(MSBuildProjectName)' == '{TEST_PROJECT.stem}'\">",
    ]
    lines += [
        f'    <Compile Remove="$(MSBuildProjectDirectory)/{path[len(project_dir):]}" />' for path in sorted(exclusions)
    ]
    lines += ["  </ItemGroup>", "</Project>"]
    return "\n".join(lines) + "\n"


def excluded_kept_tests(root, exclusions, entries):
    """(tag, path, [type full name]) for each excluded source declaring a type the kept-surface filter selects.

    These tests run neither here nor at BASE, so the diff cannot see them; the report lists them instead.
    """
    rows = []
    for path, tag in sorted(exclusions.items()):
        text = (root / path).read_text(encoding="utf-8", errors="replace")
        namespaces = NAMESPACE_DECL.findall(text) or [""]
        names = sorted({f"{ns}.{name}" if ns else name for ns in namespaces for name in TYPE_DECL.findall(text)})
        kept = [name for name in names if any(entry in name + "." for entry in entries)]
        if kept:
            rows.append((tag, path, kept))
    return rows


def _one_line(name):
    return re.sub(r"[\r\n\t]", " ", name).strip()


def parse_trx(path):
    """Map test full name (class name + '.' + test name) -> pass | fail | skip.

    A name reported more than once keeps its worst outcome, so a duplicate can never hide a failure.
    """
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as error:
        raise ToolError(f"cannot read TRX {path}: {error}") from error
    classes = {}
    for test in root.iter(f"{TRX_NS}UnitTest"):
        method = test.find(f"{TRX_NS}TestMethod")
        if method is not None:
            classes[test.get("id")] = method.get("className", "")
    results = {}
    for result in root.findall(f"{TRX_NS}Results/{TRX_NS}UnitTestResult"):
        test_name = result.get("testName", "")
        class_name = classes.get(result.get("testId"), "")
        if class_name and not test_name.startswith(class_name + "."):
            test_name = f"{class_name}.{test_name}"
        name = _one_line(test_name)
        outcome = OUTCOMES.get(result.get("outcome"), FAIL)
        if name not in results or SEVERITY[outcome] > SEVERITY[results[name]]:
            results[name] = outcome
    return results


def format_base(base_sha, digest, exclude_sha, results):
    lines = [
        "# BASE results of the kept-surface upstream tests (strip/tool/upstream_tests.py).",
        "# Generated, do not edit: regenerate with 'strip/tool/upstream_tests.py --update-base' after a bump",
        "# or an edit of strip/upstream-tests.txt or strip/upstream-tests-exclude.txt.",
        f"# base: {base_sha}",
        f"# filter-sha256: {digest}",
        f"# exclude-sha256: {exclude_sha}",
    ]
    lines += [f"{results[name]}\t{name}" for name in sorted(results)]
    return "\n".join(lines) + "\n"


def parse_base(text, source=BASE_RESULTS_FILE):
    meta, results = {}, {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        match = re.match(r"^# (base|filter-sha256|exclude-sha256): (\S+)$", line)
        if match:
            meta[match.group(1)] = match.group(2)
            continue
        if line.startswith("#"):
            continue
        outcome, sep, name = line.partition("\t")
        if not sep or outcome not in SEVERITY or not name:
            raise ToolError(f"{source}:{number}: expected '<pass|fail|skip><TAB><full test name>'")
        results[name] = outcome
    return meta, results


@dataclass
class Report:
    regressions: list = field(default_factory=list)  # (name, base outcome, current outcome)
    expected_hits: dict = field(default_factory=dict)  # name -> tag
    expected_passing: list = field(default_factory=list)  # (name, tag): listed but passes now
    expected_unknown: list = field(default_factory=list)  # (name, tag): listed but not in this run or BASE
    base_failures: list = field(default_factory=list)  # (name, base, current): not passing at BASE either
    new_tests: list = field(default_factory=list)  # (name, outcome): not in BASE
    fixed: list = field(default_factory=list)  # names: not passing at BASE, passing now


def diff(base, current, expected):
    report = Report()
    for name in sorted(set(base) | set(current)):
        before = base.get(name, MISSING)
        now = current.get(name, MISSING)
        tag = expected.get(name)
        if before == MISSING:
            report.new_tests.append((name, now))
        if now == PASS:
            if tag:
                report.expected_passing.append((name, tag))
            elif before not in (PASS, MISSING):
                report.fixed.append(name)
            continue
        if tag:
            report.expected_hits[name] = tag
        elif before == PASS or (before == MISSING and now == FAIL):
            report.regressions.append((name, before, now))
        elif before != MISSING and (before, now) != (SKIP, SKIP):
            report.base_failures.append((name, before, now))
    report.expected_unknown = [(n, t) for n, t in sorted(expected.items()) if n not in base and n not in current]
    return report


def format_report(report, base_sha, base, current, excluded=()):
    counts = {o: sum(1 for v in current.values() if v == o) for o in (PASS, FAIL, SKIP)}
    out = [
        f"upstream_tests: {len(current)} tests run ({counts[PASS]} pass, {counts[FAIL]} fail, {counts[SKIP]} skip); "
        f"BASE {base_sha[:12]}: {len(base)} tests"
    ]

    def section(title, rows):
        if rows:
            out.append(f"{title} ({len(rows)}):")
            out.extend(f"  {row}" for row in rows)

    section("REGRESSIONS", [f"[{b} -> {n}] {name}" for name, b, n in report.regressions])
    if report.expected_hits:
        tags = {}
        for tag in report.expected_hits.values():
            tags[tag] = tags.get(tag, 0) + 1
        out.append(
            f"Expected failures hit ({len(report.expected_hits)}): "
            + ", ".join(f"{tag} x{count}" for tag, count in sorted(tags.items()))
        )
    section(
        f"Expected failures that pass now (drop them from {EXPECTED_FILE})",
        [f"{tag} {name}" for name, tag in report.expected_passing],
    )
    section("Expected failures not in this run nor BASE", [f"{tag} {name}" for name, tag in report.expected_unknown])
    section("Not passing at BASE either", [f"[{b} -> {n}] {name}" for name, b, n in report.base_failures])
    section("New tests (not at BASE)", [f"[{now}] {name}" for name, now in report.new_tests])
    section("Fixed since BASE", report.fixed)
    section(
        f"Excluded sources with kept-surface tests (not run here nor at BASE; {EXCLUDE_FILE})",
        [f"{tag} {path}: {', '.join(names)}" for tag, path, names in excluded],
    )
    out.append(f"Result: {len(report.regressions)} regression(s)")
    return "\n".join(out) + "\n"


def unmatched_entries(entries, results):
    """Filter entries that select no test in results (a typo or a removed fixture)."""
    return [entry for entry in entries if not any(entry in name for name in results)]


def find_test_data(start):
    """Mirror SimpleTest.FindTestDataPath: the first bc-test-data directory in start or a parent."""
    for directory in (start, *start.parents):
        if (directory / TEST_DATA_DIR).is_dir():
            return directory / TEST_DATA_DIR
    return None


def require_test_data(tree):
    if find_test_data(tree) is None:
        raise ToolError(
            f"{TEST_DATA_DIR} not found in {tree} or any parent directory (SimpleTest.FindTestDataPath walks up "
            f"to it). Clone it read-only beside the repository (about 7 GB):\n"
            f"  cd {tree.parent} && {CLONE_COMMAND}"
        )


def find_dotnet():
    dotnet = shutil.which("dotnet")
    if dotnet is None:
        home = Path.home() / ".dotnet" / "dotnet"
        if home.is_file():
            return str(home)
        raise ToolError("dotnet not found on PATH (try: export PATH=$HOME/.dotnet:$PATH)")
    return dotnet


def write_exclusion_targets(results_dir, exclusions):
    """Write the Compile Remove file; left untouched when unchanged, as a newer import forces a full rebuild."""
    path = results_dir / "exclude.targets"
    text = exclusion_targets(exclusions)
    if not path.is_file() or path.read_text(encoding="utf-8") != text:
        path.write_text(text, encoding="utf-8")
    return path


def dotnet_test_command(dotnet, expression, targets, trx_name, results_dir, framework):
    return [
        dotnet, "test", str(TEST_PROJECT), "--nologo", "--framework", framework,
        f"-p:CustomAfterMicrosoftCommonTargets={targets}",
        "--filter", expression, "--logger", f"trx;LogFileName={trx_name}", "--results-directory", str(results_dir),
    ]


def run_tests(tree, entries, exclusions, results_dir, trx_name, framework):
    """Run the filtered upstream tests in tree without the excluded sources; return the parsed TRX."""
    expression = filter_expression(entries)
    results_dir.mkdir(parents=True, exist_ok=True)
    trx = results_dir / trx_name
    if trx.exists():
        trx.unlink()
    log = results_dir / (trx.stem + ".log")
    targets = write_exclusion_targets(results_dir, exclusions)
    command = dotnet_test_command(find_dotnet(), expression, targets, trx_name, results_dir, framework)
    env = dict(os.environ)
    env.setdefault("DOTNET_ROLL_FORWARD", "Major")
    env.setdefault("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
    print(f"upstream_tests: running filtered upstream tests in {tree} (log: {log})", file=sys.stderr)
    with open(log, "w", encoding="utf-8") as handle:
        completed = subprocess.run(command, cwd=tree, env=env, stdout=handle, stderr=subprocess.STDOUT)
    if not trx.is_file():
        raise no_trx_error(completed.returncode, log.read_text(encoding="utf-8", errors="replace"))
    return parse_trx(trx)


def no_trx_error(returncode, log_text):
    """The error for a dotnet test run that wrote no TRX; names a compile failure of crypto/test."""
    lines = log_text.splitlines()
    message = f"dotnet test exited {returncode} without a TRX"
    if any("error CS" in line for line in lines):
        message += (
            "; crypto/test does not compile on this tree (a cut removed API the upstream tests use),"
            f" so no upstream test result exists; list the failing test sources in {EXCLUDE_FILE}"
            " with the E-number of the cut"
        )
    return ToolError(message + "; last log lines:\n" + "\n".join(lines[-20:]))


def git(root, *args):
    try:
        completed = subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True)
    except (subprocess.CalledProcessError, OSError) as error:
        stderr = getattr(error, "stderr", None) or str(error)
        raise ToolError(f"git {' '.join(args)} failed in {root}: {stderr.strip()}") from error
    return completed.stdout.strip()


def update_base(root, entries, exclusions, results_dir, framework, keep_tree):
    base_sha = read_base_sha(root)
    tree = root.parent / f".upstream-base-{base_sha[:12]}"
    require_test_data(tree.parent)
    if not tree.exists():
        git(root, "worktree", "add", "--detach", str(tree), base_sha)
    elif git(tree, "rev-parse", "HEAD") != base_sha:
        raise ToolError(f"{tree} exists but is not at BASE {base_sha}; remove it (git worktree remove)")
    try:
        results = run_tests(tree, entries, exclusions, results_dir.resolve(), "base.trx", framework)
    finally:
        if not keep_tree:
            git(root, "worktree", "remove", "--force", str(tree))
    unmatched = unmatched_entries(entries, results)
    if unmatched:
        raise ToolError(f"{FILTER_FILE} entries that select no test (typo or removed fixture): {', '.join(unmatched)}")
    text = format_base(base_sha, filter_digest(entries), exclude_digest(exclusions), results)
    (root / BASE_RESULTS_FILE).write_text(text, encoding="utf-8")
    failing = sorted(name for name, outcome in results.items() if outcome != PASS)
    print(f"upstream_tests: wrote {BASE_RESULTS_FILE} ({len(results)} tests, {len(failing)} not passing at BASE)")
    for name in failing:
        print(f"  [{results[name]}] {name}")
    for tag, path, names in excluded_kept_tests(root, exclusions, entries):
        print(f"  excluded kept-surface source: {tag} {path}: {', '.join(names)}")
    return 0


def read_base_sha(root):
    path = root / BASE_FILE
    if not path.is_file():
        raise ToolError(f"{path} not found")
    return path.read_text(encoding="utf-8").strip()


def read_text(path):
    if not path.is_file():
        raise ToolError(f"{path} not found")
    return path.read_text(encoding="utf-8")


def load_base(root, entries, exclusions):
    meta, results = parse_base(read_text(root / BASE_RESULTS_FILE))
    base_sha = read_base_sha(root)
    if meta.get("base") != base_sha:
        raise ToolError(
            f"{BASE_RESULTS_FILE} is for BASE {meta.get('base')}, strip/BASE is {base_sha}: "
            "regenerate it with --update-base"
        )
    if meta.get("filter-sha256") != filter_digest(entries):
        raise ToolError(f"{FILTER_FILE} changed since {BASE_RESULTS_FILE} was generated: regenerate it with --update-base")
    if meta.get("exclude-sha256") != exclude_digest(exclusions):
        raise ToolError(
            f"{EXCLUDE_FILE} changed since {BASE_RESULTS_FILE} was generated (the BASE run drops the same sources): "
            "regenerate it with --update-base"
        )
    return base_sha, results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2], help="repository root")
    parser.add_argument("--framework", default=DEFAULT_FRAMEWORK)
    parser.add_argument("--results-dir", type=Path, help=f"TRX, logs and report (default: <root>/{RESULTS_DIR})")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--trx", type=Path, help="diff this TRX instead of running dotnet test")
    mode.add_argument("--update-base", action="store_true", help="regenerate the BASE results file")
    mode.add_argument("--print-filter", action="store_true", help="print the --filter expression and exit")
    parser.add_argument("--keep-base-tree", action="store_true", help="keep the BASE worktree after --update-base")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    results_dir = (args.results_dir or root / RESULTS_DIR).resolve()
    try:
        if not (args.trx or args.print_filter or args.update_base):
            require_test_data(root)
        entries = parse_filter(read_text(root / FILTER_FILE))
        expression = filter_expression(entries)
        exclusions = parse_exclusions(read_text(root / EXCLUDE_FILE))
        check_exclusions_exist(root, exclusions)
        if args.print_filter:
            print(expression)
            return 0
        if args.update_base:
            return update_base(root, entries, exclusions, results_dir, args.framework, args.keep_base_tree)
        expected = parse_expected(read_text(root / EXPECTED_FILE))
        base_sha, base = load_base(root, entries, exclusions)
        if args.trx:
            current = parse_trx(args.trx)
        else:
            current = run_tests(root, entries, exclusions, results_dir, "current.trx", args.framework)
        report = diff(base, current, expected)
        text = format_report(report, base_sha, base, current, excluded_kept_tests(root, exclusions, entries))
        if not args.trx:
            (results_dir / "report.txt").write_text(text, encoding="utf-8")
        print(text, end="")
        return 1 if report.regressions else 0
    except ToolError as error:
        print(f"upstream_tests: error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

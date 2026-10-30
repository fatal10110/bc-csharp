#!/usr/bin/env python3
"""Stage and build the stripped tree (STRIP_PLAN_V2.md section 5 step 3, issue #10).

strip.sh runs two subcommands around the namespace rewrite (rewrite.py, step 4):

stage  (after closure.py) reads <work>/closure_report.json and writes
       <work>/kept.txt          crypto/src-relative kept files (closure - denied), rewrite.py's file list
       <work>/roots.txt         the .cs files of the roots directory, relative to it
       <work>/stage/_TurboNamespaceStubs.cs  the namespace stubs of the kept tree: the sweep's
                                (closure - denied + roots) when the sweep ran, else the fixpoint's
       <work>/stage/stubs.txt   rewrite.py's file list for the stubs
build  (after the rewrite) builds, per define set, in <work>/build/<stage>-<set>/:
       3a  the stripped tree: kept files + stubs                      -> TurboBC.Strip.<x>.dll
       3c  the rewritten tree (<work>/rewritten/lib)                  -> TurboBC.<x>.dll
           and, as a separate assembly referencing it, the rewritten roots (the unmodified
           consumer files, RootStubs.cs, roots-extra.cs; <work>/rewritten/roots)
                                                                      -> TurboBC.Consumer.<x>.dll
       <x> is ns21 for [netstandard21], netfx for [netframework], else the set name (any
       other set). The consumer build is skipped when its TurboBC.<x>.dll did not build. Built
       TurboBC.<x>.dll files are copied to <work>/dll/ for the smoke hook; every compile error goes
       to <work>/build_report.json.
       #58: when [netstandard21] is built, its DEBUG variant [netstandard21_debug] (the captured set
       plus DEBUG and TRACE, defines.debug_variants; not in unity-defines.txt) is built too, last:
       3a, 3c and consumer, <x> = ns21-debug, its TurboBC.ns21-debug.dll copied to <work>/dll/debug/
       (strip.sh runs only the curve, KAT and registry smoke rows against it).

Every build is a copy of strip/Closure.csproj (CS3021 suppressed, exactly the captured defines) with
the define assertion of closure.py (binlog, csc /define: == the set). One `dotnet restore` per
project, then `dotnet build --no-restore`, one build at a time.

Exit codes: 0 every build clean; 1 compile errors (also with --report, which only turns the FAIL
prefix into REPORT: strip.sh decides whether to go on); 2 usage, missing input or define assertion;
3 restore or build failure without compile errors.
"""

import argparse
import json
import os
import re
import shutil
import sys
from xml.sax.saxutils import escape

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import closure as closure_mod  # noqa: E402
import defines as defines_mod  # noqa: E402

REPO = closure_mod.REPO
REPORT_FILE = "closure_report.json"
KEPT_LIST = "kept.txt"
ROOTS_LIST = "roots.txt"
STAGE_DIR = "stage"
STUBS_LIST = "stubs.txt"
REWRITTEN_LIB = os.path.join("rewritten", "lib")
REWRITTEN_ROOTS = os.path.join("rewritten", "roots")
DLL_DIR = "dll"
BUILD_REPORT = "build_report.json"
# The real sets of turboHTTP#141 (#29) get the plan's DLL names; any other set keeps its own.
DLL_SUFFIX = {"netstandard21": "ns21", defines_mod.NETFRAMEWORK_SET: "netfx", "netstandard21_debug": "ns21-debug"}
DEBUG_DLL_DIR = os.path.join(DLL_DIR, "debug")  # DEBUG variants (#58): strip.sh runs a row subset on them
_SET_NAME = re.compile(r"^[A-Za-z0-9_]+$")
SHOWN_ERRORS = 10  # per build on the console; build_report.json has all


class StageError(Exception):
    pass


def dll_suffix(set_name):
    if not _SET_NAME.match(set_name):
        raise StageError(f"define set name not usable in an assembly name: {set_name!r}")
    return DLL_SUFFIX.get(set_name, set_name)


def lib_assembly(set_name):
    return f"TurboBC.{dll_suffix(set_name)}"


def write_list(path, items, header):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"# {header}\n")
        f.writelines(f"{i}\n" for i in items)


def read_list(path):
    with open(path, encoding="utf-8") as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]


def list_cs(root):
    out = []
    for d, sub, fs in os.walk(root):
        sub[:] = sorted(x for x in sub if x not in ("bin", "obj"))
        out += [os.path.relpath(os.path.join(d, f), root).replace(os.sep, "/") for f in sorted(fs) if f.endswith(".cs")]
    return sorted(out)


def stage(work, roots):
    """Write the file lists and the kept tree's stubs; return (kept, stubs, roots files)."""
    try:
        with open(os.path.join(work, REPORT_FILE), encoding="utf-8") as f:
            report = json.load(f)
    except (OSError, ValueError) as e:
        raise StageError(f"{REPORT_FILE}: {e} (run closure.py first)")
    denied = report.get("denied", {})
    kept = [f for f in report["files"] if f not in denied]
    if not kept:
        raise StageError("closure kept no file")
    stubs = report["sweep_stubs"] if report.get("swept") else report["stubs"]
    root_files = list_cs(roots)
    if not root_files:
        raise StageError(f"no .cs file under {roots}")
    stage_dir = os.path.join(work, STAGE_DIR)
    if os.path.isdir(stage_dir):
        shutil.rmtree(stage_dir)
    os.makedirs(stage_dir)
    with open(os.path.join(stage_dir, closure_mod.SHIPPED_STUBS), "w", encoding="utf-8", newline="\n") as f:
        f.write(closure_mod.render_stubs(stubs))
    write_list(os.path.join(stage_dir, STUBS_LIST), [closure_mod.SHIPPED_STUBS], "build.py stage: shipped stubs")
    write_list(os.path.join(work, KEPT_LIST), kept, "build.py stage: kept files (closure - denied), crypto/src-relative")
    write_list(os.path.join(work, ROOTS_LIST), root_files, f"build.py stage: roots, relative to {roots}")
    return kept, stubs, root_files


class StageBuilder(closure_mod.DotnetBuilder):
    """DotnetBuilder keyed by build (e.g. '3c-min') instead of define set: each build has its own
    project directory, assembly name and references; the define assertion is the same."""

    def __init__(self, work, csproj, dotnet="dotnet", log=print):
        super().__init__(work, csproj, {}, dotnet=dotnet, log=log)
        self.targets = {}  # key -> (set name, assembly name, [reference dll paths])

    def add(self, key, set_name, defines, assembly, references=()):
        self.sets[key] = defines
        self.targets[key] = (set_name, assembly, list(references))

    def set_dir(self, key):
        return os.path.join(self.work, "build", key)

    def _write_props(self, key, files):
        set_name, assembly, refs = self.targets[key]
        props = defines_mod.render_props(defines_mod.tfm_for_set(set_name), self.sets[key], files)
        extra = ["  <PropertyGroup>", f"    <AssemblyName>{escape(assembly)}</AssemblyName>", "  </PropertyGroup>"]
        if refs:
            extra.append("  <ItemGroup>")
            for r in refs:
                name = os.path.splitext(os.path.basename(r))[0]
                extra.append(f'    <Reference Include="{escape(name)}"><HintPath>{escape(r)}</HintPath></Reference>')
            extra.append("  </ItemGroup>")
        props = props.replace("</Project>", "\n".join(extra) + "\n</Project>")
        with open(os.path.join(self.set_dir(key), "Closure.props"), "w", encoding="utf-8") as f:
            f.write(props)

    def output(self, key):
        set_name, assembly, _ = self.targets[key]
        tfm = defines_mod.tfm_for_set(set_name)
        return os.path.join(self.set_dir(key), "bin", "Debug", tfm, assembly + ".dll")


def select_sets(all_sets, wanted):
    """The captured sets to build (all when wanted is empty), then the DEBUG variants of those (#58)."""
    unknown = [s for s in wanted if s not in all_sets]
    if unknown:
        raise StageError(f"unknown define set(s) {unknown}; the define file has {list(all_sets)}")
    sets = {s: all_sets[s] for s in (wanted or all_sets)}
    sets.update(defines_mod.debug_variants(sets))
    return sets


def plan_builds(builder, sets, work, src):
    """Register every build; return [(set, key_3a, key_3c, key_consumer, 3a files, 3c files, consumer files)]."""
    kept = read_list(os.path.join(work, KEPT_LIST))
    stage_stubs = os.path.join(work, STAGE_DIR, closure_mod.SHIPPED_STUBS)
    lib_dir = os.path.join(work, REWRITTEN_LIB)
    roots_dir = os.path.join(work, REWRITTEN_ROOTS)
    for d in (lib_dir, roots_dir):
        if not os.path.isdir(d):
            raise StageError(f"{d} missing (run rewrite.py first)")
    files_3a = [os.path.join(src, f) for f in kept] + [stage_stubs]
    files_3c = [os.path.join(lib_dir, f) for f in list_cs(lib_dir)]
    files_consumer = [os.path.join(roots_dir, f) for f in list_cs(roots_dir)]
    missing = [p for p in files_3a if not os.path.isfile(p)]
    if missing:
        raise StageError("kept file(s) missing: " + ", ".join(missing[:5]))
    plan = []
    for s, defines in sets.items():
        lib = lib_assembly(s)
        k3a, k3c, kcon = f"3a-{s}", f"3c-{s}", f"3c-consumer-{s}"
        builder.add(k3a, s, defines, f"TurboBC.Strip.{dll_suffix(s)}")
        builder.add(k3c, s, defines, lib)
        builder.add(kcon, s, defines, f"TurboBC.Consumer.{dll_suffix(s)}", [builder.output(k3c)])
        plan.append((s, k3a, k3c, kcon, files_3a, files_3c, files_consumer))
    return plan


def run_builds(builder, plan, work, log=print):
    """Run the planned builds; return {key: [error strings] or None when skipped}."""
    dll_dir = os.path.join(work, DLL_DIR)
    if os.path.isdir(dll_dir):
        shutil.rmtree(dll_dir)
    os.makedirs(dll_dir)
    results = {}
    for s, k3a, k3c, kcon, files_3a, files_3c, files_consumer in plan:
        for key, files in ((k3a, files_3a), (k3c, files_3c), (kcon, files_consumer)):
            if key == kcon and results[k3c]:
                results[key] = None
                log(f"[{key}] skipped: {lib_assembly(s)}.dll did not build")
                continue
            errors = builder.build(key, files, assert_defines=True)
            results[key] = [str(e) for e in sorted(errors)]
            log(f"[{key}] {builder.targets[key][1]}.dll: {len(errors)} compile error(s)")
        if not results[k3c]:
            dest = os.path.join(work, DEBUG_DLL_DIR if s in defines_mod.DEBUG_VARIANTS else DLL_DIR)
            os.makedirs(dest, exist_ok=True)
            shutil.copyfile(builder.output(k3c), os.path.join(dest, lib_assembly(s) + ".dll"))
    return results


def failure_lines(results):
    out = []
    for key, errors in results.items():
        if errors is None:
            out.append(f"build [{key}]: skipped (its TurboBC dll did not build)")
        elif errors:
            out.append(f"build [{key}]: {len(errors)} compile error(s)")
            out += [f"  {e}" for e in errors[:SHOWN_ERRORS]]
            if len(errors) > SHOWN_ERRORS:
                out.append(f"  ... {len(errors) - SHOWN_ERRORS} more in {BUILD_REPORT}")
    return out


def parse_args(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    st = sub.add_parser("stage", help="file lists and stubs from closure_report.json")
    st.add_argument("--work", default=os.path.join(REPO, "strip", "work"))
    st.add_argument("--roots", default=os.path.join(REPO, "strip", "roots"))
    b = sub.add_parser("build", help="builds 3a and 3c per define set")
    b.add_argument("--work", default=os.path.join(REPO, "strip", "work"))
    b.add_argument("--src", default=os.path.join(REPO, "crypto", "src"))
    b.add_argument("--defines", default=os.path.join(REPO, "strip", "unity-defines.txt"))
    b.add_argument("--set", dest="sets", action="append", default=[], help="only these define sets")
    b.add_argument("--csproj", default=os.path.join(REPO, "strip", "Closure.csproj"))
    b.add_argument("--report", action="store_true", help="prefix failures REPORT instead of FAIL")
    b.add_argument("--no-restore", action="store_true")
    b.add_argument("--dotnet", default="dotnet")
    return ap.parse_args(argv)


def main(argv=None):
    a = parse_args(sys.argv[1:] if argv is None else argv)
    work = os.path.abspath(a.work)
    if a.cmd == "stage":
        try:
            kept, stubs, roots = stage(work, os.path.abspath(a.roots))
        except (OSError, KeyError, StageError) as e:
            print(f"build.py stage: error: {e}", file=sys.stderr)
            return 2
        print(f"stage: {len(kept)} kept files, {len(stubs)} stub(s) {stubs}, {len(roots)} roots files")
        return 0

    try:
        sets = select_sets(defines_mod.load_unity_defines(a.defines), a.sets)
        builder = StageBuilder(work, os.path.abspath(a.csproj), dotnet=a.dotnet)
        plan = plan_builds(builder, sets, work, os.path.abspath(a.src))
        builder.prepare(restore=not a.no_restore)
        results = run_builds(builder, plan, work)
    except (OSError, StageError, defines_mod.DefineError) as e:
        print(f"build.py: error: {e}", file=sys.stderr)
        return 2
    except closure_mod.BuildFailure as e:
        print(f"BUILD FAILURE: {e}", file=sys.stderr)
        return 3
    with open(os.path.join(work, BUILD_REPORT), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=1, sort_keys=True)
        f.write("\n")
    failures = failure_lines(results)
    for line in failures:
        print(("REPORT " if a.report else "FAIL ") + line)
    if failures:
        return 1
    built = [os.path.join(d, f).replace(os.sep, "/") for d in (DLL_DIR, DEBUG_DLL_DIR)
             if os.path.isdir(os.path.join(work, d)) for f in sorted(os.listdir(os.path.join(work, d)))
             if f.endswith(".dll")]
    print(f"builds clean: {built}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

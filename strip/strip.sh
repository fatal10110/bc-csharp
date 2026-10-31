#!/usr/bin/env bash
# Strip pipeline (STRIP_PLAN_V2.md section 5, issue #10): reduce this tree to the TLS client subset
# turboHTTP vendors and package it into strip/out/.
#
#   1 prepare   prerequisites; with --refresh-roots, re-copy strip/roots + ROOTS_SHA (refresh_roots.py)
#   2 closure   fixpoint, deny hits, referrer sweep, budget (closure.py; its fail checks)
#     stage     kept file list and the kept tree's namespace stubs (build.py stage)
#   4 rewrite   Org.BouncyCastle -> TurboHTTP.SecureProtocol.Org.BouncyCastle (rewrite.py: kept tree,
#               stubs, roots); runs before step 3 because build 3c compiles its output
#   3 builds    per define set: 3a the stripped tree, 3c the rewritten tree -> TurboBC.<x>.dll and
#               the consumer files + RootStubs + roots-extra against it (build.py build); with
#               [netstandard21] also its DEBUG variant (#58: + DEBUG TRACE, Unity Editor and
#               Development builds; derived in defines.py, not a set of unity-defines.txt)
#   5 smoke     hook: strip/smoke/run.sh when present and executable (#23 fills it); every row on the
#               release DLLs, the curve, KAT and registry rows on the DEBUG DLL
#   6 package   strip/out: Lib/ + .meta, LICENSE.md, THIRD-PARTY-NOTICES.txt, STRIP_INFO.md (package.py)
#   7 hand over strip/out/ to turboHTTP#141; this script never writes into turboHTTP.
#
# Enforce mode (default) stops with exit 1 at the first failing step: a closure fail check (deny hit,
# budget overrun, unresolved errors, ...), a compile error in a build, a failing smoke hook.
# --report logs those (REPORT lines) and goes on to package. Usage errors exit 2; a missing
# prerequisite, a tool error or a restore/build failure without compile errors exits 3 in both modes.
#
# Smoke hook contract (#23): strip/smoke/run.sh --work <work> --results <file> [--slow] <TurboBC dll>...
# runs only when every 3c build is clean; exit 0 = pass. --smoke-slow adds --slow (slow rows such as
# the 30 s handshake-timeout row, #27; the enforce run of #30 uses it, the local gate does not).
# A second call runs DEBUG_SMOKE_FILTERS on the DEBUG DLL(s) in <work>/dll/debug/ (#58: the static
# constructors, including DigestUtilities' #if DEBUG self-checks); its results are appended under a
# "DEBUG build" line. The results file, when written, goes into STRIP_INFO.md (package.py --smoke);
# otherwise STRIP_INFO.md says "Not run.".

set -uo pipefail

usage() {
  cat <<'EOF'
usage: strip/strip.sh [--report] [--refresh-roots --turbohttp <path>] [--set <name>]...
                      [--work <dir>] [--out <dir>] [--old-base <sha>] [--smoke-slow]

  --report            log fail checks (deny hits, budget, unresolved and compile errors) instead of
                      failing; still packages
  --refresh-roots     re-copy strip/roots from a turboHTTP checkout and update strip/ROOTS_SHA
  --turbohttp <path>  top level of the turboHTTP git checkout (read only; needs --refresh-roots)
  --set <name>        only this define set of strip/unity-defines.txt (repeatable; default all)
  --work <dir>        work directory (default strip/work)
  --out <dir>         package directory (default strip/out)
  --old-base <sha>    previous BASE on a bump: STRIP_INFO.md's shadow diff is OLDBASE..BASE
  --smoke-slow        also run the slow smoke rows (run.sh --slow: the 30 s handshake-timeout row,
                      about 30 s per define set); the enforce run uses it, the local gate does not
EOF
}

die_usage() { echo "strip.sh: $*" >&2; usage >&2; exit 2; }

abspath() { case $1 in /*) printf '%s\n' "$1" ;; *) printf '%s\n' "$PWD/$1" ;; esac; }

report=0
refresh=0
smoke_slow=()
turbohttp=""
old_base=""
work=""
out=""
sets=()
while [ $# -gt 0 ]; do
  case $1 in
    -h|--help) usage; exit 0 ;;
    --report) report=1 ;;
    --refresh-roots) refresh=1 ;;
    --smoke-slow) smoke_slow=(--slow) ;;
    --turbohttp|--set|--work|--out|--old-base)
      if [ $# -lt 2 ] || [ -z "$2" ]; then die_usage "$1 needs a value"; fi
      case $1 in
        --turbohttp) turbohttp=$(abspath "$2") ;;
        --set) sets+=(--set "$2") ;;
        --work) work=$(abspath "$2") ;;
        --out) out=$(abspath "$2") ;;
        --old-base) old_base=$2 ;;
      esac
      shift ;;
    *) die_usage "unknown argument: $1" ;;
  esac
  shift
done
[ "$refresh" = 1 ] && [ -z "$turbohttp" ] && die_usage "--refresh-roots needs --turbohttp <path>"
[ "$refresh" = 0 ] && [ -n "$turbohttp" ] && die_usage "--turbohttp is only used with --refresh-roots"

repo=$(cd "$(dirname "$0")/.." && pwd) || exit 3
cd "$repo" || exit 3
tool=strip/tool
work=${work:-$repo/strip/work}
out=${out:-$repo/strip/out}
mode=enforce
[ "$report" = 1 ] && mode=report

start=$SECONDS
step() { printf '\n=== strip.sh: %s (%ss)\n' "$*" "$((SECONDS - start))"; }
fatal() { echo "strip.sh: error: $*" >&2; exit 3; }
# A fail check: enforce stops here, --report logs it and goes on.
check_failed() {
  if [ "$report" = 1 ]; then echo "REPORT strip.sh: $*"; failed+=("$*"); return 0; fi
  echo "FAIL strip.sh: $*" >&2
  exit 1
}
failed=()
# #58: the rows run against the DEBUG build (run.sh --filter: substrings of group/row ids).
DEBUG_SMOKE_FILTERS=(--filter curves/ --filter kat- --filter registries/)

step "1 prepare ($mode)"
command -v python3 >/dev/null || fatal "python3 not found (Python 3.8+ required)"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' || fatal "Python 3.8+ required: $(python3 --version 2>&1)"
command -v git >/dev/null || fatal "git not found"
if ! command -v dotnet >/dev/null; then
  if [ -x "$HOME/.dotnet/dotnet" ]; then
    PATH=$HOME/.dotnet:$PATH
    export PATH
  else
    fatal "dotnet not found; install the .NET SDK 8 or try: export PATH=\$HOME/.dotnet:\$PATH"
  fi
fi
sdk=$(dotnet --version 2>/dev/null) || fatal "dotnet --version failed (no .NET SDK?)"
case $sdk in
  [0-7].*|'') fatal ".NET SDK 8 or newer required, found '$sdk'" ;;
esac
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
# OpenSSL 3.x (the system one is fine) is needed by the smoke suite's interop rows only.
ssl=$(openssl version 2>/dev/null || true)
case $ssl in
  "OpenSSL 3."*) ;;
  *) echo "warning: OpenSSL 3.x not found (openssl version: '${ssl:-none}'); the smoke suite's interop needs it" ;;
esac
echo "dotnet $sdk; $(python3 --version 2>&1); ${ssl:-no openssl}"
if [ ! -f strip/BASE ] || [ ! -f strip/ROOTS_SHA ]; then fatal "strip/BASE or strip/ROOTS_SHA missing"; fi
base=$(tr -d '[:space:]' < strip/BASE)
if [ "$refresh" = 1 ]; then
  step "1 prepare: refresh roots from $turbohttp"
  python3 "$tool/refresh_roots.py" --turbohttp "$turbohttp" --strip-dir strip || fatal "refresh_roots.py"
fi
roots_sha=$(tr -d '[:space:]' < strip/ROOTS_SHA)
echo "BASE $base, ROOTS_SHA $roots_sha, HEAD $(git rev-parse HEAD 2>/dev/null || echo unknown)"
echo "work $work, out $out"

step "2 closure"
# closure.py runs without --report in both modes: its --report exits 0 on fail checks, and strip.sh
# needs exit 1 to log them (report) or stop (enforce) and to mark a report package.
closure_args=(--roots strip/roots --work "$work" ${sets[@]+"${sets[@]}"})
python3 "$tool/closure.py" "${closure_args[@]}"
rc=$?
case $rc in
  0) ;;
  1) check_failed "closure fail checks (FAIL lines above)" ;;
  2) fatal "closure.py: usage or define assertion error (exit 2)" ;;
  *) fatal "closure.py: build failure (exit $rc)" ;;
esac

step "2 stage: kept list and namespace stubs"
python3 "$tool/build.py" stage --work "$work" --roots strip/roots || fatal "build.py stage"

step "4 rewrite"
rm -rf "$work/rewritten"
python3 "$tool/rewrite.py" --src crypto/src --files "$work/kept.txt" --out "$work/rewritten/lib" \
  || fatal "rewrite.py (library)"
python3 "$tool/rewrite.py" --src "$work/stage" --files "$work/stage/stubs.txt" --out "$work/rewritten/stubs" \
  || fatal "rewrite.py (stubs)"
[ -e "$work/rewritten/lib/_TurboNamespaceStubs.cs" ] && fatal "crypto/src has its own _TurboNamespaceStubs.cs"
cp "$work/rewritten/stubs/_TurboNamespaceStubs.cs" "$work/rewritten/lib/" || fatal "staging the stubs"
python3 "$tool/rewrite.py" --src strip/roots --files "$work/roots.txt" --out "$work/rewritten/roots" \
  || fatal "rewrite.py (roots)"

step "3 builds (3a stripped tree, 3c rewritten tree + consumer)"
build_args=(build --work "$work" ${sets[@]+"${sets[@]}"})
[ "$report" = 1 ] && build_args+=(--report)
python3 "$tool/build.py" "${build_args[@]}"
rc=$?
builds_clean=0
case $rc in
  0) builds_clean=1 ;;
  1) check_failed "compile errors in builds 3a/3c (lines above; all in $work/build_report.json)" ;;
  2) fatal "build.py: usage, input or define assertion error (exit 2)" ;;
  *) fatal "build.py: restore or build failure (exit $rc)" ;;
esac

step "5 smoke"
smoke_results=""
if [ ! -x strip/smoke/run.sh ]; then
  echo "no strip/smoke/run.sh yet (#23): smoke not run"
elif [ "$builds_clean" != 1 ]; then
  check_failed "smoke skipped: not every build is clean"
else
  case $ssl in
    "OpenSSL 3."*) ;;
    *) fatal "the smoke suite needs OpenSSL 3.x (openssl version: '${ssl:-none}')" ;;
  esac
  results=$work/smoke-results.md
  debug_results=$work/smoke-results-debug.md
  rm -f "$results" "$debug_results"
  if strip/smoke/run.sh --work "$work" --results "$results" ${smoke_slow[@]+"${smoke_slow[@]}"} \
      "$work"/dll/TurboBC.*.dll; then
    echo "smoke passed"
  else
    check_failed "smoke suite failed"
  fi
  debug_dlls=()
  for dll in "$work"/dll/debug/TurboBC.*.dll; do [ -f "$dll" ] && debug_dlls+=("$dll"); done
  if [ "${#debug_dlls[@]}" -gt 0 ]; then
    if strip/smoke/run.sh --work "$work" --results "$debug_results" "${DEBUG_SMOKE_FILTERS[@]}" \
        "${debug_dlls[@]}"; then
      echo "smoke passed (DEBUG build)"
    else
      check_failed "smoke suite failed (DEBUG build)"
    fi
    {
      echo
      echo "DEBUG build (#58): [netstandard21] + DEBUG TRACE, the Unity Editor and Development defines (derived in"
      echo "strip/tool/defines.py; unity-defines.txt is the player capture); built 3a, 3c and consumer; rows:"
      echo "${DEBUG_SMOKE_FILTERS[*]}"
      echo
      if [ -f "$debug_results" ]; then cat "$debug_results"; else echo "No results (run.sh failed before writing them)."; fi
    } >> "$results" || fatal "writing $results"
  fi
  [ -f "$results" ] && smoke_results=$results
fi
# A --report package with failing steps must not pass for a handover: say so in STRIP_INFO.md.
if [ "${#failed[@]}" -gt 0 ]; then
  note=$work/report-note.md
  {
    echo "Not for handover: \`strip.sh --report\` packaged this tree with failing steps (enforce mode fails on them):"
    echo
    printf -- '- %s\n' "${failed[@]}"
    if [ -n "$smoke_results" ]; then echo; cat "$smoke_results"; else echo; echo "Smoke: not run."; fi
  } > "$note" || fatal "writing $note"
  smoke_results=$note
fi

step "6 package -> $out"
package_args=(--lib "$work/rewritten/lib" --out "$out" --base "$base" --roots-sha "$roots_sha" --repo "$repo")
[ -n "$old_base" ] && package_args+=(--old-base "$old_base")
[ -n "$smoke_results" ] && package_args+=(--smoke "$smoke_results")
python3 "$tool/package.py" "${package_args[@]}" || fatal "package.py"

step "done ($mode)"
if [ "${#failed[@]}" -gt 0 ]; then
  echo "report: ${#failed[@]} failing step(s), enforce mode would fail:"
  printf '  %s\n' "${failed[@]}"
else
  echo "clean"
fi
echo "7 hand over: $out (turboHTTP#141 syncs Lib/; this script never writes into turboHTTP)"
exit 0

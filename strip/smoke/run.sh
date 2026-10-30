#!/usr/bin/env bash
# Strip smoke suite (STRIP_PLAN_V2.md section 5 step 5, issues #23-#27): strip.sh's step 5 hook, also run by hand.
#
#   strip/smoke/run.sh --work <work> --results <file> [--base-dll <dll>] [--filter <text>]... <TurboBC.x.dll>...
#
# 1 upstream: a full build of strip/BASE (BouncyCastle.Cryptography, net6.0) for the test servers and tooling,
#   in <work>/smoke/base/; built from a temporary git worktree of BASE (removed again) and reused while
#   <work>/smoke/base/BASE names the same commit. --base-dll skips this.
# 2 self-test: the runner's row isolation (TurboSmoke --self-test), once.
# 3 per DLL: strip/smoke/TurboSmoke.csproj built against that TurboBC.<x>.dll (client side) and the BASE build
#   (server side) in <work>/smoke/build/<x>/, then run: every row group under strip/smoke/rows/.
# The results file gets one block per DLL (summary line + one PASS/FAIL line per row, no timings): strip.sh
# packages it into STRIP_INFO.md.
#
# Exit: 0 every row of every DLL passed; 1 a row failed, the self-test failed or the harness did not compile
# against a DLL; 2 usage; 3 a prerequisite or the BASE build failed.

set -uo pipefail

usage() {
  echo "usage: strip/smoke/run.sh --work <dir> --results <file> [--base-dll <dll>] [--filter <text>]... <TurboBC.x.dll>..."
}
die_usage() { echo "run.sh: $*" >&2; usage >&2; exit 2; }
fatal() { echo "run.sh: error: $*" >&2; exit 3; }
abspath() { case $1 in /*) printf '%s\n' "$1" ;; *) printf '%s\n' "$PWD/$1" ;; esac; }

work=""
results=""
base_dll=""
filters=()
dlls=()
while [ $# -gt 0 ]; do
  case $1 in
    -h|--help) usage; exit 0 ;;
    --work|--results|--base-dll|--filter)
      if [ $# -lt 2 ] || [ -z "$2" ]; then die_usage "$1 needs a value"; fi
      case $1 in
        --work) work=$(abspath "$2") ;;
        --results) results=$(abspath "$2") ;;
        --base-dll) base_dll=$(abspath "$2") ;;
        --filter) filters+=(--filter "$2") ;;
      esac
      shift ;;
    -*) die_usage "unknown argument: $1" ;;
    *) dlls+=("$(abspath "$1")") ;;
  esac
  shift
done
[ -n "$work" ] || die_usage "--work is required"
[ -n "$results" ] || die_usage "--results is required"
[ "${#dlls[@]}" -gt 0 ] || die_usage "no TurboBC DLL given"
for dll in "${dlls[@]}"; do
  [ -f "$dll" ] || die_usage "no such DLL: $dll"
  case $(basename "$dll") in
    TurboBC.*.dll) ;;
    *) die_usage "not a TurboBC.<x>.dll: $dll" ;;
  esac
done
[ -z "$base_dll" ] || [ -f "$base_dll" ] || die_usage "no such --base-dll: $base_dll"

smoke=$(cd "$(dirname "$0")" && pwd) || exit 3
repo=$(cd "$smoke/../.." && pwd) || exit 3
if ! command -v dotnet >/dev/null; then
  if [ -x "$HOME/.dotnet/dotnet" ]; then
    PATH=$HOME/.dotnet:$PATH
    export PATH
  else
    fatal "dotnet not found; install the .NET SDK 8 or try: export PATH=\$HOME/.dotnet:\$PATH"
  fi
fi
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
sw=$work/smoke
mkdir -p "$sw" "$(dirname "$results")" || fatal "creating $sw"

echo "== smoke 1: upstream BASE build"
if [ -n "$base_dll" ]; then
  echo "using --base-dll $base_dll"
else
  [ -f "$repo/strip/BASE" ] || fatal "strip/BASE missing"
  base=$(tr -d '[:space:]' < "$repo/strip/BASE")
  bdir=$sw/base
  base_dll=$bdir/bin/BouncyCastle.Cryptography.dll
  if [ -f "$base_dll" ] && [ "$(cat "$bdir/BASE" 2>/dev/null)" = "$base" ]; then
    echo "reusing $base_dll (BASE $base)"
  else
    command -v git >/dev/null || fatal "git not found"
    src=$sw/base-src
    rm -rf "$bdir"
    git -C "$repo" worktree remove --force "$src" >/dev/null 2>&1
    rm -rf "$src"
    git -C "$repo" worktree prune
    git -C "$repo" worktree add --detach "$src" "$base" >/dev/null || fatal "git worktree add $src $base"
    dotnet build "$src/crypto/src/BouncyCastle.Crypto.csproj" -f net6.0 -c Release -nologo -v q -clp:ErrorsOnly \
      -o "$bdir/bin"
    rc=$?
    git -C "$repo" worktree remove --force "$src" || echo "warning: could not remove the worktree $src" >&2
    if [ "$rc" != 0 ] || [ ! -f "$base_dll" ]; then fatal "upstream BASE build failed (exit $rc)"; fi
    echo "$base" > "$bdir/BASE"
    echo "built $base_dll (BASE $base)"
  fi
fi

status=0
parts=()
first=1
for dll in "${dlls[@]}"; do
  name=$(basename "$dll" .dll)
  label=${name#TurboBC.}
  out=$sw/build/$label
  part=$sw/results-$label.txt
  rm -f "$part"
  echo "== smoke 3: $name.dll"
  if ! dotnet build "$smoke/TurboSmoke.csproj" -c Release -nologo -v q -clp:ErrorsOnly \
      -p:TurboBcDll="$dll" -p:UpstreamBcDll="$base_dll" -p:BaseIntermediateOutputPath="$out/obj/" -o "$out/bin"; then
    printf '%s.dll: harness build failed (compile errors above; rows not run)\n' "$name" > "$part"
    parts+=("$part")
    status=1
    continue
  fi
  if [ "$first" = 1 ]; then
    first=0
    echo "== smoke 2: runner self-test"
    if ! dotnet "$out/bin/TurboSmoke.dll" --self-test; then
      echo "harness self-test: FAILED (row isolation broken; results below are not trustworthy)" > "$sw/results-self-test.txt"
      parts+=("$sw/results-self-test.txt")
      status=1
    fi
  fi
  dotnet "$out/bin/TurboSmoke.dll" --label "$label" --dll "$dll" --work "$sw/run/$label" --results "$part" \
    ${filters[@]+"${filters[@]}"}
  rc=$?
  if [ "$rc" != 0 ]; then
    status=1
    [ -f "$part" ] || printf '%s.dll: harness exited %s without results\n' "$name" "$rc" > "$part"
  fi
  parts+=("$part")
done

{
  echo "Smoke suite (strip/smoke), BASE build: $(cat "$sw/base/BASE" 2>/dev/null || echo "$base_dll")"
  for p in "${parts[@]}"; do echo; cat "$p"; done
} > "$results" || fatal "writing $results"
if [ "$status" = 0 ]; then echo "smoke: passed ($results)"; else echo "smoke: FAILED ($results)"; fi
exit "$status"

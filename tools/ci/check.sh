#!/usr/bin/env bash
# Local quality gate for strip-v2. CI runs the same steps (.github/workflows/ci.yml).
#
#   tools/ci/check.sh            fast: whitespace format of changed C#, library/strip build
#   tools/ci/check.sh --full     also actionlint, shellcheck, Python tool tests, waves simulation
#   tools/ci/check.sh --fix      apply whitespace formatting instead of verifying it
#
# Build step: once strip/strip.sh exists it runs `strip/strip.sh --report` (the strip is the
# product; upstream code outside the closure may legitimately stop compiling after edge cuts).
# Until then it builds the whole library for netstandard2.0.
#
# Needs: python3, dotnet 8 SDK, git. Optional (--full): actionlint, shellcheck, node.
# CHECK_BASE (default origin/strip-v2) is what "changed C#" is diffed against.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 2

full=0; fix=0
for a in "$@"; do
  case "$a" in
    --full) full=1 ;;
    --fix) fix=1 ;;
    *) echo "usage: $0 [--full] [--fix]" >&2; exit 2 ;;
  esac
done

status=0
step() { echo "== $*"; }
fail() { echo "FAIL: $*"; status=1; }

base="${CHECK_BASE:-origin/strip-v2}"

if ! git rev-parse -q --verify "$base^{commit}" >/dev/null; then
  echo "FAIL: diff base $base missing (git fetch origin strip-v2)"; exit 1
fi

# Fork-owned C# is formatted whole; upstream C# is never reformatted (370+ upstream files carry
# tab/whitespace drift, and reformatting them would enlarge the rebase surface). For upstream files
# only the added lines are checked, for trailing whitespace.
owned=(); upstream=()  # bash 3.2 (macOS) has no mapfile
while IFS= read -r f; do
  [ -f "$f" ] || continue
  case "$f" in crypto/src/turbo/*|strip/*|tools/*) owned+=("$f") ;; *) upstream+=("$f") ;; esac
done < <(
  { git diff --name-only --diff-filter=ACMR "$base"...HEAD -- '*.cs'
    git diff --name-only --diff-filter=ACMR HEAD -- '*.cs'
    git ls-files --others --exclude-standard -- '*.cs'; } | sort -u)

step "format: fork-owned C# (dotnet format whitespace)"
if [ "${#owned[@]}" -eq 0 ]; then
  echo "no changed fork-owned C# files"
else
  fmt=(dotnet format whitespace --folder -v q --include "${owned[@]}")
  if [ "$fix" = 1 ]; then "${fmt[@]}" || fail "format"
  else "${fmt[@]}" --verify-no-changes || fail "format (run: tools/ci/check.sh --fix)"; fi
fi

step "format: added lines in upstream C# (trailing whitespace)"
if [ "${#upstream[@]}" -eq 0 ]; then
  echo "no changed upstream C# files"
else
  bad=$({ git diff -U0 "$base"...HEAD -- "${upstream[@]}"; git diff -U0 HEAD -- "${upstream[@]}"; } \
        | grep -nE '^\+[^+].*[[:space:]]$')
  if [ -n "$bad" ]; then echo "$bad"; fail "trailing whitespace on added upstream lines (fix by hand; never reformat upstream files)"; fi
fi

# Until #30 switches it to enforce mode, the gate runs strip.sh --report, which logs (does not
# fail on) deny hits and compile errors of the stripped builds. So until then the whole library
# must also keep compiling: that is the gate's only compile-regression check.
if [ -x strip/strip.sh ]; then
  step "strip (strip/strip.sh --report)"
  strip/strip.sh --report || fail "strip.sh --report"
fi
for tfm in netstandard2.0 net6.0; do
  step "library build ($tfm; until #30 enforces strip.sh)"
  dotnet build crypto/src/BouncyCastle.Crypto.csproj -f "$tfm" -c Release -nologo -v q -clp:ErrorsOnly \
    || fail "library build ($tfm)"
done

if [ "$full" = 1 ]; then
  step "workflow lint (actionlint)"
  if command -v actionlint >/dev/null; then actionlint || fail "actionlint"; else echo "skip: actionlint not installed"; fi
  step "shell lint (shellcheck)"
  if command -v shellcheck >/dev/null; then
    git ls-files -z '*.sh' | xargs -0 shellcheck || fail "shellcheck"
  else echo "skip: shellcheck not installed"; fi
  step "python tool tests"
  for d in tools/agent-tools strip/tool; do
    if compgen -G "$d/test_*.py" >/dev/null; then
      python3 -m unittest discover -s "$d" -p 'test_*.py' -q || fail "$d tests"
    fi
  done
  step "waves orchestration simulation"
  if command -v node >/dev/null; then node .claude/skills/bcstrip-waves/waves_sim.mjs >/dev/null || fail "waves_sim"
  else echo "skip: node not installed"; fi
fi

if [ "$status" = 0 ]; then echo "check.sh: OK"; else echo "check.sh: FAILED"; fi
exit "$status"

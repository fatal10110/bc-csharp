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

step "format (dotnet format whitespace, changed C# vs $base)"
# Only changed files: upstream sources carry whitespace drift we must not reformat (rebase surface).
changed=()  # bash 3.2 (macOS) has no mapfile
while IFS= read -r f; do [ -f "$f" ] && changed+=("$f"); done < <(
  { git diff --name-only --diff-filter=ACMR "$base"...HEAD -- '*.cs' 2>/dev/null
    git diff --name-only --diff-filter=ACMR HEAD -- '*.cs'
    git ls-files --others --exclude-standard -- '*.cs'; } | sort -u)
if [ "${#changed[@]}" -eq 0 ]; then
  echo "no changed C# files"
else
  fmt=(dotnet format whitespace --folder -v q --include "${changed[@]}")
  if [ "$fix" = 1 ]; then "${fmt[@]}" || fail "format"
  else "${fmt[@]}" --verify-no-changes || fail "format (run: tools/ci/check.sh --fix)"; fi
fi

if [ -x strip/strip.sh ]; then
  step "strip (strip/strip.sh --report)"
  strip/strip.sh --report || fail "strip.sh --report"
else
  step "library build (netstandard2.0; strip/strip.sh not present yet)"
  dotnet build crypto/src/BouncyCastle.Crypto.csproj -f netstandard2.0 -c Release -nologo -v q -clp:ErrorsOnly \
    || fail "library build"
fi

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

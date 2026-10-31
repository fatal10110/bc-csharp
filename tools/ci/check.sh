#!/usr/bin/env bash
# Local quality gate for strip-v2. CI runs the same steps (.github/workflows/ci.yml).
#
#   tools/ci/check.sh            fast: whitespace format of changed C#, strip.sh enforce run
#   tools/ci/check.sh --full     also actionlint, shellcheck, turbo NUnit tests, Python tool tests,
#                                waves simulation
#   tools/ci/check.sh --fix      apply whitespace formatting instead of verifying it
#
# Build step: `strip/strip.sh` in enforce mode (#30): deny hits, the budget, unresolved references,
# compile errors of the stripped builds and a failing smoke suite (fast rows) fail the gate. The
# strip is the product; upstream code outside the closure may legitimately stop compiling after
# edge cuts, so the fast gate does not build the whole library. --full does, at net6.0, to run the
# turbo NUnit tests: crypto/src plus crypto/test minus strip/upstream-tests-exclude.txt.
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

step "strip (strip/strip.sh, enforce)"
if [ -x strip/strip.sh ]; then
  strip/strip.sh || fail "strip.sh (enforce)"
else
  fail "strip/strip.sh missing or not executable"
fi

if [ "$full" = 1 ]; then
  step "workflow lint (actionlint)"
  if command -v actionlint >/dev/null; then actionlint || fail "actionlint"; else echo "skip: actionlint not installed"; fi
  step "shell lint (shellcheck)"
  if command -v shellcheck >/dev/null; then
    git ls-files -z '*.sh' | xargs -0 shellcheck || fail "shellcheck"
  else echo "skip: shellcheck not installed"; fi
  step "turbo NUnit tests (Org.BouncyCastle.Turbo.Tests)"
  # Regression tests for the edge cuts and TurboKeyFactory; strip/upstream-tests.txt leaves them out.
  # No bc-test-data needed. Roll-forward: net6.0 test host on the dotnet 8 runtime. The test sources a
  # cut stops compiling (strip/upstream-tests-exclude.txt) are removed as in upstream_tests.py, and zero
  # matching tests is a failure (a renamed namespace must not pass silently).
  if targets=$(python3 strip/tool/upstream_tests.py --write-exclusion-targets strip/work/turbo-nunit); then
    DOTNET_ROLL_FORWARD=Major dotnet test --nologo -v q --framework net6.0 crypto/test/BouncyCastle.Crypto.Tests.csproj \
      "-p:CustomAfterMicrosoftCommonTargets=$targets" --filter "FullyQualifiedName~Org.BouncyCastle.Turbo" \
      -- RunConfiguration.TreatNoTestsAsError=true || fail "turbo NUnit tests"
  else
    fail "turbo NUnit tests (exclusion list)"
  fi
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

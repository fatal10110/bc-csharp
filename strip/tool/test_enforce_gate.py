"""#30: the enforced strip inputs and the local gate. No dotnet, no network."""

import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import deny  # noqa: E402

REPO = os.path.dirname(os.path.dirname(HERE))


class BudgetFileTest(unittest.TestCase):
    def test_budget_is_committed_and_is_first_enforced_count_plus_ten_percent(self):
        cap = deny.load_budget()
        self.assertIsNotNone(cap, "strip/budget.txt missing: enforce mode would run without a cap")
        with open(deny.BUDGET_FILE, encoding="utf-8") as f:
            n = int(re.search(r"kept N = (\d+) files", f.read()).group(1))
        self.assertEqual(cap, -(-n * 11 // 10))  # N + 10%, rounded up


class CheckShTest(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(REPO, "tools", "ci", "check.sh"), encoding="utf-8") as f:
            self.code = [line for line in f.read().splitlines() if not line.lstrip().startswith("#")]

    def test_gate_runs_strip_sh_in_enforce_mode(self):
        calls = [line.strip() for line in self.code if re.match(r"\s*strip/strip\.sh\b", line)]
        self.assertEqual(calls, ['strip/strip.sh || fail "strip.sh (enforce)"'])
        self.assertFalse([line for line in self.code if "--report" in line or "--smoke-slow" in line])

    def test_gate_no_longer_builds_the_whole_library(self):
        self.assertFalse([line for line in self.code if "BouncyCastle.Crypto.csproj" in line])


if __name__ == "__main__":
    unittest.main()

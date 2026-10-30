"""Tests for strip/tool/deny.py and the deny/sweep/budget part of closure.py (issue #8): glob
matching, strip/deny.txt against the plan and the tree, seeds exempt, the referrer sweep on a fixture
tree (complete referrer list, re-pruned stubs) and the budget. A fake builder stands in for dotnet."""

import os
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import closure as c  # noqa: E402
import deny as d  # noqa: E402
from index import build_index  # noqa: E402

REPO = os.path.dirname(os.path.dirname(HERE))
SRC = os.path.join(REPO, "crypto", "src")
PLAN = os.path.join(REPO, "STRIP_PLAN_V2.md")


def cs0246(name):
    return f"The type or namespace name '{name}' could not be found (are you missing a using directive or an assembly reference?)"


class GlobTest(unittest.TestCase):
    def test_brace_expansion(self):
        self.assertEqual(d.expand("a/{B,C}x/{1,2}.cs"), ["a/Bx/1.cs", "a/Bx/2.cs", "a/Cx/1.cs", "a/Cx/2.cs"])
        self.assertEqual(d.expand("plain/*.cs"), ["plain/*.cs"])

    def test_matching_is_anchored_case_insensitive_and_segment_aware(self):
        rules = d.parse_deny("# c\n\nsecurity/{Cipher,Kem}Utilities.cs\n**/*gost*\n**/mlkem/**\ncms/**\nmath/ec/custom/sec/SecT*\n")
        self.assertEqual([g for g, _ in rules][0], "security/{Cipher,Kem}Utilities.cs")
        hits = {
            "security/CipherUtilities.cs": "security/{Cipher,Kem}Utilities.cs",
            "SECURITY/kemutilities.CS": "security/{Cipher,Kem}Utilities.cs",
            "crypto/engines/Gost28147Engine.cs": "**/*gost*",
            "Gost.cs": "**/*gost*",
            "crypto/kems/mlkem/Poly.cs": "**/mlkem/**",
            "mlkem/a/b/C.cs": "**/mlkem/**",
            "cms/CmsUtilities.cs": "cms/**",
            "math/ec/custom/sec/SecT571Field.cs": "math/ec/custom/sec/SecT*",
        }
        for path, glob in hits.items():
            self.assertEqual(d.match(rules, path), glob, path)
        for path in [
            "security/DigestUtilities.cs",
            "x/security/CipherUtilities.cs",  # anchored at crypto/src
            "gost/Plain.cs",  # `**/*gost*` is about the file name
            "crypto/kems/MLKemThing/x.cs",
            "pkcs/cms/X.cs",
            "math/ec/custom/sec/SecP256R1Curve.cs",
        ]:
            self.assertIsNone(d.match(rules, path), path)

    def test_rejects_paths_outside_crypto_src(self):
        for bad in ["/abs/x.cs", "a/../b.cs", "a\\b.cs", "a/{b.cs"]:
            with self.assertRaises(d.DenyError, msg=bad):
                d.parse_deny(bad)

    def test_seeds_are_exempt(self):
        rules = d.parse_deny("**/*gost*\n")
        hits = d.deny_hits(["turbo/GostFree.cs", "crypto/GostX.cs"], rules, exempt={"turbo/GostFree.cs"})
        self.assertEqual(hits, {"crypto/GostX.cs": "**/*gost*"})

    def test_dir_counts(self):
        self.assertEqual(d.dir_counts(["a/x.cs", "a/b/y.cs", "Top.cs"]), {"(root)": 1, "a": 2})

    def test_budget(self):
        self.assertEqual(d.parse_budget("# cap\n842\n"), 842)
        for bad in ["", "1\n2\n", "0", "x"]:
            with self.assertRaises(d.DenyError, msg=bad):
                d.parse_budget(bad)
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(d.load_budget(os.path.join(tmp, "budget.txt")))


class DenyFileTest(unittest.TestCase):
    """strip/deny.txt is the plan §3 list, every glob hits the tree, Ed25519 math stays."""

    def setUp(self):
        self.rules = d.load_deny()
        self.globs = [g for g, _ in self.rules]

    def test_matches_the_plan_list(self):
        with open(PLAN, encoding="utf-8") as f:
            plan = f.read()
        block = plan[plan.index("**`deny.txt`.**") : plan.index("Rev-5 dry run")]
        not_globs = {"deny.txt", "crypto/src", "math/ec/rfc8032/Ed25519.cs", "rfc7748/X25519.cs:306"}
        planned = [g for g in re.findall(r"`([^`]+)`", block) if g not in not_globs]
        self.assertEqual(self.globs, planned)

    def test_every_glob_hits_the_tree_and_ed25519_math_is_kept(self):
        tree = []
        for root, dirs, files in os.walk(SRC):
            dirs[:] = [x for x in dirs if x not in ("bin", "obj")]
            tree += [os.path.relpath(os.path.join(root, f), SRC).replace(os.sep, "/") for f in files if f.endswith(".cs")]
        hit = set(d.deny_hits(tree, self.rules).values())
        self.assertEqual([g for g in self.globs if g not in hit], [])
        for kept in ["math/ec/rfc8032/Ed25519.cs", "math/ec/rfc7748/X25519.cs", "math/ec/rfc7748/X25519Field.cs"]:
            self.assertIn(kept, tree)
            self.assertIsNone(d.match(self.rules, kept), kept)
        for denied in ["crypto/signers/Ed25519Signer.cs", "math/ec/rfc7748/X448Field.cs", "tls/crypto/impl/PqcUtilities.cs"]:
            self.assertIn(denied, tree)
            self.assertIsNotNone(d.match(self.rules, denied), denied)


# Fixture: Root -> api/Api; Api declares fields of MLKem, Tls, GostCipher (declaration-level) and
# news up an Sm2Thing in a method body; tls/Tls news up a GostCipher ([sdk] only); pqc/Kem -> KemImpl.
# The loop adds Tls and GostCipher in the same iteration, so it records only Api as GostCipher's
# referrer, and Api's declaration-level errors hide every body-level one: the sweep must find
# Tls -> GostCipher and Api -> Sm2Thing as well.
FILES = {
    "api/Api.cs": (
        "using Org.T.Pqc;\n"  # 1
        "using Org.T.Tls;\n"  # 2
        "using Org.T.X;\n"  # 3
        "namespace Org.T.Api\n"  # 4
        "{\n"  # 5
        "    public class Api { MLKem k; Tls t; GostCipher g; }\n"  # 6
        "    public class ApiBody { void M() { new Sm2Thing(); } }\n"  # 7
        "}\n"
    ),
    "tls/Tls.cs": "using Org.T.X;\nnamespace Org.T.Tls\n{\n    public class Tls { void M() { new GostCipher(); } }\n}\n",
    "x/GostCipher.cs": "namespace Org.T.X\n{\n    public class GostCipher { }\n}\n",
    "x/Sm2Thing.cs": "namespace Org.T.X\n{\n    public class Sm2Thing { }\n}\n",
    "pqc/Kem.cs": "namespace Org.T.Pqc\n{\n    public class MLKem { KemImpl i; }\n}\n",
    "pqc/KemImpl.cs": "namespace Org.T.Pqc\n{\n    public class KemImpl { }\n}\n",
    "turbo/TurboGostFree.cs": "namespace Org.T.Turbo\n{\n    public class TurboGostFree { }\n}\n",
}
DENY = "pqc/**\n**/*gost*\n**/*sm2*\n"
CANARY_ERROR = "Cannot implicitly convert type 'string' to 'int'"


class SweepBuilder:
    """Errors appear while their condition is unmet: ('file', rel) needs that file compiled;
    ('ns', name) needs `namespace name` in the stub file or a compiled file. `only` limits a rule
    to some define sets. Like csc, a build with declaration-level errors (`decl`) reports only
    those, and the sweep canary's body error only when the build reached method bodies."""

    def __init__(self, src, rules):
        self.src = src
        self.rules = rules  # compiled path (abs) -> [(BuildError, condition, sets or None, decl)]
        self.calls = []

    def build(self, name, files, assert_defines=False):
        self.calls.append((name, list(files), assert_defines))
        compiled = set(files)
        text = ""
        for f in files:
            with open(f) as fh:
                text += fh.read()
        decl, body = set(), set()
        for path, rules in self.rules.items():
            if path not in compiled:
                continue
            for e, (kind, value), only, is_decl in rules:
                if only is not None and name not in only:
                    continue
                met = os.path.join(self.src, value) in compiled if kind == "file" else f"namespace {value}" in text
                if not met:
                    (decl if is_decl else body).add(e)
        if decl:
            return decl
        canary = [f for f in files if f.endswith(c.SWEEP_CANARY_FILE)]
        return body | {c.BuildError(f, 1, 1, "CS0029", CANARY_ERROR) for f in canary}


class SweepTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = self.tmp.name
        self.src = os.path.join(base, "src")
        self.work = os.path.join(base, "work")
        os.makedirs(self.work)
        for rel, text in FILES.items():
            os.makedirs(os.path.dirname(os.path.join(self.src, rel)), exist_ok=True)
            with open(os.path.join(self.src, rel), "w") as f:
                f.write(text)
        self.root = os.path.join(base, "roots", "Root.cs")
        os.makedirs(os.path.dirname(self.root))
        with open(self.root, "w") as f:
            f.write("using Org.T.Api;\nnamespace App\n{\n    class R { Api a; }\n}\n")
        p = lambda rel: os.path.join(self.src, rel)  # noqa: E731
        using = "The type or namespace name 'Pqc' does not exist in the namespace 'Org.T' (are you missing an assembly reference?)"

        def e(path, line, name):
            return c.BuildError(path, line, 5, "CS0246", cs0246(name))

        self.rules = {
            self.root: [(e(self.root, 4, "Api"), ("file", "api/Api.cs"), None, True)],
            p("api/Api.cs"): [
                (c.BuildError(p("api/Api.cs"), 1, 13, "CS0234", using), ("ns", "Org.T.Pqc"), None, True),
                (e(p("api/Api.cs"), 6, "MLKem"), ("file", "pqc/Kem.cs"), None, True),
                (e(p("api/Api.cs"), 6, "Tls"), ("file", "tls/Tls.cs"), None, True),
                (e(p("api/Api.cs"), 6, "GostCipher"), ("file", "x/GostCipher.cs"), None, True),
                (e(p("api/Api.cs"), 7, "Sm2Thing"), ("file", "x/Sm2Thing.cs"), None, False),
            ],
            p("tls/Tls.cs"): [(e(p("tls/Tls.cs"), 4, "GostCipher"), ("file", "x/GostCipher.cs"), {"sdk"}, False)],
            p("pqc/Kem.cs"): [(e(p("pqc/Kem.cs"), 3, "KemImpl"), ("file", "pqc/KemImpl.cs"), None, True)],
        }
        self.index = build_index(self.src)

    def tearDown(self):
        self.tmp.cleanup()

    def run_all(self, deny=DENY):
        builder = SweepBuilder(self.src, self.rules)
        r = c.Resolver(self.index, self.src, repo=self.tmp.name)
        seeds = ["turbo/TurboGostFree.cs"]
        quiet = lambda *_: None  # noqa: E731
        result = c.run_closure(
            self.index, r, builder, ["min", "sdk"], seeds, [self.root], os.path.join(self.work, c.STUBS_FILE), log=quiet
        )
        n = len(builder.calls)
        stub = os.path.join(self.work, c.SWEEP_STUBS_FILE)
        c.run_sweep(self.index, r, builder, result, d.parse_deny(deny), seeds, [self.root], stub, log=quiet)
        return result, builder.calls[n:]

    def test_sweep_lists_every_kept_referrer_per_denied_file(self):
        result, sweep_calls = self.run_all()
        self.assertEqual(result.final_errors, {"min": set(), "sdk": set()})
        self.assertEqual(result.prov["x/GostCipher.cs"], ["api/Api.cs:GostCipher"])  # the loop's first referrer only
        self.assertEqual(
            result.denied,
            {"pqc/Kem.cs": "pqc/**", "pqc/KemImpl.cs": "pqc/**", "x/GostCipher.cs": "**/*gost*", "x/Sm2Thing.cs": "**/*sm2*"},
        )  # the seed turbo/TurboGostFree.cs matches **/*gost* but is exempt
        self.assertEqual(
            result.referrers,
            {
                "pqc/Kem.cs": {"api/Api.cs": {"MLKem": ["min", "sdk"]}},
                "x/GostCipher.cs": {"api/Api.cs": {"GostCipher": ["min", "sdk"]}, "tls/Tls.cs": {"GostCipher": ["sdk"]}},
                "x/Sm2Thing.cs": {"api/Api.cs": {"Sm2Thing": ["min", "sdk"]}},
            },
        )
        self.assertEqual((result.unattributed, result.sweep_incomplete), ({}, []))
        # Remove phase: drop Api (declaration-level referrer), then Root (collateral), reach method
        # bodies (Tls -> GostCipher in [sdk]); restore phase: put back Kem and GostCipher, then
        # KemImpl (Kem needs it), reach method bodies (Api -> Sm2Thing).
        rounds = {"builds": 5, "dropped": ["api/Api.cs", "roots/Root.cs"], "restored": ["pqc/Kem.cs", "pqc/KemImpl.cs", "x/GostCipher.cs"]}
        self.assertEqual(result.sweep_rounds, {"min": rounds, "sdk": rounds})
        self.assertEqual([(s, a) for s, _, a in sweep_calls], [("min", False)] * 5 + [("sdk", False)] * 5)
        # The first build: the closure without the denied files, the stubs re-pruned for the kept
        # files (Org.T.Pqc and Org.T.X are declared only by denied files now) and the canary.
        first = sweep_calls[0][1]
        self.assertEqual({os.path.relpath(f, self.src) for f in first if f.startswith(self.src)}, {"api/Api.cs", "tls/Tls.cs", "turbo/TurboGostFree.cs"})
        self.assertTrue(first[-1].endswith(c.SWEEP_CANARY_FILE) and self.root in first)
        self.assertEqual(result.sweep_stubs, ["Org.T.Pqc", "Org.T.X"])
        lines = [line for check in c.CHECKS for line in check(result)]
        self.assertEqual(
            lines,
            [
                "deny hit: pqc/Kem.cs [pqc/**] <- api/Api.cs (MLKem [min,sdk])",
                "deny hit: pqc/KemImpl.cs [pqc/**] <- denied files only (pqc/Kem.cs:KemImpl)",
                "deny hit: x/GostCipher.cs [**/*gost*] <- api/Api.cs (GostCipher [min,sdk])",
                "deny hit: x/GostCipher.cs [**/*gost*] <- tls/Tls.cs (GostCipher [sdk])",
                "deny hit: x/Sm2Thing.cs [**/*sm2*] <- api/Api.cs (Sm2Thing [min,sdk])",
            ],
        )
        report = result.to_json()
        self.assertEqual((report["kept"], report["kept_dirs"]), (3, {"api": 1, "tls": 1, "turbo": 1}))
        self.assertEqual(report["referrers"], result.referrers)

    def test_a_sweep_that_never_reaches_method_bodies_is_incomplete(self):
        tls = os.path.join(self.src, "tls/Tls.cs")
        old = c.BuildError(tls, 4, 9, "CS0246", cs0246("ValueTask"))  # unresolved before any denial (E13-like)
        self.rules[tls].append((old, ("file", "nowhere.cs"), {"sdk"}, True))
        result, _ = self.run_all()
        self.assertEqual(result.final_errors, {"min": set(), "sdk": {old}})
        self.assertEqual(result.sweep_incomplete, ["sdk"])
        self.assertEqual(result.unattributed, {})  # `old` is reported once, as unresolved
        self.assertNotIn(old, result.sweep_errors["sdk"])
        lines = [line for check in c.CHECKS for line in check(result)]
        self.assertEqual(sum("] unresolved: " in line for line in lines), 1)
        self.assertEqual(lines[-1], c.check_sweep_incomplete(result)[0])
        self.assertTrue(lines[-1].startswith("[sdk] sweep incomplete: declaration-level errors"))

    def test_no_deny_hit_means_no_sweep_and_no_failure(self):
        result, sweep_calls = self.run_all(deny="nothing/**\n")
        self.assertEqual((result.denied, result.swept, sweep_calls), ({}, False, []))
        self.assertEqual([line for check in c.CHECKS for line in check(result)], [])

    def test_unexplained_sweep_errors_and_budget_overrun_fail(self):
        result = c.ClosureResult(["min"], files=["a/A.cs", "b/B.cs", "c/C.cs"], denied={"c/C.cs": "c/**"})
        result.swept, result.referrers = True, {"c/C.cs": {"a/A.cs": {"C": ["min"]}}}
        result.unattributed = {"min": ["/s/b/B.cs(1,1): CS0103 x"]}
        self.assertEqual(c.check_sweep_unattributed(result), ["[min] sweep error no denied file explains: /s/b/B.cs(1,1): CS0103 x"])
        self.assertEqual(c.check_budget(result), [])  # no budget.txt: no cap
        result.budget = 2
        self.assertEqual(c.check_budget(result), [])  # 2 kept files: at the cap
        result.budget = 1
        self.assertEqual(c.check_budget(result), ["budget: 2 kept files > cap 1 (strip/budget.txt)"])

    def test_main_rejects_a_bad_deny_file_before_building(self):
        bad = os.path.join(self.work, "deny.txt")
        with open(bad, "w") as f:
            f.write("/abs/**\n")
        rc = c.main(["--src", self.src, "--work", self.work, "--roots", self.root, "--deny", bad])
        self.assertEqual(rc, 2)
        rc = c.main(["--src", self.src, "--work", self.work, "--roots", self.root, "--deny", bad + ".missing"])
        self.assertEqual(rc, 2)
        self.assertFalse(os.path.exists(os.path.join(self.work, "sets")))


if __name__ == "__main__":
    unittest.main()

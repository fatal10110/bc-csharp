"""Tests for strip/tool/closure.py (issue #7): lookup order, ties, arity, extension index, CS0234
rules, stub emission and pruning, the fixpoint and its fail checks. A fake builder stands in for
dotnet, so nothing here builds, restores or touches the network."""

import os
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import closure as c  # noqa: E402
from index import Index, build_index, scan  # noqa: E402

REPO = os.path.dirname(os.path.dirname(HERE))
SRC = os.path.join(REPO, "crypto", "src")

FILES = {
    "a/Util.cs": "namespace Org.X.A { public class Util { } }",
    "ops/Util.cs": "namespace Org.X.Ops { public class Util { } }",
    "ops2/Util.cs": "namespace Org.X.Ops2 { public class Util { } }",
    "x/Empty.cs": "namespace Org.X { public class Empty { } }",
    "e/Decl.cs": "namespace Org.X.Empty { class Decl { } }",
    "g/Foo.cs": "namespace Org.X.G { class Foo { } }",
    "g/Foo1.cs": "namespace Org.X.G { class Foo<T> { } class Foo<T, U> { } }",
    "n/Outer.cs": "namespace Org.X.N { class Outer { class Inner { } } }",
    "ext/Ext.cs": "namespace Org.X.Ext { static class Ext { public static int Twice(this int x) => x; } }",
    "sub/S.cs": "namespace Org.X.Sub { class S { } }",
    # Referrers (line numbers matter for the lookup levels).
    "b/User.cs": (
        "using Org.X.Empty;\n"  # 1
        "namespace Org.X.A\n"  # 2
        "{\n"  # 3
        "    using Org.X.Ops;\n"  # 4
        "    class User { Util u; }\n"  # 5
        "}\n"
    ),
    "b/Tie.cs": ("namespace Org.Y\n{\n    using Org.X.Ops;\n    using Org.X.Ops2;\n    class Tie { Util u; }\n}\n"),
    "b/Gen.cs": (
        "namespace Org.Y\n{\n    using Org.X.G;\n    using Org.X.Ext;\n    using Org.X.N;\n"
        "    class Gen { Foo<int, string> f; int t = 1.Twice(); }\n}\n"
    ),
}


def err(rel, line, code, msg, col=5):
    return c.BuildError(os.path.join("/src", rel), line, col, code, msg)


def cs0246(name):
    return f"The type or namespace name '{name}' could not be found (are you missing a using directive or an assembly reference?)"


class ResolverTest(unittest.TestCase):
    def setUp(self):
        self.index = Index([scan(text, rel) for rel, text in FILES.items()])
        self.r = c.Resolver(self.index, "/src", repo="/")

    def resolve(self, e, present=(), known_ns=()):
        res, _ = self.r.resolve(e, set(present), set(known_ns))
        return res

    def test_innermost_namespace_beats_its_usings(self):
        res = self.resolve(err("b/User.cs", 5, "CS0246", cs0246("Util")))
        self.assertEqual(res.files, {"a/Util.cs"})
        self.assertFalse(res.tie)

    def test_lookup_continues_outward_when_inner_candidate_is_compiled(self):
        # a/Util.cs is compiled and the error persists: Util is not declared there in this define
        # set, so C# goes on to the namespace's usings.
        res = self.resolve(err("b/User.cs", 5, "CS0246", cs0246("Util")), present={"a/Util.cs"})
        self.assertEqual(res.files, {"ops/Util.cs"})

    def test_same_level_tie_adds_every_candidate(self):
        res = self.resolve(err("b/Tie.cs", 5, "CS0246", cs0246("Util")))
        self.assertEqual(res.files, {"ops/Util.cs", "ops2/Util.cs"})
        self.assertTrue(res.tie)

    def test_cs0234_never_resolves_a_using_line(self):
        msg = "The type or namespace name 'Empty' does not exist in the namespace 'Org.X' (are you missing an assembly reference?)"
        self.assertIsNone(self.resolve(err("b/User.cs", 1, "CS0234", msg)))  # would wrongly pick x/Empty.cs
        self.assertEqual(self.resolve(err("b/User.cs", 5, "CS0234", msg)).files, {"x/Empty.cs"})

    def test_cs0234_namespace_hit_becomes_a_stub(self):
        msg = "The type or namespace name 'Sub' does not exist in the namespace 'Org.X' (are you missing an assembly reference?)"
        res = self.resolve(err("b/User.cs", 5, "CS0234", msg))
        self.assertEqual((res.files, res.namespaces), (set(), {"Org.X.Sub"}))
        self.assertIsNone(self.resolve(err("b/User.cs", 5, "CS0234", msg), known_ns={"Org.X.Sub"}))

    def test_arity_from_message_and_from_source(self):
        res = self.resolve(err("b/Gen.cs", 6, "CS0246", cs0246("Foo<>")))
        self.assertEqual(res.keys, [("Org.X.G", "Foo", 1)])
        res = self.resolve(err("b/Gen.cs", 6, "CS0246", cs0246("Foo")))
        self.assertEqual(res.keys, [("Org.X.G", "Foo", 0)])
        self.assertEqual(c.source_arity("    class Gen { Foo<int, Bar<a, b>> f; }", "Foo", 17), 2)
        self.assertEqual(c.source_arity("    Foo x;", "Foo", 5), 0)

    def test_cs0305_uses_the_written_arity(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "b"))
            with open(os.path.join(tmp, "b", "Gen.cs"), "w") as f:
                f.write(FILES["b/Gen.cs"])
            r = c.Resolver(self.index, tmp, repo="/")
            e = c.BuildError(os.path.join(tmp, "b", "Gen.cs"), 6, 17, "CS0305", "Using the generic type 'Org.X.G.Foo<T>' requires 1 type arguments")
            res, _ = r.resolve(e, {"g/Foo.cs"}, set())
            self.assertEqual(res.keys, [("Org.X.G", "Foo", 2)])

    def test_extension_index_resolves_cs1061_and_cs1501(self):
        msg = "'int' does not contain a definition for 'Twice' and no accessible extension method 'Twice' accepting a first argument of type 'int' could be found (are you missing a using directive or an assembly reference?)"
        self.assertEqual(self.resolve(err("b/Gen.cs", 6, "CS1061", msg)).files, {"ext/Ext.cs"})
        self.assertEqual(self.resolve(err("b/Gen.cs", 6, "CS1501", "No overload for method 'Twice' takes 2 arguments")).files, {"ext/Ext.cs"})
        self.assertIsNone(self.resolve(err("b/User.cs", 5, "CS1061", msg)))  # Org.X.Ext not in scope there

    def test_cs0426_nested_type_maps_to_outer_file(self):
        res = self.resolve(err("b/Gen.cs", 6, "CS0426", "The type name 'Inner' does not exist in the type 'Org.X.N.Outer'"))
        self.assertEqual(res.files, {"n/Outer.cs"})

    def test_unknown_names_and_codes_stay_unresolved(self):
        self.assertIsNone(self.resolve(err("b/User.cs", 5, "CS0246", cs0246("ValueTask"))))
        self.assertIsNone(self.resolve(err("b/User.cs", 5, "CS0115", "'U.Read()': no suitable method found to override")))


@unittest.skipUnless(os.path.isdir(SRC), "crypto/src not present")
class RealTreeTest(unittest.TestCase):
    def test_x509crl_binds_x509utilities_in_its_own_namespace(self):
        # X509Crl.cs is in Org.BouncyCastle.X509 and also `using Org.BouncyCastle.Crypto.Operators;`,
        # which declares another X509Utilities (Asn1Signature.cs). The innermost namespace wins.
        # (X509Certificate.cs lost both after E8, #18.)
        index = build_index(SRC)
        r = c.Resolver(index, SRC, repo=REPO)
        path = os.path.join(SRC, "x509", "X509Crl.cs")
        with open(path, encoding="utf-8-sig") as f:
            lines = f.read().splitlines()
        self.assertIn("using Org.BouncyCastle.Crypto.Operators;", lines)
        uses = [no for no, line in enumerate(lines, 1) if re.search(r"\bX509Utilities\.", line)]
        self.assertTrue(uses)
        for no in uses:
            e = c.BuildError(path, no, 1, "CS0103", "The name 'X509Utilities' does not exist in the current context")
            res, _ = r.resolve(e, set(), set())
            self.assertEqual(res.files, {"x509/X509Utilities.cs"}, no)
            self.assertFalse(res.tie)
        self.assertEqual(index.types[("Org.BouncyCastle.Crypto.Operators", "X509Utilities", 0)], ["crypto/operators/Asn1Signature.cs"])


class StubTest(unittest.TestCase):
    def test_prune_keeps_using_named_undeclared_leaves(self):
        using_ns = {"Org.X", "Org.X.A", "Org.X.Ops", "Org.X.Ops.Deep", "Org.X.Lone"}
        declared = {"Org", "Org.X", "Org.X.A"}
        self.assertEqual(c.prune_stubs(using_ns, declared), ["Org.X.Lone", "Org.X.Ops.Deep"])

    def test_using_namespaces_only_names_crypto_src_namespaces(self):
        index = Index([scan(FILES["a/Util.cs"], "a/Util.cs"), scan(FILES["e/Decl.cs"], "e/Decl.cs")])
        info = scan("using System;\nusing Org.X.Empty;\nusing T = Org.X.A.Util;\nusing N = Org.X.A;\nclass R { }", "r.cs")
        self.assertEqual(c.using_namespaces([info], index), {"Org.X.Empty", "Org.X.A"})

    def test_render(self):
        self.assertTrue(c.render_stubs(["B", "A"]).endswith("namespace A { }\nnamespace B { }\n"))


class FakeBuilder:
    """Errors appear while their condition is unmet: ('file', rel) needs that file compiled,
    ('ns', name) needs `namespace name` in the stub file."""

    def __init__(self, src, rules):
        self.src = src
        self.rules = rules  # compiled path (abs) -> [(BuildError, condition)]
        self.calls = []

    def build(self, name, files, assert_defines=False):
        self.calls.append((name, len(files), assert_defines))
        compiled = set(files)
        stubs = ""
        for f in files:
            if f.endswith(c.STUBS_FILE):
                with open(f) as fh:
                    stubs = fh.read()
        errors = set()
        for path, rules in self.rules.items():
            if path not in compiled:
                continue
            for e, (kind, value) in rules:
                met = os.path.join(self.src, value) in compiled if kind == "file" else f"namespace {value} {{" in stubs
                if not met:
                    errors.add(e)
        return errors


class FixpointTest(unittest.TestCase):
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
            f.write("using Org.X.A;\nnamespace App\n{\n    class R { User u; }\n}\n")
        user = os.path.join(self.src, "b/User.cs")
        using_msg = "The type or namespace name 'Empty' does not exist in the namespace 'Org.X' (are you missing an assembly reference?)"
        self.rules = {
            self.root: [(c.BuildError(self.root, 4, 15, "CS0246", cs0246("User")), ("file", "b/User.cs"))],
            user: [
                (c.BuildError(user, 5, 18, "CS0246", cs0246("Util")), ("file", "a/Util.cs")),
                (c.BuildError(user, 1, 13, "CS0234", using_msg), ("ns", "Org.X.Empty")),
            ],
        }
        self.index = build_index(self.src)

    def tearDown(self):
        self.tmp.cleanup()

    def snapshot(self):
        out = {}
        for d, _, fs in os.walk(self.src):
            for f in fs:
                p = os.path.join(d, f)
                out[p] = os.stat(p).st_mtime_ns
        return out

    def run_closure(self, max_iter=20):
        builder = FakeBuilder(self.src, self.rules)
        r = c.Resolver(self.index, self.src, repo=self.tmp.name)
        stub = os.path.join(self.work, c.STUBS_FILE)
        result = c.run_closure(self.index, r, builder, ["min", "sdk"], [], [self.root], stub, max_iter, log=lambda *_: None)
        return result, builder, stub

    def test_fixpoint_binds_by_lookup_order_and_prunes_stubs(self):
        before = self.snapshot()
        result, builder, stub = self.run_closure()
        self.assertEqual(result.files, ["a/Util.cs", "b/User.cs"])  # not ops/Util.cs, not x/Empty.cs
        self.assertEqual(result.prov["a/Util.cs"], ["b/User.cs:Util"])
        self.assertEqual(result.prov["b/User.cs"], ["roots/Root.cs:User"])
        # Org.X.Empty: named by a kept using, declared by no kept file -> survives.
        # Org.X.Ops: same. Org.X.A: declared by a kept file -> pruned.
        self.assertEqual(result.stubs, ["Org.X.Empty", "Org.X.Ops"])
        with open(stub) as f:
            self.assertEqual(f.read(), c.render_stubs(result.stubs))
        self.assertEqual(result.final_errors, {"min": set(), "sdk": set()})
        self.assertEqual([line for check in c.CHECKS for line in check(result)], [])
        self.assertEqual(self.snapshot(), before)  # nothing written under src
        self.assertFalse(c.is_inside(stub, self.src))

    def test_every_set_builds_every_iteration_with_define_assertion_first_and_last(self):
        result, builder, _ = self.run_closure()
        iterations = len(result.iterations)
        self.assertEqual(len(builder.calls), 2 * (iterations + 1))
        self.assertEqual([call[0] for call in builder.calls[:2]], ["min", "sdk"])
        self.assertEqual([call[2] for call in builder.calls], [True, True] + [False] * (2 * iterations - 2) + [True, True])

    def test_unresolved_errors_fail_at_the_fixpoint(self):
        user = os.path.join(self.src, "b/User.cs")
        self.rules[user].append((c.BuildError(user, 5, 9, "CS0246", cs0246("ValueTask")), ("file", "nowhere.cs")))
        result, _, _ = self.run_closure()
        self.assertFalse(result.stalled)
        failures = [line for check in c.CHECKS for line in check(result)]
        self.assertEqual(len(failures), 2)  # once per define set
        self.assertTrue(all("ValueTask" in line and "unresolved" in line for line in failures))

    def test_stall_is_reported(self):
        result, _, _ = self.run_closure(max_iter=1)
        self.assertTrue(result.stalled)
        self.assertEqual(c.check_stalled(result), ["closure did not reach a fixpoint"])

    def test_pruned_stub_regression_is_reported(self):
        e = c.BuildError("/s/a.cs", 1, 1, "CS0246", cs0246("Gone"))
        result = c.ClosureResult(["min"], loop_errors={"min": set()}, final_errors={"min": {e}})
        self.assertEqual(len(c.check_pruning(result)), 1)
        result.stalled = True  # the last batch was never built in the loop: no comparison
        self.assertEqual(c.check_pruning(result), [])

    def test_main_refuses_a_work_dir_inside_src(self):
        before = self.snapshot()
        rc = c.main(["--src", self.src, "--work", os.path.join(self.src, "w"), "--roots", self.root])
        self.assertEqual(rc, 2)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(os.path.exists(os.path.join(self.src, "w")))


class ParseTest(unittest.TestCase):
    def test_parse_errors(self):
        out = (
            "/s/a.cs(12,34): error CS0246: The type or namespace name 'X' could not be found (are you missing a using directive or an assembly reference?) [/w/Closure.csproj]\n"
            "/s/a.cs(1,1): warning CS0168: unused [/w/Closure.csproj]\n"
        )
        errs = c.parse_errors(out)
        self.assertEqual(len(errs), 1)
        e = next(iter(errs))
        self.assertEqual((e.path, e.line, e.col, e.code), ("/s/a.cs", 12, 34, "CS0246"))
        self.assertTrue(e.msg.endswith("reference?)"))


if __name__ == "__main__":
    unittest.main()

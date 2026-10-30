"""Tests for strip/tool/index.py (issue #7): declarations, nesting, arity, partial units, usings."""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from index import Index, build_index, scan, strip_code  # noqa: E402

SRC = os.path.join(os.path.dirname(os.path.dirname(HERE)), "crypto", "src")

SAMPLE = """
using System;
using Alias = A.Ops.Thing;

namespace A.B
{
    using A.Ops;

    // class NotInComment { }
    /* struct NotInBlock { } */
    public sealed class Outer<TKey, TValue> : Base where TKey : class where TValue : struct
    {
        private string s = "class NotInString { }";
        private string v = @"interface ""NotInVerbatim"" { }";
        private char c = '{';

        internal enum Inner { X }

        public delegate int Callback<T>(T value);

        void M() { Init(this); if (s != null) { } }
    }

    internal static class Ext
    {
        internal static int Twice(this int x) => x * 2;
        internal static T First<T>(this T[] xs) => xs[0];
    }

    namespace C
    {
        partial class P { }
    }
}
"""


class ScanTest(unittest.TestCase):
    def setUp(self):
        self.info = scan(SAMPLE, "a.cs")
        self.keys = {t.key for t in self.info.types}

    def test_types_keyed_by_namespace_name_arity(self):
        self.assertIn(("A.B", "Outer", 2), self.keys)
        self.assertIn(("A.B", "Ext", 0), self.keys)
        self.assertIn(("A.B.C", "P", 0), self.keys)

    def test_nested_types_and_delegates_map_to_outer(self):
        self.assertIn(("A.B", "Outer.Inner", 0), self.keys)
        self.assertIn(("A.B", "Outer.Callback", 1), self.keys)

    def test_comments_strings_and_constraints_declare_nothing(self):
        names = {k[1].rsplit(".", 1)[-1] for k in self.keys}
        for bogus in ("NotInComment", "NotInBlock", "NotInString", "NotInVerbatim", "where", "TValue"):
            self.assertNotIn(bogus, names)

    def test_partial_and_static_flags(self):
        flags = {t.name: (t.partial, t.static) for t in self.info.types}
        self.assertEqual(flags["P"], (True, False))
        self.assertEqual(flags["Ext"], (False, True))
        self.assertEqual(flags["Outer"], (False, False))

    def test_extension_methods_not_this_calls(self):
        self.assertEqual(sorted((e.ns, e.method) for e in self.info.extensions), [("A.B", "First"), ("A.B", "Twice")])

    def test_usings_carry_their_scope(self):
        got = [(u.scope, u.kind, u.target, u.alias) for u in self.info.usings]
        self.assertEqual(
            got,
            [("", "ns", "System", ""), ("", "alias", "A.Ops.Thing", "Alias"), ("A.B", "ns", "A.Ops", "")],
        )

    def test_namespace_ranges_nest(self):
        spans = {d.name: (d.start, d.end) for d in self.info.namespaces}
        self.assertLess(spans["A.B"][0], spans["A.B.C"][0])
        self.assertLess(spans["A.B.C"][1], spans["A.B"][1])

    def test_preprocessor_branches_keep_brace_depth(self):
        text = """
namespace N
{
#if X
    public class T : IA {
#else
    public class T {
#endif
        class Nested { }
    }
    class After { }
}
"""
        keys = {t.key for t in scan(text, "p.cs").types}
        self.assertEqual(keys, {("N", "T", 0), ("N", "T.Nested", 0), ("N", "After", 0)})

    def test_strip_code_keeps_lines(self):
        text = 'a /* x\n y */ b "s\\"t" // c\nd'
        self.assertEqual(strip_code(text).count("\n"), text.count("\n"))


class PartialUnitTest(unittest.TestCase):
    def test_partial_parts_are_one_unit(self):
        index = Index(
            [
                scan("namespace N { public partial class P { } }", "p1.cs"),
                scan("namespace N { partial class P { class Q { } } }", "p2.cs"),
                scan("namespace N { class R { } }", "r.cs"),
            ]
        )
        self.assertEqual(index.partial_unit("p1.cs"), {"p1.cs", "p2.cs"})
        self.assertEqual(index.partial_unit("p2.cs"), {"p1.cs", "p2.cs"})
        self.assertEqual(index.partial_unit("r.cs"), {"r.cs"})
        self.assertEqual(index.types[("N", "P", 0)], ["p1.cs", "p2.cs"])

    @unittest.skipUnless(os.path.isdir(SRC), "crypto/src not present")
    def test_binpoly_partials_in_the_tree(self):
        index = build_index(os.path.join(SRC, "math", "binpoly"))
        base = {
            "BinPolyMulBase.cs",
            "BinPolyMulBase.Binomial.cs",
            "BinPolyMulBase.Trinomial.cs",
            "BinPolyMulBase.Pentanomial.cs",
        }
        self.assertEqual(index.partial_unit("BinPolyMulBase.Trinomial.cs"), base)
        kernels = {"x86/v128/Kernels.Small.cs", "x86/v128/Kernels.Medium.cs"}
        self.assertEqual(index.partial_unit("x86/v128/Kernels.Small.cs"), kernels)
        # Same simple name in another namespace is not part of the unit.
        self.assertEqual(index.partial_unit("scalar/Kernels.cs"), {"scalar/Kernels.cs"})


if __name__ == "__main__":
    unittest.main()

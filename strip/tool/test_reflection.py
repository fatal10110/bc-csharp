"""Tests for strip/tool/reflection.py (#77): the enforce run fails on reflection in the stripped Lib."""

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import reflection  # noqa: E402


def labels(text):
    return [label for _, label, _ in reflection.scan_text(text)]


class ScanTextTest(unittest.TestCase):
    def test_planted_type_get_type_is_a_hit(self):
        src = 'namespace A\n{\n    class C\n    {\n        object T() => Type.GetType("A.Impl");\n    }\n}\n'
        self.assertEqual(reflection.scan_text(src), [(5, "Type lookup by name", "Type.GetType(")])
        self.assertEqual(labels('var t = System.Type.GetType(name, true);'), ["Type lookup by name"])

    def test_every_reflection_form_is_a_hit(self):
        for src in ("using System.Reflection;",
                    "var m = global::System.Reflection.BindingFlags.Public;",
                    "object o = Activator.CreateInstance(t);",
                    'var a = Assembly.Load("x");',
                    "var a = Assembly.GetExecutingAssembly();",
                    "foreach (var a in AppDomain.CurrentDomain.GetAssemblies()) { }",
                    "var g = typeof(List<>).MakeGenericType(t);",
                    "var g = m.MakeGenericMethod(t);",
                    'typeof(X).GetMethod("Foo").Invoke(null, null);',
                    'var p = x.GetType().GetProperty("P");',
                    "var f = typeof(X).GetFields();",
                    "var c = t.GetConstructor(Type.EmptyTypes);",
                    "var i = t.GetTypeInfo();",
                    "var d = Delegate.CreateDelegate(t, m);",
                    "d.DynamicInvoke(1);",
                    "MethodInfo m = null;",
                    "dynamic d = o;",
                    "using System.Linq.Expressions;",
                    'var s = $"{typeof(X).GetMethod("M")}";',
                    'var t = typeof(X).Assembly.GetType("Foo.Bar");',
                    'var t = asm.GetType("Foo.Bar");',
                    'var o = typeof(X).Assembly.CreateInstance("Foo.Bar");',
                    'var o = GetType().Module.GetType("Foo");',
                    "var a = Array.CreateInstance(t, 3);",
                    "var o = RuntimeHelpers.GetUninitializedObject(t);",
                    "var o = FormatterServices.GetUninitializedObject(t);"):
            with self.subTest(src=src):
                self.assertTrue(reflection.scan_text(src), src)

    def test_properties_get_property_is_not_a_hit(self):
        # util/Properties.cs: environment-variable lookups, qualified and unqualified.
        self.assertEqual(labels('string s = Properties.GetProperty("Org.BouncyCastle.X");'), [])
        self.assertEqual(labels("public static string GetProperty(string name) => GetThreadProperty(name);"), [])
        self.assertEqual(labels('bool.TryParse(GetProperty(propertyName), out v);'), [])
        self.assertEqual(labels('var s = TurboHTTP.SecureProtocol.Org.BouncyCastle.Utilities.Properties.GetProperty("x");'),
                         [])
        # Only that receiver is allowed.
        self.assertEqual(labels('var p = props.GetProperty("x");'), ["member lookup"])

    def test_get_type_for_messages_and_identity_is_not_a_hit(self):
        for src in ('throw new ArgumentException("unrecognized TlsSecret: " + secret.GetType().FullName);',
                    "return GetTypeName(obj?.GetType());",
                    "if (e.GetType() == typeof(ArgumentException)) { }",
                    "return t?.FullName ?? \"null\";",
                    'throw new InvalidOperationException($"bad {GetType().Name}");'):
            with self.subTest(src=src):
                self.assertEqual(labels(src), [])

    def test_comments_and_literals_are_not_hits(self):
        src = ("// Type.GetType(\"x\") and System.Reflection in a comment\n"
               "/* Activator.CreateInstance(t); MethodInfo */\n"
               "/// <see cref=\"System.Reflection.Assembly\"/>\n"
               "string a = \"Type.GetType(\\\"x\\\") Activator\";\n"
               "string b = @\"verbatim \"\"Assembly.Load(x)\"\" dynamic\";\n"
               "string c = $\"{{Type.GetType(x)}} {n}\";\n"
               "char q = '\"'; string d = \"MakeGenericType\";\n")
        self.assertEqual(reflection.scan_text(src), [])

    def test_code_after_literals_is_still_scanned(self):
        src = "string a = \"x\\\"\"; char q = '\\''; string b = @\"\"\"\"; var t = Type.GetType(a);\n"
        self.assertEqual(labels(src), ["Type lookup by name"])
        self.assertEqual(reflection.scan_text("/* a */\nstring s = $@\"{x}\n\";\nActivator.CreateInstance(t);"),
                         [(4, "Activator", "Activator")])

    def test_blank_code_keeps_length_and_lines(self):
        src = "a /* x\ny */ \"s\\n\" 'c' // z\nb $\"{c} {{d}}\" @\"e\r\nf\"\n"
        out = reflection.blank_code(src)
        self.assertEqual(len(out), len(src))
        self.assertEqual(out.count("\n"), src.count("\n"))
        # Comment text, string and char bodies and {{d}} are blanked; the hole {c}, quotes and \r\n stay.
        self.assertEqual(out, 'a     \n     "   " \' \'     \nb $"{c}      " @" \r\n "\n')

    def test_identifiers_containing_symbol_names_are_not_hits(self):
        for src in ("var dynamicKey = 1;", "class TlsTypeInfoX { }", "int ActivatorCount;",
                    "var x = CertificateType.GetTypes;", "MyAssembly.LoadData();"):
            with self.subTest(src=src):
                self.assertEqual(labels(src), [])


class MainTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.lib = Path(self.tmp.name) / "lib"
        (self.lib / "util").mkdir(parents=True)
        (self.lib / "util" / "Properties.cs").write_text(
            "﻿namespace TurboHTTP.SecureProtocol.Org.BouncyCastle.Utilities\n{\n"
            "    public static class Properties\n    {\n"
            "        public static string GetProperty(string name) => Platform.GetEnvironmentVariable(name);\n"
            "    }\n}\n", encoding="utf-8")
        (self.lib / "Msg.cs").write_text('class M { string S(object o) => "x: " + o.GetType().FullName; }\n')

    def run_main(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = reflection.main(list(args))
        return rc, out.getvalue(), err.getvalue()

    def test_clean_lib_passes(self):
        rc, out, _ = self.run_main("--lib", str(self.lib))
        self.assertEqual(rc, 0)
        self.assertIn("reflection scan: 2 files, 0 hit(s)", out)

    def test_planted_type_get_type_fails(self):
        (self.lib / "tls" / "Planted.cs").parent.mkdir()
        (self.lib / "tls" / "Planted.cs").write_text('class P\n{\n    object T() => Type.GetType("X");\n}\n')
        rc, out, _ = self.run_main("--lib", str(self.lib))
        self.assertEqual(rc, 1)
        self.assertIn("FAIL reflection: tls/Planted.cs:3: Type lookup by name: Type.GetType(", out)
        self.assertIn("1 hit(s)", out)

    def test_missing_lib_is_usage_error(self):
        rc, _, err = self.run_main("--lib", str(self.lib / "nope"))
        self.assertEqual(rc, 2)
        self.assertIn("not a directory", err)


if __name__ == "__main__":
    unittest.main()

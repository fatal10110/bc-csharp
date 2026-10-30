"""Tests for strip/tool/defines.py and strip/Closure.csproj (issue #6). No dotnet, no network."""

import os
import sys
import unittest
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import defines as d  # noqa: E402

STRIP = os.path.dirname(HERE)

# Shape of the Csc command line MSBuild logs (binlog replayed at normal verbosity).
CSC = (
    '/home/u/.dotnet/dotnet exec "/home/u/.dotnet/sdk/8.0.427/Roslyn/bincore/csc.dll" /noconfig /unsafe- '
    "/checked- /nowarn:1701,1702,CS1591 /fullpaths /nostdlib+ /errorreport:prompt /warn:7 "
    "/define:{defines} /highentropyva+ /reference:/x/netstandard.dll /debug- /optimize+ /out:obj/x.dll"
)


class UnityDefinesTest(unittest.TestCase):
    def test_provisional_file_has_the_three_plan_sets(self):
        sets = d.load_unity_defines(os.path.join(STRIP, "unity-defines.txt"))
        self.assertEqual(list(sets), ["min", "partial", "sdk"])
        self.assertEqual(sets["min"], ["NETSTANDARD", "NETSTANDARD2_1"])
        self.assertEqual(sets["partial"], sets["min"] + ["NETSTANDARD2_1_OR_GREATER"])
        self.assertTrue(set(sets["partial"]) < set(sets["sdk"]))
        self.assertIn("NETSTANDARD1_0_OR_GREATER", sets["sdk"])
        for name, symbols in sets.items():
            self.assertFalse(set(symbols) & set(d.LEAK_SUSPECTS), name)

    def test_real_sections_need_no_code_change(self):
        sets = d.parse_unity_defines("# from #141\n[netstandard21]\nNETSTANDARD;NETSTANDARD2_1;UNITY_2021_3\n\n[netframework]\nNET_4_6;NET471\n")
        self.assertEqual(sets["netstandard21"], ["NETSTANDARD", "NETSTANDARD2_1", "UNITY_2021_3"])
        self.assertEqual(d.tfm_for_set("netstandard21"), "netstandard2.1")
        self.assertEqual(d.tfm_for_set("netframework"), "net471")
        self.assertEqual(d.tfm_for_set("min"), "netstandard2.1")

    def test_empty_entries_are_ignored(self):
        self.assertEqual(d.parse_unity_defines("[a]\n;A;;B;\n")["a"], ["A", "B"])

    def test_malformed_files_are_rejected(self):
        for text in (
            "A;B\n",  # outside a section
            "[a]\nA\n[a]\nB\n",  # duplicate set
            "[a]\nA\nB\n",  # two DefineConstants lines
            "[a]\n",  # no line
            "[a]\nA;1B\n",  # invalid symbol
            "[a]\nA;A\n",  # duplicate symbol
            "",  # no sets
        ):
            with self.assertRaises(d.DefineError, msg=repr(text)):
                d.parse_unity_defines(text)


class PropsTest(unittest.TestCase):
    def test_props_assign_exact_defines_and_items(self):
        props = d.render_props("netstandard2.1", ["NETSTANDARD", "NETSTANDARD2_1"], ["/s/a.cs", "/s/b&c.cs"])
        root = ET.fromstring(props)
        self.assertEqual(root.findtext("PropertyGroup/DefineConstants"), "NETSTANDARD;NETSTANDARD2_1")
        self.assertEqual(root.findtext("PropertyGroup/TargetFramework"), "netstandard2.1")
        self.assertNotIn("$(DefineConstants)", props)  # assigned, not appended: replaces the SDK's TRACE
        self.assertEqual([c.get("Include") for c in root.iter("Compile")], ["/s/a.cs", "/s/b&c.cs"])

    def test_props_escape_msbuild_specials(self):
        props = d.render_props("net471", [], ["/s/x;y%.cs"])
        self.assertIn('Include="/s/x%3By%25.cs"', props)
        self.assertIn("<DefineConstants></DefineConstants>", props)


class DefineAssertionTest(unittest.TestCase):
    def test_csc_defines_parsed_ignoring_empty_entries(self):
        log = "Task Csc\n  " + CSC.format(defines="NETSTANDARD;;NETSTANDARD2_1;") + "\n"
        self.assertEqual(d.csc_defines(log), {"NETSTANDARD", "NETSTANDARD2_1"})

    def test_csc_defines_quoted_and_repeated_switches(self):
        log = CSC.format(defines='"A;B"') + " /define:C\n"
        self.assertEqual(d.csc_defines(log), {"A", "B", "C"})

    def test_no_csc_line_is_an_error_not_a_pass(self):
        with self.assertRaises(d.DefineError):
            d.csc_defines("Skipping target CoreCompile because all output files are up-to-date\n")

    def test_csc_line_without_defines_is_the_empty_set(self):
        self.assertEqual(d.csc_defines(CSC.replace(" /define:{defines}", "")), set())

    def test_exact_match_passes(self):
        actual = d.csc_defines(CSC.format(defines="NETSTANDARD2_1;NETSTANDARD"))
        self.assertEqual(d.check_defines("min", ["NETSTANDARD", "NETSTANDARD2_1", ""], actual), [])

    def test_leakage_fails(self):
        actual = d.csc_defines(CSC.format(defines="TRACE;RELEASE;NETSTANDARD;NETSTANDARD2_1"))
        problems = d.check_defines("min", ["NETSTANDARD", "NETSTANDARD2_1"], actual)
        self.assertEqual(len(problems), 1)
        self.assertIn("leakage: ['RELEASE', 'TRACE']", problems[0])

    def test_implicit_framework_defines_fail(self):
        actual = d.csc_defines(CSC.format(defines="NETSTANDARD;NETSTANDARD2_1;NETSTANDARD2_0_OR_GREATER"))
        problems = d.check_defines("partial", ["NETSTANDARD", "NETSTANDARD2_1", "NETSTANDARD2_1_OR_GREATER"], actual)
        self.assertEqual(len(problems), 2)  # one extra, one missing


class ClosureCsprojTest(unittest.TestCase):
    def setUp(self):
        self.root = ET.parse(os.path.join(STRIP, "Closure.csproj")).getroot()
        self.props = {}
        for group in self.root.iter("PropertyGroup"):
            for p in group:
                self.props[p.tag] = (p.text or "").strip()

    def test_plan_properties(self):
        expected = {
            "EnableDefaultCompileItems": "false",
            "LangVersion": "9",
            "AllowUnsafeBlocks": "false",
            "DisableImplicitFrameworkDefines": "true",
            "DisableImplicitConfigurationDefines": "true",
            "ImportDirectoryBuildProps": "false",
            "ImportDirectoryBuildTargets": "false",
        }
        for key, value in expected.items():
            self.assertEqual(self.props.get(key), value, key)
        # Single TFM per run: the generated props set TargetFramework; never multi-targeting here.
        self.assertNotIn("TargetFrameworks", self.props)
        self.assertNotIn("TargetFramework", self.props)
        self.assertNotIn("DefineConstants", self.props)

    def test_generated_props_imported_after_sdk_props(self):
        imports = [i.get("Project") for i in self.root.iter("Import")]
        self.assertEqual(imports, ["Sdk.props", "$(MSBuildThisFileDirectory)Closure.props", "Sdk.targets"])

    def test_net471_reference_assemblies(self):
        refs = [
            (r.get("Include"), r.getparent() if hasattr(r, "getparent") else None)
            for r in self.root.iter("PackageReference")
        ]
        self.assertEqual([r[0] for r in refs], ["Microsoft.NETFramework.ReferenceAssemblies"])
        groups = [g for g in self.root.iter("ItemGroup") if g.find("PackageReference") is not None]
        self.assertEqual(groups[0].get("Condition"), "'$(TargetFramework)' == 'net471'")


if __name__ == "__main__":
    unittest.main()

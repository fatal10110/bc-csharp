import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("rewrite.py")
REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "crypto" / "src"
PREFIX = b"TurboHTTP.SecureProtocol."
UNPREFIXED = re.compile(rb"(?<!TurboHTTP\.SecureProtocol\.)\bOrg\.BouncyCastle\b")

SAMPLE_LIB = """﻿using System;

namespace Org.BouncyCastle.Sample
{
    /// <summary>See <see cref="Org.BouncyCastle.Sample.Keys.Strict"/>.</summary>
    public static class Keys
    {
        public const string Strict = "Org.BouncyCastle.Pkcs1.Strict";
        public const string NotAToken = "Org.BouncyCastleFoo MyOrg.BouncyCastle";
    }
}
"""
SAMPLE_USER = """using System;
using Keys = Org.BouncyCastle.Sample.Keys;

namespace Org.BouncyCastle.Sample.Use
{
    public static class User
    {
        public static string Get() => Keys.Strict + global::Org.BouncyCastle.Sample.Keys.NotAToken;
    }
}
"""
# Not rewritten: proves the rewritten tree really lives in the TurboHTTP namespace.
SAMPLE_CONSUMER = """namespace Consumer
{
    public static class C
    {
        public static string S => TurboHTTP.SecureProtocol.Org.BouncyCastle.Sample.Use.User.Get();
    }
}
"""


def find_dotnet():
    found = shutil.which("dotnet")
    if found:
        return found
    for root in (os.environ.get("DOTNET_ROOT"), str(Path.home() / ".dotnet")):
        if root and (Path(root) / "dotnet").is_file():
            return str(Path(root) / "dotnet")
    return None


class RewriteTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tempdir.name)
        self.src = self.tmp / "src"
        (self.src / "a").mkdir(parents=True)
        (self.src / "a" / "Lib.cs").write_bytes(SAMPLE_LIB.encode("utf-8"))
        (self.src / "User.cs").write_bytes(SAMPLE_USER.replace("\n", "\r\n").encode("utf-8"))
        self.list = self.tmp / "files.txt"
        self.list.write_text("# sample\n\na/Lib.cs\nUser.cs\na/Lib.cs\n", encoding="utf-8")

    def tearDown(self):
        self.tempdir.cleanup()

    def run_tool(self, src, files, out):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--src", str(src), "--files", str(files), "--out", str(out)],
            capture_output=True,
            text=True,
        )

    def tree(self, root):
        return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}

    def test_rewrites_every_token_and_keeps_other_bytes(self):
        out = self.tmp / "out"
        r = self.run_tool(self.src, self.list, out)
        self.assertEqual(r.returncode, 0, r.stderr)
        got = self.tree(out)
        self.assertEqual(sorted(got), ["User.cs", "a/Lib.cs"])
        lib = got["a/Lib.cs"]
        self.assertTrue(lib.startswith(b"\xef\xbb\xbf"), "BOM kept")
        self.assertIn(b"namespace TurboHTTP.SecureProtocol.Org.BouncyCastle.Sample\n", lib)
        self.assertIn(b'cref="TurboHTTP.SecureProtocol.Org.BouncyCastle.Sample.Keys.Strict"', lib)
        self.assertIn(b'"TurboHTTP.SecureProtocol.Org.BouncyCastle.Pkcs1.Strict"', lib)
        self.assertIn(b'"Org.BouncyCastleFoo MyOrg.BouncyCastle"', lib, "partial tokens untouched")
        user = got["User.cs"]
        self.assertIn(b"using Keys = TurboHTTP.SecureProtocol.Org.BouncyCastle.Sample.Keys;\r\n", user)
        self.assertIn(b"global::TurboHTTP.SecureProtocol.Org.BouncyCastle.Sample.Keys.NotAToken", user)
        for name, data in got.items():
            self.assertEqual(UNPREFIXED.findall(data), [], name)
            original = (self.src / name).read_bytes()
            self.assertEqual(data.replace(PREFIX + b"Org.BouncyCastle", b"Org.BouncyCastle"), original, name)

    def test_two_runs_are_identical_and_a_second_pass_is_a_no_op(self):
        out1, out2, out3 = self.tmp / "o1", self.tmp / "o2", self.tmp / "o3"
        for out in (out1, out2):
            self.assertEqual(self.run_tool(self.src, self.list, out).returncode, 0)
        self.assertEqual(self.tree(out1), self.tree(out2))
        r = self.run_tool(out1, self.list, out3)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.tree(out3), self.tree(out1), "no double prefix")

    def test_real_tree_files_are_byte_exact_apart_from_the_token(self):
        rels = [
            "asn1/x509/GeneralName.cs",  # alias: using NetUtils = Org.BouncyCastle.Utilities.Net;
            "crypto/digests/Blake2bDigest.cs",  # UTF-8 BOM
            "crypto/encodings/Pkcs1Encoding.cs",  # string-literal property key
            "crypto/digests/SkeinEngine.cs",  # crefs
        ]
        files = self.tmp / "real.txt"
        files.write_text("\n".join(rels) + "\n", encoding="utf-8")
        out = self.tmp / "real"
        r = self.run_tool(SRC, files, out)
        self.assertEqual(r.returncode, 0, r.stderr)
        for rel in rels:
            original = (SRC / rel).read_bytes()
            data = (out / rel).read_bytes()
            self.assertEqual(UNPREFIXED.findall(data), [], rel)
            self.assertEqual(data.count(PREFIX), len(UNPREFIXED.findall(original)), rel)
            self.assertEqual(data.replace(PREFIX + b"Org.BouncyCastle", b"Org.BouncyCastle"), original, rel)
        self.assertIn(
            b"using NetUtils = TurboHTTP.SecureProtocol.Org.BouncyCastle.Utilities.Net;",
            (out / rels[0]).read_bytes(),
        )
        self.assertTrue((out / rels[1]).read_bytes().startswith(b"\xef\xbb\xbf"))
        self.assertIn(b'"TurboHTTP.SecureProtocol.Org.BouncyCastle.Pkcs1.Strict"', (out / rels[2]).read_bytes())

    def test_rejects_bad_inputs(self):
        out = self.tmp / "out"
        out.mkdir()
        (out / "stale.cs").write_text("x", encoding="utf-8")
        self.assertNotEqual(self.run_tool(self.src, self.list, out).returncode, 0, "non-empty output")
        for entry in ("../escape.cs", "/abs.cs", "a\\Lib.cs", "./a/Lib.cs", "missing.cs"):
            bad = self.tmp / "bad.txt"
            bad.write_text(entry + "\n", encoding="utf-8")
            r = self.run_tool(self.src, bad, self.tmp / "fresh")
            self.assertNotEqual(r.returncode, 0, entry)
            self.assertIn("rewrite: error:", r.stderr)
        self.assertFalse((self.tmp / "escape.cs").exists())

    def test_rewritten_sample_compiles(self):
        dotnet = find_dotnet()
        if dotnet is None:
            self.skipTest("dotnet SDK not found (PATH, DOTNET_ROOT or ~/.dotnet)")
        proj = self.tmp / "proj"
        self.assertEqual(self.run_tool(self.src, self.list, proj / "rewritten").returncode, 0)
        (proj / "Consumer.cs").write_text(SAMPLE_CONSUMER, encoding="utf-8")
        major = subprocess.run([dotnet, "--version"], capture_output=True, text=True).stdout.split(".")[0]
        (proj / "Sample.csproj").write_text(
            "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup>"
            f"<TargetFramework>net{major}.0</TargetFramework><LangVersion>9</LangVersion>"
            "<TreatWarningsAsErrors>true</TreatWarningsAsErrors><NoWarn>CS1591</NoWarn>"
            "<GenerateDocumentationFile>true</GenerateDocumentationFile>"
            "</PropertyGroup></Project>\n",
            encoding="utf-8",
        )
        env = dict(os.environ, DOTNET_CLI_TELEMETRY_OPTOUT="1", DOTNET_NOLOGO="1")
        env["PATH"] = str(Path(dotnet).parent) + os.pathsep + env.get("PATH", "")
        r = subprocess.run(
            [dotnet, "build", str(proj / "Sample.csproj"), "-nologo", "-v:q", "-m:1", "--disable-build-servers"],
            capture_output=True,
            text=True,
            env=env,
            cwd=str(proj),
        )
        self.assertEqual(r.returncode, 0, r.stdout[-3000:] + r.stderr[-2000:])


if __name__ == "__main__":
    unittest.main()

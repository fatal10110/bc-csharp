import hashlib
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("package.py")
SHADOW = (
    "crypto/src/security/PublicKeyFactory.cs",
    "crypto/src/x509/X509SignatureUtil.cs",
    "crypto/src/security/MacUtilities.cs",
    "crypto/src/crypto/modes/GCMBlockCipher.cs",
)
LICENSE = b"The MIT License (MIT)\n\nCopyright (c) 2000-2026 The Legion of the Bouncy Castle Inc.\n"
BLAKE_HEADER = """﻿namespace TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Digests
{
    // License from the original code created by Clinton Ingram (saucecontrol) for Blake2Fast

    // The MIT License

    // Copyright(c) 2018-2021 Clinton Ingram

    // Permission is hereby granted, free of charge, to any person obtaining a copy
    // of this software.
    internal static class Blake2b_X86
    {
    }
}
"""
BC_HEADER = """// Copyright (c) The Legion of the Bouncy Castle Inc.
// Permission is hereby granted, free of charge, to any person obtaining a copy
namespace TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls
{
    public class Tls
    {
        // turbo-strip: E3 offer only the AEAD suites
        int x;
    }
}
"""
EMPTY_CS = "namespace TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.X509 { }\n"


def git(repo, *args):
    cmd = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    cmd += ["-c", "commit.gpgsign=false", *args]
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout.strip()


class PackageTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tempdir.name)
        self.lib = self.tmp / "rewritten"
        for rel, text in {
            "asn1/x509/GeneralName.cs": EMPTY_CS,
            "crypto/digests/Blake2b_X86.cs": BLAKE_HEADER,
            "tls/Tls.cs": BC_HEADER,
            "Root.cs": EMPTY_CS,
        }.items():
            (self.lib / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.lib / rel).write_bytes(text.encode("utf-8"))
        self.license = self.tmp / "LICENSE.md"
        self.license.write_bytes(LICENSE)
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        for rel in SHADOW:
            (self.repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / rel).write_text("class A {}\n", encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "base")
        self.base = git(self.repo, "rev-parse", "HEAD")
        (self.repo / SHADOW[3]).write_text("class A { ``` }\n", encoding="utf-8")
        git(self.repo, "commit", "-q", "-am", "bump")
        self.new = git(self.repo, "rev-parse", "HEAD")
        self.roots = "e172f90"

    def tearDown(self):
        self.tempdir.cleanup()

    def run_tool(self, out, *extra, lib=None, base=None):
        cmd = [sys.executable, str(SCRIPT), "--lib", str(lib or self.lib), "--out", str(out)]
        cmd += ["--base", base or self.base, "--roots-sha", self.roots]
        cmd += ["--license", str(self.license), "--repo", str(self.repo), *extra]
        return subprocess.run(cmd, capture_output=True, text=True)

    def tree(self, root):
        return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}

    def test_two_runs_are_byte_identical(self):
        out1, out2 = self.tmp / "o1", self.tmp / "o2"
        self.assertEqual(self.run_tool(out1).returncode, 0)
        self.assertEqual(self.run_tool(out2).returncode, 0)
        self.assertEqual(self.tree(out1), self.tree(out2))
        r = self.run_tool(out1)  # rerun over an existing package replaces Lib/
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.tree(out1), self.tree(out2))

    def test_lib_layout_and_metas(self):
        out = self.tmp / "out"
        r = self.run_tool(out)
        self.assertEqual(r.returncode, 0, r.stderr)
        lib = out / "Lib"
        self.assertEqual((lib / "LICENSE.md").read_bytes(), LICENSE)
        self.assertEqual(
            (lib / "crypto/digests/Blake2b_X86.cs").read_bytes(),
            (self.lib / "crypto/digests/Blake2b_X86.cs").read_bytes(),
        )
        self.assertFalse((out / "Lib.meta").exists(), "Lib.meta belongs to turboHTTP")
        entries = sorted(p.relative_to(lib).as_posix() for p in lib.rglob("*") if not p.name.endswith(".meta"))
        metas = sorted(p.relative_to(lib).as_posix()[:-5] for p in lib.rglob("*.meta"))
        self.assertEqual(metas, entries, "one .meta per file and folder, no orphans")
        importer = {
            "asn1": "folderAsset: yes\nDefaultImporter:",
            "asn1/x509": "folderAsset: yes\nDefaultImporter:",
            "asn1/x509/GeneralName.cs": "MonoImporter:",
            "Root.cs": "MonoImporter:",
            "LICENSE.md": "TextScriptImporter:",
        }
        for rel, kind in importer.items():
            meta = (lib / (rel + ".meta")).read_text(encoding="utf-8")
            guid = hashlib.md5(("turbohttp-bc:" + rel).encode("utf-8")).hexdigest()
            self.assertTrue(meta.startswith(f"fileFormatVersion: 2\nguid: {guid}\n{kind}\n"), rel)
            self.assertTrue(meta.endswith("  userData: \n  assetBundleName: \n  assetBundleVariant: \n"), rel)
        self.assertIn("  icon: {instanceID: 0}\n", (lib / "Root.cs.meta").read_text(encoding="utf-8"))

    def test_notices_list_non_bc_headers_only(self):
        out = self.tmp / "out"
        self.assertEqual(self.run_tool(out).returncode, 0)
        notices = (out / "THIRD-PARTY-NOTICES.txt").read_text(encoding="utf-8")
        self.assertIn(LICENSE.decode().strip(), notices)
        self.assertIn("--- Lib/crypto/digests/Blake2b_X86.cs (lines 3-10) ---", notices)
        self.assertIn("// Copyright(c) 2018-2021 Clinton Ingram", notices)
        self.assertNotIn("tls/Tls.cs", notices, "the BC header is not a third-party notice")
        (self.lib / "crypto/digests/Blake2b_X86.cs").unlink()
        self.assertEqual(self.run_tool(out).returncode, 0)
        notices = (out / "THIRD-PARTY-NOTICES.txt").read_text(encoding="utf-8")
        self.assertIn("None found.", notices)
        self.assertNotIn("Clinton Ingram", notices)

    def test_strip_info(self):
        out = self.tmp / "out"
        self.assertEqual(self.run_tool(out).returncode, 0)
        info = (out / "STRIP_INFO.md").read_text(encoding="utf-8")
        self.assertIn(f"- BASE: `{self.base}`", info)
        self.assertIn("- ROOTS_SHA: `e172f90`", info)
        self.assertIn("- `tls/Tls.cs:7` E3 offer only the AEAD suites", info)
        for row in ("| `(root)` | 1 |", "| `asn1` | 1 |", "| `crypto` | 1 |", "| `tls` | 1 |", "| total | 4 |"):
            self.assertIn(row, info)
        self.assertIn("## Smoke results\n\nNot run.", info)
        self.assertIn("No bump (OLDBASE = BASE): empty.", info)
        self.assertNotIn(str(self.tmp), info, "no absolute paths")

        smoke = self.tmp / "smoke.txt"
        smoke.write_text("curve lookup ns21: pass\n", encoding="utf-8")
        r = self.run_tool(out, "--old-base", self.base, "--smoke", str(smoke), base=self.new)
        self.assertEqual(r.returncode, 0, r.stderr)
        info = (out / "STRIP_INFO.md").read_text(encoding="utf-8")
        self.assertIn("```\ncurve lookup ns21: pass\n```", info)
        self.assertIn(f"`{self.base}..{self.new}`:", info)
        self.assertIn("````diff\ndiff --git a/crypto/src/crypto/modes/GCMBlockCipher.cs", info)
        self.assertIn("+class A { ``` }\n````", info, "fence longer than any backtick run")
        self.assertNotIn("PublicKeyFactory.cs b/", info)

    def test_shadow_paths_checked_against_git_ls_files(self):
        git(self.repo, "mv", SHADOW[0], SHADOW[0].replace("PublicKeyFactory", "publicKeyFactory"))
        git(self.repo, "commit", "-q", "-m", "case")
        r = self.run_tool(self.tmp / "out")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("crypto/src/security/PublicKeyFactory.cs", r.stderr)

    def test_rejects_bad_inputs(self):
        (self.lib / "tls/Leftover.cs").write_text("using Org.BouncyCastle.Tls;\n", encoding="utf-8")
        r = self.run_tool(self.tmp / "o1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("tls/Leftover.cs", r.stderr)
        self.assertFalse((self.tmp / "o1" / "Lib").exists())
        (self.lib / "tls/Leftover.cs").unlink()

        (self.lib / "notes.txt").write_text("x", encoding="utf-8")
        self.assertNotEqual(self.run_tool(self.tmp / "o2").returncode, 0, "only .cs is packaged")
        (self.lib / "notes.txt").unlink()

        self.assertNotEqual(self.run_tool(self.tmp / "o3", base="not-a-sha").returncode, 0)
        self.assertNotEqual(self.run_tool(self.lib.parent, lib=self.tmp / "Lib").returncode, 0, "overlap")

    def test_packages_real_tree_sample_with_no_token_left(self):
        repo = Path(__file__).resolve().parents[2]
        sys.path.insert(0, str(SCRIPT.parent))
        from rewrite import rewrite_tree

        rewritten = self.tmp / "real"
        rewrite_tree(repo / "crypto/src", ["asn1/x509/GeneralName.cs", "crypto/digests/Blake2b_X86.cs"], rewritten)
        out = self.tmp / "out"
        r = self.run_tool(out, lib=rewritten)
        self.assertEqual(r.returncode, 0, r.stderr)
        for rel, data in self.tree(out / "Lib").items():
            self.assertIsNone(re.search(rb"(?<!SecureProtocol\.)\bOrg\.BouncyCastle\b", data), rel)
        notices = (out / "THIRD-PARTY-NOTICES.txt").read_text(encoding="utf-8")
        self.assertIn("Lib/crypto/digests/Blake2b_X86.cs", notices)
        self.assertIn("THE SOFTWARE IS PROVIDED", notices)


if __name__ == "__main__":
    unittest.main()

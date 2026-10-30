import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("refresh_roots.py")
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SCRIPT.parent))

import refresh_roots  # noqa: E402
import rewrite  # noqa: E402

CONSUMER_DIR = "Runtime/Transport/BouncyCastle"
NAMES = ("BouncyCastleTlsProvider.cs", "TurboTlsClient.cs", "TurboTlsAuthentication.cs")
SHA40 = re.compile(r"^[0-9a-f]{40}\n$")

# Consumer form, as turboHTTP vendors it: every BC token prefixed, TurboHTTP's own namespaces not.
PROVIDER = b"""using System;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Security;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls;
using TurboHTTP.Transport.Tls;

namespace TurboHTTP.Transport.BouncyCastle
{
    /// <see cref="TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls.TlsClientProtocol"/>
    internal sealed class BouncyCastleTlsProvider : ITlsProvider
    {
        private const string Name = "TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls";
    }
}
"""
# CRLF and a BOM: bytes outside the tokens must survive unchanged.
CLIENT = (b"\xef\xbb\xbf\r\n\r\nusing TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls;\r\n"
          b"namespace TurboHTTP.Transport.BouncyCastle { }\r\n")
AUTH = b"""using TurboHTTP.SecureProtocol.Org.BouncyCastle.X509;
namespace TurboHTTP.Transport.BouncyCastle { }
"""
CONSUMERS = {"BouncyCastleTlsProvider.cs": PROVIDER, "TurboTlsClient.cs": CLIENT,
             "TurboTlsAuthentication.cs": AUTH}


def git(repo, *args):
    cmd = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
           "-c", "commit.gpgsign=false", *args]
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout.strip()


def run(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)], capture_output=True, text=True)


class ReverseRewriteTest(unittest.TestCase):
    def test_round_trip_with_forward_rewrite(self):
        for name, data in CONSUMERS.items():
            with self.subTest(name=name):
                reversed_data = refresh_roots.reverse_bytes(data)
                self.assertNotIn(b"TurboHTTP.SecureProtocol", reversed_data)
                self.assertEqual(rewrite.rewrite_bytes(reversed_data)[0], data)

    def test_turbohttp_namespaces_untouched(self):
        out = refresh_roots.reverse_bytes(PROVIDER)
        self.assertIn(b"using TurboHTTP.Transport.Tls;", out)
        self.assertIn(b"namespace TurboHTTP.Transport.BouncyCastle", out)
        self.assertIn(b"using Org.BouncyCastle.Security;", out)
        self.assertIn(b'"Org.BouncyCastle.Tls"', out)

    def test_reverse_is_idempotent(self):
        once = refresh_roots.reverse_bytes(PROVIDER)
        self.assertEqual(refresh_roots.reverse_bytes(once), once)

    def test_bytes_preserved(self):
        out = refresh_roots.reverse_bytes(CLIENT)
        self.assertTrue(out.startswith(b"\xef\xbb\xbf\r\n\r\nusing Org.BouncyCastle.Tls;\r\n"))
        self.assertEqual(out.count(b"\r\n"), CLIENT.count(b"\r\n"))

    def test_unprefixed_source_token_is_rejected(self):
        # The forward rewrite would prefix it, so the committed copy would not round-trip.
        with self.assertRaises(refresh_roots.RefreshError):
            refresh_roots.reverse_checked(b"using Org.BouncyCastle.Tls;\n", "x.cs")

    def test_partial_prefix_is_not_a_token(self):
        data = b"// MyTurboHTTP.SecureProtocol.Org.BouncyCastleFoo\n"
        self.assertEqual(refresh_roots.reverse_bytes(data), data)


class RefreshTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="refresh-roots-"))
        self.turbo = self.tmp / "turboHTTP"
        consumer_dir = self.turbo / CONSUMER_DIR
        (consumer_dir / "Lib" / "Tls").mkdir(parents=True)
        for name, data in CONSUMERS.items():
            (consumer_dir / name).write_bytes(data)
            (consumer_dir / (name + ".meta")).write_bytes(b"guid: 0\n")
        (consumer_dir / "Lib" / "Tls" / "TlsClient.cs").write_bytes(b"namespace X { }\n")
        (consumer_dir / "TurboHTTP.Transport.BouncyCastle.asmdef").write_bytes(b"{}\n")
        (consumer_dir / "Extra.cs").write_bytes(b"namespace X { }\n")
        git(self.turbo, "init", "-q")
        git(self.turbo, "add", "-A")
        git(self.turbo, "commit", "-q", "-m", "base")
        self.head = git(self.turbo, "rev-parse", "HEAD")
        self.strip = self.tmp / "strip"
        self.roots = self.strip / "roots"
        self.roots.mkdir(parents=True)
        self.stubs = b"namespace TurboHTTP.Transport.Tls { } // hand-maintained\n"
        self.extra = b"using Org.BouncyCastle.Tls; // hand-maintained\n"
        (self.roots / "RootStubs.cs").write_bytes(self.stubs)
        (self.roots / "roots-extra.cs").write_bytes(self.extra)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def refresh(self, *extra):
        return run("--turbohttp", self.turbo, "--strip-dir", self.strip, *extra)

    def test_copies_reversed_files_and_writes_roots_sha(self):
        r = self.refresh()
        self.assertEqual(r.returncode, 0, r.stderr)
        for name, data in CONSUMERS.items():
            copy = (self.roots / name).read_bytes()
            self.assertEqual(copy, refresh_roots.reverse_bytes(data))
            self.assertEqual(rewrite.rewrite_bytes(copy)[0], data)
        sha = (self.strip / "ROOTS_SHA").read_text()
        self.assertRegex(sha, SHA40)
        self.assertEqual(sha.strip(), self.head)

    def test_only_consumer_files_copied_and_hand_files_kept(self):
        self.assertEqual(self.refresh().returncode, 0)
        self.assertEqual(sorted(p.name for p in self.roots.iterdir()),
                         sorted([*NAMES, "RootStubs.cs", "roots-extra.cs"]))
        self.assertEqual((self.roots / "RootStubs.cs").read_bytes(), self.stubs)
        self.assertEqual((self.roots / "roots-extra.cs").read_bytes(), self.extra)

    def test_second_run_is_idempotent(self):
        self.assertEqual(self.refresh().returncode, 0)
        before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.strip.rglob("*") if p.is_file()}
        r = self.refresh()
        self.assertEqual(r.returncode, 0, r.stderr)
        after = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.strip.rglob("*") if p.is_file()}
        self.assertEqual(after, before)
        self.assertIn("unchanged", r.stdout)

    def test_new_commit_updates_copies_and_sha(self):
        self.assertEqual(self.refresh().returncode, 0)
        auth = self.turbo / CONSUMER_DIR / "TurboTlsAuthentication.cs"
        auth.write_bytes(AUTH + b"// chain validation\n")
        git(self.turbo, "commit", "-q", "-am", "bump")
        new_head = git(self.turbo, "rev-parse", "HEAD")
        r = self.refresh()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((self.strip / "ROOTS_SHA").read_text(), new_head + "\n")
        self.assertTrue((self.roots / "TurboTlsAuthentication.cs").read_bytes().endswith(b"// chain validation\n"))

    def test_copies_come_from_the_commit_not_the_working_tree(self):
        (self.turbo / CONSUMER_DIR / "TurboTlsClient.cs").write_bytes(b"uncommitted\n")
        self.assertEqual(self.refresh().returncode, 0)
        self.assertEqual((self.roots / "TurboTlsClient.cs").read_bytes(), refresh_roots.reverse_bytes(CLIENT))

    def test_rev_selects_an_older_commit(self):
        auth = self.turbo / CONSUMER_DIR / "TurboTlsAuthentication.cs"
        auth.write_bytes(AUTH + b"// later\n")
        git(self.turbo, "commit", "-q", "-am", "later")
        r = self.refresh("--rev", self.head[:10])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((self.strip / "ROOTS_SHA").read_text(), self.head + "\n")
        self.assertEqual((self.roots / "TurboTlsAuthentication.cs").read_bytes(), refresh_roots.reverse_bytes(AUTH))

    def test_option_like_rev_is_an_error(self):
        r = self.refresh("--rev=--output=x")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("bad --rev", r.stderr)
        self.assertFalse((self.strip / "ROOTS_SHA").exists())

    def test_non_git_path_is_an_error(self):
        plain = self.tmp / "plain"
        shutil.copytree(self.turbo / "Runtime", plain / "Runtime")
        r = run("--turbohttp", plain, "--strip-dir", self.strip)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("git", r.stderr)
        self.assertFalse((self.strip / "ROOTS_SHA").exists())

    def test_subdirectory_of_checkout_is_an_error(self):
        r = run("--turbohttp", self.turbo / "Runtime", "--strip-dir", self.strip)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("top level", r.stderr)

    def test_missing_consumer_file_is_an_error_and_writes_nothing(self):
        git(self.turbo, "rm", "-q", f"{CONSUMER_DIR}/TurboTlsClient.cs")
        git(self.turbo, "commit", "-q", "-m", "drop")
        r = self.refresh()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("TurboTlsClient.cs", r.stderr)
        self.assertEqual(sorted(p.name for p in self.roots.iterdir()), ["RootStubs.cs", "roots-extra.cs"])
        self.assertFalse((self.strip / "ROOTS_SHA").exists())

    def test_unprefixed_bc_token_in_source_is_an_error(self):
        client = self.turbo / CONSUMER_DIR / "TurboTlsClient.cs"
        client.write_bytes(b"using Org.BouncyCastle.Tls;\n")
        git(self.turbo, "commit", "-q", "-am", "unprefixed")
        r = self.refresh()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not prefixed", r.stderr)
        self.assertFalse((self.strip / "ROOTS_SHA").exists())


class CommittedRootsTest(unittest.TestCase):
    """The committed strip/roots and strip/ROOTS_SHA are in the form refresh_roots.py writes."""

    def test_roots_sha_format(self):
        self.assertRegex((REPO / "strip" / "ROOTS_SHA").read_text(), SHA40)

    def test_committed_copies_are_reversed(self):
        roots = REPO / "strip" / "roots"
        self.assertEqual(sorted(p.name for p in roots.iterdir()),
                         sorted([*NAMES, "RootStubs.cs", "roots-extra.cs"]))
        for p in roots.iterdir():
            with self.subTest(name=p.name):
                data = p.read_bytes()
                self.assertNotIn(b"TurboHTTP.SecureProtocol", data)
                self.assertEqual(refresh_roots.reverse_bytes(data), data)


if __name__ == "__main__":
    unittest.main()

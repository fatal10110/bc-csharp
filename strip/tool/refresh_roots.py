#!/usr/bin/env python3
"""Refresh strip/roots from a turboHTTP checkout (STRIP_PLAN_V2.md section 5 step 1, --refresh-roots).

Copies the three consumer files of turboHTTP Runtime/Transport/BouncyCastle/ into strip/roots with
the namespace rewrite reversed (``TurboHTTP.SecureProtocol.Org.BouncyCastle`` -> ``Org.BouncyCastle``)
and writes the turboHTTP commit they came from to strip/ROOTS_SHA. The files are read from the
commit (``git show <sha>:<path>``), not the working tree, so the copies always match ROOTS_SHA.
Only the token prefix changes; a BOM, line endings and every other byte are kept, and the forward
rewrite of strip/tool/rewrite.py turns each copy back into the exact consumer file (checked).

RootStubs.cs and roots-extra.cs are maintained by hand in this repository and never touched. A file
whose bytes are already current is not rewritten, so a second run changes nothing. Nothing is ever
written into the turboHTTP checkout. strip.sh (#10) wires this as ``--refresh-roots --turbohttp``.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import rewrite  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
CONSUMER_DIR = "Runtime/Transport/BouncyCastle"
CONSUMER_FILES = ("BouncyCastleTlsProvider.cs", "TurboTlsClient.cs", "TurboTlsAuthentication.cs")
ROOTS_SHA_NAME = "ROOTS_SHA"
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
PREFIXED_RE = re.compile(rb"\b" + re.escape(rewrite.PREFIX) + rb"(?=Org\.BouncyCastle\b)")


class RefreshError(Exception):
    pass


def reverse_bytes(data):
    """Drop the TurboHTTP.SecureProtocol. prefix from every Org.BouncyCastle token."""
    return PREFIXED_RE.sub(b"", data)


def reverse_checked(data, name):
    """Reverse one consumer file; raise RefreshError unless the forward rewrite restores it exactly."""
    unprefixed = rewrite.unprefixed_tokens(data)
    if unprefixed:
        raise RefreshError(f"{name}: {unprefixed} Org.BouncyCastle token(s) not prefixed; "
                           "the forward rewrite could not restore the consumer file")
    out = reverse_bytes(data)
    if rewrite.rewrite_bytes(out)[0] != data:
        raise RefreshError(f"{name}: reverse rewrite does not round-trip")
    return out


def git(repo, *args, text=True):
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=text)
    if r.returncode != 0:
        err = r.stderr if text else r.stderr.decode("utf-8", "replace")
        raise RefreshError(f"git {' '.join(args)} failed in {repo}: {err.strip()}")
    return r.stdout


def resolve_commit(turbohttp, rev):
    turbohttp = Path(turbohttp).resolve()
    if not turbohttp.is_dir():
        raise RefreshError(f"turboHTTP checkout not found: {turbohttp}")
    top = Path(git(turbohttp, "rev-parse", "--show-toplevel").strip()).resolve()
    if top != turbohttp:
        raise RefreshError(f"--turbohttp must be the top level of the turboHTTP checkout ({top}): {turbohttp}")
    if not rev or rev.startswith("-"):
        raise RefreshError(f"bad --rev: {rev!r}")
    sha = git(turbohttp, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}").strip()
    if not SHA40_RE.match(sha):
        raise RefreshError(f"unexpected commit id for {rev!r}: {sha!r}")
    return turbohttp, sha


def read_consumers(turbohttp, sha):
    files = {}
    for name in CONSUMER_FILES:
        path = f"{CONSUMER_DIR}/{name}"
        try:
            data = git(turbohttp, "show", f"{sha}:{path}", text=False)
        except RefreshError:
            raise RefreshError(f"{path} missing at turboHTTP {sha}") from None
        files[name] = reverse_checked(data, path)
    return files


def write_if_changed(path, data):
    if path.exists() and path.read_bytes() == data:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return True


def refresh(turbohttp, strip_dir, rev="HEAD"):
    """Refresh strip_dir/roots and strip_dir/ROOTS_SHA; return the list of (path, changed)."""
    turbohttp, sha = resolve_commit(turbohttp, rev)
    files = read_consumers(turbohttp, sha)  # everything is read and checked before anything is written
    strip_dir = Path(strip_dir).resolve()
    results = []
    for name, data in files.items():
        path = strip_dir / "roots" / name
        results.append((path, write_if_changed(path, data)))
    path = strip_dir / ROOTS_SHA_NAME
    results.append((path, write_if_changed(path, (sha + "\n").encode("ascii"))))
    return sha, results


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--turbohttp", required=True, help="top level of a turboHTTP git checkout (read only)")
    ap.add_argument("--rev", default="HEAD", help="turboHTTP commit to copy from (default HEAD)")
    ap.add_argument("--strip-dir", default=str(REPO / "strip"),
                    help="directory holding roots/ and ROOTS_SHA (default: this repository's strip/)")
    args = ap.parse_args(argv)
    try:
        sha, results = refresh(args.turbohttp, args.strip_dir, args.rev)
    except RefreshError as e:
        print(f"refresh_roots: error: {e}", file=sys.stderr)
        return 1
    for path, changed in results:
        print(f"{'updated' if changed else 'unchanged'}: {path}")
    print(f"ROOTS_SHA {sha}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

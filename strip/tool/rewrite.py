#!/usr/bin/env python3
"""Namespace rewrite for the strip (STRIP_PLAN_V2.md section 5 step 4).

Copies every file of a file list from a source root into an output directory, replacing the
whole token ``Org.BouncyCastle`` with ``TurboHTTP.SecureProtocol.Org.BouncyCastle``. The match is
global (usings, aliases, crefs, string literals) and works on bytes, so a UTF-8 BOM, line endings
and every other byte stay exactly as in the source. A token that is already prefixed is left
alone, so a second pass over rewritten text changes nothing.

File list: one path per line relative to --src, '/' separators, '#' starts a comment line,
blank lines ignored. strip.sh (#10) calls this once for the library tree and once for the roots
(strip/roots) with their own --src.
"""

import argparse
import re
import sys
from pathlib import Path, PurePosixPath

PREFIX = b"TurboHTTP.SecureProtocol."
TOKEN_RE = re.compile(rb"(?<!" + re.escape(PREFIX) + rb")\bOrg\.BouncyCastle\b")


def rewrite_bytes(data):
    """Return (rewritten bytes, number of replacements)."""
    return TOKEN_RE.subn(PREFIX + b"Org.BouncyCastle", data)


def unprefixed_tokens(data):
    """Count tokens that are still not prefixed."""
    return len(TOKEN_RE.findall(data))


def read_file_list(path):
    """Read a file list; return sorted unique relative paths. Raise ValueError on a bad entry."""
    entries = set()
    with open(path, encoding="utf-8") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            check_relpath(line, f"{path}:{lineno}")
            entries.add(line)
    return sorted(entries)


def check_relpath(rel, where):
    if "\\" in rel:
        raise ValueError(f"{where}: use '/' separators: {rel}")
    p = PurePosixPath(rel)
    if p.is_absolute() or ".." in p.parts or "." in p.parts or str(p) != rel:
        raise ValueError(f"{where}: path must be relative and normalized: {rel}")


def ensure_empty_dir(out):
    if out.exists():
        if not out.is_dir():
            raise ValueError(f"output exists and is not a directory: {out}")
        if any(out.iterdir()):
            raise ValueError(f"output directory is not empty (rewrite always starts from the source): {out}")
    out.mkdir(parents=True, exist_ok=True)


def rewrite_tree(src, files, out):
    """Rewrite each file of `files` (relative to src) into out. Return total replacements."""
    src = Path(src)
    out = Path(out)
    missing = [rel for rel in files if not (src / rel).is_file() or (src / rel).is_symlink()]
    if missing:
        raise ValueError("not a regular file under the source root: " + ", ".join(missing[:10]))
    ensure_empty_dir(out)
    total = 0
    for rel in files:
        data, n = rewrite_bytes((src / rel).read_bytes())
        total += n
        dest = out / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    return total


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--src", required=True, help="source root the file list is relative to (e.g. crypto/src)")
    ap.add_argument("--files", required=True, help="file list, one path per line relative to --src")
    ap.add_argument("--out", required=True, help="output directory; must be absent or empty")
    args = ap.parse_args(argv)
    try:
        files = read_file_list(args.files)
        if not files:
            raise ValueError(f"file list is empty: {args.files}")
        total = rewrite_tree(args.src, files, args.out)
    except (OSError, ValueError) as e:
        print(f"rewrite: error: {e}", file=sys.stderr)
        return 1
    print(f"rewrite: {len(files)} files, {total} tokens rewritten -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

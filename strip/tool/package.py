#!/usr/bin/env python3
"""Package the rewritten tree into strip/out (STRIP_PLAN_V2.md section 5 step 6).

Writes, under --out:
  Lib/**                   the rewritten .cs files, Lib/LICENSE.md (verbatim copy of --license) and a
                           Unity .meta for every file and folder inside Lib/ (GUID =
                           md5("turbohttp-bc:" + relpath), relpath relative to Lib/, '/' separators)
  THIRD-PARTY-NOTICES.txt  the BC licence plus every non-BC licence header found in the packaged
                           files (to review by hand)
  STRIP_INFO.md            BASE, ROOTS_SHA, cut list, per-directory counts, smoke results, shadow diff

Only Lib/, THIRD-PARTY-NOTICES.txt and STRIP_INFO.md are replaced; nothing else under --out is
touched. The output depends only on the inputs: sorted walks, '\n' line endings, no timestamps
and no absolute paths, so two runs give byte-identical files.
"""

import argparse
import hashlib
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rewrite import unprefixed_tokens  # noqa: E402

GUID_SALT = "turbohttp-bc:"
LICENSE_NAME = "LICENSE.md"
NOTICES_NAME = "THIRD-PARTY-NOTICES.txt"
INFO_NAME = "STRIP_INFO.md"
# Files whose behavior turbo-owned code shadows; on a bump the owner ports their upstream changes.
SHADOW_PATHS = (
    "crypto/src/security/PublicKeyFactory.cs",
    "crypto/src/x509/X509SignatureUtil.cs",
    "crypto/src/security/MacUtilities.cs",
    "crypto/src/crypto/modes/GCMBlockCipher.cs",
)
LICENCE_RE = re.compile(r"Permission is hereby granted|Licensed under")
BC_HEADER_RE = re.compile(r"Legion of the Bouncy Castle")
CUT_RE = re.compile(r"//\s*turbo-strip:(.*)$")
SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")

# Unity writes "key: " with a trailing space for empty values; keep it (no trailing whitespace in source).
META_TAIL = "  userData: \n  assetBundleName: \n  assetBundleVariant: \n"
META_HEAD = "fileFormatVersion: 2\nguid: {guid}\n"
META_FOLDER = META_HEAD + "folderAsset: yes\nDefaultImporter:\n  externalObjects: {{}}\n" + META_TAIL
META_CS = (
    META_HEAD
    + "MonoImporter:\n  externalObjects: {{}}\n  serializedVersion: 2\n  defaultReferences: []\n"
    + "  executionOrder: 0\n  icon: {{instanceID: 0}}\n"
    + META_TAIL
)
META_TEXT = META_HEAD + "TextScriptImporter:\n  externalObjects: {{}}\n" + META_TAIL


class PackageError(Exception):
    pass


def guid_for(relpath):
    return hashlib.md5((GUID_SALT + relpath).encode("utf-8")).hexdigest()


def meta_for(relpath, is_dir):
    if is_dir:
        template = META_FOLDER
    elif relpath.endswith(".cs"):
        template = META_CS
    elif relpath == LICENSE_NAME:
        template = META_TEXT
    else:
        raise PackageError(f"no importer for {relpath}")
    return template.format(guid=guid_for(relpath))


def write_text(path, text):
    path.write_bytes(text.encode("utf-8"))


def collect_sources(lib_src):
    """Sorted relative paths of the .cs files under lib_src; reject anything else."""
    lib_src = Path(lib_src)
    if not lib_src.is_dir():
        raise PackageError(f"not a directory: {lib_src}")
    files = []
    for p in sorted(lib_src.rglob("*")):
        rel = p.relative_to(lib_src).as_posix()
        if p.is_symlink():
            raise PackageError(f"symlink in the rewritten tree: {rel}")
        if p.is_dir():
            continue
        if not rel.endswith(".cs"):
            raise PackageError(f"unexpected file in the rewritten tree (only .cs is packaged): {rel}")
        files.append(rel)
    if not files:
        raise PackageError(f"no .cs files under {lib_src}")
    leftover = [rel for rel in files if unprefixed_tokens((lib_src / rel).read_bytes())]
    if leftover:
        raise PackageError("Org.BouncyCastle token not rewritten in: " + ", ".join(leftover[:10]))
    return files


def build_lib(lib_src, files, license_path, lib_out):
    lib_out.mkdir(parents=True)
    for rel in files:
        dest = lib_out / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes((Path(lib_src) / rel).read_bytes())
    (lib_out / LICENSE_NAME).write_bytes(Path(license_path).read_bytes())

    entries = set()
    for rel in files + [LICENSE_NAME]:
        parts = rel.split("/")
        for i in range(1, len(parts)):
            entries.add(("/".join(parts[:i]), True))
        entries.add((rel, False))
    for rel, is_dir in sorted(entries):
        write_text(lib_out / (rel + ".meta"), meta_for(rel, is_dir))


def comment_block(lines, idx):
    """The comment block around lines[idx]: neighbouring comment or blank lines, blank edges trimmed."""

    def is_comment(s):
        s = s.strip()
        return s.startswith(("//", "/*", "*")) or s.endswith("*/")

    def is_part(s):
        return not s.strip() or is_comment(s)

    lo = idx
    while lo > 0 and is_part(lines[lo - 1]):
        lo -= 1
    hi = idx
    while hi + 1 < len(lines) and is_part(lines[hi + 1]):
        hi += 1
    while lo < idx and not lines[lo].strip():
        lo += 1
    while hi > idx and not lines[hi].strip():
        hi -= 1
    return lo, hi


def scan_licence_headers(lib_src, files):
    """[(relpath, first line, last line, text)] for every non-BC licence header block."""
    found = []
    for rel in files:
        text = (Path(lib_src) / rel).read_bytes().decode("utf-8-sig", errors="replace")
        lines = text.replace("\r\n", "\n").split("\n")
        seen_until = -1
        for i, line in enumerate(lines):
            if i <= seen_until or not LICENCE_RE.search(line):
                continue
            lo, hi = comment_block(lines, i)
            seen_until = hi
            block = "\n".join(l.rstrip() for l in lines[lo : hi + 1])
            if BC_HEADER_RE.search(block):
                continue
            found.append((rel, lo + 1, hi + 1, block))
    return found


def notices_text(license_path, headers):
    bc = Path(license_path).read_bytes().decode("utf-8").replace("\r\n", "\n").rstrip("\n")
    out = [
        "THIRD-PARTY NOTICES",
        "",
        "TurboHTTP.SecureProtocol.Org.BouncyCastle is a reduced, namespace-rewritten copy of",
        "Bouncy Castle for .NET (bc-csharp). It is distributed under the following licence.",
        "",
        "=" * 72,
        "Bouncy Castle for .NET (bc-csharp)",
        "=" * 72,
        "",
        bc,
        "",
        "=" * 72,
        "Other licence headers in the packaged files (review by hand)",
        "=" * 72,
        "",
    ]
    if not headers:
        out += ["None found.", ""]
    for rel, lo, hi, block in headers:
        out += [f"--- Lib/{rel} (lines {lo}-{hi}) ---", "", block, ""]
    return "\n".join(out)


def cut_list(lib_src, files):
    cuts = []
    for rel in files:
        text = (Path(lib_src) / rel).read_bytes().decode("utf-8-sig", errors="replace")
        for n, line in enumerate(text.split("\n"), 1):
            m = CUT_RE.search(line)
            if m:
                cuts.append((rel, n, m.group(1).strip()))
    return cuts


def dir_counts(files):
    counts = {}
    for rel in files:
        top = rel.split("/")[0] if "/" in rel else "(root)"
        counts[top] = counts.get(top, 0) + 1
    return sorted(counts.items())


def git(repo, *args):
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        raise PackageError(f"git {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout


def shadow_diff(repo, old_base, new_base):
    """Check the shadow paths against git ls-files (exact case) and diff them OLDBASE..NEWBASE."""
    listed = set(git(repo, "ls-files", "-z", "--", *SHADOW_PATHS).split("\0")) - {""}
    missing = [p for p in SHADOW_PATHS if p not in listed]
    if missing:
        raise PackageError("shadow paths not in git ls-files (check case): " + ", ".join(missing))
    if old_base == new_base:
        return ""
    for rev in (old_base, new_base):
        git(repo, "rev-parse", "--verify", "--quiet", rev + "^{commit}")
    return git(
        repo,
        "-c", "core.quotepath=true",
        "diff", "--no-color", "--no-ext-diff", "--no-textconv", "--no-renames",
        "--diff-algorithm=myers", "--src-prefix=a/", "--dst-prefix=b/",
        old_base, new_base, "--", *SHADOW_PATHS,
    )  # fmt: skip


def fence(text):
    longest = max((len(m.group(0)) for m in re.finditer(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def info_text(base, roots_sha, old_base, files, cuts, smoke, diff):
    out = [
        "# STRIP_INFO",
        "",
        "Generated by `strip/tool/package.py`. Paths are relative to `Lib/`.",
        "",
        f"- BASE: `{base}`",
        f"- ROOTS_SHA: `{roots_sha}`",
        f"- Packaged `.cs` files: {len(files)}",
        "",
        "## Cut list",
        "",
        "Every `// turbo-strip:` marker in the packaged files.",
        "",
    ]
    out += [f"- `{rel}:{n}` {text}".rstrip() for rel, n, text in cuts] or ["None."]
    out += ["", "## Per-directory counts", "", "| Directory | .cs files |", "| --- | ---: |"]
    out += [f"| `{d}` | {n} |" for d, n in dir_counts(files)]
    out += [f"| total | {len(files)} |", "", "## Smoke results", ""]
    if smoke is None:
        out += ["Not run."]
    else:
        f = fence(smoke)
        out += [f, smoke.rstrip("\n"), f]
    out += ["", "## Shadow diff", "", "Files shadowed by turbo-owned code, checked against `git ls-files`:", ""]
    out += [f"- `{p}`" for p in SHADOW_PATHS]
    out += [""]
    if old_base == base:
        out += ["No bump (OLDBASE = BASE): empty."]
    elif not diff:
        out += [f"`{old_base}..{base}`: no changes."]
    else:
        f = fence(diff)
        out += [f"`{old_base}..{base}`:", "", f + "diff", diff.rstrip("\n"), f]
    out += [""]
    return "\n".join(out)


def check_sha(name, value):
    if not SHA_RE.match(value):
        raise PackageError(f"{name} must be a lowercase hex commit id (7-40 chars): {value!r}")


def package(lib_src, out, license_path, base, roots_sha, repo, old_base=None, smoke_path=None):
    check_sha("BASE", base)
    check_sha("ROOTS_SHA", roots_sha)
    old_base = old_base or base
    check_sha("OLDBASE", old_base)
    lib_src = Path(lib_src).resolve()
    out = Path(out).resolve()
    lib_out = out / "Lib"
    if lib_src == lib_out or lib_out in lib_src.parents or lib_src in lib_out.parents:
        raise PackageError("the rewritten tree and the output Lib/ must not overlap")
    files = collect_sources(lib_src)
    diff = shadow_diff(repo, old_base, base)
    smoke = Path(smoke_path).read_bytes().decode("utf-8").replace("\r\n", "\n") if smoke_path else None
    headers = scan_licence_headers(lib_src, files)
    cuts = cut_list(lib_src, files)

    out.mkdir(parents=True, exist_ok=True)
    if lib_out.exists():
        shutil.rmtree(lib_out)
    build_lib(lib_src, files, license_path, lib_out)
    write_text(out / NOTICES_NAME, notices_text(license_path, headers))
    write_text(out / INFO_NAME, info_text(base, roots_sha, old_base, files, cuts, smoke, diff))
    return files, headers


def main(argv=None):
    repo_default = Path(__file__).resolve().parents[2]
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--lib", required=True, help="rewritten library tree (output of rewrite.py)")
    ap.add_argument("--out", required=True, help="package root, normally strip/out")
    ap.add_argument("--base", required=True, help="upstream BASE commit (strip/BASE)")
    ap.add_argument("--roots-sha", required=True, help="turboHTTP commit the roots came from (strip/ROOTS_SHA)")
    ap.add_argument("--old-base", help="previous BASE on a bump; the shadow diff is OLDBASE..BASE (default: BASE)")
    ap.add_argument("--smoke", help="smoke results file to embed (default: 'Not run.')")
    ap.add_argument("--license", default=str(repo_default / LICENSE_NAME), help="bc-csharp LICENSE.md")
    ap.add_argument("--repo", default=str(repo_default), help="git repository for ls-files and the shadow diff")
    args = ap.parse_args(argv)
    try:
        files, headers = package(
            args.lib, args.out, args.license, args.base, args.roots_sha, args.repo, args.old_base, args.smoke
        )
    except (OSError, UnicodeDecodeError, PackageError) as e:
        print(f"package: error: {e}", file=sys.stderr)
        return 1
    print(f"package: {len(files)} files, {len(headers)} non-BC licence header(s) -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

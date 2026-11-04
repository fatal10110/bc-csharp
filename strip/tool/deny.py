"""Deny list and budget (STRIP_PLAN_V2.md §3 "deny.txt"/"budget.txt", §5 step 2; issue #8).

- strip/deny.txt: one glob per line, relative to crypto/src, `#` comments. Matching is
  case-insensitive and anchored: `{a,b}` expands, `**/` is any directory prefix (or none), `**` is
  any path, `*` is any run within one path segment. The list applies to the files the closure
  adds; seeds (crypto/src/turbo/ and --seed, with their partial units) are exempt.
- strip/budget.txt: a single total cap on the kept crypto/src file count (closure - denied). Its
  value is set by the first enforced run (#30); while the file is absent there is no cap.

closure.py uses these helpers for the deny-hit check, the referrer sweep and the budget. Run as a
script, it gives the offline view of a finished closure work dir (no build, no sweep):

    python3 strip/tool/deny.py <work> [--deny strip/deny.txt]
"""

import argparse
import collections
import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DENY_FILE = os.path.join(REPO, "strip", "deny.txt")
BUDGET_FILE = os.path.join(REPO, "strip", "budget.txt")

_BRACE = re.compile(r"\{([^{}]*)\}")


class DenyError(ValueError):
    pass


def expand(glob):
    """Brace expansion: `a/{B,C}*.cs` -> [`a/B*.cs`, `a/C*.cs`] (groups expand left to right)."""
    m = _BRACE.search(glob)
    if not m:
        return [glob]
    out = []
    for option in m.group(1).split(","):
        out += expand(glob[: m.start()] + option + glob[m.end() :])
    return out


def compile_glob(glob):
    """Anchored, case-insensitive regexes for one (unexpanded) glob."""
    out = []
    for g in expand(glob):
        r = re.escape(g).replace(r"\*\*/", "(?:.*/)?").replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
        out.append(re.compile("^" + r + "$", re.IGNORECASE))
    return out


def parse_deny(text, origin="deny.txt"):
    """[(glob, [regex])] in file order; blank lines and `#` comments are skipped."""
    rules = []
    for n, line in enumerate(text.splitlines(), 1):
        g = line.split("#", 1)[0].strip()
        if not g:
            continue
        rest = _BRACE.sub("", g)
        if g.startswith("/") or "\\" in g or ".." in g.split("/") or "{" in rest or "}" in rest:
            raise DenyError(f"{origin}:{n}: not a crypto/src-relative glob: {g!r}")
        rules.append((g, compile_glob(g)))
    return rules


def load_deny(path=DENY_FILE):
    with open(path, encoding="utf-8") as f:
        return parse_deny(f.read(), path)


def match(rules, rel):
    """The first glob that denies the crypto/src-relative path `rel`, else None."""
    for glob, patterns in rules:
        if any(p.match(rel) for p in patterns):
            return glob
    return None


def deny_hits(files, rules, exempt=()):
    """{file: glob} for the closure files a rule denies; `exempt` files (seeds) never are."""
    exempt = set(exempt)
    out = {}
    for f in files:
        if f in exempt:
            continue
        g = match(rules, f)
        if g is not None:
            out[f] = g
    return out


def dir_counts(files):
    """Files per top-level crypto/src directory; files directly in crypto/src count as `(root)`."""
    c = collections.Counter(f.split("/", 1)[0] if "/" in f else "(root)" for f in files)
    return dict(sorted(c.items()))


def parse_budget(text, origin="budget.txt"):
    """The single total cap: the one non-comment line, a positive integer."""
    values = [line.split("#", 1)[0].strip() for line in text.splitlines()]
    values = [v for v in values if v]
    if len(values) != 1 or not values[0].isdigit() or int(values[0]) <= 0:
        raise DenyError(f"{origin}: expected one positive integer (the total cap), got {values}")
    return int(values[0])


def load_budget(path=BUDGET_FILE):
    """The cap, or None when the file does not exist (#30 set strip/budget.txt)."""
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as f:
        return parse_budget(f.read(), path)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Offline deny view of a finished closure work dir.")
    ap.add_argument("work")
    ap.add_argument("--deny", default=DENY_FILE)
    a = ap.parse_args(argv)
    with open(os.path.join(a.work, "closure_files.json"), encoding="utf-8") as f:
        files = [x for x in json.load(f) if not x.startswith("_")]
    with open(os.path.join(a.work, "prov.json"), encoding="utf-8") as f:
        prov = json.load(f)
    denied = deny_hits(files, load_deny(a.deny), exempt=[x for x in files if x.startswith("turbo/")])
    kept = [x for x in files if x not in denied]
    print(f"closure: {len(files)} files, denied: {len(denied)}, kept: {len(kept)}")
    for g, n in collections.Counter(denied.values()).most_common():
        print(f"  {n:4d} {g}")
    print("first recorded kept referrers (closure.py's referrer sweep gives the complete list):")
    for f in sorted(denied):
        refs = [r for r in prov.get(f, []) if r.rsplit(":", 1)[0] not in denied]
        if refs:
            print(f"  {f} <- {', '.join(refs)}")
    print(f"kept per top dir: {dir_counts(kept)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

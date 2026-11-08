"""C# declaration index for the closure resolver (STRIP_PLAN_V2.md §5 step 2, issue #7).

A light scanner, not a parser: comments and literals are blanked, then a token state machine
tracks namespace/type/block frames by braces. ``#if``/``#elif``/``#else`` branches are all scanned
(the closure runs over the union of define sets); the frame stack is restored at each branch so
unbalanced braces across branches do not shift the nesting.

Per file it records namespace declarations (with line ranges), using directives (scope = enclosing
namespace declaration), type declarations and extension methods. The ``Index`` keys types by
(namespace, name, generic arity); nested types are keyed "Outer.Inner" and map to the outer file;
the parts of a partial type form one unit.

CLI (debugging): ``index.py <crypto/src> <out.json>``.
"""

import json
import os
import re
import sys
from dataclasses import dataclass, field

TYPE_KEYWORDS = ("class", "struct", "interface", "enum")
# Identifiers that follow a type keyword without declaring a type (`where T : class where U : ...`).
NOT_A_NAME = {"where", "new", "class", "struct", "interface", "enum", "unmanaged", "notnull"}
_IDENT = re.compile(r"@?[A-Za-z_][A-Za-z0-9_]*$")
_TOKEN = re.compile(r"@?[A-Za-z_][A-Za-z0-9_]*|[{}();<>,.\[\]=:]")
_DIRECTIVE = re.compile(r"^\s*#\s*(if|elif|else|endif)\b")
_STRING_START = re.compile(r'(?:\$@|@\$|@|\$)?"')


@dataclass
class NamespaceDecl:
    name: str
    start: int
    end: int


@dataclass
class UsingDecl:
    scope: str  # full name of the enclosing namespace declaration, "" at compilation-unit level
    kind: str  # "ns" | "alias" | "static"
    target: str
    alias: str
    line: int


@dataclass
class TypeDecl:
    ns: str
    name: str  # "Outer.Inner" for nested types
    arity: int
    kind: str
    partial: bool
    static: bool
    line: int
    file: str = ""

    @property
    def key(self):
        return (self.ns, self.name, self.arity)

    @property
    def nested(self):
        return "." in self.name


@dataclass
class ExtensionDecl:
    ns: str
    method: str
    owner: str
    line: int
    file: str = ""


@dataclass
class FileInfo:
    path: str
    namespaces: list = field(default_factory=list)
    usings: list = field(default_factory=list)
    types: list = field(default_factory=list)
    extensions: list = field(default_factory=list)


def _blank(s):
    return re.sub(r"[^\n]", " ", s)


def strip_code(text):
    """Blank comments, string and char literals; newlines survive so line numbers stay valid."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
            continue
        if c == "/" and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(_blank(text[i:j]))
            i = j
            continue
        m = _STRING_START.match(text, i) if c in '@$"' else None
        if m:
            verbatim = "@" in m.group(0)
            j = m.end()
            while j < n:
                if verbatim:
                    if text[j] == '"':
                        if j + 1 < n and text[j + 1] == '"':
                            j += 2
                            continue
                        break
                else:
                    if text[j] == "\\":
                        j += 2
                        continue
                    if text[j] in '"\n':
                        break
                j += 1
            j = min(j + 1, n)
            out.append(_blank(text[i:j]))
            i = j
            continue
        if c == "'":
            j = i + 1
            j += 2 if j < n and text[j] == "\\" else 1
            while j < n and text[j] not in "'\n":
                j += 1
            j = min(j + 1, n)
            out.append(_blank(text[i:j]))
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def tokenize(text):
    """(token, line) pairs of stripped code; #if/#elif/#else/#endif become '#if' etc. tokens."""
    toks = []
    for no, line in enumerate(strip_code(text).splitlines(), 1):
        if line.lstrip().startswith("#"):
            m = _DIRECTIVE.match(line)
            if m:
                toks.append(("#" + m.group(1), no))
            continue
        for m in _TOKEN.finditer(line):
            toks.append((m.group(0), no))
    return toks


def _is_ident(tok):
    return bool(_IDENT.match(tok))


def _generic_arity(toks, j):
    """toks[j] == '<': (arity, index after the matching '>'), else (0, j)."""
    if j >= len(toks) or toks[j][0] != "<":
        return 0, j
    depth, commas, k = 0, 0, j
    while k < len(toks):
        t = toks[k][0]
        if t == "<":
            depth += 1
        elif t == ">":
            depth -= 1
            if depth == 0:
                return commas + 1, k + 1
        elif t == "," and depth == 1:
            commas += 1
        elif t in ("{", ";", "("):
            break
        k += 1
    return 0, j


def _arity_backwards(toks, end, stop):
    """toks[end] == '>': (arity, index of the token before the matching '<')."""
    depth, commas, k = 0, 0, end
    while k > stop:
        t = toks[k][0]
        if t == ">":
            depth += 1
        elif t == "<":
            depth -= 1
            if depth == 0:
                return commas + 1, k - 1
        elif t == "," and depth == 1:
            commas += 1
        k -= 1
    return 0, end


def _dotted(toks, j):
    """Read `A.B.C` (generic args kept as text) from toks[j]; returns (text, index after)."""
    parts = []
    k = j
    while k < len(toks) and toks[k][0] not in (";", "{", "="):
        parts.append(toks[k][0])
        k += 1
    return "".join(parts), k


def scan(text, path=""):
    """Scan one C# file into a FileInfo."""
    info = FileInfo(path)
    toks = tokenize(text)
    stack = []  # frames: ("ns", full, decl) | ("type", name) | ("block",)
    pp = []  # [stack at #if, stack at the end of the first branch or None]
    pending = None
    mods = []

    def cur_ns():
        for frame in reversed(stack):
            if frame[0] == "ns":
                return frame[1]
        return ""

    def type_chain():
        chain = []
        for frame in reversed(stack):
            if frame[0] == "ns":
                break
            if frame[0] == "type":
                chain.append(frame[1])
        return list(reversed(chain))

    def only_namespaces():
        return all(frame[0] == "ns" for frame in stack)

    i, n = 0, len(toks)
    while i < n:
        tok, line = toks[i]
        if tok in ("#if", "#elif", "#else", "#endif"):
            if tok == "#if":
                pp.append([list(stack), None])
            elif pp:
                entry = pp[-1]
                if tok == "#endif":
                    pp.pop()
                    if entry[1] is not None:
                        stack[:] = entry[1]
                else:
                    if entry[1] is None:
                        entry[1] = list(stack)
                    stack[:] = list(entry[0])
            i += 1
            continue
        if tok == "namespace" and only_namespaces():
            name, j = _dotted(toks, i + 1)
            outer = cur_ns()
            full = f"{outer}.{name}" if outer else name
            if j < n and toks[j][0] == ";":  # file-scoped namespace
                decl = NamespaceDecl(full, line, 1 << 30)
                info.namespaces.append(decl)
                stack.append(("ns", full, decl))
                i = j + 1
                continue
            pending = ("ns", full, line)
            i = j
            continue
        if tok == "using" and only_namespaces() and pending is None:
            j = i + 1
            kind, alias = "ns", ""
            if j < n and toks[j][0] == "static":
                kind = "static"
                j += 1
            elif j + 1 < n and _is_ident(toks[j][0]) and toks[j + 1][0] == "=":
                kind, alias = "alias", toks[j][0]
                j += 2
            target, k = _dotted(toks, j)
            if k < n and toks[k][0] == ";" and target:
                info.usings.append(UsingDecl(cur_ns(), kind, target, alias, line))
                i = k + 1
                mods = []
                continue
            i += 1
            continue
        if tok in TYPE_KEYWORDS and i + 1 < n and _is_ident(toks[i + 1][0]) and toks[i + 1][0] not in NOT_A_NAME:
            name = toks[i + 1][0].lstrip("@")
            arity, j = _generic_arity(toks, i + 2)
            decl = TypeDecl(
                cur_ns(), ".".join(type_chain() + [name]), arity, tok, "partial" in mods, "static" in mods, line, path
            )
            info.types.append(decl)
            pending = ("type", name)
            i = j
            continue
        if tok == "delegate" and (not stack or stack[-1][0] in ("ns", "type")):
            j = i + 1
            while j < n and toks[j][0] not in ("(", "{", ";", "="):
                j += 1
            if j < n and toks[j][0] == "(" and j - i >= 3:
                end, arity = j - 1, 0
                if toks[end][0] == ">":
                    arity, end = _arity_backwards(toks, end, i)
                if end > i + 1 and _is_ident(toks[end][0]):
                    name = toks[end][0].lstrip("@")
                    info.types.append(
                        TypeDecl(cur_ns(), ".".join(type_chain() + [name]), arity, "delegate", False, False, line, path)
                    )
            i = j
            continue
        if tok == "(" and stack and stack[-1][0] == "type" and i > 0 and i + 2 < n:
            # Extension method declaration: Name[<T>](this Type x ...; a call `F(this)` has no type after `this`.
            if toks[i + 1][0] == "this" and _is_ident(toks[i + 2][0]):
                k = i - 1
                if toks[k][0] == ">":
                    _, k = _arity_backwards(toks, k, 0)
                if k >= 0 and _is_ident(toks[k][0]):
                    info.extensions.append(ExtensionDecl(cur_ns(), toks[k][0].lstrip("@"), stack[-1][1], line, path))
        if tok == "{":
            if pending and pending[0] == "ns":
                decl = NamespaceDecl(pending[1], pending[2], pending[2])
                info.namespaces.append(decl)
                stack.append(("ns", pending[1], decl))
            elif pending and pending[0] == "type":
                stack.append(("type", pending[1]))
            else:
                stack.append(("block",))
            pending = None
            mods = []
        elif tok == "}":
            if stack:
                frame = stack.pop()
                if frame[0] == "ns":
                    frame[2].end = line
            mods = []
        elif tok in (";", "]"):
            if tok == ";" and pending and pending[0] == "type":
                pending = None
            mods = []
        elif _is_ident(tok):
            mods.append(tok)
        i += 1
    return info


def scan_file(path, rel=None):
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        return scan(f.read(), rel if rel is not None else path)


def namespace_prefixes(name):
    """'A.B.C' -> ['A.B.C', 'A.B', 'A']."""
    parts = name.split(".") if name else []
    return [".".join(parts[:k]) for k in range(len(parts), 0, -1)]


def full_name(ns, name):
    return f"{ns}.{name}" if ns else name


class Index:
    """Types by (namespace, name, arity), namespaces, extension methods and partial units."""

    def __init__(self, infos):
        self.files = {}
        self.types = {}  # key -> sorted files declaring it
        self.partial_keys = set()
        self.by_full = {}  # "Ns.Outer.Inner" -> [keys]
        self.namespaces = set()  # declared namespaces and their ancestors
        self.extensions = {}  # method name -> [(ns, file)]
        for info in infos:
            self.add(info)
        for key in self.types:
            self.types[key] = sorted(set(self.types[key]))

    def add(self, info):
        self.files[info.path] = info
        for ns in info.namespaces:
            self.namespaces.update(namespace_prefixes(ns.name))
        for t in info.types:
            self.types.setdefault(t.key, []).append(info.path)
            keys = self.by_full.setdefault(full_name(t.ns, t.name), [])
            if t.key not in keys:
                keys.append(t.key)
            if t.partial:
                self.partial_keys.add(t.key)
        for e in info.extensions:
            self.extensions.setdefault(e.method, []).append((e.ns, info.path))

    def partial_unit(self, path):
        """`path` plus every part of every partial type it declares (transitively)."""
        unit = {path}
        todo = [path]
        while todo:
            info = self.files.get(todo.pop())
            if info is None:
                continue
            keys = set()
            for t in info.types:
                if t.key in self.partial_keys:
                    keys.add(t.key)
                if t.nested:  # a nested type in a partial outer drags the outer's parts
                    for okey in self.by_full.get(full_name(t.ns, t.name.rsplit(".", 1)[0]), []):
                        if okey in self.partial_keys:
                            keys.add(okey)
            for key in keys:
                for f in self.types.get(key, []):
                    if f not in unit:
                        unit.add(f)
                        todo.append(f)
        return unit

    def to_json(self):
        def k2s(k):
            return f"{k[0]}|{k[1]}|{k[2]}"

        return {
            "types": {k2s(k): v for k, v in sorted(self.types.items())},
            "partial": sorted(k2s(k) for k in self.partial_keys),
            "namespaces": sorted(self.namespaces),
            "extensions": {k: sorted(set(v)) for k, v in sorted(self.extensions.items())},
        }


def build_index(src):
    """Index every .cs file under `src` (paths relative to `src`, '/' separators)."""
    infos = []
    for d, dirs, fs in os.walk(src):
        dirs[:] = sorted(x for x in dirs if x not in ("bin", "obj"))
        for f in sorted(fs):
            if f.endswith(".cs"):
                full = os.path.join(d, f)
                infos.append(scan_file(full, os.path.relpath(full, src).replace(os.sep, "/")))
    return Index(infos)


def main(argv):
    if len(argv) != 3:
        print("usage: index.py <crypto/src> <out.json>", file=sys.stderr)
        return 2
    index = build_index(argv[1])
    with open(argv[2], "w", encoding="utf-8") as f:
        json.dump(index.to_json(), f, indent=1, sort_keys=True)
    spaces = {}
    for ns, name, arity in index.types:
        spaces.setdefault((name, arity), set()).add(ns)
    print(len(index.types), "types", len(index.namespaces), "namespaces", len(index.extensions), "extension names")
    print("(name, arity) declared in more than one namespace:", sum(1 for v in spaces.values() if len(v) > 1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

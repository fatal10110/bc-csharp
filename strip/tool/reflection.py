#!/usr/bin/env python3
"""No reflection in the stripped Lib (issue #77, turboHTTP#249).

turboHTTP ships the Lib under a narrowed link.xml (turboHTTP#196) and IL2CPP with High stripping:
code that looks up types or members by name, creates instances from a Type or builds generic
types at run time can lose its target to the linker or need AOT code that was never generated.
This scan fails the enforce run on any such symbol in the produced Lib (strip.sh step 4b, over
the rewritten tree that package.py copies to strip/out/Lib).

The scan works on code only: comments and the text of string and char literals are blanked first
(interpolation holes are code), so a doc comment or a message that names an API is no hit.
Deliberately not hits: ``obj.GetType()`` and ``typeof(T)`` (type identity and names for messages
keep working under the linker), ``Properties.GetProperty`` (Bouncy Castle's environment-variable
lookup in util/Properties.cs) and unqualified calls (a member lookup is always ``x.GetMethod(...)``).

    python3 strip/tool/reflection.py --lib <dir>    # exit 0 clean, 1 hits (FAIL lines), 2 usage, 3 I/O
"""

import argparse
import re
import sys
from pathlib import Path

# (label, regex) over blanked code. Member lookups need a receiver: `x.GetMethod(`, not `GetMethod(`.
PATTERNS = [
    ("System.Reflection", r"\bSystem\s*\.\s*Reflection\b"),
    ("System.Linq.Expressions", r"\bSystem\s*\.\s*Linq\s*\.\s*Expressions\b"),
    ("Type lookup by name",
     r"(?<![\w.])(?:(?:global::)?System\s*\.\s*)?Type\s*\.\s*"
     r"(?:GetType|ReflectionOnlyGetType|GetTypeFromProgID|GetTypeFromCLSID)\s*\("),
    # asm.GetType("X"), module.GetType("X"): GetType with an argument (a blanked literal keeps its quotes).
    ("type lookup by name on a receiver", r"(?<!\bType)\.\s*GetType\s*\(\s*[^\s)]"),
    ("Assembly or Module object", r"\.\s*(?:Assembly|Module)\b"),
    ("instance creation", r"(?<!\bActivator\.)\bCreateInstance\s*\(|\bGetUninitializedObject\b"),
    ("Activator", r"\bActivator\b"),
    ("Assembly load or lookup",
     r"\bAssembly\s*\.\s*(?:Load\w*|ReflectionOnlyLoad\w*|UnsafeLoadFrom|Get(?:Executing|Calling|Entry)Assembly)\b"),
    ("assembly enumeration", r"\.\s*(?:GetAssemblies|GetExportedTypes|GetTypes)\s*\("),
    ("runtime generic or array type", r"\bMake(?:GenericType|GenericMethod|ArrayType|ByRefType|PointerType)\b"),
    ("member lookup",
     r"(?P<recv>\w*)\s*\.\s*(?P<member>GetMethods?|GetFields?|GetPropert(?:y|ies)|GetConstructors?|GetMembers?"
     r"|GetEvents?|GetNestedTypes?|GetInterfaces?|GetInterfaceMap|GetTypeInfo|GetRuntime\w+|InvokeMember"
     r"|GetCustomAttributes?|GetGenericTypeDefinition|GetGenericArguments|GetDefaultMembers|FindMembers"
     r"|FindInterfaces)\s*\("),
    ("delegate from reflection", r"\bCreateDelegate\b|\.\s*DynamicInvoke\s*\("),
    ("reflection type",
     r"\b(?:BindingFlags|MethodInfo|MethodBase|FieldInfo|PropertyInfo|ConstructorInfo|MemberInfo|ParameterInfo"
     r"|EventInfo|TypeInfo)\b"),
    ("TypeDescriptor", r"\bTypeDescriptor\b"),
    ("dynamic", r"\bdynamic\b"),
]
# (receiver, member) pairs a member-lookup pattern matches that are not reflection.
ALLOWED_MEMBER_CALLS = {("Properties", "GetProperty")}

_COMPILED = [(label, re.compile(rx)) for label, rx in PATTERNS]


def blank_code(text):
    """`text` with comments and literal contents replaced by spaces; newlines and code are kept.

    Handles // and /* */ comments, "...", @"..." (with ""), $"..." and $@"..." / @$"..." (holes
    stay code, {{ and }} are text, nested strings in holes work) and char literals.
    """
    out = list(text)
    n = len(text)
    i = 0
    # Stack of open interpolated strings: [verbatim, brace depth inside the current hole].
    holes = []

    def blank(a, b):
        for k in range(a, b):
            if out[k] not in "\r\n":
                out[k] = " "

    def scan_string(j, verbatim, interpolated):
        """Index just past the string body starting at j (after the opening quote); blanks text.
        For an interpolated string, stops at a hole opening and returns (index, True)."""
        start = j
        while j < n:
            c = text[j]
            if interpolated and c == "{":
                if j + 1 < n and text[j + 1] == "{":
                    j += 2
                    continue
                blank(start, j)
                return j + 1, True
            if interpolated and c == "}" and j + 1 < n and text[j + 1] == "}":
                j += 2
                continue
            if verbatim:
                if c == '"':
                    if j + 1 < n and text[j + 1] == '"':
                        j += 2
                        continue
                    blank(start, j)
                    return j + 1, False
            else:
                if c == "\\":
                    j += 2
                    continue
                if c == '"' or c == "\n":
                    blank(start, j)
                    return j + 1, False
            j += 1
        blank(start, n)
        return n, False

    def open_string(j, verbatim, interpolated):
        nonlocal i
        j, in_hole = scan_string(j, verbatim, interpolated)
        if in_hole:
            holes.append([verbatim, 0])
        i = j

    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if holes and c == "{":
            holes[-1][1] += 1
            i += 1
        elif holes and c == "}":
            if holes[-1][1] > 0:
                holes[-1][1] -= 1
                i += 1
            else:
                verbatim = holes.pop()[0]
                open_string(i + 1, verbatim, True)
        elif c == "/" and nxt == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif c == "/" and nxt == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            blank(i, j)
            i = j
        elif c == '"':
            open_string(i + 1, False, False)
        elif c in "@$" and nxt == '"':
            open_string(i + 2, c == "@", c == "$")
        elif c in "@$" and nxt in "@$" and nxt != c and i + 2 < n and text[i + 2] == '"':
            open_string(i + 3, True, True)
        elif c == "'":
            j = i + 1
            while j < n and text[j] not in "'\n":
                j += 2 if text[j] == "\\" else 1
            blank(i + 1, min(j, n))
            i = j + 1
        else:
            i += 1
    return "".join(out)


def scan_text(text):
    """[(line, label, match text)] for every reflection symbol in C# source `text`."""
    code = blank_code(text)
    hits = []
    for label, rx in _COMPILED:
        for m in rx.finditer(code):
            if "member" in rx.groupindex and (m.group("recv"), m.group("member")) in ALLOWED_MEMBER_CALLS:
                continue
            hits.append((code.count("\n", 0, m.start()) + 1, label, m.group(0).strip()))
    return sorted(hits)


def scan_dir(lib):
    """[(relative path, line, label, match text)] over every .cs file under `lib`, sorted."""
    root = Path(lib)
    hits = []
    for path in sorted(root.rglob("*.cs")):
        text = path.read_bytes().decode("utf-8-sig", errors="replace")
        rel = path.relative_to(root).as_posix()
        hits += [(rel, *h) for h in scan_text(text)]
    return hits


def main(argv=None):
    ap = argparse.ArgumentParser(description="Fail on reflection symbols in the stripped Lib (#77).")
    ap.add_argument("--lib", required=True, help="the produced Lib tree (strip.sh: <work>/rewritten/lib)")
    a = ap.parse_args(argv)
    if not Path(a.lib).is_dir():
        print(f"reflection.py: not a directory: {a.lib}", file=sys.stderr)
        return 2
    try:
        hits = scan_dir(a.lib)
        files = len(list(Path(a.lib).rglob("*.cs")))
    except OSError as e:
        print(f"reflection.py: {e}", file=sys.stderr)
        return 3
    for rel, line, label, text in hits:
        print(f"FAIL reflection: {rel}:{line}: {label}: {text}")
    print(f"reflection scan: {files} files, {len(hits)} hit(s)")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())

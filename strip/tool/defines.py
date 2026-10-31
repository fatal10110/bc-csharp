"""Define sets for the closure builds (STRIP_PLAN_V2.md §4, issue #6).

- ``parse_unity_defines``: ``strip/unity-defines.txt`` -> {set name: [defines]}. Section names are
  generic; the file holds the captured Unity sets ``[netstandard21]``/``[netframework]`` (#29, #30).
- ``tfm_for_set``: ``netframework`` builds against net471 reference assemblies, every other set
  against netstandard2.1.
- ``render_props``: the generated Closure.props (TargetFramework, DefineConstants, Compile items).
  Defines go through a file because ``-p:DefineConstants=a;b`` fails with MSB1006.
- ``csc_defines`` / ``check_defines``: the binlog assertion set(csc /define:) == captured set,
  ignoring empty entries.
- ``debug_variants``: the DEBUG build of #58 (Unity Editor and Development builds), derived from a
  captured set; build.py builds it, the closure does not see it.
"""

import re
from xml.sax.saxutils import escape

NETFRAMEWORK_SET = "netframework"
NETFRAMEWORK_TFM = "net471"
NETSTANDARD_TFM = "netstandard2.1"

# Symbols the SDK adds on its own; any of them in a csc command line that the set does not list is
# leakage (configuration defines, TRACE, or a -c Strip configuration).
LEAK_SUSPECTS = ("DEBUG", "RELEASE", "STRIP", "TRACE")

# #58: Unity defines DEBUG for every Editor compile and for Development player builds; the Editor
# rsp of TurboHTTP.Transport.BouncyCastle also has TRACE (unity-defines.txt header). The file stays
# the unedited player capture: the variant is derived here, as the captured set plus these symbols,
# for build.py only (builds 3a/3c/consumer and the smoke hook). closure.py never reads it, so the
# kept file list and the budget stay those of the captured sets.
EDITOR_DEFINES = ("DEBUG", "TRACE")
DEBUG_VARIANTS = {"netstandard21_debug": "netstandard21"}  # variant set -> captured set

_SECTION = re.compile(r"^\[([A-Za-z0-9_.-]+)\]$")
_SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CSC_LINE = re.compile(r"\bcsc(?:\.dll|\.exe)?\b.*\s[/-]noconfig\b", re.I)
_DEFINE_SWITCH = re.compile(r"""(?:^|[\s"])[/-]d(?:efine)?:("[^"]*"|[^\s"]+)""")


class DefineError(Exception):
    pass


def split_defines(value):
    """Split a DefineConstants value on ';' and ','; empty entries are dropped."""
    return [d.strip() for d in re.split(r"[;,]", value) if d.strip()]


def parse_unity_defines(text):
    """Parse unity-defines.txt: '[set]' headers, one DefineConstants line per set, '#' comments."""
    sets = {}
    current = None
    for no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _SECTION.match(line)
        if m:
            current = m.group(1)
            if current in sets:
                raise DefineError(f"line {no}: duplicate set [{current}]")
            sets[current] = None
            continue
        if current is None:
            raise DefineError(f"line {no}: defines outside a [set] section")
        if sets[current] is not None:
            raise DefineError(f"line {no}: [{current}] has more than one DefineConstants line")
        defines = split_defines(line)
        bad = [d for d in defines if not _SYMBOL.match(d)]
        if bad:
            raise DefineError(f"line {no}: invalid symbol(s) {bad} in [{current}]")
        if len(set(defines)) != len(defines):
            raise DefineError(f"line {no}: duplicate symbol in [{current}]")
        sets[current] = defines
    empty = [name for name, defines in sets.items() if defines is None]
    if empty:
        raise DefineError(f"set(s) without a DefineConstants line: {empty}")
    if not sets:
        raise DefineError("no define sets")
    return sets


def load_unity_defines(path):
    with open(path, encoding="utf-8") as f:
        return parse_unity_defines(f.read())


def tfm_for_set(name):
    return NETFRAMEWORK_TFM if name == NETFRAMEWORK_SET else NETSTANDARD_TFM


def debug_variants(sets):
    """{variant: captured defines + EDITOR_DEFINES} for every DEBUG variant whose captured set is in sets."""
    out = {}
    for variant, captured in DEBUG_VARIANTS.items():
        if captured in sets:
            defines = list(sets[captured])
            out[variant] = defines + [d for d in EDITOR_DEFINES if d not in defines]
    return out


def _msbuild_escape(value):
    # MSBuild item specs treat %, $, @, ', ; specially; escape them as %XX.
    return "".join(f"%{ord(c):02X}" if c in "%$@';" else c for c in value)


def render_props(tfm, defines, compile_files):
    """Closure.props: exactly these defines (assigned, not appended) and these Compile items."""
    lines = [
        "<Project>",
        "  <PropertyGroup>",
        f"    <TargetFramework>{escape(tfm)}</TargetFramework>",
        f"    <DefineConstants>{escape(';'.join(defines))}</DefineConstants>",
        "  </PropertyGroup>",
        "  <ItemGroup>",
    ]
    for path in compile_files:
        lines.append(f'    <Compile Include="{escape(_msbuild_escape(path), {chr(34): "&quot;"})}" />')
    lines += ["  </ItemGroup>", "</Project>", ""]
    return "\n".join(lines)


def csc_defines(log_text):
    """The /define: set of the csc invocation(s) in a build log (binlog replayed to text).

    Raises DefineError when the log holds no csc command line: an assertion against a build that
    did not compile would pass vacuously.
    """
    found = False
    result = set()
    for line in log_text.splitlines():
        if not _CSC_LINE.search(line):
            continue
        found = True
        for m in _DEFINE_SWITCH.finditer(line):
            result.update(split_defines(m.group(1).strip('"')))
    if not found:
        raise DefineError("no csc command line in the build log (CoreCompile skipped?)")
    return result


def check_defines(name, expected, actual):
    """[] when set(actual) == set(expected) (empty entries ignored), else one message per problem."""
    expected = set(d for d in expected if d)
    actual = set(d for d in actual if d)
    problems = []
    extra = sorted(actual - expected)
    missing = sorted(expected - actual)
    if extra:
        leaks = [d for d in extra if d in LEAK_SUSPECTS]
        note = f" (leakage: {leaks})" if leaks else ""
        problems.append(f"[{name}] csc got defines not in the set: {extra}{note}")
    if missing:
        problems.append(f"[{name}] csc is missing defines of the set: {missing}")
    return problems

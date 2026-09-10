"""The confidentiality gate: four layers detecting normative and identity
content.

This module is dependency-isolated from the rest of the `wayside` package and
uses the Python standard library ONLY. That is a condition, not a preference:
the pre-commit hook has to work in the pre-commit environment (`language:
python`, its own isolated venv) and in the temporary repository of the
integration test, without `uv sync` and without a network - any external
dependency would break both scenarios.

Four layers, from the most to the least precise:

- Layer 0, path (`path-local-corpus`): every path under `standards/.local/` is
  a violation, regardless of content. It works on binary files too (added e.g.
  with `git add -f`) and is NEVER subject to the exception list - it is the
  last line of defence for the worst case: someone trying to bypass the other
  layers outright.
- Layer 1, corpus (`corpus-shingle`): compares the scanned text against the
  local, gitignored `standards/.local` directory through twelve-word shingles
  (sha256 digests, never raw text). It works ONLY when that directory exists on
  the machine - therefore NEVER in CI, because the directory is gitignored and
  does not reach the remote repository. That is an architectural necessity: CI
  cannot be given access to that directory without defeating the purpose of the
  gate (moving the protected content into repository secrets).
- Layer 2, structural (`structural-clause-modal`): a regex for the fingerprint
  of normative language (a dotted clause number plus a normative modal term on
  the same line), working with no corpus at all - therefore in CI too.
- Layer 3, identity (`identity-*`): five rules catching content from the
  employer's network which could leak through ordinary project prose rather
  than through a quotation from a standard - RFC 1918 private addressing
  outside the declared fixtures, a hardware address as a device signature, a
  device name, and the proper name of a project fenced off by a confidentiality
  boundary. The first four are SHAPE rules, built from publicly known industry
  abbreviations and from addressing shapes, never from anyone's inventory
  (ruling R-1, plan 05-03) - a literal list of device names or addresses in a
  public file would disclose exactly the information this layer defends. They
  work with no corpus, therefore in CI too, exactly like layer 2, to which they
  are siblings. The fifth rule, the literal one, works LOCALLY ONLY, from a
  gitignored file (ruling R-2) - it is the sibling of layer 1: a control that
  stays on one machine is a control, not an inconvenience.

Layers 2 and 3 share ONE exception list (`.confidentiality-allow`), in three
distinguishable line forms (a path pattern with no prefix - layer 2;
`identity-value:<value>` - an address declaration of layer 3;
`identity-path:<rule or all>:<pattern>` - a path exemption narrowed to one rule
of layer 3, or to all of them). The exceptions of the two layers are
INDEPENDENT: exempting one rule does not lift another from the same path.

No `Violation` object and no message printed by this module carries the matched
fragment of text - that is a property of the type (`Violation` has no field for
text), not merely a coding convention. A message carries the path, the line
number and the rule identifier only.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "Violation",
    "scan_paths",
    "scan_text_structural",
    "scan_text_corpus",
    "scan_text_identity",
    "scan_files",
    "AllowListShapeError",
    "load_identity_local_literals",
    "main",
]

# --- Stale modulu -----------------------------------------------------------

RULE_PATH_LOCAL_CORPUS = "path-local-corpus"
RULE_CORPUS_SHINGLE = "corpus-shingle"
RULE_STRUCTURAL_CLAUSE_MODAL = "structural-clause-modal"

# Layer 3, identity (D-19, plan 05-03). The order is fixed and closed - the
# classifier of exception list lines (`_identity_path_exceptions`) has to know
# the whole set from the first commit of this layer, otherwise a line referring
# to a rule arriving in a later task would be a shape error today.
RULE_IDENTITY_PRIVATE_IPV4 = "identity-private-ipv4"
RULE_IDENTITY_MAC_ADDRESS = "identity-mac-address"
RULE_IDENTITY_DEVICE_NAME = "identity-device-name"
RULE_IDENTITY_PROJECT_NAME = "identity-project-name"
RULE_IDENTITY_LOCAL_LITERAL = "identity-local-literal"

IDENTITY_RULE_IDS: tuple[str, ...] = (
    RULE_IDENTITY_PRIVATE_IPV4,
    RULE_IDENTITY_MAC_ADDRESS,
    RULE_IDENTITY_DEVICE_NAME,
    RULE_IDENTITY_PROJECT_NAME,
    RULE_IDENTITY_LOCAL_LITERAL,
)

# The two address rules, the only ones honouring value declarations
# (`identity-value:`, assumption Z-93 from plan 05-03): a declaration is a
# statement about the origin of an ADDRESS, never of a device name or a proper
# name - declaring those by value would be a literal list of names in a public
# file, exactly what ruling R-1 forbids.
IDENTITY_ADDRESS_RULE_IDS: tuple[str, ...] = (
    RULE_IDENTITY_PRIVATE_IPV4,
    RULE_IDENTITY_MAC_ADDRESS,
)

# The line prefixes of the identity layer exception list (R-4). A line with
# neither of these prefixes (and with no `identity-` prefix at all) is a path
# pattern of the structural layer, exactly as today.
IDENTITY_VALUE_PREFIX = "identity-value:"
IDENTITY_PATH_PREFIX = "identity-path:"
IDENTITY_PATH_ALL = "all"

# The marker shared by both prefixes above - a line starting with it but
# matching neither of the two is a shape error, not a silent path pattern of
# the structural layer (R-4).
_IDENTITY_LINE_PREFIX = "identity-"

DEFAULT_IDENTITY_LOCAL_FILE = ".confidentiality-identity.local"

DEFAULT_CORPUS_DIR = "standards/.local"
DEFAULT_ALLOW_FILE = ".confidentiality-allow"

LOCAL_CORPUS_PATH_PREFIX = "standards/.local"

# The shingle size (in words) for the corpus layer.
SHINGLE_SIZE = 12

# The fragment length threshold (in characters) for the structural layer.
# Below that threshold a dotted number and a modal term on one line are too
# common (e.g. bullet lists) to be treated as the fingerprint of a normative
# clause.
MIN_STRUCTURAL_FRAGMENT_LENGTH = 60

# The shape of a dotted clause number: exactly digits-dot-digits (optionally
# more segments), so that designations like "62443-3-3" (hyphens, not dots)
# and semantic version numbers do NOT fire the rule on their own - the rule
# fires only in combination with a normative modal term in the same fragment
# (see NORMATIVE_MODAL_TERMS below).
#
# The negative lookbehind on `v`/`V` filters out software version numbers. It
# arrived together with extending NORMATIVE_MODAL_TERMS with "must" and
# "should": extending the modal list alone fired the layer on the project's own
# prose (`.planning/research/PITFALLS.md` writes "CVSS v4.0 ... must be
# reported separately"), because `v4.0` has the shape of a dotted clause
# number. No standard numbers its clauses as `v3.4.2`, so this exclusion costs
# nothing on the detection side.
#
# The narrowing is deliberately incomplete. A sentence pairing an interpreter
# version number with a modal term will still fire the layer - and this
# comment cannot show that example verbatim, because writing it out fires the
# rule described right here (the same Pitfall 2 the address pattern below
# names). For that remainder there is `.confidentiality-allow`, because the
# alternative - guessing whether a dotted number is a version or a clause of a
# standard - is exactly the heuristic that turns a gate into a noise
# generator.
CLAUSE_NUMBER_PATTERN = re.compile(r"(?<![vV])\d+\.\d+(?:\.\d+)*")

# Normative modal terms. A fragment is normalised (lower case, diacritics
# stripped) before comparison, so "nie moze" also catches "nie może", "nalezy"
# catches "należy" and so on - the text of a standard almost certainly carries
# diacritics, and the list below is written without them for the same reason as
# the rest of the repository (character encoding safety).
#
# The Polish terms stay on this list although the project's own prose moved to
# English: the corpus this gate defends is the author's legally purchased
# copies of standards, and those are read in Polish. A gate that only knew
# English modal terms would fall silent on exactly the text it exists to stop.
#
# The order: the negated variant before the affirmative one, so that a match
# returns the longer, more specific term.
#
# English "must" and "should" arrived after a review (CR-02 from
# 01-REVIEW.md): the list carried Polish "musi" and "powinien" from the start
# and their English counterparts not - that was an oversight, not a decision.
# The weight of that gap came from the structural layer being the ONLY one
# working in CI (the corpus by its nature does not exist on the runner), so a
# hole in it was a hole in the whole backstop.
#
# "may" and "can" are deliberately NOT here: in normative language they denote
# permission rather than a requirement, and they appear in ordinary prose often
# enough to turn this layer into a false alarm generator.
NORMATIVE_MODAL_TERMS: tuple[str, ...] = (
    "shall not",
    "shall",
    "must not",
    "must",
    "should not",
    "should",
    "musi",
    "nie moze",
    "powinien",
    "nalezy",
    "wymaga sie",
    "zaleca sie",
)

# A fragment is a structural violation only within a single line - never
# across joined lines. That is a deliberate narrowing: a prose document (the
# README, pyproject.toml) contains plenty of dotted numbers (version numbers)
# and single modal words scattered across the file; if layer 2 joined content
# across line boundaries looking for a "sentence", false alarms on the
# project's own documentation would be the rule, not the exception (see threat
# T-1-guard-false-positive in PLAN.md). A dot between digits (a clause number)
# never ends a fragment - hence the negative lookarounds below.
_SENTENCE_TERMINATOR_RE = re.compile(r"(?<!\d)[.!?](?!\d)")

# RFC 1918 private addressing: the whole first range (a /8 mask), the second
# range narrowed to the proper span of the second octet (a /12 mask), the third
# range (a /16 mask) - the three ranges from the RFC 1918 document itself,
# written here as a rule, never as a literal example (Pitfall 2 of the phase
# research: an illustrative example of one's own in a gate comment fires the
# gate's own rule). Matching runs over text normalised by
# `scan_text_identity` (digits and dots are insensitive to
# diacritics/case, so that does not change the match, it only keeps one
# normalisation path).
#
# The negative lookbehind `(?<![\d.])` filters out a component inside a longer
# run of digits and dots (e.g. a five-part version number, where without that
# narrowing the last four parts starting with "10." would be caught as a
# separate address) - a measurement from the fact table of plan 05-03: the
# pattern from the research (Pattern 3) did not have it. The right-hand
# delimiter `(?!\d)` filters out ONLY a following digit, NOT a dot - an
# address at the end of a sentence ends with a dot, and that is valid
# notation which still has to produce a violation.
PRIVATE_IPV4_PATTERN = re.compile(
    r"(?<![\d.])"
    r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})"
    r"(?!\d)"
)

# A hardware address: six groups of two hexadecimal digits separated by ONE
# AND THE SAME separator (a colon or a hyphen), with a word boundary on both
# sides. The requirement of an identical separator across the whole match goes
# through a backreference to the capturing group `\1`, not through an
# alternation of two whole patterns - "de:ad-be:ef:00:01" (mixed separators) is
# therefore NOT a match.
#
# Exactly six groups, no fewer and no more: a shorter run of that shape (three
# groups separated by colons) is a time in a timestamp ("20:18:15"), and a
# longer one is not a hardware address.
#
# The reading of the word "signatures" from criterion 4 of the phase (ruling
# R-3, plan 05-03): a hardware address is a device signature of a strictly
# defined shape, it leaks from every traffic capture, and that is exactly the
# domain this tool works in (identifying a vendor from the OUI registry).
# Signatures of other kinds (serial numbers, internal document numbers) are
# covered by the fifth, local rule (05-03/3) - their shape is specific to an
# organisation, so writing it into a public file would be the very leak R-1
# speaks of.
MAC_ADDRESS_PATTERN = re.compile(
    r"\b[0-9a-f]{2}([:-])(?:[0-9a-f]{2}\1){4}[0-9a-f]{2}\b"
)

# A closed set of publicly known industry abbreviations for OT/ICS and network
# device roles (ruling R-1, plan 05-03) - NEVER anyone's inventory. Every
# abbreviation stands in any automation or networking textbook: PLC
# (programmable logic controller), RTU (remote terminal unit), HMI (human
# machine interface), IED (intelligent electronic device), MTU (master
# terminal unit), DCS (distributed control system), SCADA (supervisory control
# and data acquisition), EWS (engineering workstation), OWS (operator
# workstation), VFD (variable frequency drive), IPC (industrial PC), RBC (radio
# block centre, ETCS), LEU (lineside electronic unit, railway signalling), SW
# (switch), FW (firewall), AP (access point).
DEVICE_ROLE_PREFIXES: tuple[str, ...] = (
    "PLC",
    "RTU",
    "HMI",
    "IED",
    "MTU",
    "DCS",
    "SCADA",
    "EWS",
    "OWS",
    "VFD",
    "IPC",
    "RBC",
    "LEU",
    "SW",
    "FW",
    "AP",
)

# A prefix from the closed set, then a MANDATORY separator (a hyphen or an
# underscore), then one to four digits, with a word boundary on both sides. The
# separator is MANDATORY, not cosmetic: the variant without it produced (during
# planning) one hit on the name of an output directory in a phase 3 planning
# artifact - a false alarm that would have bought an exemption instead of
# detection, rather than simply requiring a separator.
DEVICE_NAME_PATTERN = re.compile(
    r"\b(?:" + "|".join(p.casefold() for p in DEVICE_ROLE_PREFIXES) + r")"
    r"[-_]\d{1,4}\b"
)

# The proper name of a project fenced off by a confidentiality boundary (D-23
# of the publication phase). Matching runs over text ALREADY normalised by
# `scan_text_identity` (diacritics folded, case stripped), so the pattern below
# is written in normalised form (lower case). Between the two words of the name
# ANY run of whitespace, hyphens or underscores is allowed, INCLUDING AN EMPTY
# ONE - the concatenated form (the second word directly after the first) is the
# most common shape of a proper name in identifiers and file names, and that is
# exactly where proper names leak most often. The pattern itself has to carry
# both words of the name as a literal to match anything at all - that is why
# THIS file (and only this file) needs its own exemption in
# `.confidentiality-allow` (assumption Z-96): assembling the literal from parts
# at runtime would be a way around the gate with no change in behaviour, not a
# smaller leak.
PROJECT_NAME_PATTERN = re.compile(r"railguard[\s\-_]*sentinel")


class AllowListShapeError(ValueError):
    """A `.confidentiality-allow` line of unrecognised shape: an
    unrecognised `identity-` prefix, or a rule name in `identity-path:`
    outside the closed set `IDENTITY_RULE_IDS` (plus `IDENTITY_PATH_ALL`).

    Without this exception a typo in the prefix or in the rule name would
    quietly turn into a structural layer path pattern over a file with a
    strange name - that is, into an exemption nobody intended (R-4, plan
    05-03).
    """


@dataclass(frozen=True)
class Violation:
    """One violation of the confidentiality gate.

    There is deliberately NO field for the matched text - that is a hard
    property of the type, not a recommendation. A leak of this class (a matched
    fragment of normative content or of the local corpus in the hook/CI output)
    is then impossible by construction.
    """

    path: str
    line: int | None
    layer: str
    rule_id: str
    reason: str


def _normalize_path_str(path: str) -> str:
    """Normalises path separators to `/`, regardless of platform."""
    return path.replace("\\", "/")


def _fold_path_for_match(path: str) -> str:
    """Normalises a path for comparison - layer 0 and the exception list.

    Beyond separators it also strips case. Without that, layer 0 can be
    bypassed by changing case alone: the only supported platform is Windows,
    whose NTFS is case-insensitive, while git records the literal form of the
    path in its index. `git add -f Standards/.local/x.txt` therefore adds
    exactly the same file from disk, and a case-sensitive comparison does not
    see it (CR-01 from 01-REVIEW.md, confirmed by running it, not by reading).

    `casefold()` rather than `lower()`, because it is stricter for characters
    outside ASCII, and a directory name need not stay purely English forever.
    """
    return _normalize_path_str(path).casefold()


def _strip_diacritics(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch))


def scan_paths(paths: list[str]) -> list[Violation]:
    """Layer 0: a path under `standards/.local/` is always a violation.

    It works on the path alone (it does not read file content), so it also
    covers binary files and files that do not yet exist on disk. There is no
    exception list here - this is the only layer that cannot be bypassed with
    an entry in `.confidentiality-allow`.
    """
    violations: list[Violation] = []
    for raw_path in paths:
        normalized = _fold_path_for_match(raw_path)
        folded_prefix = LOCAL_CORPUS_PATH_PREFIX.casefold()
        if normalized == folded_prefix or normalized.startswith(folded_prefix + "/"):
            violations.append(
                Violation(
                    path=raw_path,
                    line=None,
                    layer="path",
                    rule_id=RULE_PATH_LOCAL_CORPUS,
                    reason=(
                        "The path points at the local standards corpus "
                        "(standards/.local), which must never reach the "
                        "repository."
                    ),
                )
            )
    return violations


def _iter_structural_fragments(line: str) -> list[str]:
    """Splits a single line into fragments delimited by sentence terminators."""
    fragments: list[str] = []
    start = 0
    for match in _SENTENCE_TERMINATOR_RE.finditer(line):
        end = match.end()
        fragment = line[start:end].strip()
        if fragment:
            fragments.append(fragment)
        start = end
    tail = line[start:].strip()
    if tail:
        fragments.append(tail)
    return fragments


def scan_text_structural(text: str, path: str) -> list[Violation]:
    """Layer 2: a dotted clause number plus a normative modal term on a
    line.

    It works with no corpus at all - therefore in CI too. A fragment is a
    violation when it simultaneously: carries the shape of a clause number,
    carries one of the terms from `NORMATIVE_MODAL_TERMS`, has both matches
    inside the same fragment (line), and is at least
    `MIN_STRUCTURAL_FRAGMENT_LENGTH` characters long.
    """
    violations: list[Violation] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for fragment in _iter_structural_fragments(line):
            if len(fragment) < MIN_STRUCTURAL_FRAGMENT_LENGTH:
                continue
            if not CLAUSE_NUMBER_PATTERN.search(fragment):
                continue
            normalized = _strip_diacritics(fragment).lower()
            if not any(term in normalized for term in NORMATIVE_MODAL_TERMS):
                continue
            violations.append(
                Violation(
                    path=path,
                    line=line_no,
                    layer="structural",
                    rule_id=RULE_STRUCTURAL_CLAUSE_MODAL,
                    reason=(
                        "The fragment carries both the shape of a clause "
                        "number and a normative modal term on the same line."
                    ),
                )
            )
    return violations


_WORD_RE = re.compile(r"\w+", re.UNICODE)


def _tokenize_with_lines(text: str) -> list[tuple[str, int]]:
    """Normalises text into a list of (word, line_number): lower case, no
    punctuation (`\\w+` skips it), collapsed whitespace (every word is already
    a separate token)."""
    tokens: list[tuple[str, int]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        lowered = line.lower()
        for match in _WORD_RE.finditer(lowered):
            tokens.append((match.group(0), line_no))
    return tokens


def _iter_shingles(
    tokens: list[tuple[str, int]], size: int = SHINGLE_SIZE
) -> list[tuple[str, int]]:
    """Returns (shingle text, line number of the first word) for every
    window of `size` words in `tokens`."""
    words = [word for word, _line in tokens]
    lines = [line for _word, line in tokens]
    shingles: list[tuple[str, int]] = []
    for i in range(len(words) - size + 1):
        shingles.append((" ".join(words[i : i + size]), lines[i]))
    return shingles


def _corpus_shingle_hashes(corpus_dir: Path) -> set[str]:
    hashes: set[str] = set()
    for file_path in sorted(p for p in corpus_dir.rglob("*") if p.is_file()):
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        tokens = _tokenize_with_lines(content)
        for shingle_text, _line in _iter_shingles(tokens):
            hashes.add(hashlib.sha256(shingle_text.encode("utf-8")).hexdigest())
    return hashes


def scan_text_corpus(text: str, path: str, corpus_dir: Path) -> list[Violation]:
    """Layer 1: twelve-word shingles against the local corpus.

    The source of comparison is `corpus_dir` ONLY. When the directory does not
    exist or is empty, it prints an unambiguous sentence on stderr saying the
    layer did not run, and returns an empty list - a clean result without the
    corpus layer having run must not look the same as a clean result with it,
    so that message is part of the contract, not cosmetics.
    """
    if not corpus_dir.is_dir():
        print(
            f"[confidentiality-guard] Corpus layer SKIPPED: the corpus "
            f"directory '{corpus_dir}' does not exist on this machine. This "
            f"result does NOT confirm a comparison against the local corpus.",
            file=sys.stderr,
        )
        return []

    corpus_hashes = _corpus_shingle_hashes(corpus_dir)
    if not corpus_hashes:
        print(
            f"[confidentiality-guard] Corpus layer SKIPPED: the corpus "
            f"directory '{corpus_dir}' is empty. This result does NOT confirm "
            f"a comparison against the local corpus.",
            file=sys.stderr,
        )
        return []

    tokens = _tokenize_with_lines(text)
    violations: list[Violation] = []
    seen_lines: set[int] = set()
    for shingle_text, line_no in _iter_shingles(tokens):
        digest = hashlib.sha256(shingle_text.encode("utf-8")).hexdigest()
        if digest not in corpus_hashes:
            continue
        if line_no in seen_lines:
            continue
        seen_lines.add(line_no)
        violations.append(
            Violation(
                path=path,
                line=line_no,
                layer="corpus",
                rule_id=RULE_CORPUS_SHINGLE,
                reason=(
                    "A twelve-word fragment overlapping with the local "
                    "standards corpus was detected."
                ),
            )
        )
    return violations


def load_identity_local_literals(local_file: Path) -> tuple[str, ...]:
    """Loads the literals of the fifth rule of layer 3
    (`identity-local-literal`) from a LOCAL, gitignored file absent from CI
    (ruling R-2) - the sibling of layer 1 (the corpus layer), which works on
    the same principle.

    It skips empty lines and lines starting with `#`, and strips surrounding
    whitespace. When the file is absent it prints a warning on standard error
    and returns an empty tuple - the silent absence of this control is worse
    than the noise, exactly as with a missing corpus directory (layer 1). When
    the file exists but carries no literal at all, it returns an empty tuple
    and does NOT warn (assumption Z-94): a file of comments alone is an
    explicit statement of "no local literals", an exit route that is not a
    disabling of the layer.
    """
    if not local_file.is_file():
        print(
            f"[confidentiality-guard] The local literals file '{local_file}' "
            "does not exist on this machine. The literal rule of the identity "
            "layer (identity-local-literal) did NOT run.",
            file=sys.stderr,
        )
        return ()
    literals: list[str] = []
    for raw_line in local_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        literals.append(line)
    return tuple(literals)


def _load_allow_patterns(allow_file: Path) -> list[str]:
    """Loads `fnmatch` patterns from the structural layer exception file.

    Empty lines and lines starting with `#` are skipped. A missing file means
    no exceptions (not an error) - the CLI calls a default path which need not
    exist.
    """
    if not allow_file.is_file():
        return []
    patterns: list[str] = []
    for raw_line in allow_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append(line)
    return patterns


def _matches_allow_list(path: str, allow_patterns: list[str]) -> bool:
    """Checks a path against the structural layer exception patterns.

    The comparison is case-insensitive BY DESIGN, exactly as in layer 0 - the
    target platform is Windows, whose NTFS is case-insensitive. `fnmatch.fnmatch`
    alone would give that effect only on Windows, because it strips case
    through `os.path.normcase`; the same exception list would behave
    differently on Linux. An explicit `casefold()` plus `fnmatchcase` gives one
    result on every platform and closes the divergence from layer 0 described
    in WR-03 of 01-REVIEW.md.
    """
    normalized = _fold_path_for_match(path)
    return any(
        fnmatch.fnmatchcase(normalized, pattern.casefold())
        for pattern in allow_patterns
    )


# --- Classifiers of `.confidentiality-allow` lines (R-4, assumption Z-91) ---
#
# `_load_allow_patterns` above stays UNTOUCHED - neither its signature nor its
# behaviour: an existing regression test over the tracked tree calls that
# function and passes its result on, so changing the return type would break
# that test for no gain. The three functions below classify its raw result (a
# list of lines without comments and blank lines) into three distinguishable
# forms, each testable on its own.


def _structural_allow_patterns(lines: list[str]) -> list[str]:
    """Lines WITHOUT an identity prefix: path patterns of the structural
    layer (layer 2), exactly as today."""
    return [line for line in lines if not line.startswith(_IDENTITY_LINE_PREFIX)]


def _normalize_identity_value(raw: str) -> str:
    """Normalises an address value into a comparable form: lower case
    (through `_strip_diacritics` + `casefold`, like the rest of the module),
    and - for the hardware address shape only - replacing hyphens with colons.

    Without that normalisation the same hardware address written with two
    separators (a hyphen and a colon) lands on the declared value list as TWO
    different values, and the declaration completeness test has no way to
    settle it (a measurement from the fact table of plan 05-03: the same value
    stands in the tree written with both separators).
    """
    folded = _strip_diacritics(raw).casefold().strip()
    if MAC_ADDRESS_PATTERN.fullmatch(folded):
        folded = folded.replace("-", ":")
    return folded


def _identity_declared_values(lines: list[str]) -> frozenset[str]:
    """Lines `identity-value:<value>`: address declarations of layer 3,
    holding across the whole tree regardless of file (assumption Z-93: a
    declaration is a statement about the origin of an ADDRESS, never of a
    device name or a proper name).

    Every value is normalised (`_normalize_identity_value`) before being added
    to the set. A value which after normalisation matches NEITHER of the two
    address shapes (RFC 1918, a hardware address) raises
    `AllowListShapeError` - a declaration is an inventory of addressing, not
    arbitrary text (ruling R-5).
    """
    values: set[str] = set()
    for line in lines:
        if not line.startswith(IDENTITY_VALUE_PREFIX):
            continue
        raw_value = line[len(IDENTITY_VALUE_PREFIX) :].strip()
        normalized = _normalize_identity_value(raw_value)
        if not (
            PRIVATE_IPV4_PATTERN.fullmatch(normalized)
            or MAC_ADDRESS_PATTERN.fullmatch(normalized)
        ):
            raise AllowListShapeError(
                f"{DEFAULT_ALLOW_FILE}: the declaration '{raw_value}' matches "
                "neither of the two address shapes (RFC 1918 or a hardware "
                "address)."
            )
        values.add(normalized)
    return frozenset(values)


def _identity_path_exceptions(lines: list[str]) -> dict[str, list[str]]:
    """Lines `identity-path:<rule or all>:<pattern>`: path exemptions
    narrowed to ONE rule of layer 3, or - with the word `IDENTITY_PATH_ALL` -
    to all rules at once (R-4). The key of the returned dictionary is a rule
    identifier (or `IDENTITY_PATH_ALL`); the value is the list of path
    patterns recorded for that key.

    A line starting with `identity-` that matches neither of the two known
    prefixes, and an `identity-path:` line with a rule name outside the closed
    set (and different from `all`), raise `AllowListShapeError` - without that
    branch a typo in the prefix or in the rule name would quietly turn into a
    structural layer path pattern over a file with a strange name.
    """
    known_rule_names = set(IDENTITY_RULE_IDS) | {IDENTITY_PATH_ALL}
    exceptions: dict[str, list[str]] = {}
    for line in lines:
        if line.startswith(IDENTITY_PATH_PREFIX):
            remainder = line[len(IDENTITY_PATH_PREFIX) :]
            rule_name, separator, pattern = remainder.partition(":")
            if not separator:
                raise AllowListShapeError(
                    f"{DEFAULT_ALLOW_FILE}: the line '{line}' carries the "
                    f"prefix '{IDENTITY_PATH_PREFIX}' but the separator between "
                    "the rule name and the path pattern is missing."
                )
            if rule_name not in known_rule_names:
                raise AllowListShapeError(
                    f"{DEFAULT_ALLOW_FILE}: the rule name '{rule_name}' in "
                    f"the line '{line}' is outside the closed set "
                    f"{sorted(known_rule_names)}."
                )
            exceptions.setdefault(rule_name, []).append(pattern)
        elif line.startswith(IDENTITY_VALUE_PREFIX):
            continue
        elif line.startswith(_IDENTITY_LINE_PREFIX):
            raise AllowListShapeError(
                f"{DEFAULT_ALLOW_FILE}: the line '{line}' starts with the "
                "identity marker but matches no recognised prefix "
                f"('{IDENTITY_VALUE_PREFIX}', '{IDENTITY_PATH_PREFIX}')."
            )
    return exceptions


def _identity_rule_is_suppressed(
    path: str, rule_id: str, exceptions: dict[str, list[str]]
) -> bool:
    """Checks whether `rule_id` is exempted for `path`: the patterns recorded
    explicitly for that rule AND the patterns recorded for all rules at once
    (`IDENTITY_PATH_ALL`). It uses the same path matching mechanism as layer 2
    (`_matches_allow_list`), so that case insensitivity is one and the same for
    the whole file (assumption Z-92) - the exceptions of the two layers stay
    independent, because each is applied at a separate place in the file
    scanning function.
    """
    patterns = exceptions.get(rule_id, []) + exceptions.get(IDENTITY_PATH_ALL, [])
    if not patterns:
        return False
    return _matches_allow_list(path, patterns)


def scan_text_identity(
    text: str,
    path: str,
    *,
    declared_values: frozenset[str] = frozenset(),
    local_literals: tuple[str, ...] = (),
) -> list[Violation]:
    """Layer 3: identity patterns.

    It works with no corpus at all - therefore in CI too, like layer 2, to
    which it is a sibling. The four shape rules work always, EVERYWHERE: RFC
    1918 private addressing outside `declared_values`, a hardware address
    outside `declared_values`, a device name, and the proper name of the fenced
    off project (`RULE_IDENTITY_PROJECT_NAME`) - built from publicly known
    industry abbreviations and from addressing shapes, never from anyone's
    inventory (ruling R-1). The fifth, literal rule (`local_literals`) works
    LOCALLY ONLY, from a gitignored file (ruling R-2) - it is the most
    sensitive of the five, because its input is exactly the content the whole
    gate defends, so its reason field (like all the others) carries neither the
    literal nor a fragment of the line.

    Violations are returned sorted by line number, and within the same line
    number by rule identifier - an order stable between runs, so that CI output
    can be compared (probe: ordering).
    """
    violations: list[Violation] = []
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        normalized = _strip_diacritics(raw_line).casefold()

        for match in PRIVATE_IPV4_PATTERN.finditer(normalized):
            value = _normalize_identity_value(match.group(0))
            if value in declared_values:
                continue
            violations.append(
                Violation(
                    path=path,
                    line=line_no,
                    layer="identity",
                    rule_id=RULE_IDENTITY_PRIVATE_IPV4,
                    reason=(
                        "The line carries an address shaped like RFC 1918 "
                        "private addressing, undeclared in "
                        ".confidentiality-allow."
                    ),
                )
            )

        for match in MAC_ADDRESS_PATTERN.finditer(normalized):
            value = _normalize_identity_value(match.group(0))
            if value in declared_values:
                continue
            violations.append(
                Violation(
                    path=path,
                    line=line_no,
                    layer="identity",
                    rule_id=RULE_IDENTITY_MAC_ADDRESS,
                    reason=(
                        "The line carries a run shaped like a hardware "
                        "address (a device signature), undeclared in "
                        ".confidentiality-allow."
                    ),
                )
            )

        for _match in DEVICE_NAME_PATTERN.finditer(normalized):
            violations.append(
                Violation(
                    path=path,
                    line=line_no,
                    layer="identity",
                    rule_id=RULE_IDENTITY_DEVICE_NAME,
                    reason=(
                        "The line carries a run shaped like a device name "
                        "(a role prefix, a separator, digits)."
                    ),
                )
            )

        if PROJECT_NAME_PATTERN.search(normalized):
            violations.append(
                Violation(
                    path=path,
                    line=line_no,
                    layer="identity",
                    rule_id=RULE_IDENTITY_PROJECT_NAME,
                    reason=(
                        "The line carries the name of a project fenced off "
                        "by a confidentiality boundary (decision record D-23, "
                        "the publication phase)."
                    ),
                )
            )

        for literal in local_literals:
            normalized_literal = _strip_diacritics(literal).casefold()
            if normalized_literal and normalized_literal in normalized:
                violations.append(
                    Violation(
                        path=path,
                        line=line_no,
                        layer="identity",
                        rule_id=RULE_IDENTITY_LOCAL_LITERAL,
                        reason=(
                            "The line carries a literal from the local "
                            "identity list "
                            f"({DEFAULT_IDENTITY_LOCAL_FILE})."
                        ),
                    )
                )

    violations.sort(key=lambda v: (v.line, v.rule_id))
    return violations


def scan_files(
    paths: list[str],
    corpus_dir: Path,
    use_corpus: bool,
    allow_patterns: list[str] | None = None,
    identity_local_file: Path | None = None,
) -> list[Violation]:
    """Runs all four layers over a list of paths.

    Layer 0 works on every path in the list, including files that cannot be
    read as text (binary ones) - that is the only way
    `standards/.local/file.bin` added with `git add -f` gets caught. Layers 1,
    2 and 3 work only on files readable as UTF-8 text.

    `allow_patterns` carries the RAW `.confidentiality-allow` lines
    (`_load_allow_patterns`, unchanged) in three forms: a path pattern with no
    prefix goes to layer 2 (`_structural_allow_patterns`); `identity-value:`
    goes to the address declarations of layer 3 (`_identity_declared_values`);
    `identity-path:` goes to the path exemptions of layer 3
    (`_identity_path_exceptions`). The exceptions of the two layers are
    INDEPENDENT - each is applied at a separate place below (assumption Z-92),
    so exempting one rule does not lift another from the same path.

    `identity_local_file` points at the local literals file of the fifth rule
    (`load_identity_local_literals`); with `None` the default path is used
    (`DEFAULT_IDENTITY_LOCAL_FILE`), so every existing call without that
    argument stays correct unchanged.
    """
    allow_patterns = allow_patterns or []
    structural_patterns = _structural_allow_patterns(allow_patterns)
    declared_values = _identity_declared_values(allow_patterns)
    identity_path_exceptions = _identity_path_exceptions(allow_patterns)
    local_literals = load_identity_local_literals(
        identity_local_file
        if identity_local_file is not None
        else Path(DEFAULT_IDENTITY_LOCAL_FILE)
    )

    violations: list[Violation] = []

    violations.extend(scan_paths(paths))

    for raw_path in paths:
        path_obj = Path(raw_path)
        if not path_obj.is_file():
            continue
        try:
            text = path_obj.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            # A binary file, or one unreadable as text - layers 1, 2 and 3 by
            # definition work on textual content, so they are skipped here.
            # Layer 0 already covered it above, if the path called for it.
            continue

        if use_corpus:
            violations.extend(scan_text_corpus(text, raw_path, corpus_dir))

        if not _matches_allow_list(raw_path, structural_patterns):
            violations.extend(scan_text_structural(text, raw_path))

        for violation in scan_text_identity(
            text,
            raw_path,
            declared_values=declared_values,
            local_literals=local_literals,
        ):
            if _identity_rule_is_suppressed(
                raw_path, violation.rule_id, identity_path_exceptions
            ):
                continue
            violations.append(violation)

    return violations


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="confidentiality_guard",
        description=(
            "The confidentiality gate: detects verbatim normative text and "
            "files from under the local standards/.local corpus."
        ),
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Paths to check (usually the staged files from pre-commit).",
    )
    parser.add_argument(
        "--corpus-dir",
        default=DEFAULT_CORPUS_DIR,
        help=f"The local standards corpus directory (default {DEFAULT_CORPUS_DIR}).",
    )
    parser.add_argument(
        "--no-corpus",
        action="store_true",
        help="Skip the corpus layer (CI mode, which by design has no access to the corpus).",
    )
    parser.add_argument(
        "--allow-file",
        default=DEFAULT_ALLOW_FILE,
        help=f"The file of exception patterns for the structural layer (default {DEFAULT_ALLOW_FILE}).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print violations as JSON instead of one line per violation.",
    )
    parser.add_argument(
        "--identity-local-file",
        default=DEFAULT_IDENTITY_LOCAL_FILE,
        help=(
            "The local literals file of the identity layer, LOCAL and "
            f"gitignored, absent from CI (default {DEFAULT_IDENTITY_LOCAL_FILE})."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    corpus_dir = Path(args.corpus_dir)
    allow_file = Path(args.allow_file)
    allow_patterns = _load_allow_patterns(allow_file)
    identity_local_file = Path(args.identity_local_file)

    violations = scan_files(
        paths=args.paths,
        corpus_dir=corpus_dir,
        use_corpus=not args.no_corpus,
        allow_patterns=allow_patterns,
        identity_local_file=identity_local_file,
    )

    if args.json:
        payload = [
            {
                "path": v.path,
                "line": v.line,
                "layer": v.layer,
                "rule_id": v.rule_id,
                "reason": v.reason,
            }
            for v in violations
        ]
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for v in violations:
            line_part = str(v.line) if v.line is not None else "?"
            print(f"{v.path}:{line_part}: [{v.rule_id}] {v.reason}")

    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())

# Wayside

[![CI](https://github.com/oliver-dolski/wayside/actions/workflows/ci.yml/badge.svg)](https://github.com/oliver-dolski/wayside/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Wayside is a passive security assessment tool for OT/ICS networks: it takes a
traffic capture (pcap) as input and returns an asset inventory, a
communication map and a list of findings, where every finding carries a
citation to a specific standard clause. The tool never sends a single packet
to the network - every read happens from a file.

## What a finding looks like

This is a real block from [`examples/4sics/report.md`](examples/4sics/report.md),
generated from a public dataset:

```text
### Use of an industrial protocol without an authentication mechanism in the observed communication

- Check identifier: `unauthenticated-industrial-protocol`
- Severity: high (risk: serious)
- Session parties: 192.168.2.44:58597 -> 192.168.88.50:502
- Evidence: packet no. 29, session no. 1
- Standard citation: IEC-62443-3-3 SR 1.2
  - Clause scope (own description, not a title from the copy): Software process
    and device identification and authentication
  - Status: **PROVISIONAL, UNVERIFIED** (The clause numbering and the paraphrase
    text await collation against a legal copy of IEC 62443-3-3.)
- Remediation: Restrict at the network level the set of hosts that may open a
  session to the controller at all, through segmentation and access control
  lists. The protocol itself cannot be authenticated without replacing devices
  or without an intermediary layer.
```

Three things in that block are the point of the whole project:

- The finding states **observed behaviour**, never a verdict on whether the
  installation complies with a standard. That verdict belongs to an auditor
  with a copy of the standard in hand, not to a tool reading a capture.
- The citation carries a **verification marker**. The numbering above has not
  been collated against a purchased copy of IEC 62443-3-3, so the report says
  so in capital letters instead of looking confident.
- Every inventory field carries its **provenance** - `observed`,
  `inferred:<method>` or `not-derivable-passively`. A field that cannot be
  established from a passive capture is a visible row saying exactly that,
  never a silently omitted one.

## Intended Use

The tool reads only a traffic capture file; under `src/wayside` there is not a
single import of a networking module, which the test
`tests/test_oui.py::test_no_network_module_imports_under_src_wayside` enforces.
The boundary of that proof is named outright in the same paragraph: the gate
guards imports in the source code, not the actual absence of traffic at
runtime, so it proves the tool has NO WAY to send a packet, not that it did not
send one.

### What it is for

- A point-in-time security assessment from an existing traffic capture.
- An inventory of observed devices.
- A communication matrix.
- Findings with a citation to a standard clause.
- Material for a report to the system owner.

### What it is not for

- It is not continuous network monitoring.
- It is not an active scanner or a penetration testing tool.
- It does not issue a verdict on whether an installation meets the
  requirements of a standard.
- It does not give a numeric security level.

### Condition of use

A traffic capture from someone else's network may be analysed only with the
consent of the owner of that network. The tool does not check that consent and
cannot check it - the passivity of the tool is not an answer to the question of
whether possessing the capture is lawful.

## Getting started

Prerequisites: Windows 11, Windows PowerShell 5.1, git. Wireshark, tshark and a
capture driver (Npcap) are not needed.

One command after cloning:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\bootstrap.ps1
```

The last step of that command installs the pre-commit hook
(`uv run pre-commit install`). It is a separate step because git deliberately
does NOT copy `.git/hooks/*` on clone (a hook in someone else's repository
could execute arbitrary code on the first commit) - without that step the
confidentiality gate described below exists as code but never runs.

## Usage

```powershell
uv run wayside inspect <file.pcap>
uv run wayside analyze <file.pcap> --out-dir wayside-out
```

The `analyze` command writes `analysis.json` (the machine-readable model) and
`report.md` (a markdown report) into the output directory. The `--pdf` flag
adds a third artifact, `report.pdf`, with an embedded Unicode font (DejaVu
Sans): in the text layer of the PDF every character outside ASCII - vendor
names from the IEEE registry are the routine case - appears as a single,
composed code point, regardless of the fonts installed on the system. The
boundary of that claim: how the document looks in a specific PDF reader has not
been confirmed visually on multiple machines (the author's private uncertainty
register, entries 12 and 13). The flag is off by default: the tool's default
path does not gain a new runtime dependency because of it.

```powershell
uv run wayside analyze <file.pcap> --pdf --out-dir wayside-out
```

## Example report

The directory [`examples/4sics/`](examples/4sics/) carries a complete example
report (`analysis.json`, `report.md`, `report.pdf`) generated from the public
4SICS Geek Lounge dataset.

The traffic comes from the 4SICS Geek Lounge lab (2015), made publicly
available by Netresec (https://www.netresec.com/) with the permission of
CS3Sthlm (successor to the 4SICS conference) to share the captured traffic.

Dataset page: [https://www.netresec.com/?page=PCAP4SICS](https://www.netresec.com/?page=PCAP4SICS).
The report is reproducible from the fetch script - no capture file from that
dataset is tracked by git. Details, full attribution and the domain boundary
stand in [`examples/4sics/README.md`](examples/4sics/README.md).

## Confidentiality gate

Every `git commit` passes through `scripts/confidentiality_guard.py` in four
layers:

1. **Path** - every file under `standards/.local/` is rejected, regardless of
   content, even when it was added with `git add -f`.
2. **Corpus** - compares the committed content against the local, gitignored
   `standards/.local` directory (twelve-word shingles, sha256 digests, never
   raw text). Works LOCALLY ONLY, where that directory can exist.
3. **Structural** - a regex for the fingerprint of normative language (a dotted
   clause number plus a normative modal term on the same line). Works with no
   corpus at all, so it works in CI too.
4. **Identity** - five rules catching content from the employer's network
   rather than the content of a standard: RFC 1918 private addressing, a
   hardware address as a device signature, a device name, and the proper name
   of a project fenced off by the author's confidentiality boundary. Those four
   are SHAPE rules, built from publicly known industry abbreviations and from
   addressing shapes, never from anyone's inventory, and they work with no
   local material, hence also in CI. The fifth rule is literal and works
   LOCALLY ONLY, from a gitignored file. An address present in the repository
   has to be declared by value together with its origin in
   `.confidentiality-allow` - an undeclared address fires the gate regardless
   of the file it sits in.

The `standards/.local` directory never leaves the author's machine - it is
gitignored and it **must not** be uploaded to repository secrets or to any CI
configuration, because that would defeat the purpose of this gate.

**The boundaries, named outright rather than passed over in silence:**

- The local hook is a preventive layer ONLY for commits made normally. It is
  bypassed deliberately with `git commit --no-verify` - that is a property of
  every local git hook, not a hole in this implementation.
- The layer running in CI is **detective, not preventive** - it detects after
  the fact (after `git push` has already happened) and does not stop the
  content from being sent. CI also has no access to `standards/.local`
  (gitignored), so in CI only the structural layer and the four shape rules of
  the identity layer are active.
- The fifth rule of the identity layer, the literal one, works LOCALLY ONLY -
  the file with the literals is gitignored and **must not** be uploaded to
  repository secrets or to CI configuration, because that would defeat the
  purpose of the layer it defends exactly as uploading the standards corpus
  would defeat layer 2. Its absence is reported as a warning on standard error,
  never passed over in silence.

## Citation verification status

Every finding carries a citation to a standard clause together with the
designation and edition, and every citation also carries the information of
whether the numbering of that clause has been collated against a legal copy of
the document.

IEC 62443-3-3: at the time of writing a copy is NOT PURCHASED, so the numbering
of every clause of that document in the standards catalogue is provisional, and
every citation to it carries the marker `verified: no` - the document is paid
for. The path to resolution and the split between the two documents are
described in
`docs/decisions/0006-verification-of-citations-against-a-copy-of-the-standard.md`.

CLC/TS 50701:2023: the designation and edition are confirmed at the source
(`docs/decisions/0004-clc-ts-50701-designation.md`); the clause numbering is not
confirmed and by design will not be, because the project does not buy that
copy. The document has the status of a technical specification, not a European
standard, so it is applied voluntarily. The clause field of both entries for
that document in the standards catalogue carries an openly provisional token,
never a number that looks like a clause number.

The path to raising the marker: buy a copy, read the clauses against it, edit
TWO fields - the verification field and the clause title provenance field
(`clause_title_source`) - in the standards catalogue file. The loading layer
rejects an entry that raises one of those two fields without the other. No code
file changes in the process.

A clause title that has not been transcribed from a copy renders in the report
as an own description, in a different shape from a confirmed title.

## Tests

```powershell
uv run pytest
```

## Verification in CI

Every `push` and `pull_request` runs `.github/workflows/ci.yml` on
`windows-latest` - the project's target platform is Windows 11, so a suite
green on Linux alone would not prove the tool works where it is meant to work.
Two jobs:

1. **`test`** - the full test suite on a fresh checkout: `uv sync --locked`, a
   collection completeness gate step (checking that five critical phase 1
   modules have not disappeared from the `pytest` collection), then
   `uv run pytest`.
2. **`confidentiality-backstop`** - the detective confidentiality backstop: a
   checkout with `fetch-depth: 0` (full history),
   `scripts/confidentiality_guard.py` in `--no-corpus` mode over every tracked
   file, `git log --all -- standards/.local`, which fails the job when the
   result is not empty, and a third step: an audit of three surfaces of the
   ENTIRE repository history (tree content, commit messages, file names) with
   the same identity layer patterns as the current gate, run with the `slow`
   test marker explicitly enabled.

That third step is **skipped locally by default** (the `slow` marker is
filtered in the test suite's default options), because its cost is three
surfaces times the whole set of repository commits - a developer who never
performs a public push never runs it, and that is a deliberate choice, not a
gap. The place where that scan is mandatory is CI and the gate before a public
push (`compliance/history-audit.md`).

**What CI by design does NOT see:** the local `standards/.local` corpus and the
file of local literals for the identity layer (the fifth rule,
`identity-local-literal`). Both are gitignored and never reach the remote
repository or CI secrets - that is an architectural necessity, not an
oversight: uploading either of them to repository secrets would defeat the
purpose of the layer it defends. In CI the structural layer, the path check and
the four shape rules of the identity layer are active - never the corpus layer
and never the fifth, literal rule.

**The character of that layer is detective, not preventive.** CI confirms a
violation AFTER the fact - after `git push` - and triggers a reaction: a
revert, a history rewrite with `git filter-repo` before any public push; it
never stops the content from being sent. A personal account on GitHub.com has
no server-side pre-receive hooks, so hard prevention on the remote side is not
available in this project. A green CI run confirms that nothing the gate
recognises passed in THAT push - it is not proof of tightness in general.

The boundaries of the local pre-commit hook (the other side of the same gate)
are described in the `## Confidentiality gate` section above - the two
descriptions stand next to each other so they cannot contradict one another.

## License

Wayside is released under the Apache License, version 2.0. The full text stands
in the [`LICENSE`](LICENSE) file in the root of the repository.
Redistribution, including of a modified version, requires retaining the
copyright notices and marking modified files (section 4 of the license text).
The reason for choosing this license over MIT is described in the decision
record
[`docs/decisions/0007-apache-2-0-license.md`](docs/decisions/0007-apache-2-0-license.md).

# Contributing

This is a personal project with a single maintainer. Issues and pull requests
are welcome, and none of them carries a response window: the only windows this
project commits to are the two in [`SECURITY.md`](SECURITY.md), and they cover
vulnerability reports, nothing else.

## Three things that do not belong in a public issue

1. **A vulnerability in this tool.** It goes through private vulnerability
   reporting in the Security tab of this repository, never through an issue.
   Both routes, and the boundary between a fault in this tool and a
   vulnerability in someone else's installation, stand in
   [`SECURITY.md`](SECURITY.md).

2. **Text copied out of a standard.** IEC 62443-3-3 and CLC/TS 50701 are paid
   documents. If a clause number or a paraphrase in this repository is wrong,
   write that it is wrong and name the designation and the clause; do not
   paste the wording of the document to prove the point. An issue is a public
   page, and the whole citation layer of this project exists to stay on the
   safe side of that line - see the confidentiality gate in the README.

3. **A capture from a network you do not own.** No pcap from a live
   installation, and no report generated from one, belongs in an issue or in a
   pull request. Reproduce the problem on a synthetic capture, or describe the
   shape of the packets instead of attaching them.

## What makes a bug report usable

The pipeline is deterministic - the same capture gives the same report, byte
for byte - so a report becomes reproducible as soon as it carries the command
line you ran, the output of `uv run wayside --version`, what the tool printed,
and what you expected instead. A synthetic capture that triggers the problem
is worth more than a description of one.

## Working on the code

```powershell
powershell -ExecutionPolicy Bypass -File scripts\bootstrap.ps1
uv run pytest -q
```

Two things about this repository surprise people on the first commit:

- **The pre-commit hook is not installed by cloning.** The last step of the
  bootstrap script installs it. Without that step the confidentiality gate
  exists as code and never runs.
- **The gate can reject your commit over a comment.** A line that carries a
  dotted clause number together with a normative modal term reads to the gate
  like verbatim text from a standard, regardless of who wrote it. The fix is
  the same every time: describe the case instead of quoting it.

A change that adds or reshapes a claim in the README needs its entry in
`compliance/readme-claims.yaml`, pointing at the test that proves the claim.
The gate over that catalogue is what keeps the README from promising more than
the code does.

---
decision_date: 2026-09-04
resolved_option: commit-full-table
---

# 0002: Redistribution of the IEEE OUI registry in this repository

## Context

ASSET-02 (the project requirements register) requires establishing a device
vendor from a MAC address prefix against a table derived from the IEEE OUI
registry. The same section of `REQUIREMENTS.md`, in its "Out of Scope" block,
rejects Wireshark's `manuf` file as a source for that data with the
justification: the `manuf` file is a derivative of GPLv2 and licence-poisons a
public repository, whereas the IEEE registry is in the public domain. The
second sentence of that justification is a PROJECT ASSUMPTION recorded while
writing the requirements (2026-09-01), not a fact verified against a legal
source.

The phase research (`03-RESEARCH.md`, Pattern 6, Assumption A4, Open Question
2) checked that assumption in that session: the IEEE Registration Authority
page (`standards.ieee.org/products-programs/regauth/`) does not state the
conditions for redistributing OUI registry data. The only legal mention found
on that page is a general copyright notice in the footer, with no separate
licence document and no terms of use for the assignment list itself. The
practice of the entire tooling industry (Wireshark, nmap, arp-scan,
`mac-vendor-lookup`) redistributes that same list with no separate licence
from IEEE - that is a strong industry signal, but it is not legal proof. The
research also found no precedent to the contrary (a demand from IEEE to remove
such a redistribution), but a precedent not found is not the same as one not
existing.

The repository is to become public: the PUB-01 gate
(`compliance/pre-publication-review.md`) resolved to `go` on 2026-09-02.
Committing third-party data into a tree bound for public hosting is in practice
irreversible - removing it after the fact requires rewriting git history and
invalidating every existing clone. That is the same class of cost for which the
Phase 1 standards confidentiality gate stands BEFORE the first standards
catalogue file rather than after it - which is why this ruling deserved a
separate blocking human checkpoint (`03-05-PLAN.md`, Task 3,
`gate="blocking-human"`) rather than a silent implementation choice.

## Ruling

The option chosen: the full table derived from the IEEE OUI registry,
committed to the repository under `src/wayside/assets/oui_table.tsv`.

The rejected alternatives: a subset of the registry limited to vendors from the
industrial control domain (rejected, because a hand-maintained list would omit
a vendor that could have been established, and the inventory would fall silent
about it instead of naming the limitation - a security assessment tool cares
about completeness more than about file size); zero third-party data in the
repository, with the table built locally by the user (rejected, because a fresh
clone with no network access then establishes the vendor for no host at all,
which breaks the FOUND-01 promise of working on a disconnected network exactly
at the moment the tool is meant to work on its own).

## Justification

The tool works after cloning with no additional step and with no network access
- exactly as FOUND-01 promises. Omitting a vendor outside a hand-maintained
list is a worse failure mode for a security assessment tool than a few
megabytes of text in the repository: a silently missing entry looks like
"there is nothing here", not like "it was known that this could not be
established". The choice follows the recommendation of the phase research and
the established practice of the whole tooling industry redistributing that same
list.

## Residual risk, named outright

This decision does NOT settle the legal status of the IEEE OUI registry - it
settles only that the project proceeds on the assumption of industry practice,
deliberately accepting the following risk:

- The conditions for redistributing IEEE OUI registry data have not been
  confirmed against any legal source - neither by this research nor earlier by
  `REQUIREMENTS.md`, which took "public domain" as an assumption at the moment
  of rejecting the `manuf` file. If that assumption turns out to be wrong, the
  risk applies to the whole tooling industry in parallel, not to this project
  alone, but this is NOT legal advice and does not substitute for it.
- The `oui_table.tsv` file runs to tens of thousands of rows and lands in every
  clone of the repository from this commit onward.
- Reversing this decision after the repository is made public (PUB-01, `go`,
  2026-09-02) requires rewriting git history and invalidating every existing
  clone - it is not a change reversible with an ordinary revert commit.

## Consequences for the user

A fresh clone of the repository establishes the vendor for every host with a
universally administered MAC address present in the registry, with no
additional step and with no network access. The fixtures of this project use
locally administered MAC addresses (the `02:` prefix, outside the IEEE registry
by definition), so the vendor field stays `not-derivable-passively` in every
run over the test fixtures - that is a correct result, not a fault of the
generator or of the table.

## How it is enforced

`tests/test_oui.py::test_decision_record_resolved_option_matches_tree_state`
reads the `resolved_option` field from the frontmatter of this record and
checks that the presence of `src/wayside/assets/oui_table.tsv` in the
git-tracked tree matches that ruling - changing one without the other breaks
the test gate. Separately, `tests/test_oui.py` carries two gates independent of
this decision: the absence of Wireshark's `manuf` file anywhere in the
repository tree, and the absence of a networking import under `src/wayside/`.

## Revision path

Revising this decision in the more cautious direction (removing the table from
the repository) requires updating this record with a new date and a new ruling
in the `resolved_option` field, rewriting git history so that the file actually
disappears from every earlier commit, and a message to everyone who has already
cloned the repository. Confirming the legal status of the IEEE OUI registry
against an actual legal source (rather than industry practice alone) would
close the residual risk named above without any such revision.

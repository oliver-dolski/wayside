---
decision_date: 2026-09-04
resolved_option: clc-ts-50701-2023
---

# 0004: The designation and edition of the railway document cited alongside IEC 62443-3-3

## Context

STD-04 (the project requirements register) sets the proof of the project's
distinguishing feature: adding a second standard to the catalogue is to be the
addition of a data file, with no change to a single line of code. STD-05 adds
the condition that makes such a citation verifiable: every citation states the
edition or the year of the standard. Both requirements called that document
`EN 50701` - so did the ROADMAP (criterion 4 of phase 4) and PROJECT.

That name was adopted while writing the requirements (2026-09-01) and was never
checked against a source. The project's own research saw the problem earlier:
the design research (features) describes the document as "EN 50701 (formally
CLC/TS 50701, a CENELEC Technical Specification)", and `PITFALLS.md` keeps a
separate pitfall number 13 about mistakenly treating it as superseding IEC
62443. The requirements layer did not absorb that correction, so the project was
heading into phase 4 with a designation that cannot be verified, because it does
not exist.

The ROADMAP risk register named this outright as an item to settle BEFORE phase
4, not during it. The reason is the same as with the Phase 1 confidentiality
gate: a wrong designation written into the standards catalogue then spreads to
every generated report, to the directory name in the code tree and to every
external description of the project, and undoing that is many times more
expensive than establishing the name once, before the first file exists.

## Ruling

The option chosen: `CLC/TS 50701:2023`.

Findings confirmed at the source (CEN-CENELEC) and with two independent
standards distributors:

- There is no `EN 50701` standard. The document is a CENELEC Technical
  Specification, not a European Standard, and its own designation is
  `CLC/TS 50701`. The difference is not cosmetic: a TS is a provisional
  document with weaker normative status than an EN.
- The second edition was published in August 2023 and superseded the first from
  July 2021. Citations state the year 2023.
- The content is ultimately heading into the future IEC 63452 standard,
  developed jointly by CENELEC and IEC. That standard does not exist yet, so it
  does not concern v1.

The rejected alternatives: `EN 50701` without a year (rejected, because it cites
a document that does not exist and breaks STD-05 by omitting the edition);
`CLC/TS 50701` without a year (rejected, because the two editions differ in
content, and a citation without a year cannot be verified against a copy -
exactly the failure mode STD-05 was meant to close); `IEC 63452` (rejected,
because the document is not published).

## Justification

This ruling is not a matter of editorial taste. The audience for this project is
a reviewer from the railway sector, and citing a non-existent standard
designation in a tool whose whole promise is "every finding stands on a standard
clause" undermines that promise more than the absence of a second standard would.
Stating the TS status rather than EN also has a substantive consequence: a TS is
applied voluntarily, so the report must not present it as a mandatory basis.

## Residual risk, named outright

This decision settles ONLY the designation, status and edition of the document.
It does NOT settle access to its content: the numbering and text of specific
clauses remain unverified against a legal copy, because the project does not
have a copy. That is a separate, still open risk of phase 4, kept in the ROADMAP
risk register as "Legal access to IEC 62443-3-3 and CLC/TS 50701".

Outright: the designation is now correct, and the clauses under it are not yet
confirmed. The `verified` marker in the standards catalogue exists precisely so
that this difference is visible in the data, not only in this record.

## Consequences for the user

Every citation of the railway document in a generated report reads
`CLC/TS 50701:2023`. A reader who wants to check the citation has the full
designation together with the edition, so they buy or open exactly the document
in question. The standards catalogue gets a separate data directory for that
document; its name follows the designation, not the `en50701` name proposed
earlier in the design research (architecture).

## How it is enforced

A machine gate for this ruling DOES NOT EXIST at the time this record is
written - it comes into being with the phase 4 plan, which delivers STD-04 and
STD-05. The phase 4 plan is to add a test reading the `resolved_option` field
from the frontmatter of this record and checking that no citation in the
standards catalogue or in a generated report uses the string `EN 50701`, and
that every citation of this document carries the edition year. Until that test
exists, the designation is guarded by this record and by convention, not by a
machine.

## Revision path

The publication of IEC 63452 is the event that forces a revision: citations will
then point at the international standard, and `CLC/TS 50701:2023` will become a
historical entry. The revision consists of updating this record with a new date
and a new `resolved_option` and of adding a new standards catalogue file - not
of changing code, exactly as STD-04 requires. The publication of a third edition
of `CLC/TS 50701` closes the same way.

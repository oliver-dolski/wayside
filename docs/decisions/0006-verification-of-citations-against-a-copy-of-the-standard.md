---
decision_date: 2026-09-04
resolved_option: buy-iec62443-3-3-only
---

# 0006: Which citations are verified against a legal copy of the standard

## Context

STD-03 (the project requirements register) requires every finding to carry a
citation to a clause of IEC 62443-3-3. STD-05 adds the verifiability condition:
every citation states the edition or year of the standard. Both requirements
hold only if the numbering and text of the cited clauses have been checked
against a legal copy of the document - otherwise the tool states a clause number
nobody has seen as a fact.

Both documents are paid for. The employer's copies are not a proper basis,
because the project is private and is to become public (PUB-01 resolved to `go`,
2026-09-02). The ROADMAP risk register named that access as an item to settle
before phase 4.

Prices established on 2026-09-04:

- IEC 62443-3-3, first edition from 2013, in the IEC Webstore: CHF 380.
- The same document in the ISA version (ANSI/ISA-62443-3-3-2013): USD 403, so
  the route through IEC is cheaper.
- CLC/TS 50701:2023 through the national standards body: in the order of a few
  hundred euro. The exact price at PKN was not established, because the shop
  does not pass certificate verification in the fetching tool.

The designation and edition of the railway document are settled separately -
record `0004`. This record concerns access to the CONTENT only.

## Ruling

The option chosen (Oliver, 2026-09-04): buying one copy, IEC 62443-3-3.
Citations to CLC/TS 50701:2023 enter v1 with an explicit `verified: no` marker.

The split therefore holds as follows:

- IEC 62443-3-3 - clause numbering and text verified against the purchased copy,
  ultimately `verified: yes`.
- CLC/TS 50701:2023 - designation and edition confirmed at the source (record
  `0004`), clause numbering unconfirmed, `verified: no` visible in the
  catalogue, in the report and in the README.

The rejected alternatives: buying both copies (about PLN 3300 - rejected,
because in phase 4 the role of the railway document is architectural, see the
justification); zero purchases (rejected, because STD-03 puts IEC 62443-3-3
under EVERY v1 finding, not under some of them).

## Justification

These two documents do not carry the same weight in phase 4.

IEC 62443-3-3 stands under every finding the tool produces. An unverified clause
number in that position undermines the project's main promise ("every finding
stands on a standard clause") in every single row of the report, not at its
margin. Verification is worth its price there.

The role of CLC/TS 50701 in phase 4 is architectural. Criterion 4 of that phase
proves that a SECOND standard enters the catalogue as a data file, with a zero
diff on `.py` files. That is a claim about the architecture and it is true
regardless of whether the clauses of that standard have been confirmed against a
copy. The `verified` marker exists in the catalogue precisely so that the
difference between "checked" and "unchecked" is visible in the data; raising it
after a later purchase is an edit to a YAML file, not a code change - exactly
the property criterion 4 proves.

## Residual risk, named outright

- The purchase of IEC 62443-3-3 HAD NOT yet happened at the time this record was
  written. Until the copy is in the author's hands and the clauses have been read
  against it, citations to IEC 62443-3-3 stay `verified: no` just like the
  railway ones. This record settles the intent and the split, not the state.
- The project's distinguishing feature in the railway domain enters v1 partly
  unverified. A reviewer from the railway sector who knows CLC/TS 50701 will see
  a clause number with a `verified: no` marker. That is honest and intended, but
  weaker than a confirmed citation.
- The `verified: no` marker has to be visible EVERYWHERE a citation appears, not
  only in the catalogue file. A citation that looks confident in the report while
  carrying `verified: no` in the catalogue is a worse failure mode than the
  absence of a second standard altogether.

## Consequences for the user

The report states, next to every citation, whether the clause has been checked
against a copy of the standard. The README names that state outright, together
with the reason (the documents are paid for) and with the path to raising the
marker. A reader knows which citation they can trust without their own
verification and which they should check for themselves.

## How it is enforced

A machine gate for this ruling DOES NOT EXIST at the time this record is written
- it comes into being with the phase 4 plan. The phase 4 plan is to add: a test
rejecting a citation without a `verified` field, a test checking that a
`verified: no` entry carries through into the generated report as a visible
caveat (not only into `analysis.json`), and a README passage describing that
state. Verifying the IEC 62443-3-3 clause numbering against the purchased copy is
a task for a human, so the plan sets it as a blocking checkpoint - an executor
cannot raise the `verified` marker on their own judgement, because they do not
see the copy.

## Revision path

Buying CLC/TS 50701:2023 at any later point closes the residual risk named
above: the revision consists of updating this record with a new date and a new
`resolved_option`, reading the clauses against the copy and raising the
`verified` field in the catalogue file. The pipeline code does not change.
Abandoning the purchase of IEC 62443-3-3 closes the same way in the opposite
direction, but then leaves the whole set of v1 citations unverified, and the
README has to say so.

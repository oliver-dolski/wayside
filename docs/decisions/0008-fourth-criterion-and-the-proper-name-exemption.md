---
decision_date: 2026-09-09
resolved_option: narrowed-exemption-plus-criterion-clarification
---

# 0008: Clarifying criterion four of the publication phase and the proper name exemption

## Context

Criterion 4 of phase 5, in its original wording, demanded a review of the entire
repository history for addressing, device names, signatures and the proper name
of the project this repository replaced, "with no hits". The audit of three
surfaces of the whole history (plan `05-04`, task 1) found that one of the four
pattern classes - the proper name of that project - appears in the tracked tree
in five places, for a reason the criterion in its original wording did not
foresee.

Established facts, measured in that session, recorded as findings rather than as
opinions:

- All five occurrences in the tracked tree are THE TEXT OF THE PROHIBITION
  ITSELF: the text of requirement PUB-05 (`REQUIREMENTS.md`), the introduction
  and criterion 4 of phase 5 (`ROADMAP.md`), and the prohibition attached to
  requirement ASSET-05 in the phase 3 plan (`03-02-PLAN.md`).
- No code, schema, addressing or signature originating from that project exists
  in this repository.
- The name appears in commit messages not once - a fact measured directly by the
  second surface pass of the audit (`git log --all --format=%B` through the four
  shape rules of the identity layer), not assumed.

## Ruling

The name goes onto the explicit exemption list `.confidentiality-allow`, as an
exemption NARROWED to one rule (`identity-project-name`) and to three paths (the
planning artifact directory, the exemption list file itself, and the gate file
itself - entries added in plan `05-03`). Criterion 4 of phase 5 is clarified
with a phrase about no hits OUTSIDE the explicit exemption list in
`.confidentiality-allow`, together with a pointer to this record.

The rejected alternative: rewriting the history with the tool made for it (`git
filter-repo`). Such an operation would change the digest of nearly every commit
in the repository (five occurrences among a couple of hundred commits, but
rewriting one commit rewrites the digests of every commit after it) - which
would leave the commit reference fields in every SUMMARY file of the plans so
far and in `STATE.md` pointing at objects that no longer exist, for zero value:
removing the name from the text of one's own prohibition removes no information
about that project, because no such information is there.

## Justification

The fact that the name appears ONLY in the text of one's own prohibition is an
argument IN THE AUTHOR'S FAVOUR, not against them - it shows that the boundary
between the two projects was drawn deliberately and written into the
requirements before the first line of code in this repository existed. The
exemption hides nothing: every occurrence is publicly readable in the text of
the requirement, the criterion and the prohibition that the same exemption
describes.

Narrowing the exemption to one rule (rather than to the whole identity layer) is
deliberate: an address from the employer's network or a device name in any of
the three exempted files still fires the other four rules of that layer. The
exemption covers ONLY the proper name, never addressing and never device
signatures.

## Residual risk, named outright

- An exemption is a place where the gate DELIBERATELY does not look. A future
  reader of the exemption list who does not read the justification above the
  entry may take it for a loophole - which is why the exemption is narrowed to
  one rule and three specific paths rather than to the whole planning directory
  or the whole layer, and why the justification above the entry says so
  outright.
- Clarifying criterion 4 is a change to text the phase verifier relies on -
  reversing this decision would require passing the phase verification gate
  again (reversibility assessment: costly, `05-CONTEXT.md` D-23).
- The ruling assumes the five established occurrences will remain the only ones
  - every NEW occurrence of that name outside the three exempted paths is still a
  violation of the current gate and of the history audit, regardless of this
  ruling.

## Consequences for the user

A reader of the repository who reads requirement PUB-05, criterion 4 of phase 5
or `.confidentiality-allow` will see the name of the project this repository
replaced only in a context explaining why the confidentiality boundary between
the two projects was drawn. Nothing in this repository comes from that project
apart from its name itself, used as an example of a boundary.

## How it is enforced

Three machine mechanisms at once: the narrowed
`identity-path:identity-project-name:...` entry in `.confidentiality-allow`
(plan `05-03`); the scan of three surfaces of the whole history calling that
same exemption rule (plan `05-04`, task 1); and the audit record shape gate
(`scripts/check_history_audit_gate.py`), which requires the record's
`rules_checked` field to list exactly the set of rules actually checked -
extending the identity layer with another rule requires extending that list in
two places at once, otherwise the record claims more than the scan checked.

## Revision path

The ruling requires a fresh review when any of the following occurs: the audit of
three surfaces finds a NEW occurrence of the name outside the three exempted
paths; any of the three exempted paths starts carrying content OTHER than the
text of the prohibition itself (code, a schema, addressing, a signature); or a
decision to rewrite the history is taken for another reason, which would remove
those five occurrences along the way.

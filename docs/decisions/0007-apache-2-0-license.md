---
decision_date: 2026-09-09
resolved_option: apache-2-0
---

# 0007: Choosing the Apache License 2.0 for the public repository

## Context

The repository is moving from the state of a private workshop to a state ready
for public exposure (phase 5, `05-CONTEXT.md` D-02). Without a licence file,
public code is formally "all rights reserved" in its entirety - nobody but the
author has the right to use, copy or modify it, regardless of what the
documentation says.

This is a contradiction inside a single document, not a missing capability. The
`## Intended Use` section delivered by plan `05-01` of the same phase describes
outright what the tool is intended for (security assessment, material for a
report to the system owner) and invites the reader to use it for that purpose.
The absence of a `LICENSE` file would contradict that section at the moment
anyone tried to accept the invitation.

## Ruling

The option chosen (Oliver, a phase 5 decision, D-02): **the Apache License,
version 2.0**, with the copyright header `Copyright 2026 Oliver Dolski` in the
appendix block of the text.

The rejected alternative: **MIT** - a permissive licence with no explicit patent
grant. Rejected because it falls silent exactly where the target audience from
`PROJECT.md` (automation integrators and managed service providers, commercial
use in the OT/ICS sector) needs explicitness: MIT contains no patent provision
at all, so it neither grants a patent licence nor protects the recipient against
a later patent claim from a contributor.

## Justification

The Apache License 2.0 carries, in section 3 ("Grant of Patent License"), an
explicit, irrevocable grant of a patent licence from every contributor to every
recipient, with a termination clause on filing a patent suit against Wayside. The
target recipient of this project - an integrator deploying the tool in a
client's environment, a managed service provider building a commercial offering
on it - therefore has greater legal certainty than under MIT, where the patent
question is not addressed at all.

## Residual risk, named outright

- Granting a public licence is **one-way**: against anyone who has already
  downloaded the code under that licence, revocation does not work. A licence
  change in the future would apply only going forward, not retroactively.
- Apache 2.0 carries a longer text (202 lines of canonical text) and more formal
  attribution requirements than MIT - section 4 requires retaining every notice
  of copyright, patents, trademarks and attribution from the source form, and
  marking modified files. A recipient redistributing a modified version has to
  meet those requirements; MIT asks for less.
- Choosing this particular licence is a one-off decision as to its content:
  changing the project's licence in the future (e.g. to another permissive
  licence) is possible for new releases, but it does not remove the rights
  already granted over existing copies of the code.

## Consequences for the user

What is permitted: commercial and non-commercial use, modification, distribution
and sublicensing of Wayside and of derivative works, with no obligation to
publish modified source code (a permissive licence, not copyleft).

What attribution requires: every distribution (including of a modified version)
has to retain the content of the `LICENSE` file, the copyright and patent
notices from the source form of Wayside, and clearly mark files changed against
the original. The details stand in section 4 of the licence text.

## How it is enforced

The `tests/test_license.py` machine gate checks that the content of the
`LICENSE` file differs from the canonical text by exactly one line (the
copyright line), by comparing the sha256 digest after substituting the template
line back, and by the presence of each of the nine numbered sections. The
`## License` header in `README.md` has its own entry in
`compliance/readme-claims.yaml`, so the `tests/test_readme_claims.py` gate
enforces that this header always carries a claim covered by evidence.

Confirming D-03: the project name "Wayside" stays unchanged - the review before
the first public push took place (the revision foreseen in `PROJECT.md`), and its
outcome is negative as to a change. `tests/test_license.py` checks the package
name field and the command line entry point in `pyproject.toml` against that
ruling, so that a future silent rename turns the gate red instead of passing
unnoticed.

## Revision path

The ruling requires a fresh review when any of the following occurs: the
project's business model shifts in a direction Apache 2.0 does not serve well
(e.g. a need for a copyleft licence to force publication of modifications), a
commercial partner demands a different licence as a condition of cooperation, or
a patent claim appears that requires re-evaluating the termination clause of
section 3. The revision consists of releasing a new version under a new licence
- the change applies **only going forward**, and copies already distributed
under Apache 2.0 keep that grant indefinitely.

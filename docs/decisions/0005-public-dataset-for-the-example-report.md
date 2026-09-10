---
decision_date: 2026-09-04
resolved_option: 4sics-fetch-script
---

# 0005: The public dataset the example report is generated from

## Context

REPORT-05 (the project requirements register) requires the repository to carry
an example report generated from a public dataset, reproducible from that
dataset byte for byte. This is not a cosmetic requirement: the project notes
name that report the main promotional artifact, a stronger carrier than the
repository itself, because a conclusion reads itself and work in progress does
not.

The roadmap counted on the ELECTRA dataset and named its availability a risk to
settle before phase 4. The reason for that preference was domain value: ELECTRA
models the control system of a high-speed railway traction substation and
carries Modbus and S7Comm, so it would give the example report value in exactly
the sector the project is meant to be read in. The dataset was confirmed to
exist and to be railway traffic, but not to be publicly downloadable.

## Ruling

The option chosen: a slice of 4SICS from Netresec; what enters the repository is
a fetch script plus the generated report, never the pcap file itself.

Findings confirmed in the research:

- ELECTRA is described in the academic literature, but there is no public
  download point. Access goes through contacting the dataset's authors, which
  the reproducibility requirement in REPORT-05 cannot assume: a reader of the
  repository is to reproduce the report themselves, without corresponding with
  anyone.
- 4SICS (Netresec, traffic from the ICS village of a conference) is publicly
  downloadable and weighs about 360 MB.
- The redistribution conditions of 4SICS are explicit and mild: attribution to
  CS3Sthlm for sharing the lab traffic, plus a link back to the Netresec page.
  Redistribution is therefore permitted, including in training material.

The rejected alternatives: ELECTRA as the primary route (rejected for the lack
of a public download point - it breaks reproducibility); committing the 4SICS
pcap files into the repository, which the licence would permit (rejected for
size: 360 MB in every clone for one example report is a bad trade, and
separately, committing any third-party data into a repository meant to be public
is in practice irreversible - the same cost that ruling 0002 names for the OUI
table).

## Justification

Reproducibility beats domain value. A report from ICS lab traffic is
thematically weaker than a report from a traction substation, but a report a
reader cannot reproduce proves nothing - and REPORT-05 sets byte reproducibility
as a condition, not as a nice extra. A fetch script instead of a copy of the
pcap keeps the repository small and sidesteps a whole class of redistribution
questions, even though the 4SICS licence would permit it.

## Residual risk, named outright

- The example report loses its railway domain value. Traffic from the ICS
  village of a conference is still genuine industrial traffic, but it is not
  railway traffic, so the report does not show the sector in which this project
  has its distinguishing feature. No choice of checks can make up for that.
- Byte reproducibility depends on the files at the Netresec addresses not
  changing. The fetch script is to record the digest of the downloaded file, so
  that a silent substitution at the source is detected as an error rather than
  as a drifting report.
- Attribution to CS3Sthlm is a licence condition, so its absence from the README
  or from the report itself is a violation, not an editorial slip.

## Consequences for the user

A reader of the repository sees a finished example report without downloading
anything, and if they want to check that the report really came from that
dataset, they run the fetch script and repeat the generation. A clone of the
repository does not grow by the size of the dataset.

## How it is enforced

A machine gate for this ruling DOES NOT EXIST at the time this record is written
- it comes into being with the phase 4 plan, which delivers REPORT-05. The phase
4 plan is to add an entry in the fixture manifest with the source and licence of
the dataset (the FOUND-05 requirement, which already works and has its own
test), a reproducibility test comparing the generated report against the
recorded one, and a test for the absence of pcap files of that dataset in the
git-tracked tree.

## Revision path

The appearance of a public download point for ELECTRA or for another dataset
with railway traffic closes the residual risk named above. The revision consists
of updating this record with a new date and a new `resolved_option`, replacing
the address in the fetch script and regenerating the report - the pipeline code
does not change, because the dataset is input to it, not a dependency.

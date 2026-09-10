# Example report: the 4SICS dataset

Attribution is a licence condition of redistributing this material, not a
courtesy - copying this directory copies that condition along with it.

## Attribution

The traffic comes from the 4SICS Geek Lounge lab (2015), made publicly
available by Netresec (https://www.netresec.com/) with the permission of
CS3Sthlm (successor to the 4SICS conference) to share the captured traffic.

Dataset page: [https://www.netresec.com/?page=PCAP4SICS](https://www.netresec.com/?page=PCAP4SICS).
The page of the institution the attribution is owed to: [CS3Sthlm](https://cs3sthlm.se/).
Redistribution is permitted, including in training material, on condition of
that attribution and of a link back to the Netresec page.

## Domain boundary

This traffic comes from the lab of an industrial conference, NOT from a
railway installation. The example report below does not show the domain in
which this project has its distinguishing feature - that is a residual risk
accepted deliberately and recorded in
[`docs/decisions/0005-public-dataset-for-the-example-report.md`](../../docs/decisions/0005-public-dataset-for-the-example-report.md):
a public download point with genuine railway traffic does not exist, and
reproducibility beats domain value. A reader looking for evidence from the
railway sector will not find it in this directory.

## Reproduction

Two commands, in this order:

```powershell
uv run python scripts\fetch_4sics_sample.py
uv run python scripts\gen_example_report.py
```

The first command downloads the source file of the dataset (about 200 MB)
from the Netresec page, verifies its sha256 against the constant recorded in
`scripts/fetch_4sics_sample.py` and fails on a mismatch - a silent
substitution of the file at the source will therefore be detected rather than
silently used. It then builds a deterministic 40-packet slice
(`4sics-slice.pcap`) and verifies its digest the same way. The second command
generates the three artifacts below from that slice, with a fixed timestamp.

## What this report shows

- **Summary** - the number of findings in this run.
- **Scope** - recognised protocols, the time window, the snaplen.
- **Methodology** - the severity rubric criteria, with no invented scale.
- **Asset inventory** - eight hosts observed in the slice, with the vendor
  derived from the MAC address wherever it could be established.
- **Communication matrix** - seven TCP sessions carrying payload.
- **Findings** - five occurrences of the `unauthenticated-industrial-protocol`
  check (one host polling five different Modbus/TCP servers with no
  authentication mechanism), each with a citation to IEC 62443-3-3 and to
  CLC/TS 50701. The same pattern is now readable straight from the finding
  blocks in `report.md`/`report.pdf` - every block carries a session parties
  line (`Session parties: <source> -> <target>`) with the same source address
  and five different destination addresses.
- **Recommendations** - one recommendation, shared by all five findings,
  stated once with the number of findings it applies to.

## Files

- `analysis.json` - the machine-readable model, serialised deterministically.
- `report.md` - the markdown report.
- `report.pdf` - the same report with an embedded Unicode font.

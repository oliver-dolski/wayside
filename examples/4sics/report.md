# Wayside report

Generated: 2026-09-04T00:00:00+00:00

## Summary

Analysis of capture `4sics-slice.pcap` raised 5 findings requiring attention.

## Scope

The capture carries 40 packets. Protocol(s) recognised in this capture: modbus-tcp, recognised by the shape of the segment payload, never by port number. Traffic whose protocol was not recognised has a row in the communication matrix labelled `tcp` and is not the basis of any finding.
Capture time window: from 1445499126.04817 to 1445499126.8009 (Unix epoch timestamps). Snaplen read from the capture header: 65535 bytes. Frames truncated by snaplen: 0. Events recognised with low confidence: 0.

## Methodology

Every finding carries an indicator of behaviour observed in network traffic, never a judgement on whether an installation does or does not meet the requirements of a standard. Finding severity follows the documented rubric criteria below (version 1.0), not an invented scale:

- **low**: An observation with limited security impact and no direct path to disrupting the operation of the process.
- **medium**: A departure from good practice which, combined with another condition, may lead to disrupting the operation of the process.
- **high**: An operation that by itself allows the state of the process to be influenced without authentication or authorisation of the sender.
- **critical**: A condition enabling immediate and direct interference with the safety of the process, with no further conditions required.

## Asset inventory

### 10.10.10.20

- ip: 10.10.10.20 (observed)
- mac: 00:1c:06:27:64:11 (observed)
- Vendor: Siemens Numerical Control Ltd., Nanjing (inferred:oui-lookup)
- Unit ID sub-addresses: not determined (not-derivable-passively)
- Gateway: not determined (not-derivable-passively)
- Role: undetermined (not-derivable-passively)
- Role evidence: Zero Modbus events associated with this address in this capture (requests sent: 0, requests received: 0). (observed)
- Role confidence: low (inferred:event-count-and-direction)

### 10.10.10.10

- ip: 10.10.10.10 (observed)
- mac: 28:63:36:89:59:82 (observed)
- Vendor: Siemens AG (inferred:oui-lookup)
- Unit ID sub-addresses: not determined (not-derivable-passively)
- Gateway: not determined (not-derivable-passively)
- Role: undetermined (not-derivable-passively)
- Role evidence: Zero Modbus events associated with this address in this capture (requests sent: 0, requests received: 0). (observed)
- Role confidence: low (inferred:event-count-and-direction)

### 192.168.88.50

- ip: 192.168.88.50 (observed)
- mac: 00:05:e4:01:24:d3 (observed)
- Vendor: Red Lion Controls Inc. (inferred:oui-lookup)
- Unit ID sub-addresses: 1 (observed)
- Gateway: not determined (not-derivable-passively)
- Role: Modbus server (inferred:modbus-traffic-direction)
- Role evidence: Modbus requests sent by this address: 0; Modbus requests received by this address: 1. (observed)
- Role confidence: low (inferred:event-count-and-direction)

### 192.168.2.44

- ip: 192.168.2.44 (observed)
- mac: 00:07:7c:1a:61:83 (observed)
- Vendor: Westermo Network Technologies AB (inferred:oui-lookup)
- Unit ID sub-addresses: not determined (not-derivable-passively)
- Gateway: not determined (not-derivable-passively)
- Role: Modbus client (inferred:modbus-traffic-direction)
- Role evidence: Modbus requests sent by this address: 5; Modbus requests received by this address: 0. (observed)
- Role confidence: medium (inferred:event-count-and-direction)

### 192.168.88.100

- ip: 192.168.88.100 (observed)
- mac: 00:e0:62:40:57:66 (observed)
- Vendor: HOST ENGINEERING (inferred:oui-lookup)
- Unit ID sub-addresses: 1 (observed)
- Gateway: not determined (not-derivable-passively)
- Role: Modbus server (inferred:modbus-traffic-direction)
- Role evidence: Modbus requests sent by this address: 0; Modbus requests received by this address: 1. (observed)
- Role confidence: low (inferred:event-count-and-direction)

### 192.168.88.20

- ip: 192.168.88.20 (observed)
- mac: 00:a0:45:6f:4b:83 (observed)
- Vendor: Phoenix Contact GmbH & Co. KG (inferred:oui-lookup)
- Unit ID sub-addresses: 1 (observed)
- Gateway: not determined (not-derivable-passively)
- Role: Modbus server (inferred:modbus-traffic-direction)
- Role evidence: Modbus requests sent by this address: 0; Modbus requests received by this address: 1. (observed)
- Role confidence: low (inferred:event-count-and-direction)

### 192.168.88.60

- ip: 192.168.88.60 (observed)
- mac: 00:90:e8:26:40:23 (observed)
- Vendor: MOXA TECHNOLOGIES CORP., LTD. (inferred:oui-lookup)
- Unit ID sub-addresses: 1 (observed)
- Gateway: not determined (not-derivable-passively)
- Role: Modbus server (inferred:modbus-traffic-direction)
- Role evidence: Modbus requests sent by this address: 0; Modbus requests received by this address: 1. (observed)
- Role confidence: low (inferred:event-count-and-direction)

### 192.168.88.61

- ip: 192.168.88.61 (observed)
- mac: 00:90:e8:27:8c:37 (observed)
- Vendor: MOXA TECHNOLOGIES CORP., LTD. (inferred:oui-lookup)
- Unit ID sub-addresses: 1 (observed)
- Gateway: not determined (not-derivable-passively)
- Role: Modbus server (inferred:modbus-traffic-direction)
- Role evidence: Modbus requests sent by this address: 0; Modbus requests received by this address: 1. (observed)
- Role confidence: low (inferred:event-count-and-direction)

## Communication matrix

| Session | Source | Target | Direction | Protocol | Volume (B) | Packets | Initiating party |
|---|---|---|---|---|---|---|---|
| 0 | 10.10.10.20:49156 | 10.10.10.10:102 | 10.10.10.20:49156 -> 10.10.10.10:102 (inferred:first-observed-sender) | tcp | 634 | 6 | not determined (not-derivable-passively) |
| 1 | 192.168.2.44:58597 | 192.168.88.50:502 | 192.168.2.44:58597 -> 192.168.88.50:502 (observed) | modbus-tcp | 260 | 4 | 192.168.2.44:58597 (observed) |
| 2 | 192.168.2.44:58601 | 192.168.88.100:502 | 192.168.2.44:58601 -> 192.168.88.100:502 (observed) | modbus-tcp | 320 | 5 | 192.168.2.44:58601 (observed) |
| 3 | 192.168.2.44:58599 | 192.168.88.20:502 | 192.168.2.44:58599 -> 192.168.88.20:502 (observed) | modbus-tcp | 260 | 4 | 192.168.2.44:58599 (observed) |
| 4 | 192.168.2.44:58598 | 192.168.88.60:44818 | 192.168.2.44:58598 -> 192.168.88.60:44818 (observed) | tcp | 308 | 4 | 192.168.2.44:58598 (observed) |
| 5 | 192.168.2.44:58600 | 192.168.88.60:502 | 192.168.2.44:58600 -> 192.168.88.60:502 (observed) | modbus-tcp | 367 | 5 | 192.168.2.44:58600 (observed) |
| 6 | 192.168.2.44:58602 | 192.168.88.61:502 | 192.168.2.44:58602 -> 192.168.88.61:502 (observed) | modbus-tcp | 433 | 6 | 192.168.2.44:58602 (observed) |

## Limitations

- Scope of this run: addresses observed 8, sessions with payload 7, sessions without a single segment carrying payload 2, the capture time window is 0.75273 s long.
- This report describes only traffic that reached the capture point. A device absent from the result is not a device absent from the network - it is a device whose traffic did not pass this point.
- A device sitting behind a protocol gateway is visible only under the address of that gateway. A network address in this report may therefore correspond to more than one physical device.
- Multiple hosts hidden behind a single address after address translation are indistinguishable from this point. One inventory row may correspond to more than one device.
- TCP sessions made up exclusively of packets without payload: 2. They have no row in the communication matrix, because they carry no segment to recognise - they are counted here so they do not vanish without a trace.

This report comes from a vertical slice: one capture, one check, one standard clause. The zone and conduit model is a single-zone placeholder derived automatically from this capture, not a designed network topology. Standard clause numbering is provisional and awaits collation against a legal copy of the standard.

Fields that cannot be established from this capture, grouped by field name:

- section `assets`, field `gateway`: 8 of 8 entries
- section `assets`, field `role`: 2 of 8 entries
- section `assets`, field `unit_ids`: 3 of 8 entries
- section `comm_matrix`, field `initiator`: 1 of 7 entries

## Findings

### Use of an industrial protocol without an authentication mechanism in the observed communication

- Check identifier: `unauthenticated-industrial-protocol`
- Severity: high (risk: serious)
- Session parties: 192.168.2.44:58597 -> 192.168.88.50:502
- Evidence: packet no. 29, session no. 1
- Rationale: This finding concerns the mere use of a protocol that has no mechanism for authenticating the sender, regardless of whether a write operation occurred in this capture. Any host that can see this network segment may send a command the device will execute, and a read observed in the capture proves only that the communication path exists and is open. This is a property of the protocol, not a decision or an omission of the installation operator - in an older industrial installation there is often no alternative.
- Standard citation: IEC-62443-3-3 SR 1.2
  - Clause scope (own description, not a title from the copy): Software process and device identification and authentication
  - Paraphrase: The clause concerns ensuring that every software process and every device connecting to the control system is uniquely identified and authenticated - as distinct from human users, who are covered by a separate clause of this catalogue.
  - Status: **PROVISIONAL, UNVERIFIED** (The clause numbering and the paraphrase text await collation against a legal copy of IEC 62443-3-3 in phase 4. Until then the entry is provisional and does not constitute a confirmed citation.)
- Standard citation: CLC/TS 50701 undetermined-1
  - Clause scope (own description, not a title from the copy): Security requirements for railway signalling and control systems
  - Paraphrase: The document concerns cybersecurity requirements placed on railway traffic control and signalling systems, including protection of their correct operation against deliberate and accidental compromise.
  - Status: **PROVISIONAL, UNVERIFIED** (The document has the status of a CENELEC technical specification, not a European standard, so it is applied voluntarily - the report does not present it as a mandatory basis (decision 0004). The clause numbering has not been collated against a copy, because the project does not buy that copy; the entry is provisional for that reason (decision 0006).)
- Remediation: Restrict at the network level the set of hosts that may open a session to the controller at all, through segmentation and access control lists. The protocol itself cannot be authenticated without replacing devices or without an intermediary layer.

### Use of an industrial protocol without an authentication mechanism in the observed communication

- Check identifier: `unauthenticated-industrial-protocol`
- Severity: high (risk: serious)
- Session parties: 192.168.2.44:58601 -> 192.168.88.100:502
- Evidence: packet no. 34, session no. 2
- Rationale: This finding concerns the mere use of a protocol that has no mechanism for authenticating the sender, regardless of whether a write operation occurred in this capture. Any host that can see this network segment may send a command the device will execute, and a read observed in the capture proves only that the communication path exists and is open. This is a property of the protocol, not a decision or an omission of the installation operator - in an older industrial installation there is often no alternative.
- Standard citation: IEC-62443-3-3 SR 1.2
  - Clause scope (own description, not a title from the copy): Software process and device identification and authentication
  - Paraphrase: The clause concerns ensuring that every software process and every device connecting to the control system is uniquely identified and authenticated - as distinct from human users, who are covered by a separate clause of this catalogue.
  - Status: **PROVISIONAL, UNVERIFIED** (The clause numbering and the paraphrase text await collation against a legal copy of IEC 62443-3-3 in phase 4. Until then the entry is provisional and does not constitute a confirmed citation.)
- Standard citation: CLC/TS 50701 undetermined-1
  - Clause scope (own description, not a title from the copy): Security requirements for railway signalling and control systems
  - Paraphrase: The document concerns cybersecurity requirements placed on railway traffic control and signalling systems, including protection of their correct operation against deliberate and accidental compromise.
  - Status: **PROVISIONAL, UNVERIFIED** (The document has the status of a CENELEC technical specification, not a European standard, so it is applied voluntarily - the report does not present it as a mandatory basis (decision 0004). The clause numbering has not been collated against a copy, because the project does not buy that copy; the entry is provisional for that reason (decision 0006).)
- Remediation: Restrict at the network level the set of hosts that may open a session to the controller at all, through segmentation and access control lists. The protocol itself cannot be authenticated without replacing devices or without an intermediary layer.

### Use of an industrial protocol without an authentication mechanism in the observed communication

- Check identifier: `unauthenticated-industrial-protocol`
- Severity: high (risk: serious)
- Session parties: 192.168.2.44:58599 -> 192.168.88.20:502
- Evidence: packet no. 32, session no. 3
- Rationale: This finding concerns the mere use of a protocol that has no mechanism for authenticating the sender, regardless of whether a write operation occurred in this capture. Any host that can see this network segment may send a command the device will execute, and a read observed in the capture proves only that the communication path exists and is open. This is a property of the protocol, not a decision or an omission of the installation operator - in an older industrial installation there is often no alternative.
- Standard citation: IEC-62443-3-3 SR 1.2
  - Clause scope (own description, not a title from the copy): Software process and device identification and authentication
  - Paraphrase: The clause concerns ensuring that every software process and every device connecting to the control system is uniquely identified and authenticated - as distinct from human users, who are covered by a separate clause of this catalogue.
  - Status: **PROVISIONAL, UNVERIFIED** (The clause numbering and the paraphrase text await collation against a legal copy of IEC 62443-3-3 in phase 4. Until then the entry is provisional and does not constitute a confirmed citation.)
- Standard citation: CLC/TS 50701 undetermined-1
  - Clause scope (own description, not a title from the copy): Security requirements for railway signalling and control systems
  - Paraphrase: The document concerns cybersecurity requirements placed on railway traffic control and signalling systems, including protection of their correct operation against deliberate and accidental compromise.
  - Status: **PROVISIONAL, UNVERIFIED** (The document has the status of a CENELEC technical specification, not a European standard, so it is applied voluntarily - the report does not present it as a mandatory basis (decision 0004). The clause numbering has not been collated against a copy, because the project does not buy that copy; the entry is provisional for that reason (decision 0006).)
- Remediation: Restrict at the network level the set of hosts that may open a session to the controller at all, through segmentation and access control lists. The protocol itself cannot be authenticated without replacing devices or without an intermediary layer.

### Use of an industrial protocol without an authentication mechanism in the observed communication

- Check identifier: `unauthenticated-industrial-protocol`
- Severity: high (risk: serious)
- Session parties: 192.168.2.44:58600 -> 192.168.88.60:502
- Evidence: packet no. 33, session no. 5
- Rationale: This finding concerns the mere use of a protocol that has no mechanism for authenticating the sender, regardless of whether a write operation occurred in this capture. Any host that can see this network segment may send a command the device will execute, and a read observed in the capture proves only that the communication path exists and is open. This is a property of the protocol, not a decision or an omission of the installation operator - in an older industrial installation there is often no alternative.
- Standard citation: IEC-62443-3-3 SR 1.2
  - Clause scope (own description, not a title from the copy): Software process and device identification and authentication
  - Paraphrase: The clause concerns ensuring that every software process and every device connecting to the control system is uniquely identified and authenticated - as distinct from human users, who are covered by a separate clause of this catalogue.
  - Status: **PROVISIONAL, UNVERIFIED** (The clause numbering and the paraphrase text await collation against a legal copy of IEC 62443-3-3 in phase 4. Until then the entry is provisional and does not constitute a confirmed citation.)
- Standard citation: CLC/TS 50701 undetermined-1
  - Clause scope (own description, not a title from the copy): Security requirements for railway signalling and control systems
  - Paraphrase: The document concerns cybersecurity requirements placed on railway traffic control and signalling systems, including protection of their correct operation against deliberate and accidental compromise.
  - Status: **PROVISIONAL, UNVERIFIED** (The document has the status of a CENELEC technical specification, not a European standard, so it is applied voluntarily - the report does not present it as a mandatory basis (decision 0004). The clause numbering has not been collated against a copy, because the project does not buy that copy; the entry is provisional for that reason (decision 0006).)
- Remediation: Restrict at the network level the set of hosts that may open a session to the controller at all, through segmentation and access control lists. The protocol itself cannot be authenticated without replacing devices or without an intermediary layer.

### Use of an industrial protocol without an authentication mechanism in the observed communication

- Check identifier: `unauthenticated-industrial-protocol`
- Severity: high (risk: serious)
- Session parties: 192.168.2.44:58602 -> 192.168.88.61:502
- Evidence: packet no. 35, session no. 6
- Rationale: This finding concerns the mere use of a protocol that has no mechanism for authenticating the sender, regardless of whether a write operation occurred in this capture. Any host that can see this network segment may send a command the device will execute, and a read observed in the capture proves only that the communication path exists and is open. This is a property of the protocol, not a decision or an omission of the installation operator - in an older industrial installation there is often no alternative.
- Standard citation: IEC-62443-3-3 SR 1.2
  - Clause scope (own description, not a title from the copy): Software process and device identification and authentication
  - Paraphrase: The clause concerns ensuring that every software process and every device connecting to the control system is uniquely identified and authenticated - as distinct from human users, who are covered by a separate clause of this catalogue.
  - Status: **PROVISIONAL, UNVERIFIED** (The clause numbering and the paraphrase text await collation against a legal copy of IEC 62443-3-3 in phase 4. Until then the entry is provisional and does not constitute a confirmed citation.)
- Standard citation: CLC/TS 50701 undetermined-1
  - Clause scope (own description, not a title from the copy): Security requirements for railway signalling and control systems
  - Paraphrase: The document concerns cybersecurity requirements placed on railway traffic control and signalling systems, including protection of their correct operation against deliberate and accidental compromise.
  - Status: **PROVISIONAL, UNVERIFIED** (The document has the status of a CENELEC technical specification, not a European standard, so it is applied voluntarily - the report does not present it as a mandatory basis (decision 0004). The clause numbering has not been collated against a copy, because the project does not buy that copy; the entry is provisional for that reason (decision 0006).)
- Remediation: Restrict at the network level the set of hosts that may open a session to the controller at all, through segmentation and access control lists. The protocol itself cannot be authenticated without replacing devices or without an intermediary layer.

## Recommendations

- Restrict at the network level the set of hosts that may open a session to the controller at all, through segmentation and access control lists. The protocol itself cannot be authenticated without replacing devices or without an intermediary layer. (applies to 5 findings)


# Security policy

This document describes two DIFFERENT routes for reporting a vulnerability,
which are not interchangeable - the choice between them belongs to the reader.
The document describes a route and a window; it gives no legal advice and is
not a contractual commitment.

## A vulnerability in the Wayside tool

This section covers vulnerabilities in the code of this repository, in its
scripts and in its dependencies as this repository pins them - not in someone
else's installation and not in the traffic the tool analyses.

Channel: private vulnerability reporting in the security tab of this
repository (GitHub, the Security tab, the "Report a vulnerability" option).
Why there is no email address here: the platform channel gives a private
reporting thread and a path to publishing a security advisory, and it does not
require publishing the author's private address.

Acknowledgement of a report: five business days. Initial assessment of a
report: thirty days.

**The boundaries, named outright rather than passed over in silence:**

- No fix release window stands here. The project has a single maintainer, and
  promising such a window would be exactly the class of claim without evidence
  that PUB-04 forbids - this file is under the same discipline as the README.
- No reward programme for reports stands here, for the same reason.
- This file by itself does not switch the reporting channel on. Private
  vulnerability reporting is a setting of the repository, independent of the
  content of this document, and switching it on belongs to the repository
  owner.

A reporter acting in good faith and within the scope of this section faces no
claims from the author on that account.

## A vulnerability found with Wayside in someone else's network

This section covers a finding in someone else's installation, established from
the analysis of a traffic capture taken by the reader. The author of Wayside
does not mediate such reports and does not accept them. Taking findings from
someone else's industrial infrastructure onto a private account is exactly the
class of risk this whole project deliberately keeps at arm's length.

The reporter has three routes of their own:

1. The system owner - the first and default addressee.
2. The device manufacturer or supplier.
3. Public coordination points: CISA ICS-CERT for industrial vulnerabilities,
   and for Poland CSIRT NASK and CSIRT GOV, competent for the obligations
   under the national cybersecurity system act and under the directive on the
   resilience of critical entities.

The incident reporting deadline is set by the regime applicable to the reader.
The windows from the first section do not apply to it - that is this section's
own deadline.

**The boundaries, named outright rather than passed over in silence:** what
the author can do - fix the tool, if the finding follows from a fault in the
tool rather than from a vulnerability in someone else's network. What the
author will not do - contact the owner of someone else's network, confirm a
finding in someone else's installation, or store evidence.

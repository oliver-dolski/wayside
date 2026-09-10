---
requirement: PUB-05
scope: repository-history-identity-patterns
audited_on: 2026-09-10
head_sha: fc24ce400d40f4ba5c99cae4b2a31f47625ea784
surfaces: tree-content, commit-message, file-name
rules_checked: identity-private-ipv4, identity-mac-address, identity-device-name, identity-project-name
exceptions_file: .confidentiality-allow
result: clean
author: Oliver Dolski
confirmed_on: 2026-09-10
---

This record captures THE RESULT OF A RUN of the scan of three surfaces of the
entire repository history, tied to the HEAD digest at the moment of that run -
it captures no matched fragment of history content and no file name with a hit.
The `author` and `confirmed_on` fields are the only trace that the result was
read by someone; the executor of the plan does not fill them in.

## Scope

Three surfaces, each a separate scan with its own output parsing
(`tests/test_history_audit.py`):

- **tree-content** - the tree content of every revision reachable from every
  reference (`git rev-list --all` plus a single `git grep` call over all
  revisions at once).
- **commit-message** - the messages of every commit (`git log --all`, a format
  with the record delimited by a zero byte).
- **file-name** - the file names from the tree of every revision (`git ls-tree
  -r --name-only -z` per revision, the union of names across all revisions).

Every surface is checked with THE SAME four shape rules of the identity layer as
the current gate (`scripts/confidentiality_guard.py`, D-19):
`identity-private-ipv4`, `identity-mac-address`, `identity-device-name`,
`identity-project-name`. The fifth rule (`identity-local-literal`) works LOCALLY
ONLY from a gitignored file and is not part of this audit - the same boundary
the README names for the current gate in CI.

## Result

`clean` - zero hits across all three surfaces outside the values declared and
the paths exempted in the exceptions file. The result is a MACHINE FACT from an
actual run against the HEAD digest recorded above (`uv run pytest -o addopts="-q"
-m slow tests/test_history_audit.py`, 11 tests green).

## Exceptions

The exceptions file: `.confidentiality-allow`. The same file as the current gate
- D-19 requires ONE exception list, not a second one beside it. As of this audit
the file carries: two path exemptions for the proper name rule
(`identity-path:identity-project-name:...`), and 32 declarations of address
values (`identity-value:...`) grouped by origin, with a comment naming the
source above each group. The full content of every entry stands in that file,
not here - this record does not repeat its count or shape beyond what is needed
to understand the scope of the audit.

## Remediation contract

A hit in the repository history (tree content, a commit message or a file name)
is NOT a situation to fix with another commit - the content is already in the
history. What is required is a history rewrite with `git filter-repo` BEFORE any
public push. If a public push has already happened, rewriting the history does
not undo the fact that the content could have been scraped or mirrored. The same
wording stands in the test message
(`tests/test_history_audit.py::REMEDIATION_MESSAGE`) and in the README.

## Revision conditions

This record requires repeating (a new scan run and a new `head_sha` value
together with a date) when any of the following occurs: a change to the set of
identity layer patterns, a change to the `.confidentiality-allow` exceptions
file, or when the current HEAD drifts from the digest recorded above far enough
that the audit is to be repeated before a public push - which
`scripts/check_history_audit_gate.py` checks by machine with the
`--require-current` flag.

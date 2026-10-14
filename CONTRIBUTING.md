# Contributing to aioquic

Thank you for your interest in improving aioquic! This document describes
how changes are expected to be made, whether they are written by hand or
with the help of a tool.

Please report security vulnerabilities privately, as described in
[SECURITY.md](SECURITY.md), not through issues or pull requests.

## Getting started

Install aioquic in editable mode, together with the tools used by
continuous integration:

```
pip install -e . -r requirements/lint.txt -r requirements/test.txt
```

Work on a branch and open a pull request against `main`.

## Correctness

**RFCs are the authority.** When fixing a bug or implementing new code,
ground the implementation in the relevant RFC sections (e.g. RFC 9000,
9001, 9002, 8446, 9114) and read the actual text rather than relying on
memory. Note where a MUST, SHOULD or MAY applies, and justify behaviour
changes, in comments and commit messages, by the RFC alone.

**Make the smallest change that closes the gap.** Keep a fix to its stated
aim and reuse existing helpers rather than porting an RFC's pseudocode
wholesale. Look for aioquic invariants that make parts of the general
algorithm unnecessary, and list any further RFC alignment as separate
follow-ups.

**Other implementations are a secondary reference.** quiche
(cloudflare/quiche), quic-go (quic-go/quic-go) and picoquic
(private-octopus/picoquic) are useful to compare designs, spot pitfalls
and judge how much a requirement matters in practice, but they are not a
source of truth: they deviate from the RFCs in places, and their behaviour
must be checked in their source code. Do not cite them in commit messages.

## Scope

aioquic does not support TLS client authentication: servers never
validate the client's certificate chain. Please do not report this as a
bug or propose it as a feature. Fixing crashes on the client certificate
code paths is still welcome.

## Code style

Readability is one of aioquic's key goals. Prefer plain, idiomatic Python
over compact or clever code, such as bit tricks ported from C or Rust.
When a performance or memory argument exists, measure it and present the
trade-off rather than assuming it wins.

Avoid duplicating code. Before adding a helper, look for an existing one
that can be reused or extended, and factor out logic that would otherwise
be copied.

Use f-strings in new code, even where nearby code uses `%` formatting.
Logger calls are the exception: they keep lazy `%` arguments.

Insert new functions, methods, `.pyi` stubs and `test_*` methods in
alphabetical order rather than appending them. Do not reorder existing
code unless that is the purpose of the change.

## Comments

Write comments as sentences: start with a capital letter and end with a
full stop, even though much of the existing code uses lowercase comments
without one. Do not reformat existing comments unless that is the
purpose of the change.

Keep comments short, typically one or two lines. State the non-obvious
reason and cite the RFC section in parentheses (e.g. "(RFC 9000 section
9.3)"); a full quote of the RFC text belongs in the commit message. Do not
describe behaviour that is generic in aioquic, such as lost frames being
resent by their delivery handler, or point to related code elsewhere.

## Tests

Test anything involving timers, loss, PTO or retransmission in
`QuicConnectionLossTest` (`tests/test_connection.py`), following its
conventions:

- simulated time starting at `now = 0.0`, moved with `advance_by_tick()`
  or `advance_to_timer()`, with `watch_timers()` on every connection still
  active;
- one block per network hop, introduced by a comment such as "Server
  receives X, sends Y";
- after each step, assertions on the exact datagram sizes, `get_timer()`
  value, sent packets and events;
- no loops until a condition holds: spell out each timer firing;
- a docstring explaining the RFC behaviour being checked.

## Checks

Before submitting, run the checks that continuous integration runs, from
the repository root:

```
python -m unittest discover -v
ruff check
ruff format --check
mypy
check-manifest
codespell
```

## Commit messages

Keep commit messages concise. The subject line states what the commit does
in the imperative; the body explains *why* — the goal being pursued, the
constraint that forced the approach, the non-obvious insight behind the
change. Skip anything a reader can trivially deduce from the diff: do not
enumerate the modified files, restate renamed symbols, or narrate the
changes function by function.

Reference GitHub issues in a trailer at the end of the message, not inline
in the body. Use `Fixes: #N` only when the commit fully resolves the
issue, otherwise `See: #N`.

The changelog (`docs/changelog.rst`) is written at release time, so do not
update it in your pull request.

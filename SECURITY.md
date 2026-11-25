# Security policy

## Reporting a vulnerability

Report privately through GitHub:
[Report a vulnerability](https://github.com/ln80/struct-sensitive/security/advisories/new).
Do not open a public issue, pull request or discussion for a suspected
vulnerability.

Include the affected version, what an attacker gains, and a reproduction if
you have one. We aim to acknowledge a report within 7 days and to agree a
disclosure date with you once a fix is ready. Reporters are credited in the
advisory unless they ask not to be.

## Supported versions

Until v1, only the latest minor release receives security fixes.

## What the library guarantees

struct-sensitive selects fields; it does not protect them by itself. Callers
such as privacy-engine encrypt what it selects, and `Redact` and `Mask`
rewrite it. It guarantees that:

- every field tagged as data is visited exactly once, under the subject the
  tag format assigns it ([docs/tag-format.md](docs/tag-format.md)), or the
  call returns an error. A tagged field is never skipped silently;
- a callback error writes nothing;
- `Mask` never leaves a data value as it was: a value its mask cannot handle
  is fully redacted, and the error names the field path, never the value.

A breach of one of these is a vulnerability. So is a panic reachable from
input data, such as a decoded JSON value.

## Out of scope

- Masking is not anonymisation. A masked email keeps its domain and a masked
  name keeps letters and lengths; this is documented per mask.
- `Masked` holds the original value in memory by design.
- Vulnerabilities in the Go toolchain or dependencies, unless this module
  uses the affected code. Report those upstream.

## Security status

The library has not had an independent security review.

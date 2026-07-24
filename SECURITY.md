# Security Policy

This is a personal research/portfolio project, not a maintained production
system, but reports are still welcome.

## Reporting a vulnerability

If you find a security issue in this repository (in the RSA
implementation, the API service, the Docker image, or a dependency this
project pins to a version with a known vulnerability that hasn't been
updated yet), please open a GitHub issue on this repository with:

- A description of the issue and where it is (file/endpoint/dependency)
- Steps to reproduce, if applicable
- Why you believe it's a security issue rather than a regular bug

There is no bug bounty and no formal SLA -- this is maintained by one
person in their spare time -- but reports will be read and, if valid,
addressed.

## Scope

In scope: the RSA implementation (`src/cryptosentry/rsa.py`,
`src/cryptosentry/primes.py`), the API service
(`src/cryptosentry/api.py`), the Dockerfile, and this repository's
pinned dependencies.

Out of scope: the third-party certificates surveyed via Certificate
Transparency (report data issues to the relevant CA or domain owner),
and anything about how you've deployed this project outside of what's
documented here.

## What this project already does defensively

`generate_keypair()` defaults to `secrets.SystemRandom()` (a CSPRNG
backed by the OS's entropy source), not a seeded PRNG -- see README's
"What changed from v1" for the history of this specific fix. This
project only ever surveys **public keys from public, third-party
certificates** already published in Certificate Transparency logs
(by design, CT logs never contain private keys or anything non-public);
`scripts/download_data.py` never touches a private key belonging to
anyone. No RSA keys are factored, attacked, or broken anywhere in this
project -- see README's Limitations for what the classical/quantum
complexity comparison does and does not do. Beyond that: rate limiting
on the API, no assessed key material ever logged, a non-root container
user, and CI checks (`pip-audit`, `bandit`) on every push.

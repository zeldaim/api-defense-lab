# Security Policy

## This lab is vulnerable on purpose

The target app (DVRA) is **deliberately vulnerable**, and the lab trusts a spoofable `X-Client-IP` header to simulate many users. Those are features of a practice range, not bugs — please don't report them. Run the lab only on `127.0.0.1` and never expose it to the internet.

## What to report

Please report problems in **this repository's own code and supply chain**, for example:

- The lab's containers or ports exposed beyond `127.0.0.1`, or a way for lab traffic to reach the host
- A flaw in the detector, scorer, traffic generator, or tools that could harm the machine running the lab
- Problems in the CI workflows (`.github/workflows/`), image signing, SBOM, or provenance — e.g. a way to publish an image that passes `cosign verify` without coming from `release-image.yml` on `main`
- Secrets accidentally committed

Detection gaps (attacks the rules or model miss) are welcome too, but as normal issues or PRs, not security reports.

## How to report

Use **GitHub private vulnerability reporting**: the repository's *Security* tab → *Report a vulnerability*. Please include steps to reproduce and the commit you tested (`git rev-parse --short HEAD`).

This is a personal project maintained by one person, so there is no SLA. I will acknowledge reports when I can and credit reporters in the fix unless you prefer otherwise.

## Supported versions

Only the latest commit on `main` and the latest `ghcr.io/zeldaim/api-defense-lab/tools` image are supported.

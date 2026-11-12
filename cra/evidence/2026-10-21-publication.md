# Public artifact verification — 21 October 2026

Scope: public API and agent images built from canonical revision
`12e0bf96b11a25763a5a6bf2738f68728fd7064b`. Publication completed for the
full-revision tag and `latest`, with signatures and attestations copied.
Anonymous verification of the public `latest` references succeeded on
21 October 2026. Use the immutable manifest digests below for retained evidence;
`latest` can change after this observation.

| Image | Verified manifest digest |
|---|---|
| `ghcr.io/jr-shdw/rhorizon-api` | `sha256:379e82de1cd61ad5fcae603c9252f0535e0a65e929279805c7a387422e65aa7d` |
| `ghcr.io/jr-shdw/rhorizon-agent` | `sha256:a3dbc8440f19034327400e946eb2f77919e65f28ef5fada6df96c1a0548b2a5d` |

## Checks performed

For both images, Cosign verified the image signature against the repository's
[public key](../../cosign.pub), including the exact `git-commit` annotation.
It also verified SLSA provenance v1 and CycloneDX SBOM attestations. Parsed
attestation subjects matched the image digests above, and the SLSA source
revision matched the canonical revision. Signature and offline transparency
checks passed.

Verifier image:
`gcr.io/projectsigstore/cosign:v3.0.6@sha256:de9c65609e6bde17e6b48de485ee788407c9502fa08b8f4459f595b21f56cd00`.
Public-key file SHA-256:
`b5126ed0e2ae9eb53bfd83abc13f2805a8f45f4aeddcba29403d9e5cab982afc`.

SHA-256 hashes of the locally captured verification output:

| Image | Output | SHA-256 |
|---|---|---|
| API | Signature | `e3cb025bf74249ddced945645c2ae7e64e98211571096149e1463762c610b250` |
| API | SLSA provenance | `f423e68b59ac93437a3840a5bf5ab5cdf74b5a0ff3ed88696ffd5f4ae080a13f` |
| API | CycloneDX | `021f31f9b46b68b6546bee3dc069bd5290e1d7629c6fc3860030f015843894ec` |
| Agent | Signature | `9ea7d953a979fcbf08f887015d56b697dc5c34b57bd9067c4f2f2b1be88f595f` |
| Agent | SLSA provenance | `0f192c56b024943a594c5f824cfcfcc51cc3c2a180e7a232f1a6bfe243c0d42b` |
| Agent | CycloneDX | `f5f061311577d719ce11df8a15b6b137f9250f6aed3c2c38f6bd41bd233a2530` |

The original output is temporary local evidence; these hashes do not establish
a durable archive. Preserve the signed statements and verification reports in
the manufacturer's evidence store. This summary does not reproduce private
infrastructure identifiers contained in the original provenance statements.

## CI evidence and limits

The source pipeline completed successfully. Its vulnerability summary reported
zero HIGH/CRITICAL findings with available fixes for the eight scanned images
and modules, including the frontend. That CI scan uses `--ignore-unfixed`;
the separate [local frontend scan](2026-10-20-frontend.md) did not.

The CI scan used local image tags. It does not establish per-platform scan
coverage bound to each published immutable digest. Signature verification proves
authenticity of the signed statements, not completeness of their contents or
absence of exploitable vulnerabilities. Action A-04 remains open for complete
release evidence, platform coverage and validation of promotion gates.

The frontend Dockerfile patch is public, but no frontend image was published
to GHCR: the existing publication scope remains API and agent only. No Docker
Hub publication is claimed. This record does not establish CRA conformity.

Manufacturer review and release acceptance: **open**.

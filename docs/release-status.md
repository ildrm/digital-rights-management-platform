# Release review — 2026-09-28

**Release status: FAIL.** The self-hosted publishing and licensing slice works against disposable services. The universal rights platform described in the implementation prompt is incomplete and has not passed a production deployment gate.

| Area | Status | Evidence or blocker |
| --- | --- | --- |
| Core policy, entitlement, license, encrypted packaging | PASS for tested slice | Strict typecheck and focused policy, signature, and authenticated encryption tests |
| PostgreSQL schema and tenant isolation | PASS for tested slice | Migrations 001–007 applied locally; non-owner role isolation, policy immutability, challenge replay denial, and seat race tested |
| License and publishing APIs | PASS for tested slice | OIDC verifier and PostgreSQL-backed HTTP tests; no live identity provider or production gateway |
| OpenBao Transit signing and key wrapping | PASS for local integration | Live Ed25519 verification, derived AES-GCM wrapping, authenticated identity mismatch denial, and publish-to-license flow against OpenBao 2.7.0 dev mode |
| S3-compatible encrypted package storage | PASS for local integration | Live SeaweedFS 4.47 mini-mode put, get, integrity, conditional create, and delete tests |
| Transactional outbox | PARTIAL | Issuance and device mutations commit rows atomically; claim/ack tested, but no publisher or consumer deployed |
| Identity, catalog, ingestion, commerce, UI, enterprise | FAIL | Only active-user lookup and a narrow package catalog exist; complete services and interfaces are absent |
| Certified media DRM and protected clients | FAIL | No Widevine, FairPlay, PlayReady, Readium LCP, remote rendering, or production client verifier integration |
| Offline native protection and trusted time | FAIL | License claims exist; client verifier and rollback-resistant state absent |
| Security assurance | FAIL | Threat model and negative-path tests exist; no penetration test or production key lifecycle validation |
| Accessibility and localization | FAIL | No UI to assess |
| Reliability and disaster recovery | FAIL | No durable high-availability deployment, load test, or restore drill |
| Observability and incident response | FAIL | No complete telemetry or exercised incident runbook |
| Deployment and supply chain | PARTIAL | Pinned non-root Node 26 container builds; local audit and SBOM command pass; CI has not run on hosted infrastructure and no signed artifact or staging evidence exists |
| Documentation | PARTIAL | API, provider decision, threat model, and deployment notes exist; full operator and user guides are absent |

The optional AWS KMS and Axinom adapters remain in the repository as inactive contract-tested code. Neither is part of the self-hosted API runtime. No AWS account is required for the tested slice. Self-hosted Transit does not supply certified commercial DRM or a payment processor.

## Executed checks

`npm ci` passed from the lockfile. `npm run typecheck` passed. The full test command with `SELFHOST_TEST=1 BAO_TEST=1 S3_TEST=1 PG_TEST=1 API_TEST=1` passed **22/22**, including real OpenBao and SeaweedFS calls and a PostgreSQL-backed publish-to-license round-trip. `npm audit --audit-level=high` reported **0 advisories**. Migrations through 007 applied to disposable PostgreSQL. The API Docker image rebuilt successfully after the provider change. These tests used disposable OpenBao dev mode and SeaweedFS mini mode; they do not establish high availability, durability, production TLS, scoped credentials, or provider certification.

## Next release gates

1. Complete identity, catalog, ingestion, version management, commerce, creator and enterprise APIs, UI, and the transactional outbox publisher/consumers.
2. Deploy OpenBao, SeaweedFS, PostgreSQL, and OIDC with production TLS, scoped credentials, backup and restore, key rotation, audit, monitoring, and failover; verify those controls in staging.
3. Implement and validate the required commercial DRM and protected clients against licensed providers and platforms. The generic secure-viewer format is only one distribution mode.
4. Complete security, performance, compatibility, accessibility, and disaster-recovery campaigns before changing release status.

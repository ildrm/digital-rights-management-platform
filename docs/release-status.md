# Release review — 2026-09-30

**Release status: FAIL.** The self-hosted publishing and licensing slice works against disposable services. The universal rights platform described in the implementation prompt is incomplete and has not passed a production deployment gate. Local PASS entries below describe only narrow checks of this revision, not production acceptance. See the [requirements audit](production-audit.md) for the feature-by-feature gap review.

| Area | Status | Evidence or blocker |
| --- | --- | --- |
| Core policy, entitlement, license, encrypted packaging | LOCAL PASS, INCOMPLETE | Strict typecheck and focused tests of the narrow primitive; no protected client or full policy enforcement |
| PostgreSQL schema and tenant isolation | LOCAL PASS, INCOMPLETE | Migrations 001–013, SQL isolation, separate API/worker roles, and denied-privilege tests; no production migration or restore evidence |
| License, publishing, and package retrieval APIs | LOCAL PASS, INCOMPLETE | OIDC verifier, 8 MiB uploads, durable idempotent publication, owner-scoped operation status, recovery, and HTTP admission limits; live IdP absent |
| OpenBao Transit signing and key wrapping | LOCAL PASS, INCOMPLETE | Live checks against disposable OpenBao 2.7.0 dev mode; no HA, production TLS, or key lifecycle proof |
| S3-compatible encrypted package storage | LOCAL PASS, INCOMPLETE | Live SeaweedFS 4.47 mini-mode put/get/integrity tests; no replicated filer metadata or object recovery proof |
| Transactional outbox delivery | FAIL | Claim fencing, crash retry exhaustion, signed HTTPS worker, and requeue pass local tests; no production destination, deployed worker, idempotent recipient or alert proof |
| Identity, catalog, ingestion, commerce, UI, enterprise | FAIL | Only active-user lookup and a narrow package catalog exist; complete services and interfaces are absent |
| Certified media DRM and protected clients | FAIL | No Widevine, FairPlay, PlayReady, Readium LCP, remote rendering, or production client verifier integration |
| Live DRM and payment-provider certification | BLOCKED BY EXTERNAL DEPENDENCY | No provider agreements, credentials, certified devices, payment account, or external test environment; application features are also incomplete |
| Offline native protection and trusted time | FAIL | License claims exist; client verifier and rollback-resistant state absent |
| Security assurance | FAIL | Threat model and negative-path tests exist; no penetration test or production key lifecycle validation |
| Accessibility and localization | FAIL | No UI to assess |
| Reliability and disaster recovery | FAIL | No durable high-availability deployment, load test, or restore drill |
| Observability and incident response | FAIL | No complete telemetry or exercised incident runbook |
| Deployment and supply chain | FAIL | Pinned non-root Node 26 container builds; local audit and SBOM command pass; CI has not run on hosted infrastructure and no signed artifact or staging evidence exists |
| Documentation | FAIL | API, provider decision, threat model, deployment notes and requirements audit exist; full operator and user guides are absent |

The optional AWS KMS and Axinom adapters remain in the repository as inactive contract-tested code. Neither is part of the self-hosted API runtime. No AWS account is required for the tested slice. Self-hosted Transit does not supply certified commercial DRM or a payment processor.

## Executed checks

For this working-tree revision, `npm run test:integration` passed strict TypeScript checking and **33/33 tests, with zero skipped**. The command creates and removes disposable PostgreSQL, OpenBao, and SeaweedFS services. Checks include a restricted-role publish-to-license-and-retrieve journey, uncertain uploads and COMMIT acknowledgements, idempotent retries, restart recovery, abandonment cleanup, active database disconnect/recovery, stalled storage reads, outbox fencing, HTTP admission limits, and maximum-size upload. Migrations 001–013 passed on fresh PostgreSQL 17; rerunning the ledger-based runner made no changes. `tests/postgres/core.sql` and separate runtime-role provisioning passed. The earlier remediation batch also passed an upgrade of migrations 011–012, an audit reporting zero known vulnerabilities, and SBOM generation with 54 components. Hosted PostgreSQL 18 CI has not run for this revision. These local tests do not establish high availability, production durability, TLS, deployed credentials, or provider certification.

## Next release gates

The updated Docker image also built successfully and passed package/API imports as UID 1000 with a read-only filesystem and networking disabled. Its production dependency installation reported zero known vulnerabilities. This smoke test does not exercise configured service startup or a deployed gateway.

1. Complete identity, catalog, ingestion, version management, commerce, creator and enterprise APIs and UI; deploy the outbox worker with an idempotent recipient and alerting.
2. Deploy OpenBao, SeaweedFS, PostgreSQL, and OIDC with production TLS, scoped credentials, backup and restore, key rotation, audit, monitoring, and failover; verify those controls in staging.
3. Implement and validate the required commercial DRM and protected clients against licensed providers and platforms. The generic secure-viewer format is only one distribution mode.
4. Complete security, performance, compatibility, accessibility, and disaster-recovery campaigns before changing release status.

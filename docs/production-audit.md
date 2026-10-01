# Production requirements audit — 2026-09-29

This is the **historical 2026-09-29 baseline**. Current findings and revision-specific evidence are in the [2026-09-30 implementation status](remediation-implementation-status.md) and [release review](release-status.md). Scope: the 5,236-line universal digital-rights implementation prompt supplied with this project, all repository documentation, migrations, source, tests, container configuration, and CI. A missing subsystem is a release failure, even when a related interface or design note exists. `PASS` means only the stated narrow capability was exercised locally on that historical revision; it does not certify a production deployment.

Every failed area has an implementation path and acceptance check in the [production remediation plan](production-remediation.md).

## Implemented and exercised capabilities

| Capability | Status | Evidence and limit |
| --- | --- | --- |
| Basic rights model and policy normalization | PASS | `packages/core`; deterministic digest, contradiction and malformed-input tests. It is ODRL-inspired, without ODRL import/export or full target compilation. |
| Entitlement decision function | PASS | Tenant, subject, action, policy, validity and supported constraint checks; caller-supplied usage and duty facts are trusted only in the library. |
| Signed device-bound license primitive | PASS | Ed25519 signature, one-time challenge, bounded server-side issuance, claim and time validation; no production client or trusted offline clock. |
| Generic encrypted package primitive | PASS | AES-256-GCM chunks, signed manifest, key wrapping, canonical metadata validation and tamper tests; authorized plaintext can still be copied. |
| PostgreSQL tenant-scoped licensing slice | PASS | Seven migrations, forced RLS, non-owner role checks, serialized device-seat test, immutable policy and package rows. No production database topology. |
| Active OpenBao and SeaweedFS adapters | PASS | Real disposable-service signing, wrapping, conditional object write and publish-to-license tests. Dev/mini modes do not prove production durability or scoped access. |
| OIDC-protected narrow API | PASS | Local verifier and HTTP tests for device enrollment, challenges, revocation, license, 8 MiB publishing, and licensed ciphertext retrieval. No live IdP test or customer client. |

## Required product and enforcement gaps

| Prompt area | Status | Missing release requirement |
| --- | --- | --- |
| Universal policy compiler and protection profiles | FAIL | Most target-specific enforcement payloads, complete compatibility proofs, creator explanations/UI, and full ODRL interoperability. Static capability declarations are not certified enforcement. |
| Identity and organizations | FAIL | Account lifecycle, MFA/WebAuthn, tenant administration, SSO, SCIM, roles and service accounts; only token verification and active-user lookup exist. |
| Asset ingestion and catalog | FAIL | Scanning, type inspection, sandboxing, transformations, versioning, metadata/search and retrieval. One bounded JSON upload creates version 1 only. |
| Video, live video, audio, books, publications, documents and images | FAIL | Packaging pipelines, media players/readers, accessibility tracks, playback control and rights-specific adapters. |
| Widevine, FairPlay, PlayReady and publication DRM | FAIL | Certified provider integration, platform credentials, license servers, CDM interoperability and device robustness tests. Provider agreements and credentials are also unavailable. |
| Secure viewer and protected local execution | FAIL | Protected consumer clients, trusted time, rollback detection, output policy, native key storage and anti-tamper tests. A server-side chunk opener is only a primitive. |
| Software, fonts, games, CAD, datasets and AI models | FAIL | Type-specific licensing, SDKs, execution controls, protected delivery and usage accounting. |
| Remote execution and maximum protection | FAIL | Isolated compute, session brokering, streaming, secret handling, billing and abuse controls. |
| Marketplace, commerce, subscriptions and tax | FAIL | Hosted Checkout, immutable one-time orders, reconciliation, purchase grants, and gross-sale journals now have local tests. Subscriptions, fees, invoices, refunds, disputes, tax, payouts, and real provider qualification remain missing; no gateway account is available. |
| Royalties and rights chain | FAIL | Split agreements, append-only royalty ledger, settlement, ownership evidence and disputes. |
| Creator studio, customer library and cross-device state | FAIL | All responsive user interfaces and corresponding workflows. |
| Offline access and lending | FAIL | Native lease storage, trusted time, offline revocation bounds, return/lending state and institutional controls. |
| Enterprise, white-label and administration | FAIL | Seat administration, policy delegation, branding, support, moderation and approval workflows. |
| Provenance, fingerprinting and watermarking | FAIL | C2PA integration, robust matching, visible/forensic marking and extraction validation. |
| Piracy incidents, claims and takedowns | FAIL | Evidence handling, investigations, appeals, legal holds and notification workflows. |
| Fraud, privacy and analytics | FAIL | Risk decisions, consent/retention/deletion, creator/platform/security analytics and reporting. |
| Developer platform and webhooks | FAIL | Public SDKs, documentation portal, webhook delivery/retry/signature, API keys and compatibility policy. |
| Accessibility and internationalization | FAIL | No UI, screen reader, keyboard, contrast, caption, localization or language-switching campaign. |

## Production engineering and assurance gaps

| Area | Status | Missing evidence or control |
| --- | --- | --- |
| Security assurance | FAIL | Independent review, penetration tests, parser fuzzing, hardware trust, key compromise drills and live provider threat tests. |
| Durable deployment | FAIL | Production OpenBao seal/storage, SeaweedFS replication, hardened PostgreSQL, OIDC, TLS gateway, network policy and deployment manifests. |
| Backups and disaster recovery | FAIL | Encrypted standalone Docker backups and isolated data/key recovery pass locally. Off-host recovery, production RPO/RTO, failover/fencing, continuous WAL archiving, and rollback qualification remain open. |
| Observability and response | FAIL | Metrics, tracing, dashboards, alerts, audit retention, incident exercises and runbooks. |
| Outbox delivery | FAIL | A separate signed HTTPS worker, capped retry, dead-letter state and explicit requeue now pass local tests. No production destination, deployed worker, consumer idempotency proof or alert has been verified. |
| Data lifecycle | FAIL | Tenant-scoped bounded rate-window and challenge cleanup is implemented and tested; orphan-object reconciliation, retention schedules and privacy deletion remain. |
| Performance and compatibility | FAIL | No load, soak, chaos, browser/device/DRM matrix or production-like capacity measurements. |
| Supply-chain release | FAIL | Dependency lock, SBOM, audit, pinned CI actions/images and non-root container exist; no hosted CI execution proof, signed image, provenance attestation or staging promotion. |
| Operational and user documentation | FAIL | Narrow API and design notes exist; installation automation, full operator procedures, user guides and support workflows are absent. |

## Defects corrected in this review

- Reject malformed nested policy fields and negative decision counters with domain errors instead of silently accepting them or raising unhandled type errors.
- Charge the authenticated publish quota before reading or decoding an upload body.
- Validate signed license claim shape and times, enforce `offlineUntil` on explicit offline opens, and bound package metadata before manifest verification and decryption.
- Wipe the API's decoded publish buffer after use, remove the stale startup error listener, ignore local `.env.*` secrets, and pin CI actions and disposable images to immutable digests.
- Treat OpenBao and JWKS network failures as service unavailability rather than a user authorization denial.
- Bound streamed OpenBao response bodies even when the server omits `Content-Length`, preventing an unbounded response allocation.
- Correct the architecture diagram and standards baseline; document the actual implemented server boundary and remaining client obligations.
- Add an outbox delivery worker with HMAC-signed HTTPS requests, bounded retry, dead-letter recovery, and tenant-scoped cleanup of expired transient rows; add migration 008 and focused integration tests.
- Bind issued licenses to rendition IDs and add an authenticated, rate-limited package retrieval route with database grant checks and bounded S3 length/checksum verification; add migration 009 and live denial tests.

## Ship-gate category review

| Category | Status | Evidence |
| --- | --- | --- |
| Security | FAIL | Signature, tenant and input checks passed locally; no production TLS/gateway, protected client, penetration test or key incident drill. Bearer-only routes set no cookies, so browser CSRF/cookie checks do not apply to this API. |
| Database | FAIL | Parameterized queries, forced RLS and non-owner isolation passed; no production backup/restore or data-retention job. |
| Code | PASS | Strict typecheck and 27 local/live tests passed for the implemented slice; this does not cover absent product features. |
| Dependencies and supply chain | FAIL | Lockfile, zero-advisory audit, SBOM and pinned CI actions/images exist; no hosted CI evidence, image signing or release attestation. |
| AI/LLM | NOT APPLICABLE | No LLM runtime is included. The prompt's AI-model licensing remains unimplemented product scope. |
| Deployment | FAIL | Local image builds and runs as non-root; no production topology, staging promotion, rollback or restore proof. |
| Frontend | FAIL | No UI exists; accessibility, responsive behavior and localization cannot be verified. |
| Observability | FAIL | Narrow JSON process/error logs exist; no metrics, tracing, alerts or exercised response workflow. |

## Verification performed

All nine migrations and `tests/postgres/core.sql` passed on disposable PostgreSQL 18. The full suite with `PG_TEST=1`, `API_TEST=1`, `BAO_TEST=1`, `S3_TEST=1`, and `SELFHOST_TEST=1` passed **27/27** against disposable OpenBao 2.7.0 and SeaweedFS 4.47. TypeScript strict typecheck, `npm audit --audit-level=high` (0 vulnerabilities), CycloneDX SBOM generation, workflow YAML parse, Docker build, non-root UID and active-adapter image smoke checks passed locally. Hosted CI, staging, production TLS, backup restore, accessibility, load, chaos, fuzz and penetration tests were not run.

**Release decision: FAIL.** No production deployment or public launch is authorized by these checks.

# Production remediation plan

This maps every failed area in the [requirements audit](production-audit.md) to an implementation path and an observable release check. The platform cannot be declared production-ready by replacing licensed DRM or payment networks with generic encryption or test doubles. Those integrations require provider agreements, credentials, real devices, and external certification. The self-hosted stack remains the base for the generic secure-viewer mode; target-specific workers and clients must be added around it.

## Product and enforcement

| Failed area | Implementation path | Release check |
| --- | --- | --- |
| Universal policy compiler | Define a versioned typed policy grammar and explicit lowering for each supported target. Reject any rule the target cannot enforce; document creator-facing reasons. Add ODRL import/export only after round-trip semantics are specified. | Golden policy corpus, cross-target equivalence tests, and adversarial unsupported-rule tests pass. |
| Identity and organizations | Integrate a managed or self-hosted OIDC identity service with MFA/WebAuthn, tenant provisioning, role grants, SSO, SCIM, and service accounts. Keep verified tenant and subject claims bound to database membership. | End-to-end provisioning, deprovisioning, role escalation denial, token rotation, and account recovery tests pass with a live provider. |
| Asset ingestion and catalog | Add a quarantine bucket and asynchronous ingestion worker for type inspection, malware scanning, metadata extraction, transformations, versioning, search, and safe retrieval. Publish only after all checks pass. | Malicious, malformed, oversized, duplicate, and concurrent version cases pass; catalog and retrieval match stored checksums. |
| Media and publication formats | Implement separate format pipelines and accessible players/readers for video, live, audio, books, publications, documents, and images. Keep target adapters isolated from the policy core. | Supported format/device matrix passes playback, accessibility, key rotation, revocation, and output-control tests. |
| Commercial DRM | Contract with licensed Widevine, FairPlay, PlayReady, and publication DRM providers, or explicitly exclude those formats from a separately approved release scope. Use provider SDKs and certification programs; generic AES packages are insufficient. | Provider certification, hardware/device robustness, interoperability, revocation, and license failure tests pass on real platforms. |
| Secure viewer and local execution | Build and sign native clients with OS key storage, trusted clock and rollback defense, offline lease persistence, screen/output policy, and update enforcement. | Tampering, clock rollback, revoked device, offline expiry, reinstall, and copied-package tests pass on supported OS versions. |
| Software, fonts, games, CAD, datasets, AI models | Define target-specific SDK and execution hooks, usage accounting, protected delivery, and contract semantics for each asset type. | Product-specific compatibility suites and abuse tests pass for every advertised type. |
| Remote execution | Isolate sessions with per-session compute, brokered access, short-lived credentials, output controls, metering, and resource quotas. | Tenant escape, data exfiltration, session replay, quota, teardown, and recovery tests pass under load. |
| Commerce, subscriptions, and tax | Integrate a PCI-compliant payment provider. Add order and subscription state machines, webhook verification, double-entry ledger, invoices, refunds, tax calculation, and payout reconciliation. | Sandbox and live small-value reconciliation, webhook replay, refund, dispute, and ledger-balance tests pass. |
| Royalties and rights chain | Store versioned rights evidence and split agreements; calculate royalties from immutable sales/usage entries and support disputes and settlement. | Recompute historical statements exactly; verify split totals, reversals, and audit evidence. |
| Creator studio and customer library | Build responsive web interfaces on documented APIs for upload, policy preview, catalog, purchase, entitlement, library, and support workflows. | End-to-end user journeys, keyboard and screen-reader checks, and cross-device state tests pass. |
| Offline access and lending | Extend native clients with a rollback-resistant trusted clock, bounded offline leases, return/lending state, and institutional seat controls. | Clock tamper, double spend, simultaneous borrow, revocation bounds, and expired lease tests pass. |
| Enterprise and white-label | Add tenant administration, delegated policy approval, seat management, branding isolation, moderation, and support audit trails. | Role and tenant isolation, approval bypass, branding leakage, and seat-race tests pass. |
| Provenance, fingerprinting, watermarking | Use supported provenance metadata and media-specific fingerprint/visible/forensic marking pipelines with extraction checks. | Transformation survival, false-positive, removal, and chain-of-custody test corpus passes. |
| Piracy incidents and takedowns | Add case records, evidence hashes, legal holds, appeal state, notifications, and audited operator actions. | Evidence preservation, access-control, appeal, retention, and notification tests pass. |
| Fraud, privacy, analytics | Add risk signals and review controls; define consent, retention, deletion and data export; build tenant-scoped analytics from event streams. | Privacy deletion/export, consent withdrawal, abuse simulation, and analytics reconciliation pass. |
| Developer platform | Publish versioned SDKs and API contracts, signed webhooks, retry and idempotency guidance, compatibility policy, and a developer portal. | Contract suites pass across supported SDK languages and API versions. |
| Accessibility and internationalization | Build interfaces to WCAG 2.2 AA targets with keyboard, assistive technology, captions, contrast, and localized content workflows. | Independent accessibility audit and locale/device matrix pass. |

## Engineering and assurance

| Failed area | Implementation path | Release check |
| --- | --- | --- |
| Security assurance | Commission independent review and penetration testing; add fuzzing of policy, package, license, and API parsers and key-compromise drills. | All critical and high findings closed and retested; documented residual risk accepted. |
| Durable deployment | Deploy PostgreSQL, OpenBao, object storage, OIDC, API, and worker with TLS, isolated networks, scoped workload identities, replication, and automated migrations. | Staging topology mirrors production; failover and key-rotation exercises pass. |
| Backups and disaster recovery | Automate encrypted PostgreSQL, OpenBao, and object-store backups with retention and access controls; restore all three to a clean environment. | Measured RPO/RTO and integrity checks meet agreed objectives in repeated drills. |
| Observability and response | Export metrics/traces, structured logs, outbox backlog and dead-letter alerts, dashboards, audit retention, and incident runbooks. | Synthetic failures trigger alerts and an on-call exercise resolves them within the SLO. |
| Outbox delivery | The worker now supports signed HTTPS delivery, bounded retries, dead-letter state, and explicit requeue. Deploy a recipient that verifies signatures and deduplicates event IDs; provision tenant lists and alert on backlog. | Live worker/recipient failover, replay, idempotency, and dead-letter recovery tests pass. |
| Data lifecycle | Tenant-scoped expiry cleanup now runs in bounded worker batches. Add orphan-object reconciliation, retention policies, privacy deletion, and evidence-preserving legal holds. | Reconciliation and deletion jobs pass on representative data without cross-tenant effects. |
| Performance and compatibility | Define SLOs, capacity targets, device/DRM matrix, then run load, soak, chaos, and cross-version tests on production-like infrastructure. | Capacity and error budgets met with recorded traces and repeatable results. |
| Supply-chain release | Run pinned CI on hosted infrastructure, sign images and attest provenance, scan SBOM, promote through staging, and keep a rollback artifact. | Reproducible signed release and rollback are verified by a clean deployment. |
| Operational and user documentation | Write exact install, migration, backup/restore, key rotation, incident, support, and end-user guides tied to deployed behavior. | A second operator restores and operates the system using only the runbooks. |

## Delivery order

1. Close the dependable core: tenant lifecycle, an idempotent outbox recipient, object reconciliation, backups, telemetry, and staging deployment; harden the new licensed ciphertext retrieval path under load.
2. Complete identity, entitlement commerce, catalog, versioning, and accessible creator/customer interfaces.
3. Implement target-specific DRM and clients with licensed providers, then format-specific test matrices.
4. Add enterprise, royalties, provenance, privacy, fraud, remote execution, and developer SDKs; finish independent security and operational acceptance campaigns.

Each row remains a release blocker until its check has evidence. Local unit/integration tests of the current narrow slice do not close these gates.

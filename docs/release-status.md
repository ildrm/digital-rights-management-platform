# Release review — 2026-10-01

**Release status: FAIL.** The implemented standalone slice has expanded, with tested commerce, tenant administration, encrypted Docker backups, and local data/key recovery. The universal product and its production qualification remain incomplete.

## Implemented and verified

| Area | Result | Remaining limit |
| --- | --- | --- |
| Policy, licenses, packages | Signed device-bound licenses and authenticated encrypted packages | No protected consumer client or certified media DRM |
| PostgreSQL | Migrations 001–019; restricted API/worker roles, forced tenant RLS, immutable commerce records | Single host; production failover and retention unqualified |
| Administration | Active stored admin role plus token scope; subject provisioning, free/organization/trial grants, suspension/revocation, seat/license revocation, last-admin protection | No consumer login, MFA, SSO/SCIM, account recovery, or full organization/RBAC product |
| One-time commerce | Immutable offers/orders, Stripe hosted Checkout adapter, verified raw webhook processing, authoritative retrieval, idempotent purchase grants and gross-sale journals, background reconciliation | No real Stripe account/tests; refunds, disputes, fees, subscriptions, invoices, royalties, tax, and payouts incomplete |
| Docker standalone | Pinned Node 24 LTS and PostgreSQL 18; local signing/wrapping/auth; database TLS; localhost API | No public TLS edge or redundant multi-host topology |
| Backup/recovery | Docker scheduler encrypts consistent PostgreSQL dump plus twelve recovery files; retention and health check; isolated Docker recovery of authentication, library, license, package, and plaintext integrity passed | No off-host campaign, software-image recovery, WAL archiving, failover/fencing, key rotation, or measured outage RPO/RTO |
| Operations | Bounded readiness/catalog load harness, snapshot digest drill, corrected tenant discovery | Representative sustained load, alert/on-call delivery, security/accessibility audits, and signed releases incomplete |

The formal-LTS path uses Node and PostgreSQL only. Optional OpenBao, S3/SeaweedFS, external OIDC, AWS, and Axinom integrations remain outside this path. Formal service LTS does not establish an owner support commitment for the application; that release policy remains required.

## Evidence for this revision

- Strict TypeScript and whitespace checks passed.
- Local PostgreSQL/HTTP integration gate: **41 passed, three optional live-provider skips, zero failures**, covering all nineteen migrations, restricted roles, duplicate/concurrent settlement, mismatched payment terms, missed-webhook recovery, administration authorization/revocation, and backup tampering/wrong-key rejection. Host Node was 26.5.0; Docker runtime checks used the pinned LTS version.
- PostgreSQL snapshot restore matched all **25 table digests**. Dump: 110826 bytes; local dump/restore times approximately 0.252/0.084 seconds. This is not full-service RTO or RPO.
- Exact Node 24.21.0 Docker runtime, with container networking disabled: **26 offline tests passed**, 18 environment-gated tests skipped, zero failures.
- The existing Docker database upgraded from migration 015 to 019 without replacing its volume or credentials. API and PostgreSQL reported healthy.
- Docker administration smoke passed: idempotent subject/grant creation, free-grant library visibility, stored-role denial despite an admin-scoped customer token, suspension/reactivation, offer creation, and fail-closed unconfigured payments.
- Encrypted manual backup: 113220 bytes, SHA-256 `10d3d4574c02d97287c809928b91d2acfe0b3d2c6817c6520b5d7fee3b182de4`. Extracted twelve recovery files and restored the 100187-byte dump into a fresh Docker volume/project. The recovered API passed customer authentication, library, enrollment, signed license, package retrieval, manifest verification, unwrap, and the original canary content checksum.
- The Docker backup scheduler produced its first encrypted archive and reported healthy. Its actual runtime is pinned Node 24 on the pinned PostgreSQL image, with database TLS and no Docker socket.
- Previous readiness-only check: 200/200 requests over ten seconds, zero errors, observed p95 9.97 ms. It does not qualify product capacity. Hosted CI and payment/provider certification were not executed.

## Remaining release blockers

1. Customer identity and recovery, accessible creator/customer interfaces, searchable ingestion/versioning and safety checks, broader rights/organization controls, and the remaining product capabilities in the [requirements audit](production-audit.md).
2. Refund/dispute/subscription/tax/fee/invoice/payout and royalty workflows; Stripe credentials followed by real sandbox/live reconciliation. Commercial DRM agreements, certification, protected clients, and real-device enforcement require provider and platform access.
3. Redundant Docker deployment, public TLS, PostgreSQL failover/fencing, continuous WAL/off-host backup recovery, key rotation, and measured production RPO/RTO. The current topology is single-host evaluation.
4. Representative sustained load/soak/chaos, independent security/accessibility review, alert/incident exercises, reproducible signed artifacts, hosted CI, and an application support policy.

[Commerce and administration](commerce.md) and [backup/recovery](backup-recovery.md) describe exact configuration, behavior, and limits. Local evidence closes individual implementation checks; it does not close the full production release gate.

# Release review — 2026-10-01

**Release status: FAIL.** The repository implements a tested secure-viewer slice. It is not the full universal digital-rights product and has no production deployment evidence.

## Implemented in this working tree

| Area | Result | Limit |
| --- | --- | --- |
| Core policy, licenses, encrypted packages | Local tests pass | No protected browser/native client or certified media DRM |
| PostgreSQL schema and tenant isolation | Migrations 001–015, restricted role checks, package byte storage, catalog listing | No HA deployment or measured production recovery |
| API | Device, license, bounded publish, package retrieval, creator/library listing | No full account lifecycle, creator/customer UI, scanning, or media processing |
| Standalone service path | Docker Compose runs Node 24 LTS and PostgreSQL 18; local Ed25519 signing, tenant-bound AES-GCM wrapping, and operator-issued tokens remove mandatory OpenBao, S3, and OIDC service dependencies | Local tokens are an operator mechanism, not a consumer identity product; single database host and localhost HTTP are not HA or public TLS |
| Payments | Stripe PaymentIntent creation and webhook signature/amount validation adapter has offline tests | No order state machine, entitlement grant, refund/reconciliation, Stripe account, sandbox or live transaction proof |
| Operations | Bounded load harness and PostgreSQL snapshot/restore drill | Local smoke/restore evidence is not sustained capacity, RPO/RTO, or disaster recovery proof |

The optional OpenBao, SeaweedFS/S3, external OIDC, AWS, and Axinom adapters remain in source for compatibility. They are outside the formal-LTS standalone Compose path. The user requires **formal LTS for every runtime service**; an OpenBao/SeaweedFS community deployment cannot be claimed compliant without a formal support commitment. The Node application itself requires an owner support and patch policy before release.

## Verification in this revision

- Strict TypeScript check passed.
- Pinned Node 24.21.0 ran 38 tests: 23 passed, 15 environment-gated cases skipped, zero failed.
- `LOCAL_NO_DOCKER=1 npm run test:integration` passed 35 tests with three live-provider skips against disposable local PostgreSQL.
- PostgreSQL snapshot/restore matched 18 table digests in the local drill. A two-second loopback load harness smoke returned 20/20 responses.
- Docker Compose built the app and started PostgreSQL 18 and the API on localhost. All 15 migrations and runtime-role provisioning completed; both containers reported healthy. The API returned `{"status":"ready"}`, and `pg_stat_ssl` showed the `drm_api` connection using TLS.
- An operator-issued token authenticated to `/v1/library`. `scripts/smoke-standalone.ts` published an asset, retried with the same idempotency key, and found the asset in `/v1/creator/assets` against the running Docker stack.
- A 10-second, 20-request/s readiness load check completed 200/200 requests with zero errors and 9.97 ms observed p95. It covers only the health/database query, not representative product capacity.
- Failover, a full stack backup/restore, key recovery, public TLS, sustained load, and payment/provider certification remain **unverified**.

## Release blockers

1. Complete customer identity, administration, catalog ingestion and versioning, commerce/orders/ledger, payouts, UI, client enforcement, and the remaining product requirements in the [requirements audit](production-audit.md).
2. Obtain Stripe credentials and required commercial DRM/provider agreements, then execute provider sandbox, certification, webhook replay, and live operational tests. The adapter alone cannot create real payments.
3. Deploy a redundant Docker topology with a supported failover design for PostgreSQL, TLS at the public edge, monitored backups including key material, restore and failover exercises, and measured RPO/RTO. The current single-host Compose is an evaluation deployment.
4. Qualify sustained representative load, security review, accessibility, incident response, and signed release artifacts before changing this gate.

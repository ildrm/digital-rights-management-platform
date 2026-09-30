# Digital rights platform

This repository is an executable foundation of a universal digital-rights platform. It contains a strict TypeScript rights model, deterministic policy compiler, entitlement evaluator, signed device-bound license issuer, authenticated encrypted chunk packaging, PostgreSQL issuance path, and a self-hosted OpenBao/SeaweedFS publishing path. It is **not production ready**. The [release review](docs/release-status.md), [requirements audit](docs/production-audit.md), [remediation plan](docs/production-remediation.md), and [current implementation status](docs/remediation-implementation-status.md) track the work still required.

## Run

Requires Node.js 26 and npm.

```sh
npm ci
npm run typecheck
npm test
# Full disposable PostgreSQL/OpenBao/SeaweedFS gate (local PostgreSQL tools + Docker):
npm run test:integration
```

For a local PostgreSQL schema check, run `npm run migrate` against a disposable database using PostgreSQL connection environment variables or `MIGRATION_DATABASE_URL`, then run `tests/postgres/core.sql` as its owner. The migration runner serializes deployments and verifies checksums; an existing pre-ledger installation requires a controlled baseline before using it. A remote migration connection requires `MIGRATION_DATABASE_CA_FILE`. The SQL test creates a temporary non-owner role and rolls its test data back. Live database tests require `PG_TEST=1` and `PG_TEST_DATABASE=drm_test_*`, plus a non-owner database role with table privileges; they are skipped during the default unit run. The HTTP loopback test requires `API_TEST=1` and an environment that permits a local listener.

The code includes a narrow authenticated device, license, publishing, and encrypted-package retrieval API. It verifies OIDC access tokens, binds requests to a tenant and active user, enrolls software-trust devices after key-possession proof, applies PostgreSQL rate limits, and calls transactionally consistent services. OpenBao Transit supplies signing and content-key wrapping; a live disposable OpenBao test passed. The API must not be exposed publicly until protected clients, broader policy enforcement, and operational controls are complete. See the [API contract](docs/api.md), [deployment notes](docs/deployment.md), and [technology decisions](docs/provider-decisions.md).

The publishing path creates an encrypted secure-viewer package, stores it through an S3-compatible adapter, and atomically records the asset, policy, rendition, package checksum, audit event, and outbox event. The adapter uses a private object key, a SHA-256 upload checksum, and conditional creation. A live disposable SeaweedFS test passed. An optional `drm:publish` API route accepts assets up to 8 MiB. It is not a complete media ingestion pipeline.

A separate outbox worker can deliver these events to a configured HTTPS recipient with an HMAC signature, bounded retry, dead-letter state, and explicit recovery. It also cleans expired rate windows and one-time challenges per tenant. See the [deployment notes](docs/deployment.md) and [worker configuration](config/outbox.env.example). No production recipient or deployment has been verified.

## Structure

- `packages/core/src`: policy, entitlements, licensing, and encrypted packaging
- `packages/core/test`: security and correctness tests
- `packages/postgres/src`: tenant-scoped transactions, device challenges, license issuance, outbox dispatch, and expiry cleanup
- `infrastructure/postgres/005_outbox.sql`: tenant-scoped durable event queue for security-sensitive mutations
- `packages/openbao/src`: active self-hosted signing and content-key wrapping adapter
- `packages/aws-s3/src`: S3-protocol encrypted package storage adapter, tested with SeaweedFS
- `packages/aws-kms/src`: optional AWS adapter, inactive in the API runtime
- `infrastructure/postgres/006_asset_packages.sql`: immutable, tenant-scoped package catalog
- `packages/axinom/src`: narrowly scoped online playback message adapter
- `packages/api/src`: OIDC-protected API, signed webhook outbox worker, and deployment entry points
- `docs/product.md`: product framing and protection profiles
- `docs/architecture.md`: boundaries and data flow
- `docs/threat-model.md`: trust boundaries and residual risks
- `docs/release-status.md`: evidence-based release gate
- `docs/production-audit.md`: prompt-to-implementation gap matrix and verification record
- `docs/production-remediation.md`: implementation path and acceptance check for every failed area

## Security principle

DRM cannot make copying impossible. The system should minimize reusable plaintext, authenticate and bind licenses, use trusted execution where available, and offer remote execution for assets whose source must stay server-side. Authorized exports remain copyable and must be described honestly.

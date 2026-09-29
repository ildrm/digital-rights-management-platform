# Self-hosted deployment notes

This is a deployment path for the implemented secure-viewer slice. The [release gate](release-status.md) remains FAIL; the API must not be exposed as a production product yet.

## Services

1. Run PostgreSQL with TLS, backups, and a dedicated non-owner application role without `BYPASSRLS`. Apply `infrastructure/postgres/001_core.sql` through `009_package_retrieval.sql` in order with a migration role. Grant the app role only required table privileges and verify `FORCE ROW LEVEL SECURITY` with it.
2. Run OpenBao 2.7.0 or later with TLS, durable storage, audit logging, recovery/unseal procedures, and a scoped workload token. Enable Transit. Create an Ed25519 signing key (`type=ed25519`, `exportable=false`) and a derived AES-256-GCM key per tenant (`type=aes256-gcm96`, `derived=true`, `exportable=false`). Pin the signing version in configuration. Do not give the API token permission to create, export, rotate, or delete Transit keys.
3. Run a maintained S3-compatible object service such as SeaweedFS with TLS, private bucket, scoped credentials, replication, backups, and restore drills. The API needs conditional `PutObject`, `GetObject`, SHA-256 checksum, and delete for failed publishing. Objects contain application-encrypted packages; no server-side AWS KMS setting is required.
4. Run an OIDC provider that signs short access tokens with trusted `tenant_id`, `drm:license`, and `drm:publish` scopes. Map subjects to active users in `drm.users`. The API requires a verified HTTPS issuer and JWKS URL.
5. Put an HTTPS gateway in front of the API. Apply edge rate limits, upload size limits, logging, and network policy. The app container listens on internal HTTP only.

OpenBao supports both Raft and PostgreSQL durable storage. These are operator choices requiring a backup and recovery design. The disposable tests used OpenBao dev mode and SeaweedFS mini mode only; neither is a production topology. [OpenBao storage guidance](https://openbao.org/docs/configuration/storage/), [SeaweedFS release images](https://github.com/seaweedfs/seaweedfs/blob/master/docker/README.md).

## Configuration

See [api.env.example](../config/api.env.example). `DATABASE_URL`, `DATABASE_CA_FILE`, `OPENBAO_ADDR`, `OPENBAO_TOKEN_FILE`, the pinned signing key name/version, `OPENBAO_TENANT_KEYS_JSON`, OIDC settings, and `LICENSE_ISSUER` are mandatory. Each tenant key ring names an active Transit key for new packages and an explicit allowlist for older keys. Remove an old key only after its packages are retired or rewrapped.

Set `PACKAGE_BUCKET` and `OBJECT_STORE_ENDPOINT` together to enable `/v1/assets`. The endpoint must be an HTTPS origin. Supply `OBJECT_STORE_ACCESS_KEY_FILE` and `OBJECT_STORE_SECRET_KEY_FILE` through mounted secrets. `OBJECT_STORE_REGION` defaults to `us-east-1` for S3 request signing; it does not imply AWS hosting. If bucket and endpoint are absent, `/v1/assets` returns 404. `LISTEN_HOST` defaults to loopback and should be changed to `0.0.0.0` only inside a protected container network.

```sh
npm ci
npm run typecheck
node --experimental-strip-types packages/api/src/main.ts
```

The Dockerfile uses pinned Node 26 and UID 1000. The current image built and passed runtime/UID smoke checks. A deployed cluster, TLS endpoints, scoped secrets, alerting, restore, load, and failover testing are still outstanding.

## Outbox worker

Run a separate replica of the API image with command `node --experimental-strip-types packages/api/src/outbox-worker.ts`. Set `DATABASE_URL` and `DATABASE_CA_FILE` as for the API, plus `OUTBOX_TENANT_IDS` (a comma-separated list of tenant UUIDs), `WEBHOOK_ENDPOINT` (an HTTPS destination owned by the platform), and `WEBHOOK_SECRET_FILE` (a mounted file containing a base64url-encoded key of at least 32 random bytes). Give the worker a distinct non-owner PostgreSQL role with only the table privileges it needs. The recipient must verify the `X-DRM-Signature` HMAC-SHA256 over `<X-DRM-Timestamp>.<raw request body>`, reject stale timestamps, and deduplicate by `Idempotency-Key` for at least the maximum retry horizon. The worker does not follow redirects.

Events are leased for 60 seconds and retried with capped exponential delay. After eight failed attempts, they are marked dead-lettered and remain in PostgreSQL. Alert on `outbox.batch.deadLettered > 0` and on persistent `outbox.error`; investigate the destination and explicitly requeue a repaired event using `requeueDeadLetterOutboxEvent` with a tenant-scoped operator session. This is at-least-once delivery: a successful HTTP response followed by an acknowledgment failure can result in another delivery. The configured tenant list must be updated when tenants are added. The worker also deletes expired rate windows and one-time challenges after a 24-hour safety delay in bounded hourly batches. It does not delete audit events or licenses.

## Local interoperability evidence

The optional tests in `packages/openbao/test/live.test.ts`, `packages/aws-s3/test/live.test.ts`, and `packages/postgres/test/selfhosted-stack.test.ts` exercised OpenBao 2.7.0 dev mode, SeaweedFS 4.47 mini mode, and a disposable PostgreSQL database. The full path published an encrypted package, persisted policy and package metadata, issued a device-bound signed license, fetched ciphertext, and opened its authorized chunk. The tests require `BAO_TEST=1`, `S3_TEST=1`, `SELFHOST_TEST=1`, and `PG_TEST=1` with disposable endpoints and credentials.

## Operations still required

Migration orchestration, PostgreSQL and OpenBao backup/restore, SeaweedFS replication, audit retention, key rotation and revocation runbooks, dashboards, alerts, deployment rollbacks, and incident drills are outstanding. The outbox worker now has a signed HTTPS delivery path, but no production destination or deployed worker has been verified. Liveness/readiness checks cover process and database only.

# Docker standalone evaluation deployment

The [release gate](release-status.md) is **FAIL**. This deployment runs the implemented secure-viewer slice without third-party accounts. It uses only the formally supported Node 24 and PostgreSQL 18 runtime images. It is a single-host evaluation topology with a loopback-only HTTP API.

## Start

Prerequisites: Docker Compose, Node 24.21.0, and OpenSSL. The Node and OpenSSL commands below generate local configuration; the runtime services run in Docker. Keep `.secrets/standalone` private and back it up securely.

```sh
mkdir -p .secrets/standalone
node --experimental-strip-types scripts/bootstrap-docker-database.ts .secrets/standalone/database
node --experimental-strip-types scripts/bootstrap-local-keys.ts .secrets/standalone/keys
docker compose -f compose.standalone.yaml up --build -d
docker compose -f compose.standalone.yaml ps
```

The PostgreSQL container enables TLS with a generated server certificate for `postgres` and SCRAM host authentication. The migration container applies checksummed migrations and provisions separate, non-owner API and worker logins. The API uses PostgreSQL for encrypted package bytes, file-backed Ed25519 license signing, tenant-derived AES-256-GCM content-key wrapping, and a local Ed25519 access-token verifier. The signing private key and wrapping key are mounted into the API. The local access-token signing key is mounted only into the optional operator container. Rotate, back up, and restrict these files as production secrets; loss of the wrapping key makes old packages unreadable. No automatic key rotation or multi-version local key ring exists yet.

The first operator tenant and active subject can be created with:

```sh
docker compose -f compose.standalone.yaml run --rm operator node --experimental-strip-types scripts/bootstrap-tenant.ts example operator-1
```

Record the returned tenant UUID. The operator can issue a five-minute access token for that subject with:

```sh
docker compose -f compose.standalone.yaml run --rm operator node --experimental-strip-types scripts/issue-local-token.ts /run/secrets/auth-signing drm-local drm-api TENANT_UUID operator-1 'drm:license drm:publish drm:admin'
```

Run the authenticated publish/idempotency/catalog smoke test with an existing tenant UUID and subject:

```sh
node --experimental-strip-types scripts/smoke-standalone.ts TENANT_UUID operator-1
```

New operator tenants receive explicit admin/creator/customer roles. Existing tenants need `scripts/bootstrap-admin-role.ts` before using administration. The [administration API](commerce.md) provisions subjects and free/organization/trial grants; the API still requires device enrollment and an entitlement to issue a license. The token command is an administrative test path, not customer registration or MFA. Do not expose port 8080 beyond loopback. A public deployment needs TLS termination and a complete identity and account recovery design. Do not place the operator container or its private key on the public network.

Do not regenerate `.secrets/standalone` while its PostgreSQL volume contains data. Keep the database passwords, signing key, wrapping key, and CA trust material together in the backup/recovery plan.

## Service configuration

[`compose.standalone.yaml`](../compose.standalone.yaml) pins the Node and PostgreSQL image versions, uses a private Docker network, a persistent database volume, Docker secrets, a one-shot migration job, readiness checks, and restart policies. The app image runs as UID 1000. The PostgreSQL entrypoint copies its secret key into a PostgreSQL-owned, mode-0600 file before enabling TLS. The generated CA certificate expires in one year; renew it and coordinate server/client trust before expiry. Database and key material need off-host encrypted backups and restore exercises.

`PACKAGE_STORE=postgres` avoids an S3 service. Optional S3, OpenBao, and remote OIDC modes remain in [`api.env.example`](../config/api.env.example) for existing integrations, but their community deployments have not been established as compliant with the formal-LTS requirement. The outbox worker requires an actual HTTPS recipient and is not started in this Compose file. Payment processing requires a Stripe account and is disabled by default; the [commerce guide](commerce.md) documents activation and remaining billing gates. Enable the optional `backup` profile to schedule encrypted Docker backups; see [backup and recovery](backup-recovery.md).

## Local checks and evidence

`LOCAL_NO_DOCKER=1 npm run test:integration` runs the disposable PostgreSQL/HTTP gate and a snapshot/restore drill when the Docker daemon is unavailable. `npm run drill:postgres` can run against separate source and recovery databases; see the script's required `DR_*` environment variables. Its report compares backup bytes, SHA-256, row counts, and table digests, but it does not measure complete RPO/RTO or restore application signing/wrapping keys.

`npm run load:test -- <URL> <seconds> <concurrency>` checks bounded readiness or catalog GET traffic. `LOAD_RPS`, `LOAD_MAX_P95_MS`, `LOAD_MAX_ERROR_RATE`, and `LOAD_REPORT_FILE` control the run. A release load campaign must also cover publish, license issuance, package retrieval, outbox delivery, and node/database loss on a multi-host deployment.

The previous OpenBao and SeaweedFS disposable provider tests remain available through `BAO_TEST=1`, `S3_TEST=1`, and `SELFHOST_TEST=1` with explicit local endpoints. They validate adapters only and do not qualify the standalone Compose or production providers.

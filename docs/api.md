# Rights API contract

This API exposes device enrollment, secure-viewer issuance, bounded encrypted asset publishing, basic owner/library listing, and licensed ciphertext retrieval. It does not provide identity enrollment, searchable catalog metadata, commerce, plaintext downloads, or media DRM acquisition. Do not expose it until those flows and the release gates are complete.

## Authentication

Every `/v1` request requires exactly one `Authorization: Bearer <JWT>` header. The standalone local verifier accepts an EdDSA token signed by its mounted Ed25519 public key; the optional OIDC verifier accepts RS256 or ES256 tokens from a configured HTTPS JWKS. Both require matching issuer and audience, `exp`, `iat`, `sub`, a UUID `tenant_id`, and the route's required scope: `drm:license` for device/license routes and `drm:publish` for asset publishing. Access tokens older than 15 minutes fail. The API looks up an active user by `(tenant_id, sub)` in PostgreSQL. Request bodies cannot select the tenant or user. The local signing key must be controlled by the operator; an external identity provider must issue `tenant_id` only after enforcing membership in that tenant. The local token command is not a customer login service. [jose verification options](https://github.com/panva/jose/blob/main/docs/jwt/verify/interfaces/JWTVerifyOptions.md), [remote JWKS behavior](https://github.com/panva/jose/blob/main/docs/jwks/remote/functions/createRemoteJWKSet.md).

## Routes

`GET /health/live` reports process liveness. `GET /health/ready` checks database reachability; it does not certify OpenBao or object-store availability.

`POST /v1/device-enrollment-challenges` takes `{ "publicKeyPem": "<Ed25519 SPKI PEM>", "deviceClass": "desktop" }` and returns a random challenge valid for two minutes. It binds the challenge to the authenticated user, canonical public-key fingerprint, and device class. `POST /v1/devices` takes the same two fields plus `{ "proof": { "challenge": "...", "signature": "<base64url Ed25519 signature>" } }`. The signature covers the UTF-8 challenge bytes. Successful enrollment returns a UUID and `trust: "software"`; this endpoint cannot assign hardware trust. A user may have at most ten active devices. `DELETE /v1/devices/<UUID>` revokes an owned device, releases its seats, and marks its stored licenses revoked. Already offline signed licenses can remain usable until expiry because no protected client checks online revocation yet.

`POST /v1/device-challenges` takes `application/json`:

```json
{"deviceId":"00000000-0000-4000-8000-000000000001"}
```

It returns HTTP 201 with `{ "challenge": "...", "expiresInSeconds": 120 }`. The challenge is random, stored only as a hash, tied to the registered device and active user, and consumed once. At most three live challenges per device are allowed. The caller signs the UTF-8 challenge bytes with the device's registered Ed25519 private key.

`POST /v1/licenses` takes:

```json
{
  "entitlementId":"00000000-0000-4000-8000-000000000002",
  "deviceId":"00000000-0000-4000-8000-000000000001",
  "renditionId":"00000000-0000-4000-8000-000000000003",
  "action":"read",
  "proof":{"challenge":"base64url-random-challenge","signature":"base64url-Ed25519-signature"},
  "requestedSeconds":300
}
```

It returns HTTP 201 with `{ "license": <signed license> }`. The service reloads the entitlement, device, policy, rendition key, and seat count from PostgreSQL, then signs the bounded license through the configured local Ed25519 key or optional OpenBao Transit key. The request body cannot supply policy facts or duty fulfillment. Only compatible `secureViewer` policies are currently issuable.

`POST /v1/assets` is enabled with `PACKAGE_STORE=postgres` or with configured S3-compatible storage. It requires `drm:publish`, exactly one `Idempotency-Key: <UUID>` header, and takes JSON containing exactly `contentBase64`, `mimeType`, and `policy`. The per-user publish rate limit is charged before the body is read. The decoded asset is limited to 8 MiB. The policy omits server-generated `id`, `version`, `tenantId`, and `assetId`; it must be a compatible online-only `controlled` or `protected` secure-viewer policy with `preventOriginalPossession: true`, at least one supported read/view/play/listen action, and no unimplemented duty or constraint. For example:

```json
{"contentBase64":"JVBERi0xLjQK...","mimeType":"application/pdf","policy":{"profile":"protected","permissions":["read"],"prohibitions":["downloadOriginal"],"duties":[],"constraints":{"onlineOnly":true,"maxDevices":2},"preventOriginalPossession":true}}
```

The response is HTTP 201 with `{ "asset": { "assetId", "policyId", "renditionId", "version": 1, "objectKey", "packageSha256" } }`. The service encrypts content into signed authenticated chunks, writes a tenant-scoped PostgreSQL object or private S3-compatible object with a SHA-256 checksum, then records immutable package metadata, policy, audit, and outbox rows in one database transaction. Before storage, it durably records the operation and encrypted package. Repeating the same key and input returns the same asset; reusing a key with different input returns HTTP 409 `IDEMPOTENCY_CONFLICT`. A lost storage or commit acknowledgement returns HTTP 503 `PUBLISH_UNCERTAIN`; retry with the same key. The service does not delete objects in response to an uncertain transaction. This endpoint does not scan, transcode, watermark, create entitlements, or serve a protected client.

`GET /v1/publication-operations/<idempotencyKey>` requires `drm:publish` and returns `{ "operation": { "status": "pending|committed|abandoned", "asset": <present only when committed> } }`. Only the initiating user can query the operation. Background reconciliation retries pending operations. After 24 hours, an uncommitted operation is irreversibly abandoned and its object is eligible for repeated cleanup; resubmission then requires a new key. Each owner is limited to eight pending operations and 128 MiB of staged ciphertext. These bounds apply to the current small-file publishing path.

`GET /v1/creator/assets` requires `drm:publish` and lists the authenticated creator's published assets. `GET /v1/library` requires `drm:license` and lists only that user's currently active entitlements for published assets with active renditions. Both routes are available with package storage configured and accept `limit=1..100` (default 20) and an optional UUID `cursor` returned as `nextCursor`. Results have an `items` array with `assetId`, `version`, `renditionId`, `mimeType`, and `createdAt`; library items also include `entitlementId` and `validUntil`. Each asset or entitlement returns one representative rendition. Rows are ordered by UUID, so pagination is stable for existing records but is not a historical snapshot while grants or assets change. The routes share the 60-per-minute user rate limit with package retrieval. They expose no object key or content; listing does not issue a license or permit package retrieval.

`GET /v1/assets/<assetId>/renditions/<renditionId>/package` requires `drm:license` and exactly one `X-DRM-License-ID: <UUID>` header. The server checks that the authenticated user, active entitlement, active device, unexpired and unrevoked license, published asset, and active rendition match the requested package. It returns only the encrypted package JSON (`application/vnd.drm.secure-package+json`) after a bounded object read and SHA-256/length check against the catalog. Old licenses without a stored rendition ID must be reissued. The bearer token and license ID authorize ciphertext retrieval; a protected client still has to validate the signed license and manifest and enforce device possession before opening content.

Device/license bodies are limited to 4 KiB; publishing bodies are limited to 11 MiB and decoded content to 8 MiB. Each API process admits at most 16 active requests, including at most two large upload/download transfers. Saturation returns HTTP 503 `CAPACITY_EXCEEDED` with `Retry-After: 1`; capacity remains occupied until both the operation and response finish. Responses use `Cache-Control: no-store`. Errors expose stable codes without tokens or internal details. User limits are 10 device challenge/enrollment requests, 30 issuance requests, 3 publish requests, and 60 encrypted package retrievals per UTC minute, enforced atomically in PostgreSQL across API replicas. Owner-initiated device revocation bypasses this quota so an account can still revoke a compromised device. Additional edge limits for anonymous traffic and IP abuse still need deployment. JWKS timeout/network failure and OpenBao provider failure return HTTP 503 rather than treating a valid user's rights as denied.

## Signature format

License Ed25519 signatures cover SHA-256 of the UTF-8 bytes of `drm-license-v1`, one NUL byte (`0x00`), and `canonicalJson(claims)` concatenated in that order. Package manifests use the analogous `drm-package-manifest-v1` domain. The 32-byte digest is signed as raw bytes by the configured local Ed25519 key or pinned OpenBao Transit key version. Verification requires a trusted public key paired with its key ID; a claim or manifest naming a different key is rejected. Clients must verify the exact canonical format, trusted key ID, device ID, rendition, rights, and time window before any unwrap attempt. No production client implementation exists yet.

The library's `openLicensedChunk` call requires an explicit trusted online/offline state. Offline opens are denied when the license has no `offlineUntil` value or that bound has elapsed. A production client must obtain connectivity and rollback-resistant time from a trustworthy source; this repository has no such client.

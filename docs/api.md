# Rights API contract

This API exposes device enrollment, secure-viewer issuance, and a bounded encrypted asset-publishing path. It does not provide identity enrollment, a complete catalog, commerce, downloads, or media DRM acquisition. Do not expose it until those flows and the release gates are complete.

## Authentication

Every `/v1` request requires exactly one `Authorization: Bearer <JWT>` header. The configured OIDC verifier accepts RS256 or ES256 access tokens with a valid signature from the configured HTTPS JWKS, matching issuer and audience, `exp`, `iat`, `sub`, a UUID `tenant_id`, and the route's required scope: `drm:license` for device/license routes and `drm:publish` for asset publishing. Access tokens older than 15 minutes fail. The API looks up an active user by `(tenant_id, sub)` in PostgreSQL. Request bodies cannot select the tenant or user. The identity provider must issue `tenant_id` only after enforcing membership in that tenant. [jose verification options](https://github.com/panva/jose/blob/main/docs/jwt/verify/interfaces/JWTVerifyOptions.md), [remote JWKS behavior](https://github.com/panva/jose/blob/main/docs/jwks/remote/functions/createRemoteJWKSet.md).

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

It returns HTTP 201 with `{ "license": <signed license> }`. The service reloads the entitlement, device, policy, rendition key, and seat count from PostgreSQL, then signs the bounded license through OpenBao Transit. The request body cannot supply policy facts or duty fulfillment. Only compatible `secureViewer` policies are currently issuable.

`POST /v1/assets` is enabled only when both `PACKAGE_BUCKET` and `OBJECT_STORE_ENDPOINT` are configured. It requires `drm:publish` and takes JSON containing exactly `contentBase64`, `mimeType`, and `policy`. The decoded asset is limited to 8 MiB. The policy omits server-generated `id`, `version`, `tenantId`, and `assetId`; it must be a compatible online-only `controlled` or `protected` secure-viewer policy with `preventOriginalPossession: true`, at least one supported read/view/play/listen action, and no unimplemented duty or constraint. For example:

```json
{"contentBase64":"JVBERi0xLjQK...","mimeType":"application/pdf","policy":{"profile":"protected","permissions":["read"],"prohibitions":["downloadOriginal"],"duties":[],"constraints":{"onlineOnly":true,"maxDevices":2},"preventOriginalPossession":true}}
```

The response is HTTP 201 with `{ "asset": { "assetId", "policyId", "renditionId", "version": 1, "objectKey", "packageSha256" } }`. The service encrypts content into signed authenticated chunks, writes a private S3-compatible object with a SHA-256 checksum, then records immutable package metadata, policy, audit, and outbox rows in one database transaction. A failed transaction attempts deletion of the object. This endpoint does not scan, transcode, watermark, create entitlements, or serve a protected client.

Device/license bodies are limited to 4 KiB; publishing bodies are limited to 11 MiB and decoded content to 8 MiB. Responses use `Cache-Control: no-store`. Errors expose stable codes without tokens or internal details. User limits are 10 device challenge/enrollment requests, 30 issuance requests, and 3 publish requests per UTC minute, enforced atomically in PostgreSQL across API replicas. Owner-initiated device revocation bypasses this quota so an account can still revoke a compromised device. Additional edge limits for anonymous traffic and IP abuse still need deployment. A JWKS timeout returns HTTP 503 rather than treating a valid user as unauthenticated.

## Signature format

License Ed25519 signatures cover `SHA-256("drm-license-v1\\0" || canonicalJson(claims))`. Package manifests use the analogous `drm-package-manifest-v1` domain. The 32-byte digest is signed as raw bytes by a pinned OpenBao Transit Ed25519 key version. Verification requires a trusted public key paired with its key ID; a claim or manifest naming a different key is rejected. Clients must verify the exact canonical format, trusted key ID, device ID, rendition, rights, and time window before any unwrap attempt. No production client implementation exists yet.

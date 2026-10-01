# One-time commerce and tenant administration

These capabilities use the standalone PostgreSQL service. Without gateway credentials, offers, administration, free grants, and libraries work; paid order creation returns HTTP 503 `PAYMENTS_DISABLED`. The application does not enable simulated payments.

## Offers and purchases

| Route | Scope | Contract |
| --- | --- | --- |
| `POST /v1/offers` | `drm:publish` | UUID `Idempotency-Key`; exactly `assetId`, `assetVersion`, `policyId`, `policyVersion`, `label`, `amountMinor`, `currency`. Only the published asset owner may create an offer. |
| `DELETE /v1/offers/:id` | `drm:publish` | Disable an owned offer; historical terms remain immutable. |
| `GET /v1/offers` | `drm:license` | Active tenant offers and policy previews; bounded UUID pagination. |
| `POST /v1/orders` | `drm:license` | UUID `Idempotency-Key`; exactly `{ "offerId": "UUID" }`. Returns `{ "order", "checkoutUrl" }`. Price, tenant, and buyer come from stored records. |
| `GET /v1/orders/:id` | `drm:license` | Only the recorded buyer can read the order. |
| `POST /v1/orders/:id/reconcile` | `drm:license` | Empty JSON object; retrieve the session or recover an unbound order within its safe retry window. |
| `POST /v1/webhooks/stripe` | Provider signature | Raw JSON and one `Stripe-Signature` header; no bearer token. Maximum 256 KiB. |

Prices use integer Stripe minor units and lowercase currency codes. Configure supported currencies and merchant minimum amounts. Tax, discounts, and adaptive currency pricing are disabled; offers cannot be used where that omits required tax treatment.

The order commits before [Stripe hosted Checkout creation](https://docs.stripe.com/api/checkout/sessions/create). The stable key `drm-checkout-ORDER_UUID`, operator-configured HTTPS return URLs, and server-selected line items bind the payment. Retry with the original UUID; changed terms return 409. Unbound orders older than 23 hours require operator review because [Stripe may prune idempotency keys after 24 hours](https://docs.stripe.com/api/idempotent_requests). Buyers have a quota of 20 recent pending orders.

Return-page navigation cannot grant access. Signed webhooks identify the session; the application [retrieves current provider state](https://docs.stripe.com/api/checkout/sessions/retrieve) and matches tenant, order, mode, session, amount, currency, and PaymentIntent. Only a completed, fully paid session creates a purchase grant, equal debit/credit gross-sale journal, paid-order transition, audit, and outbox event in one transaction. Concurrent/replayed events do not duplicate grants. Suspended buyers or withdrawn assets receive suspended grants. Pending payments grant nothing.

Bound pending sessions are polled in bounded background batches. Retrieval failures and mismatches are delayed five minutes. Polling never creates a payment. An asynchronous failed payment may remain pending until provider expiry or operator resolution. Refund, dispute, subscription, fee, invoice, payout, royalty, and tax state machines remain incomplete; the sale journal is not a complete settlement system.

## Stripe activation

Provision an account, private API/webhook key files, trusted return pages, and a public HTTPS endpoint. Set `DRM_STRIPE_SECRET_KEY_FILE`, `DRM_STRIPE_WEBHOOK_SECRET_FILE`, `DRM_CHECKOUT_SUCCESS_URL`, and `DRM_CHECKOUT_CANCEL_URL`, then apply:

```sh
docker compose -f compose.standalone.yaml -f compose.stripe.yaml up --build -d
```

Register `/v1/webhooks/stripe` for `checkout.session.completed`, `checkout.session.async_payment_succeeded`, `checkout.session.async_payment_failed`, and `checkout.session.expired`. Key and event modes must match. Sandbox/live reconciliation and provider qualification require actual credentials. This overlay supplies configuration; public TLS and HA remain deployment requirements. Stripe requires a payment-network account and transaction fees.

## Tenant administration

An admin needs both the verified `drm:admin` scope and an active tenant `admin` role in PostgreSQL. New operator bootstraps receive admin, creator, and customer roles. Existing active operators require this privileged, audited bootstrap:

```sh
docker compose -f compose.standalone.yaml run --rm operator node --experimental-strip-types scripts/bootstrap-admin-role.ts TENANT_UUID SUBJECT
```

| Route | Body / behavior |
| --- | --- |
| `POST /v1/admin/users` | UUID `Idempotency-Key`; `{ "subject": "subject", "roles": ["customer"] }`. Customer/creator roles only; HTTP cannot grant admin. Returns `userId`. |
| `POST /v1/admin/users/:id/status` | `{ "status": "active|suspended|revoked" }`. Revocation is permanent; the last active admin is protected. |
| `POST /v1/admin/entitlements` | UUID `Idempotency-Key`; exactly `userId`, `assetId`, `assetVersion`, `policyId`, `policyVersion`, `source`, `validUntil`. Sources: free, organization, trial. Trials require a future ISO expiry. Returns `entitlementId`. |
| `DELETE /v1/admin/entitlements/:id` | Permanently revoke the grant, stored licenses, and device seats. Safe to repeat. |

Suspension/revocation also revokes stored licenses and releases seats. Offline signed licenses remain bounded by expiry. Mutations append audit/outbox records. Access revocation does not issue refunds. Subject provisioning is an identity binding; customer login, MFA, SSO, SCIM, recovery, and broader RBAC remain incomplete. Creator permissions currently use trusted scopes and ownership checks. Writes share a 10/minute user quota; reads share the catalog quota.

`scripts/smoke-standalone-admin.ts` checks Docker-backed provisioning, idempotent grants, role denial, suspension/reactivation, offers, and disabled payments. `SMOKE_REPORT_FILE` retains a recovery canary in a new private file.

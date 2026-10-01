import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import test from 'node:test';
import { createLicenseApiServer } from '../src/index.ts';

test('commerce HTTP binds buyer identity, rejects client prices, and preserves signed raw webhook bytes', { skip: process.env.API_TEST !== '1' }, async () => {
  const tenantId = randomUUID(), buyerId = randomUUID(), offerId = randomUUID(), orderId = randomUUID(), key = randomUUID();
  const order = { orderId, offerId, amountMinor: 2500, currency: 'usd', status: 'pending' as const, entitlementId: null };
  let created = 0, webhookReceived = false;
  const raw = Buffer.from('{ "fixture": true }\n');
  const never = async (): Promise<never> => { throw new Error('Unexpected route'); };
  const server = createLicenseApiServer({
    auth: { async verify(header) { assert.equal(header, 'Bearer buyer'); return { tenantId, externalSubject: 'buyer' }; } },
    async resolveUser(tenant, subject) { assert.equal(tenant, tenantId); assert.equal(subject, 'buyer'); return buyerId; },
    async consumeRate() {}, issueChallenge: never, issueEnrollmentChallenge: never, registerDevice: never, revokeDevice: never, licenses: { issue: never },
    commerce: {
      createOffer: never, disableOffer: never, listOffers: never,
      async createOrder(tenant, buyer, offer, idempotency) {
        assert.deepEqual([tenant, buyer, offer, idempotency], [tenantId, buyerId, offerId, key]); created++; return order;
      },
      async checkout() { return { order, checkoutUrl: 'https://checkout.stripe.com/c/pay/fixture' }; },
      async order(tenant, buyer, id) { assert.deepEqual([tenant, buyer, id], [tenantId, buyerId, orderId]); return order; },
      reconcileOrder: never,
      async acceptWebhook(bytes, signature) { assert.deepEqual(bytes, raw); assert.equal(signature, 'signed-fixture'); webhookReceived = true; },
    },
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const address = server.address(); assert.ok(address && typeof address !== 'string');
  const url = `http://127.0.0.1:${address.port}`;
  try {
    const headers = { Authorization: 'Bearer buyer', 'Content-Type': 'application/json', 'Idempotency-Key': key };
    assert.equal((await fetch(`${url}/v1/orders`, { method: 'POST', headers, body: JSON.stringify({ offerId, amountMinor: 1 }) })).status, 400);
    assert.equal(created, 0);
    const bought = await fetch(`${url}/v1/orders`, { method: 'POST', headers, body: JSON.stringify({ offerId }) });
    assert.equal(bought.status, 201); assert.equal(created, 1);
    assert.equal((await fetch(`${url}/v1/orders/${orderId}`, { headers: { Authorization: 'Bearer buyer' } })).status, 200);
    const received = await fetch(`${url}/v1/webhooks/stripe`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Stripe-Signature': 'signed-fixture' }, body: raw });
    assert.equal(received.status, 200); assert.equal(webhookReceived, true);
    assert.equal((await fetch(`${url}/v1/webhooks/stripe`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: raw })).status, 400);
  } finally { await new Promise<void>((resolve) => server.close(() => resolve())); }
});

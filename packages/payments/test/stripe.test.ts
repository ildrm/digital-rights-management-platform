import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import Stripe from 'stripe';
import { StripePaymentGateway } from '../src/index.ts';

const order = { orderId: randomUUID(), tenantId: randomUUID(), amountMinor: 2500, currency: 'usd' };
const secretKey = 'sk_test_offline_fixture_only';
const webhookSecret = 'whsec_offline_fixture_only';
const stripe = new Stripe(secretKey);
const intentId = 'pi_offlinefixture12345678';
const intent = {
  id: intentId, object: 'payment_intent', client_secret: `${intentId}_secret_fixture`,
  amount: order.amountMinor, amount_received: order.amountMinor, currency: order.currency,
  status: 'succeeded', livemode: false,
  metadata: { order_id: order.orderId, tenant_id: order.tenantId },
} as unknown as Stripe.PaymentIntent;

test('Stripe adapter uses a stable order idempotency key and validates provider response', async () => {
  const requests: unknown[] = [];
  const client = {
    paymentIntents: {
      async create(parameters: unknown, options: unknown) {
        requests.push({ parameters, options });
        return intent;
      },
      async retrieve(id: string) {
        assert.equal(id, intentId);
        return intent;
      },
    },
    webhooks: stripe.webhooks,
  } as unknown as Stripe;
  const gateway = new StripePaymentGateway(secretKey, webhookSecret, client);
  assert.deepEqual(await gateway.createIntent(order),
    { id: intentId, clientSecret: `${intentId}_secret_fixture`, status: 'succeeded' });
  assert.deepEqual(requests[0], {
    parameters: {
      amount: 2500, currency: 'usd', automatic_payment_methods: { enabled: true },
      metadata: { order_id: order.orderId, tenant_id: order.tenantId },
    },
    options: { idempotencyKey: `drm-order-${order.orderId}` },
  });
  assert.equal((await gateway.retrieveIntent(intentId, order)).id, intentId);
  await assert.rejects(gateway.createIntent({ ...order, amountMinor: 1 }), { code: 'PAYMENT_MISMATCH' });
  await assert.rejects(gateway.createIntent({ ...order, amountMinor: 0 }), { code: 'INVALID_PAYMENT_ORDER' });
});

test('Stripe webhook verifier requires signed raw bytes, freshness, mode, and full payment', () => {
  const gateway = new StripePaymentGateway(secretKey, webhookSecret);
  const now = 1_790_000_000;
  const event = { id: 'evt_offlinefixture123456', object: 'event', created: now,
    livemode: false, type: 'payment_intent.succeeded', data: { object: intent } };
  const body = JSON.stringify(event);
  const header = stripe.webhooks.generateTestHeaderString({ payload: body, secret: webhookSecret, timestamp: now });
  const verified = gateway.verifyWebhook(Buffer.from(body), header, now);
  assert.deepEqual(verified, { eventId: event.id, orderId: order.orderId, tenantId: order.tenantId,
    intentId, type: event.type, amountMinor: 2500, amountReceived: 2500, currency: 'usd', created: now });
  assert.throws(() => gateway.verifyWebhook(Buffer.from(`${body} `), header, now), { code: 'INVALID_PAYMENT_WEBHOOK' });
  assert.throws(() => gateway.verifyWebhook(Buffer.from(body), header, now + 301), { code: 'INVALID_PAYMENT_WEBHOOK' });
  const shortPaid = { ...event, data: { object: { ...intent, amount_received: 2499 } } };
  const shortBody = JSON.stringify(shortPaid);
  const shortHeader = stripe.webhooks.generateTestHeaderString({ payload: shortBody, secret: webhookSecret, timestamp: now });
  assert.throws(() => gateway.verifyWebhook(Buffer.from(shortBody), shortHeader, now), { code: 'INVALID_PAYMENT_WEBHOOK' });
  const live = { ...event, livemode: true };
  const liveBody = JSON.stringify(live);
  const liveHeader = stripe.webhooks.generateTestHeaderString({ payload: liveBody, secret: webhookSecret, timestamp: now });
  assert.throws(() => gateway.verifyWebhook(Buffer.from(liveBody), liveHeader, now), { code: 'INVALID_PAYMENT_WEBHOOK' });
});

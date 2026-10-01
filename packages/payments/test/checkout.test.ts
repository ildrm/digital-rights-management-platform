import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import Stripe from 'stripe';
import { StripeCheckoutGateway } from '../src/index.ts';

const order = { orderId: randomUUID(), tenantId: randomUUID(), amountMinor: 2500, currency: 'usd', label: 'Protected document' };
const sdk = new Stripe('sk_test_offline_fixture_only');
const webhookSecret = 'whsec_offline_fixture_only';
function session(overrides: Record<string, unknown> = {}): Stripe.Checkout.Session {
  return { id: 'cs_test_offlinefixture123456', object: 'checkout.session', mode: 'payment',
    livemode: false, client_reference_id: order.orderId, metadata: { order_id: order.orderId, tenant_id: order.tenantId },
    amount_total: 2500, currency: 'usd', status: 'open', payment_status: 'unpaid', payment_intent: null,
    url: 'https://checkout.stripe.com/c/pay/cs_test_offlinefixture123456', ...overrides } as unknown as Stripe.Checkout.Session;
}
test('Checkout uses immutable order terms and fixed operator return URLs', async () => {
  let returned = session();
  const client = { checkout: { sessions: {
    async create(params: Stripe.Checkout.SessionCreateParams, options: Stripe.RequestOptions) {
      assert.equal(params.mode, 'payment');
      assert.equal(params.line_items?.[0]?.price_data?.unit_amount, order.amountMinor);
      assert.equal(params.line_items?.[0]?.quantity, 1);
      assert.equal(params.payment_intent_data?.metadata?.order_id, order.orderId);
      assert.equal(params.success_url, `https://shop.example/success?order=${order.orderId}`);
      assert.equal(options.idempotencyKey, `drm-checkout-${order.orderId}`);
      return returned;
    },
    async retrieve() { return returned; },
  } }, webhooks: sdk.webhooks } as unknown as Stripe;
  const gateway = new StripeCheckoutGateway('sk_test_offline_fixture_only', webhookSecret,
    'https://shop.example/success', 'https://shop.example/cancel', client);
  assert.equal((await gateway.createCheckout(order)).state, 'pending');
  returned = session({ status: 'complete', payment_status: 'paid', payment_intent: 'pi_offlinefixture123456', url: null });
  assert.equal((await gateway.retrieveCheckout(returned.id)).state, 'paid');
  returned = session({ amount_total: 2499 });
  await assert.rejects(gateway.createCheckout(order), { code: 'PAYMENT_MISMATCH' });
  returned = session({ url: 'https://attacker.example/' });
  await assert.rejects(gateway.retrieveCheckout(returned.id), { code: 'PAYMENT_MISMATCH' });
});

test('Checkout signed events identify a session for authoritative reconciliation', () => {
  const gateway = new StripeCheckoutGateway('sk_test_offline_fixture_only', webhookSecret,
    'https://shop.example/success', 'https://shop.example/cancel');
  const event = { id: 'evt_offlinecheckout123456', livemode: false, type: 'checkout.session.completed', data: { object: session() } };
  const payload = JSON.stringify(event);
  const signature = sdk.webhooks.generateTestHeaderString({ payload, secret: webhookSecret });
  assert.deepEqual(gateway.verifyCheckoutEvent(Buffer.from(payload), signature), {
    eventId: event.id, sessionId: session().id, tenantId: order.tenantId, orderId: order.orderId,
  });
  assert.throws(() => gateway.verifyCheckoutEvent(Buffer.from(`${payload} `), signature), { code: 'INVALID_PAYMENT_WEBHOOK' });
  const stale = sdk.webhooks.generateTestHeaderString({ payload, secret: webhookSecret, timestamp: Math.floor(Date.now() / 1000) - 301 });
  assert.throws(() => gateway.verifyCheckoutEvent(Buffer.from(payload), stale), { code: 'INVALID_PAYMENT_WEBHOOK' });
});

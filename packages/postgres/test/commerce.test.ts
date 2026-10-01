import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import test from 'node:test';
import pg from 'pg';
import type { SecurePackage } from '@drm/core';
import type { CheckoutEvent, CheckoutGateway, CheckoutOrder, CheckoutSession } from '@drm/payments';
import { PostgresAssetPublisher, PostgresCatalog, PostgresCommerceService, withTenantTransaction } from '../src/index.ts';

test('commerce settles paid orders once, grants only the recorded buyer, and rejects mismatched provider terms', { skip: process.env.PG_TEST !== '1' }, async () => {
  const database = process.env.PG_TEST_DATABASE;
  assert.match(database ?? '', /^drm_test_[a-z0-9_]+$/);
  const options = { host: process.env.PG_TEST_HOST ?? '/private/tmp', port: Number(process.env.PG_TEST_PORT ?? '55432'), database, max: 6 };
  const pool = new pg.Pool({ ...options, user: process.env.PG_TEST_USER ?? 'drm_app_test' });
  const runtime = new pg.Pool({ ...options, user: process.env.PG_RUNTIME_TEST_USER ?? process.env.PG_TEST_USER ?? 'drm_app_test' });
  const tenantId = randomUUID(), creatorId = randomUUID(), buyerId = randomUUID();
  const key = generateKeyPairSync('ed25519');
  const objects = new Map<string, Buffer>();
  const publisher = new PostgresAssetPublisher(runtime, {
    async put(objectKey: string, value: SecurePackage) {
      if (objects.has(objectKey)) throw new Error('Already stored');
      const bytes = Buffer.from(JSON.stringify(value)); objects.set(objectKey, bytes);
      return { bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') };
    }, async get(objectKey: string) { return objects.get(objectKey)!; }, async delete(objectKey: string) { objects.delete(objectKey); },
  }, {
    async wrap() { return { provider: 'test', keyVersion: '1', keyReference: 'test-wrap', ciphertext: 'wrapped' }; },
    async unwrap() { throw new Error('Unexpected unwrap'); },
  }, { keyId: 'test-signing', async signEd25519(message) { return sign(null, message, key.privateKey); } });
  const sessions = new Map<string, CheckoutSession>();
  let creationCalls = 0, loseAcknowledgement = false;
  const gateway: CheckoutGateway = {
    provider: 'stripe',
    async createCheckout(order: CheckoutOrder) {
      creationCalls++;
      let session = sessions.get(order.orderId);
      if (!session) {
        session = { ...order, sessionId: `cs_test_${randomUUID().replaceAll('-', '')}`, state: 'pending', paymentIntentId: null,
          checkoutUrl: 'https://checkout.stripe.com/c/pay/fixture' };
        sessions.set(order.orderId, session);
      }
      if (loseAcknowledgement) throw new Error('Provider acknowledgement lost');
      return { ...session };
    },
    async retrieveCheckout(sessionId: string) {
      const found = [...sessions.values()].find((value) => value.sessionId === sessionId);
      assert.ok(found); return { ...found };
    },
    verifyCheckoutEvent(rawBody: Buffer) { return JSON.parse(rawBody.toString()) as CheckoutEvent; },
  };
  const service = new PostgresCommerceService(runtime, gateway);
  const webhook = (orderId: string, eventId = `evt_${randomUUID().replaceAll('-', '')}`) => Buffer.from(JSON.stringify({
    eventId, orderId, tenantId, sessionId: sessions.get(orderId)!.sessionId,
  }));
  try {
    await withTenantTransaction(pool, tenantId, async (client) => {
      await client.query('INSERT INTO drm.tenants(id,slug) VALUES ($1,$2)', [tenantId, `commerce-${tenantId}`]);
      for (const userId of [creatorId, buyerId]) await client.query("INSERT INTO drm.users(tenant_id,id,external_subject,status) VALUES ($1,$2,$3,'active')", [tenantId, userId, userId]);
    });
    const asset = await publisher.publish({ tenantId, ownerUserId: creatorId, idempotencyKey: randomUUID(),
      content: Buffer.from('commerce test protected content'), mimeType: 'text/plain',
      policy: { profile: 'protected', permissions: ['read'], prohibitions: ['downloadOriginal'], duties: [],
        constraints: { onlineOnly: true, maxDevices: 2 }, preventOriginalPossession: true } });
    const offerInput = { tenantId, creatorUserId: creatorId, idempotencyKey: randomUUID(), assetId: asset.assetId, assetVersion: 1,
      policyId: asset.policyId, policyVersion: 1, label: 'Protected document', amountMinor: 2500, currency: 'usd' };
    const offer = await service.createOffer(offerInput);
    assert.deepEqual(await service.createOffer(offerInput), offer);
    await assert.rejects(service.createOffer({ ...offerInput, amountMinor: 1 }), { code: 'IDEMPOTENCY_CONFLICT' });
    await assert.rejects(service.createOffer({ ...offerInput, creatorUserId: buyerId, idempotencyKey: randomUUID() }), { code: 'ACCESS_DENIED' });
    assert.equal((await service.listOffers(tenantId)).items.length, 1);
    assert.equal((await service.listOffers(randomUUID())).items.length, 0);
    const orderKey = randomUUID();
    const [order, sameOrder] = await Promise.all([
      service.createOrder(tenantId, buyerId, offer.offerId, orderKey), service.createOrder(tenantId, buyerId, offer.offerId, orderKey),
    ]);
    assert.deepEqual(order, sameOrder);
    assert.equal(order.status, 'pending');
    const checkout = await service.checkout(tenantId, buyerId, order.orderId);
    assert.ok(checkout.checkoutUrl);
    await service.checkout(tenantId, buyerId, order.orderId);
    assert.equal(creationCalls, 1);
    const pendingEvent = webhook(order.orderId);
    await service.acceptWebhook(pendingEvent, 'fixture');
    assert.equal((await service.order(tenantId, buyerId, order.orderId)).entitlementId, null);
    assert.equal((await new PostgresCatalog(runtime).library(tenantId, buyerId)).items.length, 0);
    const session = sessions.get(order.orderId)!;
    sessions.set(order.orderId, { ...session, state: 'paid', paymentIntentId: `pi_${randomUUID().replaceAll('-', '')}`, amountMinor: 2499, checkoutUrl: null });
    await assert.rejects(service.acceptWebhook(webhook(order.orderId), 'fixture'), { code: 'PAYMENT_MISMATCH' });
    sessions.set(order.orderId, { ...sessions.get(order.orderId)!, amountMinor: 2500 });
    const paidEvent = webhook(order.orderId);
    await Promise.all([service.acceptWebhook(paidEvent, 'fixture'), service.acceptWebhook(paidEvent, 'fixture')]);
    await service.acceptWebhook(webhook(order.orderId), 'fixture');
    const paid = await service.order(tenantId, buyerId, order.orderId);
    assert.equal(paid.status, 'paid'); assert.ok(paid.entitlementId);
    assert.equal((await new PostgresCatalog(runtime).library(tenantId, buyerId)).items.length, 1);
    await assert.rejects(service.order(tenantId, creatorId, order.orderId), { code: 'ORDER_NOT_FOUND' });
    await assert.rejects(service.order(randomUUID(), buyerId, order.orderId), { code: 'ORDER_NOT_FOUND' });
    const counts = await withTenantTransaction(pool, tenantId, async (client) => {
      const entitlements = await client.query('SELECT id FROM drm.entitlements WHERE tenant_id = $1 AND subject_user_id = $2', [tenantId, buyerId]);
      const journal = await client.query('SELECT amount_minor,currency FROM drm.commerce_journal WHERE tenant_id = $1 AND order_id = $2', [tenantId, order.orderId]);
      return { entitlements: entitlements.rowCount, journal: journal.rows };
    });
    assert.equal(counts.entitlements, 1);
    assert.deepEqual(counts.journal, [{ amount_minor: 2500, currency: 'usd' }]);
    await assert.rejects(withTenantTransaction(pool, tenantId, (client) => client.query(
      'UPDATE drm.purchase_orders SET amount_minor = 1 WHERE tenant_id = $1 AND id = $2', [tenantId, order.orderId])), /immutable order binding/);
    await assert.rejects(withTenantTransaction(pool, tenantId, (client) => client.query(
      'DELETE FROM drm.commerce_journal WHERE tenant_id = $1', [tenantId])), /immutable record/);

    const uncertain = await service.createOrder(tenantId, buyerId, offer.offerId, randomUUID());
    loseAcknowledgement = true;
    await assert.rejects(service.checkout(tenantId, buyerId, uncertain.orderId), /acknowledgement lost/);
    loseAcknowledgement = false;
    assert.equal((await service.checkout(tenantId, buyerId, uncertain.orderId)).order.orderId, uncertain.orderId);
    const recoverySession = sessions.get(uncertain.orderId)!;
    sessions.set(uncertain.orderId, { ...recoverySession, amountMinor: 1 });
    const makeDue = () => withTenantTransaction(pool, tenantId, (client) => client.query(
      'UPDATE drm.payment_reconciliation SET due_at = clock_timestamp() WHERE tenant_id = $1 AND order_id = $2', [tenantId, uncertain.orderId]));
    await makeDue();
    assert.deepEqual(await service.reconcileTenant(tenantId), { reconciled: 0, failed: 1 });
    const retry = await withTenantTransaction(pool, tenantId, (client) => client.query(
      'SELECT failures, due_at > clock_timestamp() AS delayed FROM drm.payment_reconciliation WHERE tenant_id = $1 AND order_id = $2', [tenantId, uncertain.orderId]));
    assert.deepEqual(retry.rows, [{ failures: 1, delayed: true }]);
    sessions.set(uncertain.orderId, { ...recoverySession, state: 'paid', paymentIntentId: `pi_${randomUUID().replaceAll('-', '')}`, checkoutUrl: null });
    await makeDue();
    const recovered = await Promise.all([service.reconcileTenant(tenantId), service.reconcileTenant(tenantId)]);
    assert.equal(recovered.reduce((sum, result) => sum + result.reconciled, 0), 1);
    assert.equal((await service.order(tenantId, buyerId, uncertain.orderId)).status, 'paid');
    assert.equal((await new PostgresCatalog(runtime).library(tenantId, buyerId)).items.length, 2);
    const staleOrder = randomUUID();
    await withTenantTransaction(pool, tenantId, (client) => client.query(`INSERT INTO drm.purchase_orders
      (tenant_id,id,buyer_user_id,offer_id,idempotency_key,amount_minor,currency,label,created_at)
      VALUES ($1,$2,$3,$4,$5,2500,'usd','Protected document',clock_timestamp() - interval '24 hours')`, [tenantId, staleOrder, buyerId, offer.offerId, randomUUID()]));
    await assert.rejects(service.checkout(tenantId, buyerId, staleOrder), { code: 'PAYMENT_REVIEW_REQUIRED' });
    await service.disableOffer(tenantId, creatorId, offer.offerId);
    await assert.rejects(service.createOrder(tenantId, buyerId, offer.offerId, randomUUID()), { code: 'OFFER_NOT_FOUND' });
    assert.equal((await service.listOffers(tenantId)).items.length, 0);
    await assert.rejects(new PostgresCommerceService(runtime).createOrder(tenantId, buyerId, offer.offerId, randomUUID()), { code: 'PAYMENTS_DISABLED' });
  } finally { await runtime.end(); await pool.end(); }
});

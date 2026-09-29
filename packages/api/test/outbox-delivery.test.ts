import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import test from 'node:test';
import { createSignedWebhookDelivery } from '../src/outbox-delivery.ts';

const event = {
  id: '00000000-0000-4000-8000-000000000001',
  tenantId: '00000000-0000-4000-8000-000000000002',
  eventType: 'license.issued',
  aggregateId: '00000000-0000-4000-8000-000000000003',
  payload: { deviceId: '00000000-0000-4000-8000-000000000004' },
  attempts: 1,
};

test('webhook delivery signs the exact body and requires a successful HTTPS response', async () => {
  const secret = Buffer.alloc(32, 7);
  let requests = 0;
  const request = (async (url: URL | RequestInfo, init?: RequestInit) => {
    requests++;
    assert.equal(String(url), 'https://hooks.example.test/events');
    assert.equal(init?.method, 'POST');
    assert.equal(init?.redirect, 'manual');
    const headers = new Headers(init?.headers);
    const body = String(init?.body);
    assert.equal(headers.get('idempotency-key'), event.id);
    assert.deepEqual(JSON.parse(body), {
      id: event.id, tenantId: event.tenantId, eventType: event.eventType,
      aggregateId: event.aggregateId, payload: event.payload,
    });
    const timestamp = headers.get('x-drm-timestamp');
    assert.ok(timestamp);
    assert.equal(headers.get('x-drm-signature'),
      `sha256=${createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex')}`);
    return new Response(null, { status: requests === 1 ? 204 : 302 });
  }) as typeof fetch;
  const deliver = createSignedWebhookDelivery('https://hooks.example.test/events', secret, request);
  await deliver(event);
  await assert.rejects(() => deliver(event), /rejected/);
  assert.equal(requests, 2);
  assert.throws(() => createSignedWebhookDelivery('http://hooks.example.test/events', secret, request));
  assert.throws(() => createSignedWebhookDelivery('https://hooks.example.test/events', Buffer.alloc(8), request));
});

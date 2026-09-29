import { createHmac } from 'node:crypto';
import type { OutboxEvent } from '@drm/postgres';

export function createSignedWebhookDelivery(
  endpointValue: string, secret: Buffer, request: typeof fetch = fetch,
): (event: OutboxEvent) => Promise<void> {
  const endpoint = new URL(endpointValue);
  if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password || endpoint.search || endpoint.hash ||
      !endpoint.hostname || secret.length < 32) {
    throw new Error('Webhook requires an HTTPS endpoint and a secret of at least 32 bytes');
  }
  return async (event) => {
    const body = JSON.stringify({
      id: event.id, tenantId: event.tenantId, eventType: event.eventType,
      aggregateId: event.aggregateId, payload: event.payload,
    });
    const timestamp = new Date().toISOString();
    const signature = createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');
    const response = await request(endpoint, {
      method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(5000),
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Idempotency-Key': event.id,
        'X-DRM-Timestamp': timestamp,
        'X-DRM-Signature': `sha256=${signature}`,
      },
      body,
    });
    await response.body?.cancel();
    if (response.status < 200 || response.status >= 300) throw new Error('Webhook delivery was rejected');
  };
}

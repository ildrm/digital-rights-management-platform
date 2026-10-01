import Stripe from 'stripe';
import { DomainError } from '@drm/core';
export * from './checkout.ts';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PAYMENT_INTENT = /^pi_[A-Za-z0-9]{8,128}$/;
const EVENT_ID = /^evt_[A-Za-z0-9]{8,128}$/;

export interface PaymentOrder {
  readonly orderId: string;
  readonly tenantId: string;
  readonly amountMinor: number;
  readonly currency: string;
}

export interface PaymentIntentResult {
  readonly id: string;
  readonly clientSecret: string;
  readonly status: string;
}

export interface VerifiedPaymentEvent {
  readonly eventId: string;
  readonly orderId: string;
  readonly tenantId: string;
  readonly intentId: string;
  readonly type: 'payment_intent.succeeded' | 'payment_intent.payment_failed' | 'payment_intent.canceled';
  readonly amountMinor: number;
  readonly amountReceived: number;
  readonly currency: string;
  readonly created: number;
}

function validateOrder(order: PaymentOrder): PaymentOrder {
  if (!order || typeof order !== 'object' || !UUID.test(order.orderId) || !UUID.test(order.tenantId) ||
      !Number.isSafeInteger(order.amountMinor) || order.amountMinor < 1 || order.amountMinor > 99_999_999 ||
      typeof order.currency !== 'string' || !/^[a-z]{3}$/.test(order.currency)) {
    throw new DomainError('INVALID_PAYMENT_ORDER', 'A bounded order amount, currency, tenant and order ID are required');
  }
  return { orderId: order.orderId.toLowerCase(), tenantId: order.tenantId.toLowerCase(),
    amountMinor: order.amountMinor, currency: order.currency };
}

export class StripePaymentGateway {
  private readonly client: Stripe;
  private readonly webhookSecret: string;
  private readonly liveMode: boolean;

  constructor(secretKey: string, webhookSecret: string, client?: Stripe) {
    if (!/^sk_(test|live)_[A-Za-z0-9_]{8,}$/.test(secretKey) ||
        !/^whsec_[A-Za-z0-9_]{8,}$/.test(webhookSecret)) {
      throw new DomainError('INVALID_PAYMENT_CONFIG', 'Stripe secret and webhook signing keys are required');
    }
    this.liveMode = secretKey.startsWith('sk_live_');
    this.webhookSecret = webhookSecret;
    this.client = client ?? new Stripe(secretKey, { maxNetworkRetries: 0, timeout: 10_000 });
  }

  async createIntent(orderValue: PaymentOrder): Promise<PaymentIntentResult> {
    const order = validateOrder(orderValue);
    let intent: Stripe.PaymentIntent;
    try {
      intent = await this.client.paymentIntents.create({
        amount: order.amountMinor, currency: order.currency,
        automatic_payment_methods: { enabled: true },
        metadata: { order_id: order.orderId, tenant_id: order.tenantId },
      }, { idempotencyKey: `drm-order-${order.orderId}` });
    } catch {
      throw new DomainError('PAYMENT_UNAVAILABLE', 'Payment intent creation is unavailable');
    }
    this.matchIntent(intent, order);
    if (!intent.client_secret) throw new DomainError('PAYMENT_UNAVAILABLE', 'Payment intent has no client secret');
    return { id: intent.id, clientSecret: intent.client_secret, status: intent.status };
  }

  async retrieveIntent(intentId: string, orderValue: PaymentOrder): Promise<PaymentIntentResult> {
    const order = validateOrder(orderValue);
    if (!PAYMENT_INTENT.test(intentId)) throw new DomainError('INVALID_PAYMENT_ORDER', 'Payment intent ID is invalid');
    let intent: Stripe.PaymentIntent;
    try { intent = await this.client.paymentIntents.retrieve(intentId); }
    catch { throw new DomainError('PAYMENT_UNAVAILABLE', 'Payment intent retrieval is unavailable'); }
    this.matchIntent(intent, order);
    if (!intent.client_secret) throw new DomainError('PAYMENT_UNAVAILABLE', 'Payment intent has no client secret');
    return { id: intent.id, clientSecret: intent.client_secret, status: intent.status };
  }

  private matchIntent(intent: Stripe.PaymentIntent, order: PaymentOrder): void {
    if (!PAYMENT_INTENT.test(intent.id) || intent.amount !== order.amountMinor ||
        intent.currency !== order.currency || intent.metadata.order_id !== order.orderId ||
        intent.metadata.tenant_id !== order.tenantId || intent.livemode !== this.liveMode) {
      throw new DomainError('PAYMENT_MISMATCH', 'Payment intent does not match the recorded order');
    }
  }

  verifyWebhook(rawBody: Buffer, signature: string, nowSeconds = Math.floor(Date.now() / 1000)): VerifiedPaymentEvent | null {
    if (!Buffer.isBuffer(rawBody) || rawBody.length < 1 || rawBody.length > 256 * 1024 ||
        typeof signature !== 'string' || signature.length < 10 || signature.length > 2048) {
      throw new DomainError('INVALID_PAYMENT_WEBHOOK', 'Invalid webhook body or signature');
    }
    let event: Stripe.Event;
    try {
      event = this.client.webhooks.constructEvent(rawBody, signature, this.webhookSecret, 300,
        undefined, nowSeconds * 1000);
    } catch {
      throw new DomainError('INVALID_PAYMENT_WEBHOOK', 'Webhook signature verification failed');
    }
    if (event.livemode !== this.liveMode || !EVENT_ID.test(event.id) ||
        !Number.isSafeInteger(event.created) || event.created < 1) {
      throw new DomainError('INVALID_PAYMENT_WEBHOOK', 'Webhook mode or event envelope is invalid');
    }
    if (!['payment_intent.succeeded', 'payment_intent.payment_failed', 'payment_intent.canceled'].includes(event.type)) return null;
    const intent = event.data.object as Stripe.PaymentIntent;
    const metadata = intent?.metadata;
    if (!intent || intent.object !== 'payment_intent' || !PAYMENT_INTENT.test(intent.id) ||
        !metadata || !UUID.test(metadata.order_id ?? '') || !UUID.test(metadata.tenant_id ?? '') ||
        !Number.isSafeInteger(intent.amount) || intent.amount < 1 ||
        !Number.isSafeInteger(intent.amount_received) || intent.amount_received < 0 ||
        typeof intent.currency !== 'string' || !/^[a-z]{3}$/.test(intent.currency) ||
        intent.livemode !== this.liveMode ||
        event.type === 'payment_intent.succeeded' && (intent.status !== 'succeeded' || intent.amount_received !== intent.amount)) {
      throw new DomainError('INVALID_PAYMENT_WEBHOOK', 'Webhook payment intent is invalid');
    }
    return { eventId: event.id, orderId: metadata.order_id!.toLowerCase(),
      tenantId: metadata.tenant_id!.toLowerCase(), intentId: intent.id,
      type: event.type as VerifiedPaymentEvent['type'], amountMinor: intent.amount,
      amountReceived: intent.amount_received, currency: intent.currency, created: event.created };
  }
}

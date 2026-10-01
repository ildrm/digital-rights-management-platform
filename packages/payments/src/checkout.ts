import Stripe from 'stripe';
import { DomainError } from '@drm/core';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SESSION = /^cs_(test_|live_)?[A-Za-z0-9]{8,192}$/;
const INTENT = /^pi_[A-Za-z0-9]{8,128}$/;

export interface CheckoutOrder {
  readonly orderId: string;
  readonly tenantId: string;
  readonly amountMinor: number;
  readonly currency: string;
  readonly label: string;
}

export interface CheckoutSession {
  readonly sessionId: string;
  readonly orderId: string;
  readonly tenantId: string;
  readonly amountMinor: number;
  readonly currency: string;
  readonly state: 'pending' | 'paid' | 'expired';
  readonly paymentIntentId: string | null;
  readonly checkoutUrl: string | null;
}

export interface CheckoutEvent {
  readonly eventId: string;
  readonly sessionId: string;
  readonly tenantId: string;
  readonly orderId: string;
}

export interface CheckoutGateway {
  readonly provider: 'stripe';
  createCheckout(order: CheckoutOrder): Promise<CheckoutSession>;
  retrieveCheckout(sessionId: string): Promise<CheckoutSession>;
  verifyCheckoutEvent(rawBody: Buffer, signature: string): CheckoutEvent | null;
}

function trustedReturnUrl(input: string): URL {
  const url = new URL(input);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) {
    throw new DomainError('INVALID_PAYMENT_CONFIG', 'Checkout return URLs must be trusted HTTPS URLs');
  }
  return url;
}

export class StripeCheckoutGateway implements CheckoutGateway {
  readonly provider = 'stripe' as const;
  private readonly client: Stripe;
  private readonly webhookSecret: string;
  private readonly liveMode: boolean;
  private readonly successUrl: URL;
  private readonly cancelUrl: URL;

  constructor(secretKey: string, webhookSecret: string, successUrl: string, cancelUrl: string, client?: Stripe) {
    if (!/^sk_(test|live)_[A-Za-z0-9_]{8,}$/.test(secretKey) || !/^whsec_[A-Za-z0-9_]{8,}$/.test(webhookSecret)) {
      throw new DomainError('INVALID_PAYMENT_CONFIG', 'Stripe secret and webhook signing keys are required');
    }
    this.liveMode = secretKey.startsWith('sk_live_');
    this.webhookSecret = webhookSecret;
    this.successUrl = trustedReturnUrl(successUrl);
    this.cancelUrl = trustedReturnUrl(cancelUrl);
    this.client = client ?? new Stripe(secretKey, { maxNetworkRetries: 0, timeout: 10_000 });
  }

  async createCheckout(order: CheckoutOrder): Promise<CheckoutSession> {
    if (!UUID.test(order.orderId) || !UUID.test(order.tenantId) || !Number.isSafeInteger(order.amountMinor) ||
        order.amountMinor < 1 || order.amountMinor > 99_999_999 || !/^[a-z]{3}$/.test(order.currency) ||
        typeof order.label !== 'string' || order.label.trim().length < 1 || order.label.length > 120) {
      throw new DomainError('INVALID_PAYMENT_ORDER', 'Invalid checkout order');
    }
    const metadata = { order_id: order.orderId, tenant_id: order.tenantId };
    const success = new URL(this.successUrl);
    const cancel = new URL(this.cancelUrl);
    success.searchParams.set('order', order.orderId);
    cancel.searchParams.set('order', order.orderId);
    let session: Stripe.Checkout.Session;
    try {
      session = await this.client.checkout.sessions.create({
        mode: 'payment', client_reference_id: order.orderId, metadata,
        payment_intent_data: { metadata },
        success_url: success.toString(), cancel_url: cancel.toString(),
        adaptive_pricing: { enabled: false }, automatic_tax: { enabled: false },
        allow_promotion_codes: false,
        line_items: [{ quantity: 1, price_data: {
          currency: order.currency, unit_amount: order.amountMinor, product_data: { name: order.label },
        } }],
      }, { idempotencyKey: `drm-checkout-${order.orderId}` });
    } catch {
      throw new DomainError('PAYMENT_UNAVAILABLE', 'Checkout creation is unavailable; retry the same order');
    }
    const result = this.normalize(session);
    if (result.orderId !== order.orderId || result.tenantId !== order.tenantId ||
        result.amountMinor !== order.amountMinor || result.currency !== order.currency) {
      throw new DomainError('PAYMENT_MISMATCH', 'Checkout does not match the recorded order');
    }
    return result;
  }

  async retrieveCheckout(sessionId: string): Promise<CheckoutSession> {
    if (!SESSION.test(sessionId)) throw new DomainError('INVALID_PAYMENT_ORDER', 'Invalid Checkout Session ID');
    let session: Stripe.Checkout.Session;
    try { session = await this.client.checkout.sessions.retrieve(sessionId); }
    catch { throw new DomainError('PAYMENT_UNAVAILABLE', 'Checkout reconciliation is unavailable'); }
    const result = this.normalize(session);
    if (result.sessionId !== sessionId) throw new DomainError('PAYMENT_MISMATCH', 'Checkout identity mismatch');
    return result;
  }

  private normalize(session: Stripe.Checkout.Session): CheckoutSession {
    if (!session || typeof session !== 'object') throw new DomainError('PAYMENT_MISMATCH', 'Provider returned no Checkout Session');
    const orderId = session.metadata?.order_id;
    const tenantId = session.metadata?.tenant_id;
    const intentId = typeof session.payment_intent === 'string' ? session.payment_intent : session.payment_intent?.id ?? null;
    if (session.object !== 'checkout.session' || !SESSION.test(session.id) || session.mode !== 'payment' ||
        session.livemode !== this.liveMode || !orderId || !UUID.test(orderId) || !tenantId || !UUID.test(tenantId) ||
        session.client_reference_id !== orderId || !Number.isSafeInteger(session.amount_total) ||
        session.amount_total === null || session.amount_total < 1 || session.amount_total > 99_999_999 ||
        !session.currency || !/^[a-z]{3}$/.test(session.currency) ||
        !['open', 'complete', 'expired'].includes(session.status ?? '') ||
        !['paid', 'unpaid'].includes(session.payment_status) || intentId !== null && !INTENT.test(intentId) ||
        session.payment_status === 'paid' && (session.status !== 'complete' || intentId === null)) {
      throw new DomainError('PAYMENT_MISMATCH', 'Provider returned an invalid Checkout Session');
    }
    if (session.url !== null && typeof session.url !== 'string') throw new DomainError('PAYMENT_MISMATCH', 'Checkout redirect is invalid');
    if (session.url !== null) {
      let url: URL;
      try { url = new URL(session.url); }
      catch { throw new DomainError('PAYMENT_MISMATCH', 'Checkout redirect is not a valid URL'); }
      if (url.protocol !== 'https:' || url.hostname !== 'checkout.stripe.com' || url.username || url.password) {
        throw new DomainError('PAYMENT_MISMATCH', 'Checkout redirect is not a Stripe hosted URL');
      }
    }
    return { sessionId: session.id, orderId: orderId.toLowerCase(), tenantId: tenantId.toLowerCase(),
      amountMinor: session.amount_total, currency: session.currency, paymentIntentId: intentId,
      state: session.payment_status === 'paid' ? 'paid' : session.status === 'expired' ? 'expired' : 'pending',
      checkoutUrl: session.url };
  }

  verifyCheckoutEvent(rawBody: Buffer, signature: string): CheckoutEvent | null {
    if (!Buffer.isBuffer(rawBody) || rawBody.length < 1 || rawBody.length > 256 * 1024 ||
        typeof signature !== 'string' || signature.length > 2048) {
      throw new DomainError('INVALID_PAYMENT_WEBHOOK', 'Invalid webhook body or signature');
    }
    let event: Stripe.Event;
    try { event = this.client.webhooks.constructEvent(rawBody, signature, this.webhookSecret, 300); }
    catch { throw new DomainError('INVALID_PAYMENT_WEBHOOK', 'Webhook signature verification failed'); }
    if (event.livemode !== this.liveMode || !/^evt_[A-Za-z0-9]{8,128}$/.test(event.id)) {
      throw new DomainError('INVALID_PAYMENT_WEBHOOK', 'Webhook mode or event ID is invalid');
    }
    if (!['checkout.session.completed', 'checkout.session.async_payment_succeeded',
      'checkout.session.async_payment_failed', 'checkout.session.expired'].includes(event.type)) return null;
    const session = event.data?.object as Stripe.Checkout.Session | undefined;
    if (!session || session.object !== 'checkout.session' || !SESSION.test(session.id) ||
        !UUID.test(session.metadata?.tenant_id ?? '') || !UUID.test(session.metadata?.order_id ?? '')) {
      throw new DomainError('INVALID_PAYMENT_WEBHOOK', 'Webhook Checkout Session is invalid');
    }
    return { eventId: event.id, sessionId: session.id,
      tenantId: session.metadata!.tenant_id!.toLowerCase(), orderId: session.metadata!.order_id!.toLowerCase() };
  }
}

import { createHash, randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { DomainError } from '@drm/core';
import type { CheckoutGateway, CheckoutSession } from '@drm/payments';
import { TransactionCommitUnknownError, withTenantTransaction } from './tenant-transaction.ts';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function id(value: string): string {
  if (typeof value !== 'string' || !UUID.test(value)) throw new DomainError('INVALID_REQUEST', 'UUID required');
  return value.toLowerCase();
}

export interface CreateOfferInput {
  readonly tenantId: string;
  readonly creatorUserId: string;
  readonly idempotencyKey: string;
  readonly assetId: string;
  readonly assetVersion: number;
  readonly policyId: string;
  readonly policyVersion: number;
  readonly label: string;
  readonly amountMinor: number;
  readonly currency: string;
}

interface OfferRow {
  id: string; creator_user_id: string; asset_id: string; asset_version: number; policy_id: string; policy_version: number;
  label: string; amount_minor: number; currency: string; status: 'active' | 'disabled';
}
interface OrderRow {
  id: string; tenant_id: string; buyer_user_id: string; offer_id: string; amount_minor: number; currency: string; label: string;
  status: 'pending' | 'paid' | 'canceled'; checkout_session_id: string | null; payment_intent_id: string | null;
  entitlement_id: string | null; created_at: Date;
}
export interface PurchaseOrder {
  readonly orderId: string;
  readonly offerId: string;
  readonly amountMinor: number;
  readonly currency: string;
  readonly status: OrderRow['status'];
  readonly entitlementId: string | null;
}
function view(row: OrderRow): PurchaseOrder {
  return { orderId: row.id, offerId: row.offer_id, amountMinor: row.amount_minor, currency: row.currency,
    status: row.status, entitlementId: row.entitlement_id };
}

async function activeUser(client: PoolClient, tenantId: string, userId: string, exclusive = false): Promise<void> {
  const result = await client.query(`SELECT id FROM drm.users WHERE tenant_id = $1 AND id = $2 AND status = 'active' ${exclusive ? 'FOR UPDATE' : 'FOR SHARE'}`, [tenantId, userId]);
  if (!result.rowCount) throw new DomainError('ACCESS_DENIED', 'Active account required');
}

export class PostgresCommerceService {
  private readonly pool: Pool;
  private readonly gateway: CheckoutGateway | undefined;
  constructor(pool: Pool, gateway?: CheckoutGateway) { this.pool = pool; this.gateway = gateway; }

  private transaction<T>(tenantId: string, action: (client: PoolClient) => Promise<T>): Promise<T> {
    return withTenantTransaction(this.pool, tenantId, action).catch((error: unknown) => {
      if (error instanceof TransactionCommitUnknownError) throw new DomainError('PAYMENT_UNCERTAIN', 'Order commit outcome is unknown; retry with the same idempotency key');
      throw error;
    });
  }

  async createOffer(input: CreateOfferInput): Promise<{ offerId: string }> {
    const tenantId = id(input.tenantId), creatorId = id(input.creatorUserId), offerId = id(input.idempotencyKey);
    const assetId = id(input.assetId), policyId = id(input.policyId);
    if (!Number.isSafeInteger(input.assetVersion) || input.assetVersion < 1 ||
        !Number.isSafeInteger(input.policyVersion) || input.policyVersion < 1 ||
        !Number.isSafeInteger(input.amountMinor) || input.amountMinor < 1 || input.amountMinor > 99_999_999 ||
        typeof input.currency !== 'string' || !/^[a-z]{3}$/.test(input.currency) ||
        typeof input.label !== 'string' || input.label.trim().length < 1 || input.label.length > 120) {
      throw new DomainError('INVALID_REQUEST', 'Invalid offer version, price, currency, or label');
    }
    const snapshot = { ...input, label: input.label.trim() };
    return this.transaction(tenantId, async (client) => {
      await activeUser(client, tenantId, creatorId);
      const existing = await client.query<OfferRow>('SELECT * FROM drm.offers WHERE tenant_id = $1 AND id = $2', [tenantId, offerId]);
      const matches = (row: OfferRow) => row.creator_user_id === creatorId && row.asset_id === assetId &&
        row.asset_version === snapshot.assetVersion && row.policy_id === policyId && row.policy_version === snapshot.policyVersion &&
        row.amount_minor === snapshot.amountMinor && row.currency === snapshot.currency && row.label === snapshot.label;
      if (existing.rows[0]) {
        if (!matches(existing.rows[0])) throw new DomainError('IDEMPOTENCY_CONFLICT', 'Offer key has different terms');
        return { offerId };
      }
      const asset = await client.query(`SELECT a.id FROM drm.assets a
        JOIN drm.asset_versions v ON (v.tenant_id, v.asset_id) = (a.tenant_id, a.id)
        JOIN drm.policies p ON (p.tenant_id, p.asset_id) = (a.tenant_id, a.id)
        WHERE a.tenant_id = $1 AND a.id = $2 AND a.owner_user_id = $3 AND a.status = 'published'
          AND v.version = $4 AND p.id = $5 AND p.version = $6
          AND EXISTS (SELECT 1 FROM drm.asset_packages ap WHERE ap.tenant_id = a.tenant_id
            AND ap.asset_id = a.id AND ap.asset_version = v.version)
        FOR SHARE OF a`, [tenantId, assetId, creatorId, snapshot.assetVersion, policyId, snapshot.policyVersion]);
      if (!asset.rowCount) throw new DomainError('ACCESS_DENIED', 'Only an owned published package can be offered');
      const inserted = await client.query<OfferRow>(`INSERT INTO drm.offers
        (tenant_id, id, creator_user_id, asset_id, asset_version, policy_id, policy_version, label, amount_minor, currency)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (tenant_id, id) DO NOTHING RETURNING *`,
      [tenantId, offerId, creatorId, assetId, snapshot.assetVersion, policyId, snapshot.policyVersion, snapshot.label, snapshot.amountMinor, snapshot.currency]);
      if (!inserted.rowCount) {
        const concurrent = await client.query<OfferRow>('SELECT * FROM drm.offers WHERE tenant_id = $1 AND id = $2', [tenantId, offerId]);
        if (!concurrent.rows[0] || !matches(concurrent.rows[0])) throw new DomainError('IDEMPOTENCY_CONFLICT', 'Offer key has different terms');
      } else await client.query(`INSERT INTO drm.audit_events(tenant_id,id,actor_id,event_type,details)
        VALUES ($1,$2,$3,'commerce.offer_created',$4)`, [tenantId, randomUUID(), creatorId, { offerId }]);
      return { offerId };
    });
  }

  async disableOffer(tenant: string, user: string, offer: string): Promise<void> {
    const tenantId = id(tenant), userId = id(user), offerId = id(offer);
    await this.transaction(tenantId, async (client) => {
      await activeUser(client, tenantId, userId);
      const result = await client.query("UPDATE drm.offers SET status = 'disabled' WHERE tenant_id = $1 AND id = $2 AND creator_user_id = $3 RETURNING id", [tenantId, offerId, userId]);
      if (!result.rowCount) throw new DomainError('OFFER_NOT_FOUND', 'Owned offer not found');
    });
  }

  async listOffers(tenant: string, limit = 20, cursor?: string): Promise<{ items: unknown[]; nextCursor?: string }> {
    const tenantId = id(tenant);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw new DomainError('INVALID_REQUEST', 'Offer limit must be 1–100');
    const after = cursor ? id(cursor) : '00000000-0000-0000-0000-000000000000';
    return this.transaction(tenantId, async (client) => {
      const rows = await client.query<OfferRow & { document: unknown }>(`SELECT o.*, p.document FROM drm.offers o
        JOIN drm.assets a ON (a.tenant_id,a.id) = (o.tenant_id,o.asset_id)
        JOIN drm.users u ON (u.tenant_id,u.id) = (o.tenant_id,o.creator_user_id)
        JOIN drm.policies p ON (p.tenant_id,p.id,p.version) = (o.tenant_id,o.policy_id,o.policy_version)
        WHERE o.tenant_id = $1 AND o.id > $2 AND o.status = 'active' AND a.status = 'published' AND u.status = 'active'
        ORDER BY o.id LIMIT $3`, [tenantId, after, limit + 1]);
      const selected = rows.rows.slice(0, limit);
      return { items: selected.map((row) => ({ offerId: row.id, assetId: row.asset_id, assetVersion: row.asset_version,
        label: row.label, amountMinor: row.amount_minor, currency: row.currency, policy: row.document })),
      ...(rows.rows.length > limit ? { nextCursor: selected.at(-1)!.id } : {}) };
    });
  }

  async createOrder(tenant: string, buyer: string, offer: string, key: string): Promise<PurchaseOrder> {
    if (!this.gateway) throw new DomainError('PAYMENTS_DISABLED', 'No payment gateway is configured');
    const tenantId = id(tenant), buyerId = id(buyer), offerId = id(offer), idempotency = id(key);
    return this.transaction(tenantId, async (client) => {
      await activeUser(client, tenantId, buyerId, true);
      const previous = await client.query<OrderRow>('SELECT * FROM drm.purchase_orders WHERE tenant_id = $1 AND buyer_user_id = $2 AND idempotency_key = $3', [tenantId, buyerId, idempotency]);
      if (previous.rows[0]) {
        if (previous.rows[0].offer_id !== offerId) throw new DomainError('IDEMPOTENCY_CONFLICT', 'Order key has a different offer');
        return view(previous.rows[0]);
      }
      const selected = await client.query<OfferRow>(`SELECT o.* FROM drm.offers o
        JOIN drm.assets a ON (a.tenant_id,a.id) = (o.tenant_id,o.asset_id)
        JOIN drm.users u ON (u.tenant_id,u.id) = (o.tenant_id,o.creator_user_id)
        WHERE o.tenant_id = $1 AND o.id = $2 AND o.status = 'active' AND a.status = 'published' AND u.status = 'active'
        FOR SHARE OF o,a,u`, [tenantId, offerId]);
      const terms = selected.rows[0];
      if (!terms) throw new DomainError('OFFER_NOT_FOUND', 'Active offer not found');
      const pending = await client.query<{ count: number }>(`SELECT count(*)::integer AS count FROM drm.purchase_orders
        WHERE tenant_id = $1 AND buyer_user_id = $2 AND status = 'pending' AND created_at > clock_timestamp() - interval '1 day'`, [tenantId, buyerId]);
      if (pending.rows[0]!.count >= 20) throw new DomainError('ORDER_CAPACITY', 'Too many pending orders');
      await client.query(`INSERT INTO drm.purchase_orders(tenant_id,id,buyer_user_id,offer_id,idempotency_key,amount_minor,currency,label)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (tenant_id,buyer_user_id,idempotency_key) DO NOTHING`,
      [tenantId, randomUUID(), buyerId, offerId, idempotency, terms.amount_minor, terms.currency, terms.label]);
      const result = await client.query<OrderRow>('SELECT * FROM drm.purchase_orders WHERE tenant_id = $1 AND buyer_user_id = $2 AND idempotency_key = $3', [tenantId, buyerId, idempotency]);
      if (result.rows[0]!.offer_id !== offerId) throw new DomainError('IDEMPOTENCY_CONFLICT', 'Order key has a different offer');
      return view(result.rows[0]!);
    });
  }

  async order(tenant: string, buyer: string, order: string): Promise<PurchaseOrder> {
    return this.transaction(id(tenant), async (client) => {
      const row = await client.query<OrderRow>('SELECT * FROM drm.purchase_orders WHERE tenant_id = $1 AND id = $2 AND buyer_user_id = $3', [id(tenant), id(order), id(buyer)]);
      if (!row.rows[0]) throw new DomainError('ORDER_NOT_FOUND', 'Owned order not found');
      return view(row.rows[0]);
    });
  }

  async checkout(tenant: string, buyer: string, order: string): Promise<{ order: PurchaseOrder; checkoutUrl: string | null }> {
    const gateway = this.gateway;
    if (!gateway) throw new DomainError('PAYMENTS_DISABLED', 'No payment gateway is configured');
    const tenantId = id(tenant), buyerId = id(buyer), orderId = id(order);
    return this.transaction(tenantId, async (client) => {
      await activeUser(client, tenantId, buyerId);
      const result = await client.query<OrderRow>('SELECT * FROM drm.purchase_orders WHERE tenant_id = $1 AND id = $2 AND buyer_user_id = $3 FOR UPDATE', [tenantId, orderId, buyerId]);
      const row = result.rows[0];
      if (!row) throw new DomainError('ORDER_NOT_FOUND', 'Owned order not found');
      if (row.status === 'paid') return { order: view(row), checkoutUrl: null };
      if (!row.checkout_session_id && (row.status !== 'pending' || Date.now() - row.created_at.getTime() > 23 * 3600_000)) {
        throw new DomainError('PAYMENT_REVIEW_REQUIRED', 'Unbound order is outside the safe provider retry window');
      }
      if (!row.checkout_session_id) {
        const available = await client.query(`SELECT o.id FROM drm.offers o
          JOIN drm.assets a ON (a.tenant_id,a.id) = (o.tenant_id,o.asset_id)
          JOIN drm.users u ON (u.tenant_id,u.id) = (o.tenant_id,o.creator_user_id)
          WHERE o.tenant_id = $1 AND o.id = $2 AND o.status = 'active' AND a.status = 'published' AND u.status = 'active'
          FOR SHARE OF o,a,u`, [tenantId, row.offer_id]);
        if (!available.rowCount) throw new DomainError('OFFER_NOT_FOUND', 'Offer is no longer available for checkout');
      }
      const session = row.checkout_session_id ? await gateway.retrieveCheckout(row.checkout_session_id)
        : await gateway.createCheckout({ orderId, tenantId, amountMinor: row.amount_minor, currency: row.currency, label: row.label });
      const settled = await this.settle(client, row, session);
      return { order: settled, checkoutUrl: settled.status === 'pending' && session.state === 'pending' ? session.checkoutUrl : null };
    });
  }

  async reconcileOrder(tenant: string, buyer: string, order: string): Promise<PurchaseOrder> {
    return (await this.checkout(tenant, buyer, order)).order;
  }

  /** Polls already-bound sessions only. Never creates a payment during background recovery. */
  async reconcileTenant(tenant: string, limit = 2): Promise<{ reconciled: number; failed: number }> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 2) throw new DomainError('INVALID_REQUEST', 'Reconciliation limit must be 1–2');
    const gateway = this.gateway;
    if (!gateway) return { reconciled: 0, failed: 0 };
    return this.transaction(id(tenant), async (client) => {
      const rows = await client.query<OrderRow>(`SELECT o.* FROM drm.payment_reconciliation q
        JOIN drm.purchase_orders o ON (o.tenant_id,o.id) = (q.tenant_id,q.order_id)
        WHERE q.tenant_id = $1 AND q.due_at <= clock_timestamp()
        ORDER BY q.due_at,q.order_id LIMIT $2 FOR UPDATE OF q,o SKIP LOCKED`, [id(tenant), limit]);
      let reconciled = 0, failed = 0;
      for (const row of rows.rows) {
        if (row.status !== 'pending' || !row.checkout_session_id) {
          await client.query('DELETE FROM drm.payment_reconciliation WHERE tenant_id = $1 AND order_id = $2', [row.tenant_id, row.id]);
          continue;
        }
        let session: CheckoutSession;
        try {
          session = await gateway.retrieveCheckout(row.checkout_session_id);
          this.assertSessionMatches(row, session);
        }
        catch {
          await client.query(`UPDATE drm.payment_reconciliation SET due_at = clock_timestamp() + interval '5 minutes',
            failures = LEAST(failures + 1,1000000) WHERE tenant_id = $1 AND order_id = $2`, [row.tenant_id, row.id]);
          failed++; continue;
        }
        await this.settle(client, row, session); reconciled++;
        await client.query(`UPDATE drm.payment_reconciliation SET due_at = clock_timestamp() + interval '5 minutes', failures = 0
          WHERE tenant_id = $1 AND order_id = $2`, [row.tenant_id, row.id]);
      }
      return { reconciled, failed };
    });
  }

  async acceptWebhook(rawBody: Buffer, signature: string): Promise<void> {
    const gateway = this.gateway;
    if (!gateway) throw new DomainError('PAYMENTS_DISABLED', 'No payment gateway is configured');
    const event = gateway.verifyCheckoutEvent(rawBody, signature);
    if (!event) return;
    const duplicate = await this.transaction(event.tenantId, async (client) => {
      const found = await client.query<{ order_id: string; session_id: string }>('SELECT order_id,session_id FROM drm.payment_events WHERE event_id = $1', [event.eventId]);
      if (!found.rows[0]) return false;
      if (found.rows[0].order_id !== event.orderId || found.rows[0].session_id !== event.sessionId) throw new DomainError('PAYMENT_MISMATCH', 'Webhook event binding changed');
      return true;
    });
    if (duplicate) return;
    const session = await gateway.retrieveCheckout(event.sessionId);
    if (session.orderId !== event.orderId || session.tenantId !== event.tenantId) throw new DomainError('PAYMENT_MISMATCH', 'Webhook metadata does not match provider state');
    await this.transaction(event.tenantId, async (client) => {
      const result = await client.query<OrderRow>('SELECT * FROM drm.purchase_orders WHERE tenant_id = $1 AND id = $2 FOR UPDATE', [event.tenantId, event.orderId]);
      if (!result.rows[0]) throw new DomainError('ORDER_NOT_FOUND', 'Webhook order not found');
      await this.settle(client, result.rows[0], session);
      const inserted = await client.query(`INSERT INTO drm.payment_events(event_id,tenant_id,order_id,session_id,payload_sha256)
        VALUES ($1,$2,$3,$4,$5) ON CONFLICT (event_id) DO NOTHING RETURNING event_id`,
      [event.eventId, event.tenantId, event.orderId, event.sessionId, createHash('sha256').update(rawBody).digest()]);
      if (!inserted.rowCount) {
        const bound = await client.query<{ order_id: string; session_id: string }>('SELECT order_id,session_id FROM drm.payment_events WHERE event_id = $1', [event.eventId]);
        if (bound.rows[0]?.order_id !== event.orderId || bound.rows[0].session_id !== event.sessionId) throw new DomainError('PAYMENT_MISMATCH', 'Webhook event binding changed');
      }
    });
  }

  private assertSessionMatches(row: OrderRow, session: CheckoutSession): void {
    if (session.orderId !== row.id || session.tenantId !== row.tenant_id || session.amountMinor !== row.amount_minor ||
        session.currency !== row.currency || row.checkout_session_id !== null && session.sessionId !== row.checkout_session_id ||
        row.payment_intent_id !== null && session.paymentIntentId !== row.payment_intent_id) {
      throw new DomainError('PAYMENT_MISMATCH', 'Provider session does not match the immutable order');
    }
    if (session.state === 'paid' && !session.paymentIntentId) throw new DomainError('PAYMENT_MISMATCH', 'Paid session has no PaymentIntent');
  }

  private async settle(client: PoolClient, row: OrderRow, session: CheckoutSession): Promise<PurchaseOrder> {
    this.assertSessionMatches(row, session);
    if (row.status === 'paid') return view(row);
    if (session.state !== 'paid') {
      const result = await client.query<OrderRow>(`UPDATE drm.purchase_orders SET checkout_session_id = $3,
        status = CASE WHEN $4 = 'expired' THEN 'canceled' ELSE status END
        WHERE tenant_id = $1 AND id = $2 RETURNING *`, [row.tenant_id, row.id, session.sessionId, session.state]);
      if (result.rows[0]!.status === 'pending') {
        await client.query('INSERT INTO drm.payment_reconciliation(tenant_id,order_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [row.tenant_id, row.id]);
      } else await client.query('DELETE FROM drm.payment_reconciliation WHERE tenant_id = $1 AND order_id = $2', [row.tenant_id, row.id]);
      return view(result.rows[0]!);
    }
    if (!session.paymentIntentId) throw new DomainError('PAYMENT_MISMATCH', 'Paid session has no PaymentIntent');
    const terms = await client.query<OfferRow & { user_status: string; asset_status: string }>(`SELECT o.*, u.status AS user_status, a.status AS asset_status
      FROM drm.offers o JOIN drm.users u ON (u.tenant_id,u.id) = (o.tenant_id,$3::uuid)
      JOIN drm.assets a ON (a.tenant_id,a.id) = (o.tenant_id,o.asset_id)
      WHERE o.tenant_id = $1 AND o.id = $2 FOR SHARE OF u,a`, [row.tenant_id, row.offer_id, row.buyer_user_id]);
    const offer = terms.rows[0]!;
    const entitlementId = randomUUID();
    await client.query(`INSERT INTO drm.entitlements
      (tenant_id,id,subject_user_id,asset_id,asset_version,policy_id,policy_version,source,status,valid_from)
      VALUES ($1,$2,$3,$4,$5,$6,$7,'purchase',$8,clock_timestamp())`,
    [row.tenant_id, entitlementId, row.buyer_user_id, offer.asset_id, offer.asset_version, offer.policy_id, offer.policy_version,
      offer.user_status === 'active' && offer.asset_status === 'published' ? 'active' : 'suspended']);
    const paid = await client.query<OrderRow>(`UPDATE drm.purchase_orders SET status = 'paid', checkout_session_id = $3,
      payment_intent_id = $4, entitlement_id = $5, paid_at = clock_timestamp()
      WHERE tenant_id = $1 AND id = $2 RETURNING *`, [row.tenant_id, row.id, session.sessionId, session.paymentIntentId, entitlementId]);
    await client.query(`INSERT INTO drm.commerce_journal(tenant_id,id,order_id,amount_minor,currency,debit_account,credit_account)
      VALUES ($1,$2,$3,$4,$5,'processor_receivable','creator_payable')`, [row.tenant_id, randomUUID(), row.id, row.amount_minor, row.currency]);
    const details = { orderId: row.id, entitlementId, amountMinor: row.amount_minor, currency: row.currency };
    await client.query(`INSERT INTO drm.audit_events(tenant_id,id,actor_id,event_type,details) VALUES ($1,$2,$3,'commerce.order_paid',$4)`, [row.tenant_id, randomUUID(), row.buyer_user_id, details]);
    await client.query(`INSERT INTO drm.outbox_events(tenant_id,id,event_type,aggregate_id,payload) VALUES ($1,$2,'commerce.order_paid',$3,$4)`, [row.tenant_id, randomUUID(), row.id, details]);
    await client.query('DELETE FROM drm.payment_reconciliation WHERE tenant_id = $1 AND order_id = $2', [row.tenant_id, row.id]);
    return view(paid.rows[0]!);
  }
}

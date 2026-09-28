import { DomainError } from './errors.ts';

// Stable JSON for the limited signed schemas in this package. It is not a general JSON-LD canonicalizer.
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new DomainError('INVALID_CANONICAL_VALUE', 'Signed numbers must be safe integers');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => {
      if (record[key] === undefined) throw new DomainError('INVALID_CANONICAL_VALUE', 'Undefined signed field');
      return `${JSON.stringify(key)}:${canonicalJson(record[key])}`;
    }).join(',')}}`;
  }
  throw new DomainError('INVALID_CANONICAL_VALUE', 'Unsupported signed value');
}

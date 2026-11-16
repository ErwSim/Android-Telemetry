// Usage des opérations sensibles (contrat §11.2, `app.ops`, expérimental) : libellés, lecture tolérante de
// `GET /apps/ops`, agrégations. Ces données peuvent être absentes : l'appelant affiche alors un état vide.
import type { AppOpsResponse, AppOpsRow } from '../api/types.ts';
import { isRecord } from './data.ts';

export interface OpInfo {
  op: string;
  label: string;
  /** verbe court pour une phrase : « a envoyé des SMS » */
  group: 'sms' | 'calls' | 'contacts' | 'micro' | 'camera' | 'other';
  /** les cinq usages que le propriétaire veut voir en premier */
  headline: boolean;
}

const OPS: Record<string, Omit<OpInfo, 'op'>> = {
  send_sms: { label: 'Envoi de SMS', group: 'sms', headline: true },
  read_sms: { label: 'Lecture de SMS', group: 'sms', headline: false },
  receive_sms: { label: 'Réception de SMS', group: 'sms', headline: false },
  call_phone: { label: 'Appels passés', group: 'calls', headline: true },
  read_contacts: { label: 'Lecture des contacts', group: 'contacts', headline: true },
  read_call_log: { label: "Lecture du journal d'appels", group: 'calls', headline: false },
  record_audio: { label: 'Micro', group: 'micro', headline: true },
  camera: { label: 'Caméra', group: 'camera', headline: true },
  fine_location: { label: 'Position précise', group: 'other', headline: false },
  get_accounts: { label: 'Lecture des comptes', group: 'other', headline: false },
};

/** Ordre d'affichage : celui du contrat. */
export const OP_CODES: readonly string[] = Object.keys(OPS);

export function opInfo(op: string): OpInfo {
  const e = Object.prototype.hasOwnProperty.call(OPS, op) ? OPS[op] : undefined;
  return e ? { op, ...e } : { op, label: op, group: 'other', headline: false };
}

export const HEADLINE_OPS: readonly string[] = OP_CODES.filter((o) => OPS[o]?.headline);

function nonNeg(v: unknown): number | undefined {
  return typeof v === 'number' && Number.isFinite(v) && v >= 0 ? Math.round(v) : undefined;
}

function row(raw: unknown, pkg?: string, label?: string): AppOpsRow | undefined {
  if (!isRecord(raw)) return undefined;
  const p = typeof raw['package'] === 'string' && raw['package'] !== '' ? raw['package'] : pkg;
  const op = raw['op'];
  if (!p || typeof op !== 'string' || op === '') return undefined;
  const out: AppOpsRow = { package: p, op, count: nonNeg(raw['count']) ?? 0 };
  const l = typeof raw['label'] === 'string' && raw['label'] !== '' ? raw['label'] : label;
  if (l) out.label = l;
  const bg = nonNeg(raw['background_count']);
  if (bg !== undefined) out.background_count = bg;
  const rej = nonNeg(raw['rejected_count']);
  if (rej !== undefined && rej > 0) out.rejected_count = rej;
  if (typeof raw['last_ts'] === 'string') out.last_ts = raw['last_ts'];
  return out;
}

/**
 * Lit la réponse de `GET /apps/ops`. Deux formes sont acceptées : lignes à plat `{package, op, count, …}`
 * (sous `ops`, `rows`, `items` ou `apps`), ou applications portant leurs opérations `{package, ops: [...]}`.
 */
export function parseOpsResponse(raw: unknown): AppOpsResponse {
  const src = Array.isArray(raw) ? raw : isRecord(raw) ? (raw['apps'] ?? raw['ops'] ?? raw['rows'] ?? raw['items'] ?? []) : [];
  const rows: AppOpsRow[] = [];
  for (const it of Array.isArray(src) ? src : []) {
    if (isRecord(it) && Array.isArray(it['ops'])) {
      const pkg = typeof it['package'] === 'string' ? it['package'] : undefined;
      const label = typeof it['label'] === 'string' ? it['label'] : undefined;
      for (const o of it['ops']) {
        const r = row(o, pkg, label);
        if (r) rows.push(r);
      }
    } else {
      const r = row(it);
      if (r) rows.push(r);
    }
  }
  const out: AppOpsResponse = { rows };
  if (isRecord(raw)) {
    if (typeof raw['from'] === 'string') out.from = raw['from'];
    if (typeof raw['to'] === 'string') out.to = raw['to'];
  }
  return out;
}

export interface AppOps {
  package: string;
  label?: string;
  /** par opération, dans l'ordre du contrat */
  ops: { op: string; count: number; background: number; rejected: number; lastTs?: string }[];
  total: number;
  background: number;
  rejected: number;
}

/** Regroupe par application (additionne si une paire application/opération apparaît plusieurs fois). */
export function groupByApp(rows: readonly AppOpsRow[]): AppOps[] {
  const m = new Map<string, AppOps>();
  for (const r of rows) {
    let a = m.get(r.package);
    if (!a) {
      a = { package: r.package, ops: [], total: 0, background: 0, rejected: 0 };
      m.set(r.package, a);
    }
    if (r.label && !a.label) a.label = r.label;
    let o = a.ops.find((x) => x.op === r.op);
    if (!o) {
      o = { op: r.op, count: 0, background: 0, rejected: 0 };
      a.ops.push(o);
    }
    o.count += r.count;
    o.background += Math.min(r.background_count ?? 0, r.count);
    o.rejected += r.rejected_count ?? 0;
    a.rejected += r.rejected_count ?? 0;
    if (r.last_ts && (!o.lastTs || r.last_ts > o.lastTs)) o.lastTs = r.last_ts;
    a.total += r.count;
    a.background += Math.min(r.background_count ?? 0, r.count);
  }
  const idx = (op: string) => {
    const i = OP_CODES.indexOf(op);
    return i < 0 ? OP_CODES.length : i;
  };
  for (const a of m.values()) a.ops.sort((x, y) => idx(x.op) - idx(y.op) || x.op.localeCompare(y.op));
  return [...m.values()].sort((a, b) => b.total - a.total || a.package.localeCompare(b.package));
}

export interface OpTotal {
  op: string;
  count: number;
  background: number;
  apps: { package: string; label?: string; count: number; background: number }[];
}

/** Par opération : total, dont arrière-plan, et applications classées par nombre d'usages. */
export function groupByOp(rows: readonly AppOpsRow[]): OpTotal[] {
  const m = new Map<string, OpTotal>();
  for (const a of groupByApp(rows)) {
    for (const o of a.ops) {
      let t = m.get(o.op);
      if (!t) {
        t = { op: o.op, count: 0, background: 0, apps: [] };
        m.set(o.op, t);
      }
      t.count += o.count;
      t.background += o.background;
      t.apps.push({ package: a.package, ...(a.label ? { label: a.label } : {}), count: o.count, background: o.background });
    }
  }
  const idx = (op: string) => {
    const i = OP_CODES.indexOf(op);
    return i < 0 ? OP_CODES.length : i;
  };
  for (const t of m.values()) t.apps.sort((x, y) => y.count - x.count || x.package.localeCompare(y.package));
  return [...m.values()].sort((a, b) => idx(a.op) - idx(b.op) || a.op.localeCompare(b.op));
}

/** Part des usages faits en arrière-plan, de 0 à 1 (0 si aucun usage). */
export function backgroundShare(count: number, background: number): number {
  return count > 0 ? Math.min(1, background / count) : 0;
}

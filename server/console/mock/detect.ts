// Mock responses of GET /detections, /apps/risk and /apps/ops (contract §11.2 and §11.3), computed from the
// scenario events as the collector would (`detect.*`, `app.risk`, `app.ops` events).
import type { MockEvent } from './gen.ts';

function parseTime(v: string | null, dflt: number): number {
  if (!v) return dflt;
  const t = Date.parse(v);
  return Number.isNaN(t) ? dflt : t;
}

/**
 * `GET /detections?device_id&from&to&type&limit&cursor`: newest first, opaque cursor.
 * The `package` parameter does not exist in the contract: it is deliberately ignored (the console filters client-side).
 */
export function detections(events: MockEvent[], u: URL): { detections: Record<string, unknown>[]; next_cursor?: string } {
  const sp = u.searchParams;
  const from = parseTime(sp.get('from'), 0);
  const to = parseTime(sp.get('to'), Date.now() + 1000);
  const types = (sp.get('type') ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  const limit = Math.min(200, Math.max(1, Number(sp.get('limit') ?? 50) || 50));
  const list = events.filter((e) => e.type.startsWith('detect.') && e.type !== 'detect.muted' && e.type !== 'detect.unmuted');
  let i = list.length - 1;
  const cur = sp.get('cursor');
  if (cur) {
    const n = Number(cur.replace(/^d/, ''));
    if (Number.isInteger(n)) i = Math.min(n - 1, list.length - 1);
  }
  const out: Record<string, unknown>[] = [];
  let next: string | undefined;
  for (; i >= 0; i--) {
    const e = list[i] as MockEvent;
    if (e.t > to) continue;
    if (e.t < from) break;
    if (types.length && !types.includes(e.type)) continue;
    if (out.length >= limit) {
      next = `d${i + 1}`;
      break;
    }
    const d = e.data;
    out.push({
      id: e.id,
      ts: e.ts,
      type: e.type,
      ...(d['package'] !== undefined ? { package: d['package'] } : {}),
      ...(d['label'] !== undefined ? { label: d['label'] } : {}),
      severity: e.sev,
      summary: d['summary'],
      evidence: d['evidence'] ?? {},
      ...(d['window_from'] !== undefined ? { window_from: d['window_from'], window_to: d['window_to'] } : {}),
      ...(d['recurring'] === true ? { recurring: true } : {}),
      ...(d['muted'] === true ? { muted: true } : {}),
    });
  }
  return next ? { detections: out, next_cursor: next } : { detections: out };
}

/** `GET /apps/risk?device_id`: latest `app.risk` per application, decreasing score. */
export function risk(events: MockEvent[]): { ts?: string; apps: Record<string, unknown>[] } {
  const latest = new Map<string, MockEvent>();
  for (const e of events) if (e.type === 'app.risk' && typeof e.data['package'] === 'string') latest.set(e.data['package'], e);
  const apps = [...latest.values()]
    .map((e): Record<string, unknown> => ({ ...e.data, ts: e.ts }))
    .sort((a, b) => Number(b['score'] ?? 0) - Number(a['score'] ?? 0) || String(a['package']).localeCompare(String(b['package'])));
  const last = [...latest.values()].sort((a, b) => b.t - a.t)[0];
  return last ? { ts: last.ts, apps } : { apps };
}

/** `GET /apps/ops?device_id&from&to`: aggregate per application, with the per-operation detail (collector format). */
export function ops(events: MockEvent[], u: URL, labels: Map<string, string>): { apps: Record<string, unknown>[] } {
  const from = parseTime(u.searchParams.get('from'), Date.now() - 7 * 86_400_000);
  const to = parseTime(u.searchParams.get('to'), Date.now());
  type Row = { op: string; count: number; background_count: number; last_ts: string };
  const byApp = new Map<string, Map<string, Row>>();
  for (const e of events) {
    if (e.type !== 'app.ops' || e.t < from || e.t > to || !Array.isArray(e.data['apps'])) continue;
    for (const r of e.data['apps'] as { package: string; op: string; count: number; background_count?: number; last_ts?: string }[]) {
      const ops = byApp.get(r.package) ?? new Map<string, Row>();
      byApp.set(r.package, ops);
      const cur = ops.get(r.op) ?? { op: r.op, count: 0, background_count: 0, last_ts: '' };
      cur.count += r.count;
      cur.background_count += r.background_count ?? 0;
      if ((r.last_ts ?? '') > cur.last_ts) cur.last_ts = r.last_ts ?? '';
      ops.set(r.op, cur);
    }
  }
  const apps = [...byApp.entries()].map(([pkg, m]) => {
    const rows = [...m.values()].sort((a, b) => b.count - a.count || a.op.localeCompare(b.op));
    return {
      package: pkg,
      ...(labels.has(pkg) ? { label: labels.get(pkg) } : {}),
      count: rows.reduce((s, r) => s + r.count, 0),
      background_count: rows.reduce((s, r) => s + r.background_count, 0),
      last_ts: rows.map((r) => r.last_ts).sort().pop() ?? '',
      ops: rows,
    };
  });
  apps.sort((a, b) => b.count - a.count || a.package.localeCompare(b.package));
  return { apps };
}

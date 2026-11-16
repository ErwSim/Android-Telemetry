// "Tracking" view (contract §9): levels, statuses, reasons, aggregations. Pure functions.
import type { ApiError } from '../api/client.ts';
import type { Publisher, TrackingApp, TrackingDomain, TrackingTotals } from '../api/types.ts';

export type Tone = 'neutral' | 'ok' | 'warn' | 'bad' | 'info';

// ------------------------------------------------------------------------------------------- levels

export interface LevelText {
  key: string;
  name: string;
  description: string;
}

/** Fallback texts if the collector provides none (`levels[].name` / `description`). */
export const LEVEL_FALLBACK: Record<string, { name: string; description: string }> = {
  permissive: {
    name: 'Permissive',
    description: 'Blocks advertising and the best-known trackers. No Google or Samsung telemetry is cut: the risk of breaking an application is minimal.',
  },
  balanced: {
    name: 'Balanced',
    description: 'Adds blocking of telemetry and audience measurement (Google, Samsung, third-party publishers) while letting through what the phone needs: push notifications, updates, Google Play services.',
  },
  strict: {
    name: 'Strict',
    description: 'Also blocks the optional background services of publishers. Some applications may lose features (synchronisation, recommendations, signing in with an account).',
  },
};

export const LEVEL_ORDER = ['permissive', 'balanced', 'strict'];

/** Merges the collector's levels with the fallback texts; the order is permissive, balanced, strict. */
export function levelTexts(levels: { key: string; name?: string; description?: string }[] | undefined): LevelText[] {
  const src: { key: string; name?: string; description?: string }[] =
    levels && levels.length > 0 ? levels : LEVEL_ORDER.map((key) => ({ key }));
  const out = src.map((l) => {
    const fb = LEVEL_FALLBACK[l.key];
    return { key: l.key, name: l.name || fb?.name || l.key, description: l.description || fb?.description || '' };
  });
  const rank = (k: string) => {
    const i = LEVEL_ORDER.indexOf(k);
    return i < 0 ? LEVEL_ORDER.length : i;
  };
  return out.sort((a, b) => rank(a.key) - rank(b.key));
}

// ------------------------------------------------------------------------------------ statuses and reasons

export interface StatusText {
  label: string;
  tone: Tone;
}

export function domainStatus(status: string | undefined): StatusText {
  switch (status) {
    case 'blocked':
      return { label: 'Blocked', tone: 'ok' };
    case 'allowed':
      return { label: 'Allowed', tone: 'neutral' };
    case 'mixed':
      return { label: 'Mixed', tone: 'warn' };
    default:
      return { label: 'Not assessed', tone: 'neutral' };
  }
}

export function overrideLabel(o: 'block' | 'allow' | undefined): string | undefined {
  return o === 'block' ? 'Manual rule: block' : o === 'allow' ? 'Manual rule: allow' : undefined;
}

const REASON_TOKENS: Record<string, string> = {
  FilteredBlackList: 'Blocklist',
  FilteredBlockedService: 'Blocked service',
  FilteredSafeBrowsing: 'Safe browsing',
  FilteredParental: 'Parental control',
  FilteredSafeSearch: 'Safe search',
  FilteredInvalid: 'Invalid query',
  NotFilteredWhiteList: 'Allowed by a rule',
  NotFilteredNotFound: 'No list blocks it',
  NotFilteredError: 'Not filtered (filter error)',
  Rewrite: 'Rewritten by a rule',
  RewriteEtcHosts: 'Rewritten (hosts file)',
  RewriteAutoHosts: 'Rewritten (automatic host)',
};

/**
 * Translates a reason. The contract does not fix its format: we recognise AdGuard Home's tokens, possibly
 * followed by ": list name or rule", and display any other text as is.
 */
export function reasonLabel(reason: string | undefined): string | undefined {
  if (!reason) return undefined;
  const m = /^([A-Za-z]+)\s*(?::\s*(.*))?$/.exec(reason.trim());
  const token = m?.[1];
  const known = token ? REASON_TOKENS[token] : undefined;
  if (known) return m?.[2] ? `${known}: ${m[2]}` : known;
  return reason.trim();
}

// ----------------------------------------------------------------------------------------- aggregations

/** Blocked share in percent (0-100), or undefined without a blocked/allowed count (degraded mode). */
export function blockedPct(x: { queries: number; blocked?: number; allowed?: number }): number | undefined {
  if (x.blocked === undefined && x.allowed === undefined) return undefined;
  const total = (x.blocked ?? 0) + (x.allowed ?? 0) || x.queries;
  if (total <= 0) return 0;
  return ((x.blocked ?? 0) / total) * 100;
}

/** Totals provided by the collector, otherwise the sum of the publishers. */
export function totalsOf(totals: TrackingTotals | undefined, publishers: Publisher[]): TrackingTotals {
  if (totals) return totals;
  const out: TrackingTotals = { queries: 0 };
  for (const p of publishers) {
    out.queries += p.queries;
    if (p.blocked !== undefined) out.blocked = (out.blocked ?? 0) + p.blocked;
    if (p.allowed !== undefined) out.allowed = (out.allowed ?? 0) + p.allowed;
  }
  return out;
}

/** Publishers sorted by decreasing queries; publishers without queries are discarded. */
export function sortPublishers(publishers: Publisher[]): Publisher[] {
  return publishers.filter((p) => p.queries > 0).sort((a, b) => b.queries - a.queries || a.name.localeCompare(b.name, 'en'));
}

/** Appends the next page of domains, discarding duplicates (the cursor may overlap). */
export function mergeDomains(prev: TrackingDomain[], next: TrackingDomain[]): TrackingDomain[] {
  const seen = new Set(prev.map((d) => d.domain));
  return [...prev, ...next.filter((d) => !seen.has(d.domain))];
}

/** Effective rule of a domain: the pending local change wins over the collector's. */
export function effectiveOverride(d: TrackingDomain, local: ReadonlyMap<string, 'block' | 'allow' | 'default'>): 'block' | 'allow' | undefined {
  const l = local.get(d.domain);
  if (l === 'default') return undefined;
  return l ?? d.override;
}

/** Applications of a domain: the first `max`, and the number of the others. */
export function splitApps(apps: { package: string; count: number }[] | undefined, max = 3): { shown: { package: string; count: number }[]; more: number } {
  const sorted = [...(apps ?? [])].sort((a, b) => b.count - a.count);
  return { shown: sorted.slice(0, max), more: Math.max(0, sorted.length - max) };
}

/** Applications sorted by decreasing queries, with a search on the name or the package. */
export function filterApps(apps: TrackingApp[], q: string): TrackingApp[] {
  const f = q.trim().toLowerCase();
  return apps
    .filter((a) => !f || a.package.toLowerCase().includes(f) || (a.label ?? '').toLowerCase().includes(f))
    .sort((a, b) => b.queries - a.queries || a.package.localeCompare(b.package));
}

// ------------------------------------------------------------------------------------------- 409 error

export interface Conflict {
  message: string;
  /** what blocking would break, if the collector details it */
  impacts: string[];
}

const IMPACT_KEYS = ['impacts', 'impact', 'breaks', 'would_break', 'consequences', 'affects', 'details'];

/**
 * Reads the `409` response of `PUT /tracking/override` (essential domain). The contract only fixes its spirit
 * ("explaining what blocking would break"): we display `message`, plus any list or string found under
 * a usual key.
 */
export function parseConflict(e: Pick<ApiError, 'message' | 'body'>): Conflict {
  const impacts: string[] = [];
  const body = e.body ?? {};
  for (const k of IMPACT_KEYS) {
    const v = body[k];
    if (typeof v === 'string' && v.trim()) impacts.push(v.trim());
    else if (Array.isArray(v)) {
      for (const x of v) {
        if (typeof x === 'string' && x.trim()) impacts.push(x.trim());
        // Collector: { domain, breaks } (essential domain and what it would break).
        else if (x && typeof x === 'object') {
          const o = x as Record<string, unknown>;
          const what = typeof o['breaks'] === 'string' ? o['breaks'].trim() : '';
          const dom = typeof o['domain'] === 'string' ? o['domain'].trim() : '';
          if (what) impacts.push(dom ? `${dom}: ${what}` : what);
        }
      }
    }
  }
  return { message: e.message, impacts };
}

// ------------------------------------------------------------------------------------------- actions

export type TrackAction = 'block' | 'allow' | 'default';

/**
 * Actions offered for a domain, according to its status over the period and the manual rule in force.
 * "Block" makes no sense for a domain already blocked without a contrary rule, "Allow" for a domain
 * already allowed; "Reset to default" only exists if there is a manual rule to remove.
 */
export function availableActions(status: string | undefined, override: 'block' | 'allow' | undefined): TrackAction[] {
  const out: TrackAction[] = [];
  if (override !== 'block' && status !== 'blocked') out.push('block');
  if (override !== 'allow' && status !== 'allowed') out.push('allow');
  if (override) out.push('default');
  // Unknown status and no rule: we still offer both choices.
  if (out.length === 0) out.push('block', 'allow');
  return out;
}

export const ACTION_LABELS: Record<TrackAction, string> = { block: 'Block', allow: 'Allow', default: 'Reset to default' };

// ------------------------------------------------------------------------ errors and status data

/** Are there blocked/allowed counts? False without AdGuard (never configured): no percentage is displayed then. */
export function hasStatusData(totals: TrackingTotals | undefined): boolean {
  return (totals?.blocked ?? 0) + (totals?.allowed ?? 0) > 0;
}

/** Translates the errors of `PUT /tracking/*` (contract §9 and clarifications). */
export function trackingErrorMessage(e: { status: number; code: string; message: string }): string {
  switch (e.code) {
    case 'adguard_unavailable':
      return 'AdGuard Home is not configured or not reachable from the collector: nothing was changed.';
    case 'adguard_error':
      return 'AdGuard Home refused or did not answer: nothing was changed (or only partly). Try again, or check AdGuard Home.';
    case 'corrupt_rules':
      return `The rule block managed by Watchpost in AdGuard Home is altered: ${e.message}`;
    case 'levels_not_configured':
      return 'Choosing the level is not available: the collector has no levels → lists mapping file (WATCHPOST_ADGUARD_LEVELS_FILE).';
    case 'invalid_domain':
      return `Invalid domain name: ${e.message}`;
    default:
      return e.message;
  }
}

import { api } from '../api/endpoints.ts';
import { useApi } from '../api/useApi.ts';
import type { TopItem } from '../api/types.ts';
import { Ranking } from './Ranking.tsx';
import { Async, Stat } from './ui.tsx';
import { countKeys } from '../lib/agg.ts';
import { str } from '../lib/data.ts';
import { fmtBytes, fmtNumber } from '../lib/format.ts';

/**
 * Domains contacted by an application. The `/stats/top` API has no per-package filter: we read the
 * `net.dns` / `net.connect` events (text search on the package name) then aggregate here.
 */
async function loadAppEvents(
  deviceId: string,
  type: string,
  pkg: string,
  from: string,
  to: string,
  signal: AbortSignal,
): Promise<{ hosts: string[]; scanned: number; truncated: boolean }> {
  const hosts: string[] = [];
  let cursor: string | undefined;
  let scanned = 0;
  for (let page = 0; page < 4; page++) {
    const r = await api.events({ device_id: deviceId, type, q: pkg, from, to, limit: 500, ...(cursor ? { cursor } : {}) }, signal);
    for (const ev of r.events) {
      scanned++;
      if (str(ev.data, 'package') !== pkg) continue;
      const k = type === 'net.dns' ? str(ev.data, 'hostname') : `${str(ev.data, 'ip') ?? '?'}${ev.data['port'] !== undefined ? `:${String(ev.data['port'])}` : ''}`;
      if (k) hosts.push(k);
    }
    cursor = r.next_cursor || undefined;
    if (!cursor) return { hosts, scanned, truncated: false };
  }
  return { hosts, scanned, truncated: true };
}

export function AppDomains({ deviceId, pkg, from, to, usage }: { deviceId: string; pkg: string; from: string; to: string; usage: TopItem | undefined }) {
  const state = useApi(`appdom:${deviceId}:${pkg}:${from}:${to}`, async (signal) => {
    const [dns, con] = await Promise.all([
      loadAppEvents(deviceId, 'net.dns', pkg, from, to, signal),
      loadAppEvents(deviceId, 'net.connect', pkg, from, to, signal),
    ]);
    return { dns, con };
  });
  return (
    <>
      {usage?.bytes !== undefined && (
        <div className="stats app-stats">
          <Stat label="Volume over the period" value={fmtBytes(usage.bytes)} />
        </div>
      )}
      <Async state={state} loadingLabel="Analysing the application's events…">
        {({ dns, con }) => {
          const dnsTop = countKeys(dns.hosts, 25).map((c) => ({ key: c.key, count: c.count }));
          const conTop = countKeys(con.hosts, 15).map((c) => ({ key: c.key, count: c.count }));
          const truncated = dns.truncated || con.truncated;
          return (
            <>
              {truncated && (
                <p className="state state-warn">
                  Sample limited to the {fmtNumber(Math.max(dns.scanned, con.scanned))} most recent events: counts are partial.
                </p>
              )}
              <div className="two-col">
                <div>
                  <h3>Domains requested ({fmtNumber(dns.hosts.length)} queries)</h3>
                  <Ranking items={dnsTop} kind="host" limit={25} emptyText="No DNS queries for this application." />
                </div>
                <div>
                  <h3>Destinations contacted ({fmtNumber(con.hosts.length)} connections)</h3>
                  <Ranking items={conTop} kind="plain" limit={15} emptyText="No connections for this application." />
                </div>
              </div>
            </>
          );
        }}
      </Async>
    </>
  );
}

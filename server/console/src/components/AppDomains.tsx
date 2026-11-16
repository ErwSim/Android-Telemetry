import { api } from '../api/endpoints.ts';
import { useApi } from '../api/useApi.ts';
import type { TopItem } from '../api/types.ts';
import { Ranking } from './Ranking.tsx';
import { Async, Stat } from './ui.tsx';
import { countKeys } from '../lib/agg.ts';
import { str } from '../lib/data.ts';
import { fmtBytes, fmtNumber } from '../lib/format.ts';

/**
 * Domaines contactés par une application. L'API `/stats/top` n'a pas de filtre par paquet : on lit les
 * événements `net.dns` / `net.connect` (recherche textuelle sur le nom du paquet) puis on agrège ici.
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
          <Stat label="Volume sur la période" value={fmtBytes(usage.bytes)} />
        </div>
      )}
      <Async state={state} loadingLabel="Analyse des événements de l'application…">
        {({ dns, con }) => {
          const dnsTop = countKeys(dns.hosts, 25).map((c) => ({ key: c.key, count: c.count }));
          const conTop = countKeys(con.hosts, 15).map((c) => ({ key: c.key, count: c.count }));
          const truncated = dns.truncated || con.truncated;
          return (
            <>
              {truncated && (
                <p className="state state-warn">
                  Échantillon limité aux {fmtNumber(Math.max(dns.scanned, con.scanned))} événements les plus récents : les décomptes sont partiels.
                </p>
              )}
              <div className="two-col">
                <div>
                  <h3>Domaines demandés ({fmtNumber(dns.hosts.length)} requêtes)</h3>
                  <Ranking items={dnsTop} kind="host" limit={25} emptyText="Aucune requête DNS pour cette application." />
                </div>
                <div>
                  <h3>Destinations contactées ({fmtNumber(con.hosts.length)} connexions)</h3>
                  <Ranking items={conTop} kind="plain" limit={15} emptyText="Aucune connexion pour cette application." />
                </div>
              </div>
            </>
          );
        }}
      </Async>
    </>
  );
}

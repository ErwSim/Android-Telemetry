import type { Publisher, TrackingTotals } from '../../api/types.ts';
import { blockedPct, sortPublishers } from '../../lib/tracking.ts';
import { fmtBytes, fmtNumber, fmtPct } from '../../lib/format.ts';
import { SplitBar } from './SplitBar.tsx';

export function PublisherTable({
  publishers,
  totals,
  showStatus,
  selected,
  onSelect,
}: {
  publishers: Publisher[];
  totals: TrackingTotals;
  showStatus: boolean;
  selected: string | undefined;
  onSelect: (key: string | undefined) => void;
}) {
  const rows = sortPublishers(publishers);
  const max = Math.max(...rows.map((p) => p.queries), 1);
  return (
    <div className="table-wrap">
      <table className="tbl trk-pub">
        <caption className="sr-only">Requêtes DNS par éditeur : bloquées et autorisées, domaines, applications, octets échangés</caption>
        <thead>
          <tr>
            <th scope="col">Éditeur</th>
            <th scope="col" className="right">
              Requêtes
            </th>
            {showStatus && <th scope="col">Bloquées / autorisées</th>}
            {showStatus && (
              <th scope="col" className="right hide-sm">
                Bloquées
              </th>
            )}
            <th scope="col" className="right hide-sm">
              Domaines
            </th>
            <th scope="col" className="right hide-sm">
              Applis
            </th>
            <th scope="col" className="right hide-sm">
              Envoyé
            </th>
            <th scope="col" className="right hide-sm">
              Reçu
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((p) => {
            const pct = blockedPct(p);
            return (
              <tr key={p.key} className={selected === p.key ? 'is-selected' : undefined}>
                <th scope="row" className="pub-name">
                  <button
                    type="button"
                    className="linkish"
                    aria-pressed={selected === p.key}
                    onClick={() => onSelect(selected === p.key ? undefined : p.key)}
                    title="Filtrer les domaines et les applications sur cet éditeur"
                  >
                    <span className={`pub-swatch pub-${p.key}`} aria-hidden="true" />
                    {p.name}
                  </button>
                  <span className="rel-bar" aria-hidden="true">
                    <span className="rel-bar-fill" style={{ width: `${Math.max(2, (p.queries / max) * 100)}%` }} />
                  </span>
                </th>
                <td className="right">{fmtNumber(p.queries)}</td>
                {showStatus && (
                  <td className="split-cell">
                    <SplitBar blocked={p.blocked} allowed={p.allowed} />
                  </td>
                )}
                {showStatus && <td className="right hide-sm">{pct === undefined ? '—' : fmtPct(pct)}</td>}
                <td className="right hide-sm">{fmtNumber(p.domains)}</td>
                <td className="right hide-sm">{fmtNumber(p.apps)}</td>
                <td className="right hide-sm">{fmtBytes(p.tx_bytes)}</td>
                <td className="right hide-sm">{fmtBytes(p.rx_bytes)}</td>
              </tr>
            );
          })}
        </tbody>
        <tfoot>
          <tr>
            <th scope="row">Total</th>
            <td className="right">{fmtNumber(totals.queries)}</td>
            {showStatus && (
              <td>
                <SplitBar blocked={totals.blocked} allowed={totals.allowed} />
              </td>
            )}
            {showStatus && <td className="right hide-sm">{totals.blocked === undefined ? '—' : fmtPct(blockedPct(totals) ?? 0)}</td>}
            <td className="hide-sm" colSpan={4} />
          </tr>
        </tfoot>
      </table>
    </div>
  );
}

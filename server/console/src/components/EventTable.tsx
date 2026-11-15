import { Fragment, useState } from 'react';
import { Link } from 'react-router-dom';
import type { VigieEvent } from '../api/types.ts';
import { describeEvent, typeLabel } from '../lib/events.ts';
import { fmtDateTime, fmtDateTimeShort } from '../lib/format.ts';
import { JsonView } from './JsonView.tsx';
import { SevBadge } from './ui.tsx';

export function EventTable({
  events,
  compact = false,
  newIds,
  showDevice = false,
  describe = describeEvent,
}: {
  events: VigieEvent[];
  compact?: boolean;
  newIds?: ReadonlySet<string>;
  showDevice?: boolean;
  describe?: (ev: VigieEvent) => string;
}) {
  const [open, setOpen] = useState<string | null>(null);
  const cols = 4 + (showDevice ? 1 : 0);
  return (
    <div className="table-wrap">
      <table className="tbl tbl-stack">
        <thead>
          <tr>
            <th scope="col">Heure</th>
            <th scope="col">Sévérité</th>
            <th scope="col">Type</th>
            {showDevice && <th scope="col">Appareil</th>}
            <th scope="col">Détail</th>
          </tr>
        </thead>
        <tbody>
          {events.map((ev) => {
            const isOpen = open === ev.id;
            return (
              <Fragment key={ev.id}>
                <tr className={`sev-${Math.min(3, Math.max(0, Math.trunc(ev.sev)))}${newIds?.has(ev.id) ? ' new-row' : ''}`}>
                  <td className="nowrap c-time">
                    <button
                      type="button"
                      className="expander"
                      aria-expanded={isOpen}
                      aria-label={isOpen ? "Masquer le détail de l'événement" : "Afficher le détail de l'événement"}
                      onClick={() => setOpen(isOpen ? null : ev.id)}
                    >
                      {isOpen ? '▾' : '▸'}
                    </button>
                    <time dateTime={ev.ts} title={fmtDateTime(ev.ts)}>
                      {compact ? fmtDateTimeShort(ev.ts) : fmtDateTime(ev.ts)}
                    </time>
                  </td>
                  <td className="c-sev">
                    <SevBadge sev={ev.sev} short={compact} />
                  </td>
                  <td className="c-type">
                    {typeLabel(ev.type)}
                    {typeLabel(ev.type) !== ev.type && (
                      <>
                        <br />
                        <span className="muted mono">{ev.type}</span>
                      </>
                    )}
                  </td>
                  {showDevice && <td className="mono c-dev">{ev.device_id ?? '—'}</td>}
                  <td className="break c-detail">{describe(ev) || <span className="muted">—</span>}</td>
                </tr>
                {isOpen && (
                  <tr>
                    <td colSpan={cols} className="detail-cell">
                      <EventDetailBody ev={ev} />
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function EventDetailBody({ ev }: { ev: VigieEvent }) {
  return (
    <div>
      <div className="kv-inline hint">
        <span>
          Identifiant <code>{ev.id}</code>
        </span>
        {ev.seq !== undefined && <span> · seq {ev.seq}</span>}
        {ev.received_at && <span> · reçu le {fmtDateTime(ev.received_at)}</span>}{' '}
        · <Link to={`/evenements/${encodeURIComponent(ev.id)}`}>Permalien</Link>
      </div>
      <JsonView value={ev} />
    </div>
  );
}

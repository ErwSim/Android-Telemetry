import { useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { usePagedEvents } from '../api/usePagedEvents.ts';
import { useEventStream } from '../api/useEventStream.ts';
import type { WatchpostEvent } from '../api/types.ts';
import { EventList } from '../components/EventList.tsx';
import { PeriodPicker, usePeriod } from '../components/PeriodPicker.tsx';
import { Card } from '../components/ui.tsx';
import { DOMAIN_LABELS, TYPE_LABELS } from '../lib/events.ts';
import { matchesFilters, parsePrefixes, togglePrefix } from '../lib/eventFilter.ts';
import { periodRange } from '../lib/period.ts';
import { useDevice } from '../state/device.tsx';

const DOMAINS = Object.keys(DOMAIN_LABELS);
const MAX_LIVE = 200;

function useDebounced<T>(v: T, ms: number): T {
  const [d, setD] = useState(v);
  useEffect(() => {
    const t = window.setTimeout(() => setD(v), ms);
    return () => window.clearTimeout(t);
  }, [v, ms]);
  return d;
}

export default function Events() {
  const { deviceId } = useDevice();
  const [sp] = useSearchParams();
  const ctl = usePeriod('24h');
  const [type, setType] = useState(sp.get('type') ?? '');
  const [sevMin, setSevMin] = useState(() => {
    const n = Number(sp.get('sev_min'));
    return Number.isInteger(n) && n >= 0 && n <= 3 ? n : 0;
  });
  const [qInput, setQInput] = useState(sp.get('q') ?? '');
  const q = useDebounced(qInput, 400);
  const typeD = useDebounced(type, 400);
  const [live, setLive] = useState(false);

  const range = periodRange(ctl.period);
  const params = useMemo(
    () =>
      deviceId
        ? { device_id: deviceId, type: typeD || undefined, sev_min: sevMin > 0 ? sevMin : undefined, q: q.trim() || undefined, ...range }
        : null,
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [deviceId, typeD, sevMin, q, range.from, range.to],
  );
  const paged = usePagedEvents(params, 100);

  const filtersKey = `${deviceId}|${typeD}|${sevMin}|${q}`;
  // Events received live are tied to the active filters: changing a filter discards them.
  const [liveState, setLiveState] = useState<{ key: string; events: WatchpostEvent[] }>({ key: filtersKey, events: [] });
  const visibleLive = useMemo(() => (liveState.key === filtersKey ? liveState.events : []), [liveState, filtersKey]);

  const onEvent = useCallback(
    (ev: WatchpostEvent) => {
      if (!matchesFilters(ev, { type: typeD, sevMin, q, deviceId })) return;
      setLiveState((prev) => {
        const base = prev.key === filtersKey ? prev.events : [];
        if (base.some((e) => e.id === ev.id)) return prev;
        return { key: filtersKey, events: [ev, ...base].slice(0, MAX_LIVE) };
      });
    },
    [typeD, sevMin, q, deviceId, filtersKey],
  );
  const status = useEventStream(live, deviceId, onEvent);

  const merged = useMemo(() => {
    const seen = new Set(paged.events.map((e) => e.id));
    return [...visibleLive.filter((e) => !seen.has(e.id)), ...paged.events];
  }, [visibleLive, paged.events]);
  const newIds = useMemo(() => new Set(visibleLive.map((e) => e.id)), [visibleLive]);
  const pagedView = { ...paged, events: merged };

  const prefixes = parsePrefixes(type);

  return (
    <>
      <div className="page-head">
        <h1>Events</h1>
        <label className="check">
          <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} />
          <span className={`live-dot${status === 'open' ? '' : ' is-off'}`} aria-hidden="true" />
          Live
          <span className="hint" role="status">
            {live
              ? status === 'open'
                ? ` · connected (${visibleLive.length} received)`
                : status === 'error'
                  ? ' · connection lost, retrying…'
                  : ' · connecting…'
              : ''}
          </span>
        </label>
      </div>

      <Card className="filters-card">
        <div className="toolbar">
          <PeriodPicker ctl={ctl} />
          <label className="filter">
            Minimum severity
            <select value={sevMin} onChange={(e) => setSevMin(Number(e.target.value))}>
              <option value={0}>0 · Info (all)</option>
              <option value={1}>1 · Notable</option>
              <option value={2}>2 · Warning</option>
              <option value={3}>3 · Critical</option>
            </select>
          </label>
          <label className="filter grow">
            Search in the data
            <input type="search" value={qInput} onChange={(e) => setQInput(e.target.value)} placeholder="package, domain, SSID…" />
          </label>
        </div>
        <div className="toolbar">
          <div className="filter grow">
            <span id="type-label">Type (prefixes separated by commas)</span>
            <input
              list="event-types"
              aria-labelledby="type-label"
              value={type}
              onChange={(e) => setType(e.target.value)}
              placeholder="e.g. net.,security.log"
              spellCheck={false}
            />
            <datalist id="event-types">
              {Object.keys(TYPE_LABELS).map((t) => (
                <option key={t} value={t} />
              ))}
            </datalist>
          </div>
        </div>
        <ul className="chip-list" aria-label="Domains">
          {DOMAINS.map((d) => (
            <li key={d}>
              <button type="button" className="chip-btn" aria-pressed={prefixes.includes(`${d}.`)} onClick={() => setType(togglePrefix(type, `${d}.`))}>
                {DOMAIN_LABELS[d]}
              </button>
            </li>
          ))}
          {prefixes.length > 0 && (
            <li>
              <button type="button" className="chip-btn" onClick={() => setType('')}>
                Clear the filter
              </button>
            </li>
          )}
        </ul>
      </Card>

      <Card className="events-card">
        <div className="flush">
          <EventList paged={pagedView} newIds={newIds} empty="No event matches these filters for this period." />
        </div>
      </Card>
    </>
  );
}

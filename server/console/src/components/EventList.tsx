import type { PagedEvents } from '../api/usePagedEvents.ts';
import type { WatchpostEvent } from '../api/types.ts';
import { EventTable } from './EventTable.tsx';
import { Empty, ErrorBox, Loading } from './ui.tsx';

/** Liste paginée d'événements avec états chargement / vide / erreur. */
export function EventList({
  paged,
  compact,
  empty = 'Aucun événement.',
  describe,
  showDevice,
  newIds,
}: {
  paged: PagedEvents;
  compact?: boolean;
  empty?: string;
  describe?: (ev: WatchpostEvent) => string;
  showDevice?: boolean;
  newIds?: ReadonlySet<string>;
}) {
  if (paged.error && paged.events.length === 0) return <ErrorBox message={paged.error.message} onRetry={paged.reload} />;
  if (paged.loading && paged.events.length === 0) return <Loading label="Chargement des événements…" />;
  if (paged.events.length === 0) return <Empty>{empty}</Empty>;
  const tableProps: Parameters<typeof EventTable>[0] = { events: paged.events };
  if (compact !== undefined) tableProps.compact = compact;
  if (describe) tableProps.describe = describe;
  if (showDevice) tableProps.showDevice = showDevice;
  if (newIds) tableProps.newIds = newIds;
  return (
    <div className={paged.loading ? 'is-refreshing' : undefined}>
      <EventTable {...tableProps} />
      {paged.error && <ErrorBox message={paged.error.message} onRetry={paged.loadMore} />}
      {paged.hasMore && (
        <div className="pager">
          <button type="button" className="btn" onClick={paged.loadMore} disabled={paged.loadingMore}>
            {paged.loadingMore ? 'Chargement…' : 'Charger plus'}
          </button>
          <span>{paged.events.length} affichés</span>
        </div>
      )}
      {!paged.hasMore && <div className="pager">{paged.events.length} événement{paged.events.length > 1 ? 's' : ''} — fin de la liste</div>}
    </div>
  );
}

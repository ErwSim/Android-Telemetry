import { Link, useParams } from 'react-router-dom';
import { api } from '../api/endpoints.ts';
import { useApi } from '../api/useApi.ts';
import { EventDetailBody } from '../components/EventTable.tsx';
import { Async, Card, SevBadge } from '../components/ui.tsx';
import { describeEvent, typeLabel } from '../lib/events.ts';
import { fmtDateTime } from '../lib/format.ts';

export default function EventDetail() {
  const { id = '' } = useParams();
  const state = useApi(`event:${id}`, (s) => api.event(id, s));
  return (
    <>
      <div className="page-head">
        <h1>Événement</h1>
        <Link to="/evenements" className="btn btn-sm">
          Retour au journal
        </Link>
      </div>
      <Async state={state}>
        {(ev) => (
          <Card
            title={
              <>
                {typeLabel(ev.type)} <span className="muted mono">{ev.type}</span>
              </>
            }
            actions={<SevBadge sev={ev.sev} />}
          >
            <p>
              <strong>{fmtDateTime(ev.ts)}</strong> — {describeEvent(ev)}
            </p>
            <EventDetailBody ev={ev} />
          </Card>
        )}
      </Async>
    </>
  );
}

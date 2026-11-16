import { Fragment, useState } from 'react';
import type { RemoteCommand } from '../../api/types.ts';
import { commandLabel, isSensitive, paramsSummary, refusalInfo, statusInfo } from '../../lib/commands.ts';
import { fmtDateTime, fmtDateTimeShort, fmtRelative } from '../../lib/format.ts';
import { cleanText } from '../../lib/text.ts';
import { Badge } from '../ui.tsx';

const isSigned = (c: RemoteCommand): boolean => c.signed ?? isSensitive(c.type);

function Detail({ c }: { c: RemoteCommand }) {
  const st = statusInfo(c.status, !!c.delivered_at, isSigned(c));
  if (c.status === 'refused') {
    const r = refusalInfo(c.detail);
    return (
      <div>
        <strong>{r?.title ?? 'Refused by the phone'}</strong>
        {r && r.help !== r.title && <p className="hint">{r.help}</p>}
      </div>
    );
  }
  if (c.status === 'failed') {
    return (
      <div>
        <strong>The phone could not execute it</strong>
        {c.detail && <p className="hint">Detail: {cleanText(c.detail, 200)}</p>}
      </div>
    );
  }
  return <span className="hint">{st.help}</span>;
}

export function CommandHistory({
  commands,
  onCancel,
  cancelling,
}: {
  commands: RemoteCommand[];
  onCancel: (id: string) => void;
  cancelling: string | undefined;
}) {
  const [open, setOpen] = useState<string | null>(null);
  return (
    <div className="table-wrap">
      <table className="tbl tbl-stack cmd-tbl">
        <thead>
          <tr>
            <th scope="col">Created</th>
            <th scope="col">State</th>
            <th scope="col">Command</th>
            <th scope="col">Detail</th>
            <th scope="col">
              <span className="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {commands.map((c) => {
            const st = statusInfo(c.status, !!c.delivered_at, isSigned(c));
            const sum = paramsSummary(c.type, c.params);
            const alert = c.status === 'refused' && (c.detail === 'bad_signature' || c.detail === 'locked_out');
            const isOpen = open === c.id;
            return (
              <Fragment key={c.id}>
                <tr className={alert ? 'sev-3' : undefined} data-status={c.status}>
                  <td className="nowrap c-time">
                    <button
                      type="button"
                      className="expander"
                      aria-expanded={isOpen}
                      aria-label={isOpen ? 'Hide the times' : 'Show the times'}
                      onClick={() => setOpen(isOpen ? null : c.id)}
                    >
                      {isOpen ? '▾' : '▸'}
                    </button>
                    <time dateTime={c.created_at} title={fmtDateTime(c.created_at)}>
                      {fmtDateTimeShort(c.created_at)}
                    </time>
                  </td>
                  <td className="c-sev">
                    <Badge tone={st.tone} title={st.help}>
                      {st.label}
                    </Badge>
                  </td>
                  <td className="c-type">
                    <strong>{commandLabel(c.type)}</strong>
                    {c.signed && (
                      <>
                        {' '}
                        <Badge tone="neutral" title="Signed in the browser with the command passphrase">
                          signed
                        </Badge>
                      </>
                    )}
                    {sum && (
                      <>
                        <br />
                        <span className="muted break">{sum}</span>
                      </>
                    )}
                  </td>
                  <td className="break c-detail">
                    <Detail c={c} />
                  </td>
                  <td className="c-act">
                    {c.status === 'pending' && (
                      <button
                        type="button"
                        className="btn btn-sm"
                        onClick={() => onCancel(c.id)}
                        disabled={cancelling === c.id}
                        title={isSigned(c) ? 'Cancels on the server side only: a signed command remains executable until it expires if a copy exists' : undefined}
                      >
                        {cancelling === c.id ? 'Cancelling…' : 'Cancel'}
                      </button>
                    )}
                  </td>
                </tr>
                {isOpen && (
                  <tr>
                    <td colSpan={5} className="detail-cell">
                      <ul className="times">
                        <li>
                          Created on {fmtDateTime(c.created_at)}
                          {c.created_by ? ` by ${cleanText(c.created_by, 60)}` : ''}
                        </li>
                        {c.expires_at && (
                          <li>
                            Expires on {fmtDateTime(c.expires_at)} ({fmtRelative(c.expires_at)})
                          </li>
                        )}
                        {c.delivered_at && <li>Delivered to the phone on {fmtDateTime(c.delivered_at)}</li>}
                        {c.result_at && <li>Result on {fmtDateTime(c.result_at)}</li>}
                        <li>
                          ID <code>{c.id}</code>
                          {c.detail && c.detail !== 'cancelled' ? (
                            <>
                              {' '}
                              · reason <code>{cleanText(c.detail, 80)}</code>
                            </>
                          ) : null}
                        </li>
                      </ul>
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

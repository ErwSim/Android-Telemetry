import { Fragment, useState } from 'react';
import type { RemoteCommand } from '../../api/types.ts';
import { commandLabel, paramsSummary, refusalInfo, statusInfo } from '../../lib/commands.ts';
import { fmtDateTime, fmtDateTimeShort, fmtRelative } from '../../lib/format.ts';
import { cleanText } from '../../lib/text.ts';
import { Badge } from '../ui.tsx';

function Detail({ c }: { c: RemoteCommand }) {
  const st = statusInfo(c.status, !!c.delivered_at);
  if (c.status === 'refused') {
    const r = refusalInfo(c.detail);
    return (
      <div>
        <strong>{r?.title ?? 'Refusée par le téléphone'}</strong>
        {r && r.help !== r.title && <p className="hint">{r.help}</p>}
      </div>
    );
  }
  if (c.status === 'failed') {
    return (
      <div>
        <strong>Le téléphone n'a pas pu l'exécuter</strong>
        {c.detail && <p className="hint">Détail : {cleanText(c.detail, 200)}</p>}
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
            <th scope="col">Créée</th>
            <th scope="col">État</th>
            <th scope="col">Commande</th>
            <th scope="col">Détail</th>
            <th scope="col">
              <span className="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {commands.map((c) => {
            const st = statusInfo(c.status, !!c.delivered_at);
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
                      aria-label={isOpen ? 'Masquer les horaires' : 'Afficher les horaires'}
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
                        <Badge tone="neutral" title="Signée dans le navigateur avec le code de commande">
                          signée
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
                      <button type="button" className="btn btn-sm" onClick={() => onCancel(c.id)} disabled={cancelling === c.id}>
                        {cancelling === c.id ? 'Annulation…' : 'Annuler'}
                      </button>
                    )}
                  </td>
                </tr>
                {isOpen && (
                  <tr>
                    <td colSpan={5} className="detail-cell">
                      <ul className="times">
                        <li>
                          Créée le {fmtDateTime(c.created_at)}
                          {c.created_by ? ` par ${cleanText(c.created_by, 60)}` : ''}
                        </li>
                        {c.expires_at && (
                          <li>
                            Expire le {fmtDateTime(c.expires_at)} ({fmtRelative(c.expires_at)})
                          </li>
                        )}
                        {c.delivered_at && <li>Remise au téléphone le {fmtDateTime(c.delivered_at)}</li>}
                        {c.result_at && <li>Résultat le {fmtDateTime(c.result_at)}</li>}
                        <li>
                          Identifiant <code>{c.id}</code>
                          {c.detail && c.detail !== 'cancelled' ? (
                            <>
                              {' '}
                              · motif <code>{cleanText(c.detail, 80)}</code>
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

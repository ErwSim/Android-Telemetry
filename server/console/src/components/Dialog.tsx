import { useEffect, useId, useRef, type ReactNode } from 'react';

/**
 * Native modal dialog (`<dialog>`): trapped focus, Escape and click on the backdrop to close, focus returned
 * to the originating button. No inline style (CSP). `busy` prevents closing during an operation.
 */
export function Dialog({
  title,
  onClose,
  children,
  footer,
  busy = false,
  tone,
}: {
  title: ReactNode;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  busy?: boolean;
  tone?: 'danger';
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const busyRef = useRef(busy);
  const closeRef = useRef(onClose);
  useEffect(() => {
    busyRef.current = busy;
    closeRef.current = onClose;
  });

  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    if (!d.open) d.showModal();
    return () => {
      if (d.open) d.close();
      opener?.focus?.();
    };
  }, []);

  return (
    <dialog
      ref={ref}
      className={`dlg${tone === 'danger' ? ' dlg-danger' : ''}`}
      aria-labelledby={titleId}
      onCancel={(e) => {
        e.preventDefault();
        if (!busyRef.current) closeRef.current();
      }}
      onClick={(e) => {
        if (e.target === ref.current && !busyRef.current) closeRef.current();
      }}
    >
      <div className="dlg-box">
        <header className="dlg-head">
          <h2 id={titleId}>{title}</h2>
        </header>
        <div className="dlg-body">{children}</div>
        {footer && <footer className="dlg-foot">{footer}</footer>}
      </div>
    </dialog>
  );
}

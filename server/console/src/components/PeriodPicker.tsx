import { useMemo, useState } from 'react';
import { PERIOD_LABELS, resolvePeriod, type Period, type PeriodKey } from '../lib/period.ts';
import { toLocalInput } from '../lib/format.ts';

export interface PeriodControl {
  period: Period;
  key: PeriodKey;
  setKey: (k: PeriodKey) => void;
  customFrom: string;
  customTo: string;
  setCustomFrom: (v: string) => void;
  setCustomTo: (v: string) => void;
  /** Recomputes "now" for the relative periods. */
  refresh: () => void;
}

export function usePeriod(initial: PeriodKey = '24h'): PeriodControl {
  const [key, setKeyState] = useState<PeriodKey>(initial);
  const [anchor, setAnchor] = useState(() => Date.now());
  const [customFrom, setCustomFrom] = useState(() => toLocalInput(new Date(Date.now() - 24 * 3600_000)));
  const [customTo, setCustomTo] = useState(() => toLocalInput(new Date()));

  const period = useMemo(() => {
    const from = new Date(customFrom);
    const to = new Date(customTo);
    const custom =
      !Number.isNaN(from.getTime()) && !Number.isNaN(to.getTime()) ? { from, to } : undefined;
    return resolvePeriod(key, new Date(anchor), custom);
  }, [key, anchor, customFrom, customTo]);

  return {
    period,
    key,
    setKey: (k) => {
      setAnchor(Date.now());
      setKeyState(k);
    },
    customFrom,
    customTo,
    setCustomFrom,
    setCustomTo,
    refresh: () => setAnchor(Date.now()),
  };
}

const KEYS: PeriodKey[] = ['today', '24h', '7d', '30d', 'custom'];

export function PeriodPicker({ ctl, keys = KEYS }: { ctl: PeriodControl; keys?: PeriodKey[] }) {
  const invalid = ctl.key === 'custom' && !(new Date(ctl.customFrom) < new Date(ctl.customTo));
  return (
    <div className="period">
      <div className="seg" role="group" aria-label="Period">
        {keys.map((k) => (
          <button
            key={k}
            type="button"
            className={`seg-btn${ctl.key === k ? ' is-active' : ''}`}
            aria-pressed={ctl.key === k}
            onClick={() => ctl.setKey(k)}
          >
            {PERIOD_LABELS[k]}
          </button>
        ))}
      </div>
      {ctl.key === 'custom' && (
        <div className="period-custom">
          <label>
            From
            <input
              type="datetime-local"
              value={ctl.customFrom}
              onChange={(e) => ctl.setCustomFrom(e.target.value)}
              aria-invalid={invalid}
            />
          </label>
          <label>
            to
            <input
              type="datetime-local"
              value={ctl.customTo}
              onChange={(e) => ctl.setCustomTo(e.target.value)}
              aria-invalid={invalid}
            />
          </label>
          {invalid && (
            <span className="form-error" role="alert">
              The end must come after the start (24 h period used).
            </span>
          )}
        </div>
      )}
    </div>
  );
}

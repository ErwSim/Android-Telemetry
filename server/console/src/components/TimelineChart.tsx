import { useEffect, useMemo, useRef } from 'react';
import uPlot from 'uplot';
import 'uplot/dist/uPlot.min.css';
import type { Bucket, TimelineResponse } from '../api/types.ts';
import { stackSeries } from '../lib/agg.ts';
import { domainLabel, seriesIndex, typeLabel } from '../lib/events.ts';
import { fmtNumber } from '../lib/format.ts';
import { cssVar, useTheme } from '../state/theme.tsx';

export interface TimelineChartProps {
  data: TimelineResponse;
  bucket: Bucket;
  order?: string[];
  labelOf?: (key: string) => string;
  height?: number;
  ariaLabel: string;
}

const dayFmt = new Intl.DateTimeFormat('fr-FR', { day: '2-digit', month: '2-digit' });
const hourFmt = new Intl.DateTimeFormat('fr-FR', { hour: '2-digit', minute: '2-digit' });
const dayHourFmt = new Intl.DateTimeFormat('fr-FR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });

function defaultLabel(k: string): string {
  return k.includes('.') ? typeLabel(k) : domainLabel(k);
}

export function seriesColor(key: string): string {
  return cssVar(`--series-${seriesIndex(key)}`, '#2563eb');
}

export default function TimelineChart({ data, bucket, order, labelOf = defaultLabel, height = 220, ariaLabel }: TimelineChartProps) {
  const host = useRef<HTMLDivElement>(null);
  const tip = useRef<HTMLDivElement>(null);
  const { effective } = useTheme();
  const stacked = useMemo(() => stackSeries(data, order), [data, order]);
  const total = stacked.sums.reduce((a, b) => a + b, 0);

  useEffect(() => {
    const el = host.current;
    if (!el || stacked.x.length === 0) return;
    const text = cssVar('--text-muted', '#667');
    const grid = cssVar('--border', '#ddd');
    const n = stacked.keys.length;
    const spanS = (stacked.x[stacked.x.length - 1] ?? 0) - (stacked.x[0] ?? 0);

    // uPlot dessine dans l'ordre : on place la série cumulée la plus haute en premier.
    const rev = [...stacked.cumulative].reverse();
    const keysRev = [...stacked.keys].reverse();
    const rawCounts = stacked.keys.map((k) => data.series.find((s) => s.key === k)?.counts ?? []);

    const fmtX = (ts: number) => {
      const d = new Date(ts * 1000);
      if (bucket === 'day') return dayFmt.format(d);
      return spanS > 36 * 3600 ? dayHourFmt.format(d) : hourFmt.format(d);
    };

    const opts: uPlot.Options = {
      width: Math.max(280, el.clientWidth),
      height,
      padding: [8, 8, 0, 0],
      legend: { show: false },
      cursor: { y: false, points: { show: false }, drag: { x: false, y: false, setScale: false } },
      scales: { x: { time: true }, y: { range: (_u, _min, max) => [0, Math.max(1, max * 1.08)] } },
      axes: [
        {
          stroke: text,
          grid: { stroke: grid, width: 1 },
          ticks: { stroke: grid },
          font: '12px system-ui, sans-serif',
          values: (_u, splits) => splits.map((s) => fmtX(s)),
        },
        {
          stroke: text,
          grid: { stroke: grid, width: 1 },
          ticks: { show: false },
          font: '12px system-ui, sans-serif',
          size: 44,
          values: (_u, splits) => splits.map((s) => fmtNumber(s)),
        },
      ],
      series: [
        {},
        ...keysRev.map((k) => {
          const c = seriesColor(k);
          return {
            label: labelOf(k),
            stroke: c,
            fill: c,
            width: 0,
            paths: uPlot.paths.bars?.({ size: [0.85, 60], gap: 0 }),
            points: { show: false },
          } satisfies uPlot.Series;
        }),
      ],
      hooks: {
        setCursor: [
          (u) => {
            const t = tip.current;
            if (!t) return;
            const idx = u.cursor.idx;
            if (idx === null || idx === undefined || u.cursor.left === undefined || u.cursor.left < 0) {
              t.hidden = true;
              return;
            }
            const ts = u.data[0]?.[idx];
            if (ts === undefined) return;
            t.replaceChildren();
            const head = document.createElement('div');
            head.className = 'tip-head';
            head.textContent = dayHourFmt.format(new Date(ts * 1000));
            t.append(head);
            let any = false;
            for (let i = 0; i < n; i++) {
              const v = rawCounts[i]?.[idx] ?? 0;
              if (!v) continue;
              any = true;
              const k = stacked.keys[i] ?? '';
              const row = document.createElement('div');
              row.className = 'tip-row';
              const sw = document.createElement('span');
              sw.className = 'swatch';
              sw.style.background = seriesColor(k);
              const lab = document.createElement('span');
              lab.textContent = `${labelOf(k)} : ${fmtNumber(v)}`;
              row.append(sw, lab);
              t.append(row);
            }
            if (!any) {
              const none = document.createElement('div');
              none.textContent = 'Aucun événement';
              t.append(none);
            }
            t.hidden = false;
            const w = u.over.clientWidth;
            const left = u.cursor.left + u.over.offsetLeft;
            t.style.left = `${Math.min(Math.max(left + 12, 0), Math.max(0, w - 150))}px`;
            t.style.top = `${u.over.offsetTop + 4}px`;
          },
        ],
      },
    };
    const u = new uPlot(opts, [stacked.x, ...rev], el);
    const ro = new ResizeObserver(() => u.setSize({ width: Math.max(280, el.clientWidth), height }));
    ro.observe(el);
    const hide = () => {
      if (tip.current) tip.current.hidden = true;
    };
    u.over.addEventListener('mouseleave', hide);
    return () => {
      ro.disconnect();
      u.destroy();
    };
  }, [stacked, bucket, height, effective, labelOf, data.series]);

  return (
    <div className="chart">
      <div className="chart-plot" ref={host} role="img" aria-label={`${ariaLabel} — ${fmtNumber(total)} événements`} />
      <div className="chart-tip" ref={tip} hidden />
      <ul className="legend">
        {stacked.keys.map((k, i) => (
          <li key={k}>
            <span className="swatch" style={{ background: seriesColor(k) }} aria-hidden="true" />
            {labelOf(k)} <span className="muted">{fmtNumber(stacked.sums[i] ?? 0)}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

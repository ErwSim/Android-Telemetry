import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { readStore, writeStore } from '../lib/storage.ts';

export type ThemeMode = 'auto' | 'light' | 'dark';

interface ThemeValue {
  mode: ThemeMode;
  /** thème réellement appliqué */
  effective: 'light' | 'dark';
  cycle: () => void;
}

const Ctx = createContext<ThemeValue | null>(null);
const KEY = 'vigie.theme';

function systemDark(): boolean {
  return typeof window.matchMedia === 'function' && window.matchMedia('(prefers-color-scheme: dark)').matches;
}

function applyTheme(mode: ThemeMode): void {
  const el = document.documentElement;
  if (mode === 'auto') el.removeAttribute('data-theme');
  else el.setAttribute('data-theme', mode);
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [mode, setMode] = useState<ThemeMode>(() => {
    const s = readStore(KEY);
    return s === 'light' || s === 'dark' ? s : 'auto';
  });
  const [sys, setSys] = useState<boolean>(systemDark);

  useEffect(() => {
    if (typeof window.matchMedia !== 'function') return;
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const on = () => setSys(mq.matches);
    mq.addEventListener('change', on);
    return () => mq.removeEventListener('change', on);
  }, []);

  useEffect(() => applyTheme(mode), [mode]);

  const cycle = useCallback(() => {
    const next: ThemeMode = mode === 'auto' ? 'light' : mode === 'light' ? 'dark' : 'auto';
    writeStore(KEY, next === 'auto' ? null : next);
    // Appliqué tout de suite : les graphiques lisent les variables CSS dans leurs effets, avant celui-ci.
    applyTheme(next);
    setMode(next);
  }, [mode]);

  const effective: 'light' | 'dark' = mode === 'auto' ? (sys ? 'dark' : 'light') : mode;
  const value = useMemo(() => ({ mode, effective, cycle }), [mode, effective, cycle]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useTheme(): ThemeValue {
  const v = useContext(Ctx);
  if (!v) throw new Error('ThemeProvider manquant');
  return v;
}

/** Lit une variable CSS du thème courant (pour le canvas des graphiques et de la carte). */
export function cssVar(name: string, fallback = '#888'): string {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
}

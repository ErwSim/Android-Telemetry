// Accès défensifs aux champs de `data` : un champ peut manquer ou avoir un type inattendu.
import type { DataObject } from '../api/types.ts';

export function str(d: DataObject | undefined, k: string): string | undefined {
  const v = d?.[k];
  return typeof v === 'string' && v !== '' ? v : undefined;
}
export function num(d: DataObject | undefined, k: string): number | undefined {
  const v = d?.[k];
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined;
}
export function bool(d: DataObject | undefined, k: string): boolean | undefined {
  const v = d?.[k];
  return typeof v === 'boolean' ? v : undefined;
}
export function strList(d: DataObject | undefined, k: string): string[] {
  const v = d?.[k];
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}
export function obj(d: DataObject | undefined, k: string): DataObject | undefined {
  const v = d?.[k];
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as DataObject) : undefined;
}
export function list<T = unknown>(d: DataObject | undefined, k: string): T[] {
  const v = d?.[k];
  return Array.isArray(v) ? (v as T[]) : [];
}

export function isRecord(v: unknown): v is DataObject {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

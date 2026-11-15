import { useMemo } from 'react';
import { api } from '../api/endpoints.ts';
import { useApi } from '../api/useApi.ts';
import { useDevice } from './device.tsx';

/** Correspondance paquet → libellé d'application, d'après le dernier inventaire. */
export function useAppLabels(): (pkg: string | undefined) => string | undefined {
  const { deviceId } = useDevice();
  const { data } = useApi(deviceId ? `apps:${deviceId}` : null, (s) => api.apps(deviceId, s));
  const map = useMemo(() => {
    const m = new Map<string, string>();
    for (const a of data?.apps ?? []) if (a.label) m.set(a.package, a.label);
    return m;
  }, [data]);
  return (pkg) => (pkg ? map.get(pkg) : undefined);
}

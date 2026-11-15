import { createContext, useContext, useEffect, useMemo, useState, useCallback, type ReactNode } from 'react';
import { api } from '../api/endpoints.ts';
import { useApi } from '../api/useApi.ts';
import type { ApiError } from '../api/client.ts';
import type { Device } from '../api/types.ts';
import { readStore, writeStore } from '../lib/storage.ts';

interface DeviceValue {
  devices: Device[];
  device: Device | undefined;
  deviceId: string | undefined;
  setDeviceId: (id: string) => void;
  loading: boolean;
  error: ApiError | undefined;
  reload: () => void;
}

const Ctx = createContext<DeviceValue | null>(null);
const KEY = 'vigie.device';

export function DeviceProvider({ children }: { children: ReactNode }) {
  const { data, error, loading, reload } = useApi('devices', (signal) => api.devices(signal));
  const [selected, setSelected] = useState<string | null>(() => readStore(KEY));

  // Rafraîchit l'état de l'appareil (dernier contact, batterie…) toutes les 60 s.
  useEffect(() => {
    const t = window.setInterval(reload, 60_000);
    return () => window.clearInterval(t);
  }, [reload]);

  const devices = useMemo(() => data?.devices ?? [], [data]);
  const device = useMemo(() => {
    return devices.find((d) => d.device_id === selected) ?? devices.find((d) => !d.revoked) ?? devices[0];
  }, [devices, selected]);

  const setDeviceId = useCallback((id: string) => {
    setSelected(id);
    writeStore(KEY, id);
  }, []);

  const value = useMemo<DeviceValue>(
    () => ({ devices, device, deviceId: device?.device_id, setDeviceId, loading, error, reload }),
    [devices, device, setDeviceId, loading, error, reload],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useDevice(): DeviceValue {
  const v = useContext(Ctx);
  if (!v) throw new Error('DeviceProvider manquant');
  return v;
}

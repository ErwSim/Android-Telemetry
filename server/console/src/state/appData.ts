import { api } from '../api/endpoints.ts';
import { useApi, type ApiState } from '../api/useApi.ts';
import type { AppOpsResponse, AppRiskResponse, DetectionMute } from '../api/types.ts';
import { useDevice } from './device.tsx';

/** Risk profile (`GET /apps/risk`) of the current device. */
export function useAppRisk(): ApiState<AppRiskResponse> {
  const { deviceId } = useDevice();
  return useApi(deviceId ? `risk:${deviceId}` : null, (s) => api.appsRisk(deviceId, s));
}

/** Sensitive operations usage (`GET /apps/ops`), experimental: may be empty or absent (404). */
export function useAppOps(from: string, to: string): ApiState<AppOpsResponse> {
  const { deviceId } = useDevice();
  return useApi(deviceId ? `ops:${deviceId}:${from}:${to}` : null, (s) => api.appsOps({ device_id: deviceId, from, to }, s));
}

/** True if the error means "this collector does not know this route" (collector older than v1.2). */
export function isUnsupported(e: { status: number } | undefined): boolean {
  return e?.status === 404 || e?.status === 501;
}

/** Current detection mutes (`GET /detections/mutes`); 404 if the collector predates §11.4. */
export function useMutes(): ApiState<DetectionMute[]> {
  const { deviceId } = useDevice();
  return useApi(deviceId ? `mutes:${deviceId}` : null, (s) => api.detectionMutes(deviceId, s));
}

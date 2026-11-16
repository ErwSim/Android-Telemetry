import { api } from '../api/endpoints.ts';
import { useApi, type ApiState } from '../api/useApi.ts';
import type { AppOpsResponse, AppRiskResponse, DetectionMute } from '../api/types.ts';
import { useDevice } from './device.tsx';

/** Profil de risque (`GET /apps/risk`) de l'appareil courant. */
export function useAppRisk(): ApiState<AppRiskResponse> {
  const { deviceId } = useDevice();
  return useApi(deviceId ? `risk:${deviceId}` : null, (s) => api.appsRisk(deviceId, s));
}

/** Usage des opérations sensibles (`GET /apps/ops`), expérimental : peut être vide ou absent (404). */
export function useAppOps(from: string, to: string): ApiState<AppOpsResponse> {
  const { deviceId } = useDevice();
  return useApi(deviceId ? `ops:${deviceId}:${from}:${to}` : null, (s) => api.appsOps({ device_id: deviceId, from, to }, s));
}

/** Vrai si l'erreur signifie « ce collecteur ne connaît pas cette route » (collecteur antérieur à la v1.2). */
export function isUnsupported(e: { status: number } | undefined): boolean {
  return e?.status === 404 || e?.status === 501;
}

/** Sourdines de détections en cours (`GET /detections/mutes`) ; 404 si le collecteur est antérieur au §11.4. */
export function useMutes(): ApiState<DetectionMute[]> {
  const { deviceId } = useDevice();
  return useApi(deviceId ? `mutes:${deviceId}` : null, (s) => api.detectionMutes(deviceId, s));
}

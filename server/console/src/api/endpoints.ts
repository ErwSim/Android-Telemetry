import { request, type Query } from './client.ts';
import { parseDetectionsResponse } from '../lib/detections.ts';
import { parseOpsResponse } from '../lib/ops.ts';
import { parseRiskResponse } from '../lib/risk.ts';
import type {
  AlertsResponse,
  AppOpsResponse,
  AppRiskResponse,
  AppsResponse,
  Bucket,
  CommandsResponse,
  DetectionsResponse,
  DevicesResponse,
  EventsResponse,
  LevelResponse,
  LocationsResponse,
  MeResponse,
  OverrideAction,
  PostureResponse,
  TimelineResponse,
  TrackingAppsResponse,
  TrackingDomainsResponse,
  TrackingSummary,
  TopKind,
  TopResponse,
  VigieEvent,
} from './types.ts';

export interface Range {
  from: string;
  to: string;
}

export const api = {
  me: (signal?: AbortSignal) =>
    request<MeResponse>('/me', undefined, signal ? { signal, noAuthRedirect: true } : { noAuthRedirect: true }),
  login: (username: string, password: string) =>
    request<void>('/login', undefined, { method: 'POST', body: { username, password }, noAuthRedirect: true }),
  logout: () => request<void>('/logout', undefined, { method: 'POST', noAuthRedirect: true }),
  devices: (signal?: AbortSignal) => request<DevicesResponse>('/devices', undefined, signal ? { signal } : {}),
  events: (
    q: Range & {
      device_id?: string;
      type?: string;
      sev_min?: number;
      q?: string;
      limit?: number;
      cursor?: string;
    },
    signal?: AbortSignal,
  ) => request<EventsResponse>('/events', q as unknown as Query, signal ? { signal } : {}),
  event: (id: string, signal?: AbortSignal) =>
    request<VigieEvent>(`/events/${encodeURIComponent(id)}`, undefined, signal ? { signal } : {}),
  locations: (q: Range & { device_id?: string; max_points?: number }, signal?: AbortSignal) =>
    request<LocationsResponse>('/locations', q as unknown as Query, signal ? { signal } : {}),
  timeline: (
    q: Range & { device_id?: string; bucket: Bucket; by: 'domain' | 'type' | 'sev' },
    signal?: AbortSignal,
  ) => request<TimelineResponse>('/stats/timeline', q as unknown as Query, signal ? { signal } : {}),
  top: (q: Range & { device_id?: string; kind: TopKind; limit?: number }, signal?: AbortSignal) =>
    request<TopResponse>('/stats/top', q as unknown as Query, signal ? { signal } : {}),
  apps: (device_id?: string, signal?: AbortSignal) =>
    request<AppsResponse>('/apps', { device_id }, signal ? { signal } : {}),
  posture: (device_id?: string, signal?: AbortSignal) =>
    request<PostureResponse>('/posture', { device_id }, signal ? { signal } : {}),
  alerts: (q: { from?: string; to?: string; level_min?: number; limit?: number }, signal?: AbortSignal) =>
    request<AlertsResponse>('/alerts', q as Query, signal ? { signal } : {}),
  // Profil de risque, usage des opérations sensibles, détections (§11). Les réponses sont lues avec tolérance :
  // le contrat fixe les champs mais pas l'enveloppe exacte, et `app.ops` peut être absent.
  appsRisk: async (device_id?: string, signal?: AbortSignal): Promise<AppRiskResponse> =>
    parseRiskResponse(await request<unknown>('/apps/risk', { device_id }, signal ? { signal } : {})),
  appsOps: async (q: Range & { device_id?: string }, signal?: AbortSignal): Promise<AppOpsResponse> =>
    parseOpsResponse(await request<unknown>('/apps/ops', q as unknown as Query, signal ? { signal } : {})),
  detections: async (
    q: Range & { device_id?: string; type?: string; package?: string; limit?: number; cursor?: string },
    signal?: AbortSignal,
  ): Promise<DetectionsResponse> => parseDetectionsResponse(await request<unknown>('/detections', q as unknown as Query, signal ? { signal } : {})),
  // Commandes à distance (§8)
  commands: (q: { device_id?: string; limit?: number }, signal?: AbortSignal) =>
    request<CommandsResponse>('/commands', q as Query, signal ? { signal } : {}),
  createCommand: (body: { device_id: string; payload: string; sig?: string }) =>
    request<{ id: string }>('/commands', undefined, { method: 'POST', body }),
  cancelCommand: (id: string) => request<void>(`/commands/${encodeURIComponent(id)}/cancel`, undefined, { method: 'POST' }),
  // Pistage (§9)
  trackingSummary: (q: Range & { device_id?: string }, signal?: AbortSignal) =>
    request<TrackingSummary>('/tracking/summary', q as unknown as Query, signal ? { signal } : {}),
  trackingDomains: (
    q: Range & { device_id?: string; publisher?: string; status?: string; q?: string; limit?: number; cursor?: string },
    signal?: AbortSignal,
  ) => request<TrackingDomainsResponse>('/tracking/domains', q as unknown as Query, signal ? { signal } : {}),
  trackingApps: (q: Range & { device_id?: string; publisher?: string }, signal?: AbortSignal) =>
    request<TrackingAppsResponse>('/tracking/apps', q as unknown as Query, signal ? { signal } : {}),
  trackingOverride: (body: { domain: string; action: OverrideAction; force?: boolean }) =>
    request<void>('/tracking/override', undefined, { method: 'PUT', body }),
  trackingLevel: (signal?: AbortSignal) => request<LevelResponse>('/tracking/level', undefined, signal ? { signal } : {}),
  setTrackingLevel: (level: string) => request<void>('/tracking/level', undefined, { method: 'PUT', body: { level } }),
};

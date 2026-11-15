import { request, type Query } from './client.ts';
import type {
  AlertsResponse,
  AppsResponse,
  Bucket,
  DevicesResponse,
  EventsResponse,
  LocationsResponse,
  MeResponse,
  PostureResponse,
  TimelineResponse,
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
};

// Types de l'API console (docs/contrat/contrat.md §6) et des événements (§1-2).
// Tous les champs de `data` sont optionnels : le catalogue donne un minimum, jamais une garantie.

export type Sev = 0 | 1 | 2 | 3;

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };
export type DataObject = Record<string, unknown>;

export interface VigieEvent {
  id: string;
  ts: string;
  seq?: number;
  boot_id?: string;
  elapsed_ms?: number;
  type: string;
  sev: number;
  data: DataObject;
  received_at?: string;
  device_id?: string;
}

export interface Heartbeat {
  battery_pct?: number;
  charging?: boolean;
  uptime_ms?: number;
  queue_depth?: number;
  queue_bytes?: number;
  dropped_total?: number;
  device_owner?: boolean;
  collectors?: Record<string, string>;
  last_upload_ts?: string;
}

export interface Posture {
  security_patch?: string;
  patch_age_days?: number;
  encrypted?: boolean;
  lock_secure?: boolean;
  adb_enabled?: boolean;
  adb_wifi_enabled?: boolean;
  dev_options?: boolean;
  unknown_sources?: boolean;
  private_dns_mode?: string;
  private_dns_host?: string;
  always_on_vpn?: boolean | string;
  device_owner?: boolean;
  verified_boot_state?: string;
  user_ca_certs?: string[];
  play_protect?: boolean;
  usb_data_signaling?: boolean;
}

export interface LastLocation {
  ts: string;
  lat: number;
  lon: number;
  acc_m?: number;
}

export interface CommandChannelState {
  connected?: boolean;
  /** `stream` (connexion permanente), `poll` (interrogation) ou `unknown` */
  mode?: string;
  last_contact?: string;
}

export interface Device {
  device_id: string;
  name: string;
  enrolled_at?: string;
  last_seen?: string;
  agent_version?: string;
  revoked?: boolean;
  last_heartbeat?: Heartbeat;
  last_location?: LastLocation;
  last_posture?: Posture;
  /** Contrat §8 : état du canal de commandes. */
  command_channel?: CommandChannelState;
}

export interface DevicesResponse {
  devices: Device[];
}

export interface EventsResponse {
  events: VigieEvent[];
  next_cursor?: string;
}

export interface LocationPoint {
  ts: string;
  lat: number;
  lon: number;
  acc_m?: number;
  speed_mps?: number;
  provider?: string;
}

export interface LocationsResponse {
  points: LocationPoint[];
}

export type Bucket = 'minute' | 'hour' | 'day';

export interface TimelineResponse {
  buckets: string[];
  series: { key: string; counts: number[] }[];
}

export type TopKind =
  | 'dns_hostname'
  | 'dns_package'
  | 'connect_dest'
  | 'connect_package'
  | 'usage_package'
  | 'foreground_package'
  | 'notification_package'
  | 'event_type';

export interface TopItem {
  key: string;
  count: number;
  bytes?: number;
}

export interface TopResponse {
  items: TopItem[];
}

export interface AppInfo {
  package: string;
  label?: string;
  version_name?: string;
  version_code?: number;
  installer?: string;
  system?: boolean;
  enabled?: boolean;
  suspended?: boolean;
  hidden?: boolean;
  target_sdk?: number;
  first_install?: string | number;
  last_update?: string | number;
  signer_sha256?: string;
  granted_dangerous?: string[];
}

export interface AppsResponse {
  ts?: string;
  apps: AppInfo[];
}

export interface PostureChange {
  ts: string;
  field: string;
  old?: unknown;
  new?: unknown;
}

export interface PostureResponse {
  current: Posture;
  ts?: string;
  changes: PostureChange[];
}

export interface Alert {
  ts: string;
  level: number;
  rule_id?: string;
  description?: string;
  type?: string;
  device_id?: string;
}

export interface AlertsResponse {
  wazuh: boolean;
  alerts: Alert[];
}

export interface MeResponse {
  username: string;
}

// ---------------------------------------------------------------- Commandes à distance (contrat §8)

export type CommandStatus = 'pending' | 'delivered' | 'executed' | 'failed' | 'refused' | 'expired' | 'cancelled';

export interface RemoteCommand {
  id: string;
  device_id?: string;
  type: string;
  params?: Record<string, unknown>;
  signed?: boolean;
  status: CommandStatus | string;
  created_at?: string;
  created_by?: string;
  expires_at?: string;
  delivered_at?: string;
  result_at?: string;
  detail?: string;
}

export interface CommandsResponse {
  commands: RemoteCommand[];
}

// ---------------------------------------------------------------- Pistage (contrat §9)

export interface TrackingLevelInfo {
  key: string;
  name?: string;
  description?: string;
}

export interface TrackingTotals {
  queries: number;
  blocked?: number;
  allowed?: number;
}

export interface Publisher {
  key: string;
  name: string;
  queries: number;
  blocked?: number;
  allowed?: number;
  domains?: number;
  apps?: number;
  tx_bytes?: number;
  rx_bytes?: number;
}

export interface TrackingSummary {
  adguard: boolean;
  level?: string;
  levels?: TrackingLevelInfo[];
  totals?: TrackingTotals;
  publishers: Publisher[];
}

export type DomainStatus = 'blocked' | 'allowed' | 'mixed';
export type OverrideAction = 'block' | 'allow' | 'default';

export interface TrackingDomain {
  domain: string;
  publisher?: string;
  queries: number;
  blocked?: number;
  allowed?: number;
  status?: DomainStatus | string;
  reason?: string;
  override?: 'block' | 'allow';
  apps?: { package: string; count: number }[];
}

export interface TrackingDomainsResponse {
  domains: TrackingDomain[];
  next_cursor?: string;
}

export interface TrackingApp {
  package: string;
  label?: string;
  queries: number;
  blocked?: number;
  allowed?: number;
  tx_bytes?: number;
  rx_bytes?: number;
  top_domains?: { domain: string; count: number; status?: string }[];
}

export interface TrackingAppsResponse {
  apps: TrackingApp[];
}

export interface LevelResponse {
  level: string;
}

// ---------------------------------------------------------------- Profil de risque, usage, détections (contrat §11)

export type RiskLevel = 'low' | 'medium' | 'high';

/** `app.risk` : dernier profil de risque d'une application (contrat §11.2). */
export interface AppRisk {
  package: string;
  label?: string;
  version_code?: number;
  installer?: string;
  from_store?: boolean;
  /** 0 à 100 */
  score: number;
  /** `low`, `medium`, `high`, ou une valeur inconnue (repli : déduit du score) */
  level: string;
  /** codes de la liste fermée du §11.2 ; un code inconnu est affiché tel quel */
  reasons: string[];
  ts?: string;
}

export interface AppRiskResponse {
  ts?: string;
  apps: AppRisk[];
}

/** Ligne agrégée de `app.ops` : une application, une opération (contrat §11.2). */
export interface AppOpsRow {
  package: string;
  label?: string;
  op: string;
  count: number;
  background_count?: number;
  last_ts?: string;
}

export interface AppOpsResponse {
  from?: string;
  to?: string;
  rows: AppOpsRow[];
}

/** Détection calculée par le collecteur (contrat §11.3). */
export interface Detection {
  id: string;
  ts: string;
  type: string;
  package?: string;
  label?: string;
  /** 0 à 3, même échelle que `sev` des événements */
  severity: number;
  summary?: string;
  evidence: DataObject;
  window_from?: string;
  window_to?: string;
  device_id?: string;
}

export interface DetectionsResponse {
  detections: Detection[];
  next_cursor?: string;
}

import type { Posture } from '../api/types.ts';

export type Status = 'ok' | 'warn' | 'bad' | 'unknown';

export interface Finding {
  id: string;
  label: string;
  status: Status;
  value: string;
  detail?: string;
}

const yesNo = (b: boolean | undefined): string => (b === undefined ? 'unknown' : b ? 'yes' : 'no');

/** Labels of the `security.posture` fields (change history). */
export const POSTURE_LABELS: Record<string, string> = {
  security_patch: 'Security patch',
  patch_age_days: 'Patch age (days)',
  encrypted: 'Encrypted storage',
  lock_secure: 'Secure lock',
  adb_enabled: 'USB debugging (ADB)',
  adb_wifi_enabled: 'Wireless debugging',
  dev_options: 'Developer options',
  unknown_sources: 'Unknown sources',
  private_dns_mode: 'Private DNS mode',
  private_dns_host: 'Private DNS host',
  always_on_vpn: 'Always-on VPN',
  device_owner: 'Device Owner',
  verified_boot_state: 'Verified boot',
  user_ca_certs: 'User CA certificates',
  play_protect: 'Play Protect',
  usb_data_signaling: 'USB data signalling',
};

/** Evaluates the posture: each check gives a status and the list of points of attention. */
export function evaluatePosture(p: Posture | undefined): Finding[] {
  if (!p) return [];
  const out: Finding[] = [];
  const add = (f: Finding) => out.push(f);

  if (p.patch_age_days !== undefined) {
    const d = p.patch_age_days;
    add({
      id: 'patch',
      label: 'Security patch',
      status: d > 120 ? 'bad' : d > 60 ? 'warn' : 'ok',
      value: p.security_patch ?? `${d} d`,
      detail: `${d} days old`,
    });
  } else if (p.security_patch) {
    add({ id: 'patch', label: 'Security patch', status: 'unknown', value: p.security_patch });
  }
  if (p.encrypted !== undefined)
    add({ id: 'encrypted', label: 'Encrypted storage', status: p.encrypted ? 'ok' : 'bad', value: yesNo(p.encrypted) });
  if (p.lock_secure !== undefined)
    add({
      id: 'lock',
      label: 'Secure screen lock',
      status: p.lock_secure ? 'ok' : 'bad',
      value: yesNo(p.lock_secure),
    });
  if (p.verified_boot_state !== undefined)
    add({
      id: 'boot',
      label: 'Verified boot',
      status: p.verified_boot_state === 'green' ? 'ok' : p.verified_boot_state === 'yellow' ? 'warn' : 'bad',
      value: p.verified_boot_state,
    });
  if (p.device_owner !== undefined)
    add({
      id: 'do',
      label: 'Device Owner',
      status: p.device_owner ? 'ok' : 'warn',
      value: p.device_owner ? 'active' : 'inactive (degraded mode)',
    });
  if (p.adb_enabled !== undefined)
    add({ id: 'adb', label: 'USB debugging (ADB)', status: p.adb_enabled ? 'warn' : 'ok', value: p.adb_enabled ? 'enabled' : 'disabled' });
  if (p.adb_wifi_enabled !== undefined)
    add({
      id: 'adbwifi',
      label: 'Wireless debugging',
      status: p.adb_wifi_enabled ? 'bad' : 'ok',
      value: p.adb_wifi_enabled ? 'enabled' : 'disabled',
    });
  if (p.dev_options !== undefined)
    add({
      id: 'dev',
      label: 'Developer options',
      status: p.dev_options ? 'warn' : 'ok',
      value: p.dev_options ? 'enabled' : 'disabled',
    });
  if (p.unknown_sources !== undefined)
    add({
      id: 'unknown',
      label: 'Installation from unknown sources',
      status: p.unknown_sources ? 'warn' : 'ok',
      value: p.unknown_sources ? 'allowed for at least one app' : 'no',
    });
  if (p.private_dns_mode !== undefined) {
    const mode = p.private_dns_mode;
    add({
      id: 'dns',
      label: 'Private DNS',
      status: mode === 'hostname' ? 'ok' : mode === 'opportunistic' ? 'warn' : 'bad',
      value: mode === 'hostname' ? `enforced (${p.private_dns_host ?? 'unknown host'})` : mode,
    });
  }
  if (p.always_on_vpn !== undefined)
    add({
      id: 'vpn',
      label: 'Always-on VPN',
      status: 'unknown',
      value: typeof p.always_on_vpn === 'string' ? p.always_on_vpn : yesNo(p.always_on_vpn),
    });
  if (p.play_protect !== undefined)
    add({ id: 'pp', label: 'Play Protect', status: p.play_protect ? 'ok' : 'warn', value: p.play_protect ? 'active' : 'inactive' });
  if (p.user_ca_certs !== undefined) {
    const n = p.user_ca_certs.length;
    add({
      id: 'ca',
      label: 'CA certificates installed by the user',
      status: n === 0 ? 'ok' : 'bad',
      value: n === 0 ? 'none' : `${n} certificate${n > 1 ? 's' : ''}`,
      detail: n ? 'A user CA can allow TLS traffic to be intercepted.' : undefined,
    });
  }
  if (p.usb_data_signaling !== undefined)
    add({
      id: 'usb',
      label: 'USB data',
      status: p.usb_data_signaling ? 'warn' : 'ok',
      value: p.usb_data_signaling ? 'enabled' : 'disabled',
    });
  return out;
}

export function attentionPoints(findings: Finding[]): Finding[] {
  const rank: Record<Status, number> = { bad: 0, warn: 1, unknown: 2, ok: 3 };
  return findings.filter((f) => f.status === 'bad' || f.status === 'warn').sort((a, b) => rank[a.status] - rank[b.status]);
}

export function overallStatus(findings: Finding[]): Status {
  if (findings.length === 0) return 'unknown';
  if (findings.some((f) => f.status === 'bad')) return 'bad';
  if (findings.some((f) => f.status === 'warn')) return 'warn';
  return 'ok';
}

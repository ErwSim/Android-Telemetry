import type { Posture } from '../api/types.ts';

export type Status = 'ok' | 'warn' | 'bad' | 'unknown';

export interface Finding {
  id: string;
  label: string;
  status: Status;
  value: string;
  detail?: string;
}

const yesNo = (b: boolean | undefined): string => (b === undefined ? 'inconnu' : b ? 'oui' : 'non');

/** Libellés français des champs de `security.posture` (historique des changements). */
export const POSTURE_LABELS: Record<string, string> = {
  security_patch: 'Correctif de sécurité',
  patch_age_days: 'Ancienneté du correctif (jours)',
  encrypted: 'Stockage chiffré',
  lock_secure: 'Verrouillage sécurisé',
  adb_enabled: 'Débogage USB (ADB)',
  adb_wifi_enabled: 'Débogage sans fil',
  dev_options: 'Options pour les développeurs',
  unknown_sources: 'Sources inconnues',
  private_dns_mode: 'Mode DNS privé',
  private_dns_host: 'Hôte DNS privé',
  always_on_vpn: 'VPN permanent',
  device_owner: 'Device Owner',
  verified_boot_state: 'Démarrage vérifié',
  user_ca_certs: "Certificats d'AC utilisateur",
  play_protect: 'Play Protect',
  usb_data_signaling: 'Signalisation de données USB',
};

/** Évalue la posture : chaque contrôle donne un statut et la liste des points d'attention. */
export function evaluatePosture(p: Posture | undefined): Finding[] {
  if (!p) return [];
  const out: Finding[] = [];
  const add = (f: Finding) => out.push(f);

  if (p.patch_age_days !== undefined) {
    const d = p.patch_age_days;
    add({
      id: 'patch',
      label: 'Correctif de sécurité',
      status: d > 120 ? 'bad' : d > 60 ? 'warn' : 'ok',
      value: p.security_patch ?? `${d} j`,
      detail: `${d} jours d'ancienneté`,
    });
  } else if (p.security_patch) {
    add({ id: 'patch', label: 'Correctif de sécurité', status: 'unknown', value: p.security_patch });
  }
  if (p.encrypted !== undefined)
    add({ id: 'encrypted', label: 'Stockage chiffré', status: p.encrypted ? 'ok' : 'bad', value: yesNo(p.encrypted) });
  if (p.lock_secure !== undefined)
    add({
      id: 'lock',
      label: "Verrouillage d'écran sécurisé",
      status: p.lock_secure ? 'ok' : 'bad',
      value: yesNo(p.lock_secure),
    });
  if (p.verified_boot_state !== undefined)
    add({
      id: 'boot',
      label: 'Démarrage vérifié',
      status: p.verified_boot_state === 'green' ? 'ok' : p.verified_boot_state === 'yellow' ? 'warn' : 'bad',
      value: p.verified_boot_state,
    });
  if (p.device_owner !== undefined)
    add({
      id: 'do',
      label: 'Device Owner',
      status: p.device_owner ? 'ok' : 'warn',
      value: p.device_owner ? 'actif' : 'inactif (mode dégradé)',
    });
  if (p.adb_enabled !== undefined)
    add({ id: 'adb', label: 'Débogage USB (ADB)', status: p.adb_enabled ? 'warn' : 'ok', value: p.adb_enabled ? 'activé' : 'désactivé' });
  if (p.adb_wifi_enabled !== undefined)
    add({
      id: 'adbwifi',
      label: 'Débogage sans fil',
      status: p.adb_wifi_enabled ? 'bad' : 'ok',
      value: p.adb_wifi_enabled ? 'activé' : 'désactivé',
    });
  if (p.dev_options !== undefined)
    add({
      id: 'dev',
      label: 'Options pour les développeurs',
      status: p.dev_options ? 'warn' : 'ok',
      value: p.dev_options ? 'activées' : 'désactivées',
    });
  if (p.unknown_sources !== undefined)
    add({
      id: 'unknown',
      label: 'Installation de sources inconnues',
      status: p.unknown_sources ? 'warn' : 'ok',
      value: p.unknown_sources ? 'autorisée pour au moins une app' : 'non',
    });
  if (p.private_dns_mode !== undefined) {
    const mode = p.private_dns_mode;
    add({
      id: 'dns',
      label: 'DNS privé',
      status: mode === 'hostname' ? 'ok' : mode === 'opportunistic' ? 'warn' : 'bad',
      value: mode === 'hostname' ? `imposé (${p.private_dns_host ?? 'hôte inconnu'})` : mode,
    });
  }
  if (p.always_on_vpn !== undefined)
    add({
      id: 'vpn',
      label: 'VPN permanent',
      status: 'unknown',
      value: typeof p.always_on_vpn === 'string' ? p.always_on_vpn : yesNo(p.always_on_vpn),
    });
  if (p.play_protect !== undefined)
    add({ id: 'pp', label: 'Play Protect', status: p.play_protect ? 'ok' : 'warn', value: p.play_protect ? 'actif' : 'inactif' });
  if (p.user_ca_certs !== undefined) {
    const n = p.user_ca_certs.length;
    add({
      id: 'ca',
      label: "Certificats d'AC installés par l'utilisateur",
      status: n === 0 ? 'ok' : 'bad',
      value: n === 0 ? 'aucun' : `${n} certificat${n > 1 ? 's' : ''}`,
      detail: n ? 'Une AC utilisateur peut permettre l’interception du trafic TLS.' : undefined,
    });
  }
  if (p.usb_data_signaling !== undefined)
    add({
      id: 'usb',
      label: 'Données USB',
      status: p.usb_data_signaling ? 'warn' : 'ok',
      value: p.usb_data_signaling ? 'activées' : 'désactivées',
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

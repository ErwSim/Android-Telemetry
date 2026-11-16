// Gardes de l'agent (contrat §11.1, module :policy, Device Owner requis). Elles se règlent sur le téléphone,
// dans l'écran Politique de l'application : la console ne peut ni les activer ni les désactiver (le serveur ne
// commande jamais le téléphone). Ce fichier ne sert qu'à les rappeler.

export interface GuardInfo {
  key: string;
  label: string;
  effect: string;
}

export const GUARDS: readonly GuardInfo[] = [
  { key: 'sms', label: 'SMS', effect: "Refuse l'envoi de SMS à toutes les applications sauf une liste choisie (pré-remplie avec l'application SMS par défaut)." },
  { key: 'calls', label: 'Appels', effect: "Refuse de passer des appels (et, en option, de lire le journal d'appels) sauf à une liste choisie (le composeur par défaut)." },
  { key: 'accessibility', label: "Services d'accessibilité", effect: "Seuls les services d'accessibilité approuvés (et ceux du système) peuvent être activés." },
  { key: 'input_methods', label: 'Claviers', effect: 'Seuls les claviers approuvés (et ceux du système) peuvent être activés.' },
  {
    key: 'quarantine',
    label: 'Quarantaine',
    effect: "Toute application non système installée ensuite se voit refuser les permissions à risque (SMS, appels, contacts, micro, caméra, position en arrière-plan…) jusqu'à ce que vous la libériez.",
  },
];

export function guardInfo(key: string): GuardInfo | undefined {
  return GUARDS.find((g) => g.key === key);
}

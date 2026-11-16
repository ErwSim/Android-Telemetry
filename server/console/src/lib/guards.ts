// Agent guards (contract §11.1, :policy module, Device Owner required). They are set on the phone,
// in the application's Policy screen: the console can neither enable nor disable them (the server never
// commands the phone). This file only serves to describe them.

export interface GuardInfo {
  key: string;
  label: string;
  effect: string;
}

export const GUARDS: readonly GuardInfo[] = [
  { key: 'sms', label: 'SMS', effect: 'Refuses SMS sending to all applications except a chosen list (pre-filled with the default SMS app).' },
  { key: 'calls', label: 'Calls', effect: 'Refuses to place calls (and, optionally, to read the call log) except to a chosen list (the default dialer).' },
  { key: 'accessibility', label: 'Accessibility services', effect: 'Only approved accessibility services (and system ones) can be enabled.' },
  { key: 'input_methods', label: 'Keyboards', effect: 'Only approved keyboards (and system ones) can be enabled.' },
  {
    key: 'quarantine',
    label: 'Quarantine',
    effect: 'Any non-system application installed afterwards is denied risky permissions (SMS, calls, contacts, microphone, camera, background location...) until you release it.',
  },
];

export function guardInfo(key: string): GuardInfo | undefined {
  return GUARDS.find((g) => g.key === key);
}

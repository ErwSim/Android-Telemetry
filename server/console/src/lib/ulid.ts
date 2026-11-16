// ULID (26 caractères, alphabet de Crockford) généré dans le navigateur pour l'identifiant d'une commande.
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

/** 48 bits d'horodatage (ms) puis 80 bits aléatoires. `now` et `random` sont injectables pour les tests. */
export function ulid(now: number = Date.now(), random: (n: number) => Uint8Array = randomBytes): string {
  let t = Math.floor(now);
  let time = '';
  for (let i = 0; i < 10; i++) {
    time = ALPHABET.charAt(t % 32) + time;
    t = Math.floor(t / 32);
  }
  // 256 est un multiple de 32 : `& 31` garde une distribution uniforme.
  let rand = '';
  for (const b of random(16)) rand += ALPHABET.charAt(b & 31);
  return time + rand;
}

export const ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/;

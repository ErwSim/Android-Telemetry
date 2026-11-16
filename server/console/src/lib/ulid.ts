// ULID (26 characters, Crockford alphabet) generated in the browser for a command's identifier.
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

/** 48 bits of timestamp (ms) then 80 random bits. `now` and `random` can be injected for tests. */
export function ulid(now: number = Date.now(), random: (n: number) => Uint8Array = randomBytes): string {
  let t = Math.floor(now);
  let time = '';
  for (let i = 0; i < 10; i++) {
    time = ALPHABET.charAt(t % 32) + time;
    t = Math.floor(t / 32);
  }
  // 256 is a multiple of 32: `& 31` keeps a uniform distribution.
  let rand = '';
  for (const b of random(16)) rand += ALPHABET.charAt(b & 31);
  return time + rand;
}

export const ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/;

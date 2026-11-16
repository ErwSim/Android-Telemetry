import { describe, expect, it } from 'vitest';
import fixture from './fixtures/command-vectors.json';
import { buildVectors, seededRandom, FIXTURE_DEVICE, FIXTURE_NOW_MS, FIXTURE_SEED, type CommandVector } from './commandVectors.ts';
import { LIMITS } from './commands.ts';

// The versioned test set is replayed by the agent's Kotlin verifier and by the Go collector: if it changes
// here (payload serialisation, derivation, signature), those two must still accept it.
describe('hard signature cases shared with the Kotlin agent and the Go collector', () => {
  it('the console code reproduces the versioned test set byte for byte', async () => {
    const built = await buildVectors(FIXTURE_DEVICE, FIXTURE_NOW_MS, seededRandom(FIXTURE_SEED));
    // To regenerate it after an intended change: node scripts/command-vectors.ts > src/lib/fixtures/command-vectors.json
    expect(built).toEqual(fixture as CommandVector[]);
  }, 60_000);

  it('covers the intended cases', () => {
    const v = fixture as CommandVector[];
    expect(v.filter((x) => x.sig !== null).length).toBeGreaterThanOrEqual(9);
    expect(v.some((x) => x.code !== null && /[^\x20-\x7e]/.test(x.code))).toBe(true);
    expect(v.some((x) => x.payload.includes('\\n') && x.payload.includes('\\"') && x.payload.includes('🙂'))).toBe(true);
    expect(v.some((x) => x.expect.message?.length === LIMITS.messageMax)).toBe(true);
    // The payload does not escape non-ASCII characters: it is their UTF-8 bytes that are signed.
    expect(v.every((x) => !/\\u[0-9a-f]{4}/i.test(x.payload.replace('\\\\u0000', '')))).toBe(true);
  });
});

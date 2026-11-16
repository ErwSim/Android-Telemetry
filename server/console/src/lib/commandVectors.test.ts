import { describe, expect, it } from 'vitest';
import fixture from './fixtures/command-vectors.json';
import { buildVectors, seededRandom, FIXTURE_DEVICE, FIXTURE_NOW_MS, FIXTURE_SEED, type CommandVector } from './commandVectors.ts';
import { LIMITS } from './commands.ts';

// Le jeu d'essai versionné est rejoué par le vérificateur Kotlin de l'agent et par le collecteur Go : s'il change
// ici (sérialisation du payload, dérivation, signature), ces deux-là doivent encore l'accepter.
describe('cas difficiles de signature partagés avec l’agent Kotlin et le collecteur Go', () => {
  it('le code de la console reproduit le jeu d’essai versionné à l’octet près', async () => {
    const built = await buildVectors(FIXTURE_DEVICE, FIXTURE_NOW_MS, seededRandom(FIXTURE_SEED));
    // Pour le régénérer après un changement voulu : node scripts/command-vectors.ts > src/lib/fixtures/command-vectors.json
    expect(built).toEqual(fixture as CommandVector[]);
  }, 60_000);

  it('couvre les cas voulus', () => {
    const v = fixture as CommandVector[];
    expect(v.filter((x) => x.sig !== null).length).toBeGreaterThanOrEqual(9);
    expect(v.some((x) => x.code !== null && /[^\x20-\x7e]/.test(x.code))).toBe(true);
    expect(v.some((x) => x.payload.includes('\\n') && x.payload.includes('\\"') && x.payload.includes('🙂'))).toBe(true);
    expect(v.some((x) => x.expect.message?.length === LIMITS.messageMax)).toBe(true);
    // Le payload n'échappe pas les caractères non ASCII : ce sont leurs octets UTF-8 qui sont signés.
    expect(v.every((x) => !/\\u[0-9a-f]{4}/i.test(x.payload.replace('\\\\u0000', '')))).toBe(true);
  });
});

// Écrit sur la sortie standard les cas difficiles de signature (voir src/lib/commandVectors.ts), signés par le
// vrai code de la console :
//   node scripts/command-vectors.ts                      jeu d'essai versionné (src/lib/fixtures/command-vectors.json)
//   node scripts/command-vectors.ts <device_id>          pour un appareil réel, à l'heure courante (essai croisé)
import { buildVectors, seededRandom, FIXTURE_DEVICE, FIXTURE_NOW_MS, FIXTURE_SEED } from '../src/lib/commandVectors.ts';

const device = process.argv[2];
const vectors = device ? await buildVectors(device, Date.now()) : await buildVectors(FIXTURE_DEVICE, FIXTURE_NOW_MS, seededRandom(FIXTURE_SEED));
process.stdout.write(`${JSON.stringify(vectors, null, 2)}\n`);

// Writes to standard output the hard signature cases (see src/lib/commandVectors.ts), signed by the
// console's real code:
//   node scripts/command-vectors.ts                      versioned test set (src/lib/fixtures/command-vectors.json)
//   node scripts/command-vectors.ts <device_id>          for a real device, at the current time (cross-check)
import { buildVectors, seededRandom, FIXTURE_DEVICE, FIXTURE_NOW_MS, FIXTURE_SEED } from '../src/lib/commandVectors.ts';

const device = process.argv[2];
const vectors = device ? await buildVectors(device, Date.now()) : await buildVectors(FIXTURE_DEVICE, FIXTURE_NOW_MS, seededRandom(FIXTURE_SEED));
process.stdout.write(`${JSON.stringify(vectors, null, 2)}\n`);

# Status

Resume file for contributors: read it first, and update it at the end of every working session.

## Where things stand

Three feature sets are written end to end: version 1 (telemetry, anti-tracking policy, server), version 1.1 (remote
commands, Tracking page, notifications, location modes) and version 1.2 (protection against malware whatever its
vector). The server side has been run and tested for real; **the Android application has never run on a physical
device** (and no emulator-based test exists): it is verified by compilation, lint, JVM tests and cross tests of its
real code against the real collector.

| Part | Directory | State | Verified by execution |
|---|---|---|---|
| Architecture, contract | `docs/ARCHITECTURE.md`, `docs/contract/contract.md` | done | — |
| Platform research | `docs/research/` | done | web sources; "unverified" points are flagged in the files |
| Go collector | `server/collector/` | done, reviewed several times | `go vet`, `go test -race`, real runs with the simulator and its attack scenarios, Docker image |
| Web console | `server/console/` | done | typing, lint, 174 tests, Chromium walkthroughs against a mock server and against the real collector; real OSM tiles not loaded |
| Docker infrastructure | `infra/` | done | stack really started in internal TLS mode: mTLS, DoT, command stream, tracking against the real AdGuard, export → Wazuh without loss, all rule test cases green (`infra/wazuh/tests/run-tests.sh`) |
| Android agent and companion APK | `android/` | done, reviewed several times | `./gradlew lint test assembleDebug assembleRelease` green: 392 JVM tests (5 skipped: cross tests, run with the `WATCHPOST_CROSS_*` variables), APKs inspected |
| User guides | `README.md`, `docs/guides/01` to `08` | done | commands checked against the scripts; none run on a VPS or a phone |

## What each version brings

- **Version 1**: 21 collectors, offline buffer, mTLS upload, Device Owner policy (enforced private DNS, disabled
  packages, denied permissions, restrictions), ADB rescue, collector, console, Wazuh, AdGuard.
- **Version 1.1** (contract §8 to §10): remote commands (ring, vibrate, locate; lock and erase signed with a
  passphrase the server does not know; channel off by default); Tracking page driving AdGuard; notification companion
  APK; location modes; alert notifications; device renewal. The agent now has 25 collectors.
- **Version 1.2** (contract §11): capability guards (SMS, calls, accessibility, keyboards, quarantine), app risk
  profile, default roles, experimental counters of sensitive operations, server-side detections with muting, Wazuh
  rules and correlations.

## Review conclusions to keep in mind

- **Command signature**: it is worth something only with a high-entropy passphrase (five random words); the server
  serves the page where the passphrase is typed; a signed command stays executable until it expires. Remote erase
  must be enabled only after a trial on a sacrificial or fully backed-up device.
- **SMS sent without the user's knowledge**: the real protection is the **SMS guard**. Without the experimental
  `app_ops` counters, which have never been seen working and are probably unavailable on Android 16, this case
  produces **only one** detection, `detect.sms_permission`. An application accepted as the default SMS app is not
  blocked, only flagged. See `docs/guides/08-sms-and-malware.md`.
- **Risk profile**: an indicator of attention on declared capabilities, not a verdict (parental control, antivirus and
  automation come out "high"; a discreet store application can come out "low").
- **Detections**: the thresholds were tuned on a simulator written by the same people as the detections; false
  positives on a real phone are to be expected (a browser's encrypted DNS, a first photo backup, a long video call) and
  are handled by muting and by the `WATCHPOST_DETECT_*` variables.

## Never tested

- **All behaviour on a Samsung Galaxy phone**: Device Owner activation, permanent service, collectors, policy, guards,
  command channel, companion, ADB rescue. The roadmap is `docs/guides/06-on-device-checks.md` (checklist ordered by
  risk); the cautious order of trial is at the top of `docs/guides/03-phone.md`.
- **PowerShell scripts** (`android/scripts/*.ps1`): checked line by line, never run (PowerShell was not available
  where they were written).
- **The server in real conditions**: Let's Encrypt and the DNS-01 challenge, upstream DNS resolution, WireGuard,
  `update.sh`, SMTP with TLS and authentication, a real ntfy server, memory use under real load, ARM.

## Known limits and assumed choices

- Device Owner network logs: DNS and TCP `connect()` only, in batches (about 1 h 30); UDP/QUIC escape them.
- Camera and microphone: use is reported without the responsible application (experimental attribution, off by
  default).
- No local VPN, no Knox SDK (see `docs/ARCHITECTURE.md`).
- Nothing is collected before the first unlock following a reboot; the ADB rescue does not answer before then either.
- The system network and security logs turn on as soon as the Device Owner is activated (one switch per collector);
  Android then displays the network-monitoring notice.
- Remote ringing is silent if "Do Not Disturb" mutes alarms.
- Tracking page: bytes per publisher and blocked/allowed counters per application are estimates.
- Guards: they touch neither system applications nor the holder of the matching role; the keyboard and accessibility
  guards never turn off a service that is already active, and their real effect on One UI remains to be verified.
- Console account: whoever knows the user name can lock it out with repeated failures.
- The map uses the public OpenStreetMap tiles by default (`WATCHPOST_TILE_URL`).
- Device certificate expiries (2 years) are not notified: `infra/enroll.sh --list`.

## Development notes

- No emulator-based test exists, and Robolectric is not used: Android tests are pure JVM tests. Behaviour on a device
  is verified with the on-device checklist.
- The three cross tests of the `:app` module (`CrossServerTest`, `CrossCommandsTest`, `CrossDetectionsTest`) run the
  agent's real code against a real collector and are skipped unless their `WATCHPOST_CROSS_*` variables are set (see
  the header of each file and `docs/guides/07-development.md`).
- The signing key of the APKs is generated locally (`android/scripts/generate-keystore.*`), never versioned, and must
  be kept by whoever builds the APKs: it signs the agent and the companion, and no update is possible without it.
- Docker: container base images may need a mirror if the registry rate-limits (see `server/collector/README.md`).

## Next steps

1. Install the server (`docs/guides/01-server.md`), build the two APKs with your own keystore (`02-build-apk.md`),
   follow the cautious order of trial of the phone guide (`03-phone.md`), tick `06-on-device-checks.md` as you go and
   report the discrepancies.
2. Fix what the on-device trials reveal: this is where the remaining defects are. First: the SMS guard, the command
   channel in standby, and `adb shell dumpsys appops --history --op SEND_SMS`.
3. Further leads: `docs/guides/07-development.md` (unlock code before weakening a guard, system SMS rate limit,
   companion exclusion lists editable in the agent, local VPN).

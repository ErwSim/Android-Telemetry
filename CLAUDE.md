# Watchpost

Self-hosted security-telemetry and anti-tracking toolchain for a personal Android phone (Android 16+, developed
against Samsung One UI 8/9). A Device Owner agent app and an optional notification companion APK, a Go collector with
a web console, Wazuh as SIEM and AdGuard Home as private DNS, all deployed with Docker Compose.

The project language is English: code identifiers, user interface texts, documentation and commit messages.

## Read before working

1. `docs/STATUS.md`: what exists, what has been verified or not, known limits, next steps. **Update it at the end of
   every working session.**
2. `docs/ARCHITECTURE.md`: decisions, non-negotiable principles, components.
3. `docs/contract/contract.md`: event format and APIs. Any change starts with this file.
4. `docs/research/`: verified platform facts (Android/Samsung, Wazuh, AdGuard).
5. `docs/guides/`: user guides (server, APK, phone, rollback, operations, on-device checks, development, SMS and
   malware); `docs/guides/07-development.md` explains how to build, test and run everything locally.

## Directories

- `android/`: Watchpost Agent (Kotlin, Device Owner) and the Watchpost Notifications companion APK. See
  `android/README.md`.
- `server/collector/`: Go collector (ingestion, storage, console API, Wazuh export, CLI, simulator).
- `server/console/`: web console (React + Vite).
- `infra/`: Docker Compose (Caddy, collector, Wazuh, AdGuard Home, optional WireGuard), PKI, installation.

## Rules

- Non-negotiable principles of `docs/ARCHITECTURE.md`: no stealth; the server sends the phone only commands from a
  closed list (the sensitive ones signed with a passphrase it does not know), never configuration or policy; no
  Google dependency in the agent; third parties' private content reduced to the minimum; everything can be turned off
  and reversed.
- Never commit secrets (`.env`, keys, `.watchpost`, `.p12`, keystores): they are generated at installation.
- Say clearly what was actually run or tested and what was not.

# Sentinel Logs Guides

Microsoft Sentinel integration guides, KQL parsers, and syslog forwarding configurations for common security tools.

## Integrations

| Tool | Method | Status |
|---|---|---|
| [Nessus Professional](./nessus/) | Syslog → Sentinel | ✅ Available |
| [F5 BIG-IP / ASM](./f5/) | CEF/Syslog → Sentinel | 🔜 Coming soon |
| [Palo Alto PAN-OS](./paloalto/) | CEF/Syslog → Sentinel | 🔜 Coming soon |

## Structure

Each integration folder contains:
- `README.md` — full step-by-step guide
- `parser.kql` — KQL function to deploy in Sentinel
- `syslog-ng.conf` / `nxlog.conf` — forwarder configs (where applicable)

## Maintained by

Omar Abdulaziz

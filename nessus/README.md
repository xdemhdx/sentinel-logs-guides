# Nessus Operational Log Forwarding to Microsoft Sentinel via Syslog
### Customer Integration Guide

**Version:** 1.0  
**Date:** April 2026  
**Prepared by:** Omar Abdulaziz

---

## Table of Contents

1. [Introduction](#introduction)
2. [Why This Approach?](#why-this-approach)
3. [Syslog vs Azure Functions — When to Use Which](#syslog-vs-azure-functions)
4. [Prerequisites](#prerequisites)
5. [Architecture Overview](#architecture-overview)
6. [Linux Implementation](#linux-implementation)
7. [Windows Implementation](#windows-implementation)
8. [Microsoft Sentinel Configuration](#microsoft-sentinel-configuration)
9. [KQL Parser — NessusLogs](#kql-parser)
10. [Log Types & Key Fields](#log-types-and-key-fields)
11. [Example Queries](#example-queries)
12. [Validation Checklist](#validation-checklist)

---

## Introduction

This guide documents the integration of **Tenable Nessus Professional** operational logs into **Microsoft Sentinel** using a syslog forwarding approach. Rather than relying on Azure Functions or the Tenable.io REST API, this method leverages the native log files produced by the Nessus daemon and forwards them to Sentinel via a syslog pipeline.

The result is a lightweight, low-dependency integration that gives SOC analysts visibility into:

- **Who** is running scans, **when**, against **which targets**
- **Which plugins** were executed and their results
- **Web UI access** — logins, API calls, unauthorized attempts
- **Scanner health** — service starts/stops, errors, performance events

---

## Why This Approach?

Nessus writes rich operational logs to disk in real time. These logs contain scan lifecycle events, per-plugin execution records, web server access logs, and backend service activity — all of which are valuable for security monitoring.

Forwarding these via syslog to Sentinel is:

| Benefit | Detail |
|---|---|
| **No Azure Function needed** | Eliminates the cost, maintenance, and complexity of a serverless function pipeline |
| **No Tenable.io dependency** | Works with Nessus Professional on-prem — does not require a cloud Tenable account |
| **Real-time** | Logs are tailed and forwarded with sub-second latency |
| **Lightweight** | syslog-ng or NXLog is a single small process with minimal resource footprint |
| **Auditable** | Every scan action, login, and plugin execution is logged and searchable in Sentinel |
| **No API rate limits** | Unlike the Tenable REST API, log forwarding is not subject to polling limits |

---

## Syslog vs Azure Functions — When to Use Which

| Scenario | Use Syslog Forwarding | Use Azure Functions |
|---|---|---|
| Nessus Professional on-prem, no Tenable.io | ✅ | ❌ Not possible |
| Need vulnerability findings with CVE/CVSS in Sentinel | ❌ Limited | ✅ Best option |
| Air-gapped or restricted network environment | ✅ | ❌ |
| Monitoring scanner operational health | ✅ Best option | ❌ Not available |
| Detecting unauthorized scan launches or UI access | ✅ | ❌ |
| Full vulnerability management with asset inventory | ❌ | ✅ |
| Low budget / no Azure spend available | ✅ | ❌ Requires Azure infra |
| Tenable.io (cloud) customers | Optional | ✅ Preferred |

**Summary:** Use syslog forwarding when you need operational visibility into the scanner itself. Use Azure Functions when you need structured vulnerability and asset data in Sentinel. The two approaches are complementary — you can run both simultaneously.

---

## Prerequisites

### General
- Nessus Professional installed and licensed
- Microsoft Sentinel workspace deployed
- Log Analytics Agent (MMA) or **Azure Monitor Agent (AMA)** installed on the syslog forwarder host
- Syslog data connector enabled in Microsoft Sentinel
- Facility `local5` configured to be collected in the Sentinel Syslog connector settings

### Linux
- `syslog-ng` version 3.x or higher (or `rsyslog` as alternative)
- Outbound UDP/TCP port **514** open to the syslog forwarder IP
- Read access to Nessus log directory: `/opt/nessus/var/nessus/logs/`

### Windows
- **NXLog Community Edition** (free) or NXLog Enterprise
- Windows Event Log access or file-based log reading capability
- Outbound port **514** to the Log Analytics / AMA syslog forwarder
- Nessus log path: `C:\ProgramData\Tenable\Nessus\nessus\logs\`

---

## Architecture Overview

```
┌─────────────────────────────────┐
│         Nessus Scanner          │
│                                 │
│  /opt/nessus/var/nessus/logs/   │
│  ├── nessusd.messages           │
│  ├── backend.log                │
│  ├── www_server.log             │
│  └── nessuscli.log              │
└──────────────┬──────────────────┘
               │ file tail (follow-freq 1s)
               ▼
┌─────────────────────────────────┐
│     syslog-ng / NXLog           │
│  facility: local5               │
│  program-override: nessus       │
└──────────────┬──────────────────┘
               │ UDP/TCP 514
               ▼
┌─────────────────────────────────┐
│   Log Analytics / AMA Agent     │
│   (Syslog Data Connector)       │
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│     Microsoft Sentinel          │
│     Syslog table                │
│     NessusLogs (KQL parser)     │
└─────────────────────────────────┘
```

---

## Linux Implementation

### Step 1 — Install syslog-ng

```bash
sudo apt-get update && sudo apt-get install -y syslog-ng
```

### Step 2 — Create the Nessus forwarding config

Create the file `/etc/syslog-ng/conf.d/30-nessus-forward.conf`:

```
@version: 3.38

source s_nessus_messages {
    file("/opt/nessus/var/nessus/logs/nessusd.messages"
         follow-freq(1)
         flags(no-parse)
         program-override("nessus")
         default-facility(local5)
         default-priority(info));
};

source s_nessus_backend {
    file("/opt/nessus/var/nessus/logs/backend.log"
         follow-freq(1)
         flags(no-parse)
         program-override("nessus")
         default-facility(local5)
         default-priority(info));
};

source s_nessus_www {
    file("/opt/nessus/var/nessus/logs/www_server.log"
         follow-freq(1)
         flags(no-parse)
         program-override("nessus")
         default-facility(local5)
         default-priority(info));
};

source s_nessus_cli {
    file("/opt/nessus/var/nessus/logs/nessuscli.log"
         follow-freq(1)
         flags(no-parse)
         program-override("nessus")
         default-facility(local5)
         default-priority(info));
};

destination d_nessus_remote {
    network("<SYSLOG_FORWARDER_IP>"
            transport("udp")
            port(514));
};

log { source(s_nessus_messages); destination(d_nessus_remote); };
log { source(s_nessus_backend);  destination(d_nessus_remote); };
log { source(s_nessus_www);      destination(d_nessus_remote); };
log { source(s_nessus_cli);      destination(d_nessus_remote); };
```

> Replace `<SYSLOG_FORWARDER_IP>` with your Log Analytics / AMA agent IP.  
> Switch `transport("udp")` to `transport("tcp")` for reliable delivery on lossy networks.

### Step 3 — Restart syslog-ng

```bash
sudo systemctl restart syslog-ng
sudo systemctl status syslog-ng
```

### Step 4 — Verify logs are being read

```bash
sudo tail -f /opt/nessus/var/nessus/logs/nessusd.messages
```

---

## Windows Implementation

On Windows, Nessus logs are located at:

```
C:\ProgramData\Tenable\Nessus\nessus\logs\nessusd.messages
C:\ProgramData\Tenable\Nessus\nessus\logs\backend.log
C:\ProgramData\Tenable\Nessus\nessus\logs\www_server.log
C:\ProgramData\Tenable\Nessus\nessus\logs\nessuscli.log
```

### Step 1 — Install NXLog Community Edition

Download from: https://nxlog.co/downloads/nxlog-ce  
Install with default settings.

### Step 2 — Configure NXLog

Edit `C:\Program Files\nxlog\conf\nxlog.conf`, replacing the default content:

```
Moduledir C:\Program Files\nxlog\modules
CacheDir  C:\Program Files\nxlog\data
Logfile   C:\Program Files\nxlog\data\nxlog.log
PidFile   C:\Program Files\nxlog\data\nxlog.pid

<Extension syslog>
    Module  xm_syslog
</Extension>

<Input nessus_messages>
    Module      im_file
    File        "C:\\ProgramData\\Tenable\\Nessus\\nessus\\logs\\nessusd.messages"
    SavePos     TRUE
    ReadFromLast TRUE
    <Exec>
        $Hostname   = hostname();
        $Facility   = "local5";
        $Severity   = "info";
        $Program    = "nessus";
        to_syslog_bsd();
    </Exec>
</Input>

<Input nessus_backend>
    Module      im_file
    File        "C:\\ProgramData\\Tenable\\Nessus\\nessus\\logs\\backend.log"
    SavePos     TRUE
    ReadFromLast TRUE
    <Exec>
        $Hostname   = hostname();
        $Facility   = "local5";
        $Severity   = "info";
        $Program    = "nessus";
        to_syslog_bsd();
    </Exec>
</Input>

<Input nessus_www>
    Module      im_file
    File        "C:\\ProgramData\\Tenable\\Nessus\\nessus\\logs\\www_server.log"
    SavePos     TRUE
    ReadFromLast TRUE
    <Exec>
        $Hostname   = hostname();
        $Facility   = "local5";
        $Severity   = "info";
        $Program    = "nessus";
        to_syslog_bsd();
    </Exec>
</Input>

<Input nessus_cli>
    Module      im_file
    File        "C:\\ProgramData\\Tenable\\Nessus\\nessus\\logs\\nessuscli.log"
    SavePos     TRUE
    ReadFromLast TRUE
    <Exec>
        $Hostname   = hostname();
        $Facility   = "local5";
        $Severity   = "info";
        $Program    = "nessus";
        to_syslog_bsd();
    </Exec>
</Input>

<Output syslog_out>
    Module      om_udp
    Host        <SYSLOG_FORWARDER_IP>
    Port        514
    <Exec>to_syslog_bsd();</Exec>
</Output>

<Route nessus_route>
    Path nessus_messages, nessus_backend, nessus_www, nessus_cli => syslog_out
</Route>
```

> Replace `<SYSLOG_FORWARDER_IP>` with your Log Analytics / AMA agent IP.  
> Change `om_udp` to `om_tcp` for TCP transport.

### Step 3 — Start NXLog service

```powershell
Start-Service nxlog
Set-Service nxlog -StartupType Automatic
Get-Service nxlog
```

### Step 4 — Verify

```powershell
Get-Content "C:\ProgramData\Tenable\Nessus\nessus\logs\nessusd.messages" -Tail 20 -Wait
```

---

## Microsoft Sentinel Configuration

### Step 1 — Enable Syslog Data Connector

1. Go to **Microsoft Sentinel → Data connectors**
2. Search for **Syslog** → Open connector page
3. Click **Open connector page → Install agent** (if not already installed)
4. Under **Configure the logs to be collected**, add facility **`local5`**
5. Save

### Step 2 — Verify data is arriving

In Sentinel Log Analytics, run:

```kql
Syslog
| where ProcessName == "nessus" and Facility == "local5"
| take 10
```

You should see raw log lines within 5–10 minutes of the first log event.

### Step 3 — Deploy the NessusLogs parser

In Sentinel → **Logs**, open a new query window and run the full parser block below to save it as a workspace function with alias `NessusLogs`.

---

## KQL Parser

Save the following as a **workspace function** with alias `NessusLogs` in your Sentinel workspace:

```kql
Syslog
| where ProcessName == "nessus" and Facility == "local5"
| extend LogType = case(
    SyslogMessage matches regex @'^\[\w{3} \w{3}',                                         "ScanActivity",
    SyslogMessage matches regex @'^\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}',               "BackendLog",
    SyslogMessage matches regex @'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',                  "WebAccess",
    "DaemonLog"
)
// --- ScanActivity fields (nessusd.messages) ---
| extend ScanUser        = extract(@'\[user=([^\]]+)\]', 1, SyslogMessage)
| extend ScanName        = extract(@'\[name=([^\]]+)\]', 1, SyslogMessage)
| extend ScanID          = extract(@'\[scan=([^\]]+)\]', 1, SyslogMessage)
| extend TargetIP        = extract(@'\[target=([^\]]+)\]', 1, SyslogMessage)
| extend PluginFile      = extract(@'\[plugin=([^\]]+)\]', 1, SyslogMessage)
| extend PluginID        = extract(@'\[plugin_id=([^\]]+)\]', 1, SyslogMessage)
| extend ScanDuration    = toreal(extract(@'\[duration=([0-9.]+)\]', 1, SyslogMessage))
| extend EventStatus     = trim(' ', extract(@' : (.+)$', 1, SyslogMessage))
| extend HostsUp         = toint(extract(@'Finished: (\d+) of', 1, EventStatus))
| extend HostsTotal      = toint(extract(@'of (\d+) hosts', 1, EventStatus))
| extend HostsDead       = toint(extract(@'(\d+) dead', 1, EventStatus))
| extend HostsTimeout    = toint(extract(@'(\d+) timeout', 1, EventStatus))
| extend HostsAborted    = toint(extract(@'(\d+) aborted', 1, EventStatus))
// --- BackendLog fields (backend.log) ---
| extend BackendLogLevel  = iif(LogType == "BackendLog", extract(@'^\[.*?\] \[(\w+)\]', 1, SyslogMessage), "")
| extend BackendService   = iif(LogType == "BackendLog", extract(@'^\[.*?\] \[\w+\] \[([^\]]+)\]', 1, SyslogMessage), "")
| extend BackendMessage   = iif(LogType == "BackendLog", trim(' ', extract(@'^\[.*?\] \[\w+\] (?:\[[^\]]+\] )?(.+)$', 1, SyslogMessage)), "")
| extend BackendUsername  = extract(@'username=([^,\] ]+)', 1, SyslogMessage)
| extend BackendSourceIP  = extract(@'from ip: (\S+)', 1, SyslogMessage)
| extend BackendScanName  = extract(@"Started scan '([^']+)'", 1, SyslogMessage)
| extend BackendScanID    = extract(@"as '([a-f0-9-]+)'", 1, SyslogMessage)
// --- WebAccess fields (www_server.log) ---
| extend WebSrcIP        = iif(LogType == "WebAccess", extract(@'^(\S+)', 1, SyslogMessage), "")
| extend WebMethod       = iif(LogType == "WebAccess", extract(@'"(GET|POST|PUT|DELETE|PATCH|HEAD) ', 1, SyslogMessage), "")
| extend WebUriPath      = iif(LogType == "WebAccess", extract(@'"(?:GET|POST|PUT|DELETE|PATCH|HEAD) ([^\s"]+)', 1, SyslogMessage), "")
| extend WebStatusCode   = iif(LogType == "WebAccess", toint(extract(@'" (\d{3}) ', 1, SyslogMessage)), int(null))
| extend WebUserAgent    = iif(LogType == "WebAccess", extract(@'"((?:Mozilla|curl|python|Go-http)[^"]*)"[^"]*$', 1, SyslogMessage), "")
| extend WebElapsedSec   = iif(LogType == "WebAccess", toreal(extract(@'Elapsed=([0-9.]+)', 1, SyslogMessage)), real(null))
| project
    TimeGenerated,
    Computer,
    LogType,
    ScanUser, ScanName, ScanID, TargetIP,
    PluginFile, PluginID, ScanDuration, EventStatus,
    HostsUp, HostsTotal, HostsDead, HostsTimeout, HostsAborted,
    BackendLogLevel, BackendService, BackendMessage,
    BackendUsername, BackendSourceIP, BackendScanName, BackendScanID,
    WebSrcIP, WebMethod, WebUriPath, WebStatusCode, WebUserAgent, WebElapsedSec,
    SyslogMessage
```

**To save as a function in Sentinel:**
1. Open **Sentinel → Logs**
2. Paste the query above
3. Click **Save → Save as function**
4. Function name: `NessusLogs`
5. Legacy category: `NessusOperational`
6. Save

---

## Log Types and Key Fields

### LogType: `ScanActivity`
**Source file:** `nessusd.messages`  
**Description:** Per-plugin scan execution — every plugin launched, finished, skipped, or errored against every target.

| Field | Type | Description |
|---|---|---|
| `ScanUser` | string | Nessus user who launched the scan |
| `ScanName` | string | Human-readable scan name |
| `ScanID` | string | Unique scan UUID |
| `TargetIP` | string | Target host IP address |
| `PluginFile` | string | Plugin filename (.nasl / .nbin) |
| `PluginID` | string | Numeric Nessus plugin ID |
| `ScanDuration` | real | Plugin execution time in seconds |
| `EventStatus` | string | Launching / Finished / Not launching / Finalizing |
| `HostsUp` | int | Live hosts found (scan summary line only) |
| `HostsTotal` | int | Total hosts scanned |
| `HostsDead` | int | Hosts that did not respond |
| `HostsTimeout` | int | Hosts that timed out |
| `HostsAborted` | int | Hosts where scan was aborted |

---

### LogType: `BackendLog`
**Source file:** `backend.log`  
**Description:** Backend service events — logins, scan starts/completions, service health, errors.

| Field | Type | Description |
|---|---|---|
| `BackendLogLevel` | string | info / error / warning / performance |
| `BackendService` | string | Internal service name (e.g. http, globaldb, cleanup) |
| `BackendMessage` | string | Full log message text |
| `BackendUsername` | string | Authenticated user (logins and API calls) |
| `BackendSourceIP` | string | Source IP of the request |
| `BackendScanName` | string | Name of scan that was started |
| `BackendScanID` | string | UUID of scan that was started |

---

### LogType: `WebAccess`
**Source file:** `www_server.log`  
**Description:** HTTP access log for the Nessus web UI and REST API — every request made to port 8834.

| Field | Type | Description |
|---|---|---|
| `WebSrcIP` | string | Client IP address |
| `WebMethod` | string | HTTP method (GET, POST, PUT, DELETE) |
| `WebUriPath` | string | Requested URI path and query string |
| `WebStatusCode` | int | HTTP response code (200, 403, 404, 500…) |
| `WebUserAgent` | string | Client user agent string |
| `WebElapsedSec` | real | Request processing time in seconds |

---

### LogType: `DaemonLog`
**Source file:** `nessusd.messages` (non-scan entries)  
**Description:** Raw daemon messages that do not match the other patterns — startup banners, configuration notices, system messages.

| Field | Type | Description |
|---|---|---|
| `SyslogMessage` | string | Raw log line (use for further parsing if needed) |

---

## Example Queries

### All Nessus logs
```kql
NessusLogs
| take 50
```

### Web UI access only
```kql
NessusLogs
| where LogType == "WebAccess"
```

### Unauthorized / failed web requests
```kql
NessusLogs
| where LogType == "WebAccess" and WebStatusCode in (401, 403, 404, 500)
| project TimeGenerated, WebSrcIP, WebMethod, WebUriPath, WebStatusCode
```

### All scan activity for a specific scan
```kql
NessusLogs
| where LogType == "ScanActivity" and ScanName == "Clawbot"
| project TimeGenerated, TargetIP, PluginID, PluginFile, EventStatus, ScanDuration
```

### Scan summary — completed scans with host counts
```kql
NessusLogs
| where LogType == "ScanActivity" and EventStatus startswith "Finished:"
| project TimeGenerated, ScanUser, ScanName, ScanID, HostsUp, HostsTotal, HostsDead, ScanDuration
```

### All logins to Nessus UI
```kql
NessusLogs
| where LogType == "BackendLog" and BackendMessage has "successful login"
| project TimeGenerated, BackendUsername, BackendSourceIP
```

### Backend errors
```kql
NessusLogs
| where LogType == "BackendLog" and BackendLogLevel == "error"
| project TimeGenerated, BackendService, BackendMessage
```

### Plugins that were not launched (skipped)
```kql
NessusLogs
| where LogType == "ScanActivity" and EventStatus startswith "Not launching"
| summarize count() by EventStatus
| order by count_ desc
```

### Scan activity timeline
```kql
NessusLogs
| where LogType == "ScanActivity" and isnotempty(ScanName)
| summarize PluginsRun=countif(EventStatus == "Finished"), 
            PluginsSkipped=countif(EventStatus startswith "Not launching")
  by ScanName, ScanUser, bin(TimeGenerated, 1h)
| order by TimeGenerated desc
```

---

## Validation Checklist

Use this checklist to confirm the integration is working end-to-end:

- [ ] Nessus service is running (`systemctl status nessusd` / `Get-Service "Tenable Nessus"`)
- [ ] Log files exist and are being updated in `/opt/nessus/var/nessus/logs/` (Linux) or `C:\ProgramData\Tenable\Nessus\nessus\logs\` (Windows)
- [ ] syslog-ng / NXLog service is running and showing no errors
- [ ] Port 514 is open outbound to the syslog forwarder IP
- [ ] `Syslog` table in Sentinel shows records with `ProcessName == "nessus"` and `Facility == "local5"`
- [ ] `NessusLogs` function is saved in the workspace and callable
- [ ] `NessusLogs | summarize count() by LogType` returns all three log types
- [ ] A test scan in Nessus produces new `ScanActivity` records within 60 seconds
- [ ] A login to the Nessus UI produces a new `BackendLog` record with `BackendUsername` populated

---

*Community guide by Omar Abdulaziz.*

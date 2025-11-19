# Quick Reference - Categorized Report API

## Endpoint
```
GET /api/v1/scans/{scan_id}/report/categorized
```

## What Gets Tested?

| Vulnerability | BASIC | FULL | Type |
|--------------|-------|------|------|
| SQL Injection | ❌ | ✅ | Active |
| XSS | ❌ | ✅ | Active |
| Security Headers | ✅ | ✅ | Passive |
| Open Redirects | ✅ | ✅ | Passive |

## Status Values

| Status | Meaning |
|--------|---------|
| `passed` | No high/medium risk issues found ✅ |
| `failed` | High/medium risk issues found ❌ |
| `not_tested` | Test requires FULL scan ⏭️ |

## BASIC Scan Response
```json
{
  "overallStatus": { "passed": true },
  "vulnerabilityTests": {
    "sqli": { "status": "not_tested" },      // ❌
    "xss": { "status": "not_tested" },       // ❌
    "headers": { "status": "passed" },       // ✅
    "redirects": { "status": "passed" }      // ✅
  }
}
```

## FULL Scan Response
```json
{
  "overallStatus": { "passed": true },
  "vulnerabilityTests": {
    "sqli": { "status": "passed" },          // ✅
    "xss": { "status": "passed" },           // ✅
    "headers": { "status": "passed" },       // ✅
    "redirects": { "status": "passed" }      // ✅
  }
}
```

## Key Points
- **BASIC = Passive only** (Headers, Redirects)
- **FULL = Passive + Active** (All 4 tests)
- Active tests (SQLi, XSS) require domain verification
- Passive tests are safe to run on any site

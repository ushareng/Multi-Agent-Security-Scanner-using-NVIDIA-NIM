# Code Audit Report
**Generated:** 2026-03-01T16:30:24.607750

## Executive Summary
| Metric | Value |
|--------|-------|
| Files Scanned | 4 |
| Raw Candidates | 33 |
| False Positives Eliminated | 32 |
| Confirmed Findings | 1 |
| With Working PoC | 0 |
| Vulnerable Dependencies | 14 |

## Severity Breakdown
| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 0 |
| 🟡 MEDIUM | 1 |
| 🟢 LOW | 0 |

---

## Confirmed Findings

### 1. 🟡 Insecure Randomness
**File:** `app/static/loader.js` | **Location:** line 58
**Severity:** MEDIUM | **CWE:** CWE-338 | **PoC:** ⚠️ SANDBOX_ERROR

**Reasoning:**
> Math.random() is not cryptographically secure


**Vulnerable Code:**
```
K.f.repeat=String.prototype.repeat?function(b,c){return b.repeat(c)}:function(b,c){return Array(c+1).join(b)};K.f.Ds=function(b,c,d){b=K.P(d)?b.toFixed(d):String(b);d=b.indexOf(".");-1==d&&(d=b.length);return K.f.repeat("0",Math.max(0,c-d))+b};K.f.Mk=function(b){return null==b?"":String(b)};K.f.Pp=f...
```

**Remediation:**
```
  "Remediation": {
    "Code-Snippet": "K.f.ir = function() {
      return crypto.getRandomValues(new Uint32Array(1))[0].toString(36) +
             crypto.getRandomValues(new Uint32Array(1))[0].toString(36);
    }",
    "Explanation": "Replace Math.random() with crypto.getRandomValues() to generate cryptographically secure random numbers."
  },
  "References": [
    {
      "Title": "OWASP - Insecure Randomness",
      "Link": "https://owasp.org/www-project-top-ten/2017/A9_2017-Insecure_Domains_and_Technologies.html"
    },
    {
      "Title": "NIST - Random Number Generation",
      "Link":
```

---

## Vulnerable Dependencies

| Package | CVE | Severity | Summary |
|---------|-----|----------|---------|
| certifi | GHSA-xqr8-7jwr-rhp7 | HIGH | Removal of e-Tugra root certificate |
| certifi | PYSEC-2023-135 | UNKNOWN |  |
| Flask | GHSA-562c-5r94-xh97 | HIGH | Flask is vulnerable to Denial of Service via incorrect encoding of JSON data |
| Flask | GHSA-5wv5-4vpf-pj6m | HIGH | Pallets Project Flask is vulnerable to Denial of Service via Unexpected memory u |
| Flask | GHSA-68rp-wp8r-4726 | LOW | Flask session does not add `Vary: Cookie` header when accessed in some ways |
| gevent | GHSA-x7m3-jprg-wc5g | CRITICAL | Gevent allows remote attacker to escalate privileges |
| gevent | PYSEC-2023-177 | UNKNOWN |  |
| idna | GHSA-jjg7-2v4v-x38h | MODERATE | Internationalized Domain Names in Applications (IDNA) vulnerable to denial of se |
| idna | PYSEC-2024-60 | UNKNOWN |  |
| Jinja2 | GHSA-462w-v97r-4m45 | HIGH | Jinja2 sandbox escape via string formatting |
| Jinja2 | GHSA-cpwx-vrp4-4pq7 | MODERATE | Jinja2 vulnerable to sandbox breakout through attr filter selecting format metho |
| Jinja2 | GHSA-g3rq-g295-4j3m | MODERATE | Regular Expression Denial of Service (ReDoS) in Jinja2 |
| lxml | GHSA-55x5-fj6c-h6m8 | MODERATE | lxml's HTML Cleaner allows crafted and SVG embedded scripts to pass through |
| lxml | GHSA-jq4v-f5q6-mjqq | MODERATE | lxml vulnerable to Cross-Site Scripting  |
| lxml | GHSA-pgww-xf46-h92r | MODERATE | lxml vulnerable to Cross-site Scripting |
| PyJWT | GHSA-ffqj-6fqr-9h24 | HIGH | Key confusion through non-blocklisted public key formats |
| PyJWT | PYSEC-2022-202 | UNKNOWN |  |
| python-docx | GHSA-34wj-p5jm-2p96 | HIGH | Improper Restriction of XML External Entity Reference in python-docx |
| python-docx | PYSEC-2016-21 | UNKNOWN |  |
| PyYAML | GHSA-8q59-q68h-6hv4 | CRITICAL | Improper Input Validation in PyYAML |
| PyYAML | GHSA-rprw-h62v-c2w7 | CRITICAL | PyYAML insecurely deserializes YAML strings leading to arbitrary code execution |
| PyYAML | PYSEC-2018-49 | UNKNOWN |  |
| requests | GHSA-9hjg-9r4m-mvj7 | MODERATE | Requests vulnerable to .netrc credentials leak via malicious URLs |
| requests | GHSA-9wx4-h78v-vm56 | MODERATE | Requests `Session` object does not verify requests after making first request wi |
| requests | GHSA-j8r2-6x86-q33q | MODERATE | Unintended leak of Proxy-Authorization header in requests |
| SQLAlchemy | GHSA-38fc-9xqv-7f7q | CRITICAL | SQLAlchemy is vulnerable to SQL Injection via group_by parameter  |
| SQLAlchemy | GHSA-887w-45rq-vxgf | CRITICAL | SQLAlchemy vulnerable to SQL Injection via order_by parameter |
| SQLAlchemy | PYSEC-2019-123 | UNKNOWN |  |
| tornado | GHSA-753j-mpmx-qq6g | MODERATE | Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') |
| tornado | GHSA-7cx3-6m66-7c5m | HIGH | Tornado vulnerable to excessive logging caused by malformed multipart form data |
| tornado | GHSA-8w49-h785-mj3c | HIGH | Tornado has an HTTP cookie parsing DoS vulnerability |
| urllib3 | GHSA-2xpw-w6gg-jr37 | HIGH | urllib3 streaming API improperly handles highly compressed data |
| urllib3 | GHSA-34jh-p97f-mpxf | MODERATE | urllib3's Proxy-Authorization request header isn't stripped during cross-origin  |
| urllib3 | GHSA-g4mx-q9vg-27p4 | MODERATE | urllib3's request body not stripped after redirect from 303 status changes reque |
| Werkzeug | GHSA-29vq-49wr-vm6x | MODERATE |  Werkzeug safe_join() allows Windows special device names |
| Werkzeug | GHSA-2g68-c3qc-8985 | HIGH | Werkzeug debugger vulnerable to remote execution when interacting with attacker  |
| Werkzeug | GHSA-87hc-h4r5-73f7 | MODERATE |  Werkzeug safe_join() allows Windows special device names with compound extensio |

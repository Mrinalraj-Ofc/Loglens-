# 🔍 LogLens — Simplified Security Log Analysis

> *"Web server logs are the black box of internet traffic — they contain evidence of every attack. LogLens makes that evidence readable."*

A full-stack SIEM-lite (Security Information and Event Management) internship project demonstrating **streaming log parsing**, **regex-based threat detection**, **behavioral analysis**, and **data visualisation** using Node.js and React.

---

## Table of Contents

1. [Case Study — Why Log Analysis Matters](#1-case-study)
2. [System Architecture](#2-system-architecture)
3. [Phase 1 — The Parser Engine](#3-phase-1--the-parser-engine)
4. [Phase 2 — The Threat Detection Engine](#4-phase-2--the-threat-detection-engine)
5. [Phase 3 — Behavioral Analysis](#5-phase-3--behavioral-analysis)
6. [Phase 4 — The Job Queue Pattern](#6-phase-4--the-job-queue-pattern)
7. [The Signature Database](#7-the-signature-database)
8. [Performance: Streaming vs Loading](#8-performance-streaming-vs-loading)
9. [Getting Started](#9-getting-started)
10. [Project Structure](#10-project-structure)
11. [Attack Vector Coverage](#11-attack-vector-coverage)

---

## 1. Case Study

### The Problem

A single day of traffic on a production web server generates millions of log lines. Hidden inside those lines is evidence of every attack attempt:

```
203.0.113.45 - - [15/Jan/2024:08:02:02 +0000] "GET /login.php?user=admin'%20OR%201=1-- HTTP/1.1" 200 891
198.51.100.7 - - [15/Jan/2024:08:02:03 +0000] "GET /products?id=1%20UNION%20SELECT%20table_name,2,3%20FROM%20information_schema.tables-- HTTP/1.1" 500 233
192.0.2.88  - - [15/Jan/2024:08:03:01 +0000] "POST /login HTTP/1.1" 401 230
192.0.2.88  - - [15/Jan/2024:08:03:02 +0000] "POST /login HTTP/1.1" 401 230
... (×50 more)
```

A human analyst cannot read 2 million lines a day. Expensive commercial SIEM tools (Splunk, IBM QRadar) cost $50,000–$500,000 per year. LogLens is the educational implementation: parse, detect, and visualise — free, open-source, understandable.

### What LogLens Detects

| Attack Type | Detection Method | Example |
|-------------|-----------------|---------|
| SQL Injection | Regex pattern matching | `UNION SELECT`, `OR 1=1`, `SLEEP()` |
| XSS | Regex pattern matching | `<script>`, `onerror=`, `javascript:` |
| Path Traversal | Regex pattern matching | `../../etc/passwd`, `%2e%2e%2f` |
| Command Injection | Regex pattern matching | `; ls -la`, `| cat /etc/passwd` |
| Brute Force | Behavioral (frequency) | 15 × 401 from same IP in 5 min |
| Scanner | User-agent matching | Nikto, sqlmap, dirbuster |

### Real-World Context

Commercial SIEMs like Splunk use these same fundamental techniques:
- **Regex-based signature matching** for known attack patterns
- **Statistical behavioral analysis** for anomaly detection  
- **IP reputation** via GeoIP enrichment
- **Timeline correlation** to see attack progression

LogLens implements the same pipeline at internship scale.

---

## 2. System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        UPLOAD                                    │
│  User uploads access.log → POST /api/upload                     │
│  Server returns immediately: { jobId: "abc-123" }               │
│  (File too large to process synchronously — use job queue)      │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    JOB QUEUE (jobs.js)                          │
│                                                                  │
│  Job stored: { id, status: 'queued', progress: 0 }             │
│  Processing starts asynchronously (setImmediate)                │
└────────────────────────┬────────────────────────────────────────┘
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
┌─────────────────────┐   ┌─────────────────────────────────────┐
│   PARSER (parser.js)│   │   Frontend polls every 1.5 seconds  │
│                     │   │   GET /api/jobs/abc-123              │
│  createReadStream() │   │   ← { status: 'running', progress: 42 }
│  readline interface │   └─────────────────────────────────────┘
│  CLF regex per line │
│  → ParsedLine[]     │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│              DETECTOR (detector.js)                              │
│                                                                  │
│  Per-line:   detectSignatureThreats(line)                       │
│              → tests path + query + userAgent against           │
│                30 compiled regex patterns                        │
│                                                                  │
│  Cross-line: BehavioralAnalyzer.ingest(line) for every line    │
│              BehavioralAnalyzer.analyze() after all lines       │
│              → brute force, scanning, DoS, credential stuffing  │
└─────────┬───────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│              GEOIP ENRICHMENT (geoip.js)                        │
│                                                                  │
│  Top 10 attacker IPs → ip-api.com → country, city, ISP, proxy  │
│  Cached 24 hours. Rate-limited to 45 req/min.                  │
└─────────┬───────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│              REPORT BUILDER (detector.js:buildReport)           │
│                                                                  │
│  - Summary stats (total lines, threats, unique IPs)            │
│  - Top attackers table                                          │
│  - Attack type distribution                                      │
│  - Timeline: attacks per hour                                   │
│  - Status code breakdown                                         │
│  - Behavioral findings                                           │
│  - First 500 flagged lines with matched signatures              │
└─────────┬───────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│              STORAGE (db.js) + FRONTEND RENDER                  │
│                                                                  │
│  Report saved to SQLite as JSON blob                            │
│  Frontend: GET /api/jobs/abc-123/report                         │
│  → React renders all Recharts visualisations                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Phase 1 — The Parser Engine

### Apache/Nginx Common Log Format (CLF)

Both Apache and Nginx default to this format:

```
127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
─────────   ─────  ───────────────────────────   ────────────────────────────  ───  ────
   IP       user        timestamp                      request line            code  size
```

**Combined Log Format** (more common — adds Referer + User-Agent):
```
127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326 "http://referer.com" "Mozilla/5.0..."
```

### The Parsing Regex

```javascript
const CLF_REGEX = /^(?<ip>\S+)\s+(?<ident>\S+)\s+(?<user>\S+)\s+\[(?<timestamp>[^\]]+)\]\s+"(?<method>\S+)\s+(?<path>\S+)\s+(?<protocol>[^"]+)"\s+(?<status>\d{3})\s+(?<size>\S+)(?:\s+"(?<referer>[^"]*)"\s+"(?<useragent>[^"]*)")?/;
```

Breaking it down:
- `(?<ip>\S+)` — capture group named "ip": one or more non-space chars
- `\[(?<timestamp>[^\]]+)\]` — timestamp between square brackets
- `"(?<method>\S+)\s+(?<path>\S+)\s+(?<protocol>[^"]+)"` — request line in quotes
- `(?<status>\d{3})` — exactly 3 digits for HTTP status code
- The `(?:...)?` at the end is optional — makes Combined Format fields optional

Named capture groups (`?<name>`) make the code readable: `match.groups.ip` vs `match[1]`.

### URL Decoding for Evasion

Attackers encode their payloads to bypass simple string matching:

```
Raw:          ../../etc/passwd
URL-encoded:  %2e%2e%2fetc%2fpasswd
Double:       %252e%252e%252fetc%252fpasswd
```

LogLens decodes up to 3 levels before matching:

```javascript
function decodeURIComponentSafe(str) {
  let decoded = str;
  for (let i = 0; i < 3; i++) {
    const next = decodeURIComponent(decoded);
    if (next === decoded) break;   // no more encodings
    decoded = next;
  }
  return decoded;
}
```

---

## 4. Phase 2 — The Threat Detection Engine

### Signature Matching

Each log line is tested against 30 pre-compiled regular expressions from `signatures.json`.

```javascript
// Pre-compile at startup — compilation is expensive, matching is fast
const COMPILED_SIGS = signatures.flatMap(([type, patterns]) =>
  patterns.map(sig => ({
    ...sig,
    type,
    regex: new RegExp(sig.pattern, 'i'),  // compiled once
  }))
);

// Per-line matching — O(n × s) where n=lines, s=signatures
function detectSignatureThreats(line) {
  for (const sig of COMPILED_SIGS) {
    // Test path, query string, AND user-agent
    for (const field of ['path', 'query', 'userAgent']) {
      if (sig.regex.test(line[field])) {
        threats.push({ type: sig.type, severity: sig.severity, ... });
      }
    }
  }
}
```

**Why test the User-Agent?** Attackers reveal themselves through tool user-agents:
```
sqlmap/1.7.8#stable (https://sqlmap.org)
Nikto/2.1.6
dirbuster/1.0-RC1
```

### Signature Examples

```json
{
  "sql_injection": [
    { "id": "SQLi-001", "pattern": "(?:union.{0,20}select|select.{0,20}from)", "severity": "critical" },
    { "id": "SQLi-003", "pattern": "(?:sleep\\s*\\(|benchmark\\s*\\(|waitfor\\s+delay)", "severity": "critical" }
  ],
  "directory_traversal": [
    { "id": "LFI-001", "pattern": "(?:\\.\\./){2,}", "severity": "high" },
    { "id": "LFI-003", "pattern": "(?:/etc/passwd|/etc/shadow)", "severity": "critical" }
  ]
}
```

---

## 5. Phase 3 — Behavioral Analysis

Behavioral analysis is **stateful** — it tracks patterns across multiple lines. This catches attacks that have no single-line signature.

### Brute Force Detection

Algorithm: sliding window frequency count.

```javascript
_countInWindow(timestamps, windowMs, threshold) {
  const sorted = [...timestamps].sort((a, b) => a - b);
  let maxInWindow = 0;
  let left = 0;
  for (let right = 0; right < sorted.length; right++) {
    while (sorted[right] - sorted[left] > windowMs) left++;
    maxInWindow = Math.max(maxInWindow, right - left + 1);
  }
  return maxInWindow >= threshold ? maxInWindow : 0;
}

// Usage: >10 failures in any 5-minute window = brute force
const hit = this._countInWindow(state.paths401, 5 * 60 * 1000, 10);
```

This uses the **two-pointer / sliding window** technique — O(n log n) for sorting, O(n) for the window scan. Much faster than nested loops.

### Directory Scanning Detection

```javascript
// >50 unique paths from one IP = scanning
if (state.uniquePaths.size >= 50) {
  findings.push({ type: 'scanning', severity: 'medium', evidence: state.uniquePaths.size });
}
```

### Why Two Strategies?

| Scenario | Signature Detection | Behavioral Detection |
|----------|--------------------|--------------------|
| `UNION SELECT` in URL | ✅ Catches it | ❌ Can't see it |
| 50 login attempts, no SQL | ❌ Misses it | ✅ Catches it |
| Nikto scanner | ✅ User-agent match | ✅ Many unique paths |
| Slow password spray | ❌ Misses it | ✅ Catches it |

Real SIEMs use both. LogLens uses both.

---

## 6. Phase 4 — The Job Queue Pattern

### Why Not Process Synchronously?

A 500MB log file takes 30–60 seconds to parse. HTTP requests time out after ~30 seconds. Sending a 500MB file and waiting for the response would fail.

### The Async Pattern

```
Client → POST /api/upload → Server starts job → Returns { jobId } immediately
                                                         ↑
                                                 (response in <100ms)

Client → GET /api/jobs/abc123 → { status: 'running', progress: 42 }
Client → GET /api/jobs/abc123 → { status: 'running', progress: 71 }
Client → GET /api/jobs/abc123 → { status: 'done',    progress: 100 }
Client → GET /api/jobs/abc123/report → { ... full report ... }
```

The frontend polls every 1.5 seconds. This "polling" pattern is simple and reliable. For real-time updates you'd use WebSockets — but polling is easier to understand and debug.

### Progress Calculation

```
Parsing phase (streaming):  0% → 70%   (tracked by bytes read / file size)
Behavioral analysis:        70% → 80%  (instantaneous after streaming done)
GeoIP enrichment:           80% → 92%  (10 API calls, slowest phase)
Save to database:           92% → 100% (SQLite write)
```

---

## 7. The Signature Database

`signatures.json` is the heart of the detection engine. Each entry:

```json
{
  "id":          "SQLi-001",
  "pattern":     "(?:union.{0,20}select|select.{0,20}from)",
  "severity":    "critical",
  "description": "Classic SQL keyword chaining"
}
```

- **`id`** — unique identifier for reporting ("SQLi-001 matched")
- **`pattern`** — JavaScript-compatible regex (case-insensitive when compiled)
- **`severity`** — `critical | high | medium | low`
- **`description`** — human-readable for the dashboard

### Extending Signatures

Add new attack patterns to `signatures.json` without touching any code:

```json
"log4shell": [
  { "id": "LOG4J-001", "pattern": "\\$\\{jndi:", "severity": "critical", "description": "Log4Shell JNDI injection" },
  { "id": "LOG4J-002", "pattern": "\\$\\{\\$\\{lower:", "severity": "critical", "description": "Log4Shell obfuscated" }
]
```

This is the "Open/Closed Principle" — the engine is open for extension (new signatures) without modification.

---

## 8. Performance: Streaming vs Loading

### The Problem with Loading

```javascript
// ❌ WRONG — crashes on large files
const content = fs.readFileSync('access.log', 'utf8');  // 500MB into RAM!
const lines   = content.split('\n');
```

A 500MB file loaded into memory becomes ~1GB after JavaScript string conversion. Node.js crashes with `JavaScript heap out of memory`.

### The Solution: Streaming

```javascript
// ✅ CORRECT — only one line in memory at a time
const readStream = createReadStream(filePath, { highWaterMark: 64 * 1024 }); // 64KB chunks
const rl         = createInterface({ input: readStream });

rl.on('line', (rawLine) => {
  // Process this one line
  // It is in memory, parsed, emitted, then GARBAGE COLLECTED
  // Next line takes its place
  const parsed = parseLine(rawLine);
  emitter.emit('line', parsed);
});
```

**Memory usage comparison:**

| Approach | 100MB file | 500MB file | 2GB file |
|----------|-----------|-----------|---------|
| `readFileSync` | ~200MB | ~1GB | Crash |
| Streaming | ~50MB | ~50MB | ~50MB |

The streaming approach uses constant memory regardless of file size. Only the current 64KB chunk + current line are in memory at any time.

---

## 9. Getting Started

```bash
# Backend
cd backend
npm install
npm run dev          # starts on :4001

# Frontend
cd frontend
npm install
npm run dev          # starts on :5174
```

**Test with the demo log:**
Click "⚡ Load Demo Log" in the UI, or hit:
```
GET http://localhost:4001/api/demo
→ { jobId: "..." }
GET http://localhost:4001/api/jobs/<jobId>
→ { status: "done", progress: 100 }
GET http://localhost:4001/api/jobs/<jobId>/report
→ full JSON report
```

---

## 10. Project Structure

```
loglens/
├── backend/
│   ├── server.js          ← Express server, middleware
│   ├── parser.js          ← CLF regex parser + streaming engine
│   ├── detector.js        ← Signature matching + BehavioralAnalyzer
│   ├── signatures.json    ← Attack pattern database (30 signatures)
│   ├── geoip.js           ← IP geolocation via ip-api.com
│   ├── jobs.js            ← Async job queue management
│   ├── db.js              ← SQLite (job state + report storage)
│   └── routes/upload.js   ← Upload, job status, report endpoints
│
├── frontend/
│   └── src/
│       ├── components/
│       │   ├── UploadPage.jsx  ← File upload + job polling
│       │   └── Dashboard.jsx   ← Full report visualisation (Recharts)
│       ├── App.jsx
│       └── App.css
│
└── sample/demo.log        ← Pre-built attack demo log
```

---

## 11. Attack Vector Coverage

| ID | Attack Type | Signatures | Behavioral |
|----|------------|-----------|-----------|
| SQLi-001–006 | SQL Injection | 6 patterns | — |
| XSS-001–006 | Cross-Site Scripting | 6 patterns | — |
| LFI-001–005 | Path Traversal / LFI | 5 patterns | — |
| CMD-001–004 | Command Injection | 4 patterns | — |
| SCAN-001–004 | Scanner / Recon Tools | 4 patterns | + unique paths |
| CRED-001–003 | Admin Panel Discovery | 3 patterns | — |
| — | Brute Force | — | 401 frequency |
| — | Credential Stuffing | — | POST login frequency |
| — | Directory Scanning | — | unique path count |
| — | DoS / High Volume | — | request rate |

---

*Built as part of a Cybersecurity Software Engineering Internship exploring SIEM architecture, regex-based threat detection, and large-scale log processing.*

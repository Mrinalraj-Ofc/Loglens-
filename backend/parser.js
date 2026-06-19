/**
 * parser.js — LogLens Log Parser Engine
 * ──────────────────────────────────────
 * Parses Apache / Nginx log lines into structured objects.
 *
 * Supports two formats:
 *  • CLF  (Common Log Format):
 *    127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326
 *
 *  • Combined Log Format (adds Referer + User-Agent):
 *    127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "http://ref.com" "Mozilla/5.0..."
 *
 * Both formats are produced by Apache and Nginx by default.
 */

// ─── CLF / Combined Format Regex ─────────────────────────────────────────────
//
// Named capture groups for readability:
//   ip        — client IP address
//   ident     — RFC 1413 identity (almost always "-")
//   user      — authenticated username (almost always "-")
//   timestamp — [DD/Mon/YYYY:HH:MM:SS ±ZZZZ]
//   method    — HTTP verb (GET, POST, PUT, DELETE, …)
//   path      — request path + query string
//   protocol  — HTTP/1.0, HTTP/1.1, HTTP/2
//   status    — HTTP response status code
//   size      — response size in bytes ("-" if none)
//   referer   — HTTP Referer header (Combined format only)
//   useragent — User-Agent string (Combined format only)
//
const CLF_REGEX = /^(?<ip>\S+)\s+(?<ident>\S+)\s+(?<user>\S+)\s+\[(?<timestamp>[^\]]+)\]\s+"(?<method>\S+)\s+(?<path>\S+)\s+(?<protocol>[^"]+)"\s+(?<status>\d{3})\s+(?<size>\S+)(?:\s+"(?<referer>[^"]*)"\s+"(?<useragent>[^"]*)")?/;

// Month abbreviation → number mapping for date parsing
const MONTHS = { Jan:0, Feb:1, Mar:2, Apr:3, May:4, Jun:5, Jul:6, Aug:7, Sep:8, Oct:9, Nov:10, Dec:11 };

// ─── Timestamp Parser ─────────────────────────────────────────────────────────

/**
 * Parse CLF timestamp: "10/Oct/2000:13:55:36 -0700" → Date object
 * @param {string} ts
 * @returns {Date|null}
 */
export function parseCLFTimestamp(ts) {
  // Format: DD/Mon/YYYY:HH:MM:SS ±HHMM
  const m = ts.match(/^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{4})$/);
  if (!m) return null;

  const [, day, mon, year, hh, mm, ss, tz] = m;
  const month = MONTHS[mon];
  if (month === undefined) return null;

  // Parse timezone offset
  const tzSign  = tz[0] === '+' ? 1 : -1;
  const tzHours = parseInt(tz.slice(1, 3), 10);
  const tzMins  = parseInt(tz.slice(3, 5), 10);
  const tzOffsetMs = tzSign * (tzHours * 60 + tzMins) * 60 * 1000;

  // Build UTC date
  const utc = Date.UTC(
    parseInt(year, 10),
    month,
    parseInt(day,  10),
    parseInt(hh,   10),
    parseInt(mm,   10),
    parseInt(ss,   10)
  ) - tzOffsetMs;

  return new Date(utc);
}

// ─── Line Parser ──────────────────────────────────────────────────────────────

/**
 * Parse a single log line into a structured object.
 *
 * @param {string} line    — raw log line
 * @param {number} lineNum — 1-based line number
 * @returns {ParsedLine|null} — null if line doesn't match any known format
 *
 * @typedef {Object} ParsedLine
 * @property {number}  lineNum
 * @property {string}  ip
 * @property {string}  user
 * @property {Date}    timestamp
 * @property {string}  method
 * @property {string}  path
 * @property {string}  query
 * @property {string}  protocol
 * @property {number}  status
 * @property {number}  size
 * @property {string}  referer
 * @property {string}  userAgent
 * @property {string}  raw
 */
export function parseLine(line, lineNum = 0) {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('#')) return null;  // skip comments/blanks

  const match = CLF_REGEX.exec(trimmed);
  if (!match?.groups) return null;

  const g         = match.groups;
  const timestamp = parseCLFTimestamp(g.timestamp);
  if (!timestamp) return null;

  // Split path and query string
  const qIdx  = g.path.indexOf('?');
  const path  = qIdx >= 0 ? g.path.slice(0, qIdx) : g.path;
  const query = qIdx >= 0 ? g.path.slice(qIdx + 1) : '';

  return {
    lineNum,
    ip:        g.ip,
    user:      g.user === '-' ? null : g.user,
    timestamp,
    method:    g.method.toUpperCase(),
    path:      decodeURIComponentSafe(path),
    query:     decodeURIComponentSafe(query),
    protocol:  g.protocol,
    status:    parseInt(g.status, 10),
    size:      g.size === '-' ? 0 : parseInt(g.size, 10),
    referer:   g.referer  || '',
    userAgent: g.useragent || '',
    raw:       trimmed,
  };
}

// ─── Safe URL Decoder ─────────────────────────────────────────────────────────

/**
 * Decode URL-encoded characters safely (preserves raw string if decoding fails).
 * Attackers often double-encode payloads (e.g. %2e%2e%2f for ../), so we
 * decode up to 3 levels deep.
 */
function decodeURIComponentSafe(str) {
  let decoded = str;
  for (let i = 0; i < 3; i++) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;   // no more encodings
      decoded = next;
    } catch {
      break;  // malformed encoding — keep last valid decoded form
    }
  }
  return decoded;
}

// ─── Streaming File Parser ────────────────────────────────────────────────────

import { createReadStream }   from 'fs';
import { createInterface }    from 'readline';
import { EventEmitter }       from 'events';

/**
 * Parse a log file using Node.js streams.
 * Emits events so callers can process results incrementally:
 *
 *   emitter.on('line',     (parsedLine) => {})  — one structured line
 *   emitter.on('progress', ({ pct, linesRead }) => {})  — progress update
 *   emitter.on('done',     ({ total, parsed, skipped }) => {})
 *   emitter.on('error',    (err) => {})
 *
 * NEVER loads the whole file into RAM — uses readline streaming.
 * A 500MB file uses < 50MB of RAM because only one line is in memory at a time.
 *
 * @param {string} filePath  — path to the log file
 * @param {number} fileSize  — file size in bytes (for progress calculation)
 * @returns {EventEmitter}
 */
export function streamParseFile(filePath, fileSize = 0) {
  const emitter     = new EventEmitter();
  let   linesRead   = 0;
  let   linesParsed = 0;
  let   bytesRead   = 0;

  setImmediate(() => {
    try {
      const readStream  = createReadStream(filePath, { encoding: 'utf8', highWaterMark: 64 * 1024 }); // 64KB chunks
      const rl          = createInterface({ input: readStream, crlfDelay: Infinity });

      // Track bytes for progress
      readStream.on('data', (chunk) => {
        bytesRead += Buffer.byteLength(chunk, 'utf8');
        if (fileSize > 0) {
          const pct = Math.min(99, Math.round((bytesRead / fileSize) * 100));
          emitter.emit('progress', { pct, linesRead, linesParsed });
        }
      });

      rl.on('line', (rawLine) => {
        linesRead++;
        const parsed = parseLine(rawLine, linesRead);
        if (parsed) {
          linesParsed++;
          emitter.emit('line', parsed);
        }
      });

      rl.on('close', () => {
        emitter.emit('done', {
          total:   linesRead,
          parsed:  linesParsed,
          skipped: linesRead - linesParsed,
        });
      });

      rl.on('error', (err) => emitter.emit('error', err));
      readStream.on('error', (err) => emitter.emit('error', err));

    } catch (err) {
      emitter.emit('error', err);
    }
  });

  return emitter;
}

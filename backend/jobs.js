/**
 * jobs.js — LogLens Async Job Queue
 * ────────────────────────────────────
 * Pattern: Upload → Get Job ID → Poll status → View Report
 *
 * Why async? Parsing a 500MB log file takes 30-60 seconds.
 * A synchronous HTTP request would time out before it finishes.
 * Instead: the upload endpoint returns immediately with a jobId,
 * and the frontend polls GET /api/jobs/:id every 2 seconds.
 *
 * Implementation: simple in-memory Map. For production, replace
 * with Bull (Redis-backed) or a database-backed queue.
 */

import { v4 as uuidv4 }        from 'uuid';
import { streamParseFile }      from './parser.js';
import { detectSignatureThreats, BehavioralAnalyzer, buildReport } from './detector.js';
import { lookupIP }             from './geoip.js';
import { saveReport, getReport } from './db.js';
import { unlink }               from 'fs/promises';

// ─── In-Memory Job Store ──────────────────────────────────────────────────────

/**
 * @typedef {Object} Job
 * @property {string}  id
 * @property {'queued'|'running'|'done'|'failed'} status
 * @property {number}  progress         — 0-100
 * @property {string}  filename         — original upload filename
 * @property {number}  fileSize
 * @property {string}  tempPath         — temp file path on disk
 * @property {Date}    createdAt
 * @property {Date}    [startedAt]
 * @property {Date}    [completedAt]
 * @property {string}  [error]
 * @property {object}  [report]         — final analysis report
 */

const jobs = new Map();

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Create a new analysis job and start processing immediately.
 *
 * @param {object} opts
 * @param {string} opts.filename  — original filename for display
 * @param {number} opts.fileSize  — file size in bytes
 * @param {string} opts.tempPath  — path to the uploaded temp file
 * @returns {string} jobId
 */
export function createJob({ filename, fileSize, tempPath }) {
  const jobId = uuidv4();

  /** @type {Job} */
  const job = {
    id:          jobId,
    status:      'queued',
    progress:    0,
    filename,
    fileSize,
    tempPath,
    createdAt:   new Date(),
    startedAt:   null,
    completedAt: null,
    error:       null,
    report:      null,
  };

  jobs.set(jobId, job);

  // Start processing asynchronously — don't await
  setImmediate(() => processJob(jobId));

  return jobId;
}

/**
 * Get the current state of a job.
 * @param {string} jobId
 * @returns {Job|null}
 */
export function getJob(jobId) {
  return jobs.get(jobId) || null;
}

/**
 * Get a safe, serializable version of the job (strips tempPath from response).
 * @param {string} jobId
 */
export function getJobStatus(jobId) {
  const job = jobs.get(jobId);
  if (!job) return null;
  const { tempPath, ...safe } = job;  // never expose server file paths
  return safe;
}

// ─── Core Processing ──────────────────────────────────────────────────────────

/**
 * Process a job end-to-end:
 *  1. Stream-parse the log file
 *  2. Run signature detection on each line
 *  3. Run behavioral analysis on all lines
 *  4. GeoIP-enrich the top attacker IPs
 *  5. Build and save the report
 *  6. Clean up temp file
 */
async function processJob(jobId) {
  const job = jobs.get(jobId);
  if (!job) return;

  job.status    = 'running';
  job.startedAt = new Date();

  try {
    const lines         = [];         // all ParsedLine objects
    const lineThreats   = new Map();  // lineNum → Threat[]
    const behavioral    = new BehavioralAnalyzer();

    // ── Phase 1 & 2: Stream parse + signature detection ────────────────────

    await new Promise((resolve, reject) => {
      const emitter = streamParseFile(job.tempPath, job.fileSize);

      emitter.on('line', (parsedLine) => {
        lines.push(parsedLine);
        behavioral.ingest(parsedLine);

        const threats = detectSignatureThreats(parsedLine);
        if (threats.length > 0) {
          lineThreats.set(parsedLine.lineNum, threats);
        }
      });

      emitter.on('progress', ({ pct }) => {
        job.progress = Math.floor(pct * 0.7);  // phase 1 = 0-70%
      });

      emitter.on('done', resolve);
      emitter.on('error', reject);
    });

    job.progress = 70;

    // ── Phase 3: Behavioral analysis ──────────────────────────────────────

    const behavioralFindings = behavioral.analyze();
    job.progress = 80;

    // ── Phase 4: GeoIP enrichment for top attackers ────────────────────────

    // Build initial report first (fast)
    const report = buildReport(lines, lineThreats, behavioralFindings);

    // Enrich top 10 attacker IPs with geolocation
    const geoPromises = report.topAttackers.slice(0, 10).map(async (attacker) => {
      attacker.geo = await lookupIP(attacker.ip).catch(() => null);
    });
    await Promise.all(geoPromises);
    job.progress = 92;

    // ── Phase 5: Save report ───────────────────────────────────────────────

    await saveReport(jobId, {
      ...report,
      meta: {
        filename:     job.filename,
        fileSize:     job.fileSize,
        processedAt:  new Date().toISOString(),
        totalLines:   lines.length,
      },
    });

    job.report      = report;  // keep in memory for fast reads
    job.progress    = 100;
    job.status      = 'done';
    job.completedAt = new Date();

    console.log(`[JOB ${jobId}] Complete. Lines: ${lines.length}, Threats: ${lineThreats.size}`);

  } catch (err) {
    console.error(`[JOB ${jobId}] Failed:`, err.message);
    job.status = 'failed';
    job.error  = err.message;
  } finally {
    // Always clean up the temp file regardless of success/failure
    unlink(job.tempPath).catch(() => {});
  }
}

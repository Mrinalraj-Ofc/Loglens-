/**
 * db.js — LogLens Database Layer
 * ────────────────────────────────
 * Stores job metadata and analysis reports.
 * Reports are serialized as JSON blobs — SQLite handles them fine for
 * this use case since reports are read/written as whole units.
 */

import Database from 'better-sqlite3';
import path     from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH   = process.env.DB_PATH || path.join(__dirname, 'loglens.db');

export const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS reports (
    job_id       TEXT PRIMARY KEY,
    filename     TEXT NOT NULL,
    file_size    INTEGER NOT NULL DEFAULT 0,
    created_at   DATETIME NOT NULL DEFAULT (datetime('now')),
    report_json  TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_reports_created
    ON reports(created_at DESC);
`);

/** Save a completed report to the database. */
export async function saveReport(jobId, report) {
  db.prepare(`
    INSERT OR REPLACE INTO reports (job_id, filename, file_size, report_json)
    VALUES (?, ?, ?, ?)
  `).run(jobId, report.meta?.filename || 'unknown', report.meta?.fileSize || 0, JSON.stringify(report));
}

/** Retrieve a saved report by job ID. */
export function getReport(jobId) {
  const row = db.prepare('SELECT report_json FROM reports WHERE job_id = ?').get(jobId);
  if (!row) return null;
  try { return JSON.parse(row.report_json); } catch { return null; }
}

/** List recent jobs (last 50). */
export function listReports() {
  return db.prepare(`
    SELECT job_id, filename, file_size, created_at
    FROM reports ORDER BY created_at DESC LIMIT 50
  `).all();
}

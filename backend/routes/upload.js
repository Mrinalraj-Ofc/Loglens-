/**
 * routes/upload.js — LogLens Upload & Job Routes
 * ─────────────────────────────────────────────────
 * POST /api/upload          — accept .log file, start analysis job
 * GET  /api/jobs/:id        — poll job status + progress
 * GET  /api/jobs/:id/report — get full analysis report (when done)
 * GET  /api/reports         — list recent analyses
 * GET  /api/demo            — trigger analysis on built-in demo log
 */

import express      from 'express';
import multer       from 'multer';
import path         from 'path';
import os           from 'os';
import { createJob, getJobStatus } from '../jobs.js';
import { getReport, listReports }  from '../db.js';
import { fileURLToPath }           from 'url';

const router    = express.Router();
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ─── Multer — disk storage (not memory) for large files ───────────────────────

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, os.tmpdir()),
  filename:    (req, file, cb) => cb(null, `loglens-${Date.now()}-${file.originalname}`),
});

const upload = multer({
  storage,
  limits: { fileSize: 500 * 1024 * 1024 },  // 500MB
  fileFilter: (req, file, cb) => {
    const allowed = ['.log', '.txt', '.gz', '.access'];
    const ext     = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext) || file.mimetype === 'text/plain') {
      cb(null, true);
    } else {
      cb(new Error('Only .log, .txt, and .access files are accepted.'));
    }
  },
});

// ─── POST /api/upload ─────────────────────────────────────────────────────────

router.post('/upload', upload.single('logfile'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No log file provided.' });
  }

  const jobId = createJob({
    filename: req.file.originalname,
    fileSize: req.file.size,
    tempPath: req.file.path,
  });

  console.log(`[UPLOAD] Job ${jobId} created for ${req.file.originalname} (${req.file.size} bytes)`);

  res.status(202).json({
    jobId,
    message: 'Analysis started. Poll /api/jobs/:id for progress.',
  });
});

// ─── GET /api/jobs/:id ────────────────────────────────────────────────────────

router.get('/jobs/:id', (req, res) => {
  const job = getJobStatus(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found.' });
  res.json(job);
});

// ─── GET /api/jobs/:id/report ─────────────────────────────────────────────────

router.get('/jobs/:id/report', (req, res) => {
  const job = getJobStatus(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found.' });
  if (job.status !== 'done') return res.status(202).json({ status: job.status, progress: job.progress });

  const report = getReport(req.params.id);
  if (!report) return res.status(404).json({ error: 'Report not found.' });
  res.json(report);
});

// ─── GET /api/reports ─────────────────────────────────────────────────────────

router.get('/reports', (req, res) => {
  res.json(listReports());
});

// ─── GET /api/demo ────────────────────────────────────────────────────────────

router.get('/demo', (req, res) => {
  const demoPath = path.join(__dirname, '../../sample/demo.log');
  const jobId    = createJob({
    filename: 'demo.log',
    fileSize: 0,
    tempPath: demoPath,
  });
  res.json({ jobId, message: 'Demo analysis started.' });
});

export default router;

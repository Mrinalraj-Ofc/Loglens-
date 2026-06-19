/**
 * server.js — LogLens Backend
 * ─────────────────────────────
 * SIEM-lite log analysis API server.
 */

import express       from 'express';
import cors          from 'cors';
import helmet        from 'helmet';
import morgan        from 'morgan';
import rateLimit     from 'express-rate-limit';
import uploadRoutes  from './routes/upload.js';

const app  = express();
const PORT = process.env.PORT || 4001;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.FRONTEND_URL || 'http://localhost:5174', credentials: false }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
app.use(morgan('combined'));
app.use(express.json({ limit: '1mb' }));

app.use('/api', uploadRoutes);

app.get('/health', (req, res) => res.json({ status: 'ok', service: 'LogLens' }));

app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(err.status || 500).json({ error: err.message || 'Internal server error.' });
});

app.listen(PORT, () => {
  console.log(`
  ╔══════════════════════════════════════════╗
  ║    LogLens — SIEM-lite Analysis Server   ║
  ║    Port: ${PORT}                              ║
  ╚══════════════════════════════════════════╝
  `);
});

export default app;

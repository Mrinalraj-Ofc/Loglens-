/**
 * UploadPage.jsx — LogLens File Upload UI
 */
import { useState, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';

const API = import.meta.env.VITE_API_URL || 'http://localhost:4001/api';
const POLL_INTERVAL = 1500; // ms

function formatBytes(b) {
  if (!b) return '0 B';
  const k = 1024, s = ['B','KB','MB','GB'];
  const i = Math.floor(Math.log(b) / Math.log(k));
  return `${(b / Math.pow(k, i)).toFixed(1)} ${s[i]}`;
}

export default function UploadPage() {
  const [file,       setFile]       = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [status,     setStatus]     = useState('idle');  // idle|uploading|polling|done|error
  const [progress,   setProgress]   = useState(0);
  const [statusMsg,  setStatusMsg]  = useState('');
  const [error,      setError]      = useState('');
  const fileRef    = useRef(null);
  const pollRef    = useRef(null);
  const navigate   = useNavigate();

  const handleFile = useCallback((f) => {
    if (!f) return;
    if (f.size > 500 * 1024 * 1024) { setError('File exceeds 500MB limit.'); return; }
    setFile(f); setError('');
  }, []);

  const handleDrop = useCallback((e) => {
    e.preventDefault(); setIsDragging(false);
    handleFile(e.dataTransfer.files[0]);
  }, [handleFile]);

  const pollJob = (jobId) => {
    pollRef.current = setInterval(async () => {
      try {
        const res = await fetch(`${API}/jobs/${jobId}`);
        const job = await res.json();
        setProgress(job.progress || 0);

        const msgs = {
          queued:  'Queued — waiting to start…',
          running: `Analysing log file… ${job.progress || 0}%`,
          done:    'Complete! Loading dashboard…',
          failed:  `Failed: ${job.error}`,
        };
        setStatusMsg(msgs[job.status] || job.status);

        if (job.status === 'done') {
          clearInterval(pollRef.current);
          setTimeout(() => navigate(`/report/${jobId}`), 600);
        }
        if (job.status === 'failed') {
          clearInterval(pollRef.current);
          setStatus('error'); setError(job.error);
        }
      } catch (err) {
        clearInterval(pollRef.current);
        setStatus('error'); setError('Lost connection to server.');
      }
    }, POLL_INTERVAL);
  };

  const handleUpload = async () => {
    if (!file) return;
    setStatus('uploading'); setProgress(0); setError('');

    try {
      const form = new FormData();
      form.append('logfile', file);
      const res  = await fetch(`${API}/upload`, { method: 'POST', body: form });
      if (!res.ok) { const e = await res.json(); throw new Error(e.error); }
      const { jobId } = await res.json();
      setStatus('polling'); setStatusMsg('Queued…');
      pollJob(jobId);
    } catch (err) {
      setStatus('error'); setError(err.message);
    }
  };

  const handleDemo = async () => {
    setStatus('polling'); setProgress(0); setStatusMsg('Loading demo log…'); setFile(null);
    try {
      const res    = await fetch(`${API}/demo`);
      const { jobId } = await res.json();
      pollJob(jobId);
    } catch (err) {
      setStatus('error'); setError(err.message);
    }
  };

  const reset = () => { clearInterval(pollRef.current); setFile(null); setStatus('idle'); setProgress(0); setError(''); };

  return (
    <div className="upload-page">
      <div className="upload-hero">
        <h1 className="upload-title">Drop your server log.<br/><span className="accent">Get a threat report.</span></h1>
        <p className="upload-sub">LogLens parses Apache/Nginx access logs, detects attack patterns using regex signatures, and visualises the results — in seconds.</p>
      </div>

      {status === 'idle' && (
        <>
          <div
            className={`drop-zone ${isDragging ? 'dragging' : ''} ${file ? 'has-file' : ''}`}
            onDrop={handleDrop}
            onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
            onDragLeave={() => setIsDragging(false)}
            onClick={() => !file && fileRef.current?.click()}
          >
            <input ref={fileRef} type="file" accept=".log,.txt,.access" style={{display:'none'}} onChange={(e) => handleFile(e.target.files[0])} />
            {file ? (
              <div className="file-info">
                <div style={{fontSize:'2.5rem'}}>📋</div>
                <p className="file-name">{file.name}</p>
                <p className="file-size">{formatBytes(file.size)}</p>
                <button className="btn-ghost" onClick={(e) => { e.stopPropagation(); setFile(null); }}>✕ Remove</button>
              </div>
            ) : (
              <div className="drop-prompt">
                <div style={{fontSize:'2.5rem',marginBottom:'.5rem'}}>📁</div>
                <p>Drop an <strong>.log</strong> file, or <span className="link-text">click to browse</span></p>
                <p className="sub-text">Apache / Nginx CLF or Combined Format · Max 500MB</p>
              </div>
            )}
          </div>

          {error && <p className="error-msg">⚠ {error}</p>}

          <div className="upload-actions">
            <button className="btn-primary" onClick={handleUpload} disabled={!file}>🔍 Analyse Log</button>
            <button className="btn-demo" onClick={handleDemo}>⚡ Load Demo Log</button>
          </div>

          <div className="supported-formats">
            <span>Detects:</span>
            {['SQL Injection','XSS','Path Traversal','Brute Force','Scanners','Cmd Injection'].map(t => (
              <span key={t} className="format-tag">{t}</span>
            ))}
          </div>
        </>
      )}

      {(status === 'uploading' || status === 'polling') && (
        <div className="progress-panel">
          <div style={{fontSize:'3rem'}}>{status === 'uploading' ? '⬆️' : '🔍'}</div>
          <h3>{statusMsg || 'Processing…'}</h3>
          <div className="progress-bar"><div className="progress-fill" style={{width:`${progress}%`}} /></div>
          <p className="progress-pct">{progress}%</p>
          <p className="progress-sub">Streaming file through regex engine. Large files may take 30–60 seconds.</p>
        </div>
      )}

      {status === 'error' && (
        <div className="error-panel">
          <div style={{fontSize:'3rem'}}>❌</div>
          <h3>Analysis failed</h3>
          <p>{error}</p>
          <button className="btn-primary" onClick={reset}>Try again</button>
        </div>
      )}
    </div>
  );
}

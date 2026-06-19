/**
 * Dashboard.jsx — LogLens Analysis Dashboard
 * ────────────────────────────────────────────
 * Loads the report for a given jobId and renders all visualizations.
 */
import { useState, useEffect } from 'react';
import { useParams, Link }     from 'react-router-dom';
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
  PieChart, Pie, Cell, BarChart, Bar, Legend,
} from 'recharts';

const API = import.meta.env.VITE_API_URL || 'http://localhost:4001/api';

const SEVERITY_COLOR = { critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#22c55e', info:'#6b7280' };
const TYPE_COLOR     = ['#4f9cf9','#00d4aa','#f97316','#a855f7','#ec4899','#eab308'];

const TYPE_LABELS = {
  sql_injection:     'SQL Injection',
  xss:               'Cross-Site Scripting',
  directory_traversal: 'Path Traversal',
  command_injection: 'Command Injection',
  scanner:           'Scanner / Recon',
  credential_stuffing:'Credential Stuffing',
  brute_force:       'Brute Force',
  scanning:          'Directory Scan',
  dos:               'DoS / High Volume',
};

function SeverityBadge({ sev }) {
  const colors = { critical:'#fef2f2 #ef4444', high:'#fff7ed #f97316', medium:'#fefce8 #eab308', low:'#f0fdf4 #22c55e' };
  const [bg, col] = (colors[sev] || '#f9fafb #6b7280').split(' ');
  return <span style={{background:bg, color:col, border:`1px solid ${col}`, padding:'2px 8px', borderRadius:'100px', fontSize:'11px', fontWeight:600, textTransform:'capitalize'}}>{sev}</span>;
}

function StatCard({ icon, label, value, sub, color }) {
  return (
    <div className="stat-card">
      <div className="stat-icon" style={{background:`${color}22`,color}}>{icon}</div>
      <div>
        <p className="stat-value">{value}</p>
        <p className="stat-label">{label}</p>
        {sub && <p className="stat-sub">{sub}</p>}
      </div>
    </div>
  );
}

export default function Dashboard() {
  const { jobId }  = useParams();
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState('');

  useEffect(() => {
    fetch(`${API}/jobs/${jobId}/report`)
      .then(r => { if (!r.ok) throw new Error('Report not ready'); return r.json(); })
      .then(setReport)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, [jobId]);

  if (loading) return <div className="center-panel"><div className="spinner"/><p>Loading report…</p></div>;
  if (error)   return <div className="center-panel"><h3>❌ {error}</h3><Link to="/">← Back</Link></div>;
  if (!report) return null;

  const { summary, topAttackers, attackTypes, timeline, behavioral, threatLines, statusCodes, meta } = report;

  // Format timeline data
  const timelineData = (timeline || []).map(d => ({
    hour:  new Date(d.hour).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}),
    attacks: d.count,
  }));

  // Format attack types for pie
  const pieData = (attackTypes || []).map(d => ({
    name:  TYPE_LABELS[d.type] || d.type,
    value: d.count,
  }));

  // Status code bar chart
  const statusData = (statusCodes || []).sort((a,b) => a.code.localeCompare(b.code));

  return (
    <div className="dashboard">
      {/* ── Header ── */}
      <div className="dash-header">
        <div>
          <h2 className="dash-title">Threat Report</h2>
          <p className="dash-sub">{meta?.filename} · {new Date(meta?.processedAt).toLocaleString()}</p>
        </div>
        <Link to="/" className="btn-ghost">← New Analysis</Link>
      </div>

      {/* ── Stat Cards ── */}
      <div className="stat-grid">
        <StatCard icon="📋" label="Total Log Lines"     value={summary.totalLines?.toLocaleString()} color="#4f9cf9" />
        <StatCard icon="⚠️" label="Threat Events"       value={summary.totalThreats?.toLocaleString()} sub={`${((summary.totalThreats/summary.totalLines)*100).toFixed(1)}% of lines`} color="#ef4444" />
        <StatCard icon="🌐" label="Unique Attackers"    value={summary.uniqueAttackers} color="#f97316" />
        <StatCard icon="🧠" label="Behavioral Alerts"   value={summary.behavioralAlerts} color="#a855f7" />
      </div>

      {/* ── Severity Breakdown ── */}
      <div className="sev-row">
        {Object.entries(summary.severityCounts || {}).map(([sev, count]) => (
          <div key={sev} className="sev-card" style={{borderColor: SEVERITY_COLOR[sev]}}>
            <span className="sev-count" style={{color: SEVERITY_COLOR[sev]}}>{count}</span>
            <span className="sev-label" style={{textTransform:'capitalize'}}>{sev}</span>
          </div>
        ))}
      </div>

      {/* ── Timeline Chart ── */}
      <div className="chart-card">
        <h3 className="chart-title">🕐 Attacks Per Hour</h3>
        {timelineData.length > 0 ? (
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={timelineData}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis dataKey="hour" tick={{fontSize:11}} stroke="var(--text-muted)" />
              <YAxis tick={{fontSize:11}} stroke="var(--text-muted)" />
              <Tooltip contentStyle={{background:'var(--bg-card)',border:'1px solid var(--border)',borderRadius:'8px',fontSize:'12px'}} />
              <Line type="monotone" dataKey="attacks" stroke="#ef4444" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        ) : <p className="no-data">No time-series data available.</p>}
      </div>

      {/* ── Attack Types + Status Codes ── */}
      <div className="two-col">
        <div className="chart-card">
          <h3 className="chart-title">🎯 Attack Type Distribution</h3>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" outerRadius={80} dataKey="value" label={({name,percent}) => `${name} ${(percent*100).toFixed(0)}%`} labelLine={false} fontSize={10}>
                  {pieData.map((_, i) => <Cell key={i} fill={TYPE_COLOR[i % TYPE_COLOR.length]} />)}
                </Pie>
                <Tooltip contentStyle={{background:'var(--bg-card)',border:'1px solid var(--border)',borderRadius:'8px',fontSize:'12px'}} />
              </PieChart>
            </ResponsiveContainer>
          ) : <p className="no-data">No attack signatures matched.</p>}
        </div>

        <div className="chart-card">
          <h3 className="chart-title">📊 HTTP Status Codes</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={statusData}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis dataKey="code" tick={{fontSize:11}} stroke="var(--text-muted)" />
              <YAxis tick={{fontSize:11}} stroke="var(--text-muted)" />
              <Tooltip contentStyle={{background:'var(--bg-card)',border:'1px solid var(--border)',borderRadius:'8px',fontSize:'12px'}} />
              <Bar dataKey="count" fill="#4f9cf9" radius={[4,4,0,0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* ── Behavioral Alerts ── */}
      {behavioral?.length > 0 && (
        <div className="chart-card">
          <h3 className="chart-title">🧠 Behavioral Analysis Alerts</h3>
          <div className="threat-table-wrap">
            <table className="threat-table">
              <thead><tr><th>IP Address</th><th>Type</th><th>Severity</th><th>Evidence</th></tr></thead>
              <tbody>
                {behavioral.map((b, i) => (
                  <tr key={i}>
                    <td><code>{b.ip}</code></td>
                    <td>{TYPE_LABELS[b.type] || b.type}</td>
                    <td><SeverityBadge sev={b.severity} /></td>
                    <td style={{fontSize:'12px',color:'var(--text-secondary)'}}>{b.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Top Attackers ── */}
      <div className="chart-card">
        <h3 className="chart-title">🌐 Top Attacking IPs</h3>
        <div className="threat-table-wrap">
          <table className="threat-table">
            <thead><tr><th>IP Address</th><th>Country</th><th>Threat Events</th><th>Top Severity</th><th>Attack Types</th></tr></thead>
            <tbody>
              {(topAttackers || []).slice(0, 15).map((a, i) => (
                <tr key={i}>
                  <td><code>{a.ip}</code></td>
                  <td>{a.geo ? `${a.geo.countryCode} — ${a.geo.city}` : '—'}</td>
                  <td><strong>{a.threatCount}</strong></td>
                  <td><SeverityBadge sev={a.severity} /></td>
                  <td style={{fontSize:'11px',color:'var(--text-secondary)'}}>{(a.types||[]).join(', ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Threat Lines Sample ── */}
      <div className="chart-card">
        <h3 className="chart-title">🔍 Detected Threat Lines (first 20)</h3>
        <div className="threat-lines">
          {(threatLines || []).slice(0, 20).map((tl, i) => (
            <div key={i} className="threat-line-row">
              <div className="threat-line-meta">
                <span className="line-num">L{tl.lineNum}</span>
                <code className="line-ip">{tl.line?.ip}</code>
                <span className="line-method" style={{color:'#4f9cf9'}}>{tl.line?.method}</span>
                <code className="line-path">{(tl.line?.path||'').slice(0,60)}</code>
                <span className="line-status" style={{color: tl.line?.status >= 400 ? '#ef4444' : '#22c55e'}}>{tl.line?.status}</span>
              </div>
              <div className="threat-tags">
                {tl.threats.map((t, j) => (
                  <span key={j} className="threat-tag" style={{borderColor: SEVERITY_COLOR[t.severity], color: SEVERITY_COLOR[t.severity]}}>
                    {t.id}: {t.description}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}

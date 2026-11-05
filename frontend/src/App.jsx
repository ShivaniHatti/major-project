import { useEffect, useState } from 'react';

const API_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:5000';

const emptyForm = {
  source: 'manual',
  event_type: 'failed_login',
  username: 'user01',
  source_ip: '192.168.10.42',
  hostname: 'workstation-04',
  message: 'Failed login attempt from suspicious IP',
  severity: 'warning',
};

async function apiFetch(path, options = {}) {
  const response = await fetch(`${API_URL}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || 'Request failed');
  }

  return data;
}

export default function App() {
  const [status, setStatus] = useState('Checking backend...');
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [correlations, setCorrelations] = useState([]);
  const [hypotheses, setHypotheses] = useState([]);
  const [evidence, setEvidence] = useState({ status: 'inconclusive', summary: 'No evidence reviewed yet.', score: 0 });
  const [stats, setStats] = useState({ total_events: 0, by_source: {}, by_severity: {} });
  const [form, setForm] = useState(emptyForm);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  const refreshData = async () => {
    try {
      const [eventData, statsData, alertData, investigationData] = await Promise.all([
        apiFetch('/api/events'),
        apiFetch('/api/events/stats'),
        apiFetch('/api/alerts'),
        apiFetch('/api/investigation'),
      ]);

      setEvents(eventData.events || []);
      setStats(statsData || { total_events: 0, by_source: {}, by_severity: {} });
      setAlerts(alertData.alerts || []);
      setCorrelations(investigationData.correlations || []);
      setHypotheses(investigationData.hypotheses || []);
      setEvidence(investigationData.evidence || { status: 'inconclusive', summary: 'No evidence reviewed yet.', score: 0 });
    } catch (error) {
      console.error('Failed to refresh event data:', error);
    }
  };

  useEffect(() => {
    const loadDashboard = async () => {
      try {
        const health = await apiFetch('/api/health');
        setStatus(health.status === 'healthy' ? 'Connected' : 'Unavailable');
      } catch (error) {
        setStatus('Not connected');
      }

      await refreshData();
    };

    loadDashboard();
  }, []);

  const handleChange = (event) => {
    const { name, value } = event.target;
    setForm((previous) => ({ ...previous, [name]: value }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setLoading(true);
    setMessage('');

    try {
      await apiFetch('/api/ingest', {
        method: 'POST',
        body: JSON.stringify({
          source: form.source,
          events: [{ ...form, event_time: new Date().toISOString() }],
        }),
      });

      setMessage('Event ingested successfully.');
      setForm(emptyForm);
      await refreshData();
    } catch (error) {
      setMessage(error.message || 'Unable to ingest event.');
    } finally {
      setLoading(false);
    }
  };

  const addSampleEvent = async () => {
    setLoading(true);
    setMessage('');

    try {
      await apiFetch('/api/ingest', {
        method: 'POST',
        body: JSON.stringify({
          source: 'simulation',
          events: [{
            source: 'simulation',
            event_type: 'failed_login',
            username: 'alice',
            source_ip: '10.0.0.15',
            hostname: 'gateway',
            message: 'Failed password for alice from 10.0.0.15 port 22 ssh2',
            severity: 'high',
            event_time: new Date().toISOString(),
          }],
        }),
      });

      setMessage('Sample security event added.');
      await refreshData();
    } catch (error) {
      setMessage(error.message || 'Sample event failed.');
    } finally {
      setLoading(false);
    }
  };

  const sourceEntries = Object.entries(stats.by_source || {});
  const severityEntries = Object.entries(stats.by_severity || {});

  return (
    <main className="dashboard-shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">CYBER INVESTIGATION PLATFORM</p>
          <h1>SentinelX</h1>
        </div>
        <div className="status-pill">Backend: {status}</div>
      </header>

      <section className="summary-grid">
        <article className="stat-card">
          <span>Total Events</span>
          <strong>{stats.total_events || events.length}</strong>
        </article>
        <article className="stat-card">
          <span>Sources</span>
          <strong>{sourceEntries.length}</strong>
        </article>
        <article className="stat-card">
          <span>Severity Levels</span>
          <strong>{severityEntries.length}</strong>
        </article>
      </section>

      <section className="grid-layout">
        <div className="panel">
          <h2>Event Sources</h2>
          <ul className="compact-list">
            {sourceEntries.length === 0 ? (
              <li>No source data yet.</li>
            ) : (
              sourceEntries.map(([source, count]) => (
                <li key={source}><span>{source}</span><strong>{count}</strong></li>
              ))
            )}
          </ul>
        </div>

        <div className="panel">
          <h2>Severity</h2>
          <ul className="compact-list">
            {severityEntries.length === 0 ? (
              <li>No severity data yet.</li>
            ) : (
              severityEntries.map(([severity, count]) => (
                <li key={severity}><span>{severity}</span><strong>{count}</strong></li>
              ))
            )}
          </ul>
        </div>
      </section>

      <section className="panel form-panel">
        <div className="section-header">
          <h2>Ingest Security Event</h2>
          <div className="header-actions">
            <button type="button" className="secondary-btn" onClick={async () => {
              await refreshData();
              setMessage('Detection refreshed.');
            }} disabled={loading}>
              Run detection
            </button>
            <button type="button" className="secondary-btn" onClick={addSampleEvent} disabled={loading}>
              Add sample failed login
            </button>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="event-form">
          <label>
            Source
            <select name="source" value={form.source} onChange={handleChange}>
              <option value="manual">Manual</option>
              <option value="linux">Linux</option>
              <option value="windows">Windows</option>
              <option value="simulation">Simulation</option>
            </select>
          </label>

          <label>
            Event Type
            <input name="event_type" value={form.event_type} onChange={handleChange} />
          </label>

          <label>
            Username
            <input name="username" value={form.username} onChange={handleChange} />
          </label>

          <label>
            Source IP
            <input name="source_ip" value={form.source_ip} onChange={handleChange} />
          </label>

          <label>
            Hostname
            <input name="hostname" value={form.hostname} onChange={handleChange} />
          </label>

          <label>
            Severity
            <select name="severity" value={form.severity} onChange={handleChange}>
              <option value="info">Info</option>
              <option value="low">Low</option>
              <option value="warning">Warning</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </label>

          <label className="full-width">
            Message
            <textarea name="message" rows="3" value={form.message} onChange={handleChange} />
          </label>

          <div className="actions">
            <button type="submit" disabled={loading}>
              {loading ? 'Submitting...' : 'Submit Event'}
            </button>
          </div>
        </form>

        {message ? <p className="status-message">{message}</p> : null}
      </section>

      <section className="panel">
        <h2>Investigation Status</h2>
        <div className="investigation-summary">
          <span className={`status-pill compact-pill status-${evidence.status || 'inconclusive'}`}>
            {evidence.status || 'inconclusive'}
          </span>
          <strong>Evidence score: {evidence.score || 0}</strong>
        </div>
        <p>{evidence.summary || 'No evidence reviewed yet.'}</p>

        <div className="mini-grid">
          <div>
            <h3>Correlated signals</h3>
            {correlations.length === 0 ? (
              <p className="empty-state">No correlated event groups yet.</p>
            ) : (
              <ul className="compact-list">
                {correlations.slice(0, 4).map((group) => (
                  <li key={`${group.key_type}-${group.value}`}>
                    <span>{group.key_type}: {group.value}</span>
                    <strong>{group.event_count}</strong>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div>
            <h3>Hypotheses</h3>
            {hypotheses.length === 0 ? (
              <p className="empty-state">No hypotheses generated.</p>
            ) : (
              <ul className="compact-list">
                {hypotheses.slice(0, 4).map((hypothesis) => (
                  <li key={hypothesis.id}>
                    <span>{hypothesis.title}</span>
                    <strong>{hypothesis.confidence?.toFixed ? hypothesis.confidence.toFixed(2) : hypothesis.confidence}</strong>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </section>

      <section className="panel">
        <h2>Active Security Alerts</h2>

        {alerts.length === 0 ? (
          <p className="empty-state">No active alerts. Detection has not found suspicious patterns.</p>
        ) : (
          <div className="event-list">
            {alerts.map((alert, index) => (
              <article key={`${alert.alert_type}-${index}`} className="event-card alert-card">
                <div className="event-header">
                  <h3>{alert.alert_type}</h3>
                  <span className="severity-badge severity-high">{alert.severity || 'high'}</span>
                </div>
                <p>{alert.reason}</p>
                <div className="event-meta">
                  <span>Username: {alert.username || 'Unknown'}</span>
                  <span>Attempts: {alert.attempts || 0}</span>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>

      <section className="panel">
        <h2>Recent Security Events</h2>

        {events.length === 0 ? (
          <p className="empty-state">No security events found.</p>
        ) : (
          <div className="event-list">
            {events.map((event) => (
              <article key={event.id} className="event-card">
                <div className="event-header">
                  <h3>{event.event_type}</h3>
                  <span className={`severity-badge severity-${event.severity || 'info'}`}>
                    {event.severity || 'info'}
                  </span>
                </div>

                <p>{event.message}</p>
                <div className="event-meta">
                  <span>Source: {event.source || 'manual'}</span>
                  <span>Username: {event.username || 'Unknown'}</span>
                  <span>IP: {event.source_ip || 'Unknown'}</span>
                  <span>Host: {event.hostname || 'Unknown'}</span>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>
    </main>
  );
}

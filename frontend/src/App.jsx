import { useEffect, useState } from 'react';

const API_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:5000';

export default function App() {
  const [status, setStatus] = useState('Checking backend...');
  const [count, setCount] = useState(0);
  const [events, setEvents] = useState([]);

  useEffect(() => {
    fetch(`${API_URL}/health`)
      .then(response => {
        if (!response.ok) throw new Error('Backend error');
        return response.json();
      })
      .then(data => {
        setStatus(data.status === 'healthy' ? 'Connected' : 'Unavailable');
      })
      .catch(() => setStatus('Not connected'));

    fetch(`${API_URL}/api/events`)
      .then(response => {
        if (!response.ok) throw new Error('Events request failed');
        return response.json();
      })
      .then(data => {
        setCount(data.count);
        setEvents(data.events);
      })
      .catch(error => console.error(error));
  }, []);

  return (
    <main>
      <p className="eyebrow">CYBER INVESTIGATION PLATFORM</p>
      <h1>SentinelX</h1>
      <p>Evidence-aware autonomous cyber investigation</p>

      <section>
        <b>Backend:</b> {status}
        <br />
        <b>Stored events:</b> {count}
      </section>

      <section>
        <h2>Recent Security Events</h2>

        {events.length === 0 ? (
          <p>No security events found.</p>
        ) : (
          events.map(event => (
            <article key={event.id}>
              <h3>{event.event_type}</h3>
              <p>{event.message}</p>
              <p>Username: {event.username || 'Unknown'}</p>
              <p>Source IP: {event.source_ip || 'Unknown'}</p>
              <p>Hostname: {event.hostname || 'Unknown'}</p>
              <p>Severity: {event.severity}</p>
            </article>
          ))
        )}
      </section>

      <section>
        <h2>Investigation workflow</h2>
        <ol>
          <li>Collect and normalize telemetry</li>
          <li>Detect and correlate suspicious events</li>
          <li>Generate competing hypotheses</li>
          <li>Select next-best evidence</li>
          <li>Assess evidence sufficiency</li>
          <li>Produce an explainable finding or inconclusive result</li>
        </ol>
      </section>

      <small>Starter scaffold — advanced modules are not implemented yet.</small>
    </main>
  );
}

# Database design
The starter creates `security_events`. Planned tables: users, agents, security_events, alerts, investigations, hypotheses, evidence, hypothesis_evidence, nbe_decisions, agent_activities, reports and audit_logs. Keep evidence separate and link it to hypotheses with a supports/contradicts/neutral relationship. A hash alone is not a complete chain of custody.

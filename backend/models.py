from datetime import datetime, timezone
from extensions import db

class SecurityEvent(db.Model):
    __tablename__ = "security_events"
    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String(80), nullable=False, default="manual")
    event_type = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(120))
    source_ip = db.Column(db.String(64))
    hostname = db.Column(db.String(255))
    message = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False, default="info")
    event_time = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {k: getattr(self, k) for k in ("id", "source", "event_type", "username", "source_ip", "hostname", "message", "severity")} | {"event_time": self.event_time.isoformat() if self.event_time else None}

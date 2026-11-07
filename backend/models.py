import json
from datetime import datetime, timezone

from werkzeug.security import check_password_hash, generate_password_hash

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
        payload = {k: getattr(self, k) for k in ("id", "source", "event_type", "username", "source_ip", "hostname", "message", "severity")}
        payload["event_time"] = self.event_time.isoformat() if self.event_time else None
        return payload


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=True, index=True, default=None)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(32), nullable=False, default="security_analyst")
    status = db.Column(db.String(32), nullable=False, default="active")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class SourceRegistration(db.Model):
    __tablename__ = "source_registrations"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False, index=True)
    source_type = db.Column(db.String(32), nullable=False, default="file")
    status = db.Column(db.String(32), nullable=False, default="active")
    source_metadata = db.Column(db.Text, nullable=False, default="{}")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    @property
    def metadata_dict(self):
        if not self.source_metadata:
            return {}
        try:
            return json.loads(self.source_metadata)
        except (TypeError, ValueError):
            return {"raw": self.source_metadata}

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "source_type": self.source_type,
            "status": self.status,
            "metadata": self.metadata_dict,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class AgentRegistration(db.Model):
    __tablename__ = "agent_registrations"
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(120), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(32), nullable=False, default="security_analyst")
    status = db.Column(db.String(32), nullable=False, default="active")
    health = db.Column(db.String(32), nullable=False, default="healthy")
    last_seen = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    agent_metadata = db.Column(db.Text, nullable=False, default="{}")
    security_policy = db.Column(db.Text, nullable=False, default="{}")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    @property
    def metadata_dict(self):
        if not self.agent_metadata:
            return {}
        try:
            return json.loads(self.agent_metadata)
        except (TypeError, ValueError):
            return {"raw": self.agent_metadata}

    @property
    def policy_dict(self):
        if not self.security_policy:
            return {}
        try:
            return json.loads(self.security_policy)
        except (TypeError, ValueError):
            return {"raw": self.security_policy}

    def to_dict(self):
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "name": self.name,
            "role": self.role,
            "status": self.status,
            "health": self.health,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "metadata": self.metadata_dict,
            "security_policy": self.policy_dict,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

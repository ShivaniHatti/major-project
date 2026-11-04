
from flask import Flask, jsonify, request
from flask_cors import CORS
from config import Config
from extensions import db
from models import SecurityEvent
from detection_engine import detect_brute_force

app = Flask(__name__)
app.config.from_object(Config)

CORS(app)
db.init_app(app)


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "project": "SentinelX",
        "message": "SentinelX Backend is running"
    })


@app.route("/health", methods=["GET"])
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "service": "SentinelX Backend"
    })


@app.route("/api/events", methods=["POST"])
def create_event():
    data = request.get_json(silent=True) or {}

    required_fields = ["event_type", "message"]
    if any(not data.get(field) for field in required_fields):
        return jsonify({
            "error": "event_type and message are required"
        }), 400

    event = SecurityEvent(
        source=data.get("source", "manual"),
        event_type=data["event_type"],
        username=data.get("username"),
        source_ip=data.get("source_ip"),
        hostname=data.get("hostname"),
        message=data["message"],
        severity=data.get("severity", "info")
    )

    db.session.add(event)
    db.session.commit()

    return jsonify({
        "message": "Security event saved",
        "event": event.to_dict()
    }), 201


@app.route("/api/events", methods=["GET"])
def get_events():
    events = SecurityEvent.query.order_by(
        SecurityEvent.id.desc()
    ).all()

    return jsonify({
        "count": len(events),
        "events": [event.to_dict() for event in events]
    })

@app.route("/api/detect", methods=["GET"])
def run_detection():
    with app.app_context():
        alerts = detect_brute_force()

    return jsonify({
        "alert_count": len(alerts),
        "alerts": alerts
    })


@app.route("/api/test-brute-force", methods=["POST"])
def test_brute_force():
    from datetime import datetime, timezone
    from models import SecurityEvent
    from extensions import db

    for i in range(5):
        event = SecurityEvent(
            source="simulation",
            event_type="failed_login",
            username="testuser",
            source_ip="192.168.1.100",
            hostname="test-machine",
            message=f"Simulated failed login attempt {i + 1}",
            severity="warning",
            event_time=datetime.now(timezone.utc)
        )

        db.session.add(event)

    db.session.commit()

    return {
        "message": "Five failed login events inserted successfully",
        "username": "testuser",
        "attempts": 5
    }

if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=True)

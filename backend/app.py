from flask import Flask, jsonify, request
from flask_cors import CORS

from collectors.file_collector import FileCollector
from config import Config
from detection_engine import detect_brute_force
from detection.event_correlation import correlate_events
from extensions import db
from investigation.evidence_sufficiency import assess_hypotheses
from investigation.hypothesis_engine import generate_hypotheses
from services.event_service import create_security_event, get_all_events, get_event_stats, ingest_events

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

    try:
        event = create_security_event(data)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify({
        "message": "Security event saved",
        "event": event.to_dict()
    }), 201


@app.route("/api/events", methods=["GET"])
def get_events():
    events = get_all_events()

    return jsonify({
        "count": len(events),
        "events": [event.to_dict() for event in events]
    })


@app.route("/api/events/stats", methods=["GET"])
def get_events_stats():
    return jsonify(get_event_stats())


@app.route("/api/ingest", methods=["POST"])
def ingest_event_records():
    payload = request.get_json(silent=True) or {}
    source = payload.get("source", "manual")
    records = payload.get("events") or payload.get("records")

    if records is None:
        if isinstance(payload, list):
            records = payload
        elif payload:
            records = [payload]

    if not records:
        return jsonify({"error": "No events supplied for ingestion"}), 400

    stored_events = ingest_events(records, source=source)
    return jsonify({
        "count": len(stored_events),
        "events": [event.to_dict() for event in stored_events]
    }), 201


@app.route("/api/ingest/file", methods=["POST"])
def ingest_file_events():
    payload = request.get_json(silent=True) or {}
    file_path = payload.get("path") or payload.get("file_path")
    if not file_path:
        return jsonify({"error": "file path is required"}), 400

    try:
        collector = FileCollector(allowed_roots=payload.get("allowed_roots"))
        records = collector.collect(file_path)
        stored_events = ingest_events(records, source="file")
    except (FileNotFoundError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify({
        "count": len(stored_events),
        "source": file_path,
        "events": [event.to_dict() for event in stored_events]
    }), 201


@app.route("/api/detect", methods=["GET"])
@app.route("/api/alerts", methods=["GET"])
def run_detection():
    with app.app_context():
        alerts = detect_brute_force()

    return jsonify({
        "alert_count": len(alerts),
        "alerts": alerts
    })


@app.route("/api/correlation", methods=["GET"])
def get_correlation():
    with app.app_context():
        correlations = correlate_events()

    return jsonify({
        "count": len(correlations),
        "correlations": correlations,
    })


@app.route("/api/investigation", methods=["GET"])
def get_investigation():
    with app.app_context():
        correlations = correlate_events()
        hypotheses = generate_hypotheses(correlations)
        evidence = assess_hypotheses(correlations, hypotheses)

    return jsonify({
        "count": len(correlations),
        "correlations": correlations,
        "hypotheses": hypotheses,
        "evidence": evidence,
    })


@app.route("/api/test-brute-force", methods=["POST"])
def test_brute_force():
    from datetime import datetime, timezone

    from models import SecurityEvent

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

    app.run(debug=True, host="0.0.0.0", port=5000)

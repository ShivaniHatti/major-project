import hmac
import json
import os
import secrets
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, jsonify, request, session
from flask_cors import CORS
from sqlalchemy import inspect, text

from agent_security.activity_monitor import record_activity
from agent_security.policy_checker import evaluate_agent_policy
from collectors.file_collector import FileCollector
from config import Config
from detection.event_correlation import correlate_events
from extensions import db
from services.detection_service import evaluate_security_alerts
from investigation.hypothesis_engine import generate_hypotheses
from investigation.investigation_agent import run_investigation_cycle
from investigation.nbe_engine import select_next_best_tool
from reports.report_generator import generate_investigation_report
from models import AgentRegistration, SecurityEvent, SourceRegistration, User
from services.event_service import create_security_event, get_all_events, get_event_stats, ingest_events


def create_default_roles():
    roles = {
        "administrator": {
            "name": "administrator",
            "description": "Full system administration role.",
        },
        "security_analyst": {
            "name": "security_analyst",
            "description": "Investigation and security monitoring role.",
        },
    }
    return roles


SUPPORTED_ROLES = set(create_default_roles().keys())


def normalize_role(role_value):
    value = str(role_value or "").strip().lower()
    aliases = {
        "admin": "administrator",
        "administrator": "administrator",
        "analyst": "security_analyst",
        "investigator": "security_analyst",
        "securityanalyst": "security_analyst",
        "security_analyst": "security_analyst",
    }
    if value in SUPPORTED_ROLES:
        return value
    return aliases.get(value, "security_analyst")


def ensure_user_schema():
    inspector = inspect(db.engine)
    if "users" not in inspector.get_table_names():
        return
    columns = [column["name"] for column in inspector.get_columns("users")]
    if "email" not in columns:
        db.session.execute(text("ALTER TABLE users ADD COLUMN email VARCHAR(120) DEFAULT NULL"))
    if "status" not in columns:
        db.session.execute(text("ALTER TABLE users ADD COLUMN status VARCHAR(32) DEFAULT 'active'"))
    db.session.commit()


def migrate_legacy_roles():
    ensure_user_schema()
    for user in User.query.all():
        user.role = normalize_role(user.role)
        if user.role not in SUPPORTED_ROLES:
            user.role = "security_analyst"
        if not user.email:
            user.email = user.username + "@sentinelx.local"
        if not user.status:
            user.status = "active"
    db.session.commit()


def _cors_origins():
    raw = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
    origins = [origin.strip() for origin in raw.split(",") if origin.strip()]
    return origins or ["http://localhost:5173", "http://127.0.0.1:5173"]


app = Flask(__name__)
app.config.from_object(Config)
Config.validate()
app.config["JSON_SORT_KEYS"] = False

CORS(app, supports_credentials=True, resources={r"/api/*": {"origins": _cors_origins()}})
db.init_app(app)


def get_bootstrap_admin_credentials():
    sentinel_username = (os.getenv("SENTINELX_BOOTSTRAP_ADMIN_USERNAME") or "").strip()
    legacy_username = (os.getenv("BOOTSTRAP_ADMIN_USERNAME") or "").strip()
    sentinel_password = (os.getenv("SENTINELX_BOOTSTRAP_ADMIN_PASSWORD") or "").strip()
    legacy_password = (os.getenv("BOOTSTRAP_ADMIN_PASSWORD") or "").strip()

    if (sentinel_username or sentinel_password) and not (sentinel_username and sentinel_password):
        raise RuntimeError("Bootstrap administrator configuration requires both username and password when either value is provided.")
    if (legacy_username or legacy_password) and not (legacy_username and legacy_password):
        raise RuntimeError("Bootstrap administrator configuration requires both username and password when either value is provided.")

    username = sentinel_username or legacy_username
    password = sentinel_password or legacy_password
    return username, password


def ensure_bootstrap_administrator():
    """Create the first administrator only when environment bootstrap credentials are supplied.

    This is intentionally server-side and not exposed through public registration. It does not
    overwrite an existing administrator account on subsequent startup. Production requires the
    environment to supply complete and valid bootstrap credentials; local development may omit them
    as long as the app is not running in a production configuration.
    """
    username, password = get_bootstrap_admin_credentials()
    username = username.strip()
    password = password.strip()

    if bool(username) != bool(password):
        raise RuntimeError("Bootstrap administrator configuration requires both username and password when either value is provided.")

    if not username and not password:
        if Config.is_production():
            raise RuntimeError("Production requires bootstrap administrator credentials to be configured.")
        return None

    if not username.strip():
        raise ValueError("Bootstrap administrator username cannot be empty.")

    if len(password) < 12:
        raise ValueError("Bootstrap administrator password must be at least 12 characters long.")

    existing_admin = User.query.filter_by(role="administrator").first()
    if existing_admin is not None:
        return existing_admin

    email = "%s@sentinelx.local" % username
    admin_user = User(username=username, email=email, role="administrator", status="active")
    admin_user.set_password(password)
    db.session.add(admin_user)
    db.session.commit()
    return admin_user


def ensure_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


@app.before_request
def enforce_csrf_for_authenticated_mutations():
    excluded_paths = {
        "/api/register",
        "/api/auth/register",
        "/api/login",
        "/api/auth/login",
        "/api/logout",
        "/api/auth/logout",
    }
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return None
    if request.path in excluded_paths:
        return None
    if "user_id" not in session:
        return None

    token = request.headers.get("X-CSRFToken") or request.form.get("csrf_token") or request.values.get("csrf_token")
    expected = session.get("csrf_token")
    if not expected or not token or not hmac.compare_digest(token, expected):
        return jsonify({"error": "CSRF token missing or invalid."}), 403
    return None


with app.app_context():
    create_default_roles()
    db.create_all()
    migrate_legacy_roles()
    ensure_bootstrap_administrator()


def require_auth(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required."}), 401
        user = User.query.get(session["user_id"])
        if user is None or user.status != "active":
            session.clear()
            return jsonify({"error": "Authentication required."}), 401
        return func(*args, **kwargs)
    return wrapper


def login_required(func):
    return require_auth(func)


def require_roles(*roles):
    roles = tuple(normalize_role(role) for role in roles)

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_id = session.get("user_id")
            if user_id is None:
                return jsonify({"error": "Authentication required."}), 401
            user = User.query.get(user_id)
            if user is None:
                return jsonify({"error": "User not found."}), 401
            if user.status != "active":
                session.clear()
                return jsonify({"error": "Authentication required."}), 401
            normalized_role = normalize_role(user.role)
            if normalized_role not in roles:
                return jsonify({"error": "Forbidden.", "required_roles": list(roles), "user_role": normalized_role}), 403
            return func(*args, **kwargs)
        return wrapper
    return decorator


def role_required(*roles):
    return require_roles(*roles)


def require_admin():
    user_id = session.get("user_id")
    if user_id is None:
        return jsonify({"error": "Authentication required."}), 401
    user = User.query.get(user_id)
    if user is None:
        return jsonify({"error": "User not found."}), 401
    if normalize_role(user.role) != "administrator":
        return jsonify({"error": "Forbidden.", "required_role": "administrator", "user_role": normalize_role(user.role)}), 403
    return None


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "project": "SentinelX",
        "message": "SentinelX Backend is running",
    })


@app.route("/health", methods=["GET"])
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "service": "SentinelX Backend",
    })


def _validate_registration_payload(payload):
    username = str(payload.get("username") or "").strip()
    email = str(payload.get("email") or "").strip()
    password = payload.get("password")
    if not username or not password:
        return None, None, None, jsonify({"error": "username and password are required."}), 400
    if User.query.filter_by(username=username).first():
        return None, None, None, jsonify({"error": "User already exists."}), 409
    if not email:
        email = "%s@sentinelx.local" % username
    if User.query.filter_by(email=email).first():
        return None, None, None, jsonify({"error": "Email already exists."}), 409
    if len(password) < 8:
        return None, None, None, jsonify({"error": "Password must be at least 8 characters long."}), 400
    return username, email, password, None, None


@app.route("/api/auth/register", methods=["POST"])
@app.route("/api/register", methods=["POST"])
def register_user():
    payload = request.get_json(silent=True) or {}
    payload.pop("role", None)
    username, email, password, error_response, status_code = _validate_registration_payload(payload)
    if error_response is not None:
        return error_response, status_code

    user = User(username=username, email=email, role="security_analyst")
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    session.clear()
    session["user_id"] = user.id
    session.permanent = True
    csrf_token = ensure_csrf_token()
    response = jsonify({"message": "User registered successfully.", "user": user.to_dict(), "csrf_token": csrf_token})
    response.set_cookie("csrf_token", csrf_token, httponly=True, samesite="Lax", secure=app.config.get("SESSION_COOKIE_SECURE", False))
    return response, 201


@app.route("/api/auth/login", methods=["POST"])
@app.route("/api/login", methods=["POST"])
def login_user():
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", "")).strip()
    email = str(payload.get("email", "")).strip()
    password = payload.get("password")
    if not (username or email) or not password:
        return jsonify({"error": "username or email and password are required."}), 400
    user = User.query.filter((User.username == username) | (User.email == email)).first() if (username or email) else None
    if user is None or not user.check_password(password):
        return jsonify({"error": "Invalid username or password."}), 401
    if user.status != "active":
        return jsonify({"error": "Account is inactive or disabled."}), 403
    session.clear()
    session["user_id"] = user.id
    session.permanent = True
    csrf_token = ensure_csrf_token()
    response = jsonify({"message": "Login successful.", "user": user.to_dict(), "csrf_token": csrf_token})
    response.set_cookie("csrf_token", csrf_token, httponly=True, samesite="Lax", secure=app.config.get("SESSION_COOKIE_SECURE", False))
    return response


@app.route("/api/auth/logout", methods=["POST"])
@app.route("/api/logout", methods=["POST"])
def logout_user():
    session.clear()
    response = jsonify({"message": "Logged out successfully."})
    response.set_cookie("csrf_token", "", expires=0, httponly=True, samesite="Lax", secure=app.config.get("SESSION_COOKIE_SECURE", False))
    return response


@app.route("/api/auth/me", methods=["GET"])
@app.route("/api/me", methods=["GET"])
@login_required
def get_current_user():
    user = User.query.get(session["user_id"])
    if user is None:
        return jsonify({"error": "User not found."}), 404
    csrf_token = ensure_csrf_token()
    response = jsonify({"user": user.to_dict(), "csrf_token": csrf_token})
    response.set_cookie("csrf_token", csrf_token, httponly=True, samesite="Lax", secure=app.config.get("SESSION_COOKIE_SECURE", False))
    return response


@app.route("/api/admin/users", methods=["GET"])
@login_required
@role_required("administrator")
def list_users():
    users = User.query.order_by(User.id.asc()).all()
    return jsonify({"count": len(users), "users": [user.to_dict() for user in users]})


@app.route("/api/admin/users/<int:user_id>", methods=["GET", "PATCH"])
@login_required
@role_required("administrator")
def manage_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == "GET":
        return jsonify({"user": user.to_dict()})
    payload = request.get_json(silent=True) or {}
    if "status" in payload:
        user.status = str(payload["status"]).strip().lower()
    if "role" in payload:
        requested_role = normalize_role(payload["role"])
        if requested_role not in SUPPORTED_ROLES:
            return jsonify({"error": "Unsupported role.", "supported_roles": sorted(SUPPORTED_ROLES)}), 400
        if user.id == session["user_id"] and requested_role != "administrator":
            return jsonify({"error": "Self-role changes are restricted."}), 400
        user.role = requested_role
    db.session.commit()
    return jsonify({"message": "User updated successfully.", "user": user.to_dict()})


@app.route("/api/events", methods=["POST"])
def create_event():
    data = request.get_json(silent=True) or {}

    try:
        event = create_security_event(data)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify({
        "message": "Security event saved",
        "event": event.to_dict(),
    }), 201


@app.route("/api/events", methods=["GET"])
def get_events():
    events = get_all_events()

    return jsonify({
        "count": len(events),
        "events": [event.to_dict() for event in events],
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
        "events": [event.to_dict() for event in stored_events],
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
        "events": [event.to_dict() for event in stored_events],
    }), 201


@app.route("/api/detect", methods=["GET"])
@app.route("/api/alerts", methods=["GET"])
def run_detection():
    with app.app_context():
        alerts = evaluate_security_alerts()

    return jsonify({
        "alert_count": len(alerts),
        "alerts": alerts,
    })


@app.route("/api/correlation", methods=["GET"])
def get_correlation():
    with app.app_context():
        correlations = correlate_events()

    return jsonify({
        "count": len(correlations),
        "correlations": correlations,
    })


@app.route("/api/investigation", methods=["GET", "POST"])
def get_investigation():
    payload = request.get_json(silent=True) or {}
    incident = payload.get("incident") or payload or {}
    context = payload.get("context") or {}
    with app.app_context():
        correlations = correlate_events()
        hypotheses = generate_hypotheses(correlations)
        investigation = run_investigation_cycle(incident, context=context)

    return jsonify({
        "count": len(correlations),
        "correlations": correlations,
        "hypotheses": hypotheses,
        "evidence": investigation.get("evidence_assessment"),
        "tool_selection": investigation.get("tool_selection"),
        "missing_evidence": investigation.get("missing_evidence"),
    })


@app.route("/api/investigation/tool-selection", methods=["POST"])
@login_required
@role_required("security_analyst", "administrator")
def tool_selection_endpoint():
    payload = request.get_json(silent=True) or {}
    incident = payload.get("incident") or {}
    context = payload.get("context") or {}
    evidence = payload.get("evidence")
    available_tools = payload.get("available_tools")
    failed_tools = payload.get("failed_tools") or []
    selection = select_next_best_tool(incident, evidence=evidence, context=context, available_tools=available_tools, failed_tools=failed_tools)
    return jsonify(selection)


@app.route("/api/reports", methods=["POST"])
@login_required
@role_required("security_analyst", "administrator")
def generate_report_endpoint():
    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return jsonify({"error": "A valid JSON object is required."}), 400

    incident = payload.get("incident") or {}
    context = payload.get("context") or {}
    evidence = payload.get("evidence")
    available_tools = payload.get("available_tools")
    failed_tools = payload.get("failed_tools") or []

    if not isinstance(incident, dict) or not isinstance(context, dict):
        return jsonify({"error": "incident and context must be JSON objects."}), 400

    if evidence is not None and not isinstance(evidence, list):
        return jsonify({"error": "evidence must be a JSON array."}), 400

    if available_tools is not None and not isinstance(available_tools, list):
        return jsonify({"error": "available_tools must be a JSON array."}), 400

    if not isinstance(failed_tools, list):
        return jsonify({"error": "failed_tools must be a JSON array."}), 400

    try:
        report = generate_investigation_report(
            incident=incident,
            context=context,
            evidence=evidence,
            available_tools=available_tools,
            failed_tools=failed_tools,
        )
        return jsonify(report), 200
    except Exception:
        app.logger.exception("Investigation report generation failed.")
        return jsonify({"error": "Unable to generate investigation report."}), 500


@app.route("/api/sources", methods=["GET", "POST"])
@login_required
def handle_sources():
    if request.method == "GET":
        sources = SourceRegistration.query.order_by(SourceRegistration.id.desc()).all()
        return jsonify({"count": len(sources), "sources": [source.to_dict() for source in sources]})

    admin_check = require_admin()
    if admin_check is not None:
        return admin_check

    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name") or "").strip()
    source_type = str(payload.get("source_type") or "file").strip().lower()
    status = str(payload.get("status") or "active").strip().lower()
    if not name:
        return jsonify({"error": "Source name is required."}), 400
    allowed_types = {"file", "linux", "windows", "syslog"}
    if source_type not in allowed_types:
        return jsonify({"error": "Unsupported source type. Supported types: file, linux, windows, syslog."}), 400
    if status not in {"active", "inactive"}:
        status = "active"
    existing = SourceRegistration.query.filter_by(name=name).first()
    if existing:
        return jsonify({"error": "Source already registered.", "source": existing.to_dict()}), 409
    source = SourceRegistration(
        name=name,
        source_type=source_type,
        status=status,
        source_metadata=json.dumps(payload.get("metadata") or {}),
    )
    db.session.add(source)
    db.session.commit()
    return jsonify({"message": "Source registered successfully.", "source": source.to_dict()}), 201


@app.route("/api/sources/<int:source_id>", methods=["GET", "PATCH", "DELETE"])
@login_required
def handle_single_source(source_id):
    source = SourceRegistration.query.get_or_404(source_id)
    if request.method == "GET":
        return jsonify({"source": source.to_dict()})

    admin_check = require_admin()
    if admin_check is not None:
        return admin_check

    if request.method == "DELETE":
        db.session.delete(source)
        db.session.commit()
        return jsonify({"message": "Source removed successfully."})

    payload = request.get_json(silent=True) or {}
    if "name" in payload and payload["name"]:
        source.name = str(payload["name"]).strip()
    if "source_type" in payload and payload["source_type"]:
        source_type = str(payload["source_type"]).strip().lower()
        if source_type not in {"file", "linux", "windows", "syslog"}:
            return jsonify({"error": "Unsupported source type."}), 400
        source.source_type = source_type
    if "status" in payload and payload["status"]:
        status = str(payload["status"]).strip().lower()
        if status not in {"active", "inactive"}:
            return jsonify({"error": "Status must be either active or inactive."}), 400
        source.status = status
    if "metadata" in payload:
        source.source_metadata = json.dumps(payload.get("metadata") or {})
    db.session.commit()
    return jsonify({"message": "Source updated successfully.", "source": source.to_dict()})


@app.route("/api/agents", methods=["GET", "POST"])
@login_required
def handle_agents():
    if request.method == "GET":
        agents = AgentRegistration.query.order_by(AgentRegistration.id.desc()).all()
        return jsonify({"count": len(agents), "agents": [agent.to_dict() for agent in agents]})

    admin_check = require_admin()
    if admin_check is not None:
        return admin_check

    payload = request.get_json(silent=True) or {}
    agent_id = str(payload.get("agent_id") or "").strip()
    name = str(payload.get("name") or "").strip()
    if not agent_id or not name:
        return jsonify({"error": "agent_id and name are required."}), 400
    if AgentRegistration.query.filter_by(agent_id=agent_id).first():
        return jsonify({"error": "Agent ID already exists."}), 409
    policy = payload.get("security_policy") or {}
    status = str(payload.get("status") or "active").strip().lower()
    health = str(payload.get("health") or "healthy").strip().lower()
    allowed_status = {"active", "inactive", "suspended"}
    allowed_health = {"healthy", "degraded", "unhealthy", "critical"}
    if status not in allowed_status:
        status = "active"
    if health not in allowed_health:
        health = "healthy"
    allowed, message = evaluate_agent_policy(agent_id, payload.get("action") or "collect_evidence", status=status, health=health, metadata=policy)
    if not allowed:
        return jsonify({"error": "Agent registration denied.", "details": message}), 403
    agent = AgentRegistration(
        agent_id=agent_id,
        name=name,
        role=normalize_role(payload.get("role") or "security_analyst"),
        status=status,
        health=health,
        agent_metadata=json.dumps(payload.get("metadata") or {}),
        security_policy=json.dumps(policy),
    )
    db.session.add(agent)
    db.session.commit()
    record_activity(agent_id, "register", "success", {"name": name})
    return jsonify({"message": "Agent registered successfully.", "agent": agent.to_dict()}), 201


@app.route("/api/agents/<int:agent_id>", methods=["GET", "PATCH", "DELETE"])
@login_required
def handle_single_agent(agent_id):
    agent = AgentRegistration.query.get_or_404(agent_id)
    if request.method == "GET":
        return jsonify({"agent": agent.to_dict()})

    admin_check = require_admin()
    if admin_check is not None:
        return admin_check

    if request.method == "DELETE":
        db.session.delete(agent)
        db.session.commit()
        return jsonify({"message": "Agent removed successfully."})

    payload = request.get_json(silent=True) or {}
    if "status" in payload:
        status = str(payload["status"]).strip().lower()
        if status not in {"active", "inactive", "suspended"}:
            return jsonify({"error": "Status must be active, inactive, or suspended."}), 400
        agent.status = status
    if "health" in payload:
        health = str(payload["health"]).strip().lower()
        if health not in {"healthy", "degraded", "unhealthy", "critical"}:
            return jsonify({"error": "Invalid health state."}), 400
        agent.health = health
    if "metadata" in payload:
        agent.agent_metadata = json.dumps(payload.get("metadata") or {})
    if "security_policy" in payload:
        agent.security_policy = json.dumps(payload.get("security_policy") or {})
    if "last_seen" in payload:
        try:
            agent.last_seen = datetime.strptime(payload["last_seen"], "%Y-%m-%dT%H:%M:%S.%f%z")
        except (TypeError, ValueError):
            try:
                agent.last_seen = datetime.strptime(payload["last_seen"], "%Y-%m-%dT%H:%M:%S%z")
            except (TypeError, ValueError):
                pass
    db.session.commit()
    return jsonify({"message": "Agent updated successfully.", "agent": agent.to_dict()})


@app.route("/api/agents/<string:agent_uuid>/heartbeat", methods=["POST"])
@login_required
def agent_heartbeat(agent_uuid):
    agent = AgentRegistration.query.filter_by(agent_id=agent_uuid).first_or_404()
    payload = request.get_json(silent=True) or {}
    agent.last_seen = datetime.now(timezone.utc)
    agent.health = str(payload.get("health") or agent.health).strip().lower()
    if agent.health not in {"healthy", "degraded", "unhealthy", "critical"}:
        agent.health = "healthy"
    record_activity(agent_uuid, "heartbeat", "success", payload)
    db.session.commit()
    return jsonify({"message": "Heartbeat recorded.", "agent": agent.to_dict()})


@app.route("/api/test-brute-force", methods=["POST"])
def test_brute_force():
    from models import SecurityEvent

    for i in range(5):
        event = SecurityEvent(
            source="simulation",
            event_type="failed_login",
            username="testuser",
            source_ip="192.168.1.100",
            hostname="test-machine",
            message="Simulated failed login attempt {0}".format(i + 1),
            severity="warning",
            event_time=datetime.now(timezone.utc),
        )
        db.session.add(event)

    db.session.commit()

    return {
        "message": "Five failed login events inserted successfully",
        "username": "testuser",
        "attempts": 5,
    }


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0", port=5000)

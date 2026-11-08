import json
import os
import shutil
import uuid
from datetime import datetime

from flask import (
    Flask, render_template, request, jsonify, redirect,
    url_for, flash, abort, send_file
)
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import func

from models import (
    db, Device, ScanSession, AppRecord, Contact, SmsRecord,
    CallRecord, ScannedFile, DnsEvent, Threat, UploadedFile,
    SyncedFolder, SyncedFile, FileRequest,
)
from analyzer import analyze, analyze_file


# ============================================================
#  Конфигурация
# ============================================================
class Config:
    SECRET_KEY = os.environ.get("GRAPHENE_SECRET", "change-me-graphene-lab")
    SQLALCHEMY_DATABASE_URI = "sqlite:///graphene.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ADMIN_USERNAME = os.environ.get("GRAPHENE_ADMIN_USER", "admin")
    _ADMIN_HASH = os.environ.get("GRAPHENE_ADMIN_HASH")
    ADMIN_PASSWORD_HASH = _ADMIN_HASH or generate_password_hash("graphene2024")
    MAX_CONTENT_LENGTH = 110 * 1024 * 1024


app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Требуется вход"

UPLOAD_DIR = os.path.join(app.instance_path, "uploads")
os.makedirs(os.path.join(UPLOAD_DIR, "tmp"), exist_ok=True)

MAX_FILE_BYTES = 100 * 1024 * 1024


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


@app.template_filter("filesize")
def filesize_filter(n):
    if not n:
        return "0 B"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ============================================================
#  API клиента — телеметрия
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
#  API клиента — синхронизация папок
# ============================================================
@app.route("/api/v1/sync/folders", methods=["POST"])
def api_sync_folders():
    data = request.get_json(force=True) or {}
    device_id = (data.get("device_id") or "").strip()
    if not device_id:
        return jsonify({"error": "device_id required"}), 400

    folders = data.get("folders") or []
    incoming_uris = {f.get("uri") for f in folders if f.get("uri")}

    # удалить папки, которых больше нет
    for existing in SyncedFolder.query.filter_by(device_id=device_id).all():
        if existing.folder_uri not in incoming_uris:
            SyncedFile.query.filter_by(folder_id=existing.id).delete()
            db.session.delete(existing)

    db.session.flush()

    existing_map = {f.folder_uri: f for f in SyncedFolder.query.filter_by(device_id=device_id).all()}
    for fd in folders:
        uri = fd.get("uri")
        if not uri:
            continue
        rec = existing_map.get(uri)
        if not rec:
            rec = SyncedFolder(device_id=device_id, folder_uri=uri)
            db.session.add(rec)
        rec.display_name = (fd.get("name") or "")[:255]

    db.session.commit()
    return jsonify({"ok": True, "count": len(folders)})


@app.route("/api/v1/sync/files", methods=["POST"])
def api_sync_files():
    data = request.get_json(force=True) or {}
    device_id = (data.get("device_id") or "").strip()
    if not device_id:
        return jsonify({"error": "device_id required"}), 400

    files = data.get("files") or []
    folder_map = {f.folder_uri: f for f in SyncedFolder.query.filter_by(device_id=device_id).all()}

    SyncedFile.query.filter_by(device_id=device_id).delete()

    now = datetime.utcnow()
    added = 0
    for fd in files:
        uri = fd.get("folder_uri")
        folder = folder_map.get(uri)
        if not folder:
            continue
        db.session.add(SyncedFile(
            device_id=device_id,
            folder_id=folder.id,
            relative_path=(fd.get("relative_path") or "")[:2048],
            name=(fd.get("name") or "")[:255],
            size=fd.get("size") or 0,
            sha256=(fd.get("sha256") or "")[:64] or None,
            modified=fd.get("modified") or 0,
            mime=(fd.get("mime") or "")[:64],
            last_seen=now,
        ))
        added += 1

    for f in folder_map.values():
        f.last_scan = now

    db.session.commit()
    return jsonify({"ok": True, "count": added})


@app.route("/api/v1/sync/pending")
def api_sync_pending():
    device_id = (request.args.get("device_id") or "").strip()
    if not device_id:
        return jsonify({"error": "device_id required"}), 400

    pending = (FileRequest.query
               .filter_by(device_id=device_id, status="pending")
               .order_by(FileRequest.created_at)
               .limit(20).all())

    return jsonify({
        "requests": [
            {
                "request_id": r.request_id,
                "relative_path": r.relative_path,
                "file_name": r.file_name,
            }
            for r in pending
        ]
    })


# ============================================================
#  Загрузка файла (клиент → сервер)
# ============================================================
@app.route("/api/v1/upload", methods=["POST"])
def api_upload():
    device_id = (request.form.get("device_id") or "").strip()
    if not device_id:
        return jsonify({"error": "device_id required"}), 400

    file = request.files.get("file")
    if not file or not file.filename:
        return jsonify({"error": "file required"}), 400

    request_id = (request.form.get("request_id") or "").strip()
    relative_path = (request.form.get("relative_path") or "").strip()

    try:
        record = _process_uploaded_file(
            file,
            uploaded_by=f"api:{device_id}",
            relative_path=relative_path,
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"analysis failed: {e}"}), 500

    if request_id:
        req = FileRequest.query.filter_by(request_id=request_id).first()
        if req and req.device_id == device_id and req.status == "pending":
            req.status = "sent"
            req.fulfilled_at = datetime.utcnow()
            req.upload_id = record.upload_id

    if relative_path:
        sf = SyncedFile.query.filter_by(
            device_id=device_id, relative_path=relative_path
        ).first()
        if sf:
            sf.upload_id = record.upload_id

    db.session.commit()

    return jsonify({
        "upload_id": record.upload_id,
        "sha256": record.sha256,
        "file_type": record.file_type,
        "severity": record.severity,
        "risk_score": record.risk_score,
        "detections": json.loads(record.detections or "[]"),
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
#  Дашборд
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
    uploaded_count = UploadedFile.query.count()
    pending_requests = FileRequest.query.filter_by(status="pending").count()

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
        uploaded_count=uploaded_count,
        pending_requests=pending_requests,
    )

@app.route("/devices")
@login_required
def devices():
    devs = Device.query.order_by(Device.last_seen.desc()).all()
    ids = [d.device_id for d in devs]

    folder_counts, file_counts, pending_counts, sent_counts = {}, {}, {}, {}
    if ids:
        folder_counts = dict(
            db.session.query(SyncedFolder.device_id, func.count(SyncedFolder.id))
            .filter(SyncedFolder.device_id.in_(ids))
            .group_by(SyncedFolder.device_id).all()
        )
        file_counts = dict(
            db.session.query(SyncedFile.device_id, func.count(SyncedFile.id))
            .filter(SyncedFile.device_id.in_(ids))
            .group_by(SyncedFile.device_id).all()
        )
        pending_counts = dict(
            db.session.query(FileRequest.device_id, func.count(FileRequest.id))
            .filter(FileRequest.device_id.in_(ids), FileRequest.status == "pending")
            .group_by(FileRequest.device_id).all()
        )
        sent_counts = dict(
            db.session.query(FileRequest.device_id, func.count(FileRequest.id))
            .filter(FileRequest.device_id.in_(ids), FileRequest.status == "sent")
            .group_by(FileRequest.device_id).all()
        )

    return render_template(
        "devices.html",
        devices=devs,
        folder_counts=folder_counts,
        file_counts=file_counts,
        pending_counts=pending_counts,
        sent_counts=sent_counts,
    )


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

    folders = SyncedFolder.query.filter_by(device_id=device_id).all()
    synced_files = (SyncedFile.query
                    .filter_by(device_id=device_id)
                    .order_by(SyncedFile.relative_path).all())

    device_requests = (FileRequest.query
                       .filter_by(device_id=device_id)
                       .order_by(FileRequest.created_at.desc())
                       .limit(50).all())

    # Для каждой строки файла: pending-запрос (если есть) и последний выполненный
    pending_by_path = {}
    last_sent_by_path = {}
    for r in FileRequest.query.filter_by(device_id=device_id).all():
        if r.status == "pending":
            pending_by_path.setdefault(r.relative_path, r)
        elif r.status == "sent" and r.upload_id:
            prev = last_sent_by_path.get(r.relative_path)
            if not prev or (r.fulfilled_at and r.fulfilled_at > (prev.fulfilled_at or r.created_at)):
                last_sent_by_path[r.relative_path] = r

    return render_template(
        "device_detail.html",
        device=device, apps=apps, contacts=contacts, sms=sms,
        calls=calls, files=files, dns=dns, threats=threats, scans=scans,
        folders=folders, synced_files=synced_files,
        device_requests=device_requests,
        pending_by_path=pending_by_path,
        last_sent_by_path=last_sent_by_path,
    )

@app.route("/devices/<device_id>/request-file", methods=["POST"])
@login_required
def request_file(device_id):
    device = Device.query.filter_by(device_id=device_id).first_or_404()
    relative_path = (request.form.get("relative_path") or "").strip()
    if not relative_path:
        flash("Путь не указан")
        return redirect(url_for("device_detail", device_id=device_id))

    sf = SyncedFile.query.filter_by(device_id=device_id, relative_path=relative_path).first()
    if not sf:
        flash("Файл не найден в синхронизированных папках")
        return redirect(url_for("device_detail", device_id=device_id))

    existing = (FileRequest.query
                .filter_by(device_id=device_id, relative_path=relative_path, status="pending")
                .first())
    if existing:
        flash("Запрос на этот файл уже в очереди")
        return redirect(url_for("device_detail", device_id=device_id))

    req = FileRequest(
        request_id=str(uuid.uuid4()),
        device_id=device_id,
        relative_path=relative_path,
        file_name=sf.name[:255] if sf.name else relative_path.split("/")[-1][:255],
        created_by=current_user.id,
        status="pending",
    )
    db.session.add(req)
    db.session.commit()
    flash(f"Запрос создан: {req.file_name}")
    return redirect(url_for("device_detail", device_id=device_id))


@app.route("/devices/<device_id>/request/<request_id>/cancel", methods=["POST"])
@login_required
def cancel_request(device_id, request_id):
    req = FileRequest.query.filter_by(request_id=request_id, device_id=device_id).first_or_404()
    if req.status == "pending":
        req.status = "rejected"
        db.session.commit()
        flash("Запрос отменён")
    return redirect(url_for("device_detail", device_id=device_id))


@app.route("/requests")
@login_required
def requests_list():
    items = FileRequest.query.order_by(FileRequest.created_at.desc()).limit(300).all()
    return render_template("requests.html", requests=items)


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
    top_rows = (
        db.session.query(DnsEvent.domain, func.count(DnsEvent.id).label("hits"))
        .group_by(DnsEvent.domain).order_by(func.count(DnsEvent.id).desc())
        .limit(50).all()
    )
    total_domains = db.session.query(func.count(func.distinct(DnsEvent.domain))).scalar() or 0
    total_events = DnsEvent.query.count()
    device_rows = (
        db.session.query(DnsEvent.device_id, func.count(DnsEvent.id).label("hits"))
        .group_by(DnsEvent.device_id).order_by(func.count(DnsEvent.id).desc())
        .limit(15).all()
    )
    return render_template("network.html", top_domains=top_rows,
                          total_domains=total_domains, total_events=total_events,
                          device_rows=device_rows)


# ============================================================
#  Загрузка файлов — админ-панель
# ============================================================
@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        file = request.files.get("file")
        if not file or not file.filename:
            flash("Файл не выбран")
            return redirect(url_for("upload"))
        try:
            record = _process_uploaded_file(file, uploaded_by=current_user.id)
        except ValueError as e:
            flash(str(e))
            return redirect(url_for("upload"))
        except Exception as e:
            flash(f"Ошибка анализа: {e}")
            return redirect(url_for("upload"))
        return redirect(url_for("uploaded_file_detail", upload_id=record.upload_id))

    severity = request.args.get("severity")
    source = request.args.get("source", "all")
    if source not in ("all", "device", "manual"):
        source = "all"

    q = UploadedFile.query
    if severity in ("CLEAN", "LOW", "MEDIUM", "HIGH"):
        q = q.filter_by(severity=severity)
    if source == "device":
        q = q.filter(UploadedFile.uploaded_by.like("api:%"))
    elif source == "manual":
        q = q.filter(~UploadedFile.uploaded_by.like("api:%"))

    files = q.order_by(UploadedFile.uploaded_at.desc()).limit(200).all()

    total_count = UploadedFile.query.count()
    device_count = UploadedFile.query.filter(UploadedFile.uploaded_by.like("api:%")).count()
    manual_count = total_count - device_count

    # Обогащаем каждую запись источником: устройство или admin
    device_cache = {}
    rows = []
    for f in files:
        src = {"kind": "manual", "label": f.uploaded_by or "admin", "device_id": None}
        if f.uploaded_by and f.uploaded_by.startswith("api:"):
            dev_id = f.uploaded_by[4:]
            if dev_id not in device_cache:
                dev = Device.query.filter_by(device_id=dev_id).first()
                device_cache[dev_id] = (
                    f"{dev.manufacturer} {dev.model}".strip()
                    if dev else dev_id[:12] + "…"
                )
            src = {"kind": "device", "label": device_cache[dev_id], "device_id": dev_id}
        rows.append({"file": f, "source": src})

    return render_template(
        "upload.html",
        rows=rows,
        active_severity=severity,
        active_source=source,
        total_count=total_count,
        device_count=device_count,
        manual_count=manual_count,
    )

@app.route("/upload/<upload_id>")
@login_required
def uploaded_file_detail(upload_id):
    record = UploadedFile.query.filter_by(upload_id=upload_id).first_or_404()
    detections = json.loads(record.detections) if record.detections else []
    return render_template("uploaded_detail.html", record=record, detections=detections)


@app.route("/upload/<upload_id>/download")
@login_required
def download_uploaded(upload_id):
    record = UploadedFile.query.filter_by(upload_id=upload_id).first_or_404()
    if not record.stored_path or not os.path.exists(record.stored_path):
        abort(404)
    return send_file(record.stored_path, as_attachment=True,
                     download_name=record.original_name)


@app.route("/upload/<upload_id>/delete", methods=["POST"])
@login_required
def delete_uploaded(upload_id):
    record = UploadedFile.query.filter_by(upload_id=upload_id).first_or_404()
    if record.stored_path and os.path.exists(record.stored_path):
        try:
            os.remove(record.stored_path)
        except Exception:
            pass
    db.session.delete(record)
    db.session.commit()
    flash("Файл удалён")
    return redirect(url_for("upload"))


# ============================================================
#  Внутренняя обработка
# ============================================================
def _process_uploaded_file(file, uploaded_by: str, relative_path: str = "") -> UploadedFile:
    upload_id = str(uuid.uuid4())
    tmp_path = os.path.join(UPLOAD_DIR, "tmp", upload_id + ".bin")
    file.save(tmp_path)

    size = os.path.getsize(tmp_path)
    if size == 0:
        os.remove(tmp_path)
        raise ValueError("Пустой файл")
    if size > MAX_FILE_BYTES:
        os.remove(tmp_path)
        raise ValueError(f"Файл больше {MAX_FILE_BYTES // (1024 * 1024)} MB")

    try:
        result = analyze_file(tmp_path, file.filename)
    except Exception:
        os.remove(tmp_path)
        raise

    sha = result["sha256"]
    hash_dir = os.path.join(UPLOAD_DIR, sha[:2], sha[2:4])
    os.makedirs(hash_dir, exist_ok=True)
    final_path = os.path.join(hash_dir, sha + ".bin")

    if os.path.exists(final_path):
        os.remove(tmp_path)
    else:
        shutil.move(tmp_path, final_path)

    record = UploadedFile(
        upload_id=upload_id,
        original_name=file.filename[:255],
        relative_path=(relative_path[:2048] if relative_path else None),
        sha256=sha,
        size=size,
        file_type=result["file_type"],
        severity=result["severity"],
        risk_score=result["risk_score"],
        detections=json.dumps(result["detections"], ensure_ascii=False),
        stored_path=final_path,
        uploaded_by=uploaded_by,
    )
    db.session.add(record)
    db.session.flush()
    return record


@app.errorhandler(413)
def too_large(_e):
    return "Файл слишком большой (максимум 100 MB)", 413


# ============================================================
#  Init
# ============================================================
with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
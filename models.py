from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class Device(db.Model):
    __tablename__ = "devices"
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(64), unique=True, index=True)
    manufacturer = db.Column(db.String(64))
    model = db.Column(db.String(64))
    android_version = db.Column(db.String(16))
    sdk_int = db.Column(db.Integer)
    security_patch = db.Column(db.String(32))
    rooted = db.Column(db.Boolean, default=False)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_risk_score = db.Column(db.Integer, default=0)


class ScanSession(db.Model):
    __tablename__ = "scan_sessions"
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(64), index=True)
    scan_id = db.Column(db.String(64), unique=True)
    scanned_apps = db.Column(db.Integer, default=0)
    risk_score = db.Column(db.Integer, default=0)
    threats_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AppRecord(db.Model):
    __tablename__ = "apps"
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(64), index=True)
    package_name = db.Column(db.String(255), index=True)
    app_name = db.Column(db.String(255))
    version_name = db.Column(db.String(64))
    target_sdk = db.Column(db.Integer)
    permissions = db.Column(db.Text)          # JSON string
    first_install = db.Column(db.BigInteger)
    last_update = db.Column(db.BigInteger)
    apk_sha256 = db.Column(db.String(64))
    is_sideloaded = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)


class Contact(db.Model):
    __tablename__ = "contacts"
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(64), index=True)
    display_name = db.Column(db.String(255))
    phones = db.Column(db.Text)               # JSON
    emails = db.Column(db.Text)               # JSON
    has_photo = db.Column(db.Boolean, default=False)


class SmsRecord(db.Model):
    __tablename__ = "sms"
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(64), index=True)
    address = db.Column(db.String(64), index=True)
    body_preview = db.Column(db.Text)
    date = db.Column(db.BigInteger)
    type = db.Column(db.Integer)


class CallRecord(db.Model):
    __tablename__ = "calls"
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(64), index=True)
    number = db.Column(db.String(64), index=True)
    type = db.Column(db.Integer)
    date = db.Column(db.BigInteger)
    duration = db.Column(db.BigInteger)


class ScannedFile(db.Model):
    __tablename__ = "files"
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(64), index=True)
    path = db.Column(db.Text)
    size = db.Column(db.BigInteger)
    extension = db.Column(db.String(16))
    sha256 = db.Column(db.String(64), index=True)
    modified = db.Column(db.BigInteger)


class DnsEvent(db.Model):
    __tablename__ = "dns_events"
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(64), index=True)
    domain = db.Column(db.String(255), index=True)
    timestamp = db.Column(db.BigInteger)
    query_type = db.Column(db.Integer)


class Threat(db.Model):
    __tablename__ = "threats"
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(64), index=True)
    scan_id = db.Column(db.String(64))
    package_name = db.Column(db.String(255))
    threat_name = db.Column(db.String(255))
    severity = db.Column(db.String(16))       # LOW / MEDIUM / HIGH
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
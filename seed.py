# seed.py — пересоздаёт БД и заполняет все таблицы демо-данными.
# Запуск:  python3 seed.py
#          python3 seed.py --add      (без drop_all, только добавит новые устройства)
#          python3 seed.py --reset-files  (дополнительно очистит instance/uploads)

import io
import json
import os
import random
import shutil
import sys
import tempfile
import uuid
import zipfile
from datetime import datetime, timedelta

from faker import Faker

from app import app, UPLOAD_DIR
from analyzer import analyze_file
from models import (
    db, Device, ScanSession, AppRecord, Contact, SmsRecord,
    CallRecord, ScannedFile, DnsEvent, Threat,
    SyncedFolder, SyncedFile, FileRequest, UploadedFile,
)

fake = Faker("ru_RU")
random.seed()   # или random.seed(42) для воспроизводимости

# ============================================================
#  Справочники
# ============================================================
MANUFACTURERS = ["Samsung", "Xiaomi", "Google", "OnePlus", "Huawei", "Nokia", "Sony", "Motorola"]
ANDROID_VERSIONS = ["11", "12", "13", "14", "15"]
SDK_INTS = {"11": 30, "12": 31, "13": 33, "14": 34, "15": 35}
SECURITY_PATCHES = ["2024-01-05", "2024-06-01", "2025-02-01", "2025-09-01"]

APP_NAMES = [
    ("com.whatsapp", "WhatsApp"), ("com.telegram.messenger", "Telegram"),
    ("com.android.chrome", "Chrome"), ("com.google.android.gm", "Gmail"),
    ("com.instagram.android", "Instagram"), ("com.vkontakte.android", "VK"),
    ("ru.yandex.music", "Яндекс Музыка"), ("com.sberbankmobile", "СберБанк"),
    ("ru.tinkoff.investing", "Тинькофф Инвестиции"), ("com.google.android.apps.maps", "Google Maps"),
]

PERMISSIONS_POOL = [
    "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
    "android.permission.READ_CONTACTS", "android.permission.READ_SMS",
    "android.permission.SEND_SMS", "android.permission.READ_CALL_LOG",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.INTERNET",
    "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.REQUEST_INSTALL_PACKAGES",
]

DNS_DOMAINS = [
    "google.com", "yandex.ru", "vk.com", "mail.ru", "sberbank.ru",
    "tinkoff.ru", "gosuslugi.ru", "avito.ru", "ozon.ru", "wildberries.ru",
    "login-verify-sber.ru", "secure-update-bank.com", "sms-code-wallet.net",
]

THREAT_NAMES = ["Опасная комбинация разрешений", "Установлено не из Google Play", "Известная сигнатура"]
SEVERITIES = ["LOW", "MEDIUM", "HIGH"]

SYNC_FOLDERS = ["Download", "Documents", "Pictures", "DCIM", "Music"]

MIME_BY_EXT = {
    "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
    "pdf": "application/pdf", "apk": "application/vnd.android.package-archive",
    "zip": "application/zip", "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "mp4": "video/mp4", "exe": "application/x-msdownload",
    "elf": "application/x-executable", "bin": "application/octet-stream",
    "txt": "text/plain",
}


# ============================================================
#  Генераторы для старых моделей
# ============================================================
def random_app():
    pkg, name = random.choice(APP_NAMES)
    perms = random.sample(PERMISSIONS_POOL, k=random.randint(1, 5))
    return {
        "package_name": pkg,
        "app_name": name,
        "version_name": f"{random.randint(1, 5)}.{random.randint(0, 9)}.{random.randint(0, 20)}",
        "target_sdk": random.choice([30, 31, 33, 34, 35]),
        "permissions": json.dumps(perms),
        "first_install": int((datetime.utcnow() - timedelta(days=random.randint(30, 800))).timestamp() * 1000),
        "last_update": int((datetime.utcnow() - timedelta(days=random.randint(0, 30))).timestamp() * 1000),
        "apk_sha256": fake.sha256(),
        "is_sideloaded": random.random() < 0.15,
    }


def random_contact():
    return {
        "display_name": fake.name(),
        "phones": json.dumps([fake.phone_number() for _ in range(random.randint(1, 3))]),
        "emails": json.dumps([fake.email() for _ in range(random.randint(0, 2))]),
        "has_photo": random.choice([True, False]),
    }


def random_sms():
    return {
        "address": fake.phone_number(),
        "body_preview": fake.text(max_nb_chars=random.randint(20, 120)),
        "date": int((datetime.utcnow() - timedelta(days=random.randint(0, 60))).timestamp() * 1000),
        "type": random.choice([1, 2]),
    }


def random_call():
    return {
        "number": fake.phone_number(),
        "type": random.choice([1, 2, 3]),
        "date": int((datetime.utcnow() - timedelta(days=random.randint(0, 90))).timestamp() * 1000),
        "duration": random.randint(0, 3600),
    }


def random_scanned_file():
    ext = random.choice(["jpg", "png", "pdf", "apk", "docx", "mp4"])
    return {
        "path": f"/storage/emulated/0/Download/{fake.file_name(extension=ext)}",
        "size": random.randint(1024, 50 * 1024 * 1024),
        "extension": ext,
        "sha256": fake.sha256(),
        "modified": int((datetime.utcnow() - timedelta(days=random.randint(0, 365))).timestamp() * 1000),
    }


def random_dns_event():
    return {
        "domain": random.choice(DNS_DOMAINS),
        "timestamp": int((datetime.utcnow() - timedelta(hours=random.randint(0, 720))).timestamp() * 1000),
        "query_type": random.choice([1, 28, 16]),
    }


# ============================================================
#  Генерация ФАЙЛОВ НА ДИСКЕ для UploadedFile
# ============================================================
def _make_bytes(kind: str) -> bytes:
    """Создаёт байты с сигнатурой, соответствующей типу kind."""
    if kind == "pdf_js":
        return (b"%PDF-1.4\n1 0 obj<</OpenAction 2 0 R/JS(app.alert(1))>>endobj\n"
                + fake.binary(length=random.randint(500, 4000))
                + b"\n%%EOF")

    if kind == "pdf_clean":
        return (b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
                + fake.binary(length=random.randint(500, 4000))
                + b"\n%%EOF")

    if kind == "zip_exe":
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("readme.txt", fake.text() * 3)
            z.writestr("payload.exe", b"MZ" + fake.binary(length=2000))
            z.writestr("run.bat", b"@echo off\nshutdown /r\n")
        return buf.getvalue()

    if kind == "zip_clean":
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("doc.txt", fake.text() * 5)
            z.writestr("data.json", json.dumps({"k": fake.word()}))
        return buf.getvalue()

    if kind == "apk":
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("AndroidManifest.xml", b"<manifest package='com.example'/>")
            z.writestr("classes.dex", b"dex\n035\x00" + fake.binary(length=3000))
        return buf.getvalue()

    if kind == "exe":
        return b"MZ\x90\x00" + fake.binary(length=random.randint(2000, 6000))

    if kind == "elf":
        return b"\x7fELF" + fake.binary(length=random.randint(2000, 6000))

    if kind == "dex":
        return b"dex\n035\x00" + fake.binary(length=random.randint(2000, 5000))

    # txt
    return (fake.text() * 20).encode("utf-8", errors="ignore")


def _analyze_bytes(data: bytes, filename: str) -> tuple[str, dict]:
    """Сохраняет во временный файл, гоняет analyze_file, возвращает (stored_path, result)."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(data)
        tmp_path = f.name

    result = analyze_file(tmp_path, filename=filename)
    sha = result["sha256"]

    hash_dir = os.path.join(UPLOAD_DIR, sha[:2], sha[2:4])
    os.makedirs(hash_dir, exist_ok=True)
    final_path = os.path.join(hash_dir, sha + ".bin")

    if os.path.exists(final_path):
        os.remove(tmp_path)
    else:
        shutil.move(tmp_path, final_path)

    return final_path, result


def make_uploaded_file(uploaded_by: str, relative_path: str | None, kind: str, name: str) -> UploadedFile:
    """Создаёт физический файл + запись UploadedFile."""
    data = _make_bytes(kind)
    stored_path, result = _analyze_bytes(data, name)

    record = UploadedFile(
        upload_id=str(uuid.uuid4()),
        original_name=name[:255],
        relative_path=(relative_path[:2048] if relative_path else None),
        sha256=result["sha256"],
        size=result["size"],
        file_type=result["file_type"],
        severity=result["severity"],
        risk_score=result["risk_score"],
        detections=json.dumps(result["detections"], ensure_ascii=False),
        stored_path=stored_path,
        uploaded_by=uploaded_by,
        uploaded_at=datetime.utcnow() - timedelta(hours=random.randint(1, 96)),
    )
    db.session.add(record)
    return record


def kind_for_filename(name: str) -> str:
    """Подбираем kind по расширению — чтобы file_type совпадал с именем."""
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else "bin"
    return {
        "apk": "apk",
        "pdf": random.choice(["pdf_js", "pdf_clean"]),
        "zip": random.choice(["zip_exe", "zip_clean"]),
        "exe": "exe",
        "elf": "elf",
        "dex": "dex",
        "jpg": "txt", "jpeg": "txt", "png": "txt", "mp4": "txt",
        "docx": "zip_clean",   # не идеально, но пройдёт как валидный zip
    }.get(ext, "txt")


# ============================================================
#  Синхронизация + запросы для одного устройства
# ============================================================
def seed_sync_for_device(device_id: str):
    # 1) Разрешённые папки
    folder_names = random.sample(SYNC_FOLDERS, k=random.randint(1, 3))
    folders = []
    for fname in folder_names:
        folder = SyncedFolder(
            device_id=device_id,
            folder_uri=f"content://com.android.externalstorage.documents/tree/primary%3A{fname}",
            display_name=fname,
            added_at=datetime.utcnow() - timedelta(days=random.randint(1, 30)),
            last_scan=datetime.utcnow() - timedelta(minutes=random.randint(0, 90)),
        )
        folders.append(folder)
        db.session.add(folder)
    db.session.flush()

    # 2) Файлы в папках
    exts = ["pdf", "apk", "zip", "jpg", "docx", "mp4", "exe", "elf"]
    synced_files: list[SyncedFile] = []
    for folder in folders:
        for _ in range(random.randint(3, 10)):
            ext = random.choice(exts)
            name = f"{fake.word()}_{random.randint(100, 999)}.{ext}"
            sf = SyncedFile(
                device_id=device_id,
                folder_id=folder.id,
                relative_path=name,
                name=name,
                size=random.randint(10 * 1024, 25 * 1024 * 1024),
                sha256=fake.sha256(),
                modified=int((datetime.utcnow() - timedelta(days=random.randint(0, 180))).timestamp() * 1000),
                mime=MIME_BY_EXT.get(ext, "application/octet-stream"),
                last_seen=datetime.utcnow() - timedelta(minutes=random.randint(0, 90)),
            )
            synced_files.append(sf)
            db.session.add(sf)
    db.session.flush()

    # 3) Запросы — pending / sent / rejected
    if not synced_files:
        return

    n_requests = min(len(synced_files), random.randint(1, 5))
    for sf in random.sample(synced_files, k=n_requests):
        roll = random.random()
        created_at = datetime.utcnow() - timedelta(hours=random.randint(2, 96))

        if roll < 0.40:
            # pending — клиент ещё не забрал
            req = FileRequest(
                request_id=str(uuid.uuid4()),
                device_id=device_id,
                relative_path=sf.relative_path,
                file_name=sf.name,
                status="pending",
                created_by="admin",
                created_at=created_at,
            )
            db.session.add(req)

        elif roll < 0.85:
            # sent — файл получен, UploadedFile существует
            record = make_uploaded_file(
                uploaded_by=f"api:{device_id}",
                relative_path=sf.relative_path,
                kind=kind_for_filename(sf.name),
                name=sf.name,
            )
            db.session.flush()
            sf.upload_id = record.upload_id
            req = FileRequest(
                request_id=str(uuid.uuid4()),
                device_id=device_id,
                relative_path=sf.relative_path,
                file_name=sf.name,
                status="sent",
                created_by="admin",
                created_at=created_at,
                fulfilled_at=created_at + timedelta(hours=random.randint(1, 12)),
                upload_id=record.upload_id,
            )
            db.session.add(req)

        else:
            # rejected — отменён админом
            req = FileRequest(
                request_id=str(uuid.uuid4()),
                device_id=device_id,
                relative_path=sf.relative_path,
                file_name=sf.name,
                status="rejected",
                created_by="admin",
                created_at=created_at,
            )
            db.session.add(req)


# ============================================================
#  Одно устройство + всё связанное
# ============================================================
def seed_device(device_index: int) -> str:
    device_id = f"fake-device-{device_index:02d}-{uuid.uuid4().hex[:8]}"
    android = random.choice(ANDROID_VERSIONS)
    rooted = random.random() < 0.2

    device = Device(
        device_id=device_id,
        manufacturer=random.choice(MANUFACTURERS),
        model=f"Model-{fake.bothify(text='??-####').upper()}",
        android_version=android,
        sdk_int=SDK_INTS[android],
        security_patch=random.choice(SECURITY_PATCHES),
        rooted=rooted,
        first_seen=datetime.utcnow() - timedelta(days=random.randint(10, 300)),
        last_seen=datetime.utcnow() - timedelta(minutes=random.randint(0, 1440)),
        last_risk_score=0,
    )
    db.session.add(device)

    apps = [AppRecord(device_id=device_id, **random_app()) for _ in range(random.randint(5, 15))]
    contacts = [Contact(device_id=device_id, **random_contact()) for _ in range(random.randint(5, 20))]
    sms_records = [SmsRecord(device_id=device_id, **random_sms()) for _ in range(random.randint(5, 25))]
    calls = [CallRecord(device_id=device_id, **random_call()) for _ in range(random.randint(5, 20))]
    files = [ScannedFile(device_id=device_id, **random_scanned_file()) for _ in range(random.randint(5, 30))]

    dns_events, used = [], set()
    for _ in range(random.randint(10, 40)):
        ev = random_dns_event()
        if ev["domain"] in used:
            continue
        used.add(ev["domain"])
        dns_events.append(DnsEvent(device_id=device_id, **ev))

    threats = [
        Threat(
            device_id=device_id,
            scan_id=str(uuid.uuid4()),
            package_name=random.choice(APP_NAMES)[0],
            threat_name=random.choice(THREAT_NAMES),
            severity=random.choice(SEVERITIES),
            description=fake.sentence(nb_words=12),
        )
        for _ in range(random.randint(0, 4))
    ]

    risk_score = random.randint(0, 30)
    session = ScanSession(
        device_id=device_id,
        scan_id=str(uuid.uuid4()),
        scanned_apps=len(apps),
        risk_score=risk_score,
        threats_count=len(threats),
    )
    device.last_risk_score = risk_score

    db.session.add_all(apps + contacts + sms_records + calls + files + dns_events + threats + [session])

    # === НОВОЕ: синхронизация и запросы ===
    seed_sync_for_device(device_id)

    return device_id


# ============================================================
#  Ручные загрузки (admin, вне устройств)
# ============================================================
def seed_manual_uploads(count: int = 6):
    kinds = ["pdf_js", "pdf_clean", "zip_exe", "zip_clean", "exe", "elf", "apk", "txt", "dex"]
    for _ in range(count):
        kind = random.choice(kinds)
        ext = {"pdf_js": "pdf", "pdf_clean": "pdf", "zip_exe": "zip",
               "zip_clean": "zip", "exe": "exe", "elf": "elf",
               "apk": "apk", "txt": "txt", "dex": "dex"}[kind]
        name = f"sample_{fake.word()}_{random.randint(100, 999)}.{ext}"
        make_uploaded_file(
            uploaded_by="admin",
            relative_path=None,
            kind=kind,
            name=name,
        )


# ============================================================
#  MAIN
# ============================================================
if __name__ == "__main__":
    reset_files = "--reset-files" in sys.argv
    add_only = "--add" in sys.argv
    n_devices = 10

    with app.app_context():
        if reset_files:
            if os.path.isdir(UPLOAD_DIR):
                shutil.rmtree(UPLOAD_DIR)
                print(f"🧹 Удалено содержимое {UPLOAD_DIR}")
            os.makedirs(os.path.join(UPLOAD_DIR, "tmp"), exist_ok=True)

        if not add_only:
            db.drop_all()
            db.create_all()
            print("🗑  Таблицы пересозданы.")
        else:
            db.create_all()

        # устройства
        start_idx = 1
        if add_only:
            existing = Device.query.count()
            start_idx = existing + 1

        for i in range(start_idx, start_idx + n_devices):
            did = seed_device(i)
            print(f"   ✓ device {i:02d}  → {did}")

        # ручные загрузки от админа
        seed_manual_uploads(count=6)
        print("   ✓ 6 ручных файлов от admin")

        db.session.commit()

        # сводка
        print()
        print("=" * 60)
        print(f"  Devices:        {Device.query.count()}")
        print(f"  ScanSession:    {ScanSession.query.count()}")
        print(f"  Apps:           {AppRecord.query.count()}")
        print(f"  Contacts:       {Contact.query.count()}")
        print(f"  SMS:            {SmsRecord.query.count()}")
        print(f"  Calls:          {CallRecord.query.count()}")
        print(f"  Files (scan):   {ScannedFile.query.count()}")
        print(f"  DNS events:     {DnsEvent.query.count()}")
        print(f"  Threats:        {Threat.query.count()}")
        print(f"  SyncedFolder:   {SyncedFolder.query.count()}")
        print(f"  SyncedFile:     {SyncedFile.query.count()}")
        print(f"  FileRequest:    {FileRequest.query.count()}")
        print(f"    ├ pending:    {FileRequest.query.filter_by(status='pending').count()}")
        print(f"    ├ sent:       {FileRequest.query.filter_by(status='sent').count()}")
        print(f"    └ rejected:   {FileRequest.query.filter_by(status='rejected').count()}")
        print(f"  UploadedFile:   {UploadedFile.query.count()}")
        print(f"    ├ from dev:   {UploadedFile.query.filter(UploadedFile.uploaded_by.like('api:%')).count()}")
        print(f"    └ manual:     {UploadedFile.query.filter(~UploadedFile.uploaded_by.like('api:%')).count()}")
        print("=" * 60)
        print("✅ Готово.")
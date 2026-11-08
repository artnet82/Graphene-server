# analyzer.py
# Полный анализатор: телеметрия (analyze) + файлы (analyze_file).
# Зависимости только стандартные: hashlib, os, re, zipfile, math, collections.

import hashlib
import math
import os
import re
import zipfile
from collections import Counter


# ============================================================
#  АНАЛИЗ ТЕЛЕМЕТРИИ (apps / permissions)
# ============================================================

DANGEROUS_PERMISSIONS = {
    "android.permission.SEND_SMS":                    ("HIGH",   "Отправка SMS — типичный признак SMS-трояна"),
    "android.permission.RECEIVE_SMS":                 ("HIGH",   "Перехват входящих SMS"),
    "android.permission.READ_SMS":                    ("MEDIUM", "Чтение SMS"),
    "android.permission.READ_CALL_LOG":               ("MEDIUM", "Чтение журнала вызовов"),
    "android.permission.CALL_PHONE":                  ("MEDIUM", "Исходящие звонки"),
    "android.permission.RECORD_AUDIO":                ("MEDIUM", "Запись звука"),
    "android.permission.CAMERA":                      ("MEDIUM", "Доступ к камере"),
    "android.permission.ACCESS_FINE_LOCATION":        ("MEDIUM", "Точная геолокация"),
    "android.permission.ACCESS_BACKGROUND_LOCATION":  ("HIGH",   "Фоновая геолокация"),
    "android.permission.SYSTEM_ALERT_WINDOW":         ("HIGH",   "Оверлеи поверх других приложений"),
    "android.permission.REQUEST_INSTALL_PACKAGES":    ("HIGH",   "Установка APK из приложения"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE":  ("HIGH",   "Служба доступности"),
    "android.permission.BIND_DEVICE_ADMIN":           ("HIGH",   "Администратор устройства"),
    "android.permission.PACKAGE_USAGE_STATS":         ("LOW",    "Статистика использования"),
    "android.permission.READ_CONTACTS":               ("LOW",    "Чтение контактов"),
    "android.permission.READ_PHONE_STATE":            ("LOW",    "Данные телефона"),
}

SEVERITY_WEIGHT = {"HIGH": 25, "MEDIUM": 10, "LOW": 3}


def analyze(data: dict):
    """
    Возвращает (threats: list[dict], risk_score: int 0..100).
    threats: [{"package_name", "threat_name", "severity", "description"}]
    """
    threats = []
    apps = data.get("apps") or []
    risk = 0

    for app in apps:
        pkg = (app.get("package_name") or "")[:255]
        name = app.get("app_name") or pkg
        perms = app.get("permissions") or []
        target_sdk = app.get("target_sdk") or 0
        is_sideloaded = bool(app.get("is_sideloaded"))

        for perm in perms:
            info = DANGEROUS_PERMISSIONS.get(perm)
            if not info:
                continue
            sev, desc = info
            weight = SEVERITY_WEIGHT[sev]
            if is_sideloaded:
                weight = int(weight * 1.5)
                if sev == "MEDIUM":
                    sev = "HIGH"
            risk += weight
            threats.append({
                "package_name": pkg,
                "threat_name": f"Разрешение {perm.split('.')[-1]}",
                "severity": sev,
                "description": f"{name}: {desc}",
            })

        if target_sdk and target_sdk < 23:
            threats.append({
                "package_name": pkg,
                "threat_name": "Устаревший target SDK",
                "severity": "LOW",
                "description": f"{name}: target SDK {target_sdk} — нет runtime-разрешений",
            })
            risk += 3

    return threats, min(risk, 100)


# ============================================================
#  АНАЛИЗ ФАЙЛОВ
# ============================================================

URL_RE = re.compile(rb"https?://[a-zA-Z0-9\.\-_/:%?=&#+~]+")

APK_PATTERNS = [
    (rb"Ljava/lang/Runtime;\W+exec",                "HIGH",   "Runtime.exec — выполнение shell-команд"),
    (rb"Ljava/lang/ProcessBuilder",                 "MEDIUM", "ProcessBuilder — запуск процессов"),
    (rb"DexClassLoader",                            "HIGH",   "DexClassLoader — загрузка внешнего DEX"),
    (rb"PathClassLoader",                           "MEDIUM", "PathClassLoader — динамическая загрузка кода"),
    (rb"/system/(x?bin)/su\b",                      "HIGH",   "Путь к su-бинарнику"),
    (rb"android\.intent\.action\.BOOT_COMPLETED",   "LOW",    "Автозапуск при загрузке"),
    (rb"android\.permission\.SYSTEM_ALERT_WINDOW",  "MEDIUM", "Оверлеи"),
    (rb"android\.permission\.BIND_ACCESSIBILITY_SERVICE", "MEDIUM", "Accessibility service"),
    (rb"android\.permission\.RECEIVE_SMS",          "MEDIUM", "Перехват SMS"),
    (rb"android\.permission\.SEND_SMS",             "MEDIUM", "Отправка SMS"),
    (rb"android\.permission\.CALL_PHONE",           "LOW",    "Звонки"),
    (rb"android\.permission\.REQUEST_INSTALL_PACKAGES", "MEDIUM", "Установка APK"),
    (rb"Ljava/lang/reflect/Method;",                "LOW",    "Рефлексия"),
    (rb"loadUrl\(",                                 "LOW",    "WebView.loadUrl"),
    (rb"addJavascriptInterface",                    "MEDIUM", "JS-мост в WebView"),
]


def analyze_file(path: str, filename: str = None) -> dict:
    """
    Возвращает:
      {
        "sha256": str,
        "size": int,
        "file_type": str,   # apk / zip / pdf / pe / elf / dex / jar / docx / xlsx / ole / unknown
        "severity": str,    # CLEAN / LOW / MEDIUM / HIGH
        "risk_score": int,  # 0..100
        "detections": [ {"name", "severity", "description"}, ... ],
      }
    """
    if not filename:
        filename = os.path.basename(path)

    sha = _sha256(path)
    size = os.path.getsize(path)
    ftype = _detect_type(path, filename)

    detections: list = []
    risk = 0

    if ftype == "apk":
        detections, risk = _analyze_apk(path)
    elif ftype == "pdf":
        detections, risk = _analyze_pdf(path)
    elif ftype == "zip":
        detections, risk = _analyze_zip(path)
    elif ftype in ("pe", "elf", "dex"):
        detections, risk = _analyze_binary(path, ftype)
    else:
        detections, risk = _analyze_generic(path)

    risk = max(0, min(risk, 100))
    if risk >= 70:
        severity = "HIGH"
    elif risk >= 40:
        severity = "MEDIUM"
    elif risk >= 15:
        severity = "LOW"
    else:
        severity = "CLEAN"

    return {
        "sha256": sha,
        "size": size,
        "file_type": ftype,
        "severity": severity,
        "risk_score": risk,
        "detections": detections,
    }


# ---------- helpers ----------

def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _detect_type(path: str, filename: str) -> str:
    try:
        with open(path, "rb") as f:
            head = f.read(8)
    except Exception:
        head = b""

    if head.startswith(b"PK\x03\x04"):
        # ZIP-семейство: APK / JAR / DOCX / XLSX / обычный zip
        try:
            with zipfile.ZipFile(path) as z:
                names = z.namelist()
                if "AndroidManifest.xml" in names and any(n.endswith(".dex") for n in names):
                    return "apk"
                if "META-INF/MANIFEST.MF" in names:
                    return "jar"
                if any(n.startswith("word/") for n in names):
                    return "docx"
                if any(n.startswith("xl/") for n in names):
                    return "xlsx"
                return "zip"
        except Exception:
            return "zip"
    if head.startswith(b"%PDF"):
        return "pdf"
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"dex\n"):
        return "dex"
    if head.startswith(b"\xca\xfe\xba\xbe"):
        return "macho"
    if head.startswith(b"\xd0\xcf\x11\xe0"):
        return "ole"

    ext = ""
    if "." in filename:
        ext = filename.rsplit(".", 1)[-1].lower()
    return ext or "unknown"


def _analyze_apk(path: str):
    detections, risk = [], 0
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            dex_names = [n for n in names if n.endswith(".dex")]
            so_names = [n for n in names if n.endswith(".so")]
            cert_names = [n for n in names if n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".EC"))]

            if not cert_names:
                detections.append({
                    "name": "APK без подписи",
                    "severity": "HIGH",
                    "description": "Отсутствует файл подписи META-INF/*.RSA|DSA|EC",
                })
                risk += 30

            if so_names:
                detections.append({
                    "name": "Native-код",
                    "severity": "LOW",
                    "description": f"Содержит {len(so_names)} нативных библиотек",
                })
                risk += 3

            if len(dex_names) > 3:
                detections.append({
                    "name": "Много DEX",
                    "severity": "LOW",
                    "description": f"{len(dex_names)} DEX-файлов (возможна обфускация/мультидекс)",
                })
                risk += 5

            # Собираем строки DEX (ограничение 20 MB)
            blob = b""
            for n in dex_names:
                try:
                    data = z.read(n)
                except Exception:
                    continue
                blob += data[: max(0, 20 * 1024 * 1024 - len(blob))]
                if len(blob) >= 20 * 1024 * 1024:
                    break

            for pattern, sev, desc in APK_PATTERNS:
                if re.search(pattern, blob):
                    detections.append({
                        "name": desc,
                        "severity": sev,
                        "description": desc,
                    })
                    risk += SEVERITY_WEIGHT[sev]

            urls = set(URL_RE.findall(blob))
            if len(urls) > 10:
                detections.append({
                    "name": "Множественные URL",
                    "severity": "LOW",
                    "description": f"Найдено {len(urls)} URL в DEX",
                })
                risk += 3

    except Exception as e:
        detections.append({
            "name": "Ошибка разбора APK",
            "severity": "LOW",
            "description": str(e),
        })

    return detections, min(risk, 100)


def _analyze_pdf(path: str):
    detections, risk = [], 0
    try:
        with open(path, "rb") as f:
            data = f.read(5 * 1024 * 1024)

        if b"/JavaScript" in data or b"/JS" in data:
            detections.append({
                "name": "JavaScript в PDF",
                "severity": "HIGH",
                "description": "PDF содержит встроенный JavaScript",
            })
            risk += 30

        if b"/Launch" in data:
            detections.append({
                "name": "Автозапуск (/Launch)",
                "severity": "HIGH",
                "description": "PDF пытается запустить внешнюю программу",
            })
            risk += 30

        if b"/EmbeddedFile" in data:
            detections.append({
                "name": "Встроенный файл",
                "severity": "MEDIUM",
                "description": "PDF содержит вложенный файл",
            })
            risk += 15

        if b"/OpenAction" in data and (b"/JS" in data or b"/JavaScript" in data):
            detections.append({
                "name": "Авто-выполнение JS",
                "severity": "HIGH",
                "description": "JavaScript выполняется при открытии документа",
            })
            risk += 20

    except Exception:
        pass

    return detections, min(risk, 100)


def _analyze_zip(path: str):
    detections, risk = [], 0
    try:
        with zipfile.ZipFile(path) as z:
            infos = z.infolist()
            names = [i.filename for i in infos]

            exe_inside = [
                n for n in names
                if n.lower().endswith((".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar"))
            ]
            if exe_inside:
                detections.append({
                    "name": "Исполняемые файлы в архиве",
                    "severity": "HIGH",
                    "description": f"{len(exe_inside)}: {', '.join(exe_inside[:5])}",
                })
                risk += 35

            encrypted = any(i.flag_bits & 0x1 for i in infos)
            if encrypted:
                detections.append({
                    "name": "Зашифрованный ZIP",
                    "severity": "MEDIUM",
                    "description": "Архив защищён паролем — анализ содержимого ограничен",
                })
                risk += 10

            # Очень много файлов — потенциальный zip-bomb
            if len(infos) > 5000:
                detections.append({
                    "name": "Очень много файлов",
                    "severity": "LOW",
                    "description": f"{len(infos)} записей — возможно zip-bomb",
                })
                risk += 5

    except Exception:
        pass

    return detections, min(risk, 100)


def _analyze_binary(path: str, ftype: str):
    detections, risk = [], 0
    try:
        with open(path, "rb") as f:
            data = f.read(2 * 1024 * 1024)
    except Exception:
        return detections, 0

    if ftype == "pe":
        detections.append({
            "name": "Windows PE",
            "severity": "MEDIUM",
            "description": "Исполняемый файл Windows",
        })
        risk += 15
        if b"This program cannot be run in DOS mode" not in data[:0x200]:
            detections.append({
                "name": "Нестандартный PE-заголовок",
                "severity": "LOW",
                "description": "Отсутствует типичный DOS stub (возможна упаковка)",
            })
            risk += 5

    elif ftype == "elf":
        detections.append({
            "name": "ELF-бинарник",
            "severity": "LOW",
            "description": "Linux/Android native исполняемый файл",
        })
        risk += 3

    elif ftype == "dex":
        detections.append({
            "name": "DEX вне APK",
            "severity": "MEDIUM",
            "description": "Dalvik executable вне пакета — подозрительно",
        })
        risk += 15

    if b"exec" in data and (b"/bin/sh" in data or b"cmd.exe" in data or b"/system/bin/sh" in data):
        detections.append({
            "name": "Shell-команды",
            "severity": "HIGH",
            "description": "Строки запуска shell",
        })
        risk += 25

    return detections, min(risk, 100)


def _analyze_generic(path: str):
    detections, risk = [], 0
    try:
        with open(path, "rb") as f:
            data = f.read(1024 * 1024)
    except Exception:
        return detections, 0

    if not data:
        return detections, 0

    entropy = _entropy(data)
    if entropy > 7.5 and len(data) > 10_000:
        detections.append({
            "name": "Высокая энтропия",
            "severity": "LOW",
            "description": f"Энтропия {entropy:.2f} — возможна упаковка/шифрование",
        })
        risk += 5

    # Встроенные ELF/PE внутри якобы «безобидного» файла
    if b"\x7fELF" in data[64:] and not data.startswith(b"\x7fELF"):
        detections.append({
            "name": "Встроенный ELF",
            "severity": "MEDIUM",
            "description": "Внутри файла найден ELF-бинарник",
        })
        risk += 15

    if b"MZ\x90\x00" in data[64:] and not data.startswith(b"MZ"):
        detections.append({
            "name": "Встроенный PE",
            "severity": "MEDIUM",
            "description": "Внутри файла найден Windows PE",
        })
        risk += 15

    return detections, min(risk, 100)
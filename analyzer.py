"""
Анализатор угроз. Получает весь scan-payload и возвращает список угроз + risk score.
"""

DANGEROUS_PERMISSIONS = {
    "android.permission.SEND_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_SETTINGS",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
}

SMS_SCAM_KEYWORDS = [
    # RU
    "срочно переведи", "переведите деньги", "перевести деньги",
    "вы выиграли", "ваш выигрыш", "ваша карта заблокирована",
    "блокировка карты", "подтвердите код", "код из смс",
    "безопасный счёт", "безопасный счет", "ваш аккаунт взломан",
    "госуслуги", "gosuslugi", "следуйте по ссылке", "перейдите по ссылке",
    "жмите по ссылке", "верификация", "верифицируйте", "ваш номер заблокирован",
    # EN
    "safe account", "verify your account", "click here to verify",
    "your card is blocked", "confirm your code", "your parcel is waiting",
]

SUSPICIOUS_DOMAIN_PATTERNS = [
    "login-", "-verify", "verify-", "secure-", "update-bank",
    "sms-code", "wallet-", "crypto-", "gosuslugi-", "sber-", "tinkoff-",
    "vtb-", "alfa-", "password-", "account-", "restore-", "support-",
]

MALWARE_NAME_HINTS = ["malware", "trojan", "spyware", "spy", "hack", "rat", "backdoor"]

# Формы весов для risk score
SEVERITY_WEIGHTS = {"HIGH": 10, "MEDIUM": 4, "LOW": 1}


def analyze(payload: dict):
    """Возвращает (threats: list[dict], risk_score: int)."""
    threats: list[dict] = []

    # ---- Приложения ----
    for app in payload.get("apps") or []:
        pkg = app.get("package_name", "") or ""
        app_name = app.get("app_name", "") or ""
        perms = set(app.get("permissions") or [])

        dangerous = perms & DANGEROUS_PERMISSIONS
        if len(dangerous) >= 2:
            threats.append({
                "package_name": pkg,
                "threat_name": "Опасная комбинация разрешений",
                "severity": "HIGH" if len(dangerous) >= 4 else "MEDIUM",
                "description": "Разрешения: " + ", ".join(sorted(dangerous))[:400],
            })

        if app.get("is_sideloaded"):
            threats.append({
                "package_name": pkg,
                "threat_name": "Установлено не из Google Play",
                "severity": "MEDIUM",
                "description": "Sideload-приложение — высокий риск заражения",
            })

        haystack = (app_name + " " + pkg).lower()
        if any(h in haystack for h in MALWARE_NAME_HINTS):
            threats.append({
                "package_name": pkg,
                "threat_name": "Известная сигнатура",
                "severity": "HIGH",
                "description": "Совпадение с базой сигнатур вредоносного ПО",
            })

    # ---- SMS ----
    for sms in payload.get("sms") or []:
        body = (sms.get("body_preview") or "").lower()
        hits = [kw for kw in SMS_SCAM_KEYWORDS if kw in body]
        if hits:
            threats.append({
                "package_name": "sms://" + (sms.get("address") or "unknown"),
                "threat_name": "Подозрительное SMS (мошенничество)",
                "severity": "HIGH" if len(hits) >= 2 else "MEDIUM",
                "description": "Найдено: " + ", ".join(hits)[:400],
            })

    # ---- DNS ----
    network = payload.get("network") or {}
    for ev in network.get("dns_events") or []:
        domain = (ev.get("domain") or "").lower()
        hits = [p for p in SUSPICIOUS_DOMAIN_PATTERNS if p in domain]
        if hits:
            threats.append({
                "package_name": "dns://" + domain,
                "threat_name": "Подозрительный домен",
                "severity": "MEDIUM",
                "description": "Паттерны: " + ", ".join(hits),
            })

    # ---- Дедупликация ----
    seen = set()
    unique = []
    for t in threats:
        key = (t["package_name"], t["threat_name"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(t)

    # ---- Risk score ----
    score = sum(SEVERITY_WEIGHTS.get(t["severity"], 1) for t in unique)
    return unique, min(100, score)
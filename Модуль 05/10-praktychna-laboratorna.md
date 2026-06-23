# 5.10. Практична лабораторна на Python

Чотири лабораторні роботи, що охоплюють ключові теми модуля: реалізація TOTP-автентифікації, RBAC-система, аналізатор надійності паролів і аудитор OAuth-токенів. Всі скрипти — для навчальних цілей і аудиту власних систем.

**Залежності:**
```bash
pip install pyotp qrcode[pil] passlib[argon2] PyJWT requests
```

---

## Лабораторна 5.10.1: TOTP-автентифікатор

Повна реалізація TOTP: генерація секрету, QR-код для реєстрації в Google Authenticator, верифікація коду.

```python
"""
totp_auth.py — повна TOTP реалізація.
Сумісна з Google Authenticator, Authy, Microsoft Authenticator.
pip install pyotp qrcode[pil]
"""
import pyotp
import qrcode
import time
import secrets
import base64
from pathlib import Path


def generate_totp_secret() -> str:
    """Генерує криптографічно стійкий TOTP-секрет."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str, issuer: str = "MyApp") -> str:
    """Генерує URI для QR-коду (формат otpauth://)."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def generate_qr_code(uri: str, filename: str = "totp_qr.png") -> str:
    """Зберігає QR-код у файл для сканування в Authenticator-застосунку."""
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(filename)
    return filename


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """
    Перевіряє TOTP-код.
    window=1 дозволяє відхилення ±30 секунд (захист від неточних годинників).
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=window)


def get_current_totp(secret: str) -> tuple[str, int]:
    """Повертає поточний TOTP-код і секунди до наступного."""
    totp = pyotp.TOTP(secret)
    code = totp.now()
    remaining = 30 - (int(time.time()) % 30)
    return code, remaining


class TOTPUserDB:
    """Спрощена "база даних" користувачів з TOTP (in-memory для демонстрації)."""

    def __init__(self):
        self._users: dict[str, dict] = {}

    def register_user(self, username: str, password_hash: str) -> str:
        """Реєструє нового користувача і повертає TOTP-секрет."""
        if username in self._users:
            raise ValueError(f"Користувач {username} вже існує")

        secret = generate_totp_secret()
        self._users[username] = {
            "password_hash": password_hash,
            "totp_secret": secret,
            "totp_enabled": True,
            "created_at": time.time(),
        }
        return secret

    def authenticate(self, username: str, password_hash: str, totp_code: str) -> bool:
        """Повна автентифікація: пароль + TOTP."""
        user = self._users.get(username)
        if not user:
            # Constant-time: не розкриваємо чи існує user
            time.sleep(0.1)
            return False

        # Перевірка пароля
        if user["password_hash"] != password_hash:
            return False

        # Перевірка TOTP (якщо увімкнений)
        if user["totp_enabled"]:
            return verify_totp(user["totp_secret"], totp_code)

        return True


if __name__ == "__main__":
    print("=" * 55)
    print("Демонстрація TOTP-автентифікації")
    print("=" * 55)

    # 1. Реєстрація
    db = TOTPUserDB()
    secret = db.register_user("alice@example.com", "hashed_password_here")

    print(f"\n[Реєстрація]")
    print(f"  Username: alice@example.com")
    print(f"  TOTP Secret: {secret}")

    # 2. QR-код для застосунку
    uri = get_totp_uri(secret, "alice@example.com", "CyberGuide Demo")
    qr_file = generate_qr_code(uri, "/tmp/totp_demo.png")
    print(f"\n[QR-код]")
    print(f"  Збережено: {qr_file}")
    print(f"  URI: {uri[:60]}...")
    print(f"  → Відскануйте в Google Authenticator для тестування")

    # 3. Поточний код
    code, remaining = get_current_totp(secret)
    print(f"\n[Поточний TOTP-код]")
    print(f"  Код: {code}")
    print(f"  Дійсний ще: {remaining} секунд")

    # 4. Верифікація
    print(f"\n[Автентифікація]")
    result = db.authenticate("alice@example.com", "hashed_password_here", code)
    print(f"  Пароль + код {code}: {'✅ Успішно' if result else '❌ Відхилено'}")

    wrong_result = db.authenticate("alice@example.com", "hashed_password_here", "000000")
    print(f"  Пароль + код 000000: {'✅ Успішно' if wrong_result else '❌ Відхилено'}")
```

**Завдання:**
1. Відскануйте згенерований QR-код у Google Authenticator. Чи збігається код з виводом скрипту?
2. Змініть `window=1` на `window=0` і перевірте: чи прийме система код з попереднього 30-секундного вікна?
3. Спробуйте реалізувати **одноразовість коду**: зберігати вже використані коди і відхиляти повторні за 90-секундне вікно.

---

## Лабораторна 5.10.2: RBAC-система

```python
"""
rbac_system.py — повна RBAC-реалізація з ієрархією ролей і SoD.
"""
from dataclasses import dataclass, field
from typing import Optional
import json


@dataclass
class Permission:
    resource: str    # "budget", "code_repo", "hr_records"
    action: str      # "read", "write", "delete", "approve"

    def __hash__(self):
        return hash((self.resource, self.action))

    def __eq__(self, other):
        return self.resource == other.resource and self.action == other.action

    def __repr__(self):
        return f"{self.resource}:{self.action}"


@dataclass
class Role:
    name: str
    permissions: set[Permission] = field(default_factory=set)
    parent_roles: list[str] = field(default_factory=list)  # наслідування

    def add_permission(self, resource: str, action: str) -> None:
        self.permissions.add(Permission(resource, action))


class RBACSystem:
    def __init__(self):
        self._roles: dict[str, Role] = {}
        self._users: dict[str, set[str]] = {}          # user → {role_names}
        self._sod_conflicts: list[tuple[str, str]] = [] # [(role1, role2), ...] несумісні ролі

    # ─── Управління ролями ────────────────────────────────────────────────────

    def add_role(self, name: str, parent_roles: list[str] = None) -> Role:
        role = Role(name=name, parent_roles=parent_roles or [])
        self._roles[name] = role
        return role

    def add_sod_constraint(self, role1: str, role2: str) -> None:
        """Визначає несумісні ролі (Separation of Duties)."""
        self._sod_conflicts.append((role1, role2))

    def _get_all_permissions(self, role_name: str, visited: set = None) -> set[Permission]:
        """Рекурсивно збирає всі права ролі включно з успадкованими."""
        if visited is None:
            visited = set()
        if role_name in visited or role_name not in self._roles:
            return set()
        visited.add(role_name)

        role = self._roles[role_name]
        perms = set(role.permissions)
        for parent in role.parent_roles:
            perms |= self._get_all_permissions(parent, visited)
        return perms

    # ─── Управління користувачами ─────────────────────────────────────────────

    def assign_role(self, username: str, role_name: str) -> None:
        """Призначає роль користувачу з перевіркою SoD."""
        if role_name not in self._roles:
            raise ValueError(f"Роль '{role_name}' не існує")

        current_roles = self._users.get(username, set())

        # Перевірка SoD-конфліктів
        for r1, r2 in self._sod_conflicts:
            conflict = None
            if role_name == r1 and r2 in current_roles:
                conflict = (r1, r2)
            elif role_name == r2 and r1 in current_roles:
                conflict = (r1, r2)
            if conflict:
                raise PermissionError(
                    f"SoD порушення: неможливо призначити '{role_name}' — "
                    f"конфлікт з '{conflict[0]}' та '{conflict[1]}'"
                )

        self._users.setdefault(username, set()).add(role_name)

    def revoke_role(self, username: str, role_name: str) -> None:
        if username in self._users:
            self._users[username].discard(role_name)

    # ─── Перевірка доступу ────────────────────────────────────────────────────

    def check_access(self, username: str, resource: str, action: str) -> bool:
        """Перевіряє, чи має користувач право на дію з ресурсом."""
        user_roles = self._users.get(username, set())
        required = Permission(resource, action)
        for role_name in user_roles:
            if required in self._get_all_permissions(role_name):
                return True
        return False

    def get_user_permissions(self, username: str) -> set[Permission]:
        """Повертає всі права користувача (через всі ролі)."""
        all_perms: set[Permission] = set()
        for role_name in self._users.get(username, set()):
            all_perms |= self._get_all_permissions(role_name)
        return all_perms

    def audit_report(self) -> str:
        """Генерує звіт про всіх користувачів і їхні права."""
        lines = ["=== RBAC Аудит-звіт ===\n"]
        for username, roles in sorted(self._users.items()):
            perms = self.get_user_permissions(username)
            lines.append(f"👤 {username}")
            lines.append(f"   Ролі: {', '.join(sorted(roles))}")
            lines.append(f"   Права ({len(perms)}): {', '.join(str(p) for p in sorted(perms, key=str))}")
            lines.append("")
        return "\n".join(lines)


if __name__ == "__main__":
    rbac = RBACSystem()

    # Визначення ролей з ієрархією
    employee = rbac.add_role("employee")
    employee.add_permission("intranet", "read")
    employee.add_permission("email", "read")
    employee.add_permission("email", "write")

    developer = rbac.add_role("developer", parent_roles=["employee"])
    developer.add_permission("code_repo", "read")
    developer.add_permission("code_repo", "write")
    developer.add_permission("dev_server", "read")

    tech_lead = rbac.add_role("tech_lead", parent_roles=["developer"])
    tech_lead.add_permission("code_repo", "approve")
    tech_lead.add_permission("prod_deploy", "approve")

    finance = rbac.add_role("finance")
    finance.add_permission("budget", "read")
    finance.add_permission("budget", "write")
    finance.add_permission("payments", "create")

    approver = rbac.add_role("approver")
    approver.add_permission("payments", "approve")

    admin = rbac.add_role("admin", parent_roles=["employee", "developer"])
    admin.add_permission("users", "read")
    admin.add_permission("users", "write")

    # SoD: той хто створює платежі, не може їх підтверджувати
    rbac.add_sod_constraint("finance", "approver")

    # Призначення ролей
    rbac.assign_role("alice", "tech_lead")
    rbac.assign_role("bob", "developer")
    rbac.assign_role("carol", "finance")
    rbac.assign_role("dave", "approver")
    rbac.assign_role("eve", "admin")

    # Спроба порушити SoD
    print("Спроба порушення SoD (carol + approver):")
    try:
        rbac.assign_role("carol", "approver")
    except PermissionError as e:
        print(f"  ✅ Заблоковано: {e}\n")

    # Перевірка прав
    checks = [
        ("alice", "code_repo", "approve"),
        ("alice", "email", "read"),
        ("bob", "prod_deploy", "approve"),
        ("carol", "payments", "create"),
        ("carol", "payments", "approve"),
        ("dave", "payments", "approve"),
        ("eve", "users", "write"),
    ]

    print("Перевірка прав доступу:")
    for user, resource, action in checks:
        result = rbac.check_access(user, resource, action)
        icon = "✅" if result else "❌"
        print(f"  {icon} {user:8} → {resource}:{action}")

    print(f"\n{rbac.audit_report()}")
```

---

## Лабораторна 5.10.3: Аналізатор надійності паролів

```python
"""
password_strength.py — аналізатор надійності паролів з NIST SP 800-63B рекомендаціями.
"""
import re
import math
import urllib.request


# Список найпоширеніших паролів (зазвичай завантажується з файлу)
COMMON_PASSWORDS = {
    "password", "123456", "password123", "admin", "letmein",
    "qwerty", "abc123", "monkey", "1234567", "12345678",
    "111111", "password1", "iloveyou", "sunshine", "princess",
}


def calculate_entropy(password: str) -> float:
    """Обчислює ентропію пароля на основі розміру алфавіту."""
    charset_size = 0
    if re.search(r'[a-z]', password): charset_size += 26
    if re.search(r'[A-Z]', password): charset_size += 26
    if re.search(r'\d', password): charset_size += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset_size += 32

    if charset_size == 0 or len(password) == 0:
        return 0.0
    return len(password) * math.log2(charset_size)


def check_common_patterns(password: str) -> list[str]:
    """Виявляє небезпечні патерни в паролі."""
    warnings = []
    lower = password.lower()

    if lower in COMMON_PASSWORDS:
        warnings.append("Пароль знаходиться в списку найпоширеніших")

    if re.search(r'(.)\1{2,}', password):
        warnings.append("Містить повторювані символи (aaa, 111)")

    if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
        warnings.append("Містить послідовні цифри")

    if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', lower):
        warnings.append("Містить послідовні літери")

    if re.search(r'(qwert|asdf|zxcv|йцуке|фыва)', lower):
        warnings.append("Містить клавіатурний патерн (qwerty, asdf)")

    if re.search(r'\b(19|20)\d{2}\b', password):
        warnings.append("Містить рік — передбачуваний патерн")

    return warnings


def analyze_password(password: str) -> dict:
    """Повний аналіз пароля з рекомендаціями NIST SP 800-63B."""
    result = {
        "password": "*" * len(password),
        "length": len(password),
        "entropy_bits": calculate_entropy(password),
        "issues": [],
        "score": 0,          # 0–100
        "level": "",
        "recommendations": [],
    }

    # Перевірки довжини (NIST: мінімум 8, рекомендовано 15+)
    if len(password) < 8:
        result["issues"].append("Занадто короткий (менше 8 символів)")
    elif len(password) < 12:
        result["recommendations"].append("Рекомендовано мінімум 12 символів")
    elif len(password) < 16:
        result["recommendations"].append("Для максимальної безпеки — 16+ символів")

    # Перевірка патернів
    result["issues"].extend(check_common_patterns(password))

    # Розрахунок оцінки
    score = min(len(password) * 5, 40)                    # довжина: до 40
    score += min(int(result["entropy_bits"] * 0.5), 30)   # ентропія: до 30
    score -= len(result["issues"]) * 15                   # штраф за проблеми
    score = max(0, min(100, score))
    result["score"] = score

    # Рівень
    if score < 25:
        result["level"] = "❌ Дуже слабкий"
    elif score < 50:
        result["level"] = "⚠️  Слабкий"
    elif score < 75:
        result["level"] = "🟡 Середній"
    elif score < 90:
        result["level"] = "✅ Сильний"
    else:
        result["level"] = "✅✅ Дуже сильний"

    # NIST рекомендація: перевіряти пароль у базі витоків
    result["recommendations"].append(
        "Перевірте пароль на haveibeenpwned.com (скрипт 5.3.3)"
    )

    return result


def print_analysis(result: dict) -> None:
    print(f"\n{'─'*50}")
    print(f"Аналіз пароля: {result['password']}")
    print(f"{'─'*50}")
    print(f"  Довжина:   {result['length']} символів")
    print(f"  Ентропія:  {result['entropy_bits']:.1f} біт")
    print(f"  Оцінка:    {result['score']}/100")
    print(f"  Рівень:    {result['level']}")

    if result["issues"]:
        print(f"\n  ❗ Проблеми:")
        for issue in result["issues"]:
            print(f"    - {issue}")

    if result["recommendations"]:
        print(f"\n  💡 Рекомендації:")
        for rec in result["recommendations"]:
            print(f"    - {rec}")


if __name__ == "__main__":
    test_passwords = [
        "password",
        "P@ssw0rd",
        "Summer2024!",
        "correct-horse-battery-staple",
        "МаківкаВерсняСпіваєТихо2024!",
        "xK9#mP2@nL7$vQ4!",
    ]

    print("=== Аналізатор надійності паролів (NIST SP 800-63B) ===")
    for pwd in test_passwords:
        result = analyze_password(pwd)
        print_analysis(result)
```

---

## Лабораторна 5.10.4: JWT-аудитор

```python
"""
jwt_auditor.py — аналізатор JWT токенів на типові вразливості.
pip install PyJWT
"""
import json
import base64
import sys
from typing import Any


def decode_jwt_unsafe(token: str) -> tuple[dict, dict]:
    """Декодує JWT без верифікації (лише для аудиту)."""
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Невалідний JWT формат (потрібно 3 частини)")

    def pad(s):
        return s + '=' * (4 - len(s) % 4)

    header = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
    payload = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
    return header, payload


def audit_jwt(token: str) -> list[dict]:
    """Аналізує JWT на типові вразливості безпеки."""
    findings = []

    try:
        header, payload = decode_jwt_unsafe(token)
    except Exception as e:
        return [{"severity": "ERROR", "issue": f"Не вдалось декодувати токен: {e}"}]

    # ─── Перевірка Header ─────────────────────────────────────────────────────
    alg = header.get("alg", "none")

    if alg == "none":
        findings.append({
            "severity": "CRITICAL",
            "issue": 'alg: "none" — підпис відсутній, токен приймається без верифікації',
            "fix": "Ніколи не приймати токени з alg=none"
        })

    if alg in ("HS256", "HS384", "HS512"):
        findings.append({
            "severity": "INFO",
            "issue": f"HMAC алгоритм ({alg}) — секрет має бути достатньо довгим (32+ байт)",
            "fix": "Переконайтесь що ключ підпису генерується безпечно, а не є словом зі словника"
        })

    if alg in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512"):
        findings.append({
            "severity": "INFO",
            "issue": f"Асиметричний алгоритм ({alg}) — переконайтесь у перевірці публічного ключа",
            "fix": "Перевіряти iss і зберігати публічний ключ для кожного emitter окремо"
        })

    # ─── Перевірка Payload ────────────────────────────────────────────────────
    import time
    now = int(time.time())

    if "exp" not in payload:
        findings.append({
            "severity": "HIGH",
            "issue": "Відсутній claim exp (expiration) — токен не має терміну дії",
            "fix": "Завжди встановлювати exp; рекомендований термін: 15–60 хвилин для access tokens"
        })
    elif payload["exp"] < now:
        findings.append({
            "severity": "HIGH",
            "issue": f"Токен прострочений (exp: {payload['exp']}, зараз: {now})",
            "fix": "Токен відхилений сервером (якщо перевірка exp реалізована коректно)"
        })
    else:
        lifetime = payload["exp"] - now
        if lifetime > 86400:  # > 24 годин
            findings.append({
                "severity": "MEDIUM",
                "issue": f"Дуже довгий термін дії токена: {lifetime//3600} годин",
                "fix": "Для access tokens рекомендовано 15–60 хвилин; для refresh tokens — максимум 30 днів"
            })

    if "aud" not in payload:
        findings.append({
            "severity": "HIGH",
            "issue": "Відсутній claim aud (audience) — токен може бути використаний для будь-якого сервісу",
            "fix": "Завжди встановлювати aud; перевіряти на сервері що aud = очікуваному значенню"
        })

    if "iss" not in payload:
        findings.append({
            "severity": "MEDIUM",
            "issue": "Відсутній claim iss (issuer) — неможливо перевірити джерело токена",
            "fix": "Встановлювати iss; перевіряти iss на сервері"
        })

    if "nbf" not in payload:
        findings.append({
            "severity": "INFO",
            "issue": "Відсутній claim nbf (not before) — токен валідний з моменту видачі",
            "fix": "Для критичних сценаріїв встановлюйте nbf для захисту від раннього використання"
        })

    # Підозрілі claims з підвищеними правами
    role = payload.get("role") or payload.get("roles") or payload.get("scope")
    if role and ("admin" in str(role).lower() or "root" in str(role).lower()):
        findings.append({
            "severity": "INFO",
            "issue": f"Токен містить адміністративну роль: {role}",
            "fix": "Переконайтесь що сервер перевіряє підпис перед довірою до ролей"
        })

    return findings


def print_audit_report(token: str) -> None:
    header, payload = decode_jwt_unsafe(token)
    findings = audit_jwt(token)

    ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "INFO": "ℹ️ ", "ERROR": "❌"}

    print("\n" + "=" * 60)
    print("JWT АУДИТ-ЗВІТ")
    print("=" * 60)
    print(f"\nHeader: {json.dumps(header, indent=2, ensure_ascii=False)}")
    print(f"\nPayload: {json.dumps(payload, indent=2, ensure_ascii=False)}")
    print(f"\nЗнахідки ({len(findings)}):")

    for f in findings:
        sev = f.get("severity", "INFO")
        print(f"\n  {ICONS.get(sev, '?')} [{sev}] {f['issue']}")
        if "fix" in f:
            print(f"     → {f['fix']}")


if __name__ == "__main__":
    # Тестовий JWT без терміну дії і без aud (типові помилки)
    # Згенерований на jwt.io для демонстрації (секрет = "secret")
    test_token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiJ1c2VyMTIzIiwibmFtZSI6IkFsaWNlIiwicm9sZSI6ImFkbWluIn0"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )

    print("Тестовий JWT (без exp, без aud, роль admin):")
    print_audit_report(test_token)

    # JWT з alg:none (критична вразливість)
    none_token = (
        "eyJhbGciOibm9uZSIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9"
        "."
    )
    try:
        print("\n\nJWT з alg:none (критична вразливість):")
        print_audit_report(none_token)
    except Exception as e:
        print(f"Помилка декодування: {e}")
```

**Завдання:**
1. Згенеруйте власний JWT на `jwt.io` без claim `exp`. Запустіть аудитор — чи виявить він проблему?
2. Знайдіть JWT у будь-якому власному проекті або API (перевірте Authorization header у DevTools → Network). Запустіть аудитор.
3. Модифікуйте скрипт: додайте перевірку на `"alg": "RS256"` з `"kty": "oct"` в `jwks_uri` — це класична Key Confusion Attack.

## Джерела та додаткові матеріали

- pyotp (github.com/pyauth/pyotp) — TOTP/HOTP бібліотека.
- PyJWT (pyjwt.readthedocs.io) — JWT для Python.
- RFC 6238 — TOTP Algorithm.
- RFC 7519 — JSON Web Token (JWT).
- PortSwigger, *JWT Attacks* — практичне пояснення атак.

---

**Попередній розділ:** [5.9. Атаки на автентифікацію](09-ataky-na-avtentyfikatsiiu.md)
**Далі:** [5.11. Чек-лист і самоперевірка](11-chek-lyst-i-samoperevirka.md)
**Назад до модуля:** [README модуля 05](README.md)

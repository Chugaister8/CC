# 7.11. Практична лабораторна на Python

Чотири лабораторні, що автоматизують задачі захисника: аналіз email-заголовків на ознаки фішингу, пошук індикаторів компрометації (IOC) у логах, генератор YARA-шаблонів і аудит якості паролів за NIST SP 800-63B.

**Залежності:**
```bash
pip install dnspython requests
```

---

## Лабораторна 7.11.1: Аналізатор email-заголовків

Скрипт аналізує raw email headers і виявляє ознаки фішингу або підробки відправника.

```python
"""
email_header_analyzer.py — аналіз заголовків електронної пошти
для виявлення ознак фішингу і підробки.
"""
import re
import email
from email.header import decode_header
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class HeaderAnalysis:
    sender_display: str = ""
    sender_email: str = ""
    reply_to: str = ""
    return_path: str = ""
    subject: str = ""
    received_from: list = field(default_factory=list)
    spf_result: str = ""
    dkim_result: str = ""
    dmarc_result: str = ""
    x_mailer: str = ""
    warnings: list = field(default_factory=list)
    score: int = 0  # 0=чистий, 10+=підозрілий


def decode_mime_str(encoded: str) -> str:
    """Декодує MIME-encoded рядки (=?UTF-8?Q?...?=)."""
    parts = decode_header(encoded)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(charset or 'utf-8', errors='replace'))
        else:
            decoded.append(part)
    return ' '.join(decoded)


def extract_email_address(header_val: str) -> tuple[str, str]:
    """Витягує ім'я і email-адресу з заголовка From/Reply-To."""
    match = re.search(r'([^<]*)<([^>]+)>', header_val)
    if match:
        return match.group(1).strip().strip('"'), match.group(2).strip()
    email_match = re.search(r'[\w.+-]+@[\w.-]+\.\w+', header_val)
    if email_match:
        return "", email_match.group()
    return "", header_val.strip()


def analyze_headers(raw_headers: str) -> HeaderAnalysis:
    """Аналізує raw email headers і повертає структурований результат."""
    result = HeaderAnalysis()

    # Парсинг через email модуль
    msg = email.message_from_string(raw_headers + "\n\n")

    # FROM
    from_val = msg.get('From', '')
    result.sender_display, result.sender_email = extract_email_address(from_val)
    result.sender_display = decode_mime_str(result.sender_display)

    # SUBJECT
    result.subject = decode_mime_str(msg.get('Subject', ''))

    # REPLY-TO
    reply_to = msg.get('Reply-To', '')
    if reply_to:
        _, result.reply_to = extract_email_address(reply_to)

    # RETURN-PATH
    return_path = msg.get('Return-Path', '')
    if return_path:
        _, result.return_path = extract_email_address(return_path)

    # X-MAILER
    result.x_mailer = msg.get('X-Mailer', msg.get('X-Originating-IP', ''))

    # RECEIVED chain
    received = msg.get_all('Received', [])
    for r in received:
        result.received_from.append(r.strip()[:100])

    # Authentication-Results
    auth_results = msg.get('Authentication-Results', '')
    spf_match = re.search(r'spf=(\w+)', auth_results, re.I)
    dkim_match = re.search(r'dkim=(\w+)', auth_results, re.I)
    dmarc_match = re.search(r'dmarc=(\w+)', auth_results, re.I)

    result.spf_result = spf_match.group(1) if spf_match else 'not found'
    result.dkim_result = dkim_match.group(1) if dkim_match else 'not found'
    result.dmarc_result = dmarc_match.group(1) if dmarc_match else 'not found'

    # ─── ЕВРИСТИЧНЕ ВИЯВЛЕННЯ ОЗНАК ФІШИНГУ ───────────────────────────────

    sender_domain = result.sender_email.split('@')[-1].lower() if '@' in result.sender_email else ''
    reply_domain = result.reply_to.split('@')[-1].lower() if '@' in result.reply_to else ''

    # 1. Reply-To відрізняється від From-домену
    if reply_domain and sender_domain and reply_domain != sender_domain:
        result.warnings.append(
            f"⚠️  Reply-To домен ({reply_domain}) відрізняється від From домену ({sender_domain})"
        )
        result.score += 3

    # 2. SPF/DKIM/DMARC провалились
    for protocol, value in [('SPF', result.spf_result), ('DKIM', result.dkim_result),
                              ('DMARC', result.dmarc_result)]:
        if value in ('fail', 'hardfail', 'none', 'not found'):
            result.warnings.append(f"⚠️  {protocol} = {value}")
            result.score += 2

    # 3. Підозрілі слова в темі
    urgent_words = ['urgent', 'терміново', 'action required', 'verify', 'suspended',
                    'заблоковано', 'підтвердіть', 'verify account', 'invoice', 'account']
    subject_lower = result.subject.lower()
    for word in urgent_words:
        if word in subject_lower:
            result.warnings.append(f"⚠️  Підозріле слово у темі: '{word}'")
            result.score += 1
            break

    # 4. Тема декодована в підозрілому кодуванні
    if '=?' in msg.get('Subject', '') and result.subject == msg.get('Subject', ''):
        result.warnings.append("⚠️  Нерозпізнане MIME-кодування у темі")
        result.score += 1

    # 5. Return-Path відрізняється від From
    return_domain = result.return_path.split('@')[-1].lower() if '@' in result.return_path else ''
    if return_domain and sender_domain and return_domain != sender_domain:
        result.warnings.append(
            f"⚠️  Return-Path домен ({return_domain}) відрізняється від From ({sender_domain})"
        )
        result.score += 2

    # 6. Підозрілий домен відправника (typosquatting patterns)
    suspicious_patterns = [r'paypa1', r'g00gle', r'micosoft', r'arnazon',
                           r'suppport', r'security-\w+', r'verify-\w+']
    for pattern in suspicious_patterns:
        if re.search(pattern, sender_domain):
            result.warnings.append(f"🔴 Можливий typosquatting у домені відправника: {sender_domain}")
            result.score += 5
            break

    return result


def print_report(analysis: HeaderAnalysis) -> None:
    print("\n" + "=" * 60)
    print("АНАЛІЗ EMAIL ЗАГОЛОВКІВ")
    print("=" * 60)
    print(f"  Від (відображається): {analysis.sender_display}")
    print(f"  Email відправника:    {analysis.sender_email}")
    if analysis.reply_to:
        print(f"  Reply-To:             {analysis.reply_to}")
    if analysis.return_path:
        print(f"  Return-Path:          {analysis.return_path}")
    print(f"  Тема:                 {analysis.subject}")
    print(f"\n  SPF:   {analysis.spf_result}")
    print(f"  DKIM:  {analysis.dkim_result}")
    print(f"  DMARC: {analysis.dmarc_result}")

    if analysis.warnings:
        print(f"\n  Знахідки ({len(analysis.warnings)}):")
        for w in analysis.warnings:
            print(f"    {w}")

    risk = "🟢 Низький" if analysis.score < 3 else \
           "🟡 Середній" if analysis.score < 7 else \
           "🔴 Високий"
    print(f"\n  Рівень ризику: {risk} (score={analysis.score})")
    print("=" * 60)


if __name__ == "__main__":
    # Тестові заголовки (імітація фішингового листа)
    test_headers = """From: "PrivatBank Security" <security@privatb4nk-secure.com>
Reply-To: hacker@evil.ru
Return-Path: <bounce@spam-relay.net>
Subject: =?UTF-8?Q?TERM=C3=9AНОВО=3A_=D0=9F=D1=96=D0=B4=D1=82=D0=B2=D0=B5=D1=80=D0=B4=D1=96=D1=82=D1=8C_=D0=B2=D0=B0=D1=88_=D0=B0=D0=BA=D0=B0=D1=83=D0=BD=D1=82?=
Received: from spam-relay.net (spam-relay.net [185.220.101.1])
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail
X-Mailer: The Bat! 9.3
Date: Mon, 1 Jan 2024 12:00:00 +0000"""

    analysis = analyze_headers(test_headers)
    print_report(analysis)
```

**Завдання:**
1. Отримайте raw headers будь-якого реального листа з вашого поштового ящика (Gmail: «⋮» → «Показати оригінал»; Outlook: «Файл → Властивості»). Запустіть аналізатор.
2. Порівняйте результати для легітимного листа від банку і будь-якого рекламного листа.

---

## Лабораторна 7.11.2: Детектор IOC у логах

```python
"""
ioc_scanner.py — пошук Indicators of Compromise у текстових логах.
Підтримує IP-адреси, домени, URL, хеші файлів і email-адреси.
"""
import re
import sys
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class IOCResult:
    ioc_type: str
    value: str
    count: int
    lines: list[int] = field(default_factory=list)


# ─── IOC ПАТЕРНИ ────────────────────────────────────────────────────────────
IOC_PATTERNS = {
    'IPv4': r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
    'MD5':  r'\b[0-9a-fA-F]{32}\b',
    'SHA1': r'\b[0-9a-fA-F]{40}\b',
    'SHA256': r'\b[0-9a-fA-F]{64}\b',
    'URL':  r'https?://[^\s<>"{}|\\^`\[\]]+',
    'Email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'Domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
}

# Whitelist — виключити легітимні значення
WHITELIST_IPS = {'127.0.0.1', '0.0.0.0', '255.255.255.255', '8.8.8.8', '1.1.1.1'}
WHITELIST_DOMAINS = {'google.com', 'microsoft.com', 'windows.com', 'localhost'}

# Приклад список відомих шкідливих IOC (в реальності: завантажувати з TI-фідів)
KNOWN_BAD_IPS = {'185.220.101.1', '192.168.100.200', '10.20.30.40'}
KNOWN_BAD_DOMAINS = {'malware-c2.ru', 'evil-payload.net', 'phishing-bank.com'}


def scan_text(text: str) -> dict[str, list[IOCResult]]:
    """Сканує текст і повертає знайдені IOC по типах."""
    found: dict[str, dict[str, IOCResult]] = defaultdict(dict)
    lines = text.splitlines()

    for lineno, line in enumerate(lines, 1):
        for ioc_type, pattern in IOC_PATTERNS.items():
            for match in re.finditer(pattern, line):
                value = match.group()

                # Фільтрація whitelist
                if ioc_type == 'IPv4' and value in WHITELIST_IPS:
                    continue
                if ioc_type == 'Domain' and any(value.endswith(d) for d in WHITELIST_DOMAINS):
                    continue
                # Уникнути дублювання SHA256 і MD5 якщо збігаються з Domain
                if ioc_type == 'Domain' and (len(value) == 32 or len(value) == 40 or len(value) == 64):
                    continue

                if value not in found[ioc_type]:
                    found[ioc_type][value] = IOCResult(ioc_type, value, 0)
                found[ioc_type][value].count += 1
                found[ioc_type][value].lines.append(lineno)

    return {k: list(v.values()) for k, v in found.items()}


def flag_known_bad(results: dict) -> list[tuple]:
    """Порівнює знайдені IOC з відомими шкідливими."""
    alerts = []
    for ip_ioc in results.get('IPv4', []):
        if ip_ioc.value in KNOWN_BAD_IPS:
            alerts.append(('IP', ip_ioc.value, ip_ioc.count, ip_ioc.lines[:5]))
    for dom_ioc in results.get('Domain', []):
        if dom_ioc.value in KNOWN_BAD_DOMAINS:
            alerts.append(('Domain', dom_ioc.value, dom_ioc.count, dom_ioc.lines[:5]))
    return alerts


def print_ioc_report(results: dict, alerts: list) -> None:
    print("\n" + "=" * 60)
    print("IOC ЗВІТ")
    print("=" * 60)

    # Алерти — відомі шкідливі
    if alerts:
        print(f"\n🔴 ВІДОМІ ШКІДЛИВІ IOC ({len(alerts)} знайдено):")
        for ioc_type, value, count, lines in alerts:
            print(f"  [{ioc_type}] {value} — {count}× (рядки: {lines})")

    # Статистика знайдених IOC
    print("\n📊 Знайдені IOC:")
    for ioc_type in ['IPv4', 'Domain', 'URL', 'Email', 'MD5', 'SHA1', 'SHA256']:
        items = results.get(ioc_type, [])
        if items:
            print(f"\n  {ioc_type} ({len(items)} унікальних):")
            for item in sorted(items, key=lambda x: x.count, reverse=True)[:5]:
                print(f"    {item.value:<50} {item.count}×")
            if len(items) > 5:
                print(f"    ... та ще {len(items)-5} інших")


if __name__ == "__main__":
    # Тестовий лог (імітація Windows Event Log з підозрілою активністю)
    sample_log = """
2024-01-15 10:23:11 Connection from 185.220.101.1 to port 3389 accepted
2024-01-15 10:23:15 User admin authenticated from 185.220.101.1
2024-01-15 10:24:02 Process created: powershell.exe -enc JABjAD0A...
2024-01-15 10:24:05 DNS query: malware-c2.ru resolved to 185.220.101.1
2024-01-15 10:24:07 File created: C:\\Users\\Admin\\AppData\\Local\\Temp\\payload.exe
2024-01-15 10:24:08 Hash: d41d8cd98f00b204e9800998ecf8427e (payload.exe)
2024-01-15 10:24:10 HTTP GET http://malware-c2.ru/beacon?id=victim123
2024-01-15 10:24:12 Email sent to attacker@evil.ru from compromised@victim.com
2024-01-15 10:25:00 Outbound connection to 185.220.101.1:443
"""

    results = scan_text(sample_log)
    alerts = flag_known_bad(results)
    print_ioc_report(results, alerts)
```

---

## Лабораторна 7.11.3: YARA-шаблон генератор

YARA — мова для опису і пошуку сімейств шкідливого ПЗ. Тут — генератор базових шаблонів для навчального розуміння структури.

```python
"""
yara_template_generator.py — генератор YARA-шаблонів для навчального аналізу.
Створює шаблон на основі рядків і байт-послідовностей.
"""
import hashlib
import re


def generate_yara_rule(
    rule_name: str,
    description: str,
    author: str,
    strings_list: list[str],
    hex_patterns: list[str] = None,
    condition: str = "any of them"
) -> str:
    """
    Генерує YARA-правило для пошуку шкідливого ПЗ.

    strings_list: рядки для пошуку (текст або regex)
    hex_patterns: шістнадцяткові послідовності байт { 4D 5A 90 00 }
    """
    rule_name_clean = re.sub(r'[^a-zA-Z0-9_]', '_', rule_name)
    date = __import__('datetime').date.today().isoformat()

    # Метадані
    meta = f"""    description = "{description}"
        author = "{author}"
        date = "{date}"
        version = "1.0"
        reference = "Manual analysis" """

    # Рядки
    string_definitions = []
    for i, s in enumerate(strings_list):
        var = f"$str{i+1}"
        # Escape спеціальних символів
        escaped = s.replace('\\', '\\\\').replace('"', '\\"')
        string_definitions.append(f'        {var} = "{escaped}" ascii wide nocase')

    if hex_patterns:
        for i, h in enumerate(hex_patterns):
            var = f"$hex{i+1}"
            string_definitions.append(f'        {var} = {{ {h} }}')

    strings_block = '\n'.join(string_definitions)

    rule = f"""rule {rule_name_clean}
{{
    meta:
        {meta}

    strings:
{strings_block}

    condition:
        {condition}
}}"""
    return rule


def analyze_file_for_strings(filepath: str, min_length: int = 6) -> list[str]:
    """Витягує потенційно значущі рядки з файлу для YARA."""
    interesting = []
    printable = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./\\:')

    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        current = []
        for byte in data:
            char = chr(byte)
            if char in printable:
                current.append(char)
            else:
                if len(current) >= min_length:
                    s = ''.join(current)
                    # Фільтруємо потенційно цікаві рядки
                    if any(keyword in s.lower() for keyword in
                           ['http', 'cmd', 'powershell', 'registry', 'password',
                            'encrypt', 'wallet', 'bitcoin', '.exe', '.dll']):
                        interesting.append(s)
                current = []
    except (IOError, PermissionError) as e:
        print(f"Помилка читання файлу: {e}")

    return interesting[:20]  # Топ-20


if __name__ == "__main__":
    # Приклад: генерація YARA для fictitious ransomware
    rule = generate_yara_rule(
        rule_name="Example_Ransomware_Generic",
        description="Приклад YARA-правила для навчальних цілей",
        author="CyberGuide Student",
        strings_list=[
            "Your files have been encrypted",
            "Bitcoin address",
            "DO NOT try to recover files yourself",
            ".LOCKED",
        ],
        hex_patterns=[
            "52 61 6E 73 6F 6D 57 61 72 65",  # ASCII: RansomWare
        ],
        condition="3 of ($str*) or $hex1"
    )
    print(rule)
    print("\n" + "─" * 50)
    print("Збережіть у файл example.yar і використайте:")
    print("  yara example.yar /path/to/suspicious/file")
    print("  yara -r example.yar /path/to/directory")
```

---

## Лабораторна 7.11.4: Аудит якості паролів (NIST SP 800-63B)

```python
"""
password_audit.py — масовий аудит паролів на відповідність
вимогам NIST SP 800-63B і виявлення слабких патернів.
УВАГА: використовувати ЛИШЕ для аудиту власних облікових записів
або з явним письмовим дозволом власника.
"""
import hashlib
import math
import re
import urllib.request


# Топ-100 найпоширеніших паролів (скорочений список)
COMMON_PASSWORDS = {
    "password", "123456", "password123", "admin", "letmein",
    "qwerty", "abc123", "monkey", "1234567890", "password1",
    "111111", "iloveyou", "adobe123", "123123", "sunshine",
    "1234567", "princess", "azerty", "trustno1", "000000",
    "12345678", "batman", "dragon", "master", "superman",
}


def estimate_entropy(password: str) -> float:
    """Оцінює ентропію пароля на основі розміру алфавіту і довжини."""
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'\d', password): charset += 10
    if re.search(r'[^a-zA-Z\d]', password): charset += 32
    return len(password) * math.log2(charset) if charset else 0


def check_pwned_password(password: str) -> int:
    """Перевіряє пароль через Have I Been Pwned API (k-anonymity)."""
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        with urllib.request.urlopen(url, timeout=5) as resp:
            for line in resp.read().decode().splitlines():
                h, count = line.split(':')
                if h == suffix:
                    return int(count)
    except Exception:
        return -1  # API недоступний
    return 0


def audit_password(password: str, check_hibp: bool = True) -> dict:
    """Повний аудит одного пароля."""
    result = {
        'password': '*' * len(password),
        'length': len(password),
        'entropy': round(estimate_entropy(password), 1),
        'issues': [],
        'pwned_count': 0,
        'score': 100,  # Починаємо з 100, знімаємо бали за проблеми
    }

    # NIST SP 800-63B вимоги
    if len(password) < 8:
        result['issues'].append('Занадто короткий (NIST мінімум: 8 символів)')
        result['score'] -= 30
    elif len(password) < 12:
        result['issues'].append('Рекомендовано 12+ символів')
        result['score'] -= 10

    if password.lower() in COMMON_PASSWORDS:
        result['issues'].append('Пароль у списку найпоширеніших!')
        result['score'] -= 40

    # Патерни
    if re.search(r'(.)\1{2,}', password):
        result['issues'].append('Повторення символів (aaa, 111)')
        result['score'] -= 10
    if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
        result['issues'].append('Послідовні цифри')
        result['score'] -= 5
    if re.search(r'(qwerty|asdf|zxcv)', password.lower()):
        result['issues'].append('Клавіатурний патерн')
        result['score'] -= 10

    # HIBP перевірка
    if check_hibp:
        count = check_pwned_password(password)
        if count > 0:
            result['pwned_count'] = count
            result['issues'].append(f'Знайдено у {count:,} витоках даних!')
            result['score'] -= 50
        elif count == -1:
            result['issues'].append('HIBP API недоступний (перевірте мережу)')

    result['score'] = max(0, result['score'])
    result['rating'] = (
        '🔴 Дуже слабкий' if result['score'] < 30 else
        '🟠 Слабкий'      if result['score'] < 50 else
        '🟡 Середній'     if result['score'] < 70 else
        '🟢 Сильний'      if result['score'] < 90 else
        '✅ Відмінний'
    )
    return result


def bulk_audit(passwords: list[str], check_hibp: bool = False) -> None:
    """Аудит списку паролів без HIBP (для локального тестування)."""
    print(f"\n{'='*65}")
    print(f"{'Пароль':<20} {'Довжина':>7} {'Ентропія':>10} {'Оцінка':>8}  Проблеми")
    print('─' * 65)
    for pwd in passwords:
        r = audit_password(pwd, check_hibp=check_hibp)
        issues_short = '; '.join(r['issues'][:2]) if r['issues'] else 'немає'
        print(f"{r['password']:<20} {r['length']:>7} {r['entropy']:>9.1f} "
              f"{r['score']:>7}  {issues_short[:30]}")


if __name__ == "__main__":
    print("=== Аудит паролів (NIST SP 800-63B) ===")

    test_passwords = [
        "password",
        "P@ssw0rd",
        "Summer2024!",
        "correct-horse-battery-staple",
        "МаківкаВерсняСпіваєТихоРанком",
        "xK9#mP2@nL7$vQ4!",
        "admin",
        "Qwerty123!",
    ]

    # Без HIBP для демонстрації
    bulk_audit(test_passwords, check_hibp=False)

    # Детальний аналіз одного пароля З HIBP:
    print("\n\n=== Детальний аналіз з HIBP ===")
    r = audit_password("password123", check_hibp=True)
    print(f"Пароль: {r['password']}")
    print(f"Рейтинг: {r['rating']} (score={r['score']})")
    if r['pwned_count'] > 0:
        print(f"⚠️  Знайдено у {r['pwned_count']:,} витоках!")
    for issue in r['issues']:
        print(f"  • {issue}")
```

## Джерела та додаткові матеріали

- YARA documentation (virustotal.github.io/yara).
- Have I Been Pwned API (haveibeenpwned.com/API/v3).
- dnspython (dnspython.org) — DNS-запити з Python.

---

**Попередній розділ:** [7.10. Реагування на інцидент](10-reahuvannia-na-intsydent.md)
**Далі:** [7.12. Чек-лист і самоперевірка](12-chek-lyst-i-samoperevirka.md)
**Назад до модуля:** [README модуля 07](README.md)

# 14.12. Практична лабораторна на Python

> Код написаний у форматі ASCII (без emoji) для сумісності з Windows-консоллю, використовує лише стандартну бібліотеку Python. Лабораторна 1 виконує реальні перевірки локальної системи — запускайте її лише на системах, де у вас є на це дозвіл (власна лабораторна машина чи цей навчальний контейнер).

## Лабораторна 1: базовий hardening-аудит Linux (CIS-подібні перевірки)

Скрипт відтворює логіку CIS Benchmarks (розділ 14.2) у мінімальному вигляді: набір незалежних перевірок, кожна з яких повертає pass/fail та рекомендацію.

```python
"""
linux_hardening_audit.py
Мінімалістичний аудит hardening-стану Linux-системи за мотивами CIS Benchmarks.
Виконує лише READ-ONLY перевірки, нічого не змінює в системі.
"""

import os
import subprocess
import stat


def check_root_login_disabled() -> dict:
    """CIS-подібна перевірка: чи заборонено прямий SSH-вхід під root (розділ 14.5)."""
    path = "/etc/ssh/sshd_config"
    if not os.path.exists(path):
        return {"id": "SSH-1", "status": "N/A", "detail": "sshd_config not found"}
    with open(path, encoding="utf-8", errors="ignore") as f:
        content = f.read()
    disabled = "PermitRootLogin no" in content or "PermitRootLogin prohibit-password" in content
    return {
        "id": "SSH-1",
        "description": "Root SSH login should be disabled",
        "status": "PASS" if disabled else "FAIL",
        "recommendation": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config",
    }


def check_password_authentication() -> dict:
    """Перевірка, чи вимкнена парольна автентифікація SSH на користь ключів."""
    path = "/etc/ssh/sshd_config"
    if not os.path.exists(path):
        return {"id": "SSH-2", "status": "N/A", "detail": "sshd_config not found"}
    with open(path, encoding="utf-8", errors="ignore") as f:
        content = f.read()
    disabled = "PasswordAuthentication no" in content
    return {
        "id": "SSH-2",
        "description": "SSH password authentication should be disabled (key-based only)",
        "status": "PASS" if disabled else "FAIL",
        "recommendation": "Set 'PasswordAuthentication no' and use SSH keys instead",
    }


def find_suid_binaries(search_root: str = "/usr/bin", max_results: int = 20) -> dict:
    """Пошук SUID-бінарників (розділ 14.5) - інформаційна перевірка, не pass/fail сама по собі."""
    suid_files = []
    try:
        for entry in os.scandir(search_root):
            if entry.is_file(follow_symlinks=False):
                try:
                    mode = entry.stat().st_mode
                    if mode & stat.S_ISUID:
                        suid_files.append(entry.path)
                except (PermissionError, FileNotFoundError):
                    continue
            if len(suid_files) >= max_results:
                break
    except FileNotFoundError:
        pass
    return {
        "id": "SUID-1",
        "description": f"SUID binaries found in {search_root} (informational, review manually)",
        "status": "INFO",
        "count": len(suid_files),
        "sample": suid_files[:10],
    }


def check_world_writable_files(search_root: str = "/etc", max_results: int = 10) -> dict:
    """Пошук world-writable файлів у критичній директорії - типова CIS-перевірка."""
    findings = []
    try:
        for root, dirs, files in os.walk(search_root):
            for name in files:
                full_path = os.path.join(root, name)
                try:
                    mode = os.stat(full_path).st_mode
                    if mode & stat.S_IWOTH:
                        findings.append(full_path)
                except (PermissionError, FileNotFoundError, OSError):
                    continue
                if len(findings) >= max_results:
                    break
            if len(findings) >= max_results:
                break
    except FileNotFoundError:
        pass
    return {
        "id": "PERM-1",
        "description": f"World-writable files in {search_root}",
        "status": "PASS" if not findings else "FAIL",
        "findings": findings,
        "recommendation": "Remove world-write permission (chmod o-w) from listed files",
    }


def run_audit() -> list:
    checks = [
        check_root_login_disabled(),
        check_password_authentication(),
        find_suid_binaries(),
        check_world_writable_files(),
    ]
    return checks


def print_report(checks: list) -> None:
    print(f"{'ID':<10}{'Status':<8}{'Description'}")
    print("-" * 70)
    for c in checks:
        desc = c.get("description", c.get("detail", ""))
        print(f"{c['id']:<10}{c['status']:<8}{desc}")
        if c.get("recommendation"):
            print(f"           -> {c['recommendation']}")
        if c.get("sample"):
            print(f"           -> sample: {c['sample'][:3]}")


if __name__ == "__main__":
    results = run_audit()
    print_report(results)

    fails = sum(1 for c in results if c["status"] == "FAIL")
    print(f"\nTotal FAIL checks: {fails} / {len([c for c in results if c['status'] in ('PASS', 'FAIL')])}")
```

> **Міні-вправа 14.12.1:** Запустіть скрипт на власній системі (чи цьому навчальному контейнері). Якщо `SSH-1` чи `SSH-2` повертають `N/A` (файл sshd_config відсутній), що це означає для контексту саме цієї машини, і чи це проблема безпеки сама по собі?
>
> <details><summary>Відповідь</summary>
>
> `N/A` означає, що на цій машині взагалі не встановлений SSH-сервер (пакет openssh-server), тому перевірка не застосовна - типова ситуація для контейнерів, призначених виключно для збірки чи виконання коду, без потреби у віддаленому інтерактивному доступі. Це не проблема безпеки сама по собі, а радше ілюстрація важливого принципу з розділу 14.2: перевірка CIS Benchmark завжди контекстуальна - для системи без SSH-сервера сама вимога "hardened SSH config" неприменима, а найкращий hardening SSH у такому випадку - це відсутність SSH-сервера взагалі (мінімізація поверхні атаки, а не лише конфігурація наявного сервісу).
> </details>

## Лабораторна 2: парсер Sysmon-подібних журналів для виявлення LOLBAS-патернів

Демонстрація ідеї з розділу 14.8: аналіз command line процесів для виявлення підозрілих ланцюжків, характерних для технік LOLBAS (Модуль 07).

```python
"""
sysmon_log_analyzer.py
Аналіз спрощених Sysmon-подібних подій (Event ID 1: Process Create) на предмет
підозрілих патернів command line, характерних для LOLBAS-технік (Модуль 07).
"""

import json
import re

# Патерни, типові для зловживання легітимними системними інструментами (LOLBAS)
SUSPICIOUS_PATTERNS = [
    (r"powershell.*-enc(odedcommand)?\s+", "Base64-encoded PowerShell command"),
    (r"powershell.*-nop.*-w\s+hidden", "PowerShell with hidden window and no profile"),
    (r"certutil.*-decode", "certutil abused for file decoding (LOLBAS)"),
    (r"rundll32.*javascript:", "rundll32 abused to execute JavaScript (LOLBAS)"),
    (r"mshta\s+http", "mshta downloading remote content (LOLBAS)"),
    (r"wmic.*process\s+call\s+create", "WMI used for indirect process creation"),
]

# Приклад синтетичних Sysmon-подібних подій для навчальної демонстрації
SAMPLE_EVENTS = [
    {"event_id": 1, "image": "C:\\Windows\\System32\\notepad.exe",
     "command_line": "notepad.exe C:\\Users\\user\\report.txt", "parent_image": "explorer.exe"},
    {"event_id": 1, "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0A...",
     "parent_image": "winword.exe"},
    {"event_id": 1, "image": "C:\\Windows\\System32\\certutil.exe",
     "command_line": "certutil.exe -decode payload.b64 payload.exe", "parent_image": "cmd.exe"},
    {"event_id": 1, "image": "C:\\Windows\\System32\\svchost.exe",
     "command_line": "svchost.exe -k netsvcs", "parent_image": "services.exe"},
]


def analyze_event(event: dict) -> list:
    """Повертає список знайдених підозрілих патернів для однієї події."""
    findings = []
    command_line = event.get("command_line", "").lower()
    for pattern, description in SUSPICIOUS_PATTERNS:
        if re.search(pattern, command_line, re.IGNORECASE):
            findings.append(description)
    return findings


def analyze_log(events: list) -> list:
    alerts = []
    for event in events:
        findings = analyze_event(event)
        if findings:
            alerts.append({
                "image": event.get("image"),
                "parent_image": event.get("parent_image"),
                "command_line": event.get("command_line"),
                "findings": findings,
            })
    return alerts


if __name__ == "__main__":
    alerts = analyze_log(SAMPLE_EVENTS)
    print(f"Analyzed {len(SAMPLE_EVENTS)} events, found {len(alerts)} suspicious.\n")
    for alert in alerts:
        print(f"Image: {alert['image']}")
        print(f"Parent: {alert['parent_image']}")
        print(f"Command line: {alert['command_line'][:80]}")
        for finding in alert["findings"]:
            print(f"  ALERT: {finding}")
        print()
```

> **Міні-вправа 14.12.2:** Додайте новий патерн до `SUSPICIOUS_PATTERNS`, що виявляє виклик `net.exe user /add` (класична техніка створення нового локального облікового запису зловмисником після отримання доступу). Чому саме поєднання `image` (яка програма) і `parent_image` (хто її запустив) - як у Sysmon Event ID 1 - дає значно точнішу детекцію, ніж перевірка лише command line ізольовано, і як це пов'язано з обмеженням Windows Event Log 4688, згаданим у розділі 14.8?
>
> <details><summary>Відповідь</summary>
>
> Новий патерн: `(r"net\.exe\s+user\s+.*\s+/add", "Local user account created via net.exe")`. Поєднання image і parent_image критично важливе, оскільки та сама команда `net.exe user newaccount password /add` має принципово різне значення залежно від контексту: якщо parent_image - `services.exe` чи легітимний скрипт розгортання нового співробітника від адміністратора, це нормальна операційна дія; якщо parent_image - `winword.exe` чи `powershell.exe`, запущений з підозрілим command line з попередньої події, це майже напевно ознака компрометації (виконання пост-експлуатаційної команди через макрос чи скрипт). Стандартний Windows Event Log 4688 (розділ 14.8) без Sysmon-розширення часто взагалі не фіксує повний command line чи ланцюжок parent-child процесів настільки детально, що робить неможливим таке контекстуальне розрізнення - саме цю прогalinu Sysmon і закриває.
> </details>

## Лабораторна 3: CIS Benchmark-подібний оцінювач конфігурації

Узагальнена система підрахунку відповідності конфігурації базовому профілю (розділ 14.2), що працює з довільним словником "поточна конфігурація" проти "очікувана конфігурація".

```python
"""
cis_benchmark_scorer.py
Узагальнений оцінювач відповідності конфігурації системи базовому профілю
у стилі CIS Benchmarks Level 1 (розділ 14.2).
"""

from dataclasses import dataclass, field


@dataclass
class BenchmarkRule:
    rule_id: str
    description: str
    level: int  # 1 or 2, за аналогією з CIS Level 1/Level 2 (розділ 14.2)
    check_fn: callable  # приймає config dict, повертає bool (True = compliant)


# Приклад базового профілю з кількома правилами різного рівня
def build_sample_benchmark() -> list:
    return [
        BenchmarkRule(
            rule_id="1.1.1",
            description="Password minimum length >= 14",
            level=1,
            check_fn=lambda cfg: cfg.get("password_min_length", 0) >= 14,
        ),
        BenchmarkRule(
            rule_id="1.1.2",
            description="Account lockout threshold <= 5 attempts",
            level=1,
            check_fn=lambda cfg: 0 < cfg.get("lockout_threshold", 999) <= 5,
        ),
        BenchmarkRule(
            rule_id="2.3.1",
            description="Credential Guard enabled",
            level=2,
            check_fn=lambda cfg: cfg.get("credential_guard_enabled", False) is True,
        ),
        BenchmarkRule(
            rule_id="5.1.1",
            description="SSH root login disabled",
            level=1,
            check_fn=lambda cfg: cfg.get("ssh_permit_root_login", "yes") in ("no", "prohibit-password"),
        ),
    ]


def score_configuration(rules: list, config: dict, max_level: int = 1) -> dict:
    """max_level=1 перевіряє лише Level 1 (обов'язковий мінімум, розділ 14.2);
    max_level=2 перевіряє Level 1 + Level 2."""
    applicable = [r for r in rules if r.level <= max_level]
    results = []
    for rule in applicable:
        compliant = rule.check_fn(config)
        results.append({
            "rule_id": rule.rule_id,
            "description": rule.description,
            "level": rule.level,
            "compliant": compliant,
        })
    passed = sum(1 for r in results if r["compliant"])
    total = len(results)
    return {
        "results": results,
        "passed": passed,
        "total": total,
        "score_percent": round(100 * passed / total, 1) if total else 0.0,
    }


if __name__ == "__main__":
    benchmark = build_sample_benchmark()

    # Приклад поточної конфігурації системи, що частково відповідає профілю
    current_config = {
        "password_min_length": 12,       # не проходить (потрібно >= 14)
        "lockout_threshold": 5,           # проходить
        "credential_guard_enabled": False,  # не проходить (Level 2)
        "ssh_permit_root_login": "no",    # проходить
    }

    print("=== Level 1 only (обов'язковий мінімум) ===")
    report_l1 = score_configuration(benchmark, current_config, max_level=1)
    for r in report_l1["results"]:
        status = "PASS" if r["compliant"] else "FAIL"
        print(f"[{status}] {r['rule_id']}: {r['description']}")
    print(f"Score: {report_l1['passed']}/{report_l1['total']} ({report_l1['score_percent']}%)\n")

    print("=== Level 1 + Level 2 (розширений профіль) ===")
    report_l2 = score_configuration(benchmark, current_config, max_level=2)
    for r in report_l2["results"]:
        status = "PASS" if r["compliant"] else "FAIL"
        print(f"[{status}] {r['rule_id']}: {r['description']}")
    print(f"Score: {report_l2['passed']}/{report_l2['total']} ({report_l2['score_percent']}%)")
```

> **Міні-вправа 14.12.3:** Запустіть скрипт і порівняйте `score_percent` для Level 1 проти Level 1+2. Чому організація, що звітує лише за Level 1+2 сумарним відсотком (наприклад, "75% відповідності"), може ненавмисно приховати критичну прогалину саме в обов'язковому Level 1 (наприклад, невиправлений `password_min_length`)? Яка практична рекомендація з розділу 14.2 це запобігає?
>
> <details><summary>Відповідь</summary>
>
> Сумарний відсоток усереднює результати обох рівнів разом, тому висока відповідність необов'язковим Level 2-правилам (де організація, можливо, інвестувала значні зусилля) може статистично компенсувати провал критичного, обов'язкового Level 1-правила в загальному підсумку - наприклад, "3 з 4 правил пройдено (75%)" звучить прийнятно, хоча одне з провалених правил (`password_min_length`) є базовим мінімумом, а не опційним посиленням. Розділ 14.2 явно рекомендує розглядати Level 1 і Level 2 **окремо**, а не як єдину усереднену метрику - Level 1 має звітувати як обов'язковий поріг (в ідеалі 100%, будь-яке відхилення - негайний пріоритет), тоді як Level 2 - опційний, вибірковий рівень посилення з окремою оцінкою компромісу безпека/зручність.
> </details>

---

**Попередній розділ:** [14.11. Privileged Access Workstations та Tiered Administration](11-paw-ta-tiered-administration.md)
**Наступний розділ:** [14.13. Чек-лист і самоперевірка](13-chek-lyst-i-samoperevirka.md)
**Назад до модуля:** [README модуля 14](README.md)

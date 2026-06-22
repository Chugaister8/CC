# 3.12. Практична лабораторна на Python

Чотири лабораторні роботи, що автоматизують практичні задачі модуля: аудит стану безпеки системи, парсинг логів для виявлення підозрілої активності, перевірка відкритих портів і автозапуску, а також аналіз хешів файлів. Всі скрипти — виключно для аудиту **власних** систем.

**Вимоги:** Python 3.10+. Лабораторні 1 і 4 на Windows вимагають запуску від адміністратора для деяких перевірок.

---

## Лабораторна 3.12.1: Аудит стану безпеки системи

Скрипт збирає ключові параметри безпеки поточної системи та виводить звіт зі статусом кожного пункту.

```python
"""
security_audit.py — базовий аудит безпеки системи.
Запускати від адміністратора/root для повних результатів.
"""
import platform
import subprocess
import os
import sys
from dataclasses import dataclass
from enum import Enum


class Status(Enum):
    OK = "✅"
    WARN = "⚠️ "
    FAIL = "❌"
    INFO = "[i]"


@dataclass
class CheckResult:
    name: str
    status: Status
    detail: str


def run_cmd(cmd: list[str], shell: bool = False) -> str:
    """Виконати команду і повернути stdout або порожній рядок при помилці."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10, shell=shell
        )
        return result.stdout.strip()
    except Exception:
        return ""


# ──────────────────────────────────────────────
# WINDOWS-ПЕРЕВІРКИ
# ──────────────────────────────────────────────
def check_windows() -> list[CheckResult]:
    results = []

    # Стан Windows Defender
    out = run_cmd(["powershell", "-Command",
        "Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled"])
    if out.strip().lower() == "true":
        results.append(CheckResult("Windows Defender (real-time)", Status.OK, "увімкнено"))
    else:
        results.append(CheckResult("Windows Defender (real-time)", Status.FAIL,
            "вимкнено — критично!"))

    # BitLocker на системному диску
    out = run_cmd(["powershell", "-Command",
        "Get-BitLockerVolume -MountPoint C: | Select-Object -ExpandProperty ProtectionStatus"])
    if "on" in out.lower():
        results.append(CheckResult("BitLocker (C:)", Status.OK, "увімкнено"))
    else:
        results.append(CheckResult("BitLocker (C:)", Status.WARN,
            "вимкнено — дані не захищені при крадіжці"))

    # Фаєрвол (всі три профілі)
    fw_ps = "(Get-NetFirewallProfile -Profile Domain,Public,Private | Where-Object {$_.Enabled -ne $true}).Name"
    out = run_cmd(["powershell", "-Command", fw_ps])
    if not out.strip():
        results.append(CheckResult("Фаєрвол (Domain/Public/Private)", Status.OK, "увімкнено для всіх профілів"))
    else:
        results.append(CheckResult("Фаєрвол (Domain/Public/Private)", Status.FAIL,
            f"вимкнено для профілів: {out.strip()}"))

    # SMBv1
    out = run_cmd(["powershell", "-Command",
        "Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol"])
    if out.strip().lower() == "false":
        results.append(CheckResult("SMBv1", Status.OK, "вимкнено"))
    else:
        results.append(CheckResult("SMBv1", Status.FAIL,
            "увімкнено — вразливість (WannaCry/EternalBlue)"))

    # WDigest (зберігання пароля у відкритому вигляді)
    out = run_cmd(["powershell", "-Command",
        "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' "
        "-Name UseLogonCredential -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty UseLogonCredential"])
    if out.strip() == "0" or out.strip() == "":
        results.append(CheckResult("WDigest (пароль у пам'яті)", Status.OK, "вимкнено"))
    else:
        results.append(CheckResult("WDigest (пароль у пам'яті)", Status.FAIL,
            "увімкнено — паролі зберігаються у відкритому вигляді в LSASS"))

    # AutoRun з USB
    out = run_cmd(["powershell", "-Command",
        "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' "
        "-Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty NoDriveTypeAutoRun"])
    if out.strip() == "255":
        results.append(CheckResult("AutoRun (USB/диски)", Status.OK, "вимкнено"))
    else:
        results.append(CheckResult("AutoRun (USB/диски)", Status.WARN,
            "увімкнено — ризик запуску шкідливого ПЗ з USB"))

    # Приховані розширення файлів
    out = run_cmd(["powershell", "-Command",
        "Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' "
        "-Name HideFileExt | Select-Object -ExpandProperty HideFileExt"])
    if out.strip() == "0":
        results.append(CheckResult("Розширення файлів", Status.OK, "відображаються"))
    else:
        results.append(CheckResult("Розширення файлів", Status.WARN,
            "приховані — .pdf.exe виглядає як .pdf"))

    return results


# ──────────────────────────────────────────────
# LINUX-ПЕРЕВІРКИ
# ──────────────────────────────────────────────
def check_linux() -> list[CheckResult]:
    results = []

    # UFW
    out = run_cmd(["sudo", "ufw", "status"])
    if "active" in out.lower():
        results.append(CheckResult("UFW фаєрвол", Status.OK, "активний"))
    else:
        results.append(CheckResult("UFW фаєрвол", Status.FAIL, "неактивний"))

    # fail2ban
    out = run_cmd(["systemctl", "is-active", "fail2ban"])
    if out.strip() == "active":
        results.append(CheckResult("fail2ban", Status.OK, "активний"))
    else:
        results.append(CheckResult("fail2ban", Status.WARN, "неактивний"))

    # SSH: PermitRootLogin
    out = run_cmd(["grep", "-i", "PermitRootLogin", "/etc/ssh/sshd_config"])
    if "no" in out.lower():
        results.append(CheckResult("SSH PermitRootLogin", Status.OK, "вимкнено"))
    else:
        results.append(CheckResult("SSH PermitRootLogin", Status.FAIL,
            f"небезпечне налаштування: {out.strip() or 'не задано (default=yes)'}"))

    # SSH: PasswordAuthentication
    out = run_cmd(["grep", "-i", "PasswordAuthentication", "/etc/ssh/sshd_config"])
    if "no" in out.lower():
        results.append(CheckResult("SSH PasswordAuthentication", Status.OK,
            "вимкнено (лише ключі)"))
    else:
        results.append(CheckResult("SSH PasswordAuthentication", Status.WARN,
            "увімкнено — вразливо до брутфорсу"))

    # AppArmor
    out = run_cmd(["systemctl", "is-active", "apparmor"])
    if out.strip() == "active":
        results.append(CheckResult("AppArmor", Status.OK, "активний"))
    else:
        results.append(CheckResult("AppArmor", Status.WARN, "неактивний"))

    # Автооновлення
    out = run_cmd(["systemctl", "is-active", "unattended-upgrades"])
    if out.strip() == "active":
        results.append(CheckResult("Автоматичні оновлення безпеки", Status.OK, "увімкнено"))
    else:
        results.append(CheckResult("Автоматичні оновлення безпеки", Status.WARN,
            "неактивні — оновлення треба встановлювати вручну"))

    # Облікові записи з порожнім паролем
    try:
        with open("/etc/shadow", "r") as f:
            empty_pass = [line.split(":")[0] for line in f
                          if line.split(":")[1] == "" and not line.startswith("#")]
        if empty_pass:
            results.append(CheckResult("Порожні паролі", Status.FAIL,
                f"знайдено: {', '.join(empty_pass)}"))
        else:
            results.append(CheckResult("Порожні паролі", Status.OK, "відсутні"))
    except PermissionError:
        results.append(CheckResult("Порожні паролі", Status.INFO,
            "(потрібні права root для перевірки /etc/shadow)")

    return results


# ──────────────────────────────────────────────
# ЗАГАЛЬНІ ПЕРЕВІРКИ
# ──────────────────────────────────────────────
def check_common() -> list[CheckResult]:
    results = []

    # Версія Python (актуальна?)
    py_ver = sys.version_info
    if py_ver.major == 3 and py_ver.minor >= 11:
        results.append(CheckResult("Python (runtime)", Status.OK,
            f"{py_ver.major}.{py_ver.minor}.{py_ver.micro}"))
    else:
        results.append(CheckResult("Python (runtime)", Status.WARN,
            f"{py_ver.major}.{py_ver.minor} — розгляньте оновлення"))

    return results


# ──────────────────────────────────────────────
# ЗВІТ
# ──────────────────────────────────────────────
def print_report(results: list[CheckResult]) -> None:
    print("\n" + "=" * 60)
    print("   ЗВІТ АУДИТУ БЕЗПЕКИ СИСТЕМИ")
    print(f"   {platform.system()} {platform.release()} | {platform.node()}")
    print("=" * 60)

    counts = {Status.OK: 0, Status.WARN: 0, Status.FAIL: 0, Status.INFO: 0}
    for r in results:
        counts[r.status] += 1
        print(f"  {r.status.value}  {r.name:<40} {r.detail}")

    print("=" * 60)
    print(f"  Результат: {counts[Status.OK]} OK  |  "
          f"{counts[Status.WARN]} попереджень  |  "
          f"{counts[Status.FAIL]} критичних")
    if counts[Status.FAIL] > 0:
        print("  ⛔ Знайдено критичні проблеми — усуньте негайно!")
    elif counts[Status.WARN] > 0:
        print("  ⚠️  Є рекомендації до покращення.")
    else:
        print("  🎉 Базові перевірки пройдено!")
    print()


if __name__ == "__main__":
    system = platform.system()
    results = check_common()
    if system == "Windows":
        results += check_windows()
    elif system == "Linux":
        results += check_linux()
    else:
        print(f"Система {system} не підтримується цим скриптом.")
    print_report(results)
```

**Завдання:**
1. Запустіть скрипт (Windows — від адміністратора, Linux — з `sudo python3`).
2. Для кожного ❌ або ⚠️ знайдіть відповідний підрозділ у розділах 3.6/3.7 і виправте.
3. Запустіть повторно після виправлень і переконайтесь, що статус змінився на ✅.

---

## Лабораторна 3.12.2: Парсинг логів і виявлення брутфорсу

Скрипт аналізує логи SSH (Linux) або Security Event Log (Windows) і виявляє підозрілу активність.

```python
"""
log_analyzer.py — аналіз SSH-логів для виявлення брутфорсу.
Linux: python3 log_analyzer.py
Windows: адаптована версія для Event Log нижче.
"""
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path


def parse_auth_log(log_path: str = "/var/log/auth.log") -> None:
    path = Path(log_path)
    if not path.exists():
        # Спробувати альтернативний шлях (Debian/Ubuntu vs RHEL)
        alt = Path("/var/log/secure")
        if alt.exists():
            path = alt
        else:
            print(f"Лог-файл не знайдено: {log_path}")
            return

    failed_attempts: dict[str, list[str]] = defaultdict(list)
    accepted_logins: list[tuple] = []

    # Паттерни
    failed_re = re.compile(
        r"(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for (?:invalid user )?(\S+) from (\S+)"
    )
    accepted_re = re.compile(
        r"(\w+\s+\d+\s+\d+:\d+:\d+).*Accepted (\S+) for (\S+) from (\S+)"
    )

    with open(path, "r", errors="replace") as f:
        for line in f:
            if m := failed_re.search(line):
                timestamp, user, ip = m.group(1), m.group(2), m.group(3)
                failed_attempts[ip].append(f"{timestamp} (user: {user})")
            if m := accepted_re.search(line):
                timestamp, method, user, ip = m.groups()
                accepted_logins.append((timestamp, method, user, ip))

    # Звіт: брутфорс (>10 спроб з однієї IP)
    print("\n" + "=" * 60)
    print("  АНАЛІЗ SSH-ЛОГІВ: ПІДОЗРІЛІ IP")
    print("=" * 60)

    brute_force_ips = {ip: attempts for ip, attempts in failed_attempts.items()
                       if len(attempts) >= 10}

    if brute_force_ips:
        print(f"\n⚠️  IP-адреси з 10+ невдалими спробами ({len(brute_force_ips)} знайдено):\n")
        for ip, attempts in sorted(brute_force_ips.items(),
                                    key=lambda x: len(x[1]), reverse=True):
            print(f"  {ip:<20} {len(attempts):>5} спроб  "
                  f"(перша: {attempts[0][:15]}, остання: {attempts[-1][:15]})")
    else:
        print("\n✅ IP з >10 невдалих спроб не знайдено.")

    # Топ 5 цілей брутфорсу за кількістю атакуючих
    print(f"\n  Загалом унікальних IP, що атакували: {len(failed_attempts)}")
    print(f"  Загалом невдалих спроб: {sum(len(v) for v in failed_attempts.values())}")

    # Успішні входи
    print("\n" + "=" * 60)
    print("  УСПІШНІ ВХОДИ (останні 10)")
    print("=" * 60)
    if accepted_logins:
        for ts, method, user, ip in accepted_logins[-10:]:
            print(f"  {ts:<20} {user:<15} з {ip:<20} ({method})")
    else:
        print("  Успішних входів не знайдено в логах.")


def parse_windows_security_log() -> None:
    """Аналіз Security Event Log на Windows через PowerShell."""
    import subprocess
    print("\n⏳ Читання Windows Security Log (може зайняти кілька секунд)...\n")
    ps_script = """
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 500 -ErrorAction SilentlyContinue
$grouped = $events | Group-Object {$_.Properties[19].Value} | Sort-Object Count -Descending
foreach ($g in $grouped | Select-Object -First 15) {
    Write-Output "$($g.Count)`t$($g.Name)"
}
"""
    result = subprocess.run(
        ["powershell", "-Command", ps_script],
        capture_output=True, text=True
    )
    if result.stdout.strip():
        print("  Кількість невдалих входів за IP (з останніх 500 подій):")
        print(f"  {'Спроб':>8}  {'IP-адреса'}")
        print("  " + "-" * 35)
        for line in result.stdout.strip().splitlines():
            if line.strip():
                parts = line.split("\t")
                if len(parts) == 2:
                    count, ip = parts
                    marker = "⚠️ " if int(count) >= 10 else "   "
                    print(f"  {marker}{count:>6}  {ip}")
    else:
        print("  Потрібні права адміністратора або події відсутні.")


if __name__ == "__main__":
    import platform
    if platform.system() == "Linux":
        parse_auth_log()
    elif platform.system() == "Windows":
        parse_windows_security_log()
    else:
        print("Система не підтримується.")
```

**Завдання:**
1. Запустіть на своїй машині. Якщо SSH доступний ззовні — майже гарантовано знайдете сотні спроб.
2. Порівняйте список IP, що атакують, з тим, що показує `sudo fail2ban-client status sshd` — чи вже заблоковані найактивніші?
3. Спробуйте адаптувати скрипт для аналізу іншого лог-файлу (наприклад `/var/log/ufw.log`).

---

## Лабораторна 3.12.3: Сканер підозрілого автозапуску і процесів

```python
"""
autorun_scanner.py — перевірка автозапуску і запущених процесів.
Windows: запускати від адміністратора.
Linux: запускати з sudo.
"""
import platform
import subprocess
import os
from pathlib import Path


def scan_windows_autorun() -> None:
    """Перевірка записів автозапуску в реєстрі Windows."""
    print("\n" + "=" * 60)
    print("  ПЕРЕВІРКА АВТОЗАПУСКУ (WINDOWS REGISTRY)")
    print("=" * 60)

    reg_paths = [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    ]

    suspicious_keywords = ["temp", "tmp", "appdata\\roaming", "%appdata%",
                            "powershell", "cmd", "wscript", "cscript", "mshta"]

    for path in reg_paths:
        result = subprocess.run(
            ["reg", "query", path],
            capture_output=True, text=True, encoding="cp866"
        )
        if result.returncode == 0 and result.stdout.strip():
            print(f"\n[{path}]")
            for line in result.stdout.strip().splitlines():
                line = line.strip()
                if not line or line == path:
                    continue
                is_suspicious = any(kw in line.lower() for kw in suspicious_keywords)
                marker = "⚠️  ПІДОЗРІЛИЙ: " if is_suspicious else "   "
                print(f"  {marker}{line}")


def scan_linux_persistence() -> None:
    """Перевірка механізмів закріплення на Linux."""
    print("\n" + "=" * 60)
    print("  ПЕРЕВІРКА МЕХАНІЗМІВ ЗАКРІПЛЕННЯ (LINUX)")
    print("=" * 60)

    # Cron jobs
    print("\n[Cron jobs — системні]")
    for cron_dir in ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.weekly"]:
        p = Path(cron_dir)
        if p.exists():
            for f in p.iterdir():
                if f.is_file():
                    mtime = f.stat().st_mtime
                    print(f"  {f.name:<30} (змінено: "
                          f"{__import__('datetime').datetime.fromtimestamp(mtime):%Y-%m-%d})")

    # Systemd user services
    print("\n[Systemd user services]")
    user_systemd = Path.home() / ".config/systemd/user"
    if user_systemd.exists():
        for f in user_systemd.glob("*.service"):
            print(f"  ⚠️  Знайдено user-service: {f.name}")
    else:
        print("  Не знайдено (~/.config/systemd/user)")

    # ~/.bashrc, ~/.profile на підозрілі рядки
    print("\n[Shell startup files — пошук підозрілого]")
    suspicious_re = __import__("re").compile(
        r"curl|wget|bash\s+-c|python.*-c|eval|base64", __import__("re").IGNORECASE
    )
    for startup_file in [".bashrc", ".bash_profile", ".profile", ".zshrc"]:
        p = Path.home() / startup_file
        if p.exists():
            with open(p) as f:
                for i, line in enumerate(f, 1):
                    if suspicious_re.search(line):
                        print(f"  ⚠️  {startup_file}:{i}: {line.strip()}")


def scan_suspicious_processes() -> None:
    """Виявлення підозрілих процесів."""
    print("\n" + "=" * 60)
    print("  ПІДОЗРІЛІ ПРОЦЕСИ")
    print("=" * 60)

    if platform.system() == "Windows":
        # Процеси без шляху або з незвичного місця
        ps_script = """
Get-Process | Where-Object {$_.Path -ne $null} | ForEach-Object {
    $suspicious = $false
    $reasons = @()
    if ($_.Path -match 'temp|tmp|appdata\\\\roaming|downloads' ) {
        $suspicious = $true; $reasons += 'підозрілий шлях'
    }
    if ($suspicious) {
        "$($_.Name)|$($_.Id)|$($_.Path)|$($reasons -join ',')"
    }
}
"""
        result = subprocess.run(
            ["powershell", "-Command", ps_script],
            capture_output=True, text=True
        )
        if result.stdout.strip():
            print("\n⚠️  Процеси з підозрілого місця:")
            for line in result.stdout.strip().splitlines():
                parts = line.split("|")
                if len(parts) >= 3:
                    print(f"  {parts[0]:<20} PID:{parts[1]:<8} {parts[2]}")
        else:
            print("  Підозрілих процесів не знайдено.")

    elif platform.system() == "Linux":
        # Процеси без видимого виконуваного файлу (deleted) — ознака malware
        result = subprocess.run(
            ["ls", "-la", "/proc/"],
            capture_output=True, text=True
        )
        deleted = subprocess.run(
            ["bash", "-c",
             "ls -la /proc/*/exe 2>/dev/null | grep deleted | head -20"],
            capture_output=True, text=True
        )
        if deleted.stdout.strip():
            print("\n⚠️  Процеси із видаленим виконуваним файлом (можлива ознака malware):")
            print(deleted.stdout)
        else:
            print("  Процесів з видаленим exe не знайдено.")


if __name__ == "__main__":
    system = platform.system()
    if system == "Windows":
        scan_windows_autorun()
    elif system == "Linux":
        scan_linux_persistence()
    scan_suspicious_processes()
```

**Завдання:**
1. Запустіть скрипт і перегляньте всі ⚠️-позначки.
2. Для кожного підозрілого запису в автозапуску знайдіть відповідну програму і оцініть: чи ви свідомо її встановлювали?
3. Спробуйте знайти власний PID і перевірити шлях до виконуваного файлу вручну.

---

## Лабораторна 3.12.4: Верифікатор хешів файлів

Скрипт обчислює і порівнює хеші важливих системних файлів — основа виявлення їх несанкціонованої модифікації.

```python
"""
file_integrity.py — базова перевірка цілісності файлів через хеші.
Спочатку створює «еталон», потім порівнює з поточним станом.
"""
import hashlib
import json
from pathlib import Path
import platform
import sys


BASELINE_FILE = Path("integrity_baseline.json")

# Набір файлів для моніторингу (адаптуйте під свою систему)
MONITOR_PATHS_LINUX = [
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers",
    "/etc/ssh/sshd_config", "/etc/hosts", "/etc/crontab",
    "/bin/ls", "/bin/ps", "/usr/bin/sudo",
]

MONITOR_PATHS_WINDOWS = [
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\powershell.exe",
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\System32\lsass.exe",
    r"C:\Windows\System32\winlogon.exe",
]


def sha256_file(path: str) -> str | None:
    """Обчислити SHA-256 хеш файлу."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError) as e:
        return f"ERROR: {e}"


def create_baseline(paths: list[str]) -> None:
    """Створити еталонну базу хешів."""
    baseline = {}
    print("📸 Створення еталону хешів...")
    for p in paths:
        h = sha256_file(p)
        baseline[p] = h
        status = "✅" if not h.startswith("ERROR") else "⚠️ "
        print(f"  {status} {p}")
        print(f"       {h[:64]}")

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)
    print(f"\n✅ Еталон збережено: {BASELINE_FILE} ({len(baseline)} файлів)")


def verify_integrity(paths: list[str]) -> None:
    """Порівняти поточні хеші з еталоном."""
    if not BASELINE_FILE.exists():
        print("❌ Еталон не знайдено. Спочатку запустіть: python file_integrity.py --baseline")
        sys.exit(1)

    with open(BASELINE_FILE) as f:
        baseline = json.load(f)

    print("\n" + "=" * 60)
    print("  ПЕРЕВІРКА ЦІЛІСНОСТІ ФАЙЛІВ")
    print("=" * 60)

    changed, missing, new = [], [], []

    # Перевірити файли з еталону
    for path, old_hash in baseline.items():
        current_hash = sha256_file(path)
        if current_hash.startswith("ERROR"):
            missing.append((path, current_hash))
        elif current_hash != old_hash:
            changed.append((path, old_hash, current_hash))

    # Знайти нові файли, що не були в еталоні
    for p in paths:
        if p not in baseline:
            new.append(p)

    # Звіт
    if changed:
        print(f"\n⚠️  ЗМІНЕНІ ФАЙЛИ ({len(changed)}):")
        for path, old, cur in changed:
            print(f"\n  Файл:   {path}")
            print(f"  Було:   {old[:32]}...")
            print(f"  Стало:  {cur[:32]}...")
    else:
        print("\n✅ Змінених файлів не знайдено.")

    if missing:
        print(f"\n❌ НЕДОСТУПНІ ФАЙЛИ ({len(missing)}):")
        for path, err in missing:
            print(f"  {path}: {err}")

    if new:
        print(f"\n[i] Нові файли (не в еталоні):")
        for p in new:
            print(f"  {p}")

    print(f"\n  Перевірено: {len(baseline)} файлів")


if __name__ == "__main__":
    system = platform.system()
    paths = MONITOR_PATHS_LINUX if system == "Linux" else MONITOR_PATHS_WINDOWS

    if "--baseline" in sys.argv:
        create_baseline(paths)
    else:
        verify_integrity(paths)
        print("\nДля створення нового еталону: python file_integrity.py --baseline")
```

**Завдання:**
1. Запустіть `python file_integrity.py --baseline` для створення еталону.
2. Змініть будь-який тестовий файл (наприклад `/tmp/test.txt`, а потім додайте його до `MONITOR_PATHS_LINUX`).
3. Запустіть `python file_integrity.py` і переконайтесь, що зміна виявлена.
4. Налаштуйте cron/Task Scheduler для щоденного запуску з надсиланням звіту електронною поштою.

## Джерела та додаткові матеріали

- Python `hashlib` — стандартна бібліотека для хешування.
- Python `subprocess` — взаємодія з ОС.
- AIDE (aide.github.io) — production-рівень file integrity monitoring для Linux.
- Tripwire — комерційний аналог AIDE.

---

**Попередній розділ:** [3.11. Шкідливе ПЗ і антивірусні рішення](11-shkidlyve-po.md)
**Далі:** [3.13. Чек-лист і самоперевірка](13-chek-lyst-i-samoperevirka.md)
**Назад до модуля:** [README модуля 03](README.md)

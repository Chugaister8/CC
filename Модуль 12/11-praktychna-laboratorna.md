# 12.11. Практична лабораторна на Python

> Усі скрипти цього розділу призначені для роботи з системами, на які у вас є явний письмовий дозвіл (власна лабораторна інфраструктура, localhost, чи система з підписаним RoE — розділ 12.7). Сканування чужих систем без дозволу є кримінальним правопорушенням за ст. 361 КК України. Код написаний у форматі ASCII (без emoji) для сумісності з Windows-консоллю.

## Лабораторна 1: калькулятор CVSS 3.1 Base Score

Реалізація офіційної формули CVSS 3.1 для розрахунку базового балу з вектора метрик, розглянутих у розділі 12.4.

```python
"""
cvss_calculator.py
Розрахунок CVSS 3.1 Base Score за офіційною специфікацією FIRST.org.
Не використовує сторонніх бібліотек криптографії - лише арифметика за специфікацією.
"""

import math

# Ваги метрик згідно офіційної специфікації CVSS 3.1
AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC_WEIGHTS = {"L": 0.77, "H": 0.44}
PR_WEIGHTS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_WEIGHTS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
UI_WEIGHTS = {"N": 0.85, "R": 0.62}
CIA_WEIGHTS = {"H": 0.56, "L": 0.22, "N": 0.0}


def round_up(value: float) -> float:
    """CVSS-специфічне округлення вгору до 1 знака після коми."""
    int_value = int(round(value * 100000))
    if int_value % 10000 == 0:
        return int_value / 100000.0
    return (math.floor(int_value / 10000) + 1) / 10.0


def calculate_cvss_base(av: str, ac: str, pr: str, ui: str, scope: str,
                         conf: str, integ: str, avail: str) -> dict:
    """
    Розрахунок CVSS 3.1 Base Score.
    av: Attack Vector (N/A/L/P)
    ac: Attack Complexity (L/H)
    pr: Privileges Required (N/L/H)
    ui: User Interaction (N/R)
    scope: Scope (U/C)
    conf, integ, avail: Confidentiality/Integrity/Availability Impact (H/L/N)
    """
    iss = 1 - ((1 - CIA_WEIGHTS[conf]) * (1 - CIA_WEIGHTS[integ]) * (1 - CIA_WEIGHTS[avail]))

    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    pr_weight = PR_WEIGHTS_CHANGED[pr] if scope == "C" else PR_WEIGHTS_UNCHANGED[pr]
    exploitability = 8.22 * AV_WEIGHTS[av] * AC_WEIGHTS[ac] * pr_weight * UI_WEIGHTS[ui]

    if impact <= 0:
        base_score = 0.0
    elif scope == "U":
        base_score = round_up(min(impact + exploitability, 10))
    else:
        base_score = round_up(min(1.08 * (impact + exploitability), 10))

    severity = severity_rating(base_score)
    return {"base_score": base_score, "severity": severity, "impact_subscore": round(impact, 2),
            "exploitability_subscore": round(exploitability, 2)}


def severity_rating(score: float) -> str:
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


if __name__ == "__main__":
    # Приклад: вектор Log4Shell-подібної вразливості
    # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
    result = calculate_cvss_base(
        av="N", ac="L", pr="N", ui="N", scope="C",
        conf="H", integ="H", avail="H"
    )
    print("CVSS 3.1 Base Score:", result["base_score"])
    print("Severity:", result["severity"])
    print("Impact subscore:", result["impact_subscore"])
    print("Exploitability subscore:", result["exploitability_subscore"])
```

> **Міні-вправа 12.11.1:** Змініть вектор у прикладі на `AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N` (локальна атака, висока складність, потрібні високі привілеї, взаємодія користувача, низький вплив на конфіденційність і цілісність). Який Severity-рейтинг ви очікуєте отримати ще до запуску скрипта, і чому?
>
> <details><summary>Відповідь</summary>
>
> Очікується низький бал (ймовірно Low, ~2.0-3.0), оскільки всі фактори знижують експлуатованість (локальний вектор, висока складність, потрібні високі привілеї, потрібна взаємодія користувача) і вплив обмежений (без впливу на доступність). Запустивши скрипт, перевірте точне число — воно ілюструє, як CVSS системно винагороджує складність експлуатації низьким балом навіть за реальний, підтверджений вплив.
> </details>

## Лабораторна 2: пріоритизація вразливостей за CVSS + EPSS + KEV

Скрипт моделює логіку прийняття рішень із розділу 12.4 (дерево пріоритизації) на прикладі локального JSON-«інвентарю» вразливостей.

```python
"""
vuln_prioritizer.py
Пріоритизація списку вразливостей за CVSS, EPSS та наявністю в каталозі KEV.
Дані - локальний приклад; у реальному використанні джерелом були б API NVD
та FIRST.org EPSS (див. коментар нижче щодо мережевих запитів).
"""

from dataclasses import dataclass


@dataclass
class VulnRecord:
    cve_id: str
    cvss: float
    epss: float          # ймовірність експлуатації 0.0-1.0
    in_kev: bool          # присутність у CISA KEV
    asset_critical: bool  # чи критичний актив для бізнесу


def prioritize(vuln: VulnRecord) -> str:
    """Відтворює дерево рішень з розділу 12.4. Мітки ASCII для сумісності з Windows-консоллю."""
    if vuln.in_kev:
        return "P1: immediate"
    if vuln.epss >= 0.10 and vuln.cvss >= 7.0:
        return "P1: immediate"
    if vuln.epss >= 0.10 or vuln.asset_critical:
        return "P2: this week"
    return "P3: scheduled SLA"


SAMPLE_INVENTORY = [
    VulnRecord("CVE-2024-EXAMPLE-1", cvss=9.8, epss=0.02, in_kev=False, asset_critical=True),
    VulnRecord("CVE-2024-EXAMPLE-2", cvss=6.1, epss=0.45, in_kev=True, asset_critical=False),
    VulnRecord("CVE-2024-EXAMPLE-3", cvss=8.2, epss=0.15, in_kev=False, asset_critical=False),
    VulnRecord("CVE-2024-EXAMPLE-4", cvss=4.5, epss=0.01, in_kev=False, asset_critical=False),
]

if __name__ == "__main__":
    print(f"{'CVE ID':<22} {'CVSS':<6} {'EPSS':<7} {'KEV':<6} {'Priority'}")
    print("-" * 60)
    for v in sorted(SAMPLE_INVENTORY, key=lambda x: (not x.in_kev, -x.epss, -x.cvss)):
        priority = prioritize(v)
        print(f"{v.cve_id:<22} {v.cvss:<6} {v.epss:<7} {str(v.in_kev):<6} {priority}")
```

Зверніть увагу: результат сортування свідомо ставить `CVE-2024-EXAMPLE-2` (CVSS лише 6.1) на перше місце через присутність у KEV — це навмисна ілюстрація головного уроку розділу 12.4: формальна тяжкість і реальна терміновість — різні речі.

> **Міні-вправа 12.11.2:** Додайте до `SAMPLE_INVENTORY` новий запис із `cvss=9.5, epss=0.03, in_kev=False, asset_critical=True`. До якого пріоритету (P1/P2/P3) він потрапить за поточною логікою `prioritize()`? Чи узгоджується це з вашою інтуїцією, і чи вважаєте ви цю логіку пріоритизації достатньою для реальної продакшн-системи?
>
> <details><summary>Відповідь</summary>
>
> За поточною логікою запис потрапить у **P2** (`asset_critical=True`, але EPSS нижче порогу 0.10 і відсутність у KEV не дає P1). Це піднімає легітимне питання: чи достатньо високий сам по собі CVSS (9.5) для критичного активу, щоб виправдати P1 незалежно від EPSS? У реальному використанні багато організацій додають третє правило: `if vuln.cvss >= 9.0 and vuln.asset_critical: return "P1"`, оскільки для найбільш чутливих активів організації часто готові прийняти вищі витрати на терміновий патчинг навіть за низької статистичної ймовірності експлуатації. Це демонструє, що дерево пріоритизації з розділу 12.4 — відправна точка, яку кожна організація адаптує під власний ризик-апетит (Environmental metrics CVSS, розділ 12.4), а не універсальна формула без винятків.
> </details>

## Лабораторна 3: простий TCP-сканер портів (лише для авторизованих цілей)

```python
"""
simple_port_scanner.py
Мінімалістичний TCP connect-сканер портів для навчальних цілей.
Використовувати ЛИШЕ проти localhost чи систем з письмовим дозволом (RoE, розділ 12.7).
"""

import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-alt",
}


def scan_port(target: str, port: int, timeout: float = 0.5) -> tuple:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((target, port))
        is_open = (result == 0)
    except socket.error:
        is_open = False
    finally:
        sock.close()
    return port, is_open


def scan_target(target: str, ports: list) -> list:
    open_ports = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_port, target, p): p for p in ports}
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                service = COMMON_PORTS.get(port, "unknown")
                open_ports.append((port, service))
    return sorted(open_ports)


if __name__ == "__main__":
    target_host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    print(f"Scanning authorized target: {target_host}")
    print("WARNING: use only against systems you own or have written permission to test.")
    results = scan_target(target_host, list(COMMON_PORTS.keys()))
    if results:
        for port, service in results:
            print(f"  {port}/tcp open  {service}")
    else:
        print("  No open ports found among the checked common ports.")
```

> **Міні-вправа 12.11.3:** Скрипт перевіряє лише невеликий фіксований список поширених портів (`COMMON_PORTS`). Реальні сканери (Nmap) за замовчуванням перевіряють до 1000 портів, а повне сканування - усі 65535. Які два практичні компроміси (trade-offs) створює розширення діапазону портів, розглянуті в розділі 12.3?
>
> <details><summary>Відповідь</summary>
>
> 1. **Час виконання проти повноти** — сканування всіх 65535 портів для кожної цілі значно повільніше, особливо в мережевому масштабі з тисячами хостів; більшість практичних сканувань обмежуються поширеними портами як компромісом.
> 2. **Помітність (noise) проти повноти** — ширше й агресивніше сканування (більше портів, менші таймаути, більше паралельних потоків) створює більш виражений слід у мережевих логах і системах виявлення вторгнень цілі, що для активної фази пентесту (розділ 12.6) підвищує ризик виявлення до завершення розвідки, якщо це суперечить меті конкретної вправи (наприклад, прихованого Red Team-тесту з розділу 12.9).
> </details>

---

**Попередній розділ:** [12.10. Відповідальне розкриття вразливостей (VDP)](10-vidpovidalne-rozkryttia-vrazlyvostey.md)
**Наступний розділ:** [12.12. Чек-лист і самоперевірка](12-chek-lyst-i-samoperevirka.md)
**Назад до модуля:** [README модуля 12](README.md)

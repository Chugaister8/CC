# 16.10. Практична лабораторна на Python

> Код написаний у форматі ASCII (без emoji) для сумісності з Windows-консоллю, використовує лише стандартну бібліотеку Python.

## Лабораторна 1: спрощений кореляційний рушій SIEM

Реалізує ідею багатоступеневого кореляційного правила з розділу 16.3 - виявлення послідовності подій у визначеному часовому вікні.

```python
"""
correlation_engine.py
Спрощений кореляційний рушій для виявлення послідовності підозрілих подій
у часовому вікні (розділ 16.3) - приклад правила "невдалі спроби входу +
успішний вхід з нової локації + створення привілейованого облікового запису".
"""

from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class LogEvent:
    timestamp: datetime
    event_type: str    # "failed_login" | "successful_login" | "account_created"
    user: str
    source_ip: str
    is_new_location: bool = False
    is_privileged_account: bool = False


def find_suspicious_sequences(events: list, window_minutes: int = 15) -> list:
    """
    Шукає для кожного користувача послідовність:
    >=2 failed_login -> successful_login (нова локація) -> account_created (привілейований)
    у межах заданого часового вікна.
    """
    alerts = []
    events_by_user = {}
    for e in events:
        events_by_user.setdefault(e.user, []).append(e)

    for user, user_events in events_by_user.items():
        user_events.sort(key=lambda e: e.timestamp)

        for i, anchor in enumerate(user_events):
            if anchor.event_type != "account_created" or not anchor.is_privileged_account:
                continue

            window_start = anchor.timestamp - timedelta(minutes=window_minutes)
            window_events = [e for e in user_events if window_start <= e.timestamp <= anchor.timestamp]

            failed_logins = [e for e in window_events if e.event_type == "failed_login"]
            new_location_success = [e for e in window_events
                                     if e.event_type == "successful_login" and e.is_new_location]

            if len(failed_logins) >= 2 and new_location_success:
                alerts.append({
                    "user": user,
                    "window_start": window_start,
                    "trigger_event": anchor,
                    "failed_login_count": len(failed_logins),
                    "new_location_logins": len(new_location_success),
                    "severity": "P1" if len(failed_logins) >= 3 else "P2",
                })
    return alerts


if __name__ == "__main__":
    base_time = datetime(2026, 7, 2, 3, 0, 0)

    sample_events = [
        LogEvent(base_time, "failed_login", "admin", "203.0.113.10"),
        LogEvent(base_time + timedelta(minutes=2), "failed_login", "admin", "203.0.113.10"),
        LogEvent(base_time + timedelta(minutes=3), "successful_login", "admin", "203.0.113.10",
                  is_new_location=True),
        LogEvent(base_time + timedelta(minutes=8), "account_created", "admin", "203.0.113.10",
                  is_privileged_account=True),
        # Легітимний, непов'язаний випадок - не має спрацювати
        LogEvent(base_time + timedelta(hours=5), "successful_login", "developer", "198.51.100.5"),
        LogEvent(base_time + timedelta(hours=5, minutes=1), "account_created", "developer",
                  "198.51.100.5", is_privileged_account=False),
    ]

    alerts = find_suspicious_sequences(sample_events)

    print(f"Analyzed {len(sample_events)} events, found {len(alerts)} suspicious sequence(s):\n")
    for alert in alerts:
        print(f"Severity: {alert['severity']}")
        print(f"User: {alert['user']}")
        print(f"Failed logins in window: {alert['failed_login_count']}")
        print(f"New-location successful logins: {alert['new_location_logins']}")
        print(f"Trigger: privileged account created at {alert['trigger_event'].timestamp}")
        print()
```

> **Міні-вправа 16.10.1:** Змініть `window_minutes` з 15 на 5 і запустіть скрипт знову. Чи спрацює правило для того самого набору подій? Що це демонструє про компроміс при налаштуванні (tuning) часового вікна кореляційного правила, згаданий у розділі 16.3 щодо Alert Fatigue?
>
> <details><summary>Відповідь</summary>
>
> Із `window_minutes=5` послідовність (0хв, 2хв, 3хв, 8хв) все ще вкладається, оскільки різниця між першою невдалою спробою (0 хв) і створенням облікового запису (8 хв) перевищує 5 хвилин лише для найпершої події - перевірте: `window_start` рахується від моменту `account_created` (8 хв) назад, тобто вікно [3, 8] хв не включить подію о 0 хв, і `failed_login_count` впаде до 1, що не задовольняє умову `>= 2` - правило НЕ спрацює. Це прямо демонструє компроміс з розділу 16.3: занадто вузьке часове вікно ризикує пропустити реальну атаку, розтягнуту трохи довше за очікування (False Negative), тоді як занадто широке вікно підвищує ризик випадкового збігу непов'язаних подій одного користувача (False Positive) - оптимальне значення вимагає емпіричного налаштування на основі реальних даних організації, а не довільного вибору.
> </details>

## Лабораторна 2: зіставлення IOC з урахуванням Pyramid of Pain

Реалізує принцип із розділу 16.6: різні типи індикаторів мають різну вагу довіри та пріоритету.

```python
"""
ioc_matcher.py
Зіставлення індикаторів компрометації (IOC) з урахуванням їх позиції
у Pyramid of Pain (розділ 16.6) - різні типи індикаторів мають різну вагу.
"""

from dataclasses import dataclass

# Вага індикатора за Pyramid of Pain: чим вище в піраміді, тим цінніше й стійкіше виявлення
PYRAMID_WEIGHTS = {
    "hash": 1,
    "ip": 2,
    "domain": 2,
    "network_artifact": 3,
    "tool_behavior": 4,
    "ttp": 5,
}


@dataclass
class ThreatIndicator:
    ioc_type: str    # ключ з PYRAMID_WEIGHTS
    value: str
    source: str        # напр. "CERT-UA", "commercial_feed"
    confidence: float  # 0.0-1.0


@dataclass
class ObservedEvent:
    event_id: str
    ioc_type: str
    value: str


def build_sample_threat_intel() -> list:
    return [
        ThreatIndicator("hash", "a1b2c3d4e5f6...", "commercial_feed", 0.9),
        ThreatIndicator("ip", "203.0.113.55", "CERT-UA", 0.85),
        ThreatIndicator("domain", "malicious-example.test", "CERT-UA", 0.8),
        ThreatIndicator("ttp", "T1055_process_injection", "CERT-UA", 0.95),
    ]


def match_events_against_intel(events: list, threat_intel: list) -> list:
    matches = []
    intel_index = {(ti.ioc_type, ti.value): ti for ti in threat_intel}

    for event in events:
        key = (event.ioc_type, event.value)
        if key in intel_index:
            ti = intel_index[key]
            weight = PYRAMID_WEIGHTS.get(ti.ioc_type, 0)
            matches.append({
                "event_id": event.event_id,
                "ioc_type": ti.ioc_type,
                "value": ti.value,
                "source": ti.source,
                "confidence": ti.confidence,
                "pyramid_weight": weight,
                "priority_score": round(ti.confidence * weight, 2),
            })
    return matches


if __name__ == "__main__":
    threat_intel = build_sample_threat_intel()

    observed_events = [
        ObservedEvent("EVT-001", "hash", "a1b2c3d4e5f6..."),
        ObservedEvent("EVT-002", "ip", "203.0.113.55"),
        ObservedEvent("EVT-003", "ttp", "T1055_process_injection"),
        ObservedEvent("EVT-004", "domain", "totally-benign-site.com"),  # немає збігу
    ]

    matches = match_events_against_intel(observed_events, threat_intel)
    matches.sort(key=lambda m: -m["priority_score"])

    print(f"{'Event':<10}{'Type':<15}{'Source':<18}{'Confidence':<12}{'Priority Score'}")
    print("-" * 70)
    for m in matches:
        print(f"{m['event_id']:<10}{m['ioc_type']:<15}{m['source']:<18}"
              f"{m['confidence']:<12}{m['priority_score']}")

    print(f"\nTotal matches: {len(matches)} / {len(observed_events)} observed events")
```

> **Міні-вправа 16.10.2:** Подія `EVT-003` (збіг за TTP) і гіпотетична подія зі збігом лише за хешем мають однаковий рівень `confidence=0.9` від джерела. Поясніть, чому `priority_score` для TTP-збігу все одно вищий, і яке практичне рішення Tier 1-аналітик (розділ 16.2) має прийняти першим, розглядаючи чергу з обох сповіщень.
>
> <details><summary>Відповідь</summary>
>
> `priority_score` розраховується як добуток `confidence` на `pyramid_weight`, а вага TTP (5) значно вища за вагу hash (1) - навіть за однакового рівня довіри джерела (0.9), TTP-збіг отримує `priority_score = 4.5`, тоді як hash-збіг - лише `0.9`. Це відображає принцип з розділу 16.6: збіг за TTP означає, що спостережена поведінка відповідає фундаментальній методології атаки, яку зловмиснику дорого й повільно змінювати, тоді як збіг за хешем може виявитися застарілим уже наступного дня через тривіальну перекомпіляцію. Tier 1-аналітик, розглядаючи чергу з обох сповіщень одночасно (типова ситуація Alert Fatigue, розділ 16.3), має пріоритизувати розслідування TTP-збігу першим - вищий `priority_score` тут прямо слугує практичним інструментом сортування черги за розділом 16.2, а не лише теоретичною ілюстрацією.
> </details>

## Лабораторна 3: калькулятор MTTD/MTTR з набору інцидентів

Реалізує метрики з розділу 16.7 на основі списку задокументованих інцидентів з часовими мітками.

```python
"""
soc_metrics_calculator.py
Розрахунок MTTD (Mean Time to Detect) та MTTR (Mean Time to Respond)
на основі набору інцидентів (розділ 16.7).
"""

from dataclasses import dataclass
from datetime import datetime
import statistics


@dataclass
class Incident:
    incident_id: str
    attack_time: datetime       # коли атака фактично відбулася (за форензичним аналізом)
    detection_time: datetime     # коли SOC виявив (SIEM alert / Threat Hunting)
    containment_time: datetime   # коли загрозу стримано
    severity: str                  # "P1" | "P2" | "P3" | "P4"


def compute_ttd_minutes(incident: Incident) -> float:
    return (incident.detection_time - incident.attack_time).total_seconds() / 60


def compute_ttr_minutes(incident: Incident) -> float:
    return (incident.containment_time - incident.detection_time).total_seconds() / 60


def compute_metrics(incidents: list) -> dict:
    ttd_values = [compute_ttd_minutes(i) for i in incidents]
    ttr_values = [compute_ttr_minutes(i) for i in incidents]

    return {
        "count": len(incidents),
        "mttd_minutes": round(statistics.mean(ttd_values), 1) if ttd_values else 0,
        "mttr_minutes": round(statistics.mean(ttr_values), 1) if ttr_values else 0,
        "mttd_median_minutes": round(statistics.median(ttd_values), 1) if ttd_values else 0,
        "worst_ttd_minutes": round(max(ttd_values), 1) if ttd_values else 0,
    }


def metrics_by_severity(incidents: list) -> dict:
    by_sev = {}
    for i in incidents:
        by_sev.setdefault(i.severity, []).append(i)

    result = {}
    for sev, sev_incidents in by_sev.items():
        result[sev] = compute_metrics(sev_incidents)
    return result


if __name__ == "__main__":
    incidents = [
        Incident("INC-001",
                 datetime(2026, 6, 1, 10, 0), datetime(2026, 6, 1, 10, 15),
                 datetime(2026, 6, 1, 10, 45), "P2"),
        Incident("INC-002",
                 datetime(2026, 6, 5, 3, 0), datetime(2026, 6, 6, 2, 0),  # повільне виявлення
                 datetime(2026, 6, 6, 3, 0), "P1"),
        Incident("INC-003",
                 datetime(2026, 6, 10, 14, 0), datetime(2026, 6, 10, 14, 5),
                 datetime(2026, 6, 10, 14, 20), "P3"),
        Incident("INC-004",
                 datetime(2026, 6, 20, 9, 0), datetime(2026, 6, 20, 9, 30),
                 datetime(2026, 6, 20, 11, 0), "P1"),
    ]

    overall = compute_metrics(incidents)
    print("Overall SOC metrics:")
    print(f"  Incidents analyzed: {overall['count']}")
    print(f"  MTTD (mean): {overall['mttd_minutes']} minutes")
    print(f"  MTTD (median): {overall['mttd_median_minutes']} minutes")
    print(f"  Worst-case TTD: {overall['worst_ttd_minutes']} minutes")
    print(f"  MTTR (mean): {overall['mttr_minutes']} minutes")

    print("\nMetrics by severity:")
    by_sev = metrics_by_severity(incidents)
    for sev in sorted(by_sev.keys()):
        m = by_sev[sev]
        print(f"  {sev}: MTTD={m['mttd_minutes']} min, MTTR={m['mttr_minutes']} min, count={m['count']}")
```

> **Міні-вправа 16.10.3:** Зверніть увагу на різницю між `mttd_minutes` (середнє) і `mttd_median_minutes` (медіана) в результатах запуску - `INC-002` має аномально великий TTD (майже 24 години) порівняно з рештою інцидентів. Чому медіана в цьому випадку дає точнішу картину "типової" продуктивності SOC, ніж середнє значення, і яку окрему управлінську дію мало б спричинити саме `worst_ttd_minutes`?
>
> <details><summary>Відповідь</summary>
>
> Середнє значення чутливе до викидів (outliers): один аномально повільний інцидент (`INC-002`, майже 1400 хвилин) суттєво "тягне" середнє вгору, створюючи враження, що типовий інцидент виявляється повільніше, ніж це насправді відбувається для більшості випадків. Медіана стійкіша до поодиноких екстремальних значень і краще відображає "типовий" досвід - три з чотирьох інцидентів мають TTD від 5 до 30 хвилин, і медіана це покаже точніше за середнє. Водночас `worst_ttd_minutes` (найгірший випадок) не варто ігнорувати як просто статистичний шум - навпаки, саме він має спричинити окрему управлінську дію: розслідування, чому саме `INC-002` (до речі, P1 - найвищої критичності) виявлявся так довго, чи є системна причина (прогалина SIEM-покриття, розділ 16.3, для конкретного типу атаки) і чи потрібне окреме коригувальне впровадження нового Use Case чи Threat Hunting-гіпотези (розділ 16.5) саме для цього сценарію - агрегована метрика (середнє чи медіана) корисна для тренду, але найгірший випадок часто містить найцінніший урок для конкретного покращення.
> </details>

---

**Попередній розділ:** [16.9. Побудова SOC: In-house, MSSP, Hybrid](09-pobudova-soc-modeli.md)
**Наступний розділ:** [16.11. Чек-лист і самоперевірка](11-chek-lyst-i-samoperevirka.md)
**Назад до модуля:** [README модуля 16](README.md)

# 15.12. Практична лабораторна на Python

> Код написаний у форматі ASCII (без emoji) для сумісності з Windows-консоллю, використовує лише стандартну бібліотеку Python.

## Лабораторна 1: трекер Statement of Applicability з мультифреймворковим мапуванням

Реалізує ідею з розділів 15.3 та 15.8: один внутрішній контроль одночасно закриває вимоги кількох зовнішніх режимів.

```python
"""
soa_tracker.py
Трекер Statement of Applicability (розділ 15.3) з мапуванням контролів
на кілька одночасних режимів комплаєнсу (розділ 15.8).
"""

from dataclasses import dataclass, field


@dataclass
class Control:
    control_id: str          # напр. "A.8.8"
    description: str
    applicable: bool
    status: str               # "not_started" | "in_progress" | "implemented"
    justification: str
    mapped_frameworks: dict = field(default_factory=dict)  # {"PCI DSS": "Req 11.4", ...}


def build_sample_soa() -> list:
    return [
        Control("A.8.8", "Upravlinnia tekhnichnymy vrazlyvostiamy", True, "implemented",
                "Znyzhuie RISK-001 (RCE cherez nevypravleni CVE)",
                {"PCI DSS": "Req 11.3", "SOC 2": "CC7.1"}),
        Control("A.8.24", "Shyfruvannia danykh", True, "implemented",
                "Znyzhuie RISK-002 (vytik danykh klientiv)",
                {"PCI DSS": "Req 3.5", "SOC 2": "CC6.7", "GDPR": "Art. 32(1)(a)"}),
        Control("A.6.3", "Obiznanist ta navchannia", True, "in_progress",
                "Znyzhuie ryzyk uspishnoho fishynhu personalu",
                {"SOC 2": "CC1.4"}),
        Control("A.7.4", "Monitorynh fizychnoi bezpeky", False, "not_started",
                "Orhanizatsiia ne volodiie vlasnymy servernymy prymishenniamy",
                {}),
        Control("A.8.28", "Bezpechne koduvannia", True, "not_started",
                "Znyzhuie ryzyky OWASP Top 10 u vlasnii rozrobtsi",
                {"PCI DSS": "Req 6.2"}),
    ]


def compute_readiness(controls: list) -> dict:
    applicable = [c for c in controls if c.applicable]
    implemented = [c for c in applicable if c.status == "implemented"]
    in_progress = [c for c in applicable if c.status == "in_progress"]
    not_started = [c for c in applicable if c.status == "not_started"]

    readiness_percent = round(100 * len(implemented) / len(applicable), 1) if applicable else 0.0

    return {
        "total_applicable": len(applicable),
        "implemented": len(implemented),
        "in_progress": len(in_progress),
        "not_started": len(not_started),
        "readiness_percent": readiness_percent,
    }


def find_unjustified_na(controls: list) -> list:
    """Виявляє потенційну проблему з розділу 15.3: незастосовність без обгрунтування."""
    return [c for c in controls if not c.applicable and not c.justification.strip()]


def print_report(controls: list) -> None:
    print(f"{'ID':<10}{'Applicable':<12}{'Status':<14}{'Frameworks'}")
    print("-" * 70)
    for c in controls:
        applicable_str = "Yes" if c.applicable else "No"
        frameworks_str = ", ".join(c.mapped_frameworks.keys()) if c.mapped_frameworks else "-"
        print(f"{c.control_id:<10}{applicable_str:<12}{c.status:<14}{frameworks_str}")

    readiness = compute_readiness(controls)
    print(f"\nReadiness: {readiness['implemented']}/{readiness['total_applicable']} "
          f"applicable controls implemented ({readiness['readiness_percent']}%)")
    print(f"In progress: {readiness['in_progress']}, Not started: {readiness['not_started']}")

    unjustified = find_unjustified_na(controls)
    if unjustified:
        print(f"\nWARNING: {len(unjustified)} control(s) marked N/A without justification:")
        for c in unjustified:
            print(f"  - {c.control_id}")


if __name__ == "__main__":
    soa = build_sample_soa()
    print_report(soa)
```

> **Міні-вправа 15.12.1:** Додайте новий контроль `A.5.30` (Continuity readiness), позначений `applicable=False`, з порожнім `justification=""`. Запустіть скрипт і перевірте, чи функція `find_unjustified_na` коректно його виявляє. Чому саме такий скрипт корисний як підготовчий крок **перед** сертифікаційним аудитом (розділ 15.4), а не під час нього?
>
> <details><summary>Відповідь</summary>
>
> Після додавання такого запису `find_unjustified_na` поверне його у списку попереджень, оскільки `applicable=False` і `justification` порожній - точна відповідність умові функції. Практична цінність: автоматизована перевірка на цю конкретну, добре відому категорію проблеми (розділ 15.3, міні-вправа 15.3.1) дозволяє команді виявити й виправити необгрунтовані записи SoA заздалегідь, під час внутрішнього аудиту чи навіть щоденної роботи, а не бути захопленою зненацька, коли зовнішній аудитор сертифікаційного органу знайде цю саму прогалину під час Stage 1 (розділ 15.4) - подібний підхід є прикладом Compliance as Code (розділ 15.11) у мініатюрі.
> </details>

## Лабораторна 2: калькулятор зрілості NIST CSF Tier

Спрощена самооцінка Tier (розділ 15.5) на основі відповідей на діагностичні запитання по кожній функції.

```python
"""
nist_csf_tier_calculator.py
Спрощений калькулятор Implementation Tier за NIST CSF 2.0 (розділ 15.5)
на основі відповідей на діагностичні запитання по шести функціях.
"""

FUNCTIONS = ["GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]

# Кожна відповідь: 1 (Partial) .. 4 (Adaptive), за шкалою Tiers з розділу 15.5
TIER_NAMES = {1: "Partial", 2: "Risk Informed", 3: "Repeatable", 4: "Adaptive"}


def score_function(answers: list) -> float:
    """Середнє значення відповідей (1-4) для однієї функції."""
    return sum(answers) / len(answers) if answers else 0.0


def compute_overall_tier(function_scores: dict) -> dict:
    """
    Обчислює загальний Tier організації.
    Використовує МІНІМАЛЬНЕ значення серед функцій, а не середнє -
    відображаючи принцип, що загальна зрілість обмежена найслабшою функцією
    (аналогічно принципу 'найповільніша залежність визначає реальний RTO', Модуль 13, розділ 13.9).
    """
    overall_score = min(function_scores.values())
    overall_tier = int(round(overall_score))
    overall_tier = max(1, min(4, overall_tier))
    return {
        "function_scores": function_scores,
        "overall_score": round(overall_score, 2),
        "overall_tier": overall_tier,
        "overall_tier_name": TIER_NAMES[overall_tier],
        "weakest_function": min(function_scores, key=function_scores.get),
    }


if __name__ == "__main__":
    # Приклад: відповіді на діагностичні запитання (1-4) для кожної функції
    sample_answers = {
        "GOVERN": [2, 2, 1],       # низька зрілість - політики не формалізовані
        "IDENTIFY": [3, 3, 4],
        "PROTECT": [3, 3, 3],
        "DETECT": [2, 2, 3],
        "RESPOND": [3, 2, 2],
        "RECOVER": [3, 3, 3],
    }

    function_scores = {fn: round(score_function(answers), 2)
                        for fn, answers in sample_answers.items()}

    result = compute_overall_tier(function_scores)

    print("NIST CSF 2.0 - Function scores:")
    for fn in FUNCTIONS:
        score = function_scores[fn]
        tier = max(1, min(4, int(round(score))))
        print(f"  {fn:<10} score={score:<5} approx Tier {tier} ({TIER_NAMES[tier]})")

    print(f"\nOverall Tier: {result['overall_tier']} ({result['overall_tier_name']})")
    print(f"Weakest function: {result['weakest_function']} "
          f"(score {function_scores[result['weakest_function']]})")
    print("\nRecommendation: prioritize improvement in the weakest function first,")
    print("since overall organizational maturity is bounded by it.")
```

> **Міні-вправа 15.12.2:** Чому скрипт навмисно використовує `min()` (найслабшу функцію) для визначення загального Tier, а не `average()` (середнє значення)? Змініть `sample_answers["GOVERN"]` на `[4, 4, 4]` і порівняйте, як змінюється `overall_tier` при використанні `min` проти того, що було б при використанні середнього значення.
>
> <details><summary>Відповідь</summary>
>
> Використання `min()` відображає реалістичний принцип: організація з бездоганним технічним захистом (PROTECT/DETECT на високому рівні), але без формалізованого управлінського нагляду (GOVERN на низькому рівні), все ще має суттєву структурну слабкість - подібно до того, як "плоска" адміністративна модель (Модуль 14, розділ 14.11) робить нерелевантними інші технічні контролі, якщо привілейовані облікові дані не ізольовані належно. Середнє значення замаскувало б цю слабкість, показавши прийнятний загальний бал, що не відображає реального ризику. Після зміни `GOVERN` на `[4, 4, 4]` (середнє 4.0) `min()`-підхід дасть значно вищий загальний Tier, оскільки тепер найслабша функція - інша (наприклад, RESPOND чи DETECT з нижчими оцінками), а не GOVERN - це коректно демонструє, що покращення однієї функції підвищує загальну зрілість лише тоді, коли вона більше не є "вузьким місцем" (bottleneck).
> </details>

## Лабораторна 3: калькулятор рівня due diligence постачальника (Vendor Risk Tiering)

Реалізує логіку з розділу 15.10 - визначення необхідної глибини перевірки постачальника на основі чутливості даних і рівня доступу.

```python
"""
vendor_risk_tiering.py
Калькулятор рівня due diligence постачальника (розділ 15.10)
на основі чутливості даних, рівня доступу та критичності залежності.
"""

from dataclasses import dataclass

TIER_REQUIREMENTS = {
    "Critical": [
        "Full security questionnaire",
        "SOC 2 Type II or ISO 27001 certificate required",
        "Right-to-audit clause in contract",
        "Annual reassessment",
        "Incident notification SLA (24-72h)",
    ],
    "Significant": [
        "Simplified security questionnaire",
        "Public reputation and certificate check",
        "Reassessment every 2 years",
    ],
    "Low": [
        "No formal assessment required",
    ],
}


@dataclass
class Vendor:
    name: str
    data_sensitivity: int    # 0 = none, 1 = internal, 2 = confidential, 3 = highly sensitive (PII/payment)
    access_level: int         # 0 = none, 1 = read-only limited, 2 = broad access, 3 = admin/critical systems
    business_criticality: int  # 0 = low, 1 = medium, 2 = high (outage stops core business)


def compute_vendor_tier(vendor: Vendor) -> str:
    """Спрощена логіка: максимальний фактор ризику визначає рівень,
    за аналогією з правилом класифікації активу за CIA (Модуль 13, розділ 13.3)."""
    max_factor = max(vendor.data_sensitivity, vendor.access_level, vendor.business_criticality)

    if max_factor >= 3 or (vendor.data_sensitivity >= 2 and vendor.access_level >= 2):
        return "Critical"
    if max_factor >= 2:
        return "Significant"
    return "Low"


def assess_vendors(vendors: list) -> None:
    print(f"{'Vendor':<27}{'Tier':<12}{'Requirements'}")
    print("-" * 90)
    for v in vendors:
        tier = compute_vendor_tier(v)
        reqs = TIER_REQUIREMENTS[tier]
        print(f"{v.name:<27}{tier:<12}{reqs[0]}")
        for extra_req in reqs[1:]:
            print(f"{'':<39}{extra_req}")
        print()


if __name__ == "__main__":
    vendors = [
        Vendor("Cloud backup provider", data_sensitivity=3, access_level=2, business_criticality=2),
        Vendor("Internal chat SaaS tool", data_sensitivity=1, access_level=1, business_criticality=1),
        Vendor("Office supplies vendor", data_sensitivity=0, access_level=0, business_criticality=0),
        Vendor("Outsourced dev contractor", data_sensitivity=2, access_level=3, business_criticality=1),
    ]

    assess_vendors(vendors)
```

> **Міні-вправа 15.12.3:** Постачальник "Outsourced dev contractor" має `data_sensitivity=2` (Confidential), але `access_level=3` (адміністративний доступ до критичних систем). Поясніть, чому функція `compute_vendor_tier` класифікує його як "Critical", хоча жоден окремий фактор не дорівнює 3, окрім `access_level`. Яке практичне значення має саме друга умова (`data_sensitivity >= 2 and access_level >= 2`) у коді, а не лише перевірка `max_factor >= 3`?
>
> <details><summary>Відповідь</summary>
>
> `access_level=3` сам по собі вже задовольняє умову `max_factor >= 3`, тому цей конкретний приклад класифікується як Critical навіть без другої умови. Але друга умова (`data_sensitivity >= 2 and access_level >= 2`) окремо важлива для інших сценаріїв: постачальник із помірним, а не максимальним доступом (наприклад, `access_level=2`) до конфіденційних даних (`data_sensitivity=2`) також має класифікуватися як Critical, оскільки **комбінація** двох середніх факторів разом становить серйозний ризик, навіть якщо жоден з них окремо не досягає максимального значення 3 - подібно до логіки FAIR (Модуль 13, розділ 13.6), де ризик - добуток кількох факторів, а не максимум лише одного з них. Без цієї другої умови функція пропустила б реалістичний сценарій "помірний доступ до помірно чутливих даних", що на практиці часто становить не менший ризик, ніж один екстремальний фактор.
> </details>

---

**Попередній розділ:** [15.11. GRC-платформи та комплаєнс як код](11-grc-platformy.md)
**Наступний розділ:** [15.13. Чек-лист і самоперевірка](13-chek-lyst-i-samoperevirka.md)
**Назад до модуля:** [README модуля 15](README.md)

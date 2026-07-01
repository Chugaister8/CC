# 13.12. Практична лабораторна на Python

> Код написаний у форматі ASCII (без emoji) для сумісності з Windows-консоллю, використовує лише стандартну бібліотеку Python.

## Лабораторна 1: калькулятор ALE (Annualized Loss Expectancy)

Реалізація класичної формули з розділу 13.6: `SLE = AV x EF`, `ALE = SLE x ARO`, разом із порівнянням вартості контролю проти зниження ALE.

```python
"""
ale_calculator.py
Розрахунок Single Loss Expectancy (SLE) та Annualized Loss Expectancy (ALE)
за класичною формулою кількісної оцінки ризику (розділ 13.6).
"""

from dataclasses import dataclass


@dataclass
class RiskScenario:
    name: str
    asset_value: float       # AV - вартість активу (грн)
    exposure_factor: float   # EF - частка втраченої вартості, 0.0-1.0
    aro: float                # ARO - очікувана кількість реалізацій на рік


def calculate_sle(scenario: RiskScenario) -> float:
    return scenario.asset_value * scenario.exposure_factor


def calculate_ale(scenario: RiskScenario) -> float:
    return calculate_sle(scenario) * scenario.aro


def evaluate_control(scenario: RiskScenario, control_cost: float,
                      aro_after_control: float) -> dict:
    """Порівнює ALE до і після впровадження контролю з розділу 13.8."""
    ale_before = calculate_ale(scenario)
    scenario_after = RiskScenario(
        name=scenario.name + " (after control)",
        asset_value=scenario.asset_value,
        exposure_factor=scenario.exposure_factor,
        aro=aro_after_control,
    )
    ale_after = calculate_ale(scenario_after)
    ale_reduction = ale_before - ale_after
    net_benefit = ale_reduction - control_cost

    return {
        "ale_before": ale_before,
        "ale_after": ale_after,
        "ale_reduction": ale_reduction,
        "control_cost": control_cost,
        "net_benefit": net_benefit,
        "recommendation": "Впровадити контроль" if net_benefit > 0 else "Контроль економічно необгрунтований",
    }


if __name__ == "__main__":
    # Приклад з розділу 13.6: RISK-001, база даних клієнтів
    risk_001 = RiskScenario(
        name="RISK-001: RCE через невиправлену CVE в API платежiв",
        asset_value=50_000_000,
        exposure_factor=0.20,
        aro=0.25,
    )

    sle = calculate_sle(risk_001)
    ale = calculate_ale(risk_001)
    print(f"Scenario: {risk_001.name}")
    print(f"SLE: {sle:,.0f} UAH")
    print(f"ALE: {ale:,.0f} UAH/year")
    print()

    result = evaluate_control(risk_001, control_cost=500_000, aro_after_control=0.125)
    print("Control evaluation:")
    for key, value in result.items():
        if isinstance(value, float):
            print(f"  {key}: {value:,.0f}")
        else:
            print(f"  {key}: {value}")
```

> **Міні-вправа 13.12.1:** Додайте нову функцію `compare_controls(scenario, controls: list)`, яка приймає список контролів (кожен - словник з `name`, `cost`, `aro_after`) і повертає контроль з найбільшим `net_benefit`. Яка практична управлінська цінність такої функції для розділу 13.8 (обробка ризику)?
>
> <details><summary>Відповідь</summary>
>
> Практична цінність - автоматизація порівняння кількох альтернативних варіантів зниження одного й того самого ризику (наприклад, дешевше WAF-правило проти дорожчого повного архітектурного рефакторингу) за єдиним фінансово обґрунтованим критерієм (net_benefit), а не інтуїтивним вибором. Це прямо підтримує рішення про стратегію обробки ризику (розділ 13.8): замість запитання «чи впроваджувати контроль X», функція дозволяє запитати «який з доступних контролів дає найбільшу чисту вигоду за наявний бюджет», що є типовим реальним запитанням на нараді з пріоритизації бюджету безпеки.
> </details>

## Лабораторна 2: спрощена симуляція FAIR методом Монте-Карло

Демонстрація ключової ідеї розділу 13.6 - розрахунок ризику через діапазони, а не точкові значення, з використанням симуляції для отримання розподілу ймовірностей.

```python
"""
fair_monte_carlo.py
Спрощена симуляція FAIR (Factor Analysis of Information Risk) методом Монте-Карло.
Демонструє розрахунок Loss Event Frequency (LEF) та Loss Magnitude (LM)
з діапазонів замість точкових значень (розділ 13.6).
"""

import random
import statistics


def triangular_sample(low: float, most_likely: float, high: float) -> float:
    """Трикутний розподіл - проста апроксимація експертної оцінки 'від-до-найімовірніше'."""
    return random.triangular(low, high, most_likely)


def run_fair_simulation(tef_range: tuple, vuln_range: tuple,
                         primary_loss_range: tuple, secondary_loss_range: tuple,
                         iterations: int = 10000) -> list:
    """
    tef_range, vuln_range, primary_loss_range, secondary_loss_range:
    кожен - кортеж (low, most_likely, high)
    Повертає список симульованих річних втрат (ALE-подібне значення на одну ітерацію).
    """
    results = []
    for _ in range(iterations):
        tef = triangular_sample(*tef_range)
        vuln = triangular_sample(*vuln_range)
        lef = tef * vuln  # Loss Event Frequency

        primary_loss = triangular_sample(*primary_loss_range)
        secondary_loss = triangular_sample(*secondary_loss_range)
        loss_magnitude = primary_loss + secondary_loss

        annual_loss = lef * loss_magnitude
        results.append(annual_loss)
    return results


def summarize(results: list) -> dict:
    sorted_results = sorted(results)
    n = len(sorted_results)
    return {
        "mean": statistics.mean(results),
        "median": statistics.median(results),
        "p10": sorted_results[int(n * 0.10)],
        "p50": sorted_results[int(n * 0.50)],
        "p90": sorted_results[int(n * 0.90)],
    }


if __name__ == "__main__":
    random.seed(42)  # для відтворюваності результатів навчальної лабораторної

    # Приклад з міні-вправи 13.6.2: RISK-001
    results = run_fair_simulation(
        tef_range=(5, 15, 50),                       # спроб атаки на рік
        vuln_range=(0.05, 0.10, 0.20),                # ймовірність успіху спроби
        primary_loss_range=(200_000, 1_000_000, 3_000_000),
        secondary_loss_range=(500_000, 4_000_000, 15_000_000),
        iterations=10000,
    )

    summary = summarize(results)
    print("FAIR Monte Carlo simulation results (UAH/year):")
    print(f"  Mean:           {summary['mean']:,.0f}")
    print(f"  Median (P50):   {summary['p50']:,.0f}")
    print(f"  P10 (optimistic):  {summary['p10']:,.0f}")
    print(f"  P90 (pessimistic): {summary['p90']:,.0f}")
    print()
    print("Interpretation: with 90% confidence, annual losses from this scenario")
    print(f"will not exceed {summary['p90']:,.0f} UAH.")
```

> **Міні-вправа 13.12.2:** Запустіть скрипт і порівняйте отримане значення `mean` із простим точковим розрахунком ALE (використовуючи лише `most_likely`-значення з кожного діапазону через формулу з Лабораторної 1). Чому ці два числа не обов'язково збігаються, навіть коли `most_likely` - це "середнє" значення кожного діапазону?
>
> <details><summary>Відповідь</summary>
>
> Точковий розрахунок через `most_likely` дає добуток "найімовірніших" значень кожного фактора, тоді як симуляція Монте-Карло усереднює результат добутку **випадкових комбінацій** значень з усього діапазону кожного фактора, включно з рідкісними поєднаннями "все погано одночасно" (високий TEF, висока Vulnerability, високий Loss Magnitude в одній ітерації). Оскільки підсумкове значення - добуток кількох незалежних випадкових величин, а не їхніх точкових оцінок, математичне сподівання добутку не дорівнює добутку точкових значень (за винятком особливих випадків симетричних розподілів) - це і є практична причина, чому FAIR вважається методологічно точнішим за наївний point-estimate ALE, зокрема тому що краще відображає "хвіст" малоймовірних, але дуже дорогих сценаріїв.
> </details>

## Лабораторна 3: генератор матриці ризиків (heat map) у консолі

Візуалізація матриці 5х5 з розділу 13.5 та автоматичне зіставлення сценаріїв ризику з реєстру.

```python
"""
risk_matrix.py
Побудова текстової матриці ризиків (heat map) 5x5 та автоматична
класифікація сценаріїв ризику з реєстру (розділ 13.5, 13.7).
"""

from dataclasses import dataclass

RISK_LEVELS = [
    # рядки: ймовірність 5->1 (згори вниз), стовпці: вплив 1->5 (зліва направо)
    ["Serednii", "Vysokyi",  "Krytychnyi", "Krytychnyi", "Krytychnyi"],
    ["Nyzkyi",   "Serednii", "Vysokyi",    "Krytychnyi", "Krytychnyi"],
    ["Nyzkyi",   "Serednii", "Serednii",   "Vysokyi",    "Krytychnyi"],
    ["Nyzkyi",   "Nyzkyi",   "Serednii",   "Serednii",   "Vysokyi"],
    ["Nyzkyi",   "Nyzkyi",   "Nyzkyi",     "Serednii",   "Serednii"],
]


@dataclass
class RiskRegisterEntry:
    risk_id: str
    description: str
    likelihood: int  # 1-5
    impact: int       # 1-5


def get_risk_level(likelihood: int, impact: int) -> str:
    row_index = 5 - likelihood  # likelihood 5 -> row 0 (top)
    col_index = impact - 1       # impact 1 -> col 0 (left)
    return RISK_LEVELS[row_index][col_index]


def print_matrix():
    print("            " + "  ".join(f"Impact={i}" for i in range(1, 6)))
    for row_idx, row in enumerate(RISK_LEVELS):
        likelihood = 5 - row_idx
        cells = "  ".join(f"{cell:<11}" for cell in row)
        print(f"Likelihood={likelihood}  {cells}")


def classify_register(entries: list) -> None:
    print(f"\n{'ID':<10}{'Level':<12}{'Description'}")
    print("-" * 60)
    for entry in sorted(entries, key=lambda e: (-e.likelihood, -e.impact)):
        level = get_risk_level(entry.likelihood, entry.impact)
        print(f"{entry.risk_id:<10}{level:<12}{entry.description}")


if __name__ == "__main__":
    print("Risk Matrix (5x5):")
    print_matrix()

    # Сценарії з розділу 13.4-13.5
    register = [
        RiskRegisterEntry("RISK-001", "RCE cherez API platezhiv", likelihood=4, impact=5),
        RiskRegisterEntry("RISK-002", "Vytik cherez nadmirni prava dostupu", likelihood=3, impact=4),
        RiskRegisterEntry("RISK-003", "Regionalnyi zbiy khmarnoho postachalnyka", likelihood=2, impact=3),
        RiskRegisterEntry("RISK-004", "Tryvalyi prostiy cherez vidkliuchennia zhyvlennia", likelihood=4, impact=4),
    ]
    classify_register(register)
```

> **Міні-вправа 13.12.3:** Додайте до реєстру новий запис `RISK-005` з `likelihood=5, impact=2`. Використовуючи матрицю з коду, визначте очікуваний рівень ризику ще до запуску скрипта, а потім перевірте результат. Чому висока ймовірність із низьким впливом дає лише "Serednii" (Середній), а не "Krytychnyi", навіть коли подія майже гарантовано відбудеться?
>
> <details><summary>Відповідь</summary>
>
> За матрицею з розділу 13.5, комірка (likelihood=5, impact=2) відповідає рівню "Serednii". Це відображає навмисний методологічний принцип матриці ризиків: рівень ризику - функція **обох** вимірів одночасно, а не лише ймовірності. Подія, що відбувається майже напевно, але завдає незначної шкоди (наприклад, дрібні, малопомітні спроби сканування периметра, що рутинно блокуються файрволом), не повинна конкурувати за увагу й ресурси команди з рідкісними, але катастрофічними сценаріями (RISK-001, likelihood=4/impact=5). Саме асиметрична форма матриці (не проста сума likelihood+impact, а їх комбінований поріг) забезпечує це змістовне розрізнення.
> </details>

---

**Попередній розділ:** [13.11. Моніторинг ризиків та інтеграція в ISMS](11-monitorynh-ta-isms.md)
**Наступний розділ:** [13.13. Чек-лист і самоперевірка](13-chek-lyst-i-samoperevirka.md)
**Назад до модуля:** [README модуля 13](README.md)

# 1.8. Практична лабораторна робота на Python

У цьому розділі — дві невеликі практичні вправи на Python, що закріплюють концепції модуля: оцінку ентропії пароля (пов'язано з розділом 1.2 і темою автентифікації) та простий калькулятор особистого ризику (пов'язано з розділом 1.3).

**Вимоги:** Python 3.10+, стандартна бібліотека (зовнішні пакети не потрібні).

## Лабораторна 1.8.1: Аналізатор надійності пароля

Пароль — найпоширеніша точка відмови в особистій безпеці. Скрипт нижче оцінює ентропію пароля та враховує найпростіші патерни, які часто пропускають базові оцінювачі.

```python
import math
import re

# Невеликий список найпопулярніших скомпрометованих паролів для демонстрації
# (на практиці використовують повні списки на кшталт RockYou, що містять мільйони записів)
COMMON_PASSWORDS = {
    "123456", "password", "qwerty", "123456789", "12345678",
    "111111", "1234567", "password1", "admin", "welcome",
}


def estimate_entropy(password: str) -> float:
    """Оцінює ентропію пароля в бітах на основі розміру алфавіту символів."""
    pool = 0
    if re.search(r'[a-z]', password):
        pool += 26
    if re.search(r'[A-Z]', password):
        pool += 26
    if re.search(r'[0-9]', password):
        pool += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        pool += 32
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def has_sequential_pattern(password: str) -> bool:
    """Перевіряє наявність очевидних послідовностей (123, abc) довжиною від 3."""
    lowered = password.lower()
    sequences = ["0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop"]
    for seq in sequences:
        for i in range(len(seq) - 2):
            if seq[i:i + 3] in lowered:
                return True
    return False


def rate_password(password: str) -> str:
    if password.lower() in COMMON_PASSWORDS:
        return "КРИТИЧНО СЛАБКИЙ — пароль є у списку найпоширеніших скомпрометованих паролів"

    entropy = estimate_entropy(password)
    warnings = []
    if has_sequential_pattern(password):
        warnings.append("містить очевидну послідовність символів (123, abc тощо)")
    if len(password) < 12:
        warnings.append("коротший за рекомендовані 12 символів")

    if entropy < 28:
        verdict = f"Дуже слабкий (ентропія {entropy:.1f} біт) — зламується миттєво"
    elif entropy < 36:
        verdict = f"Слабкий (ентропія {entropy:.1f} біт) — зламується за хвилини"
    elif entropy < 60:
        verdict = f"Помірний (ентропія {entropy:.1f} біт) — зламується за дні-місяці"
    elif entropy < 128:
        verdict = f"Сильний (ентропія {entropy:.1f} біт) — практично невразливий для брутфорсу"
    else:
        verdict = f"Дуже сильний (ентропія {entropy:.1f} біт)"

    if warnings:
        verdict += "\n   Попередження: " + "; ".join(warnings)
    return verdict


if __name__ == "__main__":
    test_passwords = [
        "123456",
        "password",
        "P@ssw0rd!",
        "qwerty123",
        "K0t1k-Lyubyt-Molo4ko-2026!",
    ]
    for pwd in test_passwords:
        print(f"{pwd!r:35} -> {rate_password(pwd)}\n")
```

**Завдання:**
1. Запустіть скрипт і проаналізуйте результати для тестових паролів.
2. Перевірте 3-5 модифікованих (не справжніх!) варіантів власних паролів — наприклад, замінивши реальні цифри й слова на схожі за структурою вигадані.
3. Сформулюйте власними словами: чому довгий passphrase (наприклад, чотири випадкових слова) часто надійніший і зручніший за короткий «складний» пароль із символами?

> **Обмеження моделі:** ця оцінка — спрощена модель ентропії Шеннона за розміром пулу символів плюс перевірка на топові скомпрометовані паролі та очевидні послідовності. Реальні інструменти злому (hashcat, John the Ripper) використовують значно складніші словники, мутації правил і статистичні моделі — детальніше про це в модулі 05 (Автентифікація та контроль доступу).

## Лабораторна 1.8.2: Калькулятор персонального кіберризику

Застосуємо формулу з розділу 1.3 (Ризик = Загроза × Вразливість × Вплив) практично — у вигляді простого якісного калькулятора.

```python
from dataclasses import dataclass
from enum import IntEnum


class Level(IntEnum):
    NYZKYI = 1
    SEREDNII = 2
    VYSOKYI = 3


RISK_MATRIX_LABELS = {
    (1, 1): "Низький", (1, 2): "Низький", (1, 3): "Середній",
    (2, 1): "Низький", (2, 2): "Середній", (2, 3): "Високий",
    (3, 1): "Середній", (3, 2): "Високий", (3, 3): "Критичний",
}


@dataclass
class PersonalAsset:
    name: str
    likelihood: Level  # ймовірність реалізації загрози з огляду на наявні вразливості
    impact: Level       # вплив у разі компрометації


def assess_risk(asset: PersonalAsset) -> str:
    key = (asset.likelihood.value, asset.impact.value)
    return RISK_MATRIX_LABELS[key]


if __name__ == "__main__":
    # Приклад: заповніть свої реальні активи та чесно оцініть ймовірність і вплив
    my_assets = [
        PersonalAsset("Особиста пошта (без MFA, перевикористаний пароль)", Level.VYSOKYI, Level.VYSOKYI),
        PersonalAsset("Банківський застосунок (з MFA)", Level.NYZKYI, Level.VYSOKYI),
        PersonalAsset("Акаунт у соцмережі (унікальний пароль, без MFA)", Level.SEREDNII, Level.SEREDNII),
        PersonalAsset("Робочий ноутбук (без шифрування диска)", Level.SEREDNII, Level.VYSOKYI),
    ]

    print(f"{'Актив':55} | {'Ймовірність':12} | {'Вплив':8} | Рівень ризику")
    print("-" * 95)
    for asset in sorted(my_assets, key=lambda a: assess_risk(a), reverse=True):
        risk = assess_risk(asset)
        print(f"{asset.name:55} | {asset.likelihood.name:12} | {asset.impact.name:8} | {risk}")
```

**Завдання:**
1. Замініть приклади у списку `my_assets` на власні реальні цифрові активи (без розкриття конфіденційних деталей — досить загального опису).
2. Чесно оцініть ймовірність і вплив для кожного, спираючись на матрицю з розділу 1.3.
3. Визначте 1-2 активи з найвищим ризиком — саме з них варто почати застосування контролів (модуль 03 — hardening, модуль 05 — автентифікація).

> Це навмисно спрощений, особистий інструмент. Повноцінний реєстр ризиків організаційного рівня, з власниками, контролями та статусами обробки, розглядається детально в окремому модулі «Оцінка ризиків» основного курсу.

## Джерела та додаткові матеріали

- NIST SP 800-63B, *Digital Identity Guidelines: Authentication and Lifecycle Management* — сучасні рекомендації щодо паролів (зокрема, чому довжина важливіша за вимушену складність).
- Have I Been Pwned (haveibeenpwned.com) — перевірка облікових записів на витоки.
- OWASP, *Password Storage Cheat Sheet* — рекомендації для розробників щодо зберігання паролів.

---

**Попередній розділ:** [1.7. Правова основа](07-pravova-osnova.md)
**Далі:** [1.9. Чек-лист і самоперевірка](09-chek-lyst-i-samoperevirka.md)
**Назад до модуля:** [README модуля 01](README.md)

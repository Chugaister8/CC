# Модуль 06. Веб-безпека: OWASP Top 10 і не тільки

> Вебзастосунки — найчастіша поверхня атаки в сучасному ландшафті загроз. Кожен публічно доступний вебсайт або API постійно сканується автоматизованими інструментами, що шукають SQL-ін'єкції, XSS, неправильно налаштований доступ і десятки інших відомих вразливостей. За даними Verizon DBIR, веб-застосунки є основним вектором у більш ніж 50% підтверджених інцидентів. OWASP Top 10 — не повний перелік всіх вразливостей, але надійна карта найбільш критичних і поширених. Цей модуль переводить теорію у конкретні уразливості, що зустрічаються в реальному коді.

## Цілі модуля

Після опрацювання модуля ви зможете:

- **Запам'ятати:** назвати 10 категорій OWASP Top 10 2021; пояснити різницю між Reflected, Stored і DOM-based XSS; знати основні HTTP Security Headers.
- **Зрозуміти:** описати механізм SQLi, IDOR, SSRF, CSRF; пояснити Same-Origin Policy і CORS; описати, чому CSP захищає від XSS.
- **Застосувати:** виявити SQL-ін'єкцію і XSS у вразливому коді; реалізувати захищену Flask-форму з CSRF-токеном і CSP; скласти Security Headers для реального сайту.

**Орієнтовна тривалість модуля:** 12–14 годин.

---

## Структура модуля

| № | Розділ | Що розглядається |
|---|---|---|
| — | [Глосарій](00-glosariy.md) | Всі ключові терміни |
| 6.1 | [Веб-архітектура і моделі безпеки](01-veb-arkhitektura.md) | HTTP, cookies, Same-Origin Policy, CORS, механізми браузерного захисту |
| 6.2 | [OWASP Top 10: огляд](02-owasp-top10-ohliad.md) | Методологія, еволюція, як використовувати Top 10 |
| 6.3 | [A01: Broken Access Control](03-a01-broken-access-control.md) | IDOR, BOLA, BFLA, path traversal, privilege escalation |
| 6.4 | [A02: Cryptographic Failures](04-a02-cryptographic-failures.md) | TLS-вимоги, чутливі дані, слабке шифрування в вебі |
| 6.5 | [A03: Injection](05-a03-iniektsiia.md) | SQL, NoSQL, Command, LDAP, XXE — механізми і захист |
| 6.6 | [A04: Insecure Design](06-a04-insecure-design.md) | Threat Modeling для веб, secure design patterns, abuse cases |
| 6.7 | [A05–A10: Security Misconfiguration до SSRF](07-a05-a10-ohliady.md) | Misconfiguration, Outdated Components, Auth Failures, Integrity, Logging, SSRF |
| 6.8 | [XSS: Cross-Site Scripting](08-xss.md) | Reflected, Stored, DOM-based; CSP; реальні кейси |
| 6.9 | [CSRF і Clickjacking](09-csrf-i-klikkdzheking.md) | Механізм атаки, SameSite cookie, CSRF-токени, X-Frame-Options |
| 6.10 | [HTTP Security Headers і CSP](10-security-headers.md) | Повний перелік заголовків, CSP директиви, практичне налаштування |
| 6.11 | [API Security: OWASP API Top 10](11-api-security.md) | BOLA, Broken Auth, Excessive Data Exposure, Mass Assignment, Rate Limiting |
| 6.12 | [Практична лабораторна на Python](12-praktychna-laboratorna.md) | Flask: SQLi, XSS, CSRF, Security Headers — вразливий → захищений код |
| 6.13 | [Чек-лист і самоперевірка](13-chek-lyst-i-samoperevirka.md) | Security Headers Checklist, 40 питань з відповідями |

---

**Попередній модуль:** [Модуль 05. Автентифікація та контроль доступу](../05-avtentyfikatsiia/README.md)
**Наступний модуль:** Модуль 07. Шкідливе ПЗ та соціальна інженерія (заплановано)

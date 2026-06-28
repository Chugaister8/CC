# 6.13. Чек-лист і самоперевірка

## Підсумок модуля: ключові ідеї

1. **Same-Origin Policy — фундамент безпеки браузера.** Все, що браузер дозволяє cross-origin (форми, зображення, скрипти з CDN), є потенційним вектором. CORS контролює доступ до відповідей, але не запобігає запиту.
2. **OWASP Top 10 — карта пріоритетів, не повний перелік.** A01 (Broken Access Control) у 2021 — на першому місці. Кожна категорія охоплює клас вразливостей, не одну CVE.
3. **Broken Access Control починається з відсутності перевірки «belongs to».** Параметризований запит без фільтру по `user_id` — IDOR. Сервер-side enforcement обов'язковий.
4. **Injection — відсутність межі між кодом і даними.** Параметризовані запити, типова валідація, безпечні парсери (defusedxml) — три шари захисту.
5. **XSS — виконання коду у браузері жертви.** Автоматичний escape у шаблонізаторах + CSP з nonce = два незалежних рубежі. HttpOnly cookie — захист від крадіжки сесії навіть при XSS.
6. **CSRF — браузер надсилає cookies автоматично.** SameSite=Lax (дефолт сучасних браузерів) + CSRF-токени = двошаровий захист.
7. **Security Headers — найдешевший спосіб підвищити безпеку.** 10 хвилин конфігурації Nginx або одне middleware — захист від XSS, Clickjacking, MIME-sniffing, downgrade attacks.
8. **API Security відрізняється від веб-безпеки.** BOLA (API1) — найпоширеніша API-вразливість. Rate limiting і Pagination — захист від abuse. Shadow API — неочевидний ризик.

---

## Практичний чек-лист

### Для кожного вебзастосунку

**Access Control (A01):**
- [ ] Кожен endpoint перевіряє, чи поточний user є власником запитуваного об'єкта.
- [ ] Admin-endpoint захищені перевіркою ролі (не лише автентифікацією).
- [ ] Path traversal неможливий (resolve() перед перевіркою шляху).
- [ ] Немає Mass Assignment вразливостей (whitelist полів для оновлення).

**Cryptography (A02):**
- [ ] TLS 1.2+ для всіх з'єднань; TLS 1.0/1.1 вимкнені.
- [ ] HSTS встановлено (max-age ≥ 1 рік).
- [ ] Паролі хешуються Argon2id або bcrypt (не SHA/MD5).
- [ ] Чутливі дані відсутні в логах і API-відповідях.
- [ ] Секрети в environment variables або Vault, не в коді.

**Injection (A03):**
- [ ] Параметризовані запити для всіх SQL-операцій.
- [ ] `defusedxml` або відключені external entities для XML.
- [ ] `subprocess` з list arguments, shell=False.
- [ ] Шаблонізатор з автоматичним escape (не `| safe` для user input).

**XSS:**
- [ ] Автоматичний HTML escape активний (Jinja2: так за замовчуванням).
- [ ] `innerHTML` зі змінними даними відсутній.
- [ ] CSP встановлено без `'unsafe-inline'` у script-src.
- [ ] Сесійний cookie має HttpOnly.
- [ ] DOMPurify там, де потрібен HTML від користувача.

**CSRF:**
- [ ] SameSite cookie (Lax або Strict) для сесій.
- [ ] CSRF-токени для state-changing форм (Flask-WTF або аналог).
- [ ] API перевіряє Origin/Referer для cross-origin запитів.

**Security Headers:**
- [ ] Strict-Transport-Security: max-age=31536000
- [ ] Content-Security-Policy (без `'unsafe-inline'`)
- [ ] X-Frame-Options: DENY або frame-ancestors 'none'
- [ ] X-Content-Type-Options: nosniff
- [ ] Referrer-Policy: strict-origin-when-cross-origin
- [ ] Приховати Server і X-Powered-By заголовки

**API:**
- [ ] Rate limiting на auth endpoints (≤5 req/min).
- [ ] Pagination (max 100 items per page).
- [ ] Усі API endpoints задокументовані в OpenAPI spec.
- [ ] API keys зберігаються як хеші (не plaintext).
- [ ] Немає debug/internal endpoints в production.

---

## Самоперевірка

### 6.1. Веб-архітектура
1. Що таке Same-Origin Policy і які три компоненти визначають origin?
2. Чому форма HTML може POST-ити на інший origin, а fetch() — ні (без CORS)?
3. Чим відрізняється Preflight OPTIONS запит від звичайного CORS-запиту?
4. Яке значення атрибуту `SameSite` є дефолтним у сучасних браузерах і що він захищає?
5. Чому `Content-Security-Policy` з `'unsafe-inline'` у `script-src` не захищає від XSS?

### 6.2. OWASP Top 10
6. Яка категорія OWASP Top 10 з'явилась на першому місці у 2021 (раніше була на п'ятому)?
7. Чим відрізняється CWE від CVE? Наведіть приклад кожного.
8. Що таке OWASP ASVS і як воно пов'язане з Top 10?

### 6.3. Broken Access Control
9. Поясніть IDOR на конкретному прикладі URL і покажіть, який код був би вразливим і який захищеним.
10. Що таке BOLA і чим воно відрізняється від BFLA?
11. Чому однаковий 404 і 403 відповідь краще з точки зору безпеки, ніж різні повідомлення?
12. Що таке Path Traversal і яка функція Python захищає від неї?

### 6.4. Cryptographic Failures
13. Що означає «Cryptographic Failure» і чому A02 перейменовано з «Sensitive Data Exposure»?
14. Назвіть три конкретних дії, що потрібні для безпечної передачі даних через TLS.
15. Чому `hashlib.sha256(password)` є вразливістю при зберіганні паролів?

### 6.5. Injection
16. Поясніть Union-based SQLi атаку крок за кроком.
17. Чому `subprocess.run(['ping', '-c', '4', host])` безпечніше, ніж `os.system(f"ping {host}")`?
18. Що таке XXE і яка одна функція Python-бібліотеки захищає від неї?
19. Що таке SSTI і чому `render_template_string(user_input)` критично небезпечний?

### 6.6. Insecure Design
20. Чим Insecure Design відрізняється від Security Misconfiguration?
21. Що таке STRIDE і які 6 загроз воно охоплює?
22. Наведіть приклад Business Logic Flaw у фінансовому застосунку.
23. Що таке Abuse Case і як він відрізняється від Use Case?

### 6.7. A05–A10
24. Чому `pickle.loads(user_data)` є критичною вразливістю у вебзастосунку?
25. Що таке SSRF і яку хмарну мету (AWS) атакує найчастіше?
26. Чому `os.urandom(32)` кращий за `random.random()` для генерації session ID?
27. Назвіть три обов'язкових класи подій, що потрібно логувати у вебзастосунку.

### 6.8. XSS
28. Поясніть різницю між Reflected, Stored і DOM-based XSS.
29. Що таке HttpOnly і від якої атаки він захищає (і від якої — ні)?
30. Що таке DOMPurify і коли він потрібен?
31. Поясніть механізм CSP nonce: як генерується, де вставляється і як браузер перевіряє?

### 6.9. CSRF і Clickjacking
32. Поясніть механізм CSRF атаки крок за кроком.
33. Чому SameSite=Strict може порушити UX і яке значення є компромісом?
34. Що таке Clickjacking і який один HTTP-заголовок захищає від нього?
35. Чим Double Submit Cookie Pattern відрізняється від Synchronizer Token?

### 6.10. Security Headers
36. Що таке HSTS Preload List і навіщо вона потрібна (яку атаку унеможливлює)?
37. Що таке MIME sniffing і який заголовок від нього захищає?
38. Який заголовок контролює, чи може сайт бути вбудований в `<iframe>`?

### 6.11. API Security
39. Що таке Shadow API і чому він є ризиком безпеки?
40. Чому API Key повинен зберігатись у базі даних як хеш, а не у відкритому вигляді?

---

## Орієнтовні відповіді

<details>
<summary>Розгорнути відповіді</summary>

1. SOP забороняє скриптам одного origin читати вміст або стан іншого. Origin = Схема + Хост + Порт. `https://example.com:443` і `http://example.com` — різні origins (різна схема).
2. Форми відправляють запит, але JavaScript не може читати відповідь. Fetch() намагається читати відповідь — SOP блокує це без відповідних CORS-заголовків сервера.
3. Preflight (OPTIONS) надсилається браузером для «не-простих» запитів (наприклад, POST з Content-Type: application/json) для перевірки, чи сервер дозволяє такий cross-origin запит. Звичайний CORS — вже основний запит після позитивного Preflight.
4. SameSite=Lax — дефолт. Захищає від CSRF: cookie не надсилається при cross-site POST (але надсилається при top-level GET navigation).
5. `'unsafe-inline'` дозволяє виконання будь-якого inline-скрипту, включаючи ін'єктований через XSS. CSP без 'unsafe-inline' блокує навіть ін'єктований `<script>alert(1)</script>` — з 'unsafe-inline' CSP від XSS не захищає.
6. A01: Broken Access Control — зросла з #5 до #1.
7. CWE — загальний клас слабкості коду (наприклад CWE-89: SQL Injection — це клас). CVE — конкретний екземпляр у конкретному продукті (CVE-2021-44228: Log4Shell у Log4j).
8. ASVS (Application Security Verification Standard) — детальна специфікація 3 рівнів верифікації безпеки застосунків. Кожна вимога ASVS відображена на CWE і OWASP Top 10. Використовується як технічний стандарт для security-тестування і контрактних вимог.
9. Вразливо: `Order.query.get(order_id)` — без перевірки власника. Захищено: `Order.query.filter_by(id=order_id, user_id=current_user.id).first()`.
10. BOLA (API1) — доступ до чужого об'єкта через id (горизонтальна ескалація). BFLA (API5) — доступ до функцій, на які немає прав ролі (вертикальна ескалація).
11. Різні повідомлення («не знайдено» vs «немає прав») дозволяють user enumeration: зловмисник дізнається, що об'єкт існує, але недоступний. Однаковий 404 приховує факт існування.
12. Path Traversal: `../../../etc/passwd` в параметрі шляху. Захист: `Path(requested).resolve()` і перевірка `str(resolved).startswith(str(allowed_dir))`.
13. «Cryptographic Failure» — першопричина (слабке шифрування або його відсутність), а не наслідок (витік даних). Перейменування підкреслює: проблема — в криптографії, а не лише в самому факті витоку.
14. TLS 1.2+, HSTS, valid certificate від довіреного CA, без deprecated cipher suites (RC4, DES).
15. SHA-256 занадто швидкий: GPU обчислює мільярди хешів/секунду. При витоку бази — атакуючий підбирає паролі за хвилини. Argon2id навмисно повільний і використовує пам'ять.
16. 1) Визначити кількість стовпців через `ORDER BY N`; 2) Знайти відображувані стовпці через `UNION SELECT null,null,...`; 3) Витягти дані: `UNION SELECT table_name,column_name FROM information_schema.columns--`.
17. З list-аргументами subprocess не використовує shell, тому `;`, `&&`, `||` не інтерпретуються як розділювачі команд. `os.system(f"ping {host}")` → shell = True → injection.
18. XXE: зовнішня entity в XML читає файли або ініціює SSRF. `import defusedxml.ElementTree as ET` — автоматично блокує XXE.
19. `render_template_string(user_input)` рендерить рядок як Jinja2-шаблон. `{{7*7}}` → `49`. RCE через `{{''.__class__.__mro__[1].__subclasses__()...}}`.
20. Insecure Design — вразливість в архітектурному рішенні, яку не можна «виправити патчем» без зміни дизайну. Security Misconfiguration — правильне рішення, але неправильно налаштоване (виправляється конфігурацією).
21. STRIDE: Spoofing (автентичність), Tampering (цілісність), Repudiation (неспростовність), Information Disclosure (конфіденційність), Denial of Service (доступність), Elevation of Privilege (авторизація).
22. Race condition при переказі: два паралельних запити читають баланс (100 грн), обидва проходять перевірку, обидва списують → баланс -100 грн. Захист: db-level lock або `UPDATE WHERE balance >= amount`.
23. Abuse Case описує зловмисне використання системи. Use Case — легітимне. Для завантаження файлу: Use Case = «завантажити PDF резюме»; Abuse Case = «завантажити .php shell, SVG з XSS, 10 ГБ файл».
24. `pickle.loads()` десеріалізує довільний Python-об'єкт — включаючи клас з `__reduce__`, що виконує `os.system()`. RCE без жодної додаткової вразливості.
25. SSRF: сервер виконує HTTP-запит до URL, контрольованого атакуючим. Найчастіша ціль AWS: `http://169.254.169.254/latest/meta-data/iam/security-credentials/` → тимчасові IAM credentials.
26. `random.random()` — Mersenne Twister, передбачуваний після 624 вихідних значень. `os.urandom()` використовує системний CSPRNG (/dev/urandom / CryptGenRandom), непередбачуваний.
27. Обов'язково: (1) Спроби входу (успішні і невдалі) з IP і username; (2) Відмови авторизації (403) з ресурсом і user; (3) Зміни привілеїв і чутливих даних.
28. Reflected: payload в URL → відображається у відповіді без збереження; потрібно переконати жертву перейти. Stored: payload зберігається в БД → виконується для всіх відвідувачів. DOM-based: повністю на клієнті, payload в hash/search → обробляється JS без запиту до сервера.
29. HttpOnly: cookie недоступний через `document.cookie` в JavaScript. Захищає від XSS крадіжки сесії. НЕ захищає: від CSRF (браузер все одно надсилає cookie); від мережевого перехоплення (потрібен Secure).
30. DOMPurify — JS бібліотека для санітизації HTML: видаляє небезпечні теги і атрибути, залишаючи безпечний підмножину. Потрібен там, де користувач може вводити HTML-розмітку (WYSIWYG редактори, коментарі з форматуванням).
31. Nonce (number used once): сервер генерує `secrets.token_urlsafe(16)` для кожного запиту → вставляє в CSP (`script-src 'nonce-{value}'`) і в кожен `<script nonce="{value}">`. Браузер блокує скрипти без nonce або з невірним nonce. Ін'єктований `<script>` не знає nonce поточного запиту.
32. 1) Аліса залогінена на bank.com, сесійний cookie в браузері. 2) Аліса переходить на evil.com. 3) evil.com містить форму `<form action="bank.com/transfer" method="POST">`. 4) Форма авто-субмітиться, браузер надсилає запит до bank.com з cookie Аліси. 5) bank.com обробляє переказ від імені Аліси.
33. SameSite=Strict: cookie не надсилається навіть при переходах за посиланням з email → користувач не залогінений після переходу. SameSite=Lax (компроміс): надсилається при top-level GET (переходи), але не при cross-site POST (захист від CSRF).
34. Clickjacking: прозорий iframe поверх сайту з кнопкою-пасткою. Захист: `X-Frame-Options: DENY` або CSP `frame-ancestors 'none'`.
35. Synchronizer Token: сервер зберігає токен у сесії, перевіряє при кожному POST — stateful. Double Submit Cookie: токен в cookie (без HttpOnly) і в request параметрі; сервер лише перевіряє їх рівність — stateless, підходить для distributed систем.
36. HSTS Preload List — вбудований у браузер список доменів з примусовим HTTPS. Унеможливлює TOFU (Trust on First Use) атаку: навіть при першому відвіданні браузер не намагається HTTP. Захищає від SSL Stripping навіть при першому відвіданні.
37. MIME sniffing: браузер «вгадує» тип файлу, якщо Content-Type відсутній або невірний — може виконати JS в текстовому файлі. Захист: `X-Content-Type-Options: nosniff` забороняє снiffinf.
38. `X-Frame-Options: DENY` або `SAMEORIGIN`. Або CSP `frame-ancestors 'none'` (сучасніший підхід).
39. Shadow API: ендпоінти, що існують в production але не задокументовані і не підтримуються (стара версія, debug endpoint). Ризик: не перевіряються при аудиті, не отримують оновлення безпеки, можуть мати застарілі вразливості.
40. Аналогічно паролям: якщо база витекла — атакуючий отримує всі API keys у відкритому вигляді і може їх використати. З хешуванням: атакуючий отримує хеші, але для кожного потрібен окремий підбір.

</details>

---

**Попередній розділ:** [6.12. Практична лабораторна на Python](12-praktychna-laboratorna.md)
**Назад до модуля:** [README модуля 06](README.md)
**Наступний модуль:** Модуль 07. Шкідливе ПЗ та соціальна інженерія (заплановано)

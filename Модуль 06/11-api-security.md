# 6.11. API Security: OWASP API Security Top 10

Усі Security Headers, що ми щойно розглянули, формально стосуються HTML-відповідей браузера. Але сучасний вебзастосунок — це не монолітна HTML-сторінка: це тонкий клієнт (React, Vue, мобільний застосунок), що звертається до **API**. І API має власний набір вразливостей, що погано описуються класичним OWASP Top 10. CORS без whitelist вже розглянутий; але є і специфічні для API: BOLA (масовий IDOR на рівні API об'єктів), надмірна деталізація відповідей, відсутність rate limiting на чутливих ендпоінтах.

API — невидима інфраструктура сучасного вебу. Кожна мобільна кнопка, кожен виклик між мікросервісами, кожна інтеграція з SaaS — це API-запит. І на відміну від вебсторінок, API повертає структуровані дані без HTML-обгортки, часто без автентифікації за замовчуванням, часто без rate limiting, часто з надмірно детальними відповідями на помилки. **OWASP API Security Top 10** (2023) — окремий список, спеціально для REST, GraphQL і gRPC API.

> 📖 Ключові терміни — у [глосарії модуля](00-glosariy.md).

## OWASP API Security Top 10 2023

| # | Категорія | Суть |
|---|---|---|
| API1 | Broken Object Level Authorization (BOLA) | IDOR для API: доступ до чужих об'єктів через id |
| API2 | Broken Authentication | Слабкі токени, відсутність MFA, вразливий flow |
| API3 | Broken Object Property Level Authorization | Надання зайвих полів або зміна захищених полів |
| API4 | Unrestricted Resource Consumption | Відсутній rate limiting, quota, розмір payload |
| API5 | Broken Function Level Authorization | Доступ до адмін-функцій без відповідних прав |
| API6 | Unrestricted Access to Sensitive Business Flows | Зловживання бізнес-логікою (масова реєстрація, abuse купонів) |
| API7 | Server Side Request Forgery (SSRF) | Те саме, що A10 у OWASP Top 10 |
| API8 | Security Misconfiguration | Дефолти, verbose errors, неправильний CORS |
| API9 | Improper Inventory Management | Shadow API, forgotten endpoints, версіонування |
| API10 | Unsafe Consumption of APIs | Довіра до third-party API без валідації |

## API1: Broken Object Level Authorization (BOLA)

Найпоширеніша вразливість API — еквівалент IDOR (розділ 6.3) але в API-контексті.

```python
# ❌ ВРАЗЛИВО: будь-який автентифікований user може отримати будь-яке замовлення
@app.route('/api/v1/orders/<int:order_id>', methods=['GET'])
@jwt_required()
def get_order(order_id):
    order = Order.query.get_or_404(order_id)
    return jsonify(order.to_dict())  # API1 — перевірка власника відсутня

# ✅ ПРАВИЛЬНО: фільтр по поточному користувачу
@app.route('/api/v1/orders/<int:order_id>', methods=['GET'])
@jwt_required()
def get_order(order_id):
    current_user_id = get_jwt_identity()
    order = Order.query.filter_by(
        id=order_id,
        user_id=current_user_id  # ← belongs-to check
    ).first_or_404()
    return jsonify(order.to_dict())
```

## API2: Broken Authentication

**API2** — вразливості автентифікації специфічні для API-контексту: слабкі або неправильно реалізовані механізми перевірки ідентичності.

**Типові збої:**

```python
# ❌ Слабкий JWT secret — підбирається за словником
app.config['JWT_SECRET'] = 'secret'   # тривіальний ключ
app.config['JWT_SECRET'] = 'jwt'      # ще гірше

# ❌ Не перевіряється алгоритм підпису (alg:none атака)
import jwt
payload = jwt.decode(token, options={"verify_signature": False})  # НІКОЛИ!

# ❌ Немає rate limiting на /token endpoint
@app.route('/api/token', methods=['POST'])
def get_token():
    # Brute force пароля або client_secret без обмежень
    ...

# ✅ Правильно:
import secrets
JWT_SECRET = secrets.token_urlsafe(32)  # мінімум 256 біт

# Перевірка з явним алгоритмом
payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])  # whitelist алгоритмів

# Rate limiting на /token
@limiter.limit("10 per minute")
@app.route('/api/token', methods=['POST'])
def get_token():
    ...
```

**Refresh Token Rotation** — best practice: кожен refresh_token одноразовий; після використання видається новий і старий анулюється. Якщо refresh_token вкрадено і використано зловмисником — легітимний клієнт отримає помилку при наступному використанні (бо старий вже використаний), що є сигналом компрометації.

## API3: Broken Object Property Level Authorization

Два підтипи:

**Excessive Data Exposure** — API повертає більше полів, ніж потрібно клієнту:

```python
# ❌ ВРАЗЛИВО: повертаємо повний об'єкт
def user_to_dict(user):
    return {
        'id': user.id, 'email': user.email, 'name': user.name,
        'password_hash': user.password_hash,  # ← NI!
        'is_admin': user.is_admin,             # ← NI!
        'api_key': user.api_key,               # ← NI!
    }

# ✅ ПРАВИЛЬНО: явна серіалізація лише потрібних полів
from marshmallow import Schema, fields

class UserPublicSchema(Schema):
    id = fields.Int()
    name = fields.Str()
    avatar_url = fields.Str()

class UserPrivateSchema(Schema):  # для самого користувача
    id = fields.Int()
    name = fields.Str()
    email = fields.Email()
```

**Mass Assignment** — API дозволяє змінювати захищені поля через PUT/PATCH:

```python
# ❌ ВРАЗЛИВО: приймаємо всі поля від клієнта
@app.route('/api/v1/users/me', methods=['PATCH'])
@jwt_required()
def update_profile():
    current_user.update(**request.json)  # PATCH {"is_admin": true} → !
    db.session.commit()

# ✅ ПРАВИЛЬНО: whitelist дозволених полів
UPDATABLE_FIELDS = {'name', 'bio', 'avatar_url', 'preferences'}

@app.route('/api/v1/users/me', methods=['PATCH'])
@jwt_required()
def update_profile():
    data = {k: v for k, v in request.json.items() if k in UPDATABLE_FIELDS}
    current_user.update(**data)
    db.session.commit()
```

## API4: Unrestricted Resource Consumption

```python
# Flask-Limiter для rate limiting
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/api/v1/search')
@limiter.limit("10 per minute")  # суворіше для ресурсоємних ендпоінтів
def search():
    ...

@app.route('/api/v1/auth/login', methods=['POST'])
@limiter.limit("5 per minute")  # захист від brute force
def login():
    ...

# Обмеження розміру payload (Nginx)
# client_max_body_size 10M;

# Обмеження у Flask
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 МБ

# Pagination обов'язкова — ніколи не повертати необмежені колекції
@app.route('/api/v1/products')
def get_products():
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)  # max 100
    items = Product.query.paginate(page=page, per_page=per_page)
    return jsonify({
        'items': [i.to_dict() for i in items.items],
        'total': items.total,
        'pages': items.pages,
        'current_page': items.page
    })
```

## API5: Broken Function Level Authorization

```python
# ❌ ВРАЗЛИВО: перевіряємо лише автентифікацію, не роль
@app.route('/api/v1/admin/users', methods=['GET'])
@jwt_required()
def list_all_users():
    return jsonify([u.to_dict() for u in User.query.all()])

# ✅ ПРАВИЛЬНО: перевірка ролі
from functools import wraps

def admin_required(f):
    @wraps(f)
    @jwt_required()
    def decorated(*args, **kwargs):
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if not user or not user.is_admin:
            return jsonify({'error': 'Admin required'}), 403
        return f(*args, **kwargs)
    return decorated

@app.route('/api/v1/admin/users', methods=['GET'])
@admin_required
def list_all_users():
    return jsonify([u.to_dict() for u in User.query.all()])
```

## API6: Unrestricted Access to Sensitive Business Flows

Ці атаки не порушують контроль доступу — вони зловживають легітимними функціями:

```
Приклади:
- Масова реєстрація акаунтів (abuse реферальних програм або безкоштовних trial)
- Автоматизований викуп товарів обмеженого тиражу (scalping ботами)
- Масова відправка повідомлень через форму зворотнього зв'язку (spam)
- Перебір промо-кодів
```

**Захист:**
```python
# CAPTCHA для чутливих дій
# Device fingerprinting
# Business logic rate limits (не просто IP, але: кількість акаунтів з однієї карти,
#   кількість замовлень на день, кількість повідомлень від одного user)

# Celery task для відкладеної перевірки підозрілих патернів
@celery.task
def check_suspicious_activity(user_id: int):
    registrations_today = count_registrations_from_same_ip(user_id)
    if registrations_today > 10:
        flag_account_for_review(user_id)
        send_alert_to_security_team(user_id)
```

## API7: Server-Side Request Forgery (SSRF)

В API-контексті SSRF особливо небезпечний: API-сервіси часто мають широкий доступ до внутрішньої мережі і хмарних метаданих. Якщо API приймає URL як параметр (webhook callback, image import, document fetch) — він є потенційним SSRF-вектором.

```python
# ❌ ВРАЗЛИВО: API endpoint, що отримує зовнішній ресурс
@app.route('/api/import-image', methods=['POST'])
def import_image():
    url = request.json.get('url')
    data = requests.get(url).content   # SSRF!
    # Атака: url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# ✅ Захист: whitelist + DNS rebinding protection (детально — розділ 6.7 A10)
```

Детальний захист від SSRF — у розділі 6.7 (A10). Для API додатково: **IMDSv2** для EC2 (блокує SSRF через GET), відключення непотрібного server-side fetch взагалі де можливо, ізоляція сервісів, що роблять зовнішні запити.

## API8: Security Misconfiguration

API-специфічні мисконфігурації відрізняються від веб тим, що деталі зазвичай у JSON — і зловмисник отримує структуровану інформацію про внутрішній стан системи:

```python
# ❌ Verbose error у production API — розкриває структуру БД
{"error": "psycopg2.errors.UndefinedColumn: column \"pasword\" does not exist
           LINE 1: SELECT id FROM users WHERE pasword = 'test'"}
# Розкриває: тип БД, схему таблиці, назви стовпців, навіть друкарську помилку в коді

# ✅ Generic error
{"error": "Internal server error", "request_id": "abc-123"}
# Деталі — у внутрішньому логу прив'язано до request_id

# ❌ Надмірно широкий CORS з credentials
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true   # несумісна комбінація

# ❌ Swagger UI доступний у production — розкриває і дозволяє викликати всі ендпоінти
# ❌ HTTP замість HTTPS для внутрішніх API — трафік між мікросервісами теж шифрується
# ❌ Зайві HTTP методи: DELETE на ресурсі, де очікується лише GET
```

**API8-специфічні чек-пункти:**
- [ ] Swagger/Redoc UI вимкнено або захищено токеном у production.
- [ ] CORS whitelist, не `*` із credentials.
- [ ] Всі API responses мають `Content-Type: application/json; charset=utf-8`.
- [ ] HTTP методи обмежені явно — `@app.route('/resource', methods=['GET'])`.
- [ ] Stack traces і внутрішні помилки фільтруються перед відповіддю клієнту.

## API9: Improper Inventory Management (Shadow APIs)

Застарілі версії API (`/api/v1/` поруч з `/api/v3/`), забуті тестові ендпоінти (`/api/debug`, `/api/internal`) і недокументовані шляхи — все це Shadow APIs. Їх загальна риса: вони існують, але про них «забули», тому вони не проходять security review і залишаються незахищеними.

**Захист:**
- Ведення реєстру всіх API ендпоінтів (OpenAPI/Swagger як живий документ).
- API Gateway з явним whitelisting дозволених маршрутів.
- Регулярний аудит задеплоєних маршрутів: `flask routes`, `rails routes`, API discovery інструменти.
- Версіонування з політикою sunset: стара версія → deprecated → retired з конкретною датою.

## API10: Unsafe Consumption of APIs

API, що інтегруються з третіми сторонами, часто довіряють їхнім відповідям без валідації — і стають вразливими через ланцюжок довіри:

```python
# ❌ ВРАЗЛИВО: сліпа довіра до third-party API
def process_payment(order_id):
    response = payment_api.get_status(order_id)
    if response['status'] == 'completed':
        fulfill_order(order_id)
# Якщо payment_api скомпрометований або відповідь підмінена в transit —
# зловмисник отримує товар безкоштовно, підробивши status='completed'.

# ✅ Захист:
from pydantic import BaseModel

class PaymentStatus(BaseModel):
    order_id: int
    status: str  # 'pending'|'completed'|'failed'
    amount: float
    currency: str

def process_payment(order_id: int, expected_amount: float):
    raw = payment_api.get_status(order_id)
    # 1. Валідація схеми — Pydantic кидає виняток якщо поля відсутні або тип невірний
    status = PaymentStatus(**raw)
    # 2. Незалежна перевірка суми
    if abs(status.amount - expected_amount) > 0.01:
        raise ValueError(f"Amount mismatch: expected {expected_amount}, got {status.amount}")
    # 3. Ідемпотентність
    if order_already_fulfilled(order_id):
        return
    if status.status == 'completed':
        fulfill_order(order_id)
```

**Принципи захисту API10:**
- Валідувати схему і типи даних відповіді (Pydantic, JSON Schema, Marshmallow).
- Незалежна верифікація критичних параметрів (суми, статуси) з власного джерела.
- TLS-перевірка сертифікату third-party (`requests.get(url, verify=True)` — дефолт, не відключати).
- Timeout і circuit breaker — залежність від зовнішнього API не блокує всю систему.
- Логувати сирі відповіді third-party для forensics при інцидентах.



## Автентифікація і авторизація для API

**JWT Best Practices:**

```python
from flask_jwt_extended import create_access_token, create_refresh_token
import datetime

# Короткий термін access token (15–60 хвилин)
access_token = create_access_token(
    identity=user.id,
    expires_delta=datetime.timedelta(minutes=15),
    additional_claims={
        'role': user.role,
        'email': user.email
    }
)

# Довший refresh token (з rotation)
refresh_token = create_refresh_token(
    identity=user.id,
    expires_delta=datetime.timedelta(days=30)
)
```

**API Key Management:**

```python
import secrets
import hashlib

def generate_api_key() -> tuple[str, str]:
    """Повертає (raw_key, hashed_key). Зберігаємо лише хеш."""
    raw_key = f"sk_{secrets.token_urlsafe(32)}"
    hashed = hashlib.sha256(raw_key.encode()).hexdigest()
    return raw_key, hashed

# Надсилаємо raw_key користувачу лише один раз
# Зберігаємо hashed_key в базі (як пароль — не в відкритому вигляді)

def verify_api_key(raw_key: str) -> Optional[ApiKey]:
    hashed = hashlib.sha256(raw_key.encode()).hexdigest()
    return ApiKey.query.filter_by(key_hash=hashed, is_active=True).first()
```

## GraphQL-специфічні вразливості

```python
# GraphQL додаткові ризики:
# 1. Introspection в production — розкриває схему
# 2. Depth limiting — відсутність обмеження вкладеності запитів → DoS
# 3. Query batching — N+1 запитів → DoS/resource exhaustion

# ✅ Захист (Graphene/Strawberry для Python)
schema = graphene.Schema(query=Query)

# Вимкнути introspection в production
if not app.debug:
    schema = graphene.Schema(
        query=Query,
        types=[...],
    )
    # Або middleware для блокування introspection
    
# Depth limiting
from graphql_depth_limit import depth_limit_middleware

app.add_url_rule('/graphql',
    view_func=GraphQLView.as_view('graphql',
        schema=schema,
        middleware=[depth_limit_middleware(max_depth=5)]
    )
)
```

## OpenAPI / Swagger: документація як контроль

**OpenAPI Specification** — машиночитаний опис API, що слугує і документацією, і основою для автоматичного тестування:

```yaml
# openapi.yaml
openapi: 3.1.0
info:
  title: Example API
  version: 1.0.0
paths:
  /api/v1/orders/{order_id}:
    get:
      security:
        - bearerAuth: []     # ← обов'язкова автентифікація
      parameters:
        - name: order_id
          in: path
          required: true
          schema:
            type: integer
            minimum: 1       # ← валідація на рівні специфікації
      responses:
        '200':
          description: Order details
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Order'
        '403':
          description: Access denied (not owner)
        '404':
          description: Not found
```

```bash
# Автоматична валідація API проти специфікації
pip install schemathesis
schemathesis run openapi.yaml --url https://api.example.com
```

## Міні-вправа

```python
# Простий тест API Security чек-лист
import requests

API_BASE = "http://localhost:5000/api/v1"

def test_api_security():
    results = {}

    # 1. Rate limiting
    responses = [requests.post(f"{API_BASE}/auth/login",
        json={"email": "test@test.com", "password": "wrong"}) for _ in range(10)]
    status_codes = [r.status_code for r in responses]
    results['Rate limiting'] = 429 in status_codes  # має заблокувати

    # 2. BOLA — спроба отримати чужий ресурс (з токеном іншого user)
    # Потрібна pre-auth для двох users — реалізуйте самостійно

    # 3. Перевірка headers
    r = requests.get(f"{API_BASE}/health")
    results['X-Content-Type-Options'] = 'nosniff' in r.headers.get('X-Content-Type-Options', '')
    results['No server version leak'] = 'X-Powered-By' not in r.headers
    results['No detailed errors'] = r.status_code != 500

    for check, passed in results.items():
        print(f"{'✅' if passed else '❌'} {check}")

test_api_security()
```

## Джерела та додаткові матеріали

- OWASP API Security Top 10 2023 (owasp.org/www-project-api-security).
- OWASP REST Security Cheat Sheet.
- PortSwigger Web Academy, *API testing*.
- Schemathesis (schemathesis.io) — property-based тестування API.
- Flask-Limiter (flask-limiter.readthedocs.io).

---

**Попередній розділ:** [6.10. HTTP Security Headers](10-security-headers.md)
**Далі:** [6.12. Практична лабораторна на Python](12-praktychna-laboratorna.md)
**Назад до модуля:** [README модуля 06](README.md)

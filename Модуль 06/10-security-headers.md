# 6.10. HTTP Security Headers і Content Security Policy

Security Headers — найшвидший і найдешевший спосіб підвищити безпеку вебзастосунку: кілька рядків у конфігурації сервера закривають цілі класи атак. Між тим, регулярні перевірки мільйонів сайтів через securityheaders.com показують, що більшість із них не мають навіть базових заголовків — не через технічну складність, а через те, що «хтось колись мав це налаштувати, але не налаштував». Цей розділ систематизує всі ключові заголовки, пояснює зв'язок між ними і дає готові конфігурації для Nginx та Apache.

> 📖 Ключові терміни — у [глосарії модуля](00-glosariy.md).

## Strict-Transport-Security (HSTS)

Перший і найважливіший заголовок для будь-якого HTTPS-сайту. Він усуває можливість «SSL stripping» — атаки, де зловмисник між клієнтом і сервером перехоплює початковий HTTP-запит і не дозволяє браузеру перейти на HTTPS.

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

| Директива | Значення |
|---|---|
| `max-age=31536000` | Кешувати правило 1 рік (у секундах) |
| `includeSubDomains` | Застосовувати до всіх піддоменів |
| `preload` | Дозволяє включення до браузерного Preload List |

**HSTS Preload List** (`hstspreload.org`) — вбудований список у Chrome, Firefox і Safari. Сайт у цьому списку отримує HTTPS-захист навіть при першому відвіданні, ще до того як браузер отримав заголовок. Це закриває «вікно вразливості» при першому підключенні.

> Важливо: HSTS з `preload` — незворотне рішення на час `max-age`. Переконайтесь, що **всі** піддомени підтримують HTTPS перед увімкненням.

---

## Content-Security-Policy (CSP)

Якщо HSTS захищає транспорт, CSP захищає контент — визначає, звідки браузер може завантажувати ресурси. Навіть якщо XSS-payload ін'єктований (розділ 6.8), суворий CSP не дозволить йому виконатись: браузер перевіряє кожен скрипт і блокує незатверджені.

```
Content-Security-Policy:
  default-src 'self';
  script-src  'self' 'nonce-{random}' 'strict-dynamic';
  style-src   'self' 'nonce-{random}';
  img-src     'self' data: https:;
  connect-src 'self' https://api.example.com;
  frame-ancestors 'none';
  object-src  'none';
  base-uri    'self';
  form-action 'self';
  upgrade-insecure-requests;
```

**Основні директиви:**

| Директива | Що контролює |
|---|---|
| `default-src` | Fallback для всіх директив |
| `script-src` | JavaScript — найкритичніша директива |
| `style-src` | CSS |
| `img-src` | Зображення |
| `connect-src` | fetch, XHR, WebSocket |
| `frame-ancestors` | Хто може вбудовувати цю сторінку (замінює X-Frame-Options) |
| `form-action` | Куди можуть відправлятись форми |
| `object-src` | Flash, плагіни — завжди `'none'` |
| `base-uri` | `<base>` тег — захист від base tag injection |

**Ключові source values:**

| Значення | Що означає |
|---|---|
| `'none'` | Нічого не дозволено |
| `'self'` | Лише поточний origin |
| `'unsafe-inline'` | Дозволяє inline-скрипти — **знищує XSS-захист CSP** |
| `'nonce-{random}'` | Лише скрипти з цим одноразовим значенням |
| `'sha256-{hash}'` | Лише скрипти з цим SHA-256 хешем |
| `'strict-dynamic'` | Довірені скрипти можуть завантажувати інші |

**Nonce — правильний підхід для динамічних сайтів:**

```python
import secrets
from flask import g

@app.before_request
def generate_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)

@app.after_request
def add_csp_header(response):
    nonce = getattr(g, 'csp_nonce', '')
    response.headers['Content-Security-Policy'] = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' 'strict-dynamic'; "
        f"style-src 'self' 'nonce-{nonce}'; "
        f"img-src 'self' data: https:; "
        f"connect-src 'self'; "
        f"frame-ancestors 'none'; "
        f"object-src 'none'; "
        f"base-uri 'self'; "
        f"form-action 'self'; "
        f"upgrade-insecure-requests;"
    )
    return response
```

```html
<!-- У шаблоні: nonce дозволяє виконатись лише цьому скрипту -->
<script nonce="{{ g.csp_nonce }}">
    // Легітимний код
</script>
<!-- Ін'єктований скрипт без nonce → браузер блокує -->
```

**Report-Only — безпечний спосіб розгортання CSP:**

```
Content-Security-Policy-Report-Only: script-src 'self'; report-uri /csp-violations
```

Браузер фіксує порушення і надсилає звіт, але не блокує. Дозволяє поступово налаштовувати CSP без ризику зламати сайт.

---

## X-Frame-Options

Якщо CSP з `frame-ancestors` не підтримується старим браузером, `X-Frame-Options` є резервним захистом від Clickjacking (детально — розділ 6.9). Обидва заголовки варто виставляти одночасно.

```
X-Frame-Options: DENY        # ніхто не може вбудувати у iframe
X-Frame-Options: SAMEORIGIN  # лише той самий origin
```

Примітка: `frame-ancestors` у CSP є гнучкішим і сучаснішим рішенням — він дозволяє вказувати конкретні довірені origins. `X-Frame-Options` не підтримує whitelist.

---

## X-Content-Type-Options

Один рядок, що закриває цілий клас атак через MIME-sniffing — коли браузер «вгадує» тип файлу і виконує `.jpg` як JavaScript. Особливо важливий при user-generated content (вивантаження файлів).

```
X-Content-Type-Options: nosniff
```

Завжди виставляти разом із правильним `Content-Type` для кожного ресурсу. Без `nosniff` зловмисник може завантажити текстовий файл з JavaScript-вмістом і змусити браузер виконати його.

---

## Referrer-Policy

URL може містити конфіденційні дані: ідентифікатори сесій, токени скидання пароля, пошукові запити. Без явного `Referrer-Policy` браузер може надіслати повний URL попередньої сторінки у заголовку `Referer` при переході на зовнішній ресурс.

```
Referrer-Policy: strict-origin-when-cross-origin
```

| Значення | Що передається при cross-origin переходах |
|---|---|
| `no-referrer` | Нічого |
| `strict-origin` | Лише схема + хост (без шляху і параметрів) |
| `strict-origin-when-cross-origin` | Повний URL для same-origin, лише origin для cross-origin |
| `unsafe-url` | Повний URL завжди (небезпечно) |

`strict-origin-when-cross-origin` — рекомендований баланс між функціональністю і приватністю.

---

## Permissions-Policy

Доповнює CSP, контролюючи доступ до потужних браузерних API — тих, що зловмисний XSS або скомпрометований CDN-скрипт може спробувати використати:

```
Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=(self)
```

Значення `()` — повна заборона навіть для вбудованих скриптів. `(self)` — дозволяє лише першій стороні. Особливо важливо для сайтів, що завантажують сторонні рекламні або аналітичні скрипти — вони не повинні мати доступ до мікрофона чи камери.

---

## Cross-Origin-Resource-Policy (CORP)

Захищає ресурси від завантаження іншими origins. Без CORP ресурс `cdn.example.com/data.json` може бути включений в будь-яку сторінку через `<script src>` або `fetch`. З CORP:

```
Cross-Origin-Resource-Policy: same-origin   # ресурс тільки для свого origin
Cross-Origin-Resource-Policy: same-site     # ресурс для свого сайту (піддомени)
Cross-Origin-Resource-Policy: cross-origin  # публічний (дефолт)
```

CORP є частиною захисту від Spectre side-channel атак — браузер не дозволить сторінці з іншого origin навіть завантажити ресурс в пам'ять, не кажучи про читання.

---

## Зведена конфігурація

**Nginx:**

```nginx
server {
    # Транспорт
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # Контент
    # CSP: для динамічних сайтів — через upstream з nonce; для статичних — whitelist:
    add_header Content-Security-Policy
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests;" always;

    # Браузерний захист
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;

    # Видалити інформативні заголовки
    server_tokens off;
    # proxy_hide_header X-Powered-By;
}
```

**Apache:**

```apache
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'; object-src 'none';"
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
    Header unset X-Powered-By
</IfModule>
ServerTokens Prod
ServerSignature Off
```

---

## Пріоритети впровадження

Якщо впроваджуєте поступово — ось порядок за співвідношенням «зусилля / вплив»:

| Заголовок | Захист від | Зусилля | Пріоритет |
|---|---|---|---|
| HSTS | SSL stripping, downgrade | Низькі | 🔴 Must |
| X-Content-Type-Options | MIME sniffing | Мінімальні | 🔴 Must |
| X-Frame-Options | Clickjacking | Мінімальні | 🔴 Must |
| Referrer-Policy | Витік URL | Низькі | 🟠 Should |
| Permissions-Policy | API-зловживання | Низькі | 🟠 Should |
| CSP (базовий, whitelist) | XSS частково | Середні | 🟠 Should |
| CSP (строгий, nonce) | XSS повністю | Високі | 🟡 Advanced |
| CORP/COOP | Spectre, cross-origin | Середні | 🟡 Advanced |

---

## Міні-вправа

```bash
# Перевірити заголовки свого (або навчального) сайту
curl -I https://example.com 2>/dev/null | grep -iE \
  "strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions"

# Python-скрипт для автоматичної оцінки
import requests

REQUIRED = [
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Referrer-Policy',
]

url = 'https://your-site.com'
r = requests.get(url, timeout=10)
for h in REQUIRED:
    present = h in r.headers
    print(f"{'✅' if present else '❌'} {h}: {r.headers.get(h, 'ВІДСУТНІЙ')}")
```

Або скористайтесь онлайн-інструментом **securityheaders.com** — він дає оцінку A+ до F і конкретні рекомендації.

## Джерела та додаткові матеріали

- SecurityHeaders.com — онлайн-тест.
- CSP Evaluator (csp-evaluator.withgoogle.com) — аналіз директив CSP.
- MDN Web Docs, *HTTP headers*.
- OWASP, *HTTP Security Response Headers Cheat Sheet*.
- HSTS Preload List (hstspreload.org).

---

**Попередній розділ:** [6.9. CSRF і Clickjacking](09-csrf-i-klikkdzheking.md)
**Далі:** [6.11. API Security](11-api-security.md)
**Назад до модуля:** [README модуля 06](README.md)

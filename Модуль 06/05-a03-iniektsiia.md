# 6.5. A03: Injection

Injection — найдовговічніший клас вразливостей в історії веббезпеки. Ідея однакова для всіх різновидів: дані, надані користувачем, інтерпретуються як команди або запити мовою, відмінною від мови застосунку. Рядок, що мав бути пошуковим запитом, стає SQL-командою. Ім'я файлу стає shell-командою. Параметр URL стає LDAP-запитом. Ця вразливість виявляється знову і знову в різних технологіях, бо корінна причина — концептуальна: відсутність чіткого розмежування між кодом і даними.

> 📖 Ключові терміни — у [глосарії модуля](00-glosariy.md).

## SQL Injection: механізм і варіанти

**SQL Injection (SQLi)** — найвідоміший різновид. Вхідні дані вставляються безпосередньо в SQL-запит без параметризації.

**Базовий механізм:**

```python
# ❌ ВРАЗЛИВО: конкатенація рядків у SQL
def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return db.execute(query)

# Атакуючий вводить: admin' OR '1'='1
# Запит стає: SELECT * FROM users WHERE username = 'admin' OR '1'='1'
# Результат: повертає всіх користувачів (1=1 завжди True)

# Атака: admin'; DROP TABLE users; --
# SELECT * FROM users WHERE username = 'admin'; DROP TABLE users; --'
```

**Типи SQLi за методом виявлення:**

| Тип | Механізм | Виявлення |
|---|---|---|
| **In-band (Error-based)** | Сервер повертає SQL-помилку з даними | Додати `'` → помилка БД видна у відповіді |
| **In-band (Union-based)** | UNION SELECT витягує дані з інших таблиць | `' UNION SELECT null, table_name FROM information_schema.tables--` |
| **Blind (Boolean-based)** | Відповідь змінюється залежно від умови | `' AND 1=1--` (true) vs `' AND 1=2--` (false) |
| **Blind (Time-based)** | Затримка відповіді підтверджує умову | `'; WAITFOR DELAY '0:0:5'--` (MS SQL) |
| **Out-of-band** | Дані через DNS/HTTP до зовнішнього сервера | Складний; потрібні спецфункції БД |

**Union-based SQLi (витяг даних):**

```sql
-- Атакуючий визначає кількість стовпців
' ORDER BY 1-- (OK)
' ORDER BY 2-- (OK)
' ORDER BY 3-- (помилка → 2 стовпці)

-- Витяг з information_schema
' UNION SELECT table_name, column_name FROM information_schema.columns--

-- Витяг паролів
' UNION SELECT username, password FROM users--
```

**Захист — параметризовані запити (Prepared Statements):**

```python
# ✅ Python SQLite
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))

# ✅ Python SQLAlchemy ORM (безпечний за замовчуванням)
user = db.query(User).filter(User.username == username).first()

# ✅ Python psycopg2 (PostgreSQL)
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))

# ❌ Але навіть ORM можна «зламати»:
# SQLAlchemy raw query без параметризації — все ж вразливо
db.execute(f"SELECT * FROM users WHERE username = '{username}'")  # ← НІ!
db.execute(text("SELECT * FROM users WHERE username = :user"), {'user': username})  # ← Так
```

## NoSQL Injection

SQL-ін'єкція можлива тому, що рядок і команда передаються разом. Та сама проблема існує і в NoSQL-базах — просто «мова запитів» інша. MongoDB використовує JSON-об'єкти з операторами (`$ne`, `$gt`, `$regex`) — і якщо ці оператори можна передати у вхідних даних, атака стає можливою.

**MongoDB Injection (приклад на Node.js/Python):**

```python
# ❌ ВРАЗЛИВО: MongoDB query з user input
def login(username, password):
    user = users_collection.find_one({
        'username': username,
        'password': password
    })

# Атакуючий надсилає JSON:
# {"username": "admin", "password": {"$ne": ""}}
# MongoDB оператор $ne (not equal) → пароль ≠ "" → True для будь-якого запису!
# Результат: вхід без пароля

# ✅ Захист: валідація типів і escape
def login(username: str, password: str):
    if not isinstance(username, str) or not isinstance(password, str):
        raise ValueError("Invalid input type")
    # Можна також використовувати $eq для явного порівняння
    user = users_collection.find_one({
        'username': {'$eq': username},
        'password': {'$eq': hash_password(password)}  # завжди хешувати пароль!
    })
```

## Command Injection

Ті ж принципи — ті ж наслідки, але на рівень нижче. Якщо SQL-ін'єкція виконує команди у базі даних, Command Injection виконує команди у самій операційній системі. Наслідки масштабніші: зловмисник отримує не записи таблиці, а shell на сервері.

```python
# ❌ ВРАЗЛИВО
import os
def ping_host(host):
    os.system(f"ping -c 4 {host}")
    # Атака: host = "8.8.8.8; cat /etc/passwd"
    # Виконає: ping -c 4 8.8.8.8; cat /etc/passwd

# ❌ Теж вразливо (shell=True)
import subprocess
subprocess.call(f"ping -c 4 {host}", shell=True)

# ✅ Правильно: передаємо аргументи списком (НЕ рядком), shell=False
import subprocess
import shlex

def ping_host(host: str):
    # Валідація: дозволяємо лише IP або hostname
    if not re.match(r'^[a-zA-Z0-9._-]+$', host):
        raise ValueError("Invalid hostname")
    result = subprocess.run(
        ['ping', '-c', '4', host],  # ← список, не рядок
        capture_output=True,
        text=True,
        timeout=10,
        shell=False  # ← shell=False за замовчуванням
    )
    return result.stdout
```

## XXE: XML External Entity Injection

SQL, NoSQL, Command — всі ці ін'єкції передбачають, що дані виконуються безпосередньо. XXE працює інакше: зловмисник не виконує код — він змушує XML-парсер прочитати файл або зробити мережевий запит, маніпулюючи структурою документа. Це особливо небезпечно для систем, що приймають XML — XML-API, SOAP-сервіси, файли конфігурацій.

```xml
<!-- Шкідливий XML, надісланий атакуючим -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <!-- Або SSRF: <!ENTITY xxe SYSTEM "http://internal-server/secret"> -->
]>
<user>
  <name>&xxe;</name>  ← замінюється вмістом /etc/passwd
</user>
```

**Захист:**

```python
# ❌ ВРАЗЛИВО: дефолтний lxml з external entities
from lxml import etree
tree = etree.parse(user_xml_file)

# ✅ Правильно: відключити external entities
parser = etree.XMLParser(
    no_network=True,      # заборонити мережеві entities
    resolve_entities=False,  # не резолвити entities
    load_dtd=False,       # не завантажувати DTD
)
tree = etree.parse(user_xml_file, parser)

# Або Python defusedxml (безпечний парсер)
import defusedxml.ElementTree as ET
tree = ET.parse(user_xml_file)  # автоматично захищений від XXE
```

## LDAP Injection

Коли застосунок формує LDAP-запити з вхідних даних:

```python
# ❌ ВРАЗЛИВО
def authenticate(username, password):
    ldap_query = f"(&(uid={username})(userPassword={password}))"
    # Атака: username = "*)(&" → запит стає (&(uid=*)(&)(userPassword=...))
    # Умова uid=* → True для будь-якого запису → обхід автентифікації

# ✅ Захист: escape спеціальних символів LDAP
import ldap3
from ldap3.utils.conv import escape_filter_chars

def authenticate(username: str, password: str):
    safe_username = escape_filter_chars(username)
    ldap_query = f"(&(uid={safe_username}))"
    # Або використовувати ldap3 ORM-стиль
```

## Template Injection (SSTI)

**Server-Side Template Injection** — коли дані користувача передаються напряму в шаблонізатор:

```python
# ❌ ВРАЗЛИВО: Jinja2 з динамічним рендерингом
from flask import render_template_string

@app.route('/greet')
def greet():
    name = request.args.get('name')
    template = f"Hello, {name}!"           # ← вставляємо user input
    return render_template_string(template) # ← рендеримо як шаблон

# Атака: name = {{7*7}} → відповідь: Hello, 49!
# Атака: name = {{config.SECRET_KEY}} → витік секрету
# RCE: name = {{''.__class__.__mro__[1].__subclasses__()[...]('id', ...)}}

# ✅ Правильно: ніколи не рендерити user input як шаблон
return render_template_string("Hello, {{ name }}!", name=name)  # ← name — змінна, не шаблон
```

## Міні-вправа

Знайдіть або напишіть простий вразливий Python Flask ендпоінт:

```python
# vunlerable_app.py — для тестування ЛИШЕ локально
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/user')
def get_user():
    username = request.args.get('name', '')
    conn = sqlite3.connect(':memory:')
    conn.execute("CREATE TABLE users (id INTEGER, name TEXT, secret TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'alice', 'password123')")
    conn.execute("INSERT INTO users VALUES (2, 'bob', 'secret456')")
    # ❌ ВРАЗЛИВО:
    result = conn.execute(f"SELECT * FROM users WHERE name = '{username}'").fetchall()
    return str(result)

if __name__ == '__main__':
    app.run(debug=False)
```

Запустіть і спробуйте:
1. `/user?name=alice` — звичайний запит
2. `/user?name=alice' OR '1'='1` — всі записи
3. `/user?name=alice' UNION SELECT 1,2,sqlite_version()--` — версія БД

Потім виправте вразливість за допомогою параметризованого запиту і переконайтесь, що атаки більше не працюють.

## Зведений чек-лист захисту від Injection

| Тип | Захист |
|---|---|
| SQL | Параметризовані запити / ORM з перевіркою |
| NoSQL | Типова валідація, уникати операторів у вхідних даних |
| Command | `subprocess` зі списком, без shell=True; whitelist вхідних даних |
| XXE | Відключити external entities; `defusedxml` |
| LDAP | `escape_filter_chars` |
| Template | Ніколи не рендерити user input як шаблон |
| XSS (A03) | Output encoding (детально — розділ 6.8) |
| **Загальне** | **Validate input, Encode output, Parameterize queries** |

## Джерела та додаткові матеріали

- OWASP, *A03:2021 – Injection*.
- OWASP, *SQL Injection Prevention Cheat Sheet*.
- OWASP, *XML External Entity Prevention Cheat Sheet*.
- PortSwigger Web Academy, *SQL injection* — інтерактивні лабораторні.
- SQLMap (sqlmap.org) — автоматизований SQLi-тестер (лише на власних системах з дозволом).

> **Далі по модулю:** Injection виникає через помилки реалізації — відсутність параметризованих запитів, неправильну санітизацію. Але є клас проблем, де ніяка параметризація не допоможе, бо помилка закладена на рівні архітектурного рішення. Саме це розглядає наступний розділ: [6.6. A04: Insecure Design →](06-a04-insecure-design.md)

---

> Всі вразливості Injection, що ми розглянули, виникають через неправильну **реалізацію**: неправильно написаний запит, неправильно оброблені вхідні дані. Але є клас проблем глибший — де помилка закладена ще до написання першого рядка коду, в самому **проектному рішенні**. Саме це досліджує наступний розділ.

**Попередній розділ:** [6.4. A02: Cryptographic Failures](04-a02-cryptographic-failures.md)
**Далі:** [6.6. A04: Insecure Design](06-a04-insecure-design.md)
**Назад до модуля:** [README модуля 06](README.md)

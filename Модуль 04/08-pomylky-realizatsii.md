# 4.8. Поширені помилки реалізації криптографії

«Не пишіть власну криптографію» — найчастіша порада в галузі. Але навіть використовуючи перевірені бібліотеки, можна зробити криптографію марною через неправильне використання. Найбільше витоків і зламів відбувається не тому що алгоритм слабкий, а тому що хтось неправильно його застосував: використав небезпечний режим, повторив nonce, зберіг ключ у коді або порівняв хеші незахищеним способом. Цей розділ — каталог реальних помилок, що зустрічаються у production-системах.

> 📖 Ключові терміни — у [глосарії модуля](00-glosariy.md).

## Помилка 1: ECB-режим

Розглянуто в розділі 4.2, але варто повторити окремо — це, мабуть, найпоширеніша помилка початківців.

```python
# ❌ НЕБЕЗПЕЧНО: ECB-режим
# (приклад використовує pycryptodome лише для демонстрації антипатерну;
#  у власному коді використовуйте бібліотеку `cryptography`, як показано нижче)
# pip install pycryptodome
from Crypto.Cipher import AES as _AES_DEMO
import os

key = os.urandom(32)
cipher = _AES_DEMO.new(key, _AES_DEMO.MODE_ECB)

# Однакові блоки дають однакові шифротексти
data = b"BLOCK1_16B______" + b"BLOCK1_16B______"  # два однакових блоки
encrypted = cipher.encrypt(data)
# encrypted[0:16] == encrypted[16:32]  → структура видна!
```

**Демонстрація через ECB pinguin:** зображення Linux-пінгвіна, зашифроване ECB, зберігає контури і розпізнається як пінгвін. Це знакова демонстрація, що з'явилась у 2004 році і залишається найнаочнішим прикладом проблеми.

```python
# ✅ ПРАВИЛЬНО: GCM-режим
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = AESGCM.generate_key(bit_length=256)
nonce = os.urandom(12)  # 96-бітний nonce для GCM
aesgcm = AESGCM(key)
ciphertext = aesgcm.encrypt(nonce, data, None)  # Містить автентифікаційний тег
```

## Помилка 2: Фіксований або передбачуваний IV/Nonce

**IV (Initialization Vector)** або **Nonce** має бути унікальним для кожного шифрування з тим самим ключем. Повторення — катастрофічне:

```python
# ❌ НЕБЕЗПЕЧНО: фіксований IV
FIXED_IV = b'\x00' * 16

# При однаковому IV і ключі:
# CBC: зловмисник може визначити, чи два повідомлення починаються однаково
# CTR/GCM: зловмисник отримує XOR двох відкритих текстів!
# GCM: повторення nonce також відкриває автентифікаційний ключ

# ❌ НЕБЕЗПЕЧНО: лічильник, що починається з 0 після кожного перезапуску
counter = 0
nonce = counter.to_bytes(12, 'big')  # Якщо програма перезапуститься — nonce повториться
```

**Реальний кейс: WPA2 Nonce Reuse.** Атака KRACK (2017) на WPA2 використовувала саме повторення nonce у CTR-режимі через помилку в реалізації протоколу рукостискання.

```python
# ✅ ПРАВИЛЬНО: криптографічно безпечний випадковий nonce
import os
nonce = os.urandom(12)  # 96 біт для GCM — достатньо для 2^48 операцій без колізій
```

## Помилка 3: Ключі в коді (Hardcoded Keys/Secrets)

Одна з найпоширеніших проблем, виявлених сканерами типу GitLeaks і TruffleHog. І одна з тих, що найчастіше трапляється з досвідченими розробниками — не через незнання, а через «зроблю потім», що перетворюється на «в production».

**Реальний кейс:** у 2022 році дослідник знайшов у публічному GitHub-репозиторії одного українського держпідприємства AWS-ключі з правами адміністратора. Ключі потрапили в репозиторій через 8 місяців до виявлення — за цей час теоретично можна було отримати доступ до всієї хмарної інфраструктури. GitGuardian у своєму звіті за 2023 рік зафіксував понад 12 мільйонів нових витоків секретів у публічних репозиторіях — і це лише публічних.

```python
# ❌ НЕБЕЗПЕЧНО: ключ у коді
API_KEY = "sk_live_abcdef1234567890"
DB_PASSWORD = "admin123"
SECRET_KEY = b'\x01\x02\x03\x04...\x20'  # навіть бінарний ключ в коді — ні
```

**Чому це катастрофічно:**
- Код потрапляє в git-репозиторій (навіть приватний може бути злитий).
- Розробники бачать ключі в IDE, логах, core dumps.
- Ключ не можна замінити без нового деплою.
- Зворотна інженерія бінарника — стандартна техніка.

**Реальні кейси:** регулярно в публічних GitHub-репозиторіях знаходять API-ключі AWS, секретні ключі Stripe, паролі баз даних. GitGuardian повідомив про мільйони витоків таємниць у 2023 році.

```python
# ✅ ПРАВИЛЬНО: ключі з середовища або захищеного сховища
import os
from pathlib import Path

# З env variables
api_key = os.environ["API_KEY"]

# З файлу (з правами 0600, поза репозиторієм)
secret = Path("/etc/myapp/secret.key").read_bytes()

# З HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager тощо
# import hvac  # для Vault
```

## Помилка 4: Небезпечні PRNG

Це не абстрактна теорія. У 2008 році один рядок, видалений з вихідного коду OpenSSL у Debian-патчі, спричинив одну з найбільших криптографічних катастроф в історії Linux. Розробник видалив ініціалізацію ентропії через попередження інструменту перевірки пам'яті. Результат: всі SSL/TLS і SSH ключі, згенеровані на Debian і Ubuntu протягом двох років, мали лише 32 768 можливих значень замість 2²⁵⁶. Автоматизований перебір за хвилини. Мільйони серверів довелось терміново переналаштовувати по всьому світу.

**PRNG (Pseudo-Random Number Generator)** — критичний компонент криптографії. Ключі, nonce, salt мають генеруватись криптографічно стійким PRNG (CSPRNG).

```python
# ❌ НЕБЕЗПЕЧНО: стандартний random модуль Python
import random
key = bytes([random.randint(0, 255) for _ in range(32)])
# random використовує Mersenne Twister — передбачуваний після 624 вихідних значень

# ❌ НЕБЕЗПЕЧНО: time-based seed
random.seed(int(time.time()))

# ✅ ПРАВИЛЬНО: криптографічно стійкий PRNG
import os
key = os.urandom(32)         # системний CSPRNG (getrandom syscall / CryptGenRandom)
import secrets
token = secrets.token_bytes(32)  # Python 3.6+, аналог os.urandom
```

**Реальний кейс:** дебіановська уразливість OpenSSL (2008) — розробник Debian «закоментував» ініціалізацію ентропії в OpenSSL, і всі SSH/SSL ключі, згенеровані на Debian протягом 2 років, містили лише 32768 можливих значень.

## Помилка 5: Небезпечне порівняння (Timing Attack)

Звичайне порівняння рядків `==` є вразливим до **timing attack** (атаки за часом):

```python
# ❌ НЕБЕЗПЕЧНО: порівняння зупиняється на першому невідповідному байті
def verify_token_insecure(provided, expected):
    return provided == expected  # або: всі char-порівняння по одному

# Зловмисник може виміряти мікросекундну різницю і побайтово відгадати очікуване значення
```

```python
# ✅ ПРАВИЛЬНО: constant-time порівняння
import hmac
import secrets

def verify_token_secure(provided: str, expected: str) -> bool:
    # hmac.compare_digest завжди порівнює всі байти, незалежно від результату
    return hmac.compare_digest(
        provided.encode(), expected.encode()
    )

# Також для bytes:
def verify_mac(received: bytes, expected: bytes) -> bool:
    return secrets.compare_digest(received, expected)
```

**Де це критично:** верифікація MAC/HMAC, API-токенів, сесійних cookie, паролів (якщо не використовуєте спеціалізований алгоритм).

## Помилка 6: Padding Oracle Attack

Атака на CBC-шифрування, що дозволяє розшифровувати дані, маючи лише доступ до «oracle» — системи, що повідомляє про помилку padding.

**Механізм (спрощено):**
1. CBC потребує, щоб розмір відкритого тексту був кратний розміру блоку → дані доповнюються (padding).
2. Стандарт PKCS#7: якщо потрібно 3 байти padding, додаємо `\x03\x03\x03`.
3. При дешифруванні: якщо padding невалідний → сервер повертає помилку «Invalid padding».
4. Атакуючий модифікує шифротекст по одному байту і перевіряє, чи повертається помилка.
5. За ~128 запитів на байт — відновлює весь відкритий текст.

**Реальний кейс:** ASP.NET ViewState Padding Oracle (2010) — Microsoft знадобився термінові патчі для всього стеку .NET.

**Захист:** використовувати **AES-GCM** замість AES-CBC. GCM автентифікує шифротекст — будь-яка модифікація виявляється до спроби дешифрування, без «корисного» oracle.

```python
# ✅ GCM автоматично захищає від Padding Oracle
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

aesgcm = AESGCM(key)
# decrypt кидає InvalidTag якщо шифротекст модифіковано — до повернення будь-якого plaintext
plaintext = aesgcm.decrypt(nonce, ciphertext, None)
```

## Помилка 7: Слабкий алгоритм хешування паролів

Детально розглянуто в розділі 4.4. Ключові патерни-антипатерни:

```python
# ❌ ВСІ ЦІ ВАРІАНТИ НЕБЕЗПЕЧНІ:
import hashlib
stored = hashlib.md5(password.encode()).hexdigest()      # MD5 — мертвий
stored = hashlib.sha256(password.encode()).hexdigest()   # Швидкий хеш — можна перебрати
stored = hashlib.sha256((salt + password).encode()).hexdigest()  # Краще, але все одно швидкий

# ✅ ПРАВИЛЬНО:
from argon2 import PasswordHasher
ph = PasswordHasher()
stored = ph.hash(password)  # Автоматично: salt + параметри + повільний алгоритм
```

## Помилка 8: Key Derivation без KDF

**Пряме використання пароля як ключа** — груба помилка:

```python
# ❌ НЕБЕЗПЕЧНО: пароль безпосередньо як ключ AES
password = "mysecret"
key = password.encode().ljust(32, b'\x00')  # Тільки 8 байт реальної ентропії!

# ✅ ПРАВИЛЬНО: використати KDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,  # унікальний для кожного пароля
    iterations=600_000,  # NIST рекомендує 600k для SHA-256 (2023)
)
key = kdf.derive(password.encode())
```

Або ще краще — Argon2:
```python
import argon2.low_level as argon2_ll
key = argon2_ll.hash_secret_raw(
    password.encode(), salt,
    time_cost=3, memory_cost=65536, parallelism=4,
    hash_len=32, type=argon2_ll.Type.ID
)
```

## Помилка 9: Небезпечна рандомізація UUID/токенів

```python
# ❌ НЕБЕЗПЕЧНО: UUID v1 або v4 з не-crypto random
import uuid
token = str(uuid.uuid1())  # містить MAC-адресу і timestamp — передбачуваний!
token = str(uuid.uuid4())  # Python: використовує os.urandom() — OK, але hex encoding

# ✅ ПРАВИЛЬНО: явно криптографічний токен
import secrets
token = secrets.token_urlsafe(32)  # 32 байти = 256 біт ентропії, URL-safe base64
# або
token = secrets.token_hex(32)      # 64 hex символи
```

## Золоте правило: не реалізовуй свою криптографію

Навіть якщо ви розумієте всі ці концепції — не реалізовуйте криптографічні алгоритми самостійно. Безпечна реалізація AES або ECDSA потребує захисту від timing attacks на рівні асемблеру, правильного управління пам'яттю (zeroing секретів), перевірки всіх граничних умов і аудиту сотнями криптографів протягом років.

**Використовуйте:** `cryptography` (Python), OpenSSL/BoringSSL, libsodium, NaCl.
**Не використовуйте:** `pycrypto` (застаріла, невпідтримувана), власні реалізації.

## Міні-вправа

Запустіть `crypto_audit.py` з лабораторної 4.10 на будь-якому Python-файлі з вашого поточного або навчального проекту:

```bash
python crypto_audit.py your_project_file.py
```

Якщо власного проекту немає — знайдіть будь-який відкритий Python-репозиторій на GitHub, завантажте один файл і перевірте. Чи є знахідки? Чи стосуються вони реального коду, а не тестів?

Додатково: встановіть `pip install detect-secrets` — це промисловий інструмент від IBM для пошуку секретів у коді. Запустіть на власному проекті: `detect-secrets scan > .secrets.baseline`. Що знайдено?

## Перевірочна таблиця для code review

| Питання | Що шукати |
|---|---|
| Який режим AES? | ECB → помилка; GCM → OK |
| Як генерується IV/Nonce? | os.urandom(12) → OK; фіксований/лічильник → помилка |
| Де зберігаються ключі? | env/Vault/HSM → OK; у коді/git → помилка |
| Який PRNG? | os.urandom/secrets → OK; random модуль → помилка |
| Як порівнюються токени/MAC? | hmac.compare_digest → OK; == → помилка |
| Як хешуються паролі? | argon2/bcrypt → OK; sha256/md5 → помилка |
| Чи використовується KDF для паролів→ключ? | PBKDF2/Argon2 → OK; padding → помилка |

## Джерела та додаткові матеріали

- Moxie Marlinspike, *The Cryptographic Doom Principle* — блогпост про «розшифровуй-потім-перевіряй» помилку.
- OWASP Cryptographic Failures (owasp.org/Top10/A02) — Top 10 #2.
- cryptopals.com — набір криптографічних задач для вивчення на помилках.
- NaCl/libsodium — бібліотека, що усуває більшість цих помилок за архітектурою.

---

**Попередній розділ:** [4.7. Постквантова криптографія](07-postkvantovist.md)
**Далі:** [4.9. Українські криптографічні стандарти](09-ukrainski-standarty.md)
**Назад до модуля:** [README модуля 04](README.md)

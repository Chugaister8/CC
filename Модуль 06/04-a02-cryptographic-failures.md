# 6.4. A02: Cryptographic Failures

Криптографічні збої — категорія, що у 2021 замінила «Sensitive Data Exposure» і стала більш точною: проблема не лише в тому, що дані розкриті, а в тому, *чому* вони розкриті. Найчастіше — через відсутність шифрування, використання застарілих або зламаних алгоритмів, неправильне управління ключами чи неправильне шифрування даних у русі. Для вебзастосунків це означає: паролі в MD5, дані по HTTP, ключі API в .env на публічному сервері, TLS 1.0 на продакшн-сервері.

> 📖 Ключові терміни — у [глосарії модуля](00-glosariy.md).

## Класифікація збоїв

**Тип 1: Передача даних без шифрування або з слабким шифруванням**
- HTTP замість HTTPS для чутливих ендпоінтів.
- TLS 1.0/1.1 (зламані протоколи).
- Слабкі cipher suites (RC4, DES, 3DES, NULL cipher).
- Mixed content: HTTPS-сторінка завантажує HTTP-ресурси.

**Тип 2: Неправильне зберігання чутливих даних**
- Паролі в MD5, SHA-1, SHA-256 без salt (або взагалі у відкритому вигляді).
- Дані кредитних карток, SSN у відкритому вигляді або з симетричним шифруванням без управління ключами.
- Чутливі дані у логах (паролі, токени, PAN).
- Ключі API і секрети в коді або системах контролю версій.

**Тип 3: Криптографічно слабкі реалізації**
- Самописна криптографія (розділ 4.8 — ніколи!).
- ECB-режим для блокового шифру.
- Передбачувані або фіксовані IV/nonces.
- Ненадійний генератор випадкових чисел.

## Класифікація чутливих даних і вимоги

Не всі дані потребують однакового захисту. Важливо класифікувати дані перш ніж обирати механізм захисту:

| Клас даних | Приклади | Мінімальні вимоги |
|---|---|---|
| **Публічні** | Назви продуктів, публічні ціни | — |
| **Внутрішні** | Внутрішні документи, email між колегами | TLS при передачі |
| **Конфіденційні** | ПІБ, email, телефон | TLS + шифрування at-rest + мінімальний збір |
| **Критичні** | Паролі, фін. дані, медичні дані | TLS + надійне хешування/шифрування + аудит + DLP |

**Принцип мінімальної збірності даних (Data Minimization):** не збирати дані, що не потрібні. Найкраща криптографія для даних, яких немає — не потрібна.

## TLS-вимоги для вебзастосунків

```
✅ Must (обов'язково):
- TLS 1.2 як мінімум; TLS 1.3 — рекомендовано
- Валідний, не прострочений сертифікат від довіреного CA
- HSTS (HTTP Strict Transport Security): примусовий HTTPS
- Заборона SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1

❌ Must NOT:
- NULL cipher, анонімне шифрування (без автентифікації)
- RC4, DES, 3DES (SWEET32 атака), EXPORT cipher
- MD5 в підписах сертифікатів
- Самопідписані сертифікати на продакшні

✅ Should (рекомендовано):
- Perfect Forward Secrecy (ECDHE/DHE key exchange)
- OCSP Stapling
- Certificate Transparency
- cipher suite: TLS_AES_256_GCM_SHA384 або TLS_CHACHA20_POLY1305_SHA256
```

**Перевірка налаштувань TLS:**
```bash
# SSL Labs: онлайн-тест
# https://ssllabs.com/ssltest/analyze.html?d=yourdomain.com

# Локально через testssl.sh
./testssl.sh https://yourdomain.com

# Або через openssl
openssl s_client -connect yourdomain.com:443 -tls1_2
openssl s_client -connect yourdomain.com:443 2>&1 | grep "Protocol\|Cipher"
```

## HSTS: HTTP Strict Transport Security

**HSTS** — заголовок, що змушує браузер завжди використовувати HTTPS для домену:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
                                ↑                    ↑              ↑
                           1 рік кешування    включно з       Submit до
                                           піддоменами    HSTS Preload List
```

**HSTS Preload List** (`hstspreload.org`) — браузери мають вбудований список доменів, для яких HTTPS є обов'язковим незалежно від того, чи отримав браузер заголовок HSTS. Захищає від атак при першому відвіданні (TOFU проблема).

## Зберігання паролів: нагадування з модуля 04

Детально розглянуто в розділі 4.4, але ключові вимоги для вебзастосунку:

```python
# ❌ ЗАБОРОНЕНО у вебзастосунку:
import hashlib
stored = hashlib.md5(password.encode()).hexdigest()    # MD5 — зламаний
stored = hashlib.sha256(password.encode()).hexdigest() # SHA-256 — занадто швидкий
stored = password                                       # Відкрито — катастрофа

# ✅ ПРАВИЛЬНО: Argon2id
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
stored = ph.hash(password)  # Автоматично генерує salt

# Верифікація
ph.verify(stored, input_password)
```

## Чутливі дані у відповідях API

```python
# ❌ Типова помилка: повертаємо зайві поля
def user_to_dict(user):
    return {
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'password_hash': user.password_hash,   # ← ніколи не повертати!
        'ssn': user.ssn,                        # ← ніколи не повертати!
        'api_key': user.api_key,                # ← лише при явному запиті і з авторизацією
        'credit_card': user.credit_card_number, # ← PAN не зберігати plaintext
        'created_at': user.created_at,
    }

# ✅ Явна серіалізація лише потрібних полів
def user_to_public_dict(user):
    return {
        'id': user.id,
        'name': user.name,
        'avatar_url': user.avatar_url,
    }

def user_to_private_dict(user):
    return {
        'id': user.id,
        'name': user.name,
        'email': user.email,  # маскувати? "a***@example.com"
    }
```

## Чутливі дані в логах

```python
# ❌ Типова помилка: логуємо весь request
import logging
logging.info(f"Request: {request.args} {request.form} {request.json}")
# Якщо форма містить password або card_number — вони в логах!

# ✅ Правильно: явний whitelist полів для логування
SAFE_TO_LOG = {'username', 'action', 'resource_id', 'ip', 'method'}

def safe_log_request(request):
    safe_data = {k: v for k, v in request.form.items() if k in SAFE_TO_LOG}
    logging.info(f"Request: {safe_data}")
```

## Управління секретами: де НЕ зберігати ключі

| Місце | Ризик | Альтернатива |
|---|---|---|
| Код / репозиторій | Публічний git, всі розробники | HashiCorp Vault, AWS Secrets Manager |
| .env у prod сервері | Збій сервера, доступ DevOps | Vault + environment injection |
| База даних | SQL injection читає ключі | HSM, Key Management Service |
| Логи | Записані помилкою | Фільтрація чутливих полів |
| Browser localStorage | XSS-доступ | HttpOnly Cookie або Secure Enclave |

## Міні-вправа

```bash
# 1. Перевірити TLS свого (або навчального) сайту
# Зайдіть на ssllabs.com/ssltest і перевірте оцінку
# A+: ідеально; B: прийнятно; C/F: потрібне виправлення

# 2. Перевірити HSTS
curl -I https://your-site.com | grep -i strict

# 3. Пошук секретів у коді
# pip install detect-secrets
detect-secrets scan . --list-all-plugins | head -20
# Або: git log --all --full-history -- "*.env" "*.key" "*.pem"
```

## Джерела та додаткові матеріали

- OWASP, *A02:2021 – Cryptographic Failures*.
- SSL Labs Server Test (ssllabs.com/ssltest).
- testssl.sh (testssl.sh) — CLI TLS-тестер.
- NIST SP 800-111 — Storage Encryption for End User Devices.
- PCI DSS v4.0, Requirement 4 — Protect Cardholder Data with Strong Cryptography.

---

**Попередній розділ:** [6.3. A01: Broken Access Control](03-a01-broken-access-control.md)
**Далі:** [6.5. A03: Injection](05-a03-iniektsiia.md)
**Назад до модуля:** [README модуля 06](README.md)

# 4.10. Практична лабораторна на Python

П'ять лабораторних, що послідовно охоплюють весь модуль: симетричне шифрування (AES-GCM), асиметричне шифрування (RSA + ECDH), хешування паролів (Argon2), цифрові підписи (Ed25519) і аналіз-детектор небезпечного коду.

**Залежності:**
```bash
pip install cryptography argon2-cffi
```
Бібліотека `cryptography` є стандартним вибором для Python: активно підтримується, проходить аудити безпеки, використовує OpenSSL/BoringSSL зсередини.

---

## Лабораторна 4.10.1: AES-256-GCM шифрування і дешифрування

Правильна реалізація симетричного шифрування з автентифікацією.

```python
"""
aes_gcm_demo.py — симетричне шифрування AES-256-GCM.
Демонструє: генерацію ключа, шифрування, AAD, дешифрування, виявлення підробки.
"""
import os
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_message(key: bytes, plaintext: bytes,
                    associated_data: bytes | None = None) -> dict:
    """
    Шифрує повідомлення AES-256-GCM.
    Повертає словник з nonce, ciphertext і AAD (якщо є).
    """
    nonce = os.urandom(12)  # 96-бітний nonce — стандарт для GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "aad": base64.b64encode(associated_data).decode() if associated_data else None,
    }


def decrypt_message(key: bytes, package: dict) -> bytes:
    """
    Дешифрує повідомлення AES-256-GCM.
    Кидає InvalidTag якщо дані підроблені або ключ невірний.
    """
    nonce = base64.b64decode(package["nonce"])
    ciphertext = base64.b64decode(package["ciphertext"])
    aad = base64.b64decode(package["aad"]) if package.get("aad") else None

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)


if __name__ == "__main__":
    # 1. Генерація ключа (зберігаємо для повторного використання)
    key = AESGCM.generate_key(bit_length=256)
    print(f"Ключ (hex): {key.hex()}")
    print(f"Розмір ключа: {len(key) * 8} біт\n")

    # 2. Шифрування з Additional Authenticated Data
    message = b"Секретний переказ: 10 000 UAH → рахунок UA123456789"
    aad = b"transaction_id=42;timestamp=1700000000"  # автентифікується, але не шифрується

    package = encrypt_message(key, message, aad)
    print("Зашифрований пакет:")
    print(json.dumps(package, indent=2, ensure_ascii=False))

    # 3. Коректне дешифрування
    decrypted = decrypt_message(key, package)
    print(f"\nДешифровано: {decrypted.decode()}")

    # 4. Демонстрація: модифікація шифротексту виявляється
    print("\n--- Спроба підробки ---")
    tampered = dict(package)
    ct_bytes = bytearray(base64.b64decode(tampered["ciphertext"]))
    ct_bytes[5] ^= 0xFF  # змінюємо один байт
    tampered["ciphertext"] = base64.b64encode(bytes(ct_bytes)).decode()

    try:
        decrypt_message(key, tampered)
    except Exception as e:
        print(f"✅ Підробка виявлена: {type(e).__name__}")

    # 5. Демонстрація: невірний ключ
    print("\n--- Спроба з невірним ключем ---")
    wrong_key = AESGCM.generate_key(bit_length=256)
    try:
        decrypt_message(wrong_key, package)
    except Exception as e:
        print(f"✅ Невірний ключ виявлено: {type(e).__name__}")
```

**Завдання:**
1. Що міститься в `ciphertext`? (Підказка: дані + 16-байтний автентифікаційний тег в кінці.)
2. Змініть `aad` перед дешифруванням (не шифротекст) — чи виявиться зміна? Чому?
3. Зашифруйте два різних повідомлення тим самим ключем. Порівняйте nonce — вони різні? Що буде, якщо nonce збігатиметься?

---

## Лабораторна 4.10.2: RSA-OAEP шифрування і ECDH обмін ключами

```python
"""
asymmetric_demo.py — RSA-OAEP шифрування + ECDH обмін ключами.
"""
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ─── RSA-OAEP: шифрування / дешифрування ───────────────────────────────────

def rsa_keygen(key_size: int = 3072) -> tuple:
    """Генерує пару RSA-ключів."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    return private_key, private_key.public_key()


def rsa_encrypt(public_key, data: bytes) -> bytes:
    """Шифрує дані RSA-OAEP з SHA-256."""
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    """Дешифрує RSA-OAEP."""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ─── ECDH: обмін ключами на еліптичних кривих ─────────────────────────────

def ecdh_key_exchange_demo() -> None:
    """Демонструє ECDH обмін ключами між Алісою і Бобом."""
    # Аліса і Боб генерують свої ефемерні пари ключів
    alice_private = ec.generate_private_key(ec.X25519())
    alice_public = alice_private.public_key()

    bob_private = ec.generate_private_key(ec.X25519())
    bob_public = bob_private.public_key()

    # Обмін публічними ключами (можна по відкритому каналу)
    # Аліса обчислює спільний секрет, використовуючи публічний ключ Боба
    alice_shared = alice_private.exchange(ECDH(), bob_public)
    # Боб обчислює спільний секрет, використовуючи публічний ключ Аліси
    bob_shared = bob_private.exchange(ECDH(), alice_public)

    print(f"Аліса ECDH secret: {alice_shared.hex()[:32]}...")
    print(f"Боб   ECDH secret: {bob_shared.hex()[:32]}...")
    print(f"Секрети рівні: {alice_shared == bob_shared}")

    # Виведення ключа шифрування через HKDF
    alice_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"aes-key"
    ).derive(alice_shared)
    bob_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"aes-key"
    ).derive(bob_shared)

    print(f"\nAES-ключ Аліси: {alice_key.hex()}")
    print(f"AES-ключ Боба:  {bob_key.hex()}")
    print(f"Ключі рівні: {alice_key == bob_key}")


if __name__ == "__main__":
    print("=" * 55)
    print("RSA-OAEP шифрування")
    print("=" * 55)

    private_key, public_key = rsa_keygen(3072)
    print(f"Розмір ключа: {private_key.key_size} біт")

    # RSA шифрує лише невеликі дані (менше ~380 байт для RSA-3072)
    # Типове використання: шифрування симетричного ключа
    aes_key = os.urandom(32)
    print(f"\nAES-ключ для шифрування (32 байти): {aes_key.hex()[:16]}...")

    encrypted_key = rsa_encrypt(public_key, aes_key)
    print(f"Зашифрований AES-ключ: {encrypted_key.hex()[:32]}...")
    print(f"Розмір зашифрованого ключа: {len(encrypted_key)} байт")

    decrypted_key = rsa_decrypt(private_key, encrypted_key)
    print(f"Дешифрований AES-ключ: {decrypted_key.hex()[:16]}...")
    print(f"Ключі співпадають: {aes_key == decrypted_key}")

    print("\n" + "=" * 55)
    print("ECDH обмін ключами (X25519)")
    print("=" * 55)
    ecdh_key_exchange_demo()
```

**Завдання:**
1. Спробуйте зашифрувати RSA-OAEP більше 380 байт. Що відбувається? Чому RSA не підходить для шифрування великих даних?
2. Проведіть повну гібридну схему: Аліса шифрує дані AES-GCM; AES-ключ шифрується RSA-публічним ключем Боба; Боб дешифрує AES-ключ і потім дані.

---

## Лабораторна 4.10.3: Хешування паролів — Argon2 і порівняння

```python
"""
password_hashing.py — правильне і неправильне хешування паролів.
Демонструє різницю швидкості між SHA-256 і Argon2.
"""
import hashlib
import time
import os
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError


def benchmark_sha256(password: str, iterations: int = 100_000) -> float:
    """Вимірює час N-кратного SHA-256 хешування."""
    start = time.perf_counter()
    for _ in range(iterations):
        hashlib.sha256(password.encode()).hexdigest()
    return time.perf_counter() - start


def demo_argon2() -> None:
    ph = PasswordHasher(
        time_cost=3,        # ітерації
        memory_cost=65536,  # 64 МБ
        parallelism=4,
    )
    passwords = [
        "password123",
        "password123",   # той самий пароль → інший хеш (різний salt)
        "Password123!",
    ]

    print("Argon2id хеші:")
    hashes = []
    for pwd in passwords:
        start = time.perf_counter()
        h = ph.hash(pwd)
        elapsed = time.perf_counter() - start
        hashes.append(h)
        print(f"  {pwd!r:<20} → {h[:40]}...  ({elapsed*1000:.1f} мс)")

    print(f"\nОднакові паролі дають різні хеші: {hashes[0] != hashes[1]}")

    # Верифікація
    print("\nВерифікація:")
    test_cases = [
        ("password123", hashes[0], True),
        ("password123", hashes[1], True),   # вірний, незважаючи на різний хеш
        ("WrongPassword", hashes[0], False),
    ]
    for pwd, h, expected in test_cases:
        try:
            ph.verify(h, pwd)
            result = True
        except (VerifyMismatchError, VerificationError):
            result = False
        status = "✅" if result == expected else "❌"
        print(f"  {status} {pwd!r:<20} → {'Вірний' if result else 'Невірний'}")


if __name__ == "__main__":
    password = "MyStr0ngP@ssw0rd"

    print("=" * 55)
    print("Порівняння швидкості: SHA-256 vs Argon2")
    print("=" * 55)

    # SHA-256: 100 000 ітерацій
    sha_time = benchmark_sha256(password, 100_000)
    sha_per_sec = 100_000 / sha_time
    print(f"\nSHA-256: 100 000 ітерацій за {sha_time:.3f} сек")
    print(f"  → {sha_per_sec:,.0f} хешів/секунду")
    print(f"  → GPU може бути у 1000-10000x швидше!")

    # Один Argon2 хеш
    ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
    start = time.perf_counter()
    argon_hash = ph.hash(password)
    argon_time = time.perf_counter() - start
    print(f"\nArgon2id: 1 хеш за {argon_time*1000:.1f} мс")
    print(f"  → {1/argon_time:.1f} хешів/секунду")
    print(f"  → Захищений від GPU: пам'ять 64 МБ = VRAM overhead")

    print(f"\nSHA-256 швидший за Argon2 у {sha_per_sec/(1/argon_time):,.0f}x разів")
    print("Для зловмисника це означає в стільки ж разів більше спроб/секунду!")

    print("\n" + "=" * 55)
    print("Демонстрація Argon2")
    print("=" * 55)
    demo_argon2()
```

---

## Лабораторна 4.10.4: Цифрові підписи Ed25519

```python
"""
digital_signatures.py — створення і верифікація цифрових підписів Ed25519.
"""
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption, BestAvailableEncryption
)
from cryptography.exceptions import InvalidSignature


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def sign_document(private_key: Ed25519PrivateKey, document: bytes) -> bytes:
    return private_key.sign(document)


def verify_signature(public_key: Ed25519PublicKey,
                     signature: bytes, document: bytes) -> bool:
    try:
        public_key.verify(signature, document)
        return True
    except InvalidSignature:
        return False


def serialize_keys(private_key: Ed25519PrivateKey,
                   password: bytes | None = None) -> tuple[bytes, bytes]:
    """Серіалізує ключі у PEM-формат."""
    enc = (BestAvailableEncryption(password)
           if password else NoEncryption())

    priv_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, enc)
    pub_pem = private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return priv_pem, pub_pem


if __name__ == "__main__":
    print("=" * 55)
    print("Цифрові підписи Ed25519")
    print("=" * 55)

    # Генерація ключів
    alice_priv, alice_pub = generate_keypair()

    priv_pem, pub_pem = serialize_keys(alice_priv, password=b"key_password")
    print(f"\nПублічний ключ Аліси (PEM):\n{pub_pem.decode()}")
    print(f"Розмір приватного ключа (PEM): {len(priv_pem)} байт")

    # Підписання
    document = (
        b"Угода про конфіденційність\n"
        b"Між ТОВ «Приклад» та ФОП Іваненко І.І.\n"
        b"Дата: 2026-06-01\n"
        b"Підписано цифровим підписом Ed25519"
    )

    signature = sign_document(alice_priv, document)
    print(f"\nПідписаний документ (перші 50 байт): {document[:50].decode()}...")
    print(f"Підпис (hex): {signature.hex()}")
    print(f"Розмір підпису: {len(signature)} байт")

    # Верифікація: успішна
    is_valid = verify_signature(alice_pub, signature, document)
    print(f"\n✅ Верифікація оригінального документа: {is_valid}")

    # Верифікація: підроблений документ
    fake_doc = document.replace(b"Іваненко І.І.", b"Петренко О.О.")
    is_valid_fake = verify_signature(alice_pub, signature, fake_doc)
    print(f"✅ Верифікація підробленого документа: {is_valid_fake} (має бути False)")

    # Верифікація: чужий публічний ключ
    _, eve_pub = generate_keypair()
    is_valid_wrong_key = verify_signature(eve_pub, signature, document)
    print(f"✅ Верифікація з чужим ключем: {is_valid_wrong_key} (має бути False)")

    # Демонстрація: Ed25519 детермінований
    sig2 = sign_document(alice_priv, document)
    print(f"\nПідпис детермінований (однаковий для того самого документа): {signature == sig2}")
    print("(На відміну від ECDSA, де кожен підпис різний через випадковий nonce)")
```

---

## Лабораторна 4.10.5: Детектор небезпечного криптокоду

```python
"""
crypto_audit.py — простий статичний аналізатор Python-файлів на небезпечні
криптографічні патерни. Для навчальних цілей.
"""
import re
from pathlib import Path
from dataclasses import dataclass


@dataclass
class Finding:
    severity: str   # CRITICAL, HIGH, MEDIUM
    line: int
    pattern: str
    description: str
    fix: str


PATTERNS = [
    # ECB режим
    (r"AES\.MODE_ECB|mode=AES\.MODE_ECB",
     "CRITICAL", "ECB режим AES",
     "ECB шифрує однакові блоки однаково — структура даних видна",
     "Використовуйте AES-GCM: AESGCM з бібліотеки cryptography"),

    # MD5 / SHA1 для безпекових цілей
    (r"hashlib\.md5\(|hashlib\.sha1\(",
     "HIGH", "MD5 або SHA-1",
     "MD5 і SHA-1 криптографічно зламані для перевірки цілісності і паролів",
     "Використовуйте SHA-256 або SHA-3 для цілісності; Argon2 для паролів"),

    # Жорсткозакодовані секрети
    (r'(?i)(secret|key|password|token|api_key)\s*=\s*["\'][^"\']{8,}["\']',
     "CRITICAL", "Можливий жорсткозакодований секрет",
     "Секрети в коді потрапляють у git і компрометуються",
     "Використовуйте os.environ або сховища секретів (Vault, AWS SM)"),

    # Небезпечний random
    (r"\brandom\.random\(\)|\brandom\.randint\(|\brandom\.choice\(",
     "HIGH", "Небезпечний PRNG (random модуль)",
     "random модуль не є криптографічно стійким",
     "Використовуйте os.urandom() або secrets модуль"),

    # Порівняння == для секретів
    (r'token\s*==\s*|password\s*==\s*|hmac\s*==\s*|signature\s*==\s*',
     "MEDIUM", "Небезпечне порівняння секретів",
     "Звичайне == вразливе до timing attack",
     "Використовуйте hmac.compare_digest() або secrets.compare_digest()"),

    # SHA-256 безпосередньо для паролів
    (r'sha256.*password|password.*sha256|sha512.*password|password.*sha512',
     "HIGH", "SHA-256/512 для хешування паролів",
     "Швидкі хеші (SHA-2) небезпечні для паролів — можна перебирати мільярди/сек",
     "Використовуйте argon2, bcrypt або scrypt"),

    # Фіксований IV/nonce
    (r"iv\s*=\s*b['\"][\\x00]+['\"]|nonce\s*=\s*b['\"][\\x00]+['\"]|iv\s*=\s*b\"\\\\x00",
     "CRITICAL", "Нульовий або фіксований IV/nonce",
     "Фіксований IV компрометує безпеку шифрування",
     "Використовуйте os.urandom(16) для IV (CBC) або os.urandom(12) для GCM"),
]


def audit_file(filepath: str) -> list[Finding]:
    findings = []
    try:
        lines = Path(filepath).read_text(errors="replace").splitlines()
    except Exception as e:
        print(f"Помилка читання файлу: {e}")
        return findings

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):  # Пропускати коментарі
            continue
        for pattern, severity, name, desc, fix in PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(Finding(severity, lineno, name, desc, fix))

    return findings


def print_report(filepath: str, findings: list[Finding]) -> None:
    ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}
    print(f"\n{'='*60}")
    print(f"Аудит: {filepath}")
    print(f"{'='*60}")

    if not findings:
        print("✅ Небезпечних патернів не виявлено.")
        return

    by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": []}
    for f in findings:
        by_severity[f.severity].append(f)

    for severity in ["CRITICAL", "HIGH", "MEDIUM"]:
        for f in by_severity[severity]:
            print(f"\n{ICONS[severity]} [{f.severity}] Рядок {f.line}: {f.pattern}")
            print(f"   Проблема: {f.description}")
            print(f"   Виправлення: {f.fix}")

    c = sum(len(v) for v in by_severity.values())
    print(f"\nЗагалом: {c} знахідок "
          f"({len(by_severity['CRITICAL'])} критичних, "
          f"{len(by_severity['HIGH'])} високих, "
          f"{len(by_severity['MEDIUM'])} середніх)")


if __name__ == "__main__":
    import sys

    # Перевірити переданий файл або протестувати на "поганому" зразку
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        # Тестовий "поганий" файл
        bad_code = '''
import random
import hashlib
from Crypto.Cipher import AES

SECRET_KEY = "hardcoded_secret_key_123"
API_TOKEN = "sk_live_abcdef1234"

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def encrypt(data):
    key = b"1234567890123456"
    iv = b"\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

def verify_token(provided, expected):
    return provided == expected

session_id = str(random.randint(100000, 999999))
'''
        test_file = Path("/tmp/bad_crypto_example.py")
        test_file.write_text(bad_code)
        target = str(test_file)
        print(f"Тестовий файл: {target}")

    findings = audit_file(target)
    print_report(target, findings)
```

**Завдання:**
1. Запустіть `python crypto_audit.py` без аргументів — він перевірить тестовий файл з навмисними помилками.
2. Запустіть на будь-якому реальному Python-файлі з вашого проекту: `python crypto_audit.py your_file.py`.
3. Розширте скрипт: додайте патерн для виявлення `base64.decode` без шифрування (Base64 — не безпека).

## Джерела та додаткові матеріали

- `cryptography` (cryptography.io) — основна документація бібліотеки.
- `argon2-cffi` (argon2-cffi.readthedocs.io) — Python-обгортка для Argon2.
- Real Python, *Cryptography in Python* — практичні статті.
- cryptopals.com — набір задач для глибокого розуміння криптографії через атаки.

---

**Попередній розділ:** [4.9. Українські криптостандарти](09-ukrainski-standarty.md)
**Далі:** [4.11. Чек-лист і самоперевірка](11-chek-lyst-i-samoperevirka.md)
**Назад до модуля:** [README модуля 04](README.md)

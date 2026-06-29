# 8.3. OWASP Mobile Top 10

OWASP Mobile Security Project публікує окремий «Топ-10» для мобільних застосунків — на відміну від вебзастосунків, де вразливості виникають переважно на сервері, мобільні застосунки мають унікальні проблеми: дані зберігаються на пристрої, авторизація відбувається між клієнтом і сервером, а бінарний файл доступний для дизасемблювання всіх. Поточна версія — OWASP Mobile Application Security Verification Standard (MASVS) і Mobile Top 10 2024.

> 📖 Ключові терміни — у [глосарії модуля](00-glosariy.md).

## M1: Неправильне використання облікових даних (Improper Credential Usage)

Зберігання секретів у неналежному місці або їх передача незахищеним каналом.

**Типові помилки:**
```kotlin
// ❌ Android: пароль у SharedPreferences (не зашифровано)
val prefs = getSharedPreferences("app", Context.MODE_PRIVATE)
prefs.edit().putString("user_password", password).apply()
// SharedPreferences — звичайний XML файл, доступний при root або backup

// ❌ Hardcoded API key у коді
companion object {
    const val API_KEY = "sk_live_abc123..."  // у бінарнику, дизасемблюється легко
}

// ✅ Правильно: Android Keystore для чутливих даних
val keyStore = KeyStore.getInstance("AndroidKeyStore")
// або: EncryptedSharedPreferences (Jetpack Security)
val masterKey = MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
val encryptedPrefs = EncryptedSharedPreferences.create(context, "secure_prefs", masterKey, ...)
```

```swift
// ❌ iOS: паролі в UserDefaults
UserDefaults.standard.set(password, forKey: "user_password")

// ✅ iOS Keychain — захищено Secure Enclave
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "user_password",
    kSecValueData as String: password.data(using: .utf8)!,
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
]
SecItemAdd(query as CFDictionary, nil)
```

---

## M2: Недостатня безпека ланцюжка поставок (Inadequate Supply Chain Security)

Шкідливі компоненти або залежності можуть потрапити через сторонні SDK, npm-пакети або навіть заражені IDE.

**XcodeGhost (2015)** — розповсюджена неофіційна версія Xcode для китайських розробників (оригінал завантажувався повільно), що автоматично вбудовувала шкідливий код у всі зкомпільовані застосунки. 4 000+ застосунків у App Store, включаючи WeChat.

**Захист:**
```yaml
# Android: перевірка хешів залежностей у build.gradle
dependencies {
    implementation "com.example:library:1.0.0" {
        # Gradle Dependency Verification
    }
}
# gradle/verification-metadata.xml — hash для кожної залежності
```

```bash
# Регулярна перевірка залежностей
# Android: OWASP Dependency-Check
./dependency-check.sh --project MyApp --scan ./build

# iOS: Cocoapods
pod audit
```

---

## M3: Небезпечна автентифікація і авторизація (Insecure Authentication/Authorization)

**Client-side authorization** — перевірка прав відбувається на пристрої, а не на сервері:

```kotlin
// ❌ ВРАЗЛИВО: перевірка ролі на клієнті
if (userRole == "admin") {
    showAdminPanel()
    callAdminAPI()  // Сервер не перевіряє чи справді є права!
}

// ✅ Сервер завжди перевіряє авторизацію незалежно від клієнта
// API endpoint /admin/users перевіряє токен і роль у кожному запиті
```

**Biometric bypass** — деякі реалізації Touch ID / Face ID перевіряють лише факт успішної автентифікації локально, без криптографічного зв'язку з сервером. Зловмисник з root може підробити результат.

```swift
// ❌ ВРАЗЛИВО: локальна перевірка без cryptographic challenge
let context = LAContext()
context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, ...) { success, _ in
    if success { callAPI() }  // сервер не знає чи перевірка відбулась насправді
}

// ✅ Правильно: biometric захищає приватний ключ, що підписує challenge від сервера
let privateKey = try keychain.getKey("auth_private_key")  // захищений Touch ID
let signature = try privateKey.sign(serverChallenge)
// Сервер перевіряє підпис → знає що biometric успішно пройдено
```

---

## M4: Недостатня валідація вводу і виводу (Insufficient I/O Validation)

```kotlin
// ❌ WebView з JavaScript і довільним URL
webView.settings.javaScriptEnabled = true
webView.loadUrl(intentUrl)  // intentUrl з зовнішнього джерела → XSS або phishing

// ❌ SQL Injection у локальній SQLite БД
val cursor = db.rawQuery("SELECT * FROM users WHERE id = $userId", null)

// ✅ Параметризовані запити і валідація
val cursor = db.rawQuery("SELECT * FROM users WHERE id = ?", arrayOf(userId.toString()))

// ✅ WebView: whitelist для URL
webView.webViewClient = object : WebViewClient() {
    override fun shouldOverrideUrlLoading(view: WebView, url: String): Boolean {
        return !url.startsWith("https://allowed-domain.com")
    }
}
```

---

## M5: Небезпечна комунікація (Insecure Communication)

```kotlin
// ❌ HTTP замість HTTPS
val url = URL("http://api.example.com/login")

// ❌ Відключена перевірка сертифіката (certificate pinning bypass)
val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
})
// Це дозволяє MITM з будь-яким сертифікатом!

// ✅ Certificate Pinning (перевірка конкретного сертифіката)
// OkHttp:
val certificatePinner = CertificatePinner.Builder()
    .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    .build()
val client = OkHttpClient.Builder().certificatePinner(certificatePinner).build()
```

**Увага:** Certificate Pinning може зламати застосунок при ротації сертифіката, якщо не передбачено backup pin. Завжди пінуйте мінімум два сертифікати.

---

## M6: Неналежний контроль конфіденційності (Inadequate Privacy Controls)

**Надмірний збір даних:**
- Застосунок запитує доступ до контактів, хоча функціонально не потребує.
- Геолокація "Always" замість "While Using".
- Логи, що містять персональні дані.

**GDPR і ЗУ «Про захист персональних даних» для мобільних застосунків:**
- Privacy Notice при першому запуску.
- Явний opt-in для аналітики.
- Можливість видалити акаунт і дані.
- Мінімізація даних: збирати лише те, що необхідно.

---

## M7: Недостатня бінарна захисна оболонка (Insufficient Binary Protection)

APK і IPA файли можуть бути декомпільовані і реінжинірені. Зловмисники можуть:
- Витягти API keys, URLs, алгоритми.
- Модифікувати логіку і перепакувати (repackaged app).
- Провести reverse engineering бізнес-логіки.

**Засоби захисту:**
- **ProGuard / R8 (Android)** — обфускація коду.
- **DexGuard / iXGuard** — комерційне обфусцювання.
- **Root/Jailbreak detection** — блокувати запуск на скомпрометованих пристроях.
- **Anti-tampering** — перевірка підпису APK при запуску.
- **Runtime Application Self-Protection (RASP)** — захист під час виконання.

---

## M8–M10: Огляд

**M8: Неправильна конфігурація безпеки (Security Misconfiguration)**
- Debug-режим у production збірці.
- Зайві дозволи в `AndroidManifest.xml`.
- Відкриті backup (`android:allowBackup="true"`) → дані копіюються в незашифрованому вигляді.
- Firebase/Firestore без правил автентифікації (публічна БД).

**M9: Небезпечне зберігання даних (Insecure Data Storage)**
- Логи з чутливими даними.
- Дані у External Storage (доступні іншим застосункам).
- Незашифровані БД SQLite.
- Скриншоти кешуються (Recent Apps) з конфіденційним вмістом.

```kotlin
// Захист від Screenshots у Recent Apps
window.setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE)
```

**M10: Недостатня криптографія (Insufficient Cryptography)**
- Власна реалізація крипто (завжди помилка).
- Слабкі алгоритми (MD5, SHA1, DES, ECB).
- Ключі в коді або незахищеному сховищі.
- Відсутність перевірки цілісності зберігаємих даних.

---

## Зведена таблиця OWASP Mobile Top 10

| # | Вразливість | Ключовий захист |
|---|---|---|
| M1 | Improper Credential Usage | Android Keystore / iOS Keychain |
| M2 | Inadequate Supply Chain Security | Dependency verification, SBOM |
| M3 | Insecure Auth/Authorization | Server-side auth, cryptographic challenge |
| M4 | Insufficient I/O Validation | Input validation, parameterized queries |
| M5 | Insecure Communication | HTTPS + Certificate Pinning |
| M6 | Inadequate Privacy Controls | Data minimization, GDPR compliance |
| M7 | Insufficient Binary Protection | Obfuscation, anti-tampering, RASP |
| M8 | Security Misconfiguration | Secure defaults, remove debug flags |
| M9 | Insecure Data Storage | Encrypted storage, avoid External Storage |
| M10 | Insufficient Cryptography | Standard algorithms, Hardware-backed keys |

## Міні-вправа

Встановіть безкоштовний додаток **MobSF (Mobile Security Framework)** локально і проаналізуйте будь-який APK:

```bash
# Запуск MobSF через Docker
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# Відкрийте http://localhost:8000
# Завантажте APK будь-якого тестового застосунку
# Перегляньте звіт: Permissions, Hardcoded secrets, Security issues
```

## Джерела та додаткові матеріали

- OWASP MASVS (mas.owasp.org) — Mobile Application Security Verification Standard.
- OWASP Mobile Top 10 (owasp.org/www-project-mobile-top-10).
- OWASP MobSF (github.com/MobSF/Mobile-Security-Framework-MobSF).
- Android Security Best Practices (developer.android.com/training/articles/security-tips).

---

**Попередній розділ:** [8.2. Загрози мобільним пристроям](02-zahrozy-mobilnym-prystroyam.md)
**Далі:** [8.4. MDM, MAM і UEM](04-mdm-mam-uem.md)
**Назад до модуля:** [README модуля 08](README.md)

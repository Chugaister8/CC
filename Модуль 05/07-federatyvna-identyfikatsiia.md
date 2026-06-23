# 5.7. Федеративна ідентифікація і хмарний IAM

Двадцять років тому ідентифікація була простою: один каталог (Active Directory), одна мережа, один периметр. Сьогодні середня організація використовує 130+ SaaS-застосунків, хмарні ресурси в AWS/Azure/GCP, мобільних і віддалених співробітників. Традиційна модель «один каталог для всього» більше не існує — а разом з нею зникла можливість управляти доступом з одного місця. Федеративна ідентифікація — відповідь на це розмаїття: спосіб зберегти єдину «джерело правди» про ідентичність, делегуючи автентифікацію до різних ресурсів без дублювання облікових записів.

> 📖 Ключові терміни — у [глосарії модуля](00-glosariy.md).

## Федерація ідентифікацій: концепція

**Federated Identity** — угода між доменами про взаємне довіряння результатам автентифікації. Ваша корпоративна ідентичність в Azure AD може бути «федерована» з AWS, Salesforce, GitHub — і ви входите в усі ці сервіси через корпоративний акаунт без окремих паролів.

Федерація базується на протоколах:
- **SAML 2.0** — для enterprise B2B SSO (детально — розділ 5.4).
- **OIDC/OAuth 2.0** — для сучасних застосунків і consumer SSO.
- **WS-Federation** — Microsoft-специфічний, поступово замінюється SAML/OIDC.

## Azure Active Directory / Microsoft Entra ID

**Microsoft Entra ID** (раніше Azure Active Directory) — хмарна IAM-платформа Microsoft. Є де-факто стандартом для корпоративного IAM у Windows-середовищах.

**Ключові компоненти:**

| Компонент | Функція |
|---|---|
| **Entra ID (Azure AD)** | Хмарний каталог, SSO, MFA, Conditional Access |
| **Hybrid Join** | Синхронізація on-premises AD з хмарою (Azure AD Connect) |
| **B2B Collaboration** | Зовнішні партнери з власними IdP |
| **B2C** | Автентифікація клієнтів через social IdP або власний |
| **PIM** | Privileged Identity Management (JIT-доступ) |
| **Identity Protection** | Ризик-скоринг аномальної поведінки |
| **Conditional Access** | Доступ на основі умов (риску, пристрою, локації) |

**Conditional Access** — один з найпотужніших інструментів Microsoft Entra ID. Дозволяє задати правила:

```
IF user.role == "Finance"
   AND device.compliance == "Non-compliant"
   AND location NOT IN ["office_ip_range"]
THEN REQUIRE MFA AND BLOCK high-risk actions
```

**Типові Conditional Access Policies:**
- Вимагати MFA для всіх адміністраторів.
- Блокувати вхід з країн, де організація не має офісів.
- Вимагати Compliant Device для доступу до HR-систем.
- Блокувати Legacy Authentication (Basic Auth — без MFA).

## AWS IAM

**AWS IAM (Identity and Access Management)** — система контролю доступу до ресурсів AWS. Принципово відрізняється від AD тим, що «ресурси» — це хмарні сервіси (S3, EC2, Lambda, RDS), а не комп'ютери, і кожен ресурс має власну модель прав.

**Ключові концепції AWS IAM:**
- **User** — людський або технічний ідентифікатор з довгостроковими credentials. Для сервісів — **Role** (тимчасові credentials, що автоматично ротуються) завжди краща.
- **Policy** — JSON-документ з правилами Allow/Deny для конкретних `Action` на конкретних `Resource`.
- **Permission Boundary** — жорстка стеля дозволів: навіть якщо policy дає ширші права, boundary їх обрізає.

**Найважливіші best practices AWS IAM (CIS AWS Benchmark):**
- Не використовувати root account; увімкнути MFA для root негайно після створення акаунту.
- Для EC2/Lambda/ECS — IAM Roles (не access keys, що можуть витекти через код або логи).
- Мінімальні policy: уникати `"Action": "*"` і `"Resource": "*"` — навіть «тимчасово для тестування».
- Регулярний аудит через **AWS IAM Access Analyzer** і **AWS Security Hub**.
- **AWS SCPs (Service Control Policies)** в Organizations — максимально допустимі права для всього акаунту.

> Детальні приклади JSON policies та практична робота з AWS CLI — у спеціалізованій лабораторній по AWS. Тут зосереджуємось на концептуальній моделі: ключова відмінність від AD у тому, що в AWS кожен ресурс захищається незалежно, а не «хто всередині мережі — той довірений».

## Google Cloud IAM

**GCP IAM** використовує схожу на AWS концепцію, але з деякими відмінностями:

- **Members** — google accounts, service accounts, groups, domains.
- **Roles** — набори permissions; Basic (Owner/Editor/Viewer), Predefined, Custom.
- **Bindings** — прив'язка member до role на рівні resource.

**Workload Identity Federation** — дозволяє сервісам поза GCP (GitHub Actions, AWS Lambda) отримувати GCP-доступ без статичних service account keys.

## Identity Providers (IdP): Okta, Ping, Keycloak

**Okta** — провідний незалежний IdP, що підтримує федерацію з будь-яким SAML/OIDC-застосунком і Directory синхронізацію з AD/LDAP.

**Keycloak** — open-source IAM/SSO (Red Hat), self-hosted альтернатива Okta. Підтримує OIDC, SAML, LDAP, Social Login.

```
Типова архітектура:
Corp AD (on-prem) ──sync──→ Azure AD / Okta (IdP)
                                     │
              ┌──────────────────────┼──────────────────┐
              ↓                      ↓                   ↓
          Salesforce              GitHub              AWS (via SAML)
          (SAML SSO)            (OIDC SSO)           (AWS SSO)
```

## SCIM: Автоматичний провізіонинг

**SCIM 2.0 (System for Cross-domain Identity Management)** — REST API стандарт для автоматичного провізіонингу і депровізіонингу користувачів між IdP і застосунками.

При звільненні співробітника:
1. HR-система оновлює статус у каталозі.
2. Azure AD / Okta через SCIM надсилає запит до Salesforce, GitHub, Slack тощо.
3. Акаунт деактивується в усіх сервісах автоматично — протягом хвилин.

Без SCIM цей процес виконується вручну IT-службою — і нерідко забувається.

## Хмарний IAM і українські реалії

**CERT-UA 2022-2024** зафіксував численні атаки, де зловмисники використовували скомпрометовані хмарні облікові записи Microsoft 365 і Google Workspace:

- Фішинг корпоративних акаунтів Microsoft 365 → читання пошти і документів.
- OAuth-застосунки з надмірними правами, авторизовані співробітниками → persistent access навіть після зміни пароля.
- Відсутність MFA → тривіальний доступ після credential stuffing.

**Практичні рекомендації для українських організацій:**
- Microsoft 365: увімкнути Security Defaults або Conditional Access + MFA.
- Google Workspace: увімкнути 2-Step Verification для всіх, обмежити третіх сторін у OAuth Apps.
- Регулярно переглядати авторизовані OAuth-застосунки (`myapps.microsoft.com`, `myaccount.google.com/permissions`).

## Міні-вправа

**Для Microsoft 365 / Entra ID:**
Зайдіть на `myapps.microsoft.com` → перегляньте список підключених застосунків. Чи є серед них незнайомі або ті, яким ви не пам'ятаєте надавали доступ? Перевірте права кожного і відкличте зайві.

**Для Google Workspace:**
Зайдіть на `myaccount.google.com/permissions`. Який доступ мають підключені застосунки? Чи є там застосунки з правом `View and manage your Google Drive files`? Чи потрібен їм цей рівень доступу?

**Для AWS (якщо маєте акаунт):**
```bash
# Переглянути всі IAM users
aws iam list-users --output table

# Знайти users без MFA
aws iam get-account-summary
aws iam list-virtual-mfa-devices --assignment-status Unassigned

# Знайти policies з надмірними правами
aws iam list-attached-user-policies --user-name your-username
```

## Джерела та додаткові матеріали

- Microsoft Docs, *What is Microsoft Entra ID?*
- AWS Docs, *IAM Best Practices* (docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html).
- Okta documentation (developer.okta.com).
- Keycloak documentation (keycloak.org/documentation).
- SCIM 2.0, RFC 7642–7644.

---

**Попередній розділ:** [5.6. Привілейований доступ: PAM і JIT](06-pam-pryvileiovanyy-dostup.md)
**Далі:** [5.8. Zero Trust у корпоративному середовищі](08-zero-trust.md)
**Назад до модуля:** [README модуля 05](README.md)

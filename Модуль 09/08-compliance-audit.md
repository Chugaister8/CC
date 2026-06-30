# 9.8. Відповідність і аудит у хмарі

Хмарний провайдер може мати сертифікацію SOC 2 Type II, ISO 27001 і десяток інших стандартів — але це не означає, що ваш застосунок, розгорнутий у цій хмарі, автоматично відповідає тим самим вимогам. Сертифікація провайдера підтверджує безпеку інфраструктури (нижні рівні Shared Responsibility Model); ваша відповідність залежить від того, як ви використовуєте цю інфраструктуру. Це джерело постійної плутанини: «ми в AWS, отже ми SOC 2 compliant» — поширена, але невірна теза.

> 📖 Ключові терміни — у [глосарії модуля](00-glosariy.md).

## Ключові стандарти відповідності для хмари

### SOC 2 (Service Organization Control 2)

**SOC 2** — аудиторський стандарт AICPA для сервісних організацій, що зберігають дані клієнтів у хмарі. Особливо важливий для SaaS-компаній.

**П'ять Trust Service Criteria:**
1. **Security** — захист від несанкціонованого доступу (обов'язковий).
2. **Availability** — доступність системи відповідно до зобов'язань.
3. **Processing Integrity** — точність і повнота обробки даних.
4. **Confidentiality** — захист конфіденційної інформації.
5. **Privacy** — обробка персональних даних відповідно до заявленої політики.

**Type I vs Type II:**
- **Type I** — оцінка дизайну контролів на конкретну дату.
- **Type II** — оцінка ефективності контролів протягом періоду (6-12 місяців) — значно цінніший і складніший для отримання.

### ISO/IEC 27001

Міжнародний стандарт системи управління інформаційною безпекою (ISMS). Детально розглянуто в контексті документації у попередніх модулях; у хмарному контексті:

```
ISO 27001 Annex A controls, релевантні для хмари:
A.8 — Asset Management (інвентаризація хмарних ресурсів)
A.9 — Access Control (IAM-політики)
A.10 — Cryptography (KMS, шифрування)
A.12 — Operations Security (логування, моніторинг)
A.13 — Communications Security (мережева безпека)
A.15 — Supplier Relationships (хмарний провайдер як постачальник)
```

### GDPR у хмарному контексті

```
Ключові вимоги GDPR для хмарних впроваджень:

Art. 28 — Processor obligations:
  Хмарний провайдер = Data Processor
  Ваша компанія = Data Controller
  Потрібна Data Processing Agreement (DPA) з провайдером

Art. 32 — Security of processing:
  "Належні технічні і організаційні заходи" —
  шифрування, псевдонімізація, регулярне тестування

Art. 33 — Breach notification:
  72 години на повідомлення наглядового органу

Art. 44-49 — Transfers to third countries:
  Передача даних поза ЄС потребує адекватного захисту
  (Standard Contractual Clauses, Adequacy Decision)
```

**Практичний наслідок Schrems II (2020):** передача персональних даних ЄС-громадян у США через хмарні сервіси опинилась під юридичним сумнівом. AWS, Azure, GCP запровадили EU-специфічні регіони і Sovereign Cloud рішення у відповідь.

### PCI DSS у хмарі

Для будь-якої організації, що обробляє дані платіжних карток:

```
Shared Responsibility для PCI DSS:
├── IaaS: майже вся відповідальність на клієнті
├── PaaS: розділена (платформа vs застосунок)
└── SaaS: здебільшого на провайдері (якщо повністю PCI-compliant SaaS)

Requirement 1: Firewall конфігурація — Security Groups, NACLs
Requirement 3: Захист збережених даних карток — токенізація, шифрування
Requirement 10: Логування і моніторинг доступу до даних карток
```

---

## CloudTrail / Activity Log: журналювання хмарних дій

**AWS CloudTrail** — записує кожен API-виклик в AWS акаунті.

```bash
# Увімкнути CloudTrail для всіх регіонів з валідацією цілісності логів
aws cloudtrail create-trail \
  --name organization-trail \
  --s3-bucket-name my-cloudtrail-logs \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --kms-key-id arn:aws:kms:eu-west-1:123456789012:key/...

aws cloudtrail start-logging --name organization-trail
```

**Структура CloudTrail запису:**
```json
{
  "eventTime": "2024-01-15T10:23:11Z",
  "eventName": "DeleteBucket",
  "eventSource": "s3.amazonaws.com",
  "userIdentity": {
    "type": "IAMUser",
    "userName": "alice",
    "arn": "arn:aws:iam::123456789012:user/alice"
  },
  "sourceIPAddress": "203.0.113.45",
  "requestParameters": {"bucketName": "production-backups"},
  "responseElements": null
}
```

**Виявлення підозрілої активності через CloudTrail Insights:**
```bash
# Увімкнути CloudTrail Insights (виявлення аномалій у API-активності)
aws cloudtrail put-insight-selectors \
  --trail-name organization-trail \
  --insight-selectors '[{"InsightType": "ApiCallRateInsight"}]'
```

**Azure Activity Log** — еквівалент для Azure:
```kql
// KQL: знайти всі видалення ресурсів за останню добу
AzureActivity
| where OperationNameValue endswith "delete"
| where TimeGenerated > ago(24h)
| project TimeGenerated, Caller, ResourceGroup, Resource, ActivityStatusValue
```

---

## Well-Architected Review

**AWS Well-Architected Framework Review** — структурований процес оцінки архітектури проти найкращих практик шести стовпів (Operational Excellence, Security, Reliability, Performance Efficiency, Cost Optimization, Sustainability).

```bash
# AWS Well-Architected Tool через CLI
aws wellarchitected create-workload \
  --workload-name "Production E-commerce" \
  --description "Main customer-facing application" \
  --environment PRODUCTION \
  --lenses "wellarchitected" \
  --review-owner "security-team@company.com"
```

**Security Pillar — ключові питання Review:**
- Як ви керуєте credentials і автентифікацією?
- Як ви виявляєте і реагуєте на інциденти безпеки?
- Як ви захищаєте дані at-rest і in-transit?
- Як ви захищаєте мережу і обчислювальні ресурси?

---

## Continuous Compliance Monitoring

Замість періодичного аудиту (раз на рік) — безперервний моніторинг через автоматизацію.

```python
# Псевдокод: автоматизована перевірка compliance перед щоденним звітом
import boto3
from datetime import datetime

COMPLIANCE_CHECKS = {
    'CIS-1.1': 'Root MFA enabled',
    'CIS-2.1': 'CloudTrail enabled all regions',
    'CIS-2.9': 'VPC Flow Logging enabled',
    'GDPR-32': 'Encryption at rest for PII data stores',
    'PCI-10.2': 'Audit logs for cardholder data access',
}

def daily_compliance_report():
    results = run_compliance_checks()  # Виконує AWS Config rules
    failed = [r for r in results if r['status'] == 'NON_COMPLIANT']

    if failed:
        send_alert_to_security_team(failed)

    generate_compliance_dashboard(results)
    log_to_audit_trail(datetime.utcnow(), results)
```

**AWS Audit Manager** — автоматизує збір доказів для аудитів (SOC 2, ISO 27001, PCI DSS, GDPR Frameworks вбудовані):

```bash
aws auditmanager create-assessment \
  --name "SOC2-Type2-2024" \
  --framework-id <soc2-framework-id> \
  --scope '{"awsAccounts": [{"id": "123456789012"}]}'
```

---

## Звітність для керівництва: executive summary

Технічний аудит compliance потребує перекладу на бізнес-мову для керівництва:

```
Executive Summary Template:

Поточний стан: 78% compliant з SOC 2 Type II контролями
Критичні прогалини: 3 (з 64 контролів)
  1. Encryption at-rest не увімкнено для 2 з 15 RDS instances
  2. MFA не обов'язковий для 12% привілейованих акаунтів
  3. Backup retention не відповідає політиці (30 днів замість 90)

Бізнес-вплив: Затримка SOC 2 сертифікації; ризик втрати enterprise клієнтів,
що вимагають SOC 2 як умову контракту.

Рекомендований план: 6 тижнів на усунення критичних прогалин
Бюджет: $15,000 (інструменти) + 120 людино-годин
```

## Міні-вправа

1. Знайдіть Data Processing Agreement (DPA) свого хмарного провайдера (AWS, Azure, GCP — публічно доступні).
2. Перегляньте, які регіони пропонує провайдер для зберігання даних ЄС/України.
3. Якщо маєте доступ до хмарного акаунту — перевірте чи увімкнено CloudTrail/Activity Log для всіх регіонів.

## Джерела та додаткові матеріали

- AICPA, *SOC 2 Trust Services Criteria*.
- ISO/IEC 27001:2022, Annex A.
- AWS Compliance Programs (aws.amazon.com/compliance/programs).
- GDPR.eu, *Cloud Computing and GDPR Compliance Guide*.
- AWS Well-Architected Framework (aws.amazon.com/architecture/well-architected).

---

**Попередній розділ:** [9.7. CSPM і CWPP](07-cspm-cwpp.md)
**Далі:** [9.9. Типові хмарні атаки](09-khmarne-ataky.md)
**Назад до модуля:** [README модуля 09](README.md)

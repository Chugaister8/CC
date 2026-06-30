# 9.9. Типові хмарні атаки

У 2019 році зловмисник отримав доступ до 100 мільйонів записів клієнтів Capital One через одну SSRF-вразливість у вебзастосунку, розгорнутому в AWS. Не через вразливість AWS — через те, що вебзастосунок дозволив зловмиснику примусити сервер виконати запит до AWS Instance Metadata Service і вкрасти тимчасові IAM-credentials. Ця атака стала підручниковим прикладом того, як хмарна архітектура створює нові вектори атак, що не існували в традиційних дата-центрах. Розуміння цих векторів — необхідна умова для захисту хмарної інфраструктури.

> 📖 Ключові терміни — у [глосарії модуля](00-glosariy.md).

## MITRE ATT&CK для хмари

MITRE підтримує спеціалізовану матрицю для хмарних платформ (`attack.mitre.org/matrices/enterprise/cloud`), що охоплює тактики, специфічні для AWS, Azure, GCP, SaaS, Office 365, Google Workspace.

**Ключові хмарні тактики ATT&CK:**

| Тактика | Хмаро-специфічні техніки |
|---|---|
| Initial Access | Valid Accounts (вкрадені credentials), Phishing (Cloud) |
| Persistence | Create Account, Modify Authentication Process (OAuth grant) |
| Privilege Escalation | Cloud Account Creation, Additional Cloud Roles |
| Defense Evasion | Disable Cloud Logs, Impair Cloud Defenses |
| Credential Access | Steal Application Access Token, Cloud Instance Metadata API |
| Discovery | Cloud Service Discovery, Cloud Storage Object Discovery |
| Collection | Data from Cloud Storage |
| Exfiltration | Transfer Data to Cloud Account |

---

## Credential Theft: викрадення хмарних облікових даних

### Спосіб 1: Жорстко закодовані ключі у коді/git

```bash
# Зловмисники активно сканують публічні GitHub-репозиторії на AWS ключі
# Pattern: AKIA[0-9A-Z]{16}

# GitGuardian, TruffleHog регулярно знаходять тисячі витоків:
git log --all -p | grep -E "AKIA[0-9A-Z]{16}"

# Реальний сценарій атаки:
# 1. Розробник випадково комітить .env з AWS_SECRET_ACCESS_KEY
# 2. Push до публічного GitHub репозиторію
# 3. Бот сканує GitHub Events API в реальному часі (секунди після push!)
# 4. Зловмисник отримує credentials і одразу запускає крипто-майнінг
#    на дорогих GPU-інстанціях (рахунок на десятки тисяч $ за ніч)
```

### Спосіб 2: Phishing для OAuth-токенів (Consent Phishing)

Детально розглянуто в модулі 05; у хмарному контексті — зловмисник отримує OAuth токен з широкими правами до Google Workspace/Microsoft 365 без знання пароля.

### Спосіб 3: Скомпрометовані CI/CD secrets

```yaml
# Якщо зловмисник отримав доступ до CI/CD конфігурації:
# Усі секрети пайплайну (Production AWS keys, deployment credentials) скомпрометовані

# Реальний кейс: Codecov supply chain attack (2021)
# Зловмисник модифікував Codecov Bash Uploader script
# Скрипт виконувався в тисячах CI/CD пайплайнів і ексфільтрував environment variables
# (включаючи AWS keys, GitHub tokens, database credentials)
```

---

## SSRF → Metadata Service: класична хмарна атака

**Instance Metadata Service (IMDS)** — внутрішній HTTP endpoint (169.254.169.254), доступний лише з інстанції, що надає тимчасові IAM credentials, user-data, конфігурацію.

```
Нормальне використання (з самої EC2 інстанції):
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/my-role

Атака через SSRF (Capital One сценарій):
1. Вебзастосунок має SSRF-вразливість (приймає URL від користувача)
2. Зловмисник надсилає: ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/my-role
3. Сервер (а не браузер зловмисника!) виконує запит до metadata service
4. Сервер повертає тимчасові AWS credentials назад зловмиснику
5. Зловмисник використовує ці credentials для доступу до S3, DynamoDB тощо
```

**IMDSv2: захист від цієї атаки**

```bash
# IMDSv1 (вразливий): простий GET-запит спрацьовує
curl http://169.254.169.254/latest/meta-data/

# IMDSv2 (захищений): потрібен PUT-запит для отримання токена СПОЧАТКУ
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/

# Проста SSRF (лише підстановка URL у GET) НЕ може виконати PUT-запит
# → IMDSv2 нейтралізує більшість SSRF-атак на metadata service!
```

```bash
# Примусове увімкнення IMDSv2 для всіх інстанцій (обов'язково!)
aws ec2 modify-instance-metadata-options \
  --instance-id i-1234567890abcdef0 \
  --http-tokens required \
  --http-endpoint enabled

# Перевірити які інстанції ще використовують вразливий IMDSv1
aws ec2 describe-instances \
  --query 'Reservations[*].Instances[?MetadataOptions.HttpTokens==`optional`].[InstanceId]'
```

---

## Privilege Escalation у хмарі

Хмарні платформи мають специфічні шляхи ескалації привілеїв через ланцюжки IAM-дозволів:

```
Приклад IAM Privilege Escalation Chain (AWS):

User має лише: iam:CreatePolicyVersion + iam:PassRole

Атака:
1. iam:CreatePolicyVersion дозволяє редагувати ІСНУЮЧУ policy
2. User модифікує policy, до якої прикріплена роль з ширшими правами
3. iam:PassRole дозволяє "передати" цю роль EC2/Lambda
4. Запускає Lambda з модифікованою роллю → отримує AdministratorAccess

# Інструмент для аналізу таких ланцюжків:
# PMapper (github.com/nccgroup/PMapper) — будує граф можливих ескалацій
pmapper graph create
pmapper analysis --output-type text
```

**Поширені IAM-дозволи, що дозволяють ескалацію:**
- `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion`
- `iam:CreateAccessKey` (для іншого user)
- `iam:AttachUserPolicy` / `iam:AttachRolePolicy`
- `iam:PassRole` + здатність запустити compute (EC2/Lambda)
- `sts:AssumeRole` для ролі з ширшими правами

---

## Bucket Exposure: публічні сховища даних

```python
# Автоматизоване сканування публічних S3 бакетів (для виявлення власних помилок)
import boto3
import requests

def check_bucket_public_access(bucket_name: str) -> dict:
    """Перевіряє чи доступний бакет публічно через HTTP."""
    url = f"https://{bucket_name}.s3.amazonaws.com/"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return {'bucket': bucket_name, 'status': 'PUBLIC', 'risk': 'CRITICAL'}
        elif response.status_code == 403:
            return {'bucket': bucket_name, 'status': 'EXISTS_PRIVATE', 'risk': 'LOW'}
        else:
            return {'bucket': bucket_name, 'status': 'NOT_FOUND', 'risk': 'NONE'}
    except requests.RequestException:
        return {'bucket': bucket_name, 'status': 'ERROR', 'risk': 'UNKNOWN'}

# Зловмисники використовують подібні скрипти для масового сканування bucket names
# (звідси важливість непередбачуваних назв і Block Public Access за замовчуванням)
```

**Реальні кейси публічних бакетів:**
- **Capital One (2019)** — 100 млн записів через SSRF + надмірні IAM права (не лише bucket, а й RDS snapshots).
- **Verizon (2017)** — 14 млн записів клієнтів через неправильно налаштований S3 бакет партнера.
- **Множинні українські компанії (2022-2024)** — менш публічні, але регулярно фіксовані CERT-UA випадки відкритих сховищ з персональними даними.

---

## Cryptojacking у хмарі

Зловмисник, що отримав хмарні credentials, часто використовує їх не для крадіжки даних, а для запуску криптомайнінгу за рахунок жертви:

```
Типовий сценарій:
1. AWS keys витекли через GitHub
2. За хвилини бот запускає десятки GPU-інстанцій (p3.16xlarge — $24/година кожна)
3. Встановлює XMRig або подібний майнер
4. За добу: рахунок $50,000+ до того як власник помітить

Захист:
- AWS Budgets з алертами при незвичних витратах
- Billing anomaly detection (AWS Cost Anomaly Detection)
- Service Control Policies, що обмежують типи інстанцій
- GuardDuty виявляє CryptoCurrency findings автоматично
```

```bash
# AWS Cost Anomaly Detection
aws ce create-anomaly-monitor \
  --anomaly-monitor '{
    "MonitorName": "ServiceMonitor",
    "MonitorType": "DIMENSIONAL",
    "MonitorDimension": "SERVICE"
  }'

aws ce create-anomaly-subscription \
  --anomaly-subscription '{
    "SubscriptionName": "BillingAlerts",
    "Threshold": 100,
    "Frequency": "IMMEDIATE",
    "MonitorArnList": ["arn:aws:ce::123456789012:anomalymonitor/..."],
    "Subscribers": [{"Type": "EMAIL", "Address": "security@company.com"}]
  }'
```

---

## Container Escape у хмарних Kubernetes

```
Сценарій атаки на managed Kubernetes (EKS/AKS/GKE):

1. Зловмисник компрометує застосунок у Pod (через RCE-вразливість коду)
2. Pod виконується з надмірними правами (privileged: true, hostPath mount)
3. Container Escape → доступ до хост-ноди
4. На хост-ноді — IAM роль ноди (часто з широкими правами для управління кластером)
5. Зловмисник використовує credentials хост-ноди для доступу до інших AWS-ресурсів
   поза Kubernetes взагалі

Захист:
- Pod Security Standards: restricted (заборона privileged, hostPath)
- IRSA (IAM Roles for Service Accounts) замість IAM на рівні ноди
- Network Policies для обмеження lateral movement
```

---

## Зведена таблиця хмарних атак і захисту

| Атака | Вектор | Ключовий захист |
|---|---|---|
| Credential leak | Git, CI/CD, hardcode | Secret scanning, Vault, short-lived credentials |
| SSRF → IMDS | Вразливий вебзастосунок | IMDSv2, валідація URL |
| Privilege Escalation | Ланцюжки IAM-дозволів | Permission Boundaries, regular audits, PMapper |
| Bucket Exposure | Неправильна конфігурація | Block Public Access за замовчуванням, CSPM |
| Cryptojacking | Вкрадені credentials | Billing alerts, GuardDuty, SCPs |
| Container Escape | Privileged containers | Pod Security Standards, IRSA |
| OAuth Consent Phishing | Соціальна інженерія | App consent policies, регулярний аудит дозволів |

## Міні-вправа

1. Перевірте чи всі ваші EC2-інстанції (якщо є) використовують IMDSv2 (`--http-tokens required`).
2. Знайдіть на GitHub публічний приклад "leaked AWS key incident" (звіт security дослідника) і простежте весь ланцюжок атаки.
3. Якщо маєте AWS акаунт — перевірте AWS Cost Anomaly Detection: чи увімкнено?

## Джерела та додаткові матеріали

- MITRE ATT&CK Cloud Matrix (attack.mitre.org/matrices/enterprise/cloud).
- Capital One Breach — офіційний звіт OCC (occ.gov).
- PMapper (github.com/nccgroup/PMapper) — AWS IAM privilege escalation analyzer.
- AWS, *Instance Metadata Service Version 2* (docs.aws.amazon.com).
- The Hacker News, *Codecov Supply Chain Attack* — аналіз інциденту.

---

**Попередній розділ:** [9.8. Відповідність і аудит](08-compliance-audit.md)
**Далі:** [9.10. Практична лабораторна на Python](10-praktychna-laboratorna.md)
**Назад до модуля:** [README модуля 09](README.md)

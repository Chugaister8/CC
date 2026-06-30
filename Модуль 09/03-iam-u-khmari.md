# 9.3. IAM у хмарі: Identity and Access Management

Більшість хмарних зламів починаються не з вразливостей ПЗ, а з компрометованих або надмірно широких хмарних облікових даних. Дослідження Palo Alto Networks показало: середній хмарний ресурс має IAM-права, що у 5–7 разів перевищують необхідний мінімум. Надмірний доступ — «тиха» вразливість: не генерує алертів, не видна в сканерах, але при компрометації відкриває весь хмарний акаунт. Принцип найменших привілеїв у хмарі — не рекомендація, а перша лінія оборони.

> 📖 Ключові терміни — у [глосарії модуля](00-glosariy.md).

## AWS IAM: глибокий розгляд

### Компоненти AWS IAM

```
IAM Model:
├── Users — людські або технічні ідентифікатори
├── Groups — логічні групи users
├── Roles — набори дозволів без постійних credentials
│   ├── EC2 Instance Role → EC2 може викликати AWS API без ключів
│   ├── Lambda Execution Role
│   └── Cross-Account Role → акаунт A може призначати role в акаунті B
├── Policies — JSON-документи з дозволами (Allow/Deny)
│   ├── AWS Managed — підтримуються AWS (ReadOnlyAccess, AdministratorAccess)
│   ├── Customer Managed — ваші власні
│   └── Inline — вбудовані у конкретний User/Group/Role
└── Permission Boundaries — максимально допустимі дозволи
```

### Структура IAM Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowS3ReadSpecificBucket",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-company-data",
        "arn:aws:s3:::my-company-data/*"
      ],
      "Condition": {
        "StringEquals": {
          "aws:RequestedRegion": "eu-west-1"
        },
        "IpAddress": {
          "aws:SourceIp": ["203.0.113.0/24"]
        }
      }
    },
    {
      "Sid": "DenyDeleteEverywhere",
      "Effect": "Deny",
      "Action": [
        "s3:DeleteObject",
        "s3:DeleteBucket"
      ],
      "Resource": "*"
    }
  ]
}
```

**Ключові принципи AWS IAM:**

```bash
# ❌ НЕБЕЗПЕЧНО: надмірно широкі права (зустрічається в DevOps)
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}

# ✅ Мінімально необхідні для Lambda, що читає S3
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": "arn:aws:s3:::specific-bucket/*"
}
```

### IAM Best Practices

```bash
# 1. Ніколи не використовувати root account для щоденних операцій
# Перевірити чи є MFA на root:
aws iam get-account-summary | grep "AccountMFAEnabled"

# 2. Для EC2/Lambda використовувати IAM Roles (не access keys)
# EC2 автоматично отримує credentials через IMDS:
# curl http://169.254.169.254/latest/meta-data/iam/security-credentials/my-role

# 3. Аудит невикористаних credentials
aws iam get-credential-report
aws iam generate-credential-report

# 4. Знайти занадто широкі policies
aws iam list-policies --scope Local --only-attached \
  --query 'Policies[*].[PolicyName,DefaultVersionId]'

# 5. Access Analyzer — виявляє зовнішній доступ до ресурсів
aws accessanalyzer list-findings --analyzer-name my-analyzer
```

---

## Azure RBAC: Role-Based Access Control

Azure використовує більш ієрархічну модель ніж AWS.

**Ієрархія ресурсів Azure:**
```
Management Group
    └── Subscription
            └── Resource Group
                    └── Resource (VM, Storage Account, etc.)
```

RBAC-призначення робляться на будь-якому рівні ієрархії і успадковуються вниз.

**Вбудовані ролі Azure:**

| Роль | Рівень доступу |
|---|---|
| Owner | Повний доступ + управління правами |
| Contributor | Повний доступ до ресурсів, без управління правами |
| Reader | Лише читання |
| User Access Administrator | Управління правами без доступу до ресурсів |
| Virtual Machine Contributor | Управління VM без доступу до мережі і сховища |

```powershell
# PowerShell: перегляд призначень ролей у Subscription
Get-AzRoleAssignment | Where-Object {$_.RoleDefinitionName -eq "Owner"} |
    Select-Object DisplayName, SignInName, RoleDefinitionName, Scope

# Призначити роль Reader для конкретної Resource Group
New-AzRoleAssignment -ObjectId "user-object-id" `
    -RoleDefinitionName "Reader" `
    -ResourceGroupName "my-resource-group"
```

**Azure Managed Identities** — аналог AWS IAM Roles для Azure ресурсів:
```python
# Python: Azure SDK з Managed Identity (без hardcoded credentials)
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient

# DefaultAzureCredential автоматично використовує Managed Identity в Azure
credential = DefaultAzureCredential()
blob_service = BlobServiceClient(account_url="https://mystorage.blob.core.windows.net",
                                  credential=credential)
```

---

## Google Cloud IAM

GCP IAM відрізняється тим, що використовує **позитивну модель** (тільки Allow, немає Deny) і **Bindings** (прив'язка Principal до Role на рівні Resource).

```yaml
# GCP IAM Policy (binding формат)
bindings:
  - role: roles/storage.objectViewer
    members:
      - user:alice@example.com
      - serviceAccount:my-sa@my-project.iam.gserviceaccount.com
  - role: roles/storage.objectCreator
    members:
      - serviceAccount:upload-sa@my-project.iam.gserviceaccount.com
```

**Workload Identity Federation (GCP)** — дозволяє зовнішнім сервісам (GitHub Actions, AWS Lambda) отримувати GCP-доступ без статичних service account keys:

```yaml
# GitHub Actions: авторизація у GCP без ключів через Workload Identity
- name: Authenticate to Google Cloud
  uses: google-github-actions/auth@v1
  with:
    workload_identity_provider: 'projects/123/locations/global/workloadIdentityPools/...'
    service_account: 'deploy@my-project.iam.gserviceaccount.com'
```

---

## Secrets Management: де НЕ зберігати credentials

```python
# ❌ ЗАБОРОНЕНО: credentials у коді
AWS_ACCESS_KEY = "AKIA..."
DB_PASSWORD = "mypassword123"

# ❌ ЗАБОРОНЕНО: у змінних середовища без шифрування
# (змінні середовища видимі в CloudWatch Logs!)
os.environ['DB_PASSWORD']  # якщо значення встановлено через консоль без SecureString

# ✅ AWS Secrets Manager
import boto3, json
def get_db_credentials():
    client = boto3.client('secretsmanager', region_name='eu-west-1')
    secret = client.get_secret_value(SecretId='prod/myapp/db')
    return json.loads(secret['SecretString'])

# ✅ AWS SSM Parameter Store (SecureString — KMS-encrypted)
def get_parameter(name: str) -> str:
    ssm = boto3.client('ssm', region_name='eu-west-1')
    return ssm.get_parameter(Name=name, WithDecryption=True)['Parameter']['Value']

# ✅ HashiCorp Vault (multi-cloud)
import hvac
client = hvac.Client(url='https://vault.example.com', token=os.environ['VAULT_TOKEN'])
secret = client.secrets.kv.v2.read_secret_version(path='myapp/db')
```

---

## Cross-Account Access і Permission Boundaries

**Cross-Account Role** дозволяє ресурсам одного AWS акаунту отримати доступ до ресурсів іншого:

```json
// Trust Policy (хто може assume цю роль):
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::111111111111:root"  // Акаунт А може assume
    },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {
        "sts:ExternalId": "unique-external-id"  // Захист від confused deputy
      }
    }
  }]
}
```

**Permission Boundary** — стеля дозволів: навіть якщо policy надає більше, boundary обрізає:

```
User має: S3FullAccess + EC2FullAccess
Permission Boundary: S3ReadOnly

Результат: User може лише читати S3 (boundary переважає)
```

---

## IAM Access Analyzer і IAM Advisor

**AWS IAM Access Analyzer** — автоматично виявляє ресурси, доступні зовні акаунту:

```bash
# Створити Analyzer і переглянути findings
aws accessanalyzer create-analyzer --analyzer-name account-analyzer --type ACCOUNT

aws accessanalyzer list-findings --analyzer-name account-analyzer \
  --query 'findings[?status==`ACTIVE`].[id,resourceType,condition]'
```

**IAM Access Advisor** — показує коли сервіс востаннє використовувався певним IAM ідентифікатором → допомагає видалити зайві дозволи.

## Міні-вправа

```bash
# Аудит IAM у власному AWS акаунті (Free Tier):

# 1. Перевірити root MFA
aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'

# 2. Знайти users з доступом до консолі без MFA
aws iam list-users --query 'Users[*].UserName' --output text | \
  xargs -I {} sh -c 'mfa=$(aws iam list-mfa-devices --user-name {} --query "length(MFADevices)"); echo "{}: MFA=$mfa"'

# 3. Знайти access keys, що не використовувались >90 днів
aws iam get-credential-report && aws iam get-credential-report \
  --query 'Content' --output text | base64 -d | \
  awk -F',' 'NR>1 && $10!="N/A" && $10<strftime("%Y-%m-%d", systime()-90*86400) {print $1, $10}'
```

## Джерела та додаткові матеріали

- AWS IAM Best Practices (docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html).
- CIS AWS Foundations Benchmark, Section 1 — IAM.
- OWASP Cloud-Native Application Security Top 10.
- Microsoft, *Azure RBAC Best Practices* (docs.microsoft.com).

---

**Попередній розділ:** [9.2. Хмарна мережева безпека](02-merezheva-bezpeka.md)
**Далі:** [9.4. Безпека даних у хмарі](04-bezpeka-danykh.md)
**Назад до модуля:** [README модуля 09](README.md)

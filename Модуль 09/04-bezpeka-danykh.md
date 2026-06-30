# 9.4. Безпека даних у хмарі

Відкритий S3-бакет — можливо найпоширеніша хмарна вразливість за весь час існування публічних хмар. Від Capital One (2019, 100 мільйонів клієнтів) до десятків українських компаній: публічно доступне сховище даних, що мало бути приватним. AWS за замовчуванням блокує публічний доступ до S3 з 2018 року — але старі бакети, налаштовані до цього, і явно увімкнений публічний доступ залишаються проблемою. Захист даних у хмарі потребує трьох елементів: класифікувати що є чутливим, правильно зашифрувати і правильно обмежити доступ.

> 📖 Ключові терміни — у [глосарії модуля](00-glosariy.md).

## Шифрування at-rest і in-transit

**At-rest (у стані спокою):**

| AWS Сервіс | Шифрування за замовчуванням | Варіанти |
|---|---|---|
| S3 | SSE-S3 (AES-256, ключ AWS) | SSE-S3, SSE-KMS, SSE-C (клієнтський ключ) |
| EBS (диски EC2) | Опціонально | AES-256 через KMS |
| RDS | Опціонально (увімкнути при створенні!) | AES-256 через KMS |
| DynamoDB | AES-256 за замовчуванням | KMS або AWS-owned key |
| EFS | Опціонально | KMS |

**Критична проблема RDS:** шифрування не можна увімкнути на існуючому незашифрованому екземплярі — лише при створенні або через snapshot і відновлення. Тому `encrypt = true` має бути стандартом у Terraform/IaC.

```hcl
# Terraform: RDS з обов'язковим шифруванням
resource "aws_db_instance" "main" {
  identifier          = "production-db"
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  allocated_storage   = 20

  storage_encrypted   = true          # ← обов'язково!
  kms_key_id          = aws_kms_key.rds.arn

  deletion_protection = true          # ← захист від випадкового видалення
  multi_az            = true          # ← HA

  backup_retention_period = 7
}
```

**In-transit (у русі):**
- TLS 1.2+ для всіх API-викликів до хмарних сервісів (AWS SDK, Azure SDK використовують TLS за замовчуванням).
- Для баз даних: SSL-з'єднання (`sslmode=verify-full` для PostgreSQL).
- Між мікросервісами: mTLS (mutual TLS) або Service Mesh (Istio, Linkerd).

---

## KMS: Key Management Service

**KMS** — керований сервіс управління криптографічними ключами. Ключі ніколи не покидають KMS у відкритому вигляді — лише операції виконуються всередині.

**Типи KMS ключів (AWS):**
- **AWS Managed Key** — автоматично ротується щорічно; ви не контролюєте.
- **Customer Managed Key (CMK)** — ви контролюєте rotation, policy, deletion; можна відкликати доступ.
- **AWS CloudHSM** — апаратний модуль безпеки у вашому виключному користуванні; для регуляторних вимог.

```python
# Python: шифрування через AWS KMS
import boto3, base64

kms = boto3.client('kms', region_name='eu-west-1')
KEY_ID = 'arn:aws:kms:eu-west-1:123456789012:key/...'

# Encrypt
plaintext = b"My sensitive data"
ciphertext = kms.encrypt(KeyId=KEY_ID, Plaintext=plaintext)['CiphertextBlob']
print(f"Encrypted: {base64.b64encode(ciphertext).decode()}")

# Decrypt (KMS перевіряє IAM права перед розшифруванням)
decrypted = kms.decrypt(CiphertextBlob=ciphertext)['Plaintext']
print(f"Decrypted: {decrypted.decode()}")

# Envelope Encryption (для великих даних)
# 1. KMS генерує Data Encryption Key (DEK)
dek_response = kms.generate_data_key(KeyId=KEY_ID, KeySpec='AES_256')
dek_plaintext = dek_response['Plaintext']      # використати для шифрування даних
dek_encrypted = dek_response['CiphertextBlob'] # зберегти поруч з даними
# 2. Дані шифруються DEK (локально, швидко)
# 3. DEK зберігається в зашифрованому вигляді (encrypted DEK)
# 4. При розшифруванні: спочатку KMS розшифровує DEK, потім DEK розшифровує дані
```

**Key Rotation:**
```bash
# Увімкнути автоматичну щорічну ротацію ключа
aws kms enable-key-rotation --key-id <key-id>

# Перевірити статус ротації
aws kms get-key-rotation-status --key-id <key-id>
```

---

## S3 Security: найпоширеніша площа атак

**Amazon S3** — найчастіша ціль для неправильних конфігурацій.

**Чек-лист безпеки S3:**

```bash
# 1. Block Public Access (на рівні акаунту і бакету)
aws s3api put-public-access-block \
  --bucket my-bucket \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Перевірити налаштування
aws s3api get-public-access-block --bucket my-bucket

# 2. Bucket Policy: заборонити небезпечні дії
{
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::my-bucket/*",
      "Condition": {
        "Bool": {"aws:SecureTransport": "false"}  # Тільки HTTPS!
      }
    }
  ]
}

# 3. Увімкнути versioning (захист від ransomware)
aws s3api put-bucket-versioning \
  --bucket my-bucket \
  --versioning-configuration Status=Enabled

# 4. Увімкнути MFA Delete (критичні бакети)
aws s3api put-bucket-versioning \
  --bucket my-bucket \
  --versioning-configuration Status=Enabled,MFADelete=Enabled \
  --mfa "arn:aws:iam::123456789012:mfa/root-account-mfa-device 123456"

# 5. Object Lock (WORM — захист від видалення)
aws s3api put-object-lock-configuration \
  --bucket my-bucket \
  --object-lock-configuration \
    '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":365}}}'
```

**S3 Presigned URLs** — тимчасовий доступ до приватного об'єкта:

```python
import boto3
from datetime import timedelta

s3 = boto3.client('s3')

# Генерація presigned URL (діє 1 годину)
url = s3.generate_presigned_url(
    'get_object',
    Params={'Bucket': 'my-private-bucket', 'Key': 'sensitive-doc.pdf'},
    ExpiresIn=3600  # секунди
)
# URL містить підписаний токен — ділитись URL безпечно, він закінчиться через 1 годину
```

---

## Data Loss Prevention (DLP)

**DLP** — автоматичне виявлення і захист чутливих даних (PII, PCI, медичні дані) у хмарних сховищах.

**AWS Macie** — ML-сервіс для виявлення чутливих даних в S3:

```bash
# Запустити Macie і сканування S3
aws macie2 enable-macie
aws macie2 create-classification-job \
  --name "PII-Scan" \
  --job-type SCHEDULED \
  --schedule-frequency WEEKLY \
  --s3-job-definition '{"bucketDefinitions":[{"accountId":"123456789012","buckets":["my-bucket"]}]}'

# Переглянути findings (виявлені чутливі дані)
aws macie2 list-findings --query 'findingIds'
```

**Типи чутливих даних, що виявляє AWS Macie:**
- Номери кредитних карток (PCI).
- Номери соціального страхування (SSN, для США).
- Паспортні дані (для ЄС).
- Медичні ідентифікатори.
- AWS Access Keys у файлах.
- Email-адреси, телефони, IP-адреси.

---

## Data Residency і GDPR у хмарі

**Data Residency** — вимога зберігати дані громадян конкретної країни на серверах у тій самій країні або регіоні.

Для України і ЄС:
- **GDPR** вимагає або зберігати дані в ЄС, або забезпечити «адекватний» рівень захисту при передачі.
- AWS Regions: `eu-west-1` (Ірландія), `eu-central-1` (Франкфурт), `eu-west-3` (Париж) — відповідають GDPR.
- GCP: `europe-west1`, `europe-west3`, `europe-central2` (Польща — найближче до України).
- Azure: `North Europe` (Ірландія), `West Europe` (Нідерланди), `Germany West Central`.

```hcl
# Terraform: обмежити розгортання тільки ЄС-регіонами
variable "allowed_regions" {
  default = ["eu-west-1", "eu-central-1", "eu-west-3"]
}

resource "aws_s3_bucket" "data" {
  bucket = "my-gdpr-compliant-bucket"
  # provider регіон має бути в allowed_regions
}
```

---

## Міні-вправа

```python
# Перевірте всі S3 бакети на публічний доступ (власний AWS акаунт)
import boto3

def audit_s3_buckets():
    s3 = boto3.client('s3')
    s3control = boto3.client('s3control')

    # Перевірити account-level Block Public Access
    account_id = boto3.client('sts').get_caller_identity()['Account']
    try:
        config = s3control.get_public_access_block(AccountId=account_id)
        pac = config['PublicAccessBlockConfiguration']
        all_blocked = all([pac.get('BlockPublicAcls'), pac.get('IgnorePublicAcls'),
                          pac.get('BlockPublicPolicy'), pac.get('RestrictPublicBuckets')])
        print(f"Account-level Block Public Access: {'✅ ON' if all_blocked else '❌ OFF'}")
    except Exception as e:
        print(f"Account-level: {e}")

    # Перевірити кожен бакет
    for bucket in s3.list_buckets()['Buckets']:
        name = bucket['Name']
        try:
            bpac = s3.get_public_access_block(Bucket=name)['PublicAccessBlockConfiguration']
            blocked = all([bpac.get('BlockPublicAcls'), bpac.get('IgnorePublicAcls'),
                          bpac.get('BlockPublicPolicy'), bpac.get('RestrictPublicBuckets')])
            print(f"  {'✅' if blocked else '❌'} {name}")
        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            print(f"  ⚠️  {name}: Block Public Access не налаштовано")
        except Exception as e:
            print(f"  ❓ {name}: {e}")

audit_s3_buckets()
```

## Джерела та додаткові матеріали

- AWS, *S3 Security Best Practices* (docs.aws.amazon.com).
- AWS Macie documentation.
- NIST SP 800-111 — Storage Encryption for End User Devices.
- ENISA, *Cloud Security Guide* (enisa.europa.eu).

---

**Попередній розділ:** [9.3. IAM у хмарі](03-iam-u-khmari.md)
**Далі:** [9.5. Безпека контейнерів і Kubernetes](05-konteinery-kubernetes.md)
**Назад до модуля:** [README модуля 09](README.md)

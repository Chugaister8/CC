# 9.10. Практична лабораторна на Python

Чотири лабораторні для аудиту хмарної безпеки: комплексний AWS security auditor, перевірка публічного доступу S3, аналізатор надмірних IAM прав і парсер CloudTrail логів для виявлення підозрілої активності.

**Залежності:**
```bash
pip install boto3 requests
```

> Лабораторні потребують AWS credentials з мінімум ReadOnlyAccess для тестування на власному акаунті. Ніколи не використовуйте ці скрипти проти акаунтів без явного дозволу.

---

## Лабораторна 9.10.1: Комплексний AWS Security Auditor

```python
"""
aws_security_auditor.py — базовий аудит AWS акаунту проти CIS AWS Foundations Benchmark.
Потребує: aws configure (з ReadOnlyAccess правами мінімум).
"""
import boto3
from datetime import datetime, timezone
from dataclasses import dataclass, field
from botocore.exceptions import ClientError


@dataclass
class Finding:
    severity: str
    control: str
    resource: str
    description: str


class AWSSecurityAuditor:
    def __init__(self, region='us-east-1'):
        self.region = region
        self.findings: list[Finding] = []
        self.iam = boto3.client('iam')
        self.ec2 = boto3.client('ec2', region_name=region)
        self.s3 = boto3.client('s3')
        self.cloudtrail = boto3.client('cloudtrail', region_name=region)

    def add_finding(self, severity, control, resource, description):
        self.findings.append(Finding(severity, control, resource, description))

    # ─── IAM Checks ─────────────────────────────────────────────────────────

    def check_root_mfa(self):
        try:
            summary = self.iam.get_account_summary()['SummaryMap']
            if not summary.get('AccountMFAEnabled'):
                self.add_finding('CRITICAL', 'CIS-1.1', 'root',
                                 'Root account не має MFA')
        except ClientError as e:
            print(f"Помилка перевірки root MFA: {e}")

    def check_unused_credentials(self, days=90):
        try:
            response = self.iam.generate_credential_report()
            import time
            time.sleep(2)  # Дати час на генерацію
            report = self.iam.get_credential_report()
            import csv, io
            content = report['Content'].decode('utf-8')
            reader = csv.DictReader(io.StringIO(content))

            now = datetime.now(timezone.utc)
            for row in reader:
                last_used = row.get('password_last_used', 'N/A')
                if last_used not in ('N/A', 'no_information', None):
                    try:
                        last_used_dt = datetime.strptime(last_used[:19], '%Y-%m-%dT%H:%M:%S')
                        last_used_dt = last_used_dt.replace(tzinfo=timezone.utc)
                        days_inactive = (now - last_used_dt).days
                        if days_inactive > days:
                            self.add_finding('MEDIUM', 'CIS-1.3', row['user'],
                                            f'Не використовувався {days_inactive} днів')
                    except ValueError:
                        pass
        except ClientError as e:
            print(f"Помилка перевірки credentials: {e}")

    def check_overly_permissive_policies(self):
        try:
            policies = self.iam.list_policies(Scope='Local', OnlyAttached=True)['Policies']
            for policy in policies:
                version = self.iam.get_policy_version(
                    PolicyArn=policy['Arn'],
                    VersionId=policy['DefaultVersionId']
                )
                doc = version['PolicyVersion']['Document']
                statements = doc.get('Statement', [])
                if not isinstance(statements, list):
                    statements = [statements]
                for stmt in statements:
                    if stmt.get('Effect') == 'Allow':
                        action = stmt.get('Action', '')
                        resource = stmt.get('Resource', '')
                        if action == '*' and resource == '*':
                            self.add_finding('CRITICAL', 'IAM-WILDCARD', policy['PolicyName'],
                                            'Policy дозволяє Action:* на Resource:* (повний адмін)')
        except ClientError as e:
            print(f"Помилка перевірки policies: {e}")

    # ─── Network Checks ─────────────────────────────────────────────────────

    def check_open_security_groups(self):
        try:
            sgs = self.ec2.describe_security_groups()['SecurityGroups']
            risky_ports = {22: 'SSH', 3389: 'RDP', 3306: 'MySQL', 5432: 'PostgreSQL', 27017: 'MongoDB'}

            for sg in sgs:
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            from_port = rule.get('FromPort')
                            if from_port in risky_ports:
                                self.add_finding('CRITICAL', 'CIS-4.1', sg['GroupId'],
                                                f'{risky_ports[from_port]} (port {from_port}) '
                                                f'відкритий для 0.0.0.0/0')
        except ClientError as e:
            print(f"Помилка перевірки Security Groups: {e}")

    # ─── S3 Checks ──────────────────────────────────────────────────────────

    def check_s3_public_access(self):
        try:
            buckets = self.s3.list_buckets()['Buckets']
            for bucket in buckets:
                name = bucket['Name']
                try:
                    pab = self.s3.get_public_access_block(Bucket=name)
                    config = pab['PublicAccessBlockConfiguration']
                    if not all([config.get('BlockPublicAcls'), config.get('IgnorePublicAcls'),
                              config.get('BlockPublicPolicy'), config.get('RestrictPublicBuckets')]):
                        self.add_finding('HIGH', 'CIS-2.1.5', name,
                                        'Block Public Access не повністю увімкнено')
                except self.s3.exceptions.from_code('NoSuchPublicAccessBlockConfiguration'):
                    self.add_finding('CRITICAL', 'CIS-2.1.5', name,
                                    'Block Public Access взагалі не налаштовано')
                except ClientError:
                    pass

                try:
                    encryption = self.s3.get_bucket_encryption(Bucket=name)
                except ClientError as e:
                    if 'ServerSideEncryptionConfigurationNotFoundError' in str(e):
                        self.add_finding('MEDIUM', 'CIS-2.1.1', name,
                                        'Шифрування за замовчуванням не налаштовано')
        except ClientError as e:
            print(f"Помилка перевірки S3: {e}")

    # ─── CloudTrail Checks ──────────────────────────────────────────────────

    def check_cloudtrail_enabled(self):
        try:
            trails = self.cloudtrail.describe_trails()['trailList']
            if not trails:
                self.add_finding('CRITICAL', 'CIS-2.1', 'account',
                                'CloudTrail взагалі не налаштовано')
                return
            multi_region = any(t.get('IsMultiRegionTrail') for t in trails)
            if not multi_region:
                self.add_finding('HIGH', 'CIS-2.1', 'account',
                                'Жоден trail не покриває всі регіони')

            log_validation = any(t.get('LogFileValidationEnabled') for t in trails)
            if not log_validation:
                self.add_finding('MEDIUM', 'CIS-2.2', 'account',
                                'Log file validation не увімкнено')
        except ClientError as e:
            print(f"Помилка перевірки CloudTrail: {e}")

    # ─── Запуск всіх перевірок ──────────────────────────────────────────────

    def run_all_checks(self):
        print("Виконання перевірок...")
        self.check_root_mfa()
        self.check_unused_credentials()
        self.check_overly_permissive_policies()
        self.check_open_security_groups()
        self.check_s3_public_access()
        self.check_cloudtrail_enabled()
        return self.findings

    def print_report(self):
        ICONS = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
        print(f"\n{'='*65}")
        print(f"AWS SECURITY AUDIT REPORT")
        print(f"{'='*65}")

        severity_count = {}
        for f in self.findings:
            severity_count[f.severity] = severity_count.get(f.severity, 0) + 1

        print(f"Всього знахідок: {len(self.findings)}")
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if sev in severity_count:
                print(f"  {ICONS[sev]} {sev}: {severity_count[sev]}")

        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            sev_findings = [f for f in self.findings if f.severity == sev]
            if sev_findings:
                print(f"\n{ICONS[sev]} {sev}:")
                for f in sev_findings:
                    print(f"  [{f.control}] {f.resource}: {f.description}")


if __name__ == "__main__":
    print("УВАГА: Цей скрипт перевіряє ВАШ AWS акаунт (потрібні credentials).")
    print("Переконайтесь, що ви маєте дозвіл на аудит цього акаунту.\n")

    auditor = AWSSecurityAuditor()
    auditor.run_all_checks()
    auditor.print_report()
```

---

## Лабораторна 9.10.2: S3 Bucket Public Access Checker

```python
"""
s3_public_checker.py — перевірка S3 бакетів на публічну доступність
без використання AWS credentials (через прямі HTTP запити).
Корисно для bug bounty / власного аудиту з зовнішньої точки зору.
"""
import requests
import concurrent.futures


def check_bucket(bucket_name: str) -> dict:
    """Перевіряє публічну доступність S3 бакету через пряму спробу читання."""
    result = {'bucket': bucket_name, 'status': 'UNKNOWN', 'details': ''}

    urls_to_try = [
        f"https://{bucket_name}.s3.amazonaws.com/",
        f"https://s3.amazonaws.com/{bucket_name}/",
    ]

    for url in urls_to_try:
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                result['status'] = 'PUBLIC_LISTABLE'
                result['details'] = 'Bucket дозволяє листинг вмісту (ListBucket)!'
                return result
            elif response.status_code == 403:
                if 'AccessDenied' in response.text:
                    result['status'] = 'EXISTS_PROTECTED'
                    result['details'] = 'Bucket існує, доступ заборонено (добре)'
                    return result
            elif response.status_code == 404:
                result['status'] = 'NOT_FOUND'
                result['details'] = 'Bucket не існує або інша назва'
        except requests.RequestException as e:
            result['details'] = str(e)

    return result


def generate_bucket_name_candidates(company_name: str) -> list[str]:
    """Генерує типові варіанти назв бакетів для перевірки (власна компанія!)."""
    base = company_name.lower().replace(' ', '-')
    suffixes = ['', '-backup', '-backups', '-data', '-prod', '-production',
                '-dev', '-staging', '-logs', '-assets', '-static', '-uploads',
                '-private', '-public', '-www', '-media', '-files', '-archive']
    return [f"{base}{suffix}" for suffix in suffixes]


def scan_bucket_candidates(company_name: str, max_workers: int = 10) -> list[dict]:
    """Сканує можливі назви бакетів для компанії (для власного аудиту!)."""
    candidates = generate_bucket_name_candidates(company_name)
    print(f"Перевірка {len(candidates)} можливих назв бакетів...")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_bucket, name): name for name in candidates}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result['status'] != 'NOT_FOUND':
                results.append(result)

    return results


def print_results(results: list[dict]) -> None:
    print(f"\n{'='*60}")
    print(f"S3 BUCKET EXPOSURE CHECK")
    print(f"{'='*60}")

    public = [r for r in results if r['status'] == 'PUBLIC_LISTABLE']
    protected = [r for r in results if r['status'] == 'EXISTS_PROTECTED']

    if public:
        print(f"\n🔴 КРИТИЧНО — публічно доступні бакети ({len(public)}):")
        for r in public:
            print(f"  {r['bucket']}: {r['details']}")

    if protected:
        print(f"\n✅ Існують, але захищені ({len(protected)}):")
        for r in protected:
            print(f"  {r['bucket']}")

    if not results:
        print("\nЖодних бакетів не знайдено за цими назвами.")


if __name__ == "__main__":
    # УВАГА: перевіряйте лише ВЛАСНІ компанії/бакети!
    company = "example-company"  # Замініть на свою компанію
    print(f"УВАГА: Перевіряйте лише власні ресурси!\n")

    results = scan_bucket_candidates(company)
    print_results(results)
```

---

## Лабораторна 9.10.3: IAM Permission Analyzer

```python
"""
iam_permission_analyzer.py — аналіз IAM policy на надмірні права
і потенційні шляхи ескалації привілеїв.
"""
import json
from dataclasses import dataclass


# Дії, що можуть призвести до ескалації привілеїв
ESCALATION_ACTIONS = {
    'iam:CreatePolicyVersion': 'Може модифікувати існуючі policy',
    'iam:SetDefaultPolicyVersion': 'Може активувати шкідливу версію policy',
    'iam:CreateAccessKey': 'Може створити ключі для іншого user',
    'iam:AttachUserPolicy': 'Може прикріпити адмін-policy до себе',
    'iam:AttachRolePolicy': 'Може прикріпити адмін-policy до ролі',
    'iam:PutUserPolicy': 'Може додати inline policy користувачу',
    'iam:PutRolePolicy': 'Може додати inline policy ролі',
    'iam:PassRole': 'Може передати роль сервісу (в комбінації з compute — небезпечно)',
    'sts:AssumeRole': 'Може приймати роль (перевірте які саме ролі)',
    'lambda:CreateFunction': 'В комбінації з PassRole — може запустити код з чужою роллю',
    'ec2:RunInstances': 'В комбінації з PassRole — може запустити інстанцію з чужою роллю',
}

WILDCARD_RISK_ACTIONS = {
    '*': 'CRITICAL: повний доступ до ВСІХ дій AWS',
    'iam:*': 'CRITICAL: повний контроль над IAM',
    's3:*': 'HIGH: повний контроль над усіма S3 бакетами',
    'ec2:*': 'HIGH: повний контроль над EC2',
}


@dataclass
class PolicyFinding:
    severity: str
    issue: str
    detail: str


def analyze_policy_document(policy_json: dict) -> list[PolicyFinding]:
    """Аналізує IAM Policy документ на потенційні проблеми."""
    findings = []
    statements = policy_json.get('Statement', [])
    if not isinstance(statements, list):
        statements = [statements]

    for stmt in statements:
        if stmt.get('Effect') != 'Allow':
            continue

        actions = stmt.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]

        resources = stmt.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]

        has_wildcard_resource = '*' in resources

        for action in actions:
            # Перевірка на wildcard дії
            if action in WILDCARD_RISK_ACTIONS:
                findings.append(PolicyFinding(
                    severity='CRITICAL' if action in ('*', 'iam:*') else 'HIGH',
                    issue=f'Widcard дія: {action}',
                    detail=WILDCARD_RISK_ACTIONS[action]
                ))

            # Перевірка на ескалаційні дії
            if action in ESCALATION_ACTIONS:
                severity = 'HIGH' if has_wildcard_resource else 'MEDIUM'
                findings.append(PolicyFinding(
                    severity=severity,
                    issue=f'Потенціал ескалації: {action}',
                    detail=ESCALATION_ACTIONS[action] +
                           (' (на Resource: *)' if has_wildcard_resource else '')
                ))

        # Перевірка на відсутність умов (Condition) для чутливих дій
        if not stmt.get('Condition') and has_wildcard_resource:
            sensitive_prefixes = ('iam:', 's3:Delete', 'ec2:Terminate', 'rds:Delete')
            if any(a.startswith(p) for a in actions for p in sensitive_prefixes):
                findings.append(PolicyFinding(
                    severity='MEDIUM',
                    issue='Відсутні умови (Condition) для чутливої дії',
                    detail='Розгляньте додавання IP-restriction або MFA-condition'
                ))

    return findings


def print_analysis(findings: list[PolicyFinding], policy_name: str = "Policy") -> None:
    ICONS = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
    print(f"\n{'='*55}")
    print(f"IAM POLICY ANALYSIS: {policy_name}")
    print(f"{'='*55}")

    if not findings:
        print("✅ Явних проблем не виявлено")
        return

    for f in sorted(findings, key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].index(x.severity)):
        icon = ICONS.get(f.severity, '?')
        print(f"\n  {icon} [{f.severity}] {f.issue}")
        print(f"     {f.detail}")


if __name__ == "__main__":
    # Приклад небезпечної policy для аналізу
    dangerous_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["iam:CreatePolicyVersion", "iam:PassRole", "lambda:CreateFunction"],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*"
            }
        ]
    }

    findings = analyze_policy_document(dangerous_policy)
    print_analysis(findings, "ExampleDangerousPolicy")
```

---

## Лабораторна 9.10.4: CloudTrail Log Parser

```python
"""
cloudtrail_parser.py — парсинг CloudTrail логів для виявлення підозрілої активності.
Приймає JSON-файл з CloudTrail записами (експортовані з S3 або CloudWatch).
"""
import json
from collections import defaultdict
from datetime import datetime


SUSPICIOUS_EVENTS = {
    'ConsoleLogin': 'Вхід в AWS Console',
    'CreateAccessKey': 'Створення нового access key',
    'DeleteTrail': 'Видалення CloudTrail (приховування слідів!)',
    'StopLogging': 'Зупинка CloudTrail логування (приховування слідів!)',
    'PutBucketPolicy': 'Зміна S3 bucket policy',
    'PutBucketAcl': 'Зміна S3 bucket ACL',
    'AuthorizeSecurityGroupIngress': 'Відкриття вхідного firewall-правила',
    'CreateUser': 'Створення нового IAM user',
    'AttachUserPolicy': 'Прикріплення policy до user',
    'DeleteFlowLogs': 'Видалення VPC Flow Logs (приховування слідів!)',
}

CRITICAL_EVENTS = {'DeleteTrail', 'StopLogging', 'DeleteFlowLogs'}


def parse_cloudtrail_log(log_data: list[dict]) -> dict:
    """Аналізує список CloudTrail записів."""
    analysis = {
        'total_events': len(log_data),
        'suspicious_events': [],
        'failed_logins': defaultdict(int),
        'actions_by_user': defaultdict(list),
        'unusual_regions': defaultdict(int),
    }

    for event in log_data:
        event_name = event.get('eventName', '')
        user = event.get('userIdentity', {}).get('userName',
               event.get('userIdentity', {}).get('arn', 'unknown'))
        source_ip = event.get('sourceIPAddress', 'unknown')
        event_time = event.get('eventTime', '')
        region = event.get('awsRegion', 'unknown')

        # Підозрілі події
        if event_name in SUSPICIOUS_EVENTS:
            severity = 'CRITICAL' if event_name in CRITICAL_EVENTS else 'INFO'
            analysis['suspicious_events'].append({
                'event': event_name,
                'description': SUSPICIOUS_EVENTS[event_name],
                'user': user,
                'source_ip': source_ip,
                'time': event_time,
                'severity': severity,
            })

        # Невдалі логіни
        if event_name == 'ConsoleLogin':
            response = event.get('responseElements', {})
            if response and response.get('ConsoleLogin') == 'Failure':
                analysis['failed_logins'][source_ip] += 1

        # Дії по користувачу
        analysis['actions_by_user'][user].append(event_name)

        # Нетипові регіони (налаштуйте під вашу організацію)
        EXPECTED_REGIONS = {'eu-west-1', 'eu-central-1'}
        if region != 'unknown' and region not in EXPECTED_REGIONS:
            analysis['unusual_regions'][region] += 1

    return analysis


def print_analysis_report(analysis: dict) -> None:
    print(f"\n{'='*60}")
    print(f"CLOUDTRAIL LOG ANALYSIS")
    print(f"{'='*60}")
    print(f"Всього подій: {analysis['total_events']}")

    if analysis['suspicious_events']:
        critical = [e for e in analysis['suspicious_events'] if e['severity'] == 'CRITICAL']
        if critical:
            print(f"\n🔴 КРИТИЧНІ події (потенційне приховування слідів):")
            for e in critical:
                print(f"  {e['time']} | {e['event']} | user={e['user']} | ip={e['source_ip']}")
                print(f"    → {e['description']}")

        info_events = [e for e in analysis['suspicious_events'] if e['severity'] == 'INFO']
        if info_events:
            print(f"\nℹ️  Інші помітні події ({len(info_events)}):")
            for e in info_events[:10]:
                print(f"  {e['time']} | {e['event']} | user={e['user']}")

    if analysis['failed_logins']:
        print(f"\n⚠️  Невдалі спроби входу за IP:")
        for ip, count in sorted(analysis['failed_logins'].items(), key=lambda x: -x[1]):
            flag = "🔴" if count >= 5 else "🟡"
            print(f"  {flag} {ip}: {count} невдалих спроб")

    if analysis['unusual_regions']:
        print(f"\n🟡 Активність у нетипових регіонах:")
        for region, count in analysis['unusual_regions'].items():
            print(f"  {region}: {count} подій")


# Тестові дані (імітація CloudTrail записів)
SAMPLE_LOG = [
    {
        "eventTime": "2024-01-15T03:23:11Z",
        "eventName": "StopLogging",
        "userIdentity": {"userName": "compromised-user", "arn": "arn:aws:iam::123:user/compromised-user"},
        "sourceIPAddress": "185.220.101.1",
        "awsRegion": "us-east-1"
    },
    {
        "eventTime": "2024-01-15T03:24:01Z",
        "eventName": "CreateUser",
        "userIdentity": {"userName": "compromised-user"},
        "sourceIPAddress": "185.220.101.1",
        "awsRegion": "us-east-1"
    },
    {
        "eventTime": "2024-01-15T03:24:15Z",
        "eventName": "AttachUserPolicy",
        "userIdentity": {"userName": "compromised-user"},
        "sourceIPAddress": "185.220.101.1",
        "awsRegion": "us-east-1"
    },
    {
        "eventTime": "2024-01-15T02:00:00Z",
        "eventName": "ConsoleLogin",
        "userIdentity": {"userName": "alice"},
        "sourceIPAddress": "203.0.113.5",
        "responseElements": {"ConsoleLogin": "Failure"},
        "awsRegion": "eu-west-1"
    },
] * 1 + [{
        "eventTime": f"2024-01-15T02:0{i}:00Z",
        "eventName": "ConsoleLogin",
        "userIdentity": {"userName": "alice"},
        "sourceIPAddress": "203.0.113.5",
        "responseElements": {"ConsoleLogin": "Failure"},
        "awsRegion": "eu-west-1"
    } for i in range(6)]


if __name__ == "__main__":
    analysis = parse_cloudtrail_log(SAMPLE_LOG)
    print_analysis_report(analysis)
```

## Джерела та додаткові матеріали

- boto3 documentation (boto3.amazonaws.com).
- AWS CloudTrail Event Reference (docs.aws.amazon.com).
- PMapper — IAM privilege escalation analysis (github.com/nccgroup/PMapper).
- ScoutSuite — multi-cloud security auditing tool (github.com/nccgroup/ScoutSuite).

---

**Попередній розділ:** [9.9. Типові хмарні атаки](09-khmarne-ataky.md)
**Далі:** [9.11. Чек-лист і самоперевірка](11-chek-lyst-i-samoperevirka.md)
**Назад до модуля:** [README модуля 09](README.md)

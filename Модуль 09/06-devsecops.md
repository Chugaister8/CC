# 9.6. DevSecOps і безпека CI/CD

«Shift Left» — одна з найважливіших ідей сучасної безпеки: чим раніше в життєвому циклі розробки виявлено проблему, тим дешевше її виправити. Вразливість, знайдена в IDE розробника, коштує копійки. Та сама вразливість, виявлена після релізу в продакшені — потенційно мільйони. DevSecOps інтегрує перевірки безпеки безпосередньо в CI/CD пайплайн, роблячи їх частиною звичайного робочого процесу, а не окремим етапом «перед релізом».

> 📖 Ключові терміни — у [глосарії модуля](00-glosariy.md).

## Shift Left: економіка раннього виявлення

```mermaid
graph LR
    A["IDE\n(розробка)\n$"] --> B["Code Review\n$$"]
    B --> C["CI Pipeline\n$$$"]
    C --> D["Staging\n$$$$"]
    D --> E["Production\n$$$$$$$$$$"]
```

**IBM Systems Sciences Institute:** вартість виправлення дефекту зростає експоненційно з кожним етапом — від виявлення в IDE до виявлення в продакшені різниця може сягати 100x.

---

## Security Gates у CI/CD пайплайні

```mermaid
graph TD
    COMMIT["Git Commit"] --> PRECOMMIT["Pre-commit hooks\n(secrets scan, lint)"]
    PRECOMMIT --> PR["Pull Request"]
    PR --> SAST["SAST\n(аналіз коду)"]
    SAST --> SCA["SCA\n(аналіз залежностей)"]
    SCA --> BUILD["Build"]
    BUILD --> IMGSCAN["Image Scan\n(Trivy/Grype)"]
    IMGSCAN --> SIGN["Sign Artifact\n(Cosign/Sigstore)"]
    SIGN --> DEPLOY_STG["Deploy to Staging"]
    DEPLOY_STG --> DAST["DAST\n(динамічне тестування)"]
    DAST --> APPROVAL["Manual Approval\n(production gate)"]
    APPROVAL --> DEPLOY_PROD["Deploy to Production"]

    SAST -.->|"FAIL: CRITICAL"| BLOCK1["🛑 Block merge"]
    SCA -.->|"FAIL: known CVE"| BLOCK2["🛑 Block build"]
    IMGSCAN -.->|"FAIL: CRITICAL CVE"| BLOCK3["🛑 Block deploy"]
```

---

## SAST: Static Application Security Testing

Аналіз вихідного коду без виконання, на ранньому етапі (Pull Request).

```yaml
# GitHub Actions: SAST через Semgrep
name: SAST Scan
on: [pull_request]

jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/secrets
            p/owasp-top-ten
        env:
          SEMGREP_RULES: "auto"
```

```bash
# Bandit (Python-специфічний SAST)
pip install bandit
bandit -r ./src -f json -o bandit-report.json -ll  # -ll = тільки MEDIUM+

# CodeQL (GitHub-нативний, найпотужніший)
# Автоматично через GitHub Advanced Security або github/codeql-action

# Snyk Code
snyk code test --severity-threshold=high
```

**Інструменти SAST за мовою:**

| Мова | Інструменти |
|---|---|
| Python | Bandit, Semgrep, Pylint security plugins |
| JavaScript/TypeScript | ESLint security plugin, Semgrep, SonarQube |
| Java | SpotBugs + Find Security Bugs, Checkmarx |
| Go | gosec, Staticcheck |
| Multi-language | Semgrep, CodeQL, SonarQube, Checkmarx |

---

## SCA: Software Composition Analysis

Перевірка залежностей на відомі вразливості (CVE).

```yaml
# GitHub Actions: SCA через Dependabot (вбудований, безкоштовний)
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10

  - package-ecosystem: "npm"
    directory: "/frontend"
    schedule:
      interval: "weekly"
```

```bash
# pip-audit (Python)
pip install pip-audit
pip-audit --desc --format json -o audit-report.json

# npm audit (Node.js)
npm audit --audit-level=high
npm audit fix

# OWASP Dependency-Check (Java, .NET, Python, Node, Ruby...)
dependency-check.sh --project "MyApp" --scan ./src --format JSON

# Snyk (multi-language, з базою даних вразливостей)
snyk test --severity-threshold=high
snyk monitor  # continuous monitoring after deploy
```

---

## Container Image Scanning у пайплайні

```yaml
# GitLab CI: Trivy для сканування образів перед push
stages:
  - build
  - scan
  - deploy

build:
  stage: build
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .

scan:
  stage: scan
  image: aquasec/trivy:latest
  script:
    - trivy image --exit-code 1 --severity CRITICAL,HIGH $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  allow_failure: false  # Блокує пайплайн при критичних вразливостях

deploy:
  stage: deploy
  script:
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  only:
    - main
  needs: ["scan"]  # Деплой лише якщо scan пройшов успішно
```

---

## Secrets Management у CI/CD

**Найпоширеніша помилка CI/CD:** хардкод секретів у конфіг-файлах пайплайну.

```yaml
# ❌ ВРАЗЛИВО: секрет у репозиторії
env:
  DB_PASSWORD: "mypassword123"  # видно в git history назавжди!

# ✅ GitHub Actions Secrets
env:
  DB_PASSWORD: ${{ secrets.DB_PASSWORD }}

# ✅ GitLab CI Variables (Protected + Masked)
# Settings → CI/CD → Variables → Protected (лише для protected branches)

# ✅ HashiCorp Vault integration
steps:
  - name: Import Secrets
    uses: hashicorp/vault-action@v2
    with:
      url: https://vault.example.com
      token: ${{ secrets.VAULT_TOKEN }}
      secrets: |
        secret/data/myapp db_password | DB_PASSWORD
```

**Секрет-сканування для запобігання витоку:**

```bash
# TruffleHog — пошук секретів у git history
trufflehog git file://. --json

# GitLeaks — швидкий сканер для CI/CD
gitleaks detect --source . --verbose

# Pre-commit hook (зупиняє коміт із секретом ДО потрапляння в git):
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
```

---

## Supply Chain Security: SBOM і підписання артефактів

**SLSA (Supply chain Levels for Software Artifacts)** — фреймворк рівнів довіри до supply chain:

| Рівень | Вимоги |
|---|---|
| SLSA 1 | Build process задокументований |
| SLSA 2 | Версіонований source control + build service |
| SLSA 3 | Hardened build platform, non-falsifiable provenance |
| SLSA 4 | Two-party review, hermetic, reproducible builds |

```yaml
# Генерація SBOM (Software Bill of Materials)
- name: Generate SBOM
  uses: anchore/sbom-action@v0
  with:
    image: ${{ env.IMAGE }}
    format: cyclonedx-json
    output-file: sbom.json

# Підписання артефакту через Sigstore/Cosign (keyless signing)
- name: Sign container image
  run: |
    cosign sign --yes ${{ env.IMAGE }}@${{ steps.build.outputs.digest }}

# Верифікація підпису при деплої
- name: Verify image signature
  run: |
    cosign verify --certificate-identity-regexp ".*" \
      --certificate-oidc-issuer-regexp ".*" \
      ${{ env.IMAGE }}
```

**Урок SolarWinds (2020) і XZ Utils (2024):** найкритичніша supply chain атака — компрометація самого build/release процесу, а не лише прямих залежностей. SLSA framework і підписання артефактів — пряма відповідь на ці інциденти.

---

## Infrastructure as Code (IaC) Security

```bash
# Checkov — сканування Terraform/CloudFormation/Kubernetes маніфестів
pip install checkov
checkov -d ./terraform --framework terraform

# Приклад знахідки:
# CKV_AWS_18: "Ensure the S3 bucket has access logging configured"
#   FAILED for resource: aws_s3_bucket.data
#   File: /main.tf:15-20

# tfsec — Terraform-специфічний сканер
tfsec ./terraform

# Інтеграція в CI:
- name: Checkov IaC Scan
  uses: bridgecrewio/checkov-action@master
  with:
    directory: terraform/
    framework: terraform
    soft_fail: false  # block pipeline on findings
```

---

## DevSecOps Maturity Model (спрощено)

| Рівень | Характеристика |
|---|---|
| 0 — Ad hoc | Security перевіряється вручну перед релізом (або не перевіряється) |
| 1 — Automated Basic | SAST/SCA в CI, але як інформаційний звіт |
| 2 — Gated | Security gates блокують merge/deploy при критичних знахідках |
| 3 — Shift Left | Pre-commit hooks, IDE-плагіни, навчання розробників |
| 4 — Continuous | Runtime protection, continuous monitoring, automated remediation |

## Міні-вправа

```bash
# Налаштуйте базовий security pipeline для тестового репозиторію:

# 1. Встановити pre-commit з gitleaks
pip install pre-commit
cat > .pre-commit-config.yaml << EOF
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
EOF
pre-commit install

# 2. Спробувати закомітити "секрет" і побачити блокування
echo 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"' > test.py
git add test.py
git commit -m "test"  # Має заблокувати!

# 3. Запустити Trivy на будь-якому Docker образі
docker pull nginx:latest
trivy image nginx:latest
```

## Джерела та додаткові матеріали

- OWASP DevSecOps Guideline (owasp.org/www-project-devsecops-guideline).
- SLSA Framework (slsa.dev).
- Sigstore/Cosign (sigstore.dev).
- NIST SP 800-218 — Secure Software Development Framework (SSDF).
- Checkov (checkov.io), Trivy (aquasecurity.github.io/trivy).

---

**Попередній розділ:** [9.5. Контейнери і Kubernetes](05-konteinery-kubernetes.md)
**Далі:** [9.7. CSPM і Cloud Workload Protection](07-cspm-cwpp.md)
**Назад до модуля:** [README модуля 09](README.md)

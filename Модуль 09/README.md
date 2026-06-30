# Модуль 09. Хмарна безпека

> Хмара змінила не лише де зберігаються дані — вона змінила саму модель відповідальності за безпеку. У традиційній моделі «у вас є сервер — ви відповідаєте за все». У хмарі відповідальність розділяється: провайдер захищає інфраструктуру, клієнт — все що «вище». Більшість хмарних інцидентів відбуваються не через вразливості провайдера, а через помилки конфігурації клієнта: відкритий S3-бакет, надмірно широкі IAM-права, незашифровані дані. За даними Gartner, до 2025 року 99% хмарних інцидентів безпеки будуть на совісті клієнта, а не провайдера.

## Цілі модуля

Після опрацювання модуля ви зможете:

- **Запам'ятати:** моделі IaaS/PaaS/SaaS і межі відповідальності; ключові сервіси безпеки AWS, Azure, GCP; компоненти DevSecOps пайплайну.
- **Зрозуміти:** пояснити Shared Responsibility Model; описати типові хмарні мисконфігурації і їх наслідки; пояснити різницю між CSPM і CWPP; описати атаку через SSRF на хмарний metadata endpoint.
- **Застосувати:** провести базовий аудит AWS/GCP акаунту; виявити відкриті S3-бакети; реалізувати хмарний CI/CD пайплайн із security gates; налаштувати базові alerting правила.

**Орієнтовна тривалість:** 10–12 годин.

---

## Структура модуля

| № | Розділ | Що розглядається |
|---|---|---|
| — | [Глосарій](00-glosariy.md) | Всі ключові терміни |
| 9.1 | [Хмарні моделі і Shared Responsibility](01-khmara-modeli.md) | IaaS/PaaS/SaaS, модель спільної відповідальності, типи хмар |
| 9.2 | [Хмарна мережева безпека](02-merezheva-bezpeka.md) | VPC, Security Groups, NACLs, WAF, DDoS захист, Private Link |
| 9.3 | [IAM у хмарі](03-iam-u-khmari.md) | AWS IAM, Azure RBAC, GCP IAM, принцип найменших привілеїв, Workload Identity |
| 9.4 | [Безпека даних у хмарі](04-bezpeka-danykh.md) | Шифрування at-rest і in-transit, KMS, DLP, S3/Blob misconfig |
| 9.5 | [Безпека контейнерів і Kubernetes](05-konteinery-kubernetes.md) | Docker security, Kubernetes RBAC, Pod Security, Network Policies, image scanning |
| 9.6 | [DevSecOps і безпека CI/CD](06-devsecops.md) | Shift Left, SAST/DAST/SCA у пайплайні, secrets management, supply chain |
| 9.7 | [CSPM і Cloud Workload Protection](07-cspm-cwpp.md) | Cloud Security Posture Management, CWPP, Cloud Detection & Response |
| 9.8 | [Відповідність і аудит у хмарі](08-compliance-audit.md) | SOC 2, ISO 27001, GDPR у хмарі, CloudTrail/Activity Log, Well-Architected |
| 9.9 | [Типові хмарні атаки](09-khmarne-ataky.md) | MITRE ATT&CK Cloud, credential theft, SSRF→metadata, bucket exposure, cryptojacking |
| 9.10 | [Практична лабораторна на Python](10-praktychna-laboratorna.md) | AWS/GCP security auditor, S3 bucket checker, IAM analyzer, CloudTrail parser |
| 9.11 | [Чек-лист і самоперевірка](11-chek-lyst-i-samoperevirka.md) | 40 питань з відповідями |

---

**Попередній модуль:** [Модуль 08. Безпека мобільних пристроїв та IoT](../08-mobilni-ta-iot/README.md)
**Наступний модуль:** Модуль 10. Мережева безпека (заплановано)

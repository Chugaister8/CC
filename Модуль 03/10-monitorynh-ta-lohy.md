# 3.10. Моніторинг і логи

Hardening — це профілактика. Логування і моніторинг — це здатність виявити, коли профілактика не спрацювала, або простежити, що саме відбулось після інциденту. Система без логів після інциденту нагадує місце злочину без свідків і камер: ви знаєте, що щось сталось, але не знаєте ні хто, ні як, ні коли. Грамотно налаштовані логи — це і детектор аномалій, і криміналістичний слід для розслідування.

> 📖 Ключові терміни — у [глосарії модуля](00-glosariy.md).

## Що таке «корисний» лог

Не всі логи однаково цінні. Корисний лог містить:

- **Час** (timestamp) з часовим поясом — бажано UTC для відсутності плутанини.
- **Джерело** — який процес/служба/хост згенерував подію.
- **Тип події** — що сталось.
- **Контекст** — хто (user/IP/PID), що (файл/ресурс), звідки (IP, hostname).
- **Результат** — успішно чи відмовлено.

## Windows Event Log

Windows централізовано зберігає всі системні події в **Event Log**, доступному через `eventvwr.msc`.

### Ключові журнали

| Журнал | Шлях | Що містить |
|---|---|---|
| **Security** | `Windows Logs\Security` | Автентифікація, авторизація, зміни облікових записів, аудит файлів |
| **System** | `Windows Logs\System` | Системні події, збої служб, помилки драйверів |
| **Application** | `Windows Logs\Application` | Події застосунків |
| **PowerShell/Operational** | `Applications and Services\Microsoft\Windows\PowerShell\Operational` | Виконання PowerShell-команд |
| **Sysmon** | `Applications and Services\Microsoft\Windows\Sysmon\Operational` | Детальні події процесів, мережі, файлів (потребує встановлення Sysmon) |

### Критично важливі Event ID для безпеки

| Event ID | Що означає | Чому важливий |
|---|---|---|
| **4624** | Успішний вхід | Хто і коли увійшов; аномалії часу і місця |
| **4625** | Невдалий вхід | Серія → брутфорс |
| **4634/4647** | Вихід із системи | Разом з 4624 — реконструкція сесій |
| **4648** | Вхід з явними обліковими даними | Pass-the-Hash, lateral movement |
| **4688** | Створення процесу | З Audit Process Creation: бачимо командний рядок |
| **4697** | Встановлення служби | Нова служба = підозра на persistence |
| **4698/4702** | Нова/змінена задача планувальника | Ще один механізм persistence |
| **4720/4726** | Створення/видалення облікового запису | Несанкціоновані зміни |
| **4732/4733** | Додавання/видалення з групи Administrators | Ескалація привілеїв |
| **4771** | Невдалий Kerberos pre-auth | Брутфорс в AD-середовищі |
| **7045** | Встановлено нову службу | Persistence або легітимне встановлення |

```powershell
# Пошук невдалих входів за останню добу
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
    StartTime = (Get-Date).AddDays(-1)
} | Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}},
    @{N='IP';E={$_.Properties[19].Value}} | Sort-Object TimeCreated

# Пошук нових служб
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
    Select-Object TimeCreated, @{N='ServiceName';E={$_.Properties[0].Value}}

# Зберегти Security Log у файл для подальшого аналізу
wevtutil epl Security C:\Logs\security_$(Get-Date -Format 'yyyy-MM-dd').evtx
```

### Sysmon: розширений моніторинг

**Sysmon (System Monitor)** — безкоштовний інструмент Sysinternals/Microsoft, що надає значно детальніші логи, ніж стандартний Event Log.

```powershell
# Завантажити і встановити Sysmon з конфігурацією Swift-Tink
# (одна з найкращих публічних конфігурацій)
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Expand-Archive Sysmon.zip -DestinationPath .\Sysmon\
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "sysmon-config.xml"
.\Sysmon\Sysmon64.exe -accepteula -i sysmon-config.xml
```

Sysmon додає Event ID:

| Event ID Sysmon | Що логує |
|---|---|
| 1 | Створення процесу (з хешем) |
| 3 | Мережеве з'єднання (який процес підключився куди) |
| 7 | Завантаження DLL |
| 11 | Створення файлу |
| 13 | Зміна значення реєстру |
| 22 | DNS-запит |

## Linux: syslog, journald і auditd

### journald: основний агрегатор логів

**systemd-journald** збирає логи від всіх служб, ядра і системи.

```bash
# Переглянути всі логи (від нового до старого)
journalctl -r

# Логи за останню годину
journalctl --since "1 hour ago"

# Логи конкретної служби
journalctl -u sshd.service -n 50

# Фільтр за пріоритетом (0=emergency, 3=error, 4=warning, 6=info, 7=debug)
journalctl -p 3 --since "2025-01-01"

# Логи ядра
journalctl -k

# Неперервний моніторинг (як tail -f)
journalctl -f

# Пошук по ключовому слову
journalctl | grep "Failed password"

# Статистика за розміром
journalctl --disk-usage
```

### Важливі файли логів Linux

| Файл | Що містить |
|---|---|
| `/var/log/auth.log` | SSH-входи, sudo, PAM-автентифікація |
| `/var/log/syslog` | Загальні системні повідомлення |
| `/var/log/kern.log` | Повідомлення ядра |
| `/var/log/dpkg.log` | Встановлення і видалення пакетів |
| `/var/log/fail2ban.log` | Дії fail2ban |
| `/var/log/audit/audit.log` | Дані auditd (якщо налаштовано) |
| `/var/log/ufw.log` | Дії UFW-фаєрвола |

### Аналіз SSH-логів

```bash
# Знайти всі невдалі спроби SSH-входу
grep "Failed password" /var/log/auth.log | tail -50

# Топ IP-адрес, що атакують SSH
grep "Failed password" /var/log/auth.log | \
    awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20

# Успішні SSH-входи
grep "Accepted" /var/log/auth.log

# Дії sudo
grep "sudo" /var/log/auth.log | grep -v "session"

# Нові облікові записи
grep "useradd\|new user" /var/log/auth.log
```

### auditd: низькорівневий аудит

```bash
# Після налаштування auditd (розділ 3.7) — перегляд подій
# Всі події за сьогодні
sudo ausearch --start today --raw | aureport -au

# Спроби доступу до /etc/shadow
sudo ausearch -f /etc/shadow

# Команди sudo за сьогодні
sudo ausearch -k sudo_usage --start today

# Всі виконані команди від root
sudo ausearch -ua root --start today | grep "type=EXECVE"

# Зміни у файлах /etc/
sudo ausearch -k identity

# Звіт по невдалим спробам
sudo aureport --failed
```

## Що шукати: індикатори компрометації в логах

Наступні патерни в логах — сигнали, що потребують негайного розслідування:

**Автентифікація і облікові записи:**
- Серія невдалих входів (>5 за хвилину) з однієї IP → брутфорс.
- Успішний вхід після серії невдалих → можливий успішний брутфорс.
- Вхід у незвичний час (середина ночі, вихідні) з незвичного місця.
- Новий обліковий запис або зміна членства в групі Administrators.
- Вхід від облікового запису, що мав бути вимкнений.

**Процеси і виконання:**
- Процес PowerShell/cmd, запущений з незвичного батьківського процесу (наприклад, `Word.exe → powershell.exe`).
- Виконання скрипта з папки Temp/Downloads/AppData.
- Нова служба або задача планувальника, створена несподівано.
- Процес, що звертається до мережевих адрес.

**Файлова система:**
- Масова зміна файлів за короткий час (індикатор ransomware).
- Зміна бінарних системних файлів.
- Нові файли в системних директоріях (`C:\Windows\System32\`, `/bin/`, `/usr/bin/`).
- Зміна `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`.

**Мережа:**
- З'єднання на нестандартні порти або незнайомі IP.
- Незвично великий обсяг вихідного трафіку (ексфільтрація).
- DNS-запити до підозрілих або нових доменів.

## Централізоване логування

Для кількох машин (навіть домашньої мережі з кількома пристроями) варто направити логи до центрального сховища:
- Зловмисник, що скомпрометував систему, може видалити локальні логи.
- Централізовані логи збережуться навіть якщо атакована машина стерта.

**Інструменти:**
- **Rsyslog** — стандартний syslog-демон Linux, підтримує пересилання логів.
- **Graylog** — open-source SIEM для централізованого збору і пошуку.
- **Elastic Stack (ELK)** — потужніший варіант, але складніший у налаштуванні.

```bash
# Налаштувати rsyslog для пересилання на центральний лог-сервер
echo "*.* @192.168.1.200:514" | sudo tee -a /etc/rsyslog.conf
sudo systemctl restart rsyslog
```

## Ротація і зберігання логів

Логи займають місце, і старі логи часом не менш важливі за нові (розслідування інциденту, що стався місяць тому). Налаштуйте ротацію та термін зберігання.

**Linux (logrotate):**
```bash
# /etc/logrotate.d/custom
/var/log/auth.log {
    daily
    rotate 365          # зберігати 365 днів
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
```

**Windows:**
```powershell
# Збільшити максимальний розмір Security Log
wevtutil sl Security /ms:1073741824  # 1 ГБ
# Встановити режим збереження: OverwriteAsNeeded або Archive
wevtutil sl Security /rt:false  # false = OverwriteAsNeeded
```

## Міні-вправа

**Windows:**
```powershell
# Переглянути останні 20 невдалих входів
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 20 |
    Select-Object TimeCreated, @{N='Account';E={$_.Properties[5].Value}},
    @{N='IP';E={$_.Properties[19].Value}} | Format-Table
```

**Linux:**
```bash
# Переглянути останні 20 SSH-спроб входу (успішних і невдалих)
grep -E "Accepted|Failed" /var/log/auth.log | tail -20

# Знайти топ-5 IP, що найбільше «стукають» у SSH
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | \
    sort | uniq -c | sort -rn | head -5
```

Зверніть увагу на результати: якщо сервер публічно доступний по SSH, майже гарантовано знайдете десятки (або тисячі) спроб входу від різних IP.

## Джерела та додаткові матеріали

- Sysmon (docs.microsoft.com/en-us/sysinternals/downloads/sysmon).
- SwiftOnSecurity/sysmon-config (github.com/SwiftOnSecurity/sysmon-config) — популярна конфігурація Sysmon.
- NIST SP 800-92 — Guide to Computer Security Log Management.
- `man auditd`, `man ausearch`, `man journalctl` — офіційна документація.
- MITRE ATT&CK — Detection (колонка «Detection» для кожної техніки).

---

**Попередній розділ:** [3.9. Резервне копіювання](09-rezervne-kopiuvannia.md)
**Далі:** [3.11. Шкідливе ПЗ і антивірусні рішення](11-shkidlyve-po.md)
**Назад до модуля:** [README модуля 03](README.md)

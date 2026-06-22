# 3.7. Hardening Linux: повний практичний гайд

Linux — і найбільш гнучка, і найбільш відповідальна ОС з точки зору безпеки. Гнучкість означає, що ви можете налаштувати захист дуже точно. Відповідальність — що за замовчуванням система робить рівно те, що ви їй скажете, без «зручних» зупинок безпеки Windows. На незахищеному Linux-сервері з відкритим SSH і слабким паролем перші спроби брутфорсу з'являються протягом хвилин після підключення до інтернету — бо боти сканують весь простір IPv4 безперервно.

Структура цього розділу паралельна розділу 3.6: ті самі принципи hardening, але в Linux-реалізації. Якщо ви вже пройшли Windows-hardening — деякі концепції будуть впізнавані; якщо починаєте з Linux — розділ 3.6 можна читати паралельно для порівняння.

Цей розділ охоплює Ubuntu/Debian як базовий дистрибутив, із відповідними примітками для RHEL/CentOS/Fedora.

> 📖 Ключові терміни — у [глосарії модуля](00-glosariy.md). Цей розділ спирається на CIS Benchmark for Ubuntu Linux 22.04 LTS.

## Блок 1: Перші кроки після встановлення

```bash
# Оновити всі пакети до актуальних версій
sudo apt update && sudo apt upgrade -y
sudo apt autoremove -y  # видалити невикористовувані залежності

# Встановити інструменти безпеки, що знадобляться
sudo apt install -y \
    ufw \               # фаєрвол
    fail2ban \          # захист від брутфорсу
    unattended-upgrades \ # автооновлення безпеки
    auditd \            # аудит системних подій
    rkhunter \          # пошук руткітів
    lynis \             # аудит безпеки системи
    apt-show-versions   # перевірка версій пакетів

# Налаштувати автоматичні оновлення безпеки
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

**Налаштування `/etc/apt/apt.conf.d/50unattended-upgrades`:**
```
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Automatic-Reboot "false";  // Не перезавантажувати автоматично
```

## Блок 2: Управління користувачами

```bash
# Переконатись, що root-вхід заблоковано (пароль заблокований, не просто порожній)
sudo passwd -l root
# Перевірка: $ sudo grep root /etc/shadow → повинно починатись з root:!

# Створити нового адмін-користувача замість root
sudo adduser admin_alice
sudo usermod -aG sudo admin_alice

# Перевірити всіх користувачів з UID 0 (усі мають бути лише root)
awk -F: '($3 == 0) { print $1 }' /etc/passwd

# Заблокувати порожні паролі
sudo sed -i 's/^#\?.*pam_unix.so.*/& nullok/' /etc/pam.d/common-auth
# Краще: переконатись, що nullok відсутній або замінений на reject_empty_passwords

# Знайти облікові записи з порожніми паролями
sudo awk -F: '($2 == "" ) { print $1 }' /etc/shadow

# Обмежити доступ до su (лише члени групи sudo можуть використовувати su)
echo "auth required pam_wheel.so use_uid" | sudo tee -a /etc/pam.d/su
```

## Блок 3: SSH — критичний вектор атаки

SSH-сервер на публічній IP — найчастіша точка атаки на Linux. Hardening SSH — перший і найважливіший крок для будь-якого публічно доступного сервера.

### Конфігурація `/etc/ssh/sshd_config`

```bash
sudo nano /etc/ssh/sshd_config
```

**Обов'язкові зміни:**
```
# Порт (зміна з 22 знижує кількість автоматизованих спроб, але не є захистом від цілеспрямованих)
Port 2222  # або будь-який нестандартний; оновіть правила фаєрвола відповідно

# Заборонити вхід під root
PermitRootLogin no

# Вимкнути автентифікацію за паролем (лише ключі)
PasswordAuthentication no
PermitEmptyPasswords no

# Вимкнути X11 Forwarding якщо не потрібно
X11Forwarding no

# Явно вказати дозволені методи автентифікації
AuthenticationMethods publickey

# Обмежити дозволених користувачів (лише явно вказані)
AllowUsers alice bob deploy_user

# Таймаут незайнятої сесії (600 секунд = 10 хвилин)
ClientAliveInterval 300
ClientAliveCountMax 2

# Вимкнути застарілі методи
IgnoreRhosts yes
HostbasedAuthentication no

# Обмежити версію протоколу (лише SSH-2)
Protocol 2  # В новому OpenSSH це за замовчуванням, але явно вказати не шкодить

# Логувати рівень VERBOSE для аудиту
LogLevel VERBOSE
```

```bash
# Перевірити конфігурацію перед перезапуском (важливо!)
sudo sshd -t

# Перезапустити SSH
sudo systemctl restart sshd

# ПЕРЕД закриттям поточної сесії — перевірити, що нова сесія відкривається
# (в окремому терміналі або вкладці)
```

## Блок 4: Фаєрвол (ufw)

```bash
# Встановити базову конфігурацію: все вхідне заблоковано, все вихідне дозволено
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Дозволити SSH (на зміненому порті, якщо міняли)
sudo ufw allow 2222/tcp  # або 22/tcp якщо стандартний

# Дозволити HTTP/HTTPS якщо це вебсервер
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Увімкнути фаєрвол
sudo ufw enable

# Переглянути правила
sudo ufw status verbose

# Дозволити доступ лише з конкретної IP (наприклад, SSH лише з офісу)
sudo ufw allow from 203.0.113.50 to any port 22

# Обмежити SSH (автоматично блокує IP після 6 спроб за 30 секунд)
sudo ufw limit ssh
```

## Блок 5: fail2ban — захист від брутфорсу

```bash
# fail2ban автоматично блокує IP після N невдалих спроб входу
sudo systemctl enable fail2ban --now

# Конфігурація: /etc/fail2ban/jail.local (створити, не редагувати jail.conf)
sudo nano /etc/fail2ban/jail.local
```

```ini
[DEFAULT]
bantime  = 3600        ; блокувати на 1 годину
findtime  = 600        ; вікно пошуку спроб (10 хвилин)
maxretry = 5           ; кількість спроб до блокування
ignoreip = 127.0.0.1/8 ::1 192.168.1.0/24  ; ваша домашня мережа

[sshd]
enabled  = true
port     = 2222        ; змінений порт SSH
logpath  = %(sshd_log)s
backend  = %(sshd_backend)s
maxretry = 3           ; суворіше для SSH
bantime  = 86400       ; блокувати на 24 години
```

```bash
sudo systemctl restart fail2ban

# Переглянути заблоковані IP
sudo fail2ban-client status sshd

# Розблокувати IP вручну
sudo fail2ban-client set sshd unbanip 203.0.113.50
```

## Блок 6: Ядро і sysctl — мережеві параметри безпеки

```bash
sudo nano /etc/sysctl.d/99-security.conf
```

```ini
# ===== ЗАХИСТ МЕРЕЖІ =====
# Відключити пересилання пакетів (якщо не маршрутизатор)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Захист від SYN flood
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2

# Ігнорувати broadcast ping (захист від smurf-атак)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ігнорувати неправильно сформовані пакети
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Захист від IP spoofing через reverse path filter
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Вимкнути ICMP redirect (може використовуватись для атак на маршрутизацію)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Не приймати source-routed пакети
net.ipv4.conf.all.accept_source_route = 0

# Логувати підозрілі пакети
net.ipv4.conf.all.log_martians = 1

# ===== ЗАХИСТ ПАМ'ЯТІ =====
# Рандомізація адресного простору (ASLR) — максимальний рівень
kernel.randomize_va_space = 2

# Обмежити доступ до /proc/pid/ для інших користувачів
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2

# Заборонити ptrace між процесами не-root і не-батьківськими
kernel.yama.ptrace_scope = 1
```

```bash
# Застосувати зміни
sudo sysctl -p /etc/sysctl.d/99-security.conf
```

## Блок 7: Вимкнення непотрібних служб

```bash
# Переглянути всі запущені служби
sudo systemctl list-units --type=service --state=running

# Служби, що часто можна вимкнути:
SERVICES_TO_DISABLE=(
    "avahi-daemon"      # Zero-conf networking — рідко потрібен на серверах
    "cups"              # Служба принтера
    "bluetooth"         # Bluetooth — якщо не використовується
    "ModemManager"      # Управління модемами
    "whoopsie"          # Ubuntu crash reporter
    "apport"            # Crash reporter
)

for svc in "${SERVICES_TO_DISABLE[@]}"; do
    if systemctl is-active --quiet "$svc"; then
        sudo systemctl stop "$svc"
        sudo systemctl disable "$svc"
        echo "Вимкнено: $svc"
    fi
done
```

## Блок 8: AppArmor і SELinux — мандатний контроль доступу

AppArmor — це MAC-система (Mandatory Access Control), вбудована в Ubuntu за замовчуванням. Вона обмежує, що конкретний застосунок може робити, незалежно від прав Linux-користувача. Якщо nginx скомпрометовано — AppArmor не дозволить йому читати `/etc/shadow` або запускати нові процеси, навіть якщо він виконується від root.

**AppArmor (Ubuntu/Debian):**

```bash
# Перевірити стан AppArmor
sudo apparmor_status

# Завантажити всі доступні профілі у режимі enforce
sudo aa-enforce /etc/apparmor.d/*

# Переглянути порушення AppArmor в логах
sudo journalctl -k | grep "apparmor.*DENIED"

# Встановити додаткові профілі
sudo apt install apparmor-profiles apparmor-profiles-extra
```

**SELinux (RHEL/CentOS/Fedora):**

Якщо ваш дистрибутив — RHEL, CentOS, Fedora або Rocky Linux, замість AppArmor за замовчуванням використовується **SELinux**. Принцип той самий (MAC-обмеження), але синтаксис інший:

```bash
# Перевірити поточний режим SELinux
getenforce
# Enforcing (активний), Permissive (логує, але не блокує), Disabled

# Переглянути відмови (AVC denials) — аналог "apparmor DENIED"
sudo ausearch -m avc --start today

# Або в реальному часі
sudo journalctl -k | grep "avc: denied"

# Включити режим Enforcing (якщо Permissive)
sudo setenforce 1

# Щоб SELinux залишався увімкненим після перезавантаження — /etc/selinux/config:
# SELINUX=enforcing
```

**Найпоширеніша помилка з SELinux:** якщо якась служба після встановлення «не працює», перша інстинктивна реакція — вимкнути SELinux (`setenforce 0` або `SELINUX=disabled`). Це замість того, щоб знайти і виправити конкретну AVC-відмову. Вимкнення SELinux — найгірший можливий «фікс» для проблеми конфігурації.

## Блок 9: auditd — аудит системних подій

```bash
sudo systemctl enable auditd --now

# Базові правила аудиту: /etc/audit/rules.d/audit.rules
sudo nano /etc/audit/rules.d/audit.rules
```

```
# Незмінний режим (зміна правил потребує перезавантаження) — додати в кінець
# -e 2

# Логувати зміни часу
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change

# Логувати зміни користувачів і груп
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers

# Логувати входи/виходи
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins

# Логувати зміни мережевих налаштувань
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale

# Логувати mount-операції
-a always,exit -F arch=b64 -S mount -k mounts

# Логувати видалення файлів
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete

# Логувати зміни привілеїв (SUID/SGID)
-a always,exit -F arch=b64 -S setuid -S setgid -k setuid

# Логувати sudo
-w /usr/bin/sudo -p x -k sudo_usage
```

```bash
sudo service auditd restart

# Переглянути події аудиту
sudo ausearch -k identity --start today
sudo ausearch -k sudo_usage --start today
```

## Блок 10: Захист важливих файлів (chattr)

```bash
# Зробити файли незмінними навіть для root
sudo chattr +i /etc/passwd
sudo chattr +i /etc/shadow
sudo chattr +i /etc/group
sudo chattr +i /etc/sudoers

# Увімкнений атрибут '+i' → файл не можна змінити, видалити або перейменувати
# (навіть root'ом) без попереднього chattr -i

# Перевірити атрибути файлу
lsattr /etc/passwd
```

> **Увага:** після встановлення атрибута `+i` ви не зможете змінити ці файли без його зняття (`sudo chattr -i`). Переконайтесь, що конфігурація коректна перед застосуванням.

## Блок 11: rkhunter і lynis — регулярний аудит

```bash
# rkhunter: пошук руткітів і підозрілих змін у системних файлах
sudo rkhunter --update
sudo rkhunter --check --skip-keypress 2>&1 | grep -E "Warning|Infected|Found"

# lynis: комплексний аудит безпеки системи
sudo lynis audit system
# Виводить оцінку безпеки (Hardening Index) і список рекомендацій

# Налаштувати регулярний запуск через cron
echo "0 3 * * 0 root /usr/sbin/lynis audit system --cronjob >> /var/log/lynis.log 2>&1" | \
    sudo tee /etc/cron.d/lynis
```

## Міні-вправа

```bash
# Зведений швидкий аудит стану Linux hardening
echo "=== Стан основних захисних заходів ==="

echo -n "ufw:              "; sudo ufw status | grep -q "active" && echo "✅ active" || echo "❌ inactive"
echo -n "fail2ban:         "; systemctl is-active fail2ban 2>/dev/null || echo "❌ inactive"
echo -n "AppArmor:         "; systemctl is-active apparmor 2>/dev/null || echo "❌ inactive"
echo -n "auditd:           "; systemctl is-active auditd 2>/dev/null || echo "❌ inactive"
echo -n "unattended-upg:   "; systemctl is-active unattended-upgrades 2>/dev/null || echo "❌ inactive"
echo -n "SSH root login:   "; grep -qi "PermitRootLogin.*no" /etc/ssh/sshd_config && echo "✅ заблоковано" || echo "❌ дозволено"
echo -n "SSH passwd auth:  "; grep -qi "PasswordAuthentication.*no" /etc/ssh/sshd_config && echo "✅ вимкнено" || echo "⚠️  увімкнено"
echo -n "Порожні паролі:   "; sudo awk -F: '($2 == "") {print "❌ " $1}' /etc/shadow 2>/dev/null | grep -q "❌" || echo "✅ відсутні"
echo -n "LUKS шифрування:  "; lsblk -o FSTYPE | grep -q "crypto_LUKS" && echo "✅ є" || echo "⚠️  не знайдено"
```

## Підсумковий чек-лист Linux Hardening

| Захід | Пріоритет | Команда перевірки |
|---|---|---|
| Всі оновлення встановлені | Must | `apt list --upgradable` |
| Root-вхід по SSH заблоковано | Must | `grep PermitRootLogin /etc/ssh/sshd_config` |
| Автентифікація за паролем SSH вимкнена | Must | `grep PasswordAuthentication /etc/ssh/sshd_config` |
| ufw увімкнено | Must | `sudo ufw status` |
| fail2ban активний | Must | `sudo systemctl status fail2ban` |
| Порожні паролі відсутні | Must | `sudo awk -F: '($2 == "")' /etc/shadow` |
| SMB/NFS/Avahi вимкнені якщо не потрібні | Should | `systemctl status smbd avahi-daemon nfs-server` |
| sysctl параметри безпеки налаштовані | Should | `sysctl net.ipv4.tcp_syncookies` |
| AppArmor увімкнено | Should | `sudo apparmor_status` |
| auditd налаштовано і активно | Should | `sudo systemctl status auditd` |
| SUID-файли перевірено | Should | `find / -perm -4000 -type f 2>/dev/null` |
| LUKS-шифрування диска | Should | `lsblk -o FSTYPE` |
| unattended-upgrades налаштовано | Should | `cat /etc/apt/apt.conf.d/50unattended-upgrades` |
| lynis/rkhunter запускаються регулярно | Should | `crontab -l` |

## Джерела та додаткові матеріали

- CIS Benchmark for Ubuntu Linux 22.04 LTS (cisecurity.org).
- `man sshd_config`, `man ufw`, `man fail2ban`, `man auditd`.
- AppArmor documentation (ubuntu.com/server/docs/security-apparmor).
- lynis (cisofy.com/lynis) — документація і опис перевірок.

---

**Попередній розділ:** [3.6. Hardening Windows](06-hardening-windows.md)
**Далі:** [3.8. Браузер і мережева безпека на пристрої](08-brauzer-ta-merezha.md)
**Назад до модуля:** [README модуля 03](README.md)

# 3.6. Hardening Windows: повний практичний гайд

Попередні п'ять розділів заклали фундамент: принципи hardening, архітектура ОС, права доступу, автентифікація і шифрування диска. Тепер — час практики. Цей розділ перекладає принципи на конкретні команди для Windows. Кожен блок нижче відповідає одному з принципів розділу 3.1: зменшення привілеїв, зменшення поверхні атаки, своєчасне оновлення. Виконуйте послідовно — саме в такому порядку порядок пріоритетів максимізує захист при обмеженому часі. Windows є найпоширенішою ОС для робочих станцій у корпоративному середовищі і вдома, і водночас найбільшою мішенню для атак. Не тому що вона принципово «менш безпечна», а тому що масштаб і кількість неправильно налаштованих систем роблять її атрактивною для масових кампаній. Більшість з описаного тут — не екзотика, а те, що мало б бути зроблено з коробки.

> 📖 Ключові терміни — у [глосарії модуля](00-glosariy.md). Цей розділ спирається на CIS Benchmark for Windows 10/11.

## Блок 1: Облікові записи і привілеї

### 1.1. Обліковий запис адміністратора

Вбудований обліковий запис Administrator (або `Адміністратор`) є першочерговою ціллю брутфорсу, бо відомо, що він існує на кожній Windows-машині.

```powershell
# Перейменувати вбудований Administrator (ускладнює атаки)
Rename-LocalUser -Name "Administrator" -NewName "SysAdmin_Backup"

# Відключити вбудований Administrator (якщо є інший адмін-акаунт)
Disable-LocalUser -Name "Administrator"

# Переконатись, що Guest вимкнено
Disable-LocalUser -Name "Guest"
```

### 1.2. Стандартний обліковий запис для щоденної роботи

```powershell
# Створити стандартного користувача для щоденної роботи
New-LocalUser -Name "DailyWork" -Password (ConvertTo-SecureString "SecurePass123!" -AsPlainText -Force) -FullName "Daily Work Account"

# Переконатись, що він НЕ в групі Administrators
Get-LocalGroupMember -Group "Administrators"
```

### 1.3. LAPS — унікальні паролі локального адміністратора

**LAPS (Local Administrator Password Solution)** — безкоштовний інструмент Microsoft, що автоматично генерує і ротує унікальний пароль локального адміністратора для кожного комп'ютера в домені, зберігаючи його в Active Directory. Без LAPS один скомпрометований пароль локального адміна дає доступ до всіх машин у мережі.

## Блок 2: Оновлення і патч-менеджмент

```powershell
# Увімкнути автоматичні оновлення через реєстр (якщо Group Policy недоступна)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
    -Name "AUOptions" -Value 4  # 4 = автоматичне завантаження і встановлення

# Перевірити стан Windows Update
Get-WindowsUpdateLog  # генерує лог оновлень

# PowerShell-модуль для керування оновленнями (треба встановити)
Install-Module PSWindowsUpdate
Get-WindowsUpdate
Install-WindowsUpdate -AcceptAll
```

**Категорії оновлень за пріоритетом:**
- **Security updates** — Must. Встановлювати щойно доступні.
- **Critical updates** — Must. Так само.
- **Driver updates** — Should. Особливо для компонентів, пов'язаних з мережею.
- **Feature updates** (нові версії Windows) — Should. Протестувати на тестовій машині перед розгортанням.

## Блок 3: Microsoft Defender і антивірусний захист

Microsoft Defender Antivirus — вбудований в Windows 10/11 і достатньо ефективний для більшості користувачів.

```powershell
# Переглянути статус Defender
Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, `
    AntivirusEnabled, RealTimeProtectionEnabled, OnAccessProtectionEnabled, `
    IoavProtectionEnabled, AntivirusSignatureLastUpdated

# Оновити сигнатури вручну
Update-MpSignature

# Запустити швидке сканування
Start-MpScan -ScanType QuickScan

# Додати виняток (лише якщо ДУЖЕ необхідно — розширює поверхню атаки)
# Add-MpPreference -ExclusionPath "C:\DevTools"

# Увімкнути захист від програм-вимагачів (Controlled Folder Access)
Set-MpPreference -EnableControlledFolderAccess Enabled
```

**Захист від програм-вимагачів (Controlled Folder Access):**
Захищає важливі папки (Документи, Зображення, Завантаження) від несанкціонованих змін. Якщо шкідливий код спробує зашифрувати файли в захищених папках — Defender заблокує спробу.

## Блок 4: Фаєрвол Windows

```powershell
# Переглянути профілі фаєрвола
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

# Увімкнути фаєрвол для всіх профілів
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Встановити правило за замовчуванням: блокувати вхідні, дозволяти вихідні
Set-NetFirewallProfile -Profile Domain,Public,Private `
    -DefaultInboundAction Block -DefaultOutboundAction Allow

# Переглянути активні правила (фільтр: лише вхідні, дозволяючі)
Get-NetFirewallRule | Where-Object {$_.Direction -eq "Inbound" -and $_.Action -eq "Allow" -and $_.Enabled -eq "True"} |
    Select-Object DisplayName, Profile, LocalPort

# Заблокувати конкретний порт (наприклад, Telnet 23)
New-NetFirewallRule -DisplayName "Block Telnet" -Direction Inbound `
    -Protocol TCP -LocalPort 23 -Action Block
```

## Блок 5: UAC і захист привілеїв

```powershell
# Встановити максимальний рівень UAC (4 = завжди повідомляти)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "ConsentPromptBehaviorAdmin" -Value 2  # 2 = prompt with secure desktop

# Захист облікових даних (Credential Guard) — Windows 10 Enterprise+
# Вимагає підтримки апаратної віртуалізації
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
    -Name "EnableVirtualizationBasedSecurity" -Value 1
```

## Блок 6: Служби Windows

Кожна запущена служба — це код, що виконується у фоні, слухає запити або відкриває мережеві порти. Деякі служби критичні для роботи ОС; інші були корисні у 2003 році і з тих пір просто «є». Принцип attack surface reduction вимагає: якщо ви не знаєте, навіщо служба запущена — вона має бути зупинена. Кожна вимкнена непотрібна служба — це мінус один потенційний вектор атаки без жодних витрат.

```powershell
# Переглянути всі запущені служби
Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name, DisplayName, StartType

# Служби, що варто вимкнути на домашній машині (залежить від потреб):
$servicesToDisable = @(
    "RemoteRegistry",    # Віддалений реєстр — непотрібен більшості користувачів
    "Telnet",            # Telnet — небезпечний протокол
    "TlntSvr",           # Telnet Server
    "SNMP",              # SNMP — якщо не використовується моніторинг
    "Fax"                # Служба факсів
)

foreach ($svc in $servicesToDisable) {
    if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
        Stop-Service -Name $svc -Force
        Set-Service -Name $svc -StartupType Disabled
        Write-Host "Вимкнено: $svc"
    }
}
```

**Критично вимкнути або обмежити:**

| Служба | Причина | Дія |
|---|---|---|
| `RemoteRegistry` | Дозволяє редагувати реєстр по мережі | Вимкнути якщо не потрібно |
| `WinRM` | Windows Remote Management — PowerShell Remoting | Вимкнути на non-server машинах |
| `Print Spooler` | Численні CVE (PrintNightmare) | Вимкнути якщо принтер не підключено |
| `LLMNR` | Протокол розпізнавання імен без DNS — ціль для responder-атак | Вимкнути через Group Policy |
| `NetBIOS` | Застарілий протокол — ціль для атак | Вимкнути |
| `SMBv1` | Використаний WannaCry; численні CVE | Вимкнути негайно |

```powershell
# Вимкнути SMBv1 (КРИТИЧНО важливо)
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Set-SmbClientConfiguration -EnableSMB1Protocol $false -Force

# Вимкнути LLMNR через реєстр
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" -Value 0

# Вимкнути NetBIOS over TCP/IP на мережевих адаптерах
# Через GUI: Властивості підключення → IPv4 → Додатково → WINS → Вимкнути NetBIOS
```

## Блок 7: PowerShell і виконання скриптів

PowerShell — потужний інструмент адміністрування, але й популярний вектор атаки (Living off the Land — LOLBAS).

```powershell
# Встановити обмежену політику виконання (лише підписані скрипти)
Set-ExecutionPolicy AllSigned -Scope LocalMachine

# Або RemoteSigned (локальні скрипти без підпису, з інтернету — лише підписані)
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine

# Увімкнути логування PowerShell (ScriptBlock Logging)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" -Value 1

# Увімкнути Module Logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    -Name "EnableModuleLogging" -Value 1
```

## Блок 8: BitLocker

Шифрування диска докладно описано в розділі 3.5 — включаючи новий підрозділ про Secure Boot. Тут лише швидка перевірка в контексті загального hardening: якщо BitLocker вимкнений на ноутбуці, всі інші заходи безпеки не захистять дані при фізичній крадіжці пристрою.

```powershell
# Перевірити статус BitLocker
$status = Get-BitLockerVolume -MountPoint "C:"
if ($status.ProtectionStatus -ne "On") {
    Write-Warning "BitLocker вимкнено! Дані не захищені при фізичній крадіжці."
}
```

## Блок 9: Налаштування реєстру (додаткові захисні заходи)

```powershell
# Вимкнути автозапуск з USB та інших носіїв (Autorun)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -Name "NoDriveTypeAutoRun" -Value 255

# Увімкнути відображення розширень файлів (прихований .exe у .pdf.exe — класична атака)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
    -Name "HideFileExt" -Value 0

# Увімкнути відображення прихованих файлів і системних файлів
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
    -Name "Hidden" -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
    -Name "ShowSuperHidden" -Value 1

# Вимкнути відновлення після збою (може перезаписати важливі докази при інциденті)
# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AutoReboot" -Value 0

# Вимкнути WDigest (зберігало паролі у відкритому вигляді в пам'яті — CVE)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
    -Name "UseLogonCredential" -Value 0
```

## Блок 10: AppLocker і контроль додатків

**AppLocker** (Windows Pro/Enterprise) і **Windows Defender Application Control (WDAC)** дозволяють визначити, які програми можуть виконуватись на системі. Це один з найефективніших захисних заходів проти шкідливого ПЗ.

```powershell
# Переглянути поточні правила AppLocker
Get-AppLockerPolicy -Effective | Select-Xml -XPath "//RuleCollection" | Select-Object -Expand Node

# Увімкнути режим аудиту (без блокування — для початку)
Set-AppLockerPolicy -PolicyObject (Get-AppLockerPolicy -Effective) -Merge
```

Базова стратегія AppLocker:
- Дозволити виконання лише з `C:\Windows\` і `C:\Program Files\`.
- Заблокувати виконання з папки Temp, Downloads, AppData.
- Більшість шкідливого ПЗ запускається саме з цих папок.

## Міні-вправа

Запустіть скрипт аудиту з лабораторної 3.12.1 і порівняйте результат з підсумковим чек-листом нижче. Для кожного пункту, що отримав ❌ або ⚠️, знайдіть відповідний «Блок» у цьому розділі і виконайте рекомендовані команди.

Якщо хочете перевірити стан системи компактно без скрипта:

```powershell
# Швидкий зведений звіт про стан ключових налаштувань
@{
    "Defender (real-time)"   = (Get-MpComputerStatus).RealTimeProtectionEnabled
    "Firewall (Public)"      = (Get-NetFirewallProfile -Profile Public).Enabled
    "BitLocker (C:)"         = ((Get-BitLockerVolume -MountPoint "C:" -EA SilentlyContinue).ProtectionStatus -eq "On")
    "SMBv1 disabled"         = -not (Get-SmbServerConfiguration).EnableSMB1Protocol
    "WDigest disabled"       = ((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -EA SilentlyContinue).UseLogonCredential -eq 0)
    "AutoRun disabled"       = ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -EA SilentlyContinue).NoDriveTypeAutoRun -eq 255)
} | ForEach-Object { $_.GetEnumerator() } |
    Select-Object @{N='Перевірка';E={$_.Key}}, @{N='Стан';E={if ($_.Value) {"✅ OK"} else {"❌ Виправити"}}} |
    Format-Table -AutoSize
```

## Підсумковий чек-лист Windows Hardening

| Захід | Пріоритет | Перевірка |
|---|---|---|
| Щоденна робота — стандартний обліковий запис | Must | `whoami /groups` не містить Administrators |
| Автоматичні оновлення увімкнені | Must | Windows Update: Up to date |
| Microsoft Defender активний і оновлений | Must | `Get-MpComputerStatus` |
| Фаєрвол увімкнений для всіх профілів | Must | `Get-NetFirewallProfile` |
| SMBv1 вимкнено | Must | `Get-SmbServerConfiguration` |
| BitLocker увімкнено (для ноутбуків) | Must | `Get-BitLockerVolume` |
| UAC на рівні "Always notify" | Should | Панель керування → UAC |
| RemoteRegistry і WinRM вимкнені | Should | `Get-Service` |
| Розширення файлів відображаються | Should | Explorer → Вигляд |
| WDigest вимкнено | Should | Реєстр |
| ScriptBlock Logging увімкнено | Should | Реєстр/GP |
| Autorun вимкнено | Should | Реєстр |
| LAPS налаштовано (для організацій) | Should | AD |
| AppLocker налаштовано | Optional (но ефективно) | gpedit.msc |

## Джерела та додаткові матеріали

- CIS Benchmark for Microsoft Windows 10/11 (cisecurity.org/benchmark/microsoft_windows) — детальний стандарт.
- Microsoft Security Baselines (microsoft.com/en-us/download/details.aspx?id=55319) — офіційні базові конфігурації.
- DISA STIG for Windows — найсуворіші вимоги.
- Microsoft Docs, *Windows Defender Application Control* — повна документація WDAC.

---

**Попередній розділ:** [3.5. Шифрування дисків](05-shyfruvannia-dyskiv.md)
**Далі:** [3.7. Hardening Linux](07-hardening-linux.md)
**Назад до модуля:** [README модуля 03](README.md)

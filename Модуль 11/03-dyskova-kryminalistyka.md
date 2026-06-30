# 11.3. Дискова форензика

Видалений файл насправді не видаляється — операційна система просто позначає простір, що він займав, як «доступний для перезапису», і прибирає посилання на нього з файлової таблиці. Сам вміст файлу залишається на диску, доки якісь нові дані фізично не запишуться поверх нього. Це фундаментальний факт, на якому будується вся дискова форензика: навіть зловмисник, що «видалив сліди», часто залишає за собою достатньо матеріалу для відновлення повної картини — якщо знати, де і як шукати.

> 📖 Ключові терміни — у [глосарії модуля](00-glosariy.md).

## Файлові системи: де ховаються докази

### NTFS (Windows)

**Master File Table (MFT)** — центральна структура NTFS, що містить запис для кожного файлу і директорії на томі.

```
Кожен MFT-запис містить:
├── Стандартні атрибути (timestamps: Created, Modified,
│   Accessed, MFT Modified — "MACE" або "MACB")
├── Ім'я файлу (можливо кілька — короткі 8.3 і довгі імена)
├── Дані (якщо файл малий — "resident" дані прямо в MFT;
│   якщо великий — вказівники на кластери диска)
└── Прапор: чи файл активний чи видалений
    (видалення лише позначає запис як "вільний",
     дані залишаються до перезапису)
```

**Чотири часові мітки NTFS (MACB/MACE):**

| Мітка | Що означає | Криміналістичне значення |
|---|---|---|
| **M**odified | Останнє редагування вмісту | Коли файл востаннє змінено |
| **A**ccessed | Останнє читання | Коли файл востаннє відкритий (обережно: часто вимкнено для продуктивності в сучасних Windows) |
| **C**hanged/**C**reated | MFT-запис змінено / Створення | Системні метадані змінились |
| **B**orn (Entry Modified) | Час створення файлу | Коли файл вперше з'явився |

**Timestomping** (детально — anti-forensics, 11.8) — техніка зміни цих timestamps для приховування справжнього часу дій зловмисника.

### ext4 (Linux)

```
Ключові структури ext4:
├── Inode — метадані файлу (без імені; ім'я зберігається
│   окремо в директорії-записі)
├── Journal — журнал транзакцій (можна відновити нещодавні
│   зміни навіть після збою)
└── Extended Attributes — додаткові метадані (SELinux context,
    ACLs)

Часові мітки ext4:
- atime (access time)
- mtime (modification time)
- ctime (inode change time)
- crtime (creation time, лише в ext4, не в ext3/ext2)
```

## File Carving: відновлення видалених файлів

**File Carving** — техніка відновлення файлів безпосередньо з необробленого (raw) образу диска, без покладання на файлову систему — корисно, коли метадані файлової системи пошкоджені, видалені або відформатовані.

**Принцип Header/Footer Carving:**

```python
# Спрощена демонстрація принципу file carving
# Реальні інструменти (Foremost, PhotoRec, Scalpel) роблять це ефективніше

FILE_SIGNATURES = {
    'jpg': {'header': b'\xFF\xD8\xFF', 'footer': b'\xFF\xD9'},
    'pdf': {'header': b'%PDF', 'footer': b'%%EOF'},
    'png': {'header': b'\x89PNG\r\n\x1a\n', 'footer': b'IEND\xaeB`\x82'},
    'zip': {'header': b'PK\x03\x04', 'footer': b'PK\x05\x06'},
}

def carve_files(raw_image_path: str, file_type: str):
    """Демонстрація принципу: шукаємо header...footer пари у raw-даних."""
    sig = FILE_SIGNATURES[file_type]
    with open(raw_image_path, 'rb') as f:
        data = f.read()

    start = 0
    found_files = []
    while True:
        header_pos = data.find(sig['header'], start)
        if header_pos == -1:
            break
        footer_pos = data.find(sig['footer'], header_pos)
        if footer_pos == -1:
            break
        footer_pos += len(sig['footer'])
        found_files.append((header_pos, footer_pos))
        start = footer_pos

    return found_files
```

**Реальні інструменти file carving:**
- **PhotoRec** — найпопулярніший безкоштовний інструмент; відновлює сотні типів файлів.
- **Foremost** — заснований на конфігураційних сигнатурах.
- **Scalpel** — швидший форк Foremost.
- **bulk_extractor** — паралельний carving + автоматичне виявлення credit card numbers, email-адрес, URL.

```bash
# PhotoRec (інтерактивний інструмент)
photorec /d /output/recovered_files /d image.dd

# bulk_extractor: автоматичне виявлення артефактів
bulk_extractor -o output_dir evidence.dd
# Створює окремі файли: email.txt, url.txt, ccn.txt (credit card numbers) тощо
```

## Slack Space і Unallocated Space

**Slack Space** — простір між кінцем фактичних даних файлу і кінцем виділеного йому кластера диска.

```
Кластер диска (наприклад, 4096 байт):
┌────────────────────────────────────┐
│ Дані файлу (3000 байт)              │ ← Файл "official.txt"
│──────────────────────────────────────│
│ SLACK SPACE (1096 байт)              │ ← Залишок попереднього файлу,
│ можуть бути дані попереднього файлу  │    що раніше займав цей кластер
└────────────────────────────────────┘
```

**Криміналістична цінність slack space:** якщо зловмисник «видалив» файл і записав поверх новий менший файл — частина старих даних може залишитись у slack space нового файлу.

**Unallocated Space** — кластери, не призначені жодному поточному файлу (включно з повністю видаленими файлами, чиї дані ще не перезаписані). Основна територія для file carving.

## Реєстр Windows як форензичне джерело

**Реєстр (Registry)** — ієрархічна база даних конфігурації Windows, надзвичайно багате джерело форензичних артефактів.

```
Ключові форензичні гілки реєстру:

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
  → Команди, виконані через Run dialog (Win+R)

HKEY_CURRENT_USER\...\Explorer\RecentDocs
  → Нещодавно відкриті документи

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services
  → Встановлені служби (місце persistence для malware)

HKEY_LOCAL_MACHINE\...\Run, RunOnce
  → Програми автозапуску (класичний persistence-механізм)

NTUSER.DAT (файл, не "жива" гілка)
  → Профіль користувача; UserAssist ключ показує
    запущені GUI-програми з лічильником і timestamp

SYSTEM hive → ControlSet\Enum\USBSTOR
  → Історія підключених USB-пристроїв (vendor, product,
    serial number, перше і останнє підключення)
```

```bash
# Аналіз реєстру через RegRipper (відкритий інструмент)
rip.pl -r SYSTEM -p usbstor
# Виводить історію всіх USB-пристроїв, що підключались до системи

# RECmd (Eric Zimmerman tools) — для glибокого аналізу
RECmd.exe -f NTUSER.DAT --bn BatchExamples\UserAssist.reb
```

## Timeline Analysis: реконструкція хронології подій

**Super Timeline** — об'єднання timestamps з усіх можливих джерел (файлова система, реєстр, логи подій, browser history, prefetch) в єдину хронологічну послідовність для розуміння повної картини інциденту.

```bash
# log2timeline / plaso — індустріальний стандарт для побудови super timeline
log2timeline.py timeline.plaso evidence_image.dd

# Конвертація в читабельний CSV
psort.py -o l2tcsv -w timeline.csv timeline.plaso

# Фільтрація за часовим діапазоном інциденту
psort.py -o l2tcsv -w filtered.csv timeline.plaso \
  "date > '2024-01-15 00:00:00' AND date < '2024-01-16 00:00:00'"
```

**Приклад фрагменту super timeline:**

```
Time                 Source      Description
2024-01-15 03:12:01  FILE        backdoor.php CREATED in /var/www/html/
2024-01-15 03:12:05  WEBSERVER   Apache access log: POST /upload.php from 185.220.101.1
2024-01-15 03:14:33  PREFETCH    powershell.exe executed (3rd run)
2024-01-15 03:14:35  REGISTRY    RunMRU: "powershell -enc JABjAD0A..." 
2024-01-15 03:15:02  EVTLOG      Windows Event 4688: New process svch0st.exe created
2024-01-15 03:15:45  NETWORK     Outbound connection to 185.220.101.1:443
```

Цей формат дозволяє побачити повну послідовність атаки — від початкового завантаження webshell до виконання PowerShell і встановлення мережевого з'єднання — в одній хронологічній стрічці з різних незалежних джерел, що підтверджують одне одного.

## Prefetch і Shimcache: докази виконання програм

**Prefetch файли** (`C:\Windows\Prefetch\*.pf`) — Windows кешує інформацію про запущені програми для прискорення наступного запуску. Криміналістична цінність: показує, скільки разів і коли програма виконувалась, навіть якщо сам виконуваний файл вже видалений.

```bash
# PECmd (Eric Zimmerman) для аналізу Prefetch
PECmd.exe -d C:\Windows\Prefetch --csv output

# Виявляє: ім'я програми, кількість запусків, перший/останній запуск,
# завантажені DLL, навіть шлях, з якого програма запускалась
```

**Shimcache (AppCompatCache)** — реєстрова структура, що відстежує сумісність застосунків; неочікувано корисна для форензики, бо записує факт існування виконуваного файлу за певним шляхом у певний час, навіть якщо файл не був фактично запущений (лише «розглядався» Windows).

## Міні-вправа

```bash
# Якщо у вас є доступ до тестової VM з Windows або Linux:

# Windows: перегляньте Prefetch файли
dir C:\Windows\Prefetch

# Linux: перегляньте timestamps файлу
stat /etc/passwd
# Зверніть увагу на Access, Modify, Change

# Створіть тестовий файл, видаліть його, спробуйте відновити
echo "Test forensic recovery" > /tmp/test_file.txt
rm /tmp/test_file.txt
# На Linux: extundelete або photorec для спроби відновлення
# (демонстрація принципу, не гарантований результат на сучасних SSD з TRIM)
```

## Джерела та додаткові матеріали

- Carrier B., *File System Forensic Analysis* — фундаментальна книга по NTFS/ext.
- log2timeline/plaso documentation (plaso.readthedocs.io).
- Eric Zimmerman Tools (ericzimmerman.github.io) — набір безкоштовних форензичних утиліт.
- SANS FOR500 — Windows Forensic Analysis course materials.
- Autopsy (sleuthkit.org/autopsy) — відкрита GUI-платформа дискової форензики.

---

**Попередній розділ:** [11.2. Chain of Custody](02-chain-of-custody.md)
**Далі:** [11.4. Memory Forensics](04-memory-forensics.md)
**Назад до модуля:** [README модуля 11](README.md)

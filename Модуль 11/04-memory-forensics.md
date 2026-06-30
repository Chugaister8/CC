# 11.4. Memory Forensics

Сучасне fileless malware (модуль 07) ніколи не торкається диска — воно живе виключно в оперативній пам'яті, виконуючись через легітимні системні процеси. Дискова форензика, якою б ретельною вона не була, просто не знайде того, чого там немає. Memory Forensics — єдиний спосіб «спіймати» такі загрози: захопити стан RAM до того, як вимкнення живлення назавжди знищить ці ефемерні докази. Це водночас найскладніша і найбагатша на інформацію галузь цифрової криміналістики: пам'ять містить розшифровані дані, паролі в plaintext, мережеві з'єднання в реальному часі — все те, чого диск ніколи не покаже.

> 📖 Ключові терміни — у [глосарії модуля](00-glosariy.md).

## Чому Memory Forensics критична

```
Що ВИДНО лише в пам'яті, але НЕ на диску:

✅ Розшифровані дані (ключі шифрування активні в RAM)
✅ Fileless malware (PowerShell у пам'яті, process injection)
✅ Активні мережеві з'єднання (включно з закритими нещодавно)
✅ Паролі у відкритому вигляді (з LSASS, браузерів)
✅ Команди, виконані в консолі (включно з історією поточної сесії)
✅ Розшифрований вміст зашифрованих дисків (якщо том примонтований)
✅ Запущені, але не збережені на диск процеси
✅ Артефакти process hollowing і code injection
```

## Збір дампу пам'яті: методи і інструменти

**Критичне правило:** збір пам'яті завжди виконується ПЕРШИМ (Order of Volatility, розділ 11.1) — до вимкнення живлення, до від'єднання мережі (якщо можливо), до будь-яких інших форензичних дій.

### Інструменти для збору пам'яті

```bash
# Windows: WinPmem (відкритий, рекомендований SANS)
winpmem_mini_x64.exe memory_dump.raw

# Windows: DumpIt (простий, для швидкого реагування)
DumpIt.exe /OUTPUT memory_dump.raw

# Linux: LiME (Linux Memory Extractor) — потребує kernel module
insmod lime.ko "path=/mnt/usb/memory.lime format=lime"

# macOS: osxpmem (частина rekall/volatility tools)
sudo ./osxpmem.app/osxpmem -o memory_dump.raw

# Віртуальні машини: знімок пам'яті без агента на хості
# VMware: .vmem файл при suspend або snapshot
# VirtualBox: VBoxManage debugvm <vm-name> dumpvmcore --filename mem.elf
# Hyper-V: через PowerShell Checkpoint-VM з повним snapshot
```

**Важлива деталь для virtual machines:** якщо досліджувана система — VM, найчистіший спосіб отримати дамп пам'яті — через snapshot/suspend на рівні гіпервізора, а не через агента всередині гостьової ОС (що саме могло бути скомпрометоване).

### Розмір і час: практичні обмеження

```
Типові обсяги RAM для форензики:
- Робоча станція: 8-32 ГБ → дамп займає стільки ж місця
- Сервер: 64-512+ ГБ → потрібно швидке сховище і час

Швидкість збору залежить від:
- Швидкості диска призначення (USB 3.0 vs NVMe)
- Навантаження системи (чи можна паузити процеси)
- Антивірус/EDR може заважати інструментам збору пам'яті
  (потрібні винятки заздалегідь налаштовані в IR-плані)
```

## Volatility Framework: основний інструмент аналізу

**Volatility** — провідний відкритий framework для аналізу дампів пам'яті, що дозволяє витягувати структуровану інформацію з сирих байтів RAM.

```bash
# Volatility 3 (сучасна версія, автоматичне визначення профілю ОС)
pip install volatility3

# Базова інформація про образ
vol3 -f memory_dump.raw windows.info

# Список процесів (еквівалент Task Manager на момент збору)
vol3 -f memory_dump.raw windows.pslist

# Список процесів з ієрархією (виявляє підозрілі parent-child зв'язки)
vol3 -f memory_dump.raw windows.pstree

# Мережеві з'єднання, активні на момент збору
vol3 -f memory_dump.raw windows.netscan

# Завантажені DLL для конкретного процесу
vol3 -f memory_dump.raw windows.dlllist --pid 4521

# Виявлення прихованих процесів (rootkit-техніки)
vol3 -f memory_dump.raw windows.psscan
# psscan сканує всю пам'ять незалежно від офіційних списків ОС —
# виявляє процеси, приховані rootkit через unlinking з PEB

# Дамп конкретного процесу для подальшого аналізу (наприклад VirusTotal)
vol3 -f memory_dump.raw -o output_dir windows.pslist.PsList --pid 4521 --dump

# Виявлення command-line history
vol3 -f memory_dump.raw windows.cmdline

# Hashdump — витяг NTLM-хешів з LSASS (для виявлення credential theft)
vol3 -f memory_dump.raw windows.hashdump
```

## Типові форензичні знахідки у пам'яті

### Виявлення Process Injection

```
Ознаки process injection (модуль 07, Living off the Land):

1. Процес з "порожньою" Image (PE заголовок не відповідає
   очікуваному для цього процесу)
2. VAD (Virtual Address Descriptor) регіони з виконуваними
   правами (RWX) у нетипових для процесу місцях
3. Розбіжність між шляхом на диску (EPROCESS) і фактичним
   завантаженим кодом
4. Процес svchost.exe, explorer.exe з нетиповим parent process

vol3 -f memory_dump.raw windows.malfind
# malfind автоматично шукає підозрілі VAD-регіони з ознаками
# ін'єкції коду (RWX permissions + PE header у пам'яті)
```

### Виявлення мережевих C2-з'єднань

```bash
vol3 -f memory_dump.raw windows.netscan
# Виводить: локальна адреса:порт, віддалена адреса:порт,
# стан з'єднання (ESTABLISHED, CLOSE_WAIT), власник-процес, час

# Приклад підозрілого результату:
# Offset    Proto  LocalAddr      ForeignAddr         State       PID  Owner
# 0x8e3f... TCPv4  10.0.1.50:49234 185.220.101.1:443  ESTABLISHED 4521 svch0st.exe
#                                                                       ↑ typosquatting!
```

### Виявлення Credential Theft

```bash
# LSASS process містить credentials в пам'яті (модуль 05, Pass-the-Hash)
vol3 -f memory_dump.raw windows.pslist | grep lsass
# Знайти PID LSASS, потім дослідити чи був dump LSASS пам'яті
# (Mimikatz та подібні інструменти зазвичай dump-лять весь
# процес LSASS для офлайн-аналізу credentials)

# Перевірка чи LSASS процес мав підозрілий доступ
vol3 -f memory_dump.raw windows.handles --pid <lsass_pid>
```

## Memory Forensics для Linux

```bash
# Volatility 3 також підтримує Linux (потребує symbol table для версії ядра)
vol3 -f linux_memory.raw linux.pslist
vol3 -f linux_memory.raw linux.bash
# linux.bash витягує історію команд bash прямо з пам'яті процесу,
# навіть якщо .bash_history був видалений або відключений!

vol3 -f linux_memory.raw linux.netstat
# Активні мережеві з'єднання

vol3 -f linux_memory.raw linux.malfind
# Виявлення підозрілих виконуваних регіонів пам'яті (аналог Windows malfind)
```

## Аналіз дампу пам'яті браузера: витяг credentials і історії

Часто потрібно проаналізувати конкретно пам'ять браузера для відновлення сесійних токенів, паролів, історії перегляду на момент збору:

```bash
# Volatility plugin для Chrome
vol3 -f memory_dump.raw windows.pslist | grep chrome
# Знайти PID chrome.exe, потім dump процесу

vol3 -f memory_dump.raw -o output windows.memmap.Memmap --pid <chrome_pid> --dump
# Подальший аналіз дампу через strings + grep для пошуку
# залишків HTTP-заголовків, токенів, URL

strings chrome_process.dmp | grep -i "authorization:"
strings chrome_process.dmp | grep -E "session_token|auth_token"
```

## Карта артефактів для типових сценаріїв розслідування

| Сценарій | Ключові Volatility плагіни |
|---|---|
| Підозра на ransomware | `pslist`, `cmdline`, `filescan` (знайти процес шифрування) |
| Підозра на C2-комунікацію | `netscan`, `connections`, `dlllist` |
| Credential theft | `hashdump`, `handles` для LSASS |
| Fileless malware / LOLBAS | `cmdline`, `malfind`, `pstree` (аномальні parent-child) |
| Rootkit | `psscan` vs `pslist` (розбіжність = приховані процеси) |
| Lateral movement | `netscan`, `connections`, `privileges` |

## Обмеження Memory Forensics

```
Виклики:
├── Пам'ять летка — будь-яка затримка зі збором втрачає дані
├── Анти-форензичні техніки можуть очищати сліди в пам'яті
│   до завершення збору (детально — розділ 11.8)
├── Дамп великих систем (512 ГБ+ RAM) потребує часу і місця
├── Шифрування пам'яті на рівні апаратного забезпечення
│   (Intel SGX, AMD SEV) ускладнює традиційний дамп
└── Версії ОС постійно змінюють внутрішні структури —
    Volatility потребує оновлених symbol tables
```

## Міні-вправа

Якщо у вас є доступ до тестової VM (не продакшн-системи!):

```bash
# 1. Зробіть дамп пам'яті тестової VM
# VirtualBox приклад:
VBoxManage debugvm "TestVM" dumpvmcore --filename test_memory.elf

# 2. Встановіть і запустіть Volatility 3
pip install volatility3
vol3 -f test_memory.elf windows.info

# 3. Перегляньте процеси і порівняйте pslist з psscan —
#    чи є розбіжності (потенційно приховані процеси)?
vol3 -f test_memory.elf windows.pslist
vol3 -f test_memory.elf windows.psscan
```

## Джерела та додаткові матеріали

- Volatility 3 Documentation (volatility3.readthedocs.io).
- Ligh M., Case A., et al., *The Art of Memory Forensics* — фундаментальна книга.
- SANS FOR526 — Memory Forensics In-Depth course materials.
- Volatility Foundation plugin repository (github.com/volatilityfoundation).

---

**Попередній розділ:** [11.3. Дискова форензика](03-dyskova-kryminalistyka.md)
**Далі:** [11.5. Мережева форензика](05-merezheva-kryminalistyka.md)
**Назад до модуля:** [README модуля 11](README.md)

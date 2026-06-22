# 2.10. Практична лабораторна на Python

У цьому розділі — чотири лабораторні роботи, що закріплюють теорію модуля практикою. Всі скрипти виконують **захисні** або **діагностичні** функції на власних системах і локальній мережі. Жодна з технік не має застосовуватись до чужих систем без явного письмового дозволу.

**Вимоги:** Python 3.10+. Лабораторна 4 (сніфер) потребує бібліотеки `scapy` та прав адміністратора/root.

---

## Лабораторна 2.10.1: Сканер портів

Реалізуємо власний сканер портів на основі сокетів. Це спрощена версія того, що робить Nmap — корисно для розуміння механізму зсередини.

```python
import socket
import concurrent.futures
from datetime import datetime

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 27017: "MongoDB",
}


def scan_port(host: str, port: int, timeout: float = 0.5) -> bool:
    """Перевіряє, чи відкритий порт на хості TCP-з'єднанням."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def scan_host(host: str, ports: list[int], max_workers: int = 100) -> dict[int, str]:
    """Сканує список портів паралельно, повертає словник відкритих портів."""
    open_ports = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(scan_port, host, p): p for p in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            if future.result():
                service = COMMON_PORTS.get(port, "невідомий сервіс")
                open_ports[port] = service
    return dict(sorted(open_ports.items()))


if __name__ == "__main__":
    # ВИКОРИСТОВУЙТЕ ЛИШЕ ДЛЯ АУДИТУ ВЛАСНИХ СИСТЕМ
    target = "127.0.0.1"   # localhost — завжди безпечно

    print(f"Сканування: {target}")
    print(f"Час початку: {datetime.now().strftime('%H:%M:%S')}")
    print("-" * 40)

    ports_to_scan = list(COMMON_PORTS.keys()) + list(range(1024, 1100))
    result = scan_host(target, ports_to_scan)

    if result:
        for port, service in result.items():
            print(f"  ВІДКРИТИЙ  {port:5d}/tcp  →  {service}")
    else:
        print("  Відкритих портів не знайдено.")

    print("-" * 40)
    print(f"Час завершення: {datetime.now().strftime('%H:%M:%S')}")
    print(f"Знайдено відкритих портів: {len(result)}")
```

**Завдання:**
1. Запустіть проти `127.0.0.1`. Для кожного відкритого порту визначте, яка програма його використовує (`netstat -ano` + PID у Windows або `sudo ss -tulpn` у Linux). Чи всі вони потрібні?
2. Спробуйте запустити проти IP вашого домашнього роутера (наприклад `192.168.1.1`). Які порти відкриті? Чи відкрита адмін-панель (порт 80/443)?

---

## Лабораторна 2.10.2: DNS-розвідка

Скрипт для аналізу DNS-записів домену — корисний інструмент аудиту.

```python
import socket
import subprocess
import sys


def resolve_a(domain: str) -> list[str]:
    """Отримати A-записи домену."""
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        return list({r[4][0] for r in results})
    except socket.gaierror as e:
        return [f"Помилка: {e}"]


def run_dig(domain: str, record_type: str) -> str:
    """Виконати dig-запит і повернути результат."""
    try:
        result = subprocess.run(
            ["dig", "+short", domain, record_type],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip() or "(немає записів)"
    except FileNotFoundError:
        return "(dig не встановлено — встановіть dnsutils/bind-tools)"
    except subprocess.TimeoutExpired:
        return "(тайм-аут)"


def audit_domain(domain: str) -> None:
    print(f"\n{'=' * 50}")
    print(f"DNS-аудит домену: {domain}")
    print(f"{'=' * 50}")

    print(f"\n[A] IPv4-адреси:")
    for ip in resolve_a(domain):
        print(f"    {ip}")

    for rtype in ("AAAA", "MX", "NS", "TXT"):
        print(f"\n[{rtype}] Записи:")
        output = run_dig(domain, rtype)
        for line in output.splitlines():
            print(f"    {line}")

    # Перевірка SPF
    print("\n[Аналіз безпеки пошти]")
    txt = run_dig(domain, "TXT")
    spf_found = any("v=spf1" in line for line in txt.splitlines())
    dmarc = run_dig(f"_dmarc.{domain}", "TXT")
    dmarc_found = "v=DMARC1" in dmarc

    print(f"    SPF:   {'✅ знайдено' if spf_found else '❌ відсутній'}")
    print(f"    DMARC: {'✅ знайдено' if dmarc_found else '❌ відсутній'}")


if __name__ == "__main__":
    domains = sys.argv[1:] if len(sys.argv) > 1 else ["google.com", "diia.gov.ua"]
    for d in domains:
        audit_domain(d)
```

**Завдання:**
1. Запустіть для кількох українських держсайтів: `diia.gov.ua`, `kmu.gov.ua`, будь-якого банку. Чи є у них SPF і DMARC?
2. Запустіть для домену вашої організації або власного домену. Що можна покращити?

---

## Лабораторна 2.10.3: Аналіз HTTP-заголовків безпеки

Перевіряємо, чи правильно налаштовані заголовки безпеки на вебсайті.

```python
import urllib.request
import urllib.error
import ssl
from dataclasses import dataclass


@dataclass
class HeaderCheck:
    header: str
    description: str
    critical: bool  # True = Must, False = Should


SECURITY_HEADERS: list[HeaderCheck] = [
    HeaderCheck("Strict-Transport-Security", "Примусовий HTTPS (HSTS)", True),
    HeaderCheck("Content-Security-Policy", "Обмеження джерел вмісту (захист XSS)", True),
    HeaderCheck("X-Frame-Options", "Захист від clickjacking", True),
    HeaderCheck("X-Content-Type-Options", "Заборона MIME sniffing", True),
    HeaderCheck("Referrer-Policy", "Контроль передачі Referrer", False),
    HeaderCheck("Permissions-Policy", "Контроль дозволів браузера", False),
]


def check_headers(url: str) -> None:
    print(f"\nАналіз заголовків безпеки: {url}")
    print("-" * 60)

    ctx = ssl.create_default_context()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityAudit/1.0"})
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}

            for check in SECURITY_HEADERS:
                key = check.header.lower()
                level = "Must" if check.critical else "Should"
                if key in headers:
                    print(f"  ✅ [{level}] {check.header}")
                    print(f"       Значення: {headers[key][:80]}")
                else:
                    mark = "❌" if check.critical else "⚠️"
                    print(f"  {mark} [{level}] {check.header} — ВІДСУТНІЙ")
                    print(f"       {check.description}")

            # Перевірка чи не розкривається зайва інформація
            print("\n[Витік інформації]")
            for leak_header in ("server", "x-powered-by", "x-aspnet-version"):
                if leak_header in headers:
                    print(f"  ⚠️  {leak_header}: {headers[leak_header]} "
                          f"— розкриває технологічний стек")

    except urllib.error.URLError as e:
        print(f"  Помилка з'єднання: {e}")
    except Exception as e:
        print(f"  Помилка: {e}")


if __name__ == "__main__":
    sites = [
        "https://diia.gov.ua",
        "https://google.com",
        "https://cloudflare.com",
    ]
    for site in sites:
        check_headers(site)
```

**Завдання:**
1. Запустіть для кількох сайтів. Порівняйте результати: у яких найкраще налаштовані заголовки?
2. Додайте до списку будь-який сайт вашої організації або знайомого бізнесу. Які заголовки відсутні?

---

## Лабораторна 2.10.4: Базовий мережевий сніфер (потребує scapy)

Ця лабораторна демонструє, що саме «бачить» сніфер у мережі — і дає відповідь на важливе питання: чому DNS без DoH і незашифрований HTTP настільки небезпечні навіть у «звичайній» домашній мережі. Виконуйте **виключно** в домашній або лабораторній мережі, де ви маєте повне право на моніторинг трафіку.

**Встановлення:**
```bash
# Linux/macOS:
pip install scapy --break-system-packages
# Запуск: sudo python3 lab4_sniffer.py

# Windows: додатково потрібен Npcap (https://npcap.com) — встановіть ПЕРЕД scapy.
# Після встановлення Npcap:
# pip install scapy
# Запуск: від імені адміністратора у PowerShell
# Якщо scapy не бачить інтерфейс: python -c "from scapy.all import show_interfaces; show_interfaces()"
```

```python
# lab4_sniffer.py
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
from datetime import datetime


def packet_callback(pkt) -> None:
    """Обробляє кожен перехоплений пакет."""
    ts = datetime.now().strftime("%H:%M:%S")

    # DNS-запити: бачимо, які домени запитуються
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        if pkt[DNS].qr == 0:  # qr=0 — це запит, qr=1 — відповідь
            qname = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
            src = pkt[IP].src if pkt.haslayer(IP) else "?"
            print(f"[{ts}] DNS запит   {src:16s}  →  {qname}")

    # TCP-з'єднання: SYN-пакети — нові з'єднання
    elif pkt.haslayer(TCP) and pkt.haslayer(IP):
        flags = pkt[TCP].flags
        if "S" in str(flags) and "A" not in str(flags):  # SYN без ACK
            print(
                f"[{ts}] TCP SYN     "
                f"{pkt[IP].src}:{pkt[TCP].sport:5d}  →  "
                f"{pkt[IP].dst}:{pkt[TCP].dport}"
            )


if __name__ == "__main__":
    print("Мережевий сніфер запущено. Ctrl+C для зупинки.")
    print("Показуються DNS-запити та нові TCP-з'єднання.\n")
    print("-" * 70)

    # Перехоплення пакетів: filter = BPF-фільтр (той самий синтаксис, що в Wireshark)
    sniff(
        filter="udp port 53 or (tcp[tcpflags] & tcp-syn != 0)",
        prn=packet_callback,
        store=False,   # не зберігати в пам'яті — лише обробляти
        count=50,      # зупинитись після 50 пакетів
    )
```

**Завдання:**
1. Запустіть з правами sudo і відкрийте кілька сайтів у браузері. Бачите DNS-запити в реальному часі? Зверніть увагу: один сайт генерує десятки DNS-запитів до різних доменів — трекери, CDN, рекламні мережі, шрифти. Це і є «ціна» сучасного вебу з точки зору приватності.
2. Порівняйте з тим, що бачить Wireshark (якщо встановлений): відфільтруйте `dns` — результати мають збігатись.
3. Тепер уявіть: ця мережа — публічний Wi-Fi у кафе, і ви не використовуєте DoH. Ваш провайдер, адміністратор кафе або зловмисник з ноутбуком бачать точно такий самий список доменів. Паролі захищені HTTPS — але список сайтів, які ви відвідуєте, видно без жодного злому.

## Джерела та додаткові матеріали

- Scapy documentation (scapy.net) — повна документація бібліотеки.
- Wireshark (wireshark.org) — графічний аналізатор мережевого трафіку.
- Python `socket` module documentation (docs.python.org).

---

**Попередній розділ:** [2.9. Бездротові мережі та їх безпека](09-bezdrotovi-merezhi.md)
**Далі:** [2.11. Чек-лист і самоперевірка](11-chek-lyst-i-samoperevirka.md)
**Назад до модуля:** [README модуля 02](README.md)

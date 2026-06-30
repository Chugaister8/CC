# 10.10. Практична лабораторна на Python

Чотири лабораторні: простий пакетний сніфер для розуміння структури мережевих пакетів, детектор сканування портів через аналіз патернів з'єднань, детектор потенційного DNS tunneling за ентропією subdomain і аналізатор правил firewall на типові помилки конфігурації.

**Залежності:**
```bash
pip install scapy dnspython
```

> Лабораторні з захопленням пакетів (scapy) потребують прав адміністратора/root та мають використовуватись лише у власній мережі або з явним дозволом.

---

## Лабораторна 10.10.1: Простий Packet Sniffer

```python
"""
packet_sniffer.py — базовий аналізатор мережевих пакетів через scapy.
Демонструє структуру TCP/IP пакетів для навчальних цілей.
ВАЖЛИВО: запускати лише у власній мережі з правами адміністратора.
"""
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
from collections import defaultdict
from datetime import datetime


class PacketAnalyzer:
    def __init__(self):
        self.packet_count = 0
        self.protocol_stats = defaultdict(int)
        self.connections = defaultdict(int)
        self.dns_queries = []

    def process_packet(self, packet):
        self.packet_count += 1

        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst

            if TCP in packet:
                self.protocol_stats['TCP'] += 1
                conn_key = f"{src}:{packet[TCP].sport} -> {dst}:{packet[TCP].dport}"
                self.connections[conn_key] += 1

                # Виявлення можливих SYN-сканувань
                flags = packet[TCP].flags
                if flags == 'S':  # SYN без ACK
                    self._check_syn_scan(src, dst, packet[TCP].dport)

            elif UDP in packet:
                self.protocol_stats['UDP'] += 1

                if DNS in packet and packet.haslayer(DNS):
                    if packet[DNS].qd:
                        query_name = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
                        self.dns_queries.append({
                            'time': datetime.now().isoformat(),
                            'src': src,
                            'query': query_name
                        })
                        self._check_suspicious_dns(query_name)
            else:
                self.protocol_stats['Other'] += 1

        if self.packet_count % 50 == 0:
            print(f"  Оброблено {self.packet_count} пакетів...")

    def _check_syn_scan(self, src, dst, port):
        """Спрощена евристика виявлення потенційного сканування портів."""
        key = f"{src}->{dst}"
        if not hasattr(self, '_syn_tracker'):
            self._syn_tracker = defaultdict(set)
        self._syn_tracker[key].add(port)

        if len(self._syn_tracker[key]) > 10:
            print(f"  ⚠️  Можливе сканування портів: {src} -> {dst} "
                  f"({len(self._syn_tracker[key])} різних портів)")

    def _check_suspicious_dns(self, query_name: str):
        """Перевірка DNS-запиту на ознаки tunneling."""
        domain_part = query_name.rstrip('.')
        if len(domain_part) > 0:
            subdomain = domain_part.split('.')[0] if '.' in domain_part else domain_part
            if len(subdomain) > 50:
                print(f"  ⚠️  Підозріло довгий DNS subdomain ({len(subdomain)} символів): "
                      f"{query_name[:80]}...")

    def print_summary(self):
        print(f"\n{'='*55}")
        print(f"PACKET CAPTURE SUMMARY")
        print(f"{'='*55}")
        print(f"Всього пакетів: {self.packet_count}")
        print(f"\nПротоколи:")
        for proto, count in sorted(self.protocol_stats.items(), key=lambda x: -x[1]):
            print(f"  {proto}: {count}")

        print(f"\nТоп-10 з'єднань за кількістю пакетів:")
        top_conns = sorted(self.connections.items(), key=lambda x: -x[1])[:10]
        for conn, count in top_conns:
            print(f"  {conn}: {count} пакетів")

        if self.dns_queries:
            print(f"\nВсього DNS-запитів: {len(self.dns_queries)}")
            unique_domains = set(q['query'] for q in self.dns_queries)
            print(f"Унікальних доменів: {len(unique_domains)}")


def main():
    analyzer = PacketAnalyzer()

    print("Запуск захоплення пакетів (Ctrl+C для зупинки)...")
    print("УВАГА: потрібні права root/administrator\n")

    try:
        # count=0 означає безперервне захоплення до Ctrl+C
        sniff(prn=analyzer.process_packet, store=False, count=200)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("❌ Помилка: потрібні права root/administrator для захоплення пакетів")
        return

    analyzer.print_summary()


if __name__ == "__main__":
    main()
```

**Завдання:**
1. Запустіть скрипт з правами root/admin на 1-2 хвилини звичайної роботи в мережі.
2. Перегляньте розподіл протоколів — чи відповідає очікуванням (переважно TCP для веб-перегляду)?
3. Перевірте список унікальних DNS-доменів — чи є щось несподіване?

---

## Лабораторна 10.10.2: Port Scan Detector

```python
"""
port_scan_detector.py — детектор сканування портів через аналіз
послідовності з'єднань без необхідності live-захоплення (працює з логами).
"""
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta


@dataclass
class ConnectionAttempt:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    dst_port: int
    flags: str = "S"  # SYN за замовчуванням


@dataclass
class ScanAlert:
    src_ip: str
    dst_ip: str
    ports_scanned: list
    time_window: float
    scan_type: str


class PortScanDetector:
    """
    Виявляє типові патерни сканування портів:
    - Vertical scan: багато портів проти ОДНОГО хоста
    - Horizontal scan: ОДИН порт проти багатьох хостів
    - Block scan: комбінація (багато портів проти багатьох хостів)
    """

    def __init__(self, port_threshold: int = 15, time_window_seconds: int = 60):
        self.port_threshold = port_threshold
        self.time_window = timedelta(seconds=time_window_seconds)
        self.attempts: list[ConnectionAttempt] = []

    def add_attempt(self, attempt: ConnectionAttempt):
        self.attempts.append(attempt)

    def detect_vertical_scans(self) -> list[ScanAlert]:
        """Виявляє сканування багатьох портів проти одного хоста з одного джерела."""
        alerts = []
        grouped = defaultdict(list)

        for a in self.attempts:
            key = (a.src_ip, a.dst_ip)
            grouped[key].append(a)

        for (src, dst), attempts_list in grouped.items():
            attempts_list.sort(key=lambda x: x.timestamp)
            ports_in_window = set()
            window_start = attempts_list[0].timestamp

            for a in attempts_list:
                if a.timestamp - window_start > self.time_window:
                    # Перевірка чи накопичена кількість портів перевищує поріг
                    if len(ports_in_window) >= self.port_threshold:
                        alerts.append(ScanAlert(
                            src_ip=src, dst_ip=dst,
                            ports_scanned=sorted(ports_in_window),
                            time_window=self.time_window.total_seconds(),
                            scan_type='VERTICAL (port scan)'
                        ))
                    ports_in_window = set()
                    window_start = a.timestamp

                ports_in_window.add(a.dst_port)

            if len(ports_in_window) >= self.port_threshold:
                alerts.append(ScanAlert(
                    src_ip=src, dst_ip=dst,
                    ports_scanned=sorted(ports_in_window),
                    time_window=self.time_window.total_seconds(),
                    scan_type='VERTICAL (port scan)'
                ))

        return alerts

    def detect_horizontal_scans(self, host_threshold: int = 10) -> list[ScanAlert]:
        """Виявляє сканування одного порту проти багатьох хостів (мережева розвідка)."""
        alerts = []
        grouped = defaultdict(set)  # (src, port) -> set of dst hosts

        for a in self.attempts:
            key = (a.src_ip, a.dst_port)
            grouped[key].add(a.dst_ip)

        for (src, port), hosts in grouped.items():
            if len(hosts) >= host_threshold:
                alerts.append(ScanAlert(
                    src_ip=src, dst_ip=f"{len(hosts)} different hosts",
                    ports_scanned=[port],
                    time_window=0,
                    scan_type=f'HORIZONTAL (network sweep on port {port})'
                ))

        return alerts

    def print_report(self):
        vertical = self.detect_vertical_scans()
        horizontal = self.detect_horizontal_scans()

        print(f"\n{'='*55}")
        print(f"PORT SCAN DETECTION REPORT")
        print(f"{'='*55}")
        print(f"Проаналізовано спроб з'єднання: {len(self.attempts)}")

        if vertical:
            print(f"\n🔴 Виявлено VERTICAL SCANS ({len(vertical)}):")
            for alert in vertical:
                print(f"  {alert.src_ip} -> {alert.dst_ip}: "
                      f"{len(alert.ports_scanned)} портів за {alert.time_window}с")
                print(f"    Порти: {alert.ports_scanned[:15]}"
                      f"{'...' if len(alert.ports_scanned) > 15 else ''}")

        if horizontal:
            print(f"\n🟠 Виявлено HORIZONTAL SCANS ({len(horizontal)}):")
            for alert in horizontal:
                print(f"  {alert.src_ip}: {alert.scan_type}")

        if not vertical and not horizontal:
            print("\n✅ Підозрілих патернів сканування не виявлено")


def generate_test_data() -> PortScanDetector:
    """Генерує тестові дані, що імітують реальне сканування портів."""
    detector = PortScanDetector(port_threshold=10, time_window_seconds=60)

    base_time = datetime.now()
    # Імітація vertical scan: один атакуючий проти одного хоста, багато портів
    attacker_ip = "203.0.113.99"
    target_ip = "10.0.1.50"
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 8080, 8443]

    for i, port in enumerate(common_ports):
        detector.add_attempt(ConnectionAttempt(
            timestamp=base_time + timedelta(seconds=i*2),
            src_ip=attacker_ip, dst_ip=target_ip, dst_port=port
        ))

    # Імітація горизонтального сканування: один порт, багато хостів
    for i in range(15):
        detector.add_attempt(ConnectionAttempt(
            timestamp=base_time + timedelta(seconds=i),
            src_ip=attacker_ip, dst_ip=f"10.0.1.{60+i}", dst_port=22
        ))

    # Легітимний трафік (не повинен викликати alert)
    for i in range(5):
        detector.add_attempt(ConnectionAttempt(
            timestamp=base_time + timedelta(seconds=i*10),
            src_ip="10.0.1.5", dst_ip="93.184.216.34", dst_port=443
        ))

    return detector


if __name__ == "__main__":
    detector = generate_test_data()
    detector.print_report()
```

---

## Лабораторна 10.10.3: DNS Tunneling Detector

```python
"""
dns_tunneling_detector.py — детектор потенційного DNS tunneling
через аналіз ентропії та структури subdomain.
"""
import math
import re
from collections import defaultdict, Counter
from dataclasses import dataclass


@dataclass
class DNSQuery:
    query_name: str
    src_ip: str
    record_type: str = "A"


def calculate_entropy(s: str) -> float:
    """Обчислює ентропію Шеннона для рядка — висока ентропія = більш випадковий/закодований."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((count/length) * math.log2(count/length) for count in freq.values())


def extract_subdomain_label(query_name: str) -> str:
    """Витягує перший (найглибший) label з FQDN."""
    parts = query_name.rstrip('.').split('.')
    return parts[0] if parts else ''


class DNSTunnelingDetector:
    def __init__(self, entropy_threshold: float = 3.5, length_threshold: int = 40):
        self.entropy_threshold = entropy_threshold
        self.length_threshold = length_threshold
        self.queries: list[DNSQuery] = []
        self.domain_query_count = defaultdict(int)
        self.domain_query_volume = defaultdict(int)  # загальний обсяг байтів запитів

    def add_query(self, query: DNSQuery):
        self.queries.append(query)
        domain = self._extract_base_domain(query.query_name)
        self.domain_query_count[domain] += 1
        self.domain_query_volume[domain] += len(query.query_name)

    @staticmethod
    def _extract_base_domain(query_name: str) -> str:
        """Спрощене витягання базового домену (останні 2 labels)."""
        parts = query_name.rstrip('.').split('.')
        return '.'.join(parts[-2:]) if len(parts) >= 2 else query_name

    def analyze(self) -> list[dict]:
        findings = []

        for query in self.queries:
            subdomain = extract_subdomain_label(query.query_name)
            indicators = []

            # 1. Довжина subdomain
            if len(subdomain) > self.length_threshold:
                indicators.append(f"Довгий subdomain ({len(subdomain)} символів)")

            # 2. Ентропія (висока = схоже на закодовані дані base64/hex)
            entropy = calculate_entropy(subdomain)
            if entropy > self.entropy_threshold:
                indicators.append(f"Висока ентропія ({entropy:.2f})")

            # 3. Base64/Hex-подібний патерн
            if re.match(r'^[A-Za-z0-9+/=]{30,}$', subdomain):
                indicators.append("Схоже на base64-кодування")
            elif re.match(r'^[0-9a-fA-F]{30,}$', subdomain):
                indicators.append("Схоже на hex-кодування")

            # 4. Незвичний тип запису (TXT часто використовується для tunneling - більше даних)
            if query.record_type in ('TXT', 'NULL'):
                indicators.append(f"Нетиповий тип запису ({query.record_type})")

            if indicators:
                findings.append({
                    'query': query.query_name,
                    'src_ip': query.src_ip,
                    'indicators': indicators,
                    'risk_score': len(indicators)
                })

        return sorted(findings, key=lambda x: -x['risk_score'])

    def analyze_volume_anomalies(self, threshold: int = 50) -> list[dict]:
        """Виявляє домени з аномально високою кількістю запитів (можлива ексфільтрація)."""
        anomalies = []
        for domain, count in self.domain_query_count.items():
            if count >= threshold:
                anomalies.append({
                    'domain': domain,
                    'query_count': count,
                    'total_bytes_sent': self.domain_query_volume[domain],
                })
        return sorted(anomalies, key=lambda x: -x['query_count'])

    def print_report(self):
        findings = self.analyze()
        volume_anomalies = self.analyze_volume_anomalies()

        print(f"\n{'='*55}")
        print(f"DNS TUNNELING DETECTION REPORT")
        print(f"{'='*55}")
        print(f"Проаналізовано DNS-запитів: {len(self.queries)}")

        if findings:
            print(f"\n🔴 Підозрілі запити ({len(findings)}):")
            for f in findings[:10]:
                print(f"\n  Query: {f['query'][:70]}...")
                print(f"  Src: {f['src_ip']} | Risk Score: {f['risk_score']}")
                for ind in f['indicators']:
                    print(f"    - {ind}")

        if volume_anomalies:
            print(f"\n🟠 Домени з аномальним обсягом запитів:")
            for a in volume_anomalies:
                print(f"  {a['domain']}: {a['query_count']} запитів, "
                      f"{a['total_bytes_sent']} байт сумарно")

        if not findings and not volume_anomalies:
            print("\n✅ Ознак DNS tunneling не виявлено")


def generate_test_queries() -> DNSTunnelingDetector:
    """Генерує тестові дані з імітацією DNS tunneling та нормального трафіку."""
    detector = DNSTunnelingDetector()

    # Імітація DNS tunneling (base64-кодовані дані як subdomain)
    tunneling_payloads = [
        "dGhpcyBpcyBhIHRlc3Qgb2YgZG5zIHR1bm5lbGluZw",
        "ZXhmaWx0cmF0ZWQgZGF0YSBjaHVuayBudW1iZXIgdHdv",
        "bW9yZSBzdG9sZW4gZGF0YSBnb2VzIGhlcmUgYW5kIGhlcmU",
    ]
    for payload in tunneling_payloads:
        detector.add_query(DNSQuery(
            query_name=f"{payload}.attacker-c2.com",
            src_ip="10.0.1.42",
            record_type="TXT"
        ))

    # Нормальний DNS-трафік
    normal_domains = ["google.com", "github.com", "stackoverflow.com", "wikipedia.org"]
    for domain in normal_domains:
        detector.add_query(DNSQuery(query_name=domain, src_ip="10.0.1.10"))

    return detector


if __name__ == "__main__":
    detector = generate_test_queries()
    detector.print_report()
```

---

## Лабораторна 10.10.4: Firewall Rule Analyzer

```python
"""
firewall_rule_analyzer.py — аналіз правил firewall на типові помилки конфігурації.
Працює з спрощеним JSON-форматом правил (адаптуйте під свій firewall).
"""
import json
from dataclasses import dataclass


@dataclass
class FirewallRule:
    rule_id: str
    action: str  # ALLOW / DENY
    source: str
    destination: str
    port: str
    protocol: str
    enabled: bool = True
    description: str = ""


RISKY_PORTS = {
    22: "SSH", 23: "Telnet", 3389: "RDP",
    3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB",
    1433: "MSSQL", 6379: "Redis", 9200: "Elasticsearch",
}


def analyze_rules(rules: list[FirewallRule]) -> list[dict]:
    findings = []

    for rule in rules:
        if not rule.enabled or rule.action != 'ALLOW':
            continue

        # 1. Перевірка на 0.0.0.0/0 (any) джерело для чутливих портів
        if rule.source in ('0.0.0.0/0', 'any', '*'):
            port_num = _extract_port_number(rule.port)
            if port_num in RISKY_PORTS:
                findings.append({
                    'severity': 'CRITICAL',
                    'rule_id': rule.rule_id,
                    'issue': f'{RISKY_PORTS[port_num]} (порт {port_num}) відкритий для всього інтернету',
                    'recommendation': 'Обмежити source до конкретних IP/підмереж'
                })

        # 2. Правило ANY-ANY-ANY (надмірно широке)
        if (rule.source in ('0.0.0.0/0', 'any', '*') and
            rule.destination in ('0.0.0.0/0', 'any', '*') and
            rule.port in ('any', '*', '0-65535')):
            findings.append({
                'severity': 'CRITICAL',
                'rule_id': rule.rule_id,
                'issue': 'Правило ANY-ANY-ANY дозволяє весь трафік без обмежень',
                'recommendation': 'Замінити на конкретні правила за принципом найменших привілеїв'
            })

        # 3. Відсутність опису (проблема управління, не безпосередньо безпеки)
        if not rule.description.strip():
            findings.append({
                'severity': 'LOW',
                'rule_id': rule.rule_id,
                'issue': 'Правило без опису — складно аудитувати призначення',
                'recommendation': 'Додати опис з обґрунтуванням і власником правила'
            })

        # 4. Telnet взагалі (застарілий, незашифрований протокол)
        port_num = _extract_port_number(rule.port)
        if port_num == 23:
            findings.append({
                'severity': 'HIGH',
                'rule_id': rule.rule_id,
                'issue': 'Telnet (порт 23) дозволений — незашифрований протокол',
                'recommendation': 'Замінити на SSH (порт 22) з ключовою автентифікацією'
            })

    return findings


def _extract_port_number(port_str: str) -> int | None:
    """Витягує перший номер порту з рядка (підтримує діапазони типу '80-443')."""
    try:
        return int(port_str.split('-')[0])
    except (ValueError, AttributeError):
        return None


def find_shadowed_rules(rules: list[FirewallRule]) -> list[dict]:
    """
    Спрощене виявлення "затінених" правил —
    правило, що ніколи не спрацює через ширше попереднє правило DENY.
    """
    shadowed = []
    deny_all_seen = False

    for i, rule in enumerate(rules):
        if deny_all_seen and rule.action == 'ALLOW':
            shadowed.append({
                'rule_id': rule.rule_id,
                'issue': f'Правило йде ПІСЛЯ DENY-ALL правила — ніколи не спрацює',
                'position': i
            })

        if (rule.action == 'DENY' and
            rule.source in ('0.0.0.0/0', 'any', '*') and
            rule.destination in ('0.0.0.0/0', 'any', '*')):
            deny_all_seen = True

    return shadowed


def print_analysis(findings: list[dict], shadowed: list[dict]):
    ICONS = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}

    print(f"\n{'='*55}")
    print(f"FIREWALL RULE ANALYSIS")
    print(f"{'='*55}")

    if findings:
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            sev_findings = [f for f in findings if f['severity'] == sev]
            if sev_findings:
                print(f"\n{ICONS[sev]} {sev} ({len(sev_findings)}):")
                for f in sev_findings:
                    print(f"  [{f['rule_id']}] {f['issue']}")
                    print(f"    → {f['recommendation']}")
    else:
        print("\n✅ Критичних проблем не виявлено")

    if shadowed:
        print(f"\n⚠️  Затінені правила ({len(shadowed)}):")
        for s in shadowed:
            print(f"  [{s['rule_id']}] {s['issue']}")


if __name__ == "__main__":
    # Тестовий набір правил з типовими помилками
    test_rules = [
        FirewallRule("FW-001", "ALLOW", "0.0.0.0/0", "10.0.1.50", "22", "TCP",
                     description="SSH доступ"),  # CRITICAL: SSH відкритий для всіх
        FirewallRule("FW-002", "ALLOW", "203.0.113.0/24", "10.0.1.0/24", "443", "TCP",
                     description="HTTPS з офісу"),  # OK
        FirewallRule("FW-003", "ALLOW", "any", "any", "any", "any",
                     description=""),  # CRITICAL: ANY-ANY-ANY
        FirewallRule("FW-004", "ALLOW", "10.0.1.0/24", "10.0.2.5", "23", "TCP",
                     description="Legacy telnet access"),  # HIGH: Telnet
        FirewallRule("FW-005", "ALLOW", "10.0.1.0/24", "10.0.2.10", "443", "TCP"),
                     # LOW: без опису
    ]

    findings = analyze_rules(test_rules)
    shadowed = find_shadowed_rules(test_rules)
    print_analysis(findings, shadowed)
```

## Джерела та додаткові матеріали

- Scapy documentation (scapy.readthedocs.io).
- dnspython (dnspython.org).
- SANS, *Intrusion Detection FAQ*.
- NIST SP 800-94 — Guide to Intrusion Detection and Prevention Systems.

---

**Попередній розділ:** [10.9. Моніторинг мережі](09-monitorynh-merezhi.md)
**Далі:** [10.11. Чек-лист і самоперевірка](11-chek-lyst-i-samoperevirka.md)
**Назад до модуля:** [README модуля 10](README.md)

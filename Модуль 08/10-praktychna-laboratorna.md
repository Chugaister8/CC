# 8.10. Практична лабораторна на Python

Чотири лабораторні, що охоплюють практичну роботу з IoT і мобільною безпекою: сканер IoT-пристроїв у мережі, аналізатор MQTT-трафіку, перевірник безпеки мобільних застосунків і пошук CVE для конкретних пристроїв.

**Залежності:**
```bash
pip install python-nmap paho-mqtt requests
```

---

## Лабораторна 8.10.1: IoT Network Scanner

Виявляє IoT-пристрої у мережі та перевіряє типові вразливі сервіси.

```python
"""
iot_scanner.py — сканер IoT-пристроїв у локальній мережі.
ВАЖЛИВО: запускайте лише у власній мережі або з явним дозволом.
"""
import socket
import ipaddress
import concurrent.futures
from dataclasses import dataclass, field


# Порти, характерні для IoT пристроїв
IOT_PORTS = {
    23: "Telnet (НЕБЕЗПЕЧНО — відкритий текст, часто дефолтні паролі)",
    80: "HTTP Web Interface",
    81: "Alternative HTTP",
    443: "HTTPS Web Interface",
    554: "RTSP (IP camera stream)",
    1883: "MQTT (незашифрований!)",
    4786: "Cisco Smart Install",
    5000: "UPnP / Sonos",
    5683: "CoAP (IoT protocol)",
    7547: "CWMP/TR-069 (Remote Mgmt)",
    8080: "HTTP Alt / Camera UI",
    8443: "HTTPS Alt",
    8883: "MQTT over TLS",
    9100: "Printer (RAW)",
    49152: "UPnP",
}

# Порти з критичним ризиком
CRITICAL_PORTS = {23, 1883, 4786, 7547}


@dataclass
class IoTDevice:
    ip: str
    hostname: str = ""
    open_ports: dict = field(default_factory=dict)  # port → service
    risk_level: str = "LOW"
    warnings: list = field(default_factory=list)


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def check_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    """Перевіряє чи відкритий порт."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except Exception:
        return False


def scan_host(ip: str) -> IoTDevice | None:
    """Сканує один хост на IoT-порти."""
    # Спочатку перевірити чи хост взагалі відповідає
    if not check_port(ip, 80) and not check_port(ip, 443) and not check_port(ip, 22):
        # Швидка перевірка через ping-like TCP probe
        is_up = any(check_port(ip, p) for p in [23, 554, 1883, 8080])
        if not is_up:
            return None

    device = IoTDevice(ip=ip)
    device.hostname = resolve_hostname(ip)

    # Перевірити всі IoT-порти
    for port, service in IOT_PORTS.items():
        if check_port(ip, port):
            device.open_ports[port] = service
            if port in CRITICAL_PORTS:
                device.warnings.append(
                    f"⚠️  Критичний порт {port} ({service.split(' ')[0]}) відкритий!"
                )

    if not device.open_ports:
        return None

    # Визначити рівень ризику
    critical_count = sum(1 for p in device.open_ports if p in CRITICAL_PORTS)
    if critical_count >= 2:
        device.risk_level = "CRITICAL"
    elif critical_count == 1:
        device.risk_level = "HIGH"
    elif len(device.open_ports) > 3:
        device.risk_level = "MEDIUM"

    # Специфічні попередження
    if 23 in device.open_ports:
        device.warnings.append("🔴 Telnet відкритий — замініть на SSH!")
    if 1883 in device.open_ports and 8883 not in device.open_ports:
        device.warnings.append("🔴 MQTT без TLS — весь трафік у відкритому вигляді!")
    if 554 in device.open_ports:
        device.warnings.append("📹 IP Camera виявлена — перевірте автентифікацію!")

    return device


def scan_network(network: str, max_workers: int = 50) -> list[IoTDevice]:
    """Сканує всю підмережу в паралельному режимі."""
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        print(f"Невірна мережа: {e}")
        return []

    hosts = list(net.hosts())
    print(f"Сканування {len(hosts)} хостів у {network}...")

    devices = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_host, str(ip)): str(ip) for ip in hosts}
        completed = 0
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            if completed % 20 == 0:
                print(f"  Перевірено {completed}/{len(hosts)} хостів...")
            result = future.result()
            if result:
                devices.append(result)

    return sorted(devices, key=lambda d: (d.risk_level == 'CRITICAL', d.risk_level == 'HIGH'), reverse=True)


def print_report(devices: list[IoTDevice]) -> None:
    RISK_ICONS = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}

    print(f"\n{'='*60}")
    print(f"IoT SECURITY SCAN REPORT")
    print(f"{'='*60}")
    print(f"Виявлено пристроїв: {len(devices)}")

    risk_counts = {}
    for d in devices:
        risk_counts[d.risk_level] = risk_counts.get(d.risk_level, 0) + 1
    for level, count in sorted(risk_counts.items()):
        print(f"  {RISK_ICONS.get(level, '?')} {level}: {count}")

    print(f"\nДеталі:")
    for device in devices:
        icon = RISK_ICONS.get(device.risk_level, '?')
        hostname = f" ({device.hostname})" if device.hostname else ""
        print(f"\n  {icon} {device.ip}{hostname} [{device.risk_level}]")
        for port, service in sorted(device.open_ports.items()):
            print(f"    Port {port:>5}: {service}")
        for warning in device.warnings:
            print(f"    {warning}")


if __name__ == "__main__":
    import sys

    # Виявити поточну мережу
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        # Припустити /24 підмережу
        network = '.'.join(local_ip.split('.')[:3]) + '.0/24'
    except Exception:
        network = "192.168.1.0/24"

    if len(sys.argv) > 1:
        network = sys.argv[1]

    print(f"Ваша мережа: {network}")
    print("УВАГА: сканування лише ВЛАСНОЇ мережі або з дозволу!\n")

    devices = scan_network(network)
    print_report(devices)
```

**Завдання:**
1. Запустіть скрипт у своїй домашній або навчальній мережі.
2. Скільки IoT-пристроїв знайдено? Чи є відкриті критичні порти?
3. Перевірте кожен виявлений пристрій — чи знаєте ви що це таке?

---

## Лабораторна 8.10.2: MQTT Security Analyzer

```python
"""
mqtt_analyzer.py — перевірка безпеки MQTT брокера.
Тестує анонімний доступ, wildcard subscriptions і TLS.
"""
import socket
import ssl
import struct
import time


class MQTTSecurityChecker:
    """Перевіряє безпеку MQTT брокера (для власної інфраструктури!)."""

    def __init__(self, host: str, port: int = 1883):
        self.host = host
        self.port = port
        self.findings = []

    def _check_port_open(self) -> bool:
        try:
            with socket.create_connection((self.host, self.port), timeout=3):
                return True
        except (ConnectionRefusedError, socket.timeout, OSError):
            return False

    def check_anonymous_access(self) -> bool:
        """Перевіряє чи дозволений анонімний доступ."""
        try:
            # Мінімальний MQTT CONNECT пакет без username/password
            # Fixed header: CONNECT (0x10), remaining length
            connect_flags = 0x02  # Clean Session, без username/password
            payload = struct.pack(
                '!H4sBBH',
                4, b'MQTT',  # Protocol Name
                4,            # Protocol Level (MQTT 3.1.1)
                connect_flags,
                60            # Keep Alive (60 seconds)
            ) + struct.pack('!H', 7) + b'test123'  # Client ID

            remaining_len = len(payload)
            header = bytes([0x10, remaining_len])

            with socket.create_connection((self.host, self.port), timeout=3) as sock:
                sock.send(header + payload)
                response = sock.recv(4)

                if len(response) >= 4 and response[0] == 0x20:  # CONNACK
                    return_code = response[3]
                    if return_code == 0:  # Connection Accepted
                        self.findings.append({
                            'severity': 'CRITICAL',
                            'check': 'Анонімний доступ',
                            'result': 'ВРАЗЛИВІСТЬ: брокер дозволяє підключення без автентифікації!'
                        })
                        return True
                    else:
                        self.findings.append({
                            'severity': 'INFO',
                            'check': 'Анонімний доступ',
                            'result': f'Захищено: автентифікація вимагається (code={return_code})'
                        })
        except Exception as e:
            self.findings.append({
                'severity': 'INFO',
                'check': 'Анонімний доступ',
                'result': f'Не вдалось перевірити: {e}'
            })
        return False

    def check_tls_available(self) -> bool:
        """Перевіряє чи є MQTT over TLS (порт 8883)."""
        tls_port = 8883
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.host, tls_port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    self.findings.append({
                        'severity': 'INFO',
                        'check': 'TLS підтримка',
                        'result': f'✅ MQTT/TLS доступний на порту {tls_port}'
                    })
                    return True
        except Exception:
            # Якщо порт 1883 відкритий, але 8883 ні — проблема
            if self.port == 1883:
                self.findings.append({
                    'severity': 'HIGH',
                    'check': 'TLS підтримка',
                    'result': f'⚠️ MQTT/TLS недоступний — весь трафік у відкритому вигляді!'
                })
            return False

    def run_all_checks(self) -> None:
        print(f"\n{'='*50}")
        print(f"MQTT Security Check: {self.host}:{self.port}")
        print(f"{'='*50}")

        if not self._check_port_open():
            print(f"❌ Порт {self.port} недоступний")
            return

        print(f"✅ Порт {self.port} відкритий")
        self.check_anonymous_access()
        self.check_tls_available()

        # Вивести результати
        print("\nРезультати:")
        ICONS = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'INFO': 'ℹ️ '}
        for finding in self.findings:
            icon = ICONS.get(finding['severity'], '?')
            print(f"  {icon} [{finding['severity']}] {finding['check']}")
            print(f"     {finding['result']}")


if __name__ == "__main__":
    # Тест локального брокера
    checker = MQTTSecurityChecker("localhost", 1883)
    checker.run_all_checks()
```

---

## Лабораторна 8.10.3: CVE Lookup для IoT пристроїв

```python
"""
iot_cve_checker.py — пошук відомих CVE для IoT пристроїв через NVD API.
Допомагає визначити чи потребує пристрій оновлення прошивки.
"""
import urllib.request
import json
import urllib.parse


def search_nvd_cves(product: str, version: str = "", max_results: int = 10) -> list[dict]:
    """
    Шукає CVE у National Vulnerability Database (NVD) для конкретного продукту.
    """
    query = urllib.parse.quote(product)
    url = (
        f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?keywordSearch={query}"
        f"&resultsPerPage={max_results}"
    )

    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'IoT-CVE-Checker/1.0'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        cves = []
        for item in data.get('vulnerabilities', []):
            cve = item.get('cve', {})
            metrics = cve.get('metrics', {})
            cvss_data = (
                metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}) or
                metrics.get('cvssMetricV30', [{}])[0].get('cvssData', {}) or
                metrics.get('cvssMetricV2', [{}])[0].get('cvssData', {})
            )
            cves.append({
                'id': cve.get('id'),
                'score': cvss_data.get('baseScore', 'N/A'),
                'severity': cvss_data.get('baseSeverity', 'UNKNOWN'),
                'description': cve.get('descriptions', [{}])[0].get('value', '')[:200],
                'published': cve.get('published', '')[:10],
            })
        return sorted(cves, key=lambda x: float(x['score']) if isinstance(x['score'], (int, float)) else 0, reverse=True)

    except Exception as e:
        print(f"Помилка запиту NVD: {e}")
        return []


def check_device_cves(device_name: str, firmware_version: str = "") -> None:
    print(f"\n{'='*55}")
    print(f"CVE перевірка: {device_name} {firmware_version}")
    print(f"{'='*55}")

    cves = search_nvd_cves(device_name, firmware_version)

    if not cves:
        print("✅ CVE не знайдено або API недоступний")
        return

    critical = [c for c in cves if c['severity'] in ('CRITICAL', 'HIGH')]
    print(f"Знайдено CVE: {len(cves)} (критичних/серйозних: {len(critical)})")

    SICONS = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'UNKNOWN': '❓'}
    for cve in cves[:5]:
        icon = SICONS.get(cve['severity'], '?')
        print(f"\n  {icon} {cve['id']} | Score: {cve['score']} | {cve['severity']}")
        print(f"     Дата: {cve['published']}")
        print(f"     {cve['description'][:120]}...")

    if len(cves) > 5:
        print(f"\n  ... та ще {len(cves) - 5} CVE. Перевірте https://nvd.nist.gov/")


if __name__ == "__main__":
    # Перевірте відомі IoT продукти
    devices_to_check = [
        ("Hikvision IP Camera", "V5.5.0"),
        ("Mikrotik RouterOS", "6.48"),
        ("D-Link DIR-825", ""),
    ]
    for device, version in devices_to_check:
        check_device_cves(device, version)
        import time; time.sleep(1)  # NVD rate limit
```

---

## Лабораторна 8.10.4: Mobile App Security Checker

```python
"""
mobile_app_checker.py — статичний аналіз безпеки AndroidManifest.xml.
Виявляє небезпечні дозволи і конфігурації без встановлення застосунку.
"""
import re
from pathlib import Path


# Дозволи, що вимагають особливої уваги
DANGEROUS_PERMISSIONS = {
    'android.permission.READ_CALL_LOG': ('HIGH', 'Читання журналу дзвінків'),
    'android.permission.WRITE_CALL_LOG': ('HIGH', 'Запис у журнал дзвінків'),
    'android.permission.READ_SMS': ('HIGH', 'Читання SMS — може перехоплювати OTP!'),
    'android.permission.RECEIVE_SMS': ('HIGH', 'Отримання SMS'),
    'android.permission.SEND_SMS': ('HIGH', 'Відправлення SMS'),
    'android.permission.RECORD_AUDIO': ('HIGH', 'Запис аудіо (мікрофон)'),
    'android.permission.CAMERA': ('MEDIUM', 'Доступ до камери'),
    'android.permission.ACCESS_FINE_LOCATION': ('MEDIUM', 'Точна геолокація'),
    'android.permission.ACCESS_BACKGROUND_LOCATION': ('HIGH', 'Геолокація у фоні — слідкування?'),
    'android.permission.PROCESS_OUTGOING_CALLS': ('HIGH', 'Перехоплення/перенаправлення дзвінків'),
    'android.permission.READ_CONTACTS': ('MEDIUM', 'Читання контактів'),
    'android.permission.WRITE_CONTACTS': ('MEDIUM', 'Запис до контактів'),
    'android.permission.GET_ACCOUNTS': ('MEDIUM', 'Список облікових записів пристрою'),
    'android.permission.REQUEST_INSTALL_PACKAGES': ('HIGH', 'Встановлення застосунків!'),
    'android.permission.SYSTEM_ALERT_WINDOW': ('HIGH', 'Відображення поверх інших застосунків — overlay attack!'),
    'android.permission.BIND_ACCESSIBILITY_SERVICE': ('HIGH', 'Accessibility — може читати екран, симулювати кліки!'),
    'android.permission.BIND_DEVICE_ADMIN': ('CRITICAL', 'Device Admin — повний контроль пристрою!'),
    'android.permission.MANAGE_EXTERNAL_STORAGE': ('HIGH', 'Повний доступ до файлів'),
    'android.permission.READ_PHONE_STATE': ('MEDIUM', 'IMEI, номер телефону, стан мережі'),
}

SECURITY_FLAGS = {
    'android:allowBackup="true"': ('MEDIUM', 'allowBackup=true — дані копіюються незашифровано через ADB backup'),
    'android:debuggable="true"': ('CRITICAL', 'debuggable=true — застосунок відлагоджується! НЕ для production!'),
    'android:exported="true"': ('LOW', 'Компонент exported — доступний іншим застосункам'),
    'android:usesCleartextTraffic="true"': ('HIGH', 'usesCleartextTraffic=true — HTTP дозволено!'),
}


def analyze_manifest(manifest_path: str) -> dict:
    """Аналізує AndroidManifest.xml на потенційні проблеми безпеки."""
    try:
        content = Path(manifest_path).read_text(encoding='utf-8', errors='replace')
    except FileNotFoundError:
        return {'error': f'Файл не знайдено: {manifest_path}'}

    findings = {'permissions': [], 'flags': [], 'summary': {}}

    # Перевірка дозволів
    for perm, (severity, desc) in DANGEROUS_PERMISSIONS.items():
        if perm in content:
            findings['permissions'].append({
                'permission': perm.split('.')[-1],
                'severity': severity,
                'description': desc
            })

    # Перевірка прапорів конфігурації
    for flag, (severity, desc) in SECURITY_FLAGS.items():
        if flag in content:
            findings['flags'].append({
                'flag': flag.split('"')[0].replace('android:', '').strip(),
                'severity': severity,
                'description': desc
            })

    # Підрахунок
    findings['summary'] = {
        'total_issues': len(findings['permissions']) + len(findings['flags']),
        'critical': sum(1 for p in findings['permissions'] + findings['flags']
                       if p.get('severity') == 'CRITICAL'),
        'high': sum(1 for p in findings['permissions'] + findings['flags']
                   if p.get('severity') == 'HIGH'),
    }
    return findings


def print_manifest_report(findings: dict) -> None:
    if 'error' in findings:
        print(f"Помилка: {findings['error']}")
        return

    ICONS = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
    s = findings['summary']
    print(f"\n{'='*55}")
    print(f"AndroidManifest.xml Security Analysis")
    print(f"{'='*55}")
    print(f"Загалом знахідок: {s['total_issues']} "
          f"(критичних: {s['critical']}, серйозних: {s['high']})")

    if findings['permissions']:
        print(f"\n📋 Дозволи ({len(findings['permissions'])}):")
        for p in sorted(findings['permissions'], key=lambda x: x['severity']):
            icon = ICONS.get(p['severity'], '?')
            print(f"  {icon} [{p['severity']}] {p['permission']}")
            print(f"       {p['description']}")

    if findings['flags']:
        print(f"\n⚙️  Конфігурація ({len(findings['flags'])}):")
        for f in findings['flags']:
            icon = ICONS.get(f['severity'], '?')
            print(f"  {icon} [{f['severity']}] {f['flag']}")
            print(f"       {f['description']}")


# Тест з прикладом маніфесту
EXAMPLE_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.suspicious">
    <uses-permission android:name="android.permission.READ_SMS"/>
    <uses-permission android:name="android.permission.RECORD_AUDIO"/>
    <uses-permission android:name="android.permission.ACCESS_BACKGROUND_LOCATION"/>
    <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
    <uses-permission android:name="android.permission.CAMERA"/>
    <application
        android:allowBackup="true"
        android:debuggable="true"
        android:usesCleartextTraffic="true">
    </application>
</manifest>"""

if __name__ == "__main__":
    import tempfile, os

    # Зберегти приклад у тимчасовий файл
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        f.write(EXAMPLE_MANIFEST)
        temp_path = f.name

    findings = analyze_manifest(temp_path)
    print_manifest_report(findings)
    os.unlink(temp_path)
```

## Джерела та додаткові матеріали

- NVD API (nvd.nist.gov/developers) — National Vulnerability Database.
- paho-mqtt (github.com/eclipse/paho.mqtt.python) — MQTT для Python.
- OWASP MobSF (github.com/MobSF/Mobile-Security-Framework-MobSF) — повний мобільний аналізатор.
- python-nmap (xael.org/pages/python-nmap-en.html) — Nmap Python wrapper.

---

**Попередній розділ:** [8.9. Захист IoT-інфраструктури](09-zakhyst-iot.md)
**Далі:** [8.11. Чек-лист і самоперевірка](11-chek-lyst-i-samoperevirka.md)
**Назад до модуля:** [README модуля 08](README.md)

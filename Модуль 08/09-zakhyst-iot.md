# 8.9. Захист IoT-інфраструктури: сегментація і моніторинг

IoT-пристрій — найслабша ланка будь-якої мережі. IP-камера, розумна лампочка або принтер із застарілою прошивкою стають плацдармом для lateral movement у всю корпоративну мережу. Ізоляція IoT від критичних систем і постійний моніторинг — мінімально необхідний рівень захисту, що не потребує жодних спеціалізованих IoT-рішень і доступний будь-якій організації.

> 📖 Ключові терміни — у [глосарії модуля](00-glosariy.md).

## VLAN-сегментація для IoT

**VLAN (Virtual LAN)** — логічне розділення мережі на ізольовані сегменти на рівні комутатора. IoT-пристрої в окремому VLAN не можуть безпосередньо спілкуватись з корпоративними ПК.

**Рекомендована архітектура:**

```
VLAN 10: Corporate (ПК, ноутбуки, сервери) — 192.168.10.0/24
VLAN 20: IoT / OT (камери, принтери, розумні пристрої) — 192.168.20.0/24
VLAN 30: Guest Wi-Fi (гості) — 192.168.30.0/24
VLAN 40: SCADA / Industrial (якщо є) — 10.0.40.0/24

Firewall Rules між VLAN:
  VLAN 20 → Internet: ALLOW (IoT потребує хмарного зв'язку)
  VLAN 20 → VLAN 10: DENY ALL (IoT не має доступу до корп. мережі)
  VLAN 10 → VLAN 20: ALLOW specific (адміни можуть керувати IoT)
  VLAN 30 → VLAN 10: DENY ALL
  VLAN 30 → VLAN 20: DENY ALL
```

**Реалізація на Cisco IOS:**

```
! Створення VLAN
vlan 20
 name IoT-Devices

! Налаштування інтерфейсу для IoT пристроїв
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan 20
 spanning-tree portfast       ! для швидкого підключення
 ip dhcp snooping limit rate 10

! SVI (Switched Virtual Interface) для VLAN 20
interface Vlan20
 ip address 192.168.20.1 255.255.255.0
 ip helper-address 192.168.10.1  ! DHCP server у корп. мережі

! ACL для заборони IoT→Corporate трафіку
ip access-list extended BLOCK-IOT-TO-CORP
 deny ip 192.168.20.0 0.0.0.255 192.168.10.0 0.0.0.255
 permit ip any any

interface Vlan20
 ip access-group BLOCK-IOT-TO-CORP in
```

**pfSense / OPNsense (для SOHO/SMB):**
```
Interfaces → VLANs → Add:
  Parent: em0 (або ваш інтерфейс)
  VLAN Tag: 20
  Description: IoT

Firewall → Rules → IoT:
  Action: Block | Protocol: any | Source: IoT net | Destination: LAN net
  Description: Block IoT to Corporate LAN
```

---

## Інвентаризація IoT-пристроїв

**Перший крок захисту — знати що підключено.** У більшості організацій немає повного переліку IoT пристроїв у мережі.

**Пасивне виявлення (без впливу на пристрої):**

```bash
# Nmap пасивне виявлення (power users — може бути помітним)
nmap -sn 192.168.20.0/24 -oX iot_hosts.xml

# ARP-сканування (тихіше)
arp-scan 192.168.20.0/24
# або
ip neigh show

# Passiv DNS через DHCP логи (якщо є)
grep "DHCPACK" /var/log/dhcpd.log | awk '{print $7, $9}' | sort -u
```

**Shodan для власних IP (зовнішня перевірка):**
```python
import shodan
api = shodan.Shodan('YOUR_API_KEY')

# Перевірте чи ваш публічний IP у Shodan
result = api.host('your_public_ip')
for item in result.get('data', []):
    print(f"Port {item['port']}: {item.get('product', 'unknown')}")
```

---

## IoT Network Access Control (NAC)

**NAC** — система, що контролює доступ пристроїв до мережі на основі їх ідентифікації і стану:

1. **Device Fingerprinting** — ідентифікація типу пристрою за MAC, DHCP options, User-Agent, Bonjour/mDNS.
2. **Policy-based Access** — IoT-камера автоматично потрапляє в VLAN 20; ноутбук — в VLAN 10.
3. **Compliance Check** — пристрій без актуальної прошивки → карантинний VLAN.

**Рішення NAC:** Cisco ISE, Aruba ClearPass, ForeScout, PacketFence (open-source).

---

## Моніторинг IoT-трафіку

**Аномальна поведінка IoT:**
- IP-камера надсилає дані на зовнішній IP о 3:00 ночі.
- Температурний сенсор намагається підключитись до SSH.
- MQTT брокер отримує підписки з незнайомих IP.
- Різке зростання DNS-запитів від одного пристрою.

**SIEM-запити для IoT моніторингу:**

```
# Kibana / Elastic: виявлення аномальних IoT підключень
index: network-*
query:
  source_ip: 192.168.20.0/24  (IoT VLAN)
  destination_port: NOT IN [80, 443, 1883, 8883, 5683]
  NOT destination_ip: [відомі легітимні IoT cloud endpoints]

# Suricata правило для підозрілого MQTT
alert mqtt any any -> any 1883 (
  msg:"MQTT Anonymous Access";
  content:"|10|"; offset:0; depth:1;  ! MQTT CONNECT packet type
  content:"|00 00|"; offset:8; depth:2;  ! no username, no password flag
  sid:9000001;
)
```

**Відкриті інструменти:**
- **Zeek** — мережевий аналізатор; скрипти для MQTT, CoAP, Modbus.
- **Suricata** — IDS/IPS з промисловими протоколами.
- **Nozomi Networks / Claroty** — комерційні OT/IoT security platforms.
- **Security Onion** — безкоштовна платформа моніторингу.

---

## Управління прошивками у масштабі

Для організацій з сотнями IoT-пристроїв:

**Централізоване управління прошивками:**
```python
# Псевдокод: автоматизований аудит версій IoT прошивок
import requests
from dataclasses import dataclass

@dataclass
class IoTDevice:
    ip: str
    device_type: str
    current_firmware: str
    location: str

def check_firmware_updates(devices: list[IoTDevice]) -> list[dict]:
    """Перевіряє наявність оновлень для кожного пристрою."""
    outdated = []
    for device in devices:
        # Запит до vendor API або NVD для перевірки CVE
        cves = check_nvd_for_cves(device.device_type, device.current_firmware)
        if cves:
            outdated.append({
                'device': device.ip,
                'type': device.device_type,
                'firmware': device.current_firmware,
                'critical_cves': len([c for c in cves if c['severity'] == 'CRITICAL']),
                'location': device.location
            })
    return sorted(outdated, key=lambda x: x['critical_cves'], reverse=True)
```

---

## Деcommissioning: що робити зі старими IoT пристроями

**Безпечне виведення з експлуатації:**

```
1. Видалити пристрій з MDM / IoT Platform (деreєстрація)
2. Відкликати X.509 сертифікат пристрою (якщо використовувався)
3. Factory Reset пристрою (очищення конфігурацій, паролів, credentials)
4. Перевірити що пристрій відключений від хмарного аккаунта
5. Задокументувати виведення (для аудиту)
6. Фізична утилізація згідно з регламентом
```

**Чому factory reset важливий:** IP-камера або NAS без скидання може зберігати Wi-Fi паролі, API keys, знімки відеозапису.

## Міні-вправа

Проведіть аудит IoT у вашій мережі або домашньому роутері:

```bash
# 1. Знайти всі пристрої в мережі
nmap -sn $(ip route | grep -m1 / | awk '{print $1}') 2>/dev/null

# 2. Перевірити чи є пристрої з відкритим Telnet (порт 23 — ознака застарілого/небезпечного)
nmap -p 23 192.168.1.0/24 --open 2>/dev/null

# 3. Перевірити відкриті веб-інтерфейси IoT (часто незахищені)
nmap -p 80,8080,8443 192.168.1.0/24 --open 2>/dev/null

# 4. Для кожного знайденого IoT пристрою:
#    - Чи знаєте ви що це?
#    - Яка версія прошивки?
#    - Чи змінено дефолтний пароль?
#    - Чи потрібен він взагалі в мережі?
```

## Джерела та додаткові матеріали

- NIST SP 800-213 — IoT Device Cybersecurity Guidance.
- CIS IoT Security Controls (cisecurity.org).
- PacketFence NAC (packetfence.org) — відкритий NAC.
- Zeek (zeek.org) — мережевий аналізатор з IoT протоколами.
- OWASP IoT Attack Surface Areas Project.

---

**Попередній розділ:** [8.8. Hardening мобільних пристроїв](08-hardening-mobilnykh.md)
**Далі:** [8.10. Практична лабораторна на Python](10-praktychna-laboratorna.md)
**Назад до модуля:** [README модуля 08](README.md)

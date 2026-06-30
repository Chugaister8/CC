# Модуль 10. Мережева безпека

> Мережа — кровоносна система будь-якої інформаційної системи: кожен байт даних, що рухається між користувачем і сервером, між мікросервісами, між офісом і хмарою, проходить через неї. Модулі 06 і 09 розглядали мережеву безпеку у вузьких контекстах — веб-протоколи і хмарні VPC. Цей модуль повертається до фундаменту: класичні мережеві засоби захисту, що існували задовго до хмари і залишаються основою захисту будь-якої інфраструктури — від домашнього роутера до дата-центру оператора критичної інфраструктури.

## Цілі модуля

Після опрацювання модуля ви зможете:

- **Запам'ятати:** еволюцію firewall-технологій; різницю між IDS і IPS; типи VPN-протоколів; рівні Zero Trust Networking.
- **Зрозуміти:** пояснити як stateful firewall відстежує з'єднання; описати механізм сигнатурного і поведінкового виявлення вторгнень; пояснити, чому WireGuard архітектурно простіший за IPSec; описати DNS tunneling як вектор ексфільтрації.
- **Застосувати:** налаштувати базові правила firewall; написати Snort/Suricata-правило; розгорнути WireGuard VPN; провести аналіз PCAP-файлу на підозрілий трафік.

**Орієнтовна тривалість:** 12–14 годин.

---

## Структура модуля

| № | Розділ | Що розглядається |
|---|---|---|
| — | [Глосарій](00-glosariy.md) | Всі ключові терміни |
| 10.1 | [Firewalls: від пакетної фільтрації до NGFW](01-firewalls.md) | Stateless, stateful, application-layer, NGFW, UTM |
| 10.2 | [IDS/IPS: виявлення і запобігання вторгненням](02-ids-ips.md) | Сигнатурні vs аномальні, Snort/Suricata, NIDS/HIDS |
| 10.3 | [VPN-технології глибоко](03-vpn-tekhnolohii.md) | IPSec (детально), WireGuard, SSL/TLS VPN, Split Tunneling |
| 10.4 | [Сегментація мережі і Zero Trust Networking](04-segmentatsiia-merezhi.md) | VLAN, мікросегментація, ZTNA, SDN/SD-WAN |
| 10.5 | [NAC: контроль доступу до мережі](05-nac.md) | 802.1X, RADIUS, posture assessment, guest networks |
| 10.6 | [DNS-безпека](06-dns-bezpeka.md) | DNSSEC, DNS over HTTPS/TLS, DNS filtering, DNS tunneling |
| 10.7 | [Проксі та Secure Web Gateway](07-proxy-swg.md) | Forward/reverse proxy, SWG, SSL inspection, CASB-інтеграція |
| 10.8 | [Безпека бездротових мереж](08-bezdrotovi-merezhi.md) | WPA3, Enterprise Wi-Fi, Rogue AP detection, Bluetooth безпека |
| 10.9 | [Моніторинг мережі та аналіз трафіку](09-monitorynh-merezhi.md) | NetFlow, packet capture, Wireshark, baseline і аномалії |
| 10.10 | [Практична лабораторна на Python](10-praktychna-laboratorna.md) | Packet sniffer, port scanner detector, DNS tunneling detector, firewall rule analyzer |
| 10.11 | [Чек-лист і самоперевірка](11-chek-lyst-i-samoperevirka.md) | 40 питань з відповідями |

---

**Попередній модуль:** [Модуль 09. Хмарна безпека](../09-khmarna-bezpeka/README.md)
**Наступний модуль:** Модуль 11. Цифрова криміналістика та реагування на інциденти (заплановано)

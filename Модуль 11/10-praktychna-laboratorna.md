# 11.10. Практична лабораторна на Python

Чотири лабораторні, що автоматизують ключові форензичні задачі: верифікація цілісності доказів через хешування, побудова timeline з різнорідних джерел, екстракція метаданих файлів і структурований форензичний логер для документування методології відповідно до ACPO принципів (розділ 11.1).

**Залежності:**
```bash
pip install python-magic pillow exifread
```

---

## Лабораторна 11.10.1: Hash-верифікатор доказів (Chain of Custody)

```python
"""
evidence_hasher.py — обчислення і верифікація хешів доказів
відповідно до принципів Chain of Custody (розділ 11.2).
"""
import hashlib
import json
import os
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class EvidenceRecord:
    evidence_id: str
    file_path: str
    file_size: int
    md5: str
    sha256: str
    collected_at: str
    collected_by: str
    notes: str = ""


def compute_hashes(file_path: str, chunk_size: int = 8192) -> tuple[str, str]:
    """Обчислює MD5 і SHA-256 одночасно, читаючи файл лише раз."""
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()

    with open(file_path, 'rb') as f:
        while chunk := f.read(chunk_size):
            md5_hash.update(chunk)
            sha256_hash.update(chunk)

    return md5_hash.hexdigest(), sha256_hash.hexdigest()


def create_evidence_record(file_path: str, evidence_id: str,
                            collected_by: str, notes: str = "") -> EvidenceRecord:
    """Створює запис доказу з обчисленими хешами."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Файл не знайдено: {file_path}")

    md5_hash, sha256_hash = compute_hashes(file_path)

    return EvidenceRecord(
        evidence_id=evidence_id,
        file_path=str(path.absolute()),
        file_size=path.stat().st_size,
        md5=md5_hash,
        sha256=sha256_hash,
        collected_at=datetime.now(timezone.utc).isoformat(),
        collected_by=collected_by,
        notes=notes,
    )


def verify_evidence(file_path: str, expected_sha256: str) -> bool:
    """Перевіряє, чи відповідає поточний хеш файлу очікуваному
    (виявляє будь-яку зміну файлу з моменту збору)."""
    _, actual_sha256 = compute_hashes(file_path)
    return actual_sha256 == expected_sha256


class EvidenceLog:
    """Журнал усіх зібраних доказів для справи."""

    def __init__(self, case_number: str, log_path: str = None):
        self.case_number = case_number
        self.log_path = log_path or f"evidence_log_{case_number}.json"
        self.records: list[EvidenceRecord] = []
        self._load_existing()

    def _load_existing(self):
        if os.path.exists(self.log_path):
            with open(self.log_path) as f:
                data = json.load(f)
                self.records = [EvidenceRecord(**r) for r in data.get('records', [])]

    def add_evidence(self, file_path: str, evidence_id: str,
                     collected_by: str, notes: str = "") -> EvidenceRecord:
        record = create_evidence_record(file_path, evidence_id, collected_by, notes)
        self.records.append(record)
        self._save()
        return record

    def _save(self):
        data = {
            'case_number': self.case_number,
            'records': [asdict(r) for r in self.records],
            'last_updated': datetime.now(timezone.utc).isoformat(),
        }
        with open(self.log_path, 'w') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def verify_all(self) -> dict:
        """Перевіряє цілісність усіх зареєстрованих доказів."""
        results = {}
        for record in self.records:
            if os.path.exists(record.file_path):
                is_valid = verify_evidence(record.file_path, record.sha256)
                results[record.evidence_id] = '✅ INTACT' if is_valid else '🔴 MODIFIED!'
            else:
                results[record.evidence_id] = '⚠️ FILE MISSING'
        return results

    def print_chain_of_custody(self):
        print(f"\n{'='*70}")
        print(f"CHAIN OF CUSTODY LOG — Case {self.case_number}")
        print(f"{'='*70}")
        for r in self.records:
            print(f"\nEvidence ID: {r.evidence_id}")
            print(f"  File: {r.file_path}")
            print(f"  Size: {r.file_size:,} bytes")
            print(f"  SHA-256: {r.sha256}")
            print(f"  MD5: {r.md5}")
            print(f"  Collected: {r.collected_at} by {r.collected_by}")
            if r.notes:
                print(f"  Notes: {r.notes}")


if __name__ == "__main__":
    # Демонстрація: створення тестового доказу і верифікація
    test_file = "/tmp/test_evidence.txt"
    with open(test_file, 'w') as f:
        f.write("Тестовий вміст доказу для демонстрації хешування")

    log = EvidenceLog(case_number="CASE-2024-0142", log_path="/tmp/test_evidence_log.json")
    record = log.add_evidence(
        test_file,
        evidence_id="EV-001",
        collected_by="I.Petrenko",
        notes="Тестовий файл для демонстрації"
    )

    log.print_chain_of_custody()

    print(f"\n{'='*70}")
    print("ВЕРИФІКАЦІЯ ЦІЛІСНОСТІ:")
    print(f"{'='*70}")
    results = log.verify_all()
    for evidence_id, status in results.items():
        print(f"  {evidence_id}: {status}")

    # Демонстрація виявлення модифікації
    print(f"\n{'='*70}")
    print("ТЕСТ: модифікація файлу після збору доказу")
    print(f"{'='*70}")
    with open(test_file, 'a') as f:
        f.write("\nЗловмисна модифікація!")
    results = log.verify_all()
    for evidence_id, status in results.items():
        print(f"  {evidence_id}: {status}")
```

---

## Лабораторна 11.10.2: Timeline Builder (Super Timeline)

```python
"""
timeline_builder.py — об'єднання подій з різних джерел доказів
у єдину хронологічну Super Timeline (розділ 11.3).
"""
import csv
import json
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum


class SourceType(Enum):
    FILE_SYSTEM = "FileSystem"
    REGISTRY = "Registry"
    EVENT_LOG = "EventLog"
    NETWORK = "Network"
    WEB_LOG = "WebServerLog"
    CLOUD_TRAIL = "CloudTrail"
    PREFETCH = "Prefetch"


@dataclass
class TimelineEvent:
    timestamp: str          # ISO 8601 формат
    source_type: str
    description: str
    details: str = ""
    evidence_reference: str = ""

    def sort_key(self) -> datetime:
        return datetime.fromisoformat(self.timestamp.replace('Z', '+00:00'))


class TimelineBuilder:
    def __init__(self, case_number: str):
        self.case_number = case_number
        self.events: list[TimelineEvent] = []

    def add_event(self, timestamp: str, source_type: SourceType,
                  description: str, details: str = "",
                  evidence_reference: str = "") -> None:
        self.events.append(TimelineEvent(
            timestamp=timestamp,
            source_type=source_type.value,
            description=description,
            details=details,
            evidence_reference=evidence_reference,
        ))

    def sort_chronologically(self) -> list[TimelineEvent]:
        return sorted(self.events, key=lambda e: e.sort_key())

    def filter_by_timerange(self, start: str, end: str) -> list[TimelineEvent]:
        start_dt = datetime.fromisoformat(start)
        end_dt = datetime.fromisoformat(end)
        return [e for e in self.sort_chronologically()
                if start_dt <= e.sort_key() <= end_dt]

    def filter_by_source(self, source_type: SourceType) -> list[TimelineEvent]:
        return [e for e in self.sort_chronologically()
                if e.source_type == source_type.value]

    def export_csv(self, output_path: str) -> None:
        sorted_events = self.sort_chronologically()
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Source', 'Description', 'Details', 'Evidence Ref'])
            for e in sorted_events:
                writer.writerow([e.timestamp, e.source_type, e.description,
                                e.details, e.evidence_reference])

    def export_markdown_table(self) -> str:
        """Генерує markdown-таблицю для форензичного звіту (розділ 11.9)."""
        sorted_events = self.sort_chronologically()
        lines = ["| Час | Подія | Джерело доказу |", "|---|---|---|"]
        for e in sorted_events:
            lines.append(f"| {e.timestamp} | {e.description} | {e.evidence_reference or e.source_type} |")
        return '\n'.join(lines)

    def print_timeline(self) -> None:
        print(f"\n{'='*70}")
        print(f"SUPER TIMELINE — Case {self.case_number}")
        print(f"{'='*70}")
        for e in self.sort_chronologically():
            print(f"\n[{e.timestamp}] {e.source_type}")
            print(f"  {e.description}")
            if e.details:
                print(f"  Деталі: {e.details}")
            if e.evidence_reference:
                print(f"  Джерело: {e.evidence_reference}")


if __name__ == "__main__":
    # Реконструкція хронології інциденту з прикладу розділу 11.9
    timeline = TimelineBuilder(case_number="CASE-2024-0142")

    timeline.add_event(
        "2024-01-15T03:12:01+00:00", SourceType.FILE_SYSTEM,
        "Webshell backdoor.php створено в /var/www/html/uploads/",
        evidence_reference="File system timestamp, Додаток A файл #3"
    )
    timeline.add_event(
        "2024-01-15T03:12:05+00:00", SourceType.WEB_LOG,
        "Apache access log: POST /upload.php з IP 185.220.101.1",
        evidence_reference="access.log, рядок 4521"
    )
    timeline.add_event(
        "2024-01-15T03:14:33+00:00", SourceType.PREFETCH,
        "Виконання powershell.exe зафіксовано в Prefetch",
        evidence_reference="POWERSHELL.EXE-XXXX.pf"
    )
    timeline.add_event(
        "2024-01-15T03:15:02+00:00", SourceType.EVENT_LOG,
        "Windows Event 4688: створено процес svch0st.exe",
        details="Typosquatting легітимного svchost.exe",
        evidence_reference="Security.evtx, EventRecordID 78234"
    )
    timeline.add_event(
        "2024-01-15T03:15:45+00:00", SourceType.NETWORK,
        "Вихідне TCP-з'єднання до 185.220.101.1:443",
        evidence_reference="NetFlow запис"
    )
    timeline.add_event(
        "2024-01-15T14:24:15+00:00", SourceType.CLOUD_TRAIL,
        "GetCallerIdentity з вкраденими credentials",
        evidence_reference="CloudTrail EventID a1b2c3"
    )

    timeline.print_timeline()

    print(f"\n{'='*70}")
    print("Markdown-таблиця для звіту:")
    print(f"{'='*70}")
    print(timeline.export_markdown_table())

    timeline.export_csv("/tmp/incident_timeline.csv")
    print(f"\nCSV експортовано: /tmp/incident_timeline.csv")
```

---

## Лабораторна 11.10.3: Metadata Extractor

```python
"""
metadata_extractor.py — витяг метаданих файлів для форензичного
аналізу: EXIF з зображень, базові атрибути файлової системи.
"""
import os
import hashlib
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict


@dataclass
class FileMetadata:
    file_path: str
    file_size: int
    created: str
    modified: str
    accessed: str
    sha256: str
    file_type: str = "unknown"
    exif_data: dict = None


def get_file_type(file_path: str) -> str:
    """Визначає тип файлу за magic bytes (а не лише за розширенням —
    форензично важливо, бо зловмисник може змінити розширення)."""
    SIGNATURES = {
        b'\xFF\xD8\xFF': 'JPEG image',
        b'\x89PNG\r\n\x1a\n': 'PNG image',
        b'%PDF': 'PDF document',
        b'PK\x03\x04': 'ZIP/Office archive',
        b'\x4D\x5A': 'Windows executable (PE)',
        b'\x7fELF': 'Linux executable (ELF)',
        b'GIF8': 'GIF image',
        b'\x52\x61\x72\x21': 'RAR archive',
    }
    try:
        with open(file_path, 'rb') as f:
            header = f.read(16)
        for sig, file_type in SIGNATURES.items():
            if header.startswith(sig):
                return file_type
    except (IOError, PermissionError):
        pass
    return f"unknown (ext: {Path(file_path).suffix})"


def extract_exif(file_path: str) -> dict:
    """Витягує EXIF-метадані з зображення (геолокація, камера, час зйомки)."""
    try:
        import exifread
        with open(file_path, 'rb') as f:
            tags = exifread.process_file(f, details=False)

        exif_data = {}
        interesting_tags = [
            'GPS GPSLatitude', 'GPS GPSLongitude',
            'Image Make', 'Image Model',
            'EXIF DateTimeOriginal', 'EXIF DateTimeDigitized',
            'Image Software',
        ]
        for tag in interesting_tags:
            if tag in tags:
                exif_data[tag] = str(tags[tag])
        return exif_data
    except ImportError:
        return {'error': 'exifread не встановлено (pip install exifread)'}
    except Exception as e:
        return {'error': str(e)}


def extract_metadata(file_path: str) -> FileMetadata:
    """Витягує повні форензичні метадані файлу."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Файл не знайдено: {file_path}")

    stat = path.stat()

    # SHA-256 для верифікації цілісності
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            sha256_hash.update(chunk)

    file_type = get_file_type(file_path)

    metadata = FileMetadata(
        file_path=str(path.absolute()),
        file_size=stat.st_size,
        created=datetime.fromtimestamp(stat.st_ctime).isoformat(),
        modified=datetime.fromtimestamp(stat.st_mtime).isoformat(),
        accessed=datetime.fromtimestamp(stat.st_atime).isoformat(),
        sha256=sha256_hash.hexdigest(),
        file_type=file_type,
    )

    # EXIF лише для зображень
    if 'image' in file_type.lower():
        metadata.exif_data = extract_exif(file_path)

    return metadata


def check_extension_mismatch(file_path: str) -> bool:
    """Перевіряє, чи розширення файлу відповідає його справжньому типу
    (зловмисники часто маскують виконувані файли під документи)."""
    declared_ext = Path(file_path).suffix.lower()
    actual_type = get_file_type(file_path)

    SUSPICIOUS_COMBOS = {
        '.jpg': ['Windows executable', 'Linux executable', 'ZIP'],
        '.png': ['Windows executable', 'Linux executable'],
        '.pdf': ['Windows executable', 'Linux executable'],
        '.txt': ['Windows executable', 'PE'],
        '.doc': ['Windows executable (PE)'],
    }

    if declared_ext in SUSPICIOUS_COMBOS:
        for suspicious in SUSPICIOUS_COMBOS[declared_ext]:
            if suspicious in actual_type:
                return True
    return False


def print_metadata_report(metadata: FileMetadata) -> None:
    print(f"\n{'='*60}")
    print(f"METADATA REPORT: {Path(metadata.file_path).name}")
    print(f"{'='*60}")
    print(f"  Повний шлях: {metadata.file_path}")
    print(f"  Розмір: {metadata.file_size:,} байт")
    print(f"  Справжній тип: {metadata.file_type}")
    print(f"  SHA-256: {metadata.sha256}")
    print(f"  Створено: {metadata.created}")
    print(f"  Змінено: {metadata.modified}")
    print(f"  Доступ: {metadata.accessed}")

    if check_extension_mismatch(metadata.file_path):
        print(f"  🔴 ПОПЕРЕДЖЕННЯ: розширення файлу НЕ відповідає справжньому типу!")

    if metadata.exif_data:
        print(f"\n  EXIF дані:")
        for key, value in metadata.exif_data.items():
            print(f"    {key}: {value}")


if __name__ == "__main__":
    # Тестова демонстрація
    test_file = "/tmp/test_metadata_file.txt"
    with open(test_file, 'w') as f:
        f.write("Тестовий файл для демонстрації екстракції метаданих")

    metadata = extract_metadata(test_file)
    print_metadata_report(metadata)

    # Демонстрація виявлення підміни розширення
    print(f"\n{'='*60}")
    print("ТЕСТ: файл .txt з PE header (підозріла підміна)")
    print(f"{'='*60}")
    fake_exe = "/tmp/fake_document.txt"
    with open(fake_exe, 'wb') as f:
        f.write(b'\x4D\x5A\x90\x00')  # PE header (MZ signature)
        f.write(b'\x00' * 100)

    metadata2 = extract_metadata(fake_exe)
    print_metadata_report(metadata2)
```

---

## Лабораторна 11.10.4: Forensic Investigation Logger

```python
"""
forensic_logger.py — структурований журнал дій дослідника
відповідно до ACPO Принципу 3 (відтворюваність методології,
розділ 11.1 і 11.2).
"""
import json
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field


@dataclass
class InvestigationStep:
    timestamp: str
    analyst: str
    action: str
    tool_used: str
    tool_version: str
    purpose: str
    result_summary: str
    output_reference: str = ""


class ForensicInvestigationLog:
    """Журнал дій дослідника для забезпечення reproducibility (ACPO Принцип 3)."""

    def __init__(self, case_number: str, analyst_name: str):
        self.case_number = case_number
        self.analyst_name = analyst_name
        self.steps: list[InvestigationStep] = []
        self.start_time = datetime.now(timezone.utc).isoformat()

    def log_step(self, action: str, tool_used: str, tool_version: str,
                purpose: str, result_summary: str,
                output_reference: str = "") -> InvestigationStep:
        """Записує один крок дослідження з повним контекстом."""
        step = InvestigationStep(
            timestamp=datetime.now(timezone.utc).isoformat(),
            analyst=self.analyst_name,
            action=action,
            tool_used=tool_used,
            tool_version=tool_version,
            purpose=purpose,
            result_summary=result_summary,
            output_reference=output_reference,
        )
        self.steps.append(step)
        return step

    def export_json(self, output_path: str) -> None:
        data = {
            'case_number': self.case_number,
            'analyst': self.analyst_name,
            'investigation_start': self.start_time,
            'export_time': datetime.now(timezone.utc).isoformat(),
            'total_steps': len(self.steps),
            'steps': [asdict(s) for s in self.steps],
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def export_methodology_section(self) -> str:
        """Генерує розділ Methodology для форензичного звіту (розділ 11.9)."""
        lines = ["## Methodology\n", "Послідовність виконаних дій:\n"]
        for i, step in enumerate(self.steps, 1):
            lines.append(f"\n**Крок {i}** [{step.timestamp}]")
            lines.append(f"- Дія: {step.action}")
            lines.append(f"- Інструмент: {step.tool_used} (версія {step.tool_version})")
            lines.append(f"- Мета: {step.purpose}")
            lines.append(f"- Результат: {step.result_summary}")
            if step.output_reference:
                lines.append(f"- Посилання на вивід: {step.output_reference}")
        return '\n'.join(lines)

    def print_log(self) -> None:
        print(f"\n{'='*70}")
        print(f"FORENSIC INVESTIGATION LOG — Case {self.case_number}")
        print(f"Analyst: {self.analyst_name} | Started: {self.start_time}")
        print(f"{'='*70}")
        for i, step in enumerate(self.steps, 1):
            print(f"\n[{i}] {step.timestamp}")
            print(f"    Action: {step.action}")
            print(f"    Tool: {step.tool_used} v{step.tool_version}")
            print(f"    Purpose: {step.purpose}")
            print(f"    Result: {step.result_summary}")


if __name__ == "__main__":
    log = ForensicInvestigationLog(
        case_number="CASE-2024-0142",
        analyst_name="I. Petrenko"
    )

    # Симуляція реального розслідування
    log.log_step(
        action="Створення write-blocked образу диска",
        tool_used="dd (with hardware write-blocker)",
        tool_version="GNU coreutils 9.1",
        purpose="Збір незмінної копії для подальшого аналізу",
        result_summary="Образ створено: evidence_001.dd (500GB), SHA-256 verified",
        output_reference="evidence_001.dd.sha256"
    )

    log.log_step(
        action="Побудова Super Timeline",
        tool_used="log2timeline/plaso",
        tool_version="20231025",
        purpose="Реконструкція хронології подій з усіх джерел диска",
        result_summary="Згенеровано 1,247,392 timeline events",
        output_reference="timeline.plaso"
    )

    log.log_step(
        action="Аналіз Windows Event Logs на ознаки видалення логів",
        tool_used="Volatility 3 (для пам'яті) + wevtutil",
        tool_version="Volatility 3.2.0",
        purpose="Перевірка чи зловмисник намагався приховати сліди",
        result_summary="Виявлено Event ID 1102 о 14:35 — Security log очищено",
        output_reference="security_evtx_analysis.txt"
    )

    log.print_log()

    print(f"\n{'='*70}")
    print("Methodology секція для звіту:")
    print(f"{'='*70}")
    print(log.export_methodology_section())

    log.export_json("/tmp/investigation_log.json")
    print(f"\nЖурнал експортовано: /tmp/investigation_log.json")
```

## Джерела та додаткові матеріали

- exifread (pypi.org/project/exifread) — EXIF-парсер для Python.
- Python hashlib documentation — криптографічні хеш-функції.
- NIST SP 800-86, Appendix — приклади форм документування.

---

**Попередній розділ:** [11.9. Написання форензичного звіту](09-forensychnyy-zvit.md)
**Далі:** [11.11. Чек-лист і самоперевірка](11-chek-lyst-i-samoperevirka.md)
**Назад до модуля:** [README модуля 11](README.md)

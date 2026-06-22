"""SQLite-backed scan history storage."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import asyncio
import tempfile
from platformdirs import user_data_path
from sqlalchemy import event
from sqlmodel import Field, Session, SQLModel, create_engine, select

from supplyscan.models import ScanReport


class ScanRecord(SQLModel, table=True):
    """Database row containing a serialized scan report."""

    id: int | None = Field(default=None, primary_key=True)
    package: str = Field(index=True)
    version: str | None = Field(default=None, index=True)
    scanned_at: datetime = Field(index=True)
    clean: bool = Field(index=True)
    severity: str = Field(index=True)
    report_json: str


class ScanStore:
    """Persist and retrieve scan reports."""

    def __init__(self, path: Path) -> None:
        """Create a store bound to a SQLite file path."""

        self.path = resolve_store_path(path)
        self.engine = create_engine(
            f"sqlite:///{self.path.as_posix()}",
            connect_args={"check_same_thread": False, "timeout": 30},
        )
        event.listen(self.engine, "connect", configure_sqlite_connection)
        SQLModel.metadata.create_all(self.engine)

    @classmethod
    def default(cls) -> "ScanStore":
        """Create a store at the default per-user application data path."""

        return cls(default_store_path())

    async def save(self, report: ScanReport) -> None:
        """Persist a scan report."""

        await asyncio.to_thread(self._save_sync, report)

    async def load_latest(self) -> ScanReport | None:
        """Load the latest stored report if present."""

        return await asyncio.to_thread(self._load_latest_sync)

    async def load_recent(self, limit: int = 20) -> list[ScanReport]:
        """Load recent scan reports."""

        return await asyncio.to_thread(self._load_recent_sync, limit)

    async def load_stats(self) -> dict[str, int | float]:
        """Load aggregate scan history statistics."""

        return await asyncio.to_thread(self._load_stats_sync)

    def _save_sync(self, report: ScanReport) -> None:
        """Synchronously persist a scan report in a worker thread."""

        record = ScanRecord(
            package=report.target.name,
            version=report.target.version,
            scanned_at=report.scanned_at,
            clean=report.clean,
            severity=report.overall_severity.value,
            report_json=report.model_dump_json(),
        )
        with Session(self.engine) as session:
            session.add(record)
            session.commit()

    def _load_latest_sync(self) -> ScanReport | None:
        """Synchronously load the latest report in a worker thread."""

        with Session(self.engine) as session:
            statement = select(ScanRecord).order_by(ScanRecord.scanned_at.desc(), ScanRecord.id.desc())
            record = session.exec(statement).first()
        if record is None:
            return None
        return ScanReport.model_validate_json(record.report_json)

    def _load_recent_sync(self, limit: int = 20) -> list[ScanReport]:
        """Synchronously load recent reports in a worker thread."""

        safe_limit = max(1, min(limit, 200))
        with Session(self.engine) as session:
            statement = (
                select(ScanRecord)
                .order_by(ScanRecord.scanned_at.desc(), ScanRecord.id.desc())
                .limit(safe_limit)
            )
            records = list(session.exec(statement))
        return [ScanReport.model_validate_json(record.report_json) for record in records]

    def _load_stats_sync(self) -> dict[str, int | float]:
        """Synchronously calculate aggregate scan statistics."""

        with Session(self.engine) as session:
            records = list(session.exec(select(ScanRecord)))
        threats = sum(1 for record in records if record.severity in {"CRITICAL", "HIGH"})
        clean = sum(1 for record in records if record.clean)
        durations = [
            ScanReport.model_validate_json(record.report_json).duration_ms
            for record in records
        ]
        avg_ms = (sum(durations) / len(durations)) if durations else 0.0
        return {
            "total_scans": len(records),
            "threats_blocked": threats,
            "clean_packages": clean,
            "avg_ms": avg_ms,
        }


def default_store_path() -> Path:
    """Return the default SQLite path for SupplyScan history."""

    return user_data_path("SupplyScan", "SupplyScan") / "history.sqlite3"


def resolve_store_path(preferred_path: Path) -> Path:
    """Return the first writable SQLite path from the resilient storage fallback chain."""

    for candidate in store_path_candidates(preferred_path):
        try:
            candidate.parent.mkdir(parents=True, exist_ok=True)
            probe_path = candidate.parent / ".supplyscan-write-test"
            probe_path.write_text("ok", encoding="utf-8")
            probe_path.unlink(missing_ok=True)
            return candidate
        except OSError:
            continue
    fallback = Path.cwd() / ".supplyscan" / "history.sqlite3"
    fallback.parent.mkdir(parents=True, exist_ok=True)
    return fallback


def store_path_candidates(preferred_path: Path) -> list[Path]:
    """Return storage path candidates ordered from platform-native to local fallback."""

    candidates = [
        preferred_path,
        user_data_path("SupplyScan", "SupplyScan") / "history.sqlite3",
        Path.home() / ".supplyscan" / "history.sqlite3",
        Path.cwd() / ".supplyscan" / "history.sqlite3",
        Path(tempfile.gettempdir()) / "supplyscan" / "history.sqlite3",
    ]
    deduped: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate.expanduser().resolve(strict=False)).lower()
        if key not in seen:
            seen.add(key)
            deduped.append(candidate.expanduser())
    return deduped


def configure_sqlite_connection(dbapi_connection: object, _connection_record: object) -> None:
    """Enable SQLite settings that keep concurrent package-manager scans resilient."""

    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
    finally:
        cursor.close()

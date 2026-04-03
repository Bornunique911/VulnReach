import os
from pathlib import Path

from storage.repository import StorageRepository


def get_repository() -> StorageRepository:
    """Return the appropriate StorageRepository based on environment.

    - DATABASE_URL set → PostgresRepository (production / Docker)
    - Otherwise        → SQLiteRepository at SQLITE_PATH (default ~/.vulnreach/vulnreach.db)
    """
    if db_url := os.getenv("DATABASE_URL"):
        from storage.repository import PostgresRepository
        return PostgresRepository(db_url)

    db_path = os.getenv(
        "SQLITE_PATH",
        str(Path.home() / ".vulnreach" / "vulnreach.db"),
    )
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    from storage.sqlite_repository import SQLiteRepository
    return SQLiteRepository(db_path)

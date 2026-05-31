from __future__ import annotations
import asyncio
from sentinel.config import Settings
from sentinel.db.duckdb import SentinelStore

async def main() -> None:
    store = SentinelStore(Settings.from_env())
    await store.init()
    print(f"initialized {store.settings.duckdb_path}")
    print(f"coral data {store.settings.coral_data_dir}")

if __name__ == "__main__": asyncio.run(main())

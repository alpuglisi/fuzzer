"""Filesystem paths for packaged tool data, resolved relative to the package.

Keeps defaults working when a tool is run from anywhere (``python -m
fuzzlab.tools.fetcher``) instead of only from the old working directory.
"""

from __future__ import annotations

from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"

#: Indicator/rules database consumed by the auditor and rebuilt by build_sql_db.
INDICATOR_DB = DATA_DIR / "php_indicators.db"

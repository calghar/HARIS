import json
import logging
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)

PAYLOADS_TABLE = "payloads"
VULNERABILITY = "vulnerability"
ANOMALY = "anomaly"
# headers, referer and the responses table hold cookies; leave them unread.
_PAYLOAD_SQL = """
SELECT
    paths.path,
    paths.method,
    payloads.level,
    payloads.parameter,
    payloads.info,
    payloads.wstg,
    payloads.module,
    payloads.category,
    payloads.type
FROM payloads
JOIN paths ON payloads.evil_path_id = paths.path_id
"""

type Item = dict[str, str | int | list[str]]


def _wstg(raw: object) -> str | list[str]:
    text = "" if raw is None else str(raw)
    if "," not in text:
        return text
    return text.split(",")


def _item(row: sqlite3.Row) -> Item:
    parameter = row["parameter"]
    return {
        "path": str(row["path"]),
        "method": str(row["method"]),
        "level": int(row["level"]),
        "parameter": "" if parameter is None else str(parameter),
        "info": str(row["info"]),
        "wstg": _wstg(row["wstg"]),
        "module": str(row["module"]),
    }


def _grouped(rows: list[sqlite3.Row], kind: str) -> dict[str, list[Item]]:
    grouped: dict[str, list[Item]] = {}
    for row in rows:
        if row["type"] != kind:
            continue
        grouped.setdefault(str(row["category"]), []).append(_item(row))
    return grouped


def _database(session_dir: Path) -> Path | None:
    if not session_dir.is_dir():
        logger.debug("Wapiti session directory missing: %s", session_dir)
        return None
    matches = sorted(path for path in session_dir.glob("*.db") if path.is_file())
    if not matches:
        logger.debug("No Wapiti session database in %s", session_dir)
        return None
    return matches[0]


def _report(connection: sqlite3.Connection) -> str:
    present = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (PAYLOADS_TABLE,),
    ).fetchone()
    if present is None:
        logger.debug("Wapiti session database has no %s table", PAYLOADS_TABLE)
        return ""
    connection.row_factory = sqlite3.Row
    rows = list(connection.execute(_PAYLOAD_SQL))
    payload = {
        "vulnerabilities": _grouped(rows, VULNERABILITY),
        "anomalies": _grouped(rows, ANOMALY),
    }
    return json.dumps(payload)


def session_report(session_dir: Path) -> str:
    """Return a Wapiti JSON report from the session directory, or ""."""
    database = _database(session_dir)
    if database is None:
        return ""
    uri = f"{database.resolve().as_uri()}?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        logger.debug("Wapiti session database unreadable: %s", exc)
        return ""
    try:
        return _report(connection)
    except sqlite3.Error as exc:
        logger.debug("Wapiti session database unreadable: %s", exc)
        return ""
    finally:
        connection.close()

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import stat
import sys
from uuid import UUID

from .errors import ValidationError
from .jsonio import document_digest


STATE_ROOT = Path("/var/lib/linxira/components/system-transactions")


def _plan_id(value: str) -> str:
    try:
        if str(UUID(value)) != value:
            raise ValueError
    except ValueError as exc:
        raise ValidationError("invalid isolated worker plan ID") from exc
    return value


def launch_system_worker(plan: dict) -> dict:
    identifier = _plan_id(str(plan.get("id", "")))
    unit = f"linxira-components-worker@{identifier}.service"
    from .system_transactions import _bounded_process
    result = _bounded_process(
        ["/usr/bin/systemctl", "start", "--wait", unit], limit=256 * 1024,
        timeout=86400, env={"PATH": "/usr/bin", "LC_ALL": "C"},
    )
    path = STATE_ROOT / "worker-results" / f"{identifier}.json"
    if result.returncode != 0 and not path.is_file():
        progress_path = STATE_ROOT / "worker-progress" / f"{identifier}.json"
        try:
            progress = json.loads(progress_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError("isolated system worker failed before creating a rollback snapshot") from exc
        if (
            not isinstance(progress, dict)
            or progress.get("schemaVersion") != "org.linxira.components.system-worker-progress.v1"
            or progress.get("operationId") != plan.get("operationId")
            or progress.get("planId") != identifier
            or progress.get("planDigest") != plan.get("digest")
            or progress.get("digest") != document_digest(progress)
            or not isinstance(progress.get("snapshot"), dict)
        ):
            raise ValidationError("isolated system worker left invalid recovery progress")
        from .driver_worker import _failed_result
        failed = _failed_result(
            plan, "isolated worker stopped after snapshot; package state requires verification",
            progress["snapshot"], True,
        )
        failed["digest"] = document_digest(failed)
        return failed
    try:
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > 1024 * 1024 or stat.S_IMODE(metadata.st_mode) & 0o077
            or (os.geteuid() == 0 and metadata.st_uid != 0)
        ):
            raise ValidationError("isolated system worker result is unsafe")
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValidationError("isolated system worker result has duplicate fields")
                value[key] = item
            return value
        document = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("isolated system worker result is unavailable") from exc
    if not isinstance(document, dict):
        raise ValidationError("isolated system worker result is invalid")
    return document


def main() -> int:
    if os.geteuid() != 0 or len(sys.argv) != 2:
        print("Linxira system worker requires root and one plan ID", file=sys.stderr)
        return 2
    try:
        identifier = _plan_id(sys.argv[1])
        from .system_transactions import SystemTransactionStore
        store = SystemTransactionStore(recover=False)
        store.execute_worker(identifier)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0

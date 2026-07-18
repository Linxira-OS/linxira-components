from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any

from .errors import UnsafePathError, ValidationError


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def loads_strict(data: str | bytes, *, source: str = "JSON document") -> Any:
    try:
        return json.loads(data, object_pairs_hook=_reject_duplicate_keys)
    except UnicodeDecodeError as exc:
        raise ValidationError(f"{source} is not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ValidationError(
            f"invalid {source} at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc


def load_strict(path: str | os.PathLike[str]) -> Any:
    input_path = Path(path)
    try:
        data = input_path.read_bytes()
    except OSError as exc:
        raise ValidationError(f"cannot read {input_path}: {exc}") from exc
    return loads_strict(data, source=str(input_path))


def canonical_bytes(document: Any) -> bytes:
    try:
        text = json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"document cannot be canonicalized: {exc}") from exc
    return text.encode("ascii")


def document_digest(document: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in document.items() if key != "digest"}
    return hashlib.sha256(canonical_bytes(unsigned)).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ensure_real_directory(path: Path) -> Path:
    try:
        absolute = path.absolute()
        current = Path(absolute.anchor)
        for part in absolute.parts[1:]:
            current = current / part
            mode = current.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise UnsafePathError(f"output directory contains a symlink: {current}")
        if not absolute.is_dir():
            raise UnsafePathError(f"output directory is not a directory: {absolute}")
        return absolute
    except UnsafePathError:
        raise
    except OSError as exc:
        raise UnsafePathError(f"invalid output directory {path}: {exc}") from exc


def atomic_write_json(
    output_dir: str | os.PathLike[str], filename: str, document: dict[str, Any]
) -> Path:
    if not filename or filename in {".", ".."} or Path(filename).name != filename:
        raise UnsafePathError("output filename must be one plain file name")
    if "/" in filename or "\\" in filename:
        raise UnsafePathError("output filename must not contain path separators")

    directory = _ensure_real_directory(Path(output_dir))
    target = directory / filename
    try:
        if target.exists() or target.is_symlink():
            mode = target.lstat().st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
                raise UnsafePathError(f"output target is not a regular file: {target}")
    except OSError as exc:
        raise UnsafePathError(f"cannot inspect output target {target}: {exc}") from exc

    payload = json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2)
    payload += "\n"
    fd = -1
    temporary: Path | None = None
    try:
        fd, name = tempfile.mkstemp(prefix=f".{filename}.", suffix=".tmp", dir=directory)
        temporary = Path(name)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            fd = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        temporary = None
        return target
    except OSError as exc:
        raise UnsafePathError(f"cannot atomically write {target}: {exc}") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

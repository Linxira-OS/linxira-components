from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import threading
from typing import Any, Callable
from uuid import UUID, uuid4

from .errors import ValidationError
from .jsonio import document_digest


PLAN_SCHEMA = "org.linxira.components.system-plan.v1"
RECEIPT_SCHEMA = "org.linxira.components.system-receipt.v1"
REGISTRY_VERSION = "2026.07.22.1"
PACMAN_PROCESSES = frozenset({"pacman", "makepkg", "yay", "paru", "pikaur", "packagekitd"})
OPERATIONS = {
    "org.linxira.recovery.pacman-lock-diagnose.v1": {
        "action": "org.linxira.components.recovery",
        "lockDomain": "package-diagnostics",
        "risk": "read-only",
        "rollback": "not-applicable",
    },
    "org.linxira.recovery.live-chroot-readiness.v1": {
        "action": "org.linxira.components.recovery",
        "lockDomain": "live-target-diagnostics",
        "risk": "read-only",
        "rollback": "not-applicable",
    },
}
REGISTRY_DIGEST = hashlib.sha256(
    json.dumps({"version": REGISTRY_VERSION, "operations": OPERATIONS}, sort_keys=True).encode()
).hexdigest()
ID_RE = re.compile(r"^[0-9a-f-]{36}$")
MACHINE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
BOOT_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
MAX_PLANS_PER_UID = 128
MAX_SYSTEM_PLANS = 4096
PLAN_RETENTION = timedelta(days=30)
Runner = Callable[..., subprocess.CompletedProcess[str]]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _strict_json(value: str) -> dict[str, Any]:
    if len(value.encode("utf-8")) > 16 * 1024:
        raise ValidationError("system operation parameters exceed 16 KiB")

    def reject_duplicates(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ValidationError(f"duplicate parameter field: {key}")
            result[key] = item
        return result

    try:
        document = json.loads(value, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValidationError(f"invalid system operation parameters: {exc}") from exc
    if document != {}:
        raise ValidationError("this system operation accepts an exact empty parameter object")
    return document


def _read_text(path: Path, limit: int = 4096) -> str:
    try:
        with path.open("rb") as stream:
            return stream.read(limit).decode("utf-8", errors="replace").strip("\x00\r\n ")
    except OSError:
        return ""


class SystemTransactionStore:
    def __init__(
        self,
        state_root: Path = Path("/var/lib/linxira/components/system-transactions"),
        system_root: Path = Path("/"),
        *,
        runner: Runner = subprocess.run,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        self.state_root = state_root
        self.system_root = system_root
        self.runner = runner
        self.clock = clock
        self._lock = threading.RLock()
        for name in ("plans", "state", "receipts"):
            directory = self.state_root / name
            directory.mkdir(parents=True, exist_ok=True, mode=0o750)
            if directory.is_symlink() or not directory.is_dir():
                raise ValidationError(f"unsafe system transaction directory: {directory}")
            try:
                directory.chmod(0o750)
            except OSError as exc:
                raise ValidationError(f"cannot secure system transaction directory: {directory}") from exc
        self.recover_interrupted()

    def _system_path(self, value: str) -> Path:
        return self.system_root / value.lstrip("/")

    def _binding(self) -> dict[str, str]:
        machine_id = _read_text(self._system_path("/etc/machine-id"))
        boot_id = _read_text(self._system_path("/proc/sys/kernel/random/boot_id"))
        if not MACHINE_ID_RE.fullmatch(machine_id):
            raise ValidationError("system machine ID is unavailable or malformed")
        if not BOOT_ID_RE.fullmatch(boot_id):
            raise ValidationError("system boot ID is unavailable or malformed")
        return {
            "machineIdSha256": hashlib.sha256(machine_id.encode()).hexdigest(),
            "bootId": boot_id,
            "architecture": platform.machine() or "unknown",
            "registrySha256": REGISTRY_DIGEST,
        }

    def _pacman_lock_evidence(self) -> dict[str, Any]:
        lock = self._system_path("/var/lib/pacman/db.lck")
        try:
            metadata = lock.lstat()
            lock_evidence = {
                "exists": True,
                "regular": stat.S_ISREG(metadata.st_mode),
                "symlink": stat.S_ISLNK(metadata.st_mode),
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
                "size": metadata.st_size,
                "mtimeNs": metadata.st_mtime_ns,
            }
        except FileNotFoundError:
            lock_evidence = {"exists": False}
        except OSError as exc:
            lock_evidence = {"exists": None, "error": type(exc).__name__}

        processes = []
        proc = self._system_path("/proc")
        try:
            candidates = sorted(
                (item for item in proc.iterdir() if item.name.isdigit()),
                key=lambda item: int(item.name),
            )[:4096]
        except OSError:
            candidates = []
        for process in candidates:
            name = _read_text(process / "comm", 256)
            if name not in PACMAN_PROCESSES:
                continue
            stat_fields = _read_text(process / "stat", 4096).split()
            processes.append({
                "pid": int(process.name),
                "program": name,
                "startTimeTicks": stat_fields[21] if len(stat_fields) > 21 else "unknown",
            })
        return {"lock": lock_evidence, "packageProcesses": processes}

    def _live_readiness_evidence(self) -> dict[str, Any]:
        target = self._system_path("/mnt")
        command = [
            "/usr/bin/findmnt", "--json", "--bytes", "--output",
            "TARGET,SOURCE,FSTYPE,OPTIONS,FSROOTS,AVAIL,USED,SIZE", "/mnt",
        ]
        try:
            result = self.runner(
                command, check=False, capture_output=True, text=True, timeout=10,
                shell=False, env={"PATH": "/usr/bin:/usr/sbin", "LC_ALL": "C"},
            )
            document = json.loads(result.stdout) if result.returncode == 0 and result.stdout else None
            filesystems = document.get("filesystems", []) if isinstance(document, dict) else []
            mount = next(
                (
                    item for item in filesystems
                    if isinstance(item, dict) and item.get("target") == "/mnt"
                ),
                None,
            )
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            mount = None
        checks = {}
        for relative in ("etc/pacman.conf", "usr/bin/pacman", "bin/sh", "etc/fstab"):
            checks[f"/mnt/{relative}"] = self._fixed_regular_file(target, relative)
        checks["/usr/bin/arch-chroot"] = self._fixed_regular_file(
            self.system_root, "usr/bin/arch-chroot"
        )
        return {"mount": mount, "checks": checks, "ready": mount is not None and all(checks.values())}

    @staticmethod
    def _fixed_regular_file(root: Path, relative: str) -> bool:
        current = root
        try:
            if current.is_symlink() or not current.is_dir():
                return False
            for part in Path(relative).parts:
                current = current / part
                metadata = current.lstat()
                if stat.S_ISLNK(metadata.st_mode):
                    return False
            return stat.S_ISREG(metadata.st_mode)
        except OSError:
            return False

    def _evidence(self, operation_id: str) -> dict[str, Any]:
        if operation_id == "org.linxira.recovery.pacman-lock-diagnose.v1":
            return self._pacman_lock_evidence()
        if operation_id == "org.linxira.recovery.live-chroot-readiness.v1":
            return self._live_readiness_evidence()
        raise ValidationError(f"unsupported system operation: {operation_id}")

    def _path(self, collection: str, identifier: str) -> Path:
        try:
            if str(UUID(identifier)) != identifier:
                raise ValueError
        except ValueError as exc:
            raise ValidationError("invalid system transaction ID") from exc
        return self.state_root / collection / f"{identifier}.json"

    def _write_new(self, path: Path, document: dict[str, Any]) -> None:
        if path.exists() or path.is_symlink():
            raise ValidationError(f"system transaction document already exists: {path.name}")
        payload = json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(descriptor)
        self._sync_directory(path.parent)

    def _replace(self, path: Path, document: dict[str, Any]) -> None:
        temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        try:
            self._write_new(temporary, document)
            os.replace(temporary, path)
            self._sync_directory(path.parent)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    @staticmethod
    def _sync_directory(directory: Path) -> None:
        if os.name != "posix":
            return
        descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _load(self, path: Path) -> dict[str, Any]:
        try:
            metadata = path.lstat()
        except FileNotFoundError as exc:
            raise ValidationError("system transaction document does not exist") from exc
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise ValidationError("system transaction document is not a regular file")
        if os.name == "posix":
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                raise ValidationError("system transaction document permissions are too broad")
            if os.geteuid() == 0 and metadata.st_uid != 0:
                raise ValidationError("system transaction document is not root-owned")
        if metadata.st_size > 1024 * 1024:
            raise ValidationError("system transaction document exceeds size limit")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValidationError("invalid system transaction document") from exc
        if not isinstance(value, dict):
            raise ValidationError("system transaction document must be an object")
        return value

    def recover_interrupted(self) -> None:
        state_directory = self.state_root / "state"
        for path in state_directory.glob("*.json"):
            try:
                document = self._load(path)
            except ValidationError:
                continue
            if document.get("status") not in {"confirmed", "applying", "verifying"}:
                continue
            receipt_id = document.get("receiptId")
            if document.get("status") == "verifying" and isinstance(receipt_id, str):
                try:
                    receipt = self._load(self._path("receipts", receipt_id))
                    plan = self._load(self._path("plans", str(document.get("id"))))
                    if (
                        receipt.get("schemaVersion") == RECEIPT_SCHEMA
                        and receipt.get("id") == receipt_id
                        and receipt.get("digest") == document_digest(receipt)
                        and receipt.get("planId") == document.get("id")
                        and receipt.get("planDigest") == plan.get("digest")
                        and receipt.get("operationId") == plan.get("operationId")
                        and receipt.get("creatorUid") == plan.get("creatorUid")
                        and receipt.get("status") == "succeeded"
                        and isinstance(receipt.get("completedAt"), str)
                    ):
                        self._replace(path, {
                            "id": document.get("id"), "status": "succeeded",
                            "updatedAt": receipt.get("completedAt"), "receiptId": receipt_id,
                        })
                        continue
                except ValidationError:
                    pass
            self._replace(path, {
                "id": document.get("id"),
                "status": "interrupted",
                "updatedAt": _timestamp(self.clock()),
            })

    def _enforce_plan_quota(self, creator_uid: int) -> None:
        total = 0
        owned = 0
        for path in (self.state_root / "plans").glob("*.json"):
            try:
                plan = self._load(path)
            except ValidationError:
                total += 1
                continue
            try:
                created = datetime.fromisoformat(str(plan["createdAt"]).replace("Z", "+00:00"))
                state = self._load(self._path("state", str(plan["id"])))
            except (KeyError, ValueError, ValidationError):
                total += 1
                continue
            if (
                self.clock() - created > PLAN_RETENTION
                and state.get("status") in {"planned", "stale", "interrupted", "failed", "succeeded"}
            ):
                path.unlink()
                self._path("state", str(plan["id"])).unlink()
                self._sync_directory(path.parent)
                self._sync_directory(self.state_root / "state")
                continue
            total += 1
            if plan.get("creatorUid") == creator_uid:
                owned += 1
            if total > MAX_SYSTEM_PLANS:
                raise ValidationError("system transaction plan quota is exhausted")
        if total >= MAX_SYSTEM_PLANS or owned >= MAX_PLANS_PER_UID:
            raise ValidationError("system transaction plan quota is exhausted")

    def create_plan(self, operation_id: str, parameters_json: str, creator_uid: int) -> dict[str, Any]:
        if operation_id not in OPERATIONS:
            raise ValidationError(f"unsupported system operation: {operation_id}")
        if not isinstance(creator_uid, int) or creator_uid < 0:
            raise ValidationError("invalid transaction creator UID")
        parameters = _strict_json(parameters_json)
        with self._lock:
            self._enforce_plan_quota(creator_uid)
            created = self.clock()
            identifier = str(uuid4())
            operation = OPERATIONS[operation_id]
            plan = {
                "schemaVersion": PLAN_SCHEMA,
                "id": identifier,
                "operationId": operation_id,
                "parameters": parameters,
                "creatorUid": creator_uid,
                "createdAt": _timestamp(created),
                "expiresAt": _timestamp(created + timedelta(minutes=10)),
                **self._binding(),
                "lockDomain": operation["lockDomain"],
                "risk": operation["risk"],
                "rollback": operation["rollback"],
                "preState": self._evidence(operation_id),
            }
            plan["digest"] = document_digest(plan)
            self._write_new(self._path("plans", identifier), plan)
            self._write_new(self._path("state", identifier), {
                "id": identifier, "status": "planned", "updatedAt": plan["createdAt"],
            })
        return plan

    def confirm_and_apply(
        self, plan_id: str, plan_digest: str, caller_uid: int
    ) -> dict[str, Any]:
        with self._lock:
            plan = self._load(self._path("plans", plan_id))
            state_path = self._path("state", plan_id)
            state = self._load(state_path)
            if state.get("id") != plan_id or state.get("status") != "planned":
                raise ValidationError("system plan is not in the planned state")
            if plan.get("schemaVersion") != PLAN_SCHEMA or plan.get("digest") != document_digest(plan):
                raise ValidationError("system plan digest is invalid")
            if plan["digest"] != plan_digest:
                raise ValidationError("confirmed system plan digest does not match")
            if plan.get("creatorUid") != caller_uid:
                raise ValidationError("system plan belongs to a different caller")
            if self.clock() > datetime.fromisoformat(plan["expiresAt"].replace("Z", "+00:00")):
                self._replace(self._path("state", plan_id), {
                    "id": plan_id, "status": "stale", "updatedAt": _timestamp(self.clock()),
                })
                raise ValidationError("system plan has expired")
            for key, value in self._binding().items():
                if plan.get(key) != value:
                    self._replace(self._path("state", plan_id), {
                        "id": plan_id, "status": "stale", "updatedAt": _timestamp(self.clock()),
                    })
                    raise ValidationError(f"system plan is stale: {key} changed")

            for status_value in ("confirmed", "applying"):
                self._replace(state_path, {
                    "id": plan_id, "status": status_value, "updatedAt": _timestamp(self.clock()),
                })
            try:
                current = self._evidence(plan["operationId"])
            except Exception:
                self._replace(state_path, {
                    "id": plan_id, "status": "failed", "updatedAt": _timestamp(self.clock()),
                })
                raise
            receipt_id = str(uuid4())
            self._replace(state_path, {
                "id": plan_id, "status": "verifying", "updatedAt": _timestamp(self.clock()),
                "receiptId": receipt_id,
            })
            receipt = {
                "schemaVersion": RECEIPT_SCHEMA,
                "id": receipt_id,
                "planId": plan_id,
                "planDigest": plan["digest"],
                "operationId": plan["operationId"],
                "creatorUid": caller_uid,
                "status": "succeeded",
                "completedAt": _timestamp(self.clock()),
                "preState": plan["preState"],
                "verifiedState": current,
                "changed": False,
                "rollback": "not-applicable",
            }
            receipt["digest"] = document_digest(receipt)
            self._write_new(self._path("receipts", receipt_id), receipt)
            self._replace(state_path, {
                "id": plan_id, "status": "succeeded", "updatedAt": receipt["completedAt"],
                "receiptId": receipt_id,
            })
            return receipt

    def get_receipt(self, receipt_id: str, caller_uid: int) -> dict[str, Any]:
        receipt = self._load(self._path("receipts", receipt_id))
        if receipt.get("creatorUid") != caller_uid:
            raise ValidationError("system receipt belongs to a different caller")
        if receipt.get("digest") != document_digest(receipt):
            raise ValidationError("system receipt digest is invalid")
        return receipt

    def action_for_plan(self, plan_id: str, caller_uid: int) -> str:
        plan = self._load(self._path("plans", plan_id))
        if plan.get("creatorUid") != caller_uid:
            raise ValidationError("system plan belongs to a different caller")
        return self.operation_action(str(plan.get("operationId", "")))

    def operation_action(self, operation_id: str) -> str:
        try:
            return str(OPERATIONS[operation_id]["action"])
        except KeyError as exc:
            raise ValidationError(f"unsupported system operation: {operation_id}") from exc

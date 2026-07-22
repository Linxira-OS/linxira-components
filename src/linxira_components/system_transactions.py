from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import shutil
import stat
import subprocess
import threading
from typing import Any, Callable
from uuid import UUID, uuid4

from .errors import ValidationError
from .jsonio import document_digest


PLAN_SCHEMA = "org.linxira.components.system-plan.v1"
RECEIPT_SCHEMA = "org.linxira.components.system-receipt.v1"
REGISTRY_VERSION = "2026.07.22.4"
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
    "org.linxira.hardware.driver-state-diagnose.v1": {
        "action": "org.linxira.components.inspect",
        "lockDomain": "hardware-diagnostics",
        "risk": "read-only",
        "rollback": "not-applicable",
    },
    "org.linxira.driver.vm-hyperv-guest.v1": {
        "action": "org.linxira.components.driver",
        "lockDomain": "system-packages",
        "risk": "system-change-reboot-possible",
        "rollback": "pre-change-timeshift-snapshot-separate-restore-authorization",
    },
    "org.linxira.driver.vm-qemu-guest.v1": {
        "action": "org.linxira.components.driver",
        "lockDomain": "system-packages",
        "risk": "system-change-reboot-possible",
        "rollback": "pre-change-timeshift-snapshot-separate-restore-authorization",
    },
    "org.linxira.driver.vm-vmware-guest.v1": {
        "action": "org.linxira.components.driver",
        "lockDomain": "system-packages",
        "risk": "system-change-reboot-possible",
        "rollback": "pre-change-timeshift-snapshot-separate-restore-authorization",
    },
}
REGISTRY_DIGEST = hashlib.sha256(
    json.dumps({"version": REGISTRY_VERSION, "operations": OPERATIONS}, sort_keys=True).encode()
).hexdigest()
ID_RE = re.compile(r"^[0-9a-f-]{36}$")
MACHINE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
BOOT_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-(?:(?:0|[1-9][0-9]*)|(?:[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))"
    r"(?:\.(?:(?:0|[1-9][0-9]*)|(?:[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
PCI_BUS_RE = re.compile(r"^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$")
PCI_ID_RE = re.compile(r"^[0-9a-f]{4}$")
HARDWARE_PROFILE_IDS = frozenset({
    "cpu.amd", "cpu.intel", "graphics.amd", "graphics.hybrid", "graphics.intel",
    "graphics.nvidia", "vm.hyperv", "vm.qemu", "vm.virtualbox", "vm.vmware", "vm.xen",
})
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


def _bounded_process(command: list[str], *, limit: int, timeout: int, env: dict[str, str]):
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        env=env,
        start_new_session=os.name == "posix",
    )
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    size = 0
    exceeded = threading.Event()
    size_lock = threading.Lock()

    def kill_group() -> None:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass

    def read_output(stream, chunks) -> None:
        nonlocal size
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                return
            with size_lock:
                size += len(chunk)
                if size > limit:
                    exceeded.set()
                    kill_group()
                    return
            chunks.append(chunk)

    assert process.stdout is not None and process.stderr is not None
    readers = (
        threading.Thread(target=read_output, args=(process.stdout, stdout_chunks), daemon=True),
        threading.Thread(target=read_output, args=(process.stderr, stderr_chunks), daemon=True),
    )
    for reader in readers:
        reader.start()
    timed_out = False
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        kill_group()
        returncode = process.wait()
    for reader in readers:
        reader.join(timeout=5)
    if any(reader.is_alive() for reader in readers):
        kill_group()
        process.stdout.close()
        process.stderr.close()
        for reader in readers:
            reader.join(timeout=5)
    streams_open = any(reader.is_alive() for reader in readers)
    process.stdout.close()
    process.stderr.close()
    if streams_open:
        raise ValidationError("hardware detector output streams did not close")
    if timed_out:
        raise subprocess.TimeoutExpired(command, timeout)
    if exceeded.is_set():
        raise ValidationError("hardware detector output exceeds size limit")
    return subprocess.CompletedProcess(
        command, returncode, b"".join(stdout_chunks), b"".join(stderr_chunks)
    )


class SystemTransactionStore:
    def __init__(
        self,
        state_root: Path = Path("/var/lib/linxira/components/system-transactions"),
        system_root: Path = Path("/"),
        *,
        runner: Runner = subprocess.run,
        clock: Callable[[], datetime] = _now,
        mutation_executor: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
        recover: bool = True,
    ) -> None:
        self.state_root = state_root
        self.system_root = system_root
        self.runner = runner
        self.clock = clock
        self.mutation_executor = mutation_executor
        self._lock = threading.RLock()
        for name in ("plans", "state", "receipts", "worker-results", "worker-progress"):
            directory = self.state_root / name
            directory.mkdir(parents=True, exist_ok=True, mode=0o750)
            if directory.is_symlink() or not directory.is_dir():
                raise ValidationError(f"unsafe system transaction directory: {directory}")
            try:
                directory.chmod(0o750)
            except OSError as exc:
                raise ValidationError(f"cannot secure system transaction directory: {directory}") from exc
        cache = self.state_root / "worker-cache"
        cache.mkdir(parents=True, exist_ok=True, mode=0o700)
        if cache.is_symlink() or not cache.is_dir():
            raise ValidationError(f"unsafe system transaction directory: {cache}")
        cache.chmod(0o700)
        if recover:
            self.recover_interrupted()

    def _run_fixed(self, command: list[str], timeout: int, limit: int):
        environment = {"PATH": "/usr/bin:/usr/sbin", "LC_ALL": "C"}
        try:
            if self.runner is subprocess.run:
                result = _bounded_process(command, limit=limit, timeout=timeout, env=environment)
            else:
                result = self.runner(
                    command, check=False, capture_output=True, text=True, timeout=timeout,
                    shell=False, env=environment,
                )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValidationError(f"fixed system command failed: {command[0]}") from exc
        stdout_value = result.stdout or b""
        stderr_value = result.stderr or b""
        stdout_bytes = stdout_value.encode() if isinstance(stdout_value, str) else stdout_value
        stderr_bytes = stderr_value.encode() if isinstance(stderr_value, str) else stderr_value
        if len(stdout_bytes) + len(stderr_bytes) > limit:
            raise ValidationError(f"fixed system command output exceeds limit: {command[0]}")
        try:
            stdout = stdout_bytes.decode("utf-8", errors="strict")
            stderr = stderr_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValidationError(f"fixed system command output is not UTF-8: {command[0]}") from exc
        return subprocess.CompletedProcess(command, result.returncode, stdout, stderr)

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

    def _hardware_driver_evidence(self) -> dict[str, Any]:
        command = ["/usr/bin/linxira-chwd-detector"]
        try:
            environment = {"PATH": "/usr/bin", "LC_ALL": "C"}
            if self.runner is subprocess.run:
                result = _bounded_process(command, limit=512 * 1024, timeout=10, env=environment)
            else:
                result = self.runner(
                    command, check=False, capture_output=True, text=True, timeout=10,
                    shell=False, env=environment,
                )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValidationError("hardware detector is unavailable") from exc
        raw_value = result.stdout or b""
        raw_bytes = raw_value.encode("utf-8") if isinstance(raw_value, str) else raw_value
        try:
            raw = raw_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValidationError("hardware detector output is not valid UTF-8") from exc
        if result.returncode != 0:
            raise ValidationError(f"hardware detector failed with status {result.returncode}")
        if len(raw_bytes) > 512 * 1024:
            raise ValidationError("hardware detector output exceeds size limit")

        def reject_duplicates(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValidationError(f"duplicate hardware detector field: {key}")
                value[key] = item
            return value

        try:
            document = json.loads(raw, object_pairs_hook=reject_duplicates)
        except json.JSONDecodeError as exc:
            raise ValidationError("hardware detector returned invalid JSON") from exc
        self._validate_hardware_document(document)
        return {
            "detector": document["detector"],
            "evidence": document["evidence"],
            "profileIds": document["profile_ids"],
            "warnings": document["warnings"],
            "rawSha256": hashlib.sha256(raw_bytes).hexdigest(),
        }

    @staticmethod
    def _validate_hardware_document(document: Any) -> None:
        def exact(value: Any, name: str, keys: set[str]) -> dict[str, Any]:
            if not isinstance(value, dict) or set(value) != keys:
                raise ValidationError(f"hardware detector {name} has invalid fields")
            return value

        root = exact(
            document, "root", {"schema_version", "detector", "evidence", "profile_ids", "warnings"}
        )
        if type(root["schema_version"]) is not int or root["schema_version"] != 1:
            raise ValidationError("hardware detector schema version is unsupported")
        metadata = exact(root["detector"], "metadata", {"name", "version", "upstream_chwd"})
        if metadata["name"] != "linxira-chwd-detector":
            raise ValidationError("hardware detector identity is invalid")
        if not all(
            isinstance(metadata[key], str) and SEMVER_RE.fullmatch(metadata[key])
            for key in ("version", "upstream_chwd")
        ):
            raise ValidationError("hardware detector version is invalid")
        evidence = exact(root["evidence"], "evidence", {"pci", "dmi", "cpu", "virtualization"})
        if not isinstance(evidence["pci"], list) or len(evidence["pci"]) > 4096:
            raise ValidationError("hardware detector PCI evidence is invalid")
        for item in evidence["pci"]:
            device = exact(item, "PCI device", {"bus_id", "class_id", "vendor_id", "device_id"})
            if (
                not isinstance(device["bus_id"], str)
                or not PCI_BUS_RE.fullmatch(device["bus_id"])
                or not all(
                    isinstance(device[key], str) and PCI_ID_RE.fullmatch(device[key])
                    for key in ("class_id", "vendor_id", "device_id")
                )
            ):
                raise ValidationError("hardware detector PCI value is invalid")
        bus_ids = [item["bus_id"] for item in evidence["pci"]]
        if bus_ids != sorted(set(bus_ids)):
            raise ValidationError("hardware detector PCI devices are not sorted and unique")
        for name, keys in (
            ("dmi", {"system_vendor", "product_name", "chassis_type"}),
            ("cpu", {"vendor", "family", "model"}),
        ):
            item = exact(evidence[name], name, keys)
            if not all(
                value is None or (isinstance(value, str) and "\x00" not in value and len(value) <= 1024)
                for value in item.values()
            ):
                raise ValidationError(f"hardware detector {name} value is invalid")
        virtualization_profiles = {
            "kvm": "vm.qemu", "qemu": "vm.qemu", "oracle": "vm.virtualbox",
            "vmware": "vm.vmware", "microsoft": "vm.hyperv", "xen": "vm.xen",
        }
        if evidence["virtualization"] is not None and evidence["virtualization"] not in virtualization_profiles:
            raise ValidationError("hardware detector virtualization value is invalid")
        profiles = root["profile_ids"]
        if (
            not isinstance(profiles, list)
            or not all(isinstance(item, str) for item in profiles)
            or profiles != sorted(set(profiles))
            or not set(profiles).issubset(HARDWARE_PROFILE_IDS)
        ):
            raise ValidationError("hardware detector profile IDs are invalid")
        expected_profiles = set()
        graphics_vendors = set()
        for device in evidence["pci"]:
            if device["class_id"] not in {"0300", "0302", "0380"}:
                continue
            graphics_vendors.add(device["vendor_id"])
            profile = {"1002": "graphics.amd", "8086": "graphics.intel", "10de": "graphics.nvidia"}.get(
                device["vendor_id"]
            )
            if profile:
                expected_profiles.add(profile)
        if len(graphics_vendors) > 1:
            expected_profiles.add("graphics.hybrid")
        cpu_profile = {
            "genuineintel": "cpu.intel", "authenticamd": "cpu.amd",
        }.get((evidence["cpu"]["vendor"] or "").lower())
        if cpu_profile:
            expected_profiles.add(cpu_profile)
        if evidence["virtualization"] is not None:
            expected_profiles.add(virtualization_profiles[evidence["virtualization"]])
        if profiles != sorted(expected_profiles):
            raise ValidationError("hardware detector profile IDs do not match evidence")
        warnings = root["warnings"]
        if not isinstance(warnings, list) or len(warnings) > 1024:
            raise ValidationError("hardware detector warnings are invalid")
        for item in warnings:
            warning = exact(item, "warning", {"source", "message"})
            if not all(isinstance(value, str) for value in warning.values()):
                raise ValidationError("hardware detector warning is invalid")
        warning_keys = [(item["source"], item["message"]) for item in warnings]
        if warning_keys != sorted(set(warning_keys)):
            raise ValidationError("hardware detector warnings are not sorted and unique")

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
        if operation_id == "org.linxira.hardware.driver-state-diagnose.v1":
            return self._hardware_driver_evidence()
        from .driver_worker import GUEST_SPECS, collect_guest_prestate
        if operation_id in GUEST_SPECS:
            return collect_guest_prestate(
                self.system_root, self._run_fixed, self._hardware_driver_evidence(),
                self._pacman_lock_evidence(), GUEST_SPECS[operation_id],
            )
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
        temporary = path.with_name(f".{path.name}.{uuid4().hex}.new")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(descriptor)
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise ValidationError(f"system transaction document already exists: {path.name}") from exc
        finally:
            temporary.unlink(missing_ok=True)
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
            try:
                plan = self._load(self._path("plans", str(document.get("id"))))
            except ValidationError:
                plan = None
            if (
                isinstance(plan, dict)
                and plan.get("operationId") in {
                    "org.linxira.driver.vm-hyperv-guest.v1",
                    "org.linxira.driver.vm-qemu-guest.v1",
                    "org.linxira.driver.vm-vmware-guest.v1",
                }
                and document.get("status") in {"applying", "verifying"}
                and (
                    document.get("status") == "applying"
                    or not isinstance(document.get("receiptId"), str)
                    or not self._path("receipts", str(document.get("receiptId"))).exists()
                )
            ):
                if self._worker_is_active(str(plan["id"])):
                    continue
                try:
                    from .driver_worker import _failed_result, validate_result
                    try:
                        result = self._load(self._path("worker-results", str(plan["id"])))
                    except ValidationError:
                        progress = self._load(self._path("worker-progress", str(plan["id"])))
                        if (
                            progress.get("schemaVersion") != "org.linxira.components.system-worker-progress.v1"
                            or progress.get("operationId") != plan["operationId"]
                            or progress.get("planId") != plan["id"]
                            or progress.get("planDigest") != plan["digest"]
                            or progress.get("digest") != document_digest(progress)
                        ):
                            raise ValidationError("invalid interrupted worker progress")
                        result = _failed_result(
                            plan, "worker interrupted after rollback snapshot; package state requires verification",
                            progress.get("snapshot"), True,
                        )
                        result["digest"] = document_digest(result)
                    validate_result(result, plan)
                    self._finalize_mutation(plan, result)
                    continue
                except ValidationError:
                    pass
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
                        and receipt.get("status") in {"succeeded", "failed"}
                        and isinstance(receipt.get("completedAt"), str)
                    ):
                        self._replace(path, {
                            "id": document.get("id"), "status": receipt.get("status"),
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

    def _worker_is_active(self, plan_id: str) -> bool:
        if self.system_root != Path("/"):
            return False
        try:
            result = subprocess.run(
                [
                    "/usr/bin/systemctl", "show", "--property=ActiveState", "--value",
                    f"linxira-components-worker@{plan_id}.service",
                ],
                check=False, capture_output=True, text=True, timeout=10, shell=False,
                env={"PATH": "/usr/bin", "LC_ALL": "C"},
            )
            return result.returncode == 0 and result.stdout.strip() in {"activating", "active", "reloading"}
        except (OSError, subprocess.TimeoutExpired):
            return False

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
                for collection in ("worker-progress", "worker-results"):
                    related = self._path(collection, str(plan["id"]))
                    if related.exists() and not related.is_symlink():
                        related.unlink()
                receipt_id = state.get("receiptId")
                if isinstance(receipt_id, str):
                    receipt_path = self._path("receipts", receipt_id)
                    if receipt_path.exists() and not receipt_path.is_symlink():
                        receipt_path.unlink()
                cache = self.state_root / "worker-cache" / str(plan["id"])
                if cache.is_dir() and not cache.is_symlink():
                    shutil.rmtree(cache)
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
            if plan["risk"] != "read-only":
                if current != plan["preState"]:
                    self._replace(state_path, {
                        "id": plan_id, "status": "stale", "updatedAt": _timestamp(self.clock()),
                    })
                    raise ValidationError("system state changed after the driver plan was created")
                if self.mutation_executor is None:
                    self._replace(state_path, {
                        "id": plan_id, "status": "failed", "updatedAt": _timestamp(self.clock()),
                    })
                    raise ValidationError("isolated system worker is unavailable")
                try:
                    result = self.mutation_executor(plan)
                    from .driver_worker import validate_result
                    result = validate_result(result, plan)
                except Exception:
                    self._replace(state_path, {
                        "id": plan_id, "status": "failed", "updatedAt": _timestamp(self.clock()),
                    })
                    raise
                completed_state = self._load(state_path)
                if completed_state.get("status") in {"succeeded", "failed"}:
                    receipt = self._load(self._path("receipts", str(completed_state.get("receiptId"))))
                    if (
                        receipt.get("planId") != plan_id or receipt.get("planDigest") != plan["digest"]
                        or receipt.get("digest") != document_digest(receipt)
                    ):
                        raise ValidationError("isolated worker finalized an invalid receipt")
                    return receipt
                return self._finalize_mutation(plan, result)
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
                "status": result["status"] if plan["risk"] != "read-only" else "succeeded",
                "completedAt": _timestamp(self.clock()),
                "preState": plan["preState"],
                "verifiedState": result["verifiedState"] if plan["risk"] != "read-only" else current,
                "changed": result["changed"] if plan["risk"] != "read-only" else False,
                "rollback": result["rollback"] if plan["risk"] != "read-only" else "not-applicable",
            }
            if plan["risk"] != "read-only":
                receipt["snapshot"] = result["snapshot"]
            receipt["digest"] = document_digest(receipt)
            self._write_new(self._path("receipts", receipt_id), receipt)
            self._replace(state_path, {
                "id": plan_id, "status": receipt["status"], "updatedAt": receipt["completedAt"],
                "receiptId": receipt_id,
            })
            return receipt

    def _finalize_mutation(self, plan: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        receipt_id = str(uuid4())
        receipt = {
            "schemaVersion": RECEIPT_SCHEMA,
            "id": receipt_id,
            "planId": plan["id"],
            "planDigest": plan["digest"],
            "operationId": plan["operationId"],
            "creatorUid": plan["creatorUid"],
            "status": result["status"],
            "completedAt": _timestamp(self.clock()),
            "preState": plan["preState"],
            "verifiedState": result["verifiedState"],
            "changed": result["changed"],
            "rollback": result["rollback"],
            "snapshot": result["snapshot"],
        }
        if result["status"] == "failed":
            receipt["error"] = result["error"]
        receipt["digest"] = document_digest(receipt)
        self._replace(self._path("state", plan["id"]), {
            "id": plan["id"], "status": "verifying", "updatedAt": receipt["completedAt"],
            "receiptId": receipt_id,
        })
        self._write_new(self._path("receipts", receipt_id), receipt)
        self._replace(self._path("state", plan["id"]), {
            "id": plan["id"], "status": receipt["status"], "updatedAt": receipt["completedAt"],
            "receiptId": receipt_id,
        })
        return receipt

    def execute_worker(self, plan_id: str) -> dict[str, Any]:
        from .driver_worker import GUEST_SPECS, apply_guest
        plan = self._load(self._path("plans", plan_id))
        state = self._load(self._path("state", plan_id))
        spec = GUEST_SPECS.get(str(plan.get("operationId")))
        if (
            plan.get("schemaVersion") != PLAN_SCHEMA or plan.get("digest") != document_digest(plan)
            or spec is None or state.get("status") != "applying"
        ):
            raise ValidationError("worker plan or state is invalid")
        for key, value in self._binding().items():
            if plan.get(key) != value:
                raise ValidationError(f"worker plan is stale: {key} changed")
        current = self._evidence(spec.operation_id)
        if current != plan.get("preState"):
            raise ValidationError("system state changed before isolated driver apply")
        def checkpoint(snapshot):
            progress = {
                "schemaVersion": "org.linxira.components.system-worker-progress.v1",
                "planId": plan["id"], "planDigest": plan["digest"],
                "operationId": spec.operation_id, "snapshot": snapshot,
            }
            progress["digest"] = document_digest(progress)
            self._write_new(self._path("worker-progress", plan["id"]), progress)

        result = apply_guest(
            plan, self._run_fixed, lambda: self._evidence(spec.operation_id),
            self.state_root / "worker-cache", spec, checkpoint,
        )
        result["digest"] = document_digest(result)
        self._write_new(self._path("worker-results", plan_id), result)
        from .driver_worker import validate_result
        validate_result(result, plan)
        self._finalize_mutation(plan, result)
        return result

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

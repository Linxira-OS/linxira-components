from __future__ import annotations

import hashlib
import base64
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
from typing import Any, Callable

from .errors import ValidationError
from .jsonio import document_digest


HYPERV_OPERATION = "org.linxira.driver.vm-hyperv-guest.v1"
RESULT_SCHEMA = "org.linxira.components.system-worker-result.v1"
PACKAGE_NAME_RE = re.compile(r"^[a-z0-9@._+:-]+$")
SNAPSHOT_RE = re.compile(
    r"^\s*[0-9]+\s+>\s+(?P<name>[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2})"
    r"\s+(?P<tags>[OBHDWM]+)\s+(?P<comment>.*)$"
)
RunFixed = Callable[[list[str], int, int], subprocess.CompletedProcess]
HYPERV_SERVICES = ("hv_kvp_daemon.service", "hv_vss_daemon.service")


def _strict_object(path: Path, limit: int = 128 * 1024) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise ValidationError(f"unsafe system file: {path}")
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValidationError(f"system file is unavailable: {path}") from exc

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValidationError(f"duplicate system file field: {key}")
            value[key] = item
        return value

    try:
        document = json.loads(raw, object_pairs_hook=unique)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid system JSON file: {path}") from exc
    if not isinstance(document, dict):
        raise ValidationError(f"system JSON file is not an object: {path}")
    return document


def _sync_database_digest(root: Path) -> str:
    directory = root / "var/lib/pacman/sync"
    entries: list[tuple[str, str]] = []
    try:
        paths = sorted(directory.glob("*.db"))
    except OSError as exc:
        raise ValidationError("pacman sync databases are unavailable") from exc
    if not paths:
        raise ValidationError("pacman sync databases are unavailable")
    if len(paths) > 64:
        raise ValidationError("too many pacman sync databases")
    for path in paths:
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 64 * 1024 * 1024:
            raise ValidationError("pacman sync database is unsafe")
        entries.append((path.name, hashlib.sha256(path.read_bytes()).hexdigest()))
    return hashlib.sha256(json.dumps(entries, separators=(",", ":")).encode()).hexdigest()


def _root_mount(run: RunFixed) -> dict[str, Any]:
    result = run([
        "/usr/bin/findmnt", "--json", "--bytes", "--output",
        "TARGET,SOURCE,FSTYPE,FSROOTS,UUID,AVAIL,SIZE", "/",
    ], 10, 128 * 1024)
    try:
        document = json.loads(result.stdout) if result.returncode == 0 else None
        filesystems = document.get("filesystems", []) if isinstance(document, dict) else []
        mount = filesystems[0] if len(filesystems) == 1 and isinstance(filesystems[0], dict) else None
        available = int(mount["avail"]) if mount else 0
        size = int(mount["size"]) if mount else 0
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        mount, available, size = None, 0, 0
    if not mount or mount.get("target") != "/" or mount.get("fstype") != "btrfs":
        raise ValidationError("Hyper-V driver apply requires a Btrfs root filesystem")
    if available < 2 * 1024**3 or not size or available / size < 0.10:
        raise ValidationError("insufficient Btrfs free space for a pre-change snapshot")
    filesystem_uuid = mount.get("uuid")
    fs_roots = mount.get("fsroots")
    if not isinstance(filesystem_uuid, str) or not filesystem_uuid or fs_roots not in ("@", "/@", ["@"], ["/@"]):
        raise ValidationError("Btrfs root layout is incompatible with Timeshift")
    return {
        "target": "/", "source": mount.get("source"), "filesystem": "btrfs",
        "fsRoots": fs_roots, "filesystemUuid": filesystem_uuid,
        "availableBytes": available, "sizeBytes": size,
    }


def _sync_metadata(root: Path) -> dict[str, dict[str, str]]:
    packages = {}
    try:
        config_lines = (root / "etc/pacman.conf").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise ValidationError("pacman configuration is unavailable") from exc
    repositories = []
    for line in config_lines:
        line = line.strip()
        if line.startswith("[") and line.endswith("]") and line != "[options]":
            name = line[1:-1]
            if not PACKAGE_NAME_RE.fullmatch(name) or name in repositories:
                raise ValidationError("pacman repository order is invalid")
            repositories.append(name)
    if not repositories:
        raise ValidationError("pacman repository order is unavailable")
    for repository in repositories:
        database = root / "var/lib/pacman/sync" / f"{repository}.db"
        if not database.is_file() or database.is_symlink():
            raise ValidationError(f"active pacman repository database is unavailable: {repository}")
        try:
            with tarfile.open(database, "r:*") as archive:
                members = [item for item in archive.getmembers() if item.isfile() and item.name.endswith("/desc")]
                if len(members) > 200_000:
                    raise ValidationError("pacman sync database has too many package records")
                for member in members:
                    if member.size > 256 * 1024:
                        raise ValidationError("pacman package metadata exceeds size limit")
                    stream = archive.extractfile(member)
                    text = stream.read().decode("utf-8", errors="strict") if stream else ""
                    fields = {}
                    lines = text.splitlines()
                    index = 0
                    while index < len(lines):
                        marker = lines[index]
                        index += 1
                        if not (marker.startswith("%") and marker.endswith("%")):
                            continue
                        values = []
                        while index < len(lines) and lines[index] != "":
                            values.append(lines[index])
                            index += 1
                        fields[marker] = values
                        index += 1
                    required = ("%NAME%", "%VERSION%", "%FILENAME%", "%CSIZE%", "%SHA256SUM%", "%PGPSIG%")
                    if not all(len(fields.get(key, [])) == 1 for key in required):
                        continue
                    name = fields["%NAME%"][0]
                    try:
                        size = int(fields["%CSIZE%"][0])
                        signature = base64.b64decode(fields["%PGPSIG%"][0], validate=True)
                    except (ValueError, TypeError) as exc:
                        raise ValidationError("pacman package metadata has invalid size or signature") from exc
                    packages.setdefault(name, {
                        "repository": repository,
                        "version": fields["%VERSION%"][0],
                        "filename": fields["%FILENAME%"][0],
                        "size": str(size),
                        "sha256": fields["%SHA256SUM%"][0],
                        "signature": fields["%PGPSIG%"][0],
                        "signatureSha256": hashlib.sha256(signature).hexdigest(),
                    })
        except (OSError, tarfile.TarError, UnicodeDecodeError) as exc:
            raise ValidationError("pacman sync database metadata is invalid") from exc
    return packages


def _package_artifacts(root: Path, run: RunFixed) -> list[dict[str, str]]:
    result = run([
        "/usr/bin/pacman", "--sync", "--print", "--print-format", "%n\t%v\t%l", "--", "hyperv",
    ], 30, 512 * 1024)
    if result.returncode != 0:
        raise ValidationError("pacman cannot resolve the fixed Hyper-V package cohort")
    artifacts = []
    for line in result.stdout.splitlines():
        fields = line.split("\t")
        if (
            len(fields) != 3 or not PACKAGE_NAME_RE.fullmatch(fields[0]) or not fields[1]
            or not fields[2].startswith(("https://", "http://", "file://"))
        ):
            raise ValidationError("pacman returned malformed package resolution data")
        artifacts.append({"name": fields[0], "version": fields[1], "location": fields[2]})
    if not artifacts or len({item["name"] for item in artifacts}) != len(artifacts):
        raise ValidationError("pacman package resolution is empty or duplicated")
    artifacts.sort(key=lambda item: (item["name"], item["version"]))
    if not any(item["name"] == "hyperv" for item in artifacts):
        raise ValidationError("pacman resolution omitted the fixed Hyper-V package")
    metadata = _sync_metadata(root)
    for artifact in artifacts:
        record = metadata.get(artifact["name"])
        if (
            record is None or record["version"] != artifact["version"]
            or not artifact["location"].endswith("/" + record["filename"])
            or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])
        ):
            raise ValidationError("pacman resolution does not match signed sync metadata")
        artifact.update(record)
    return artifacts


def _installed_version(run: RunFixed) -> str | None:
    result = run(["/usr/bin/pacman", "--query", "--", "hyperv"], 10, 64 * 1024)
    if result.returncode != 0:
        return None
    fields = result.stdout.strip().split()
    if len(fields) != 2 or fields[0] != "hyperv":
        raise ValidationError("pacman returned malformed installed Hyper-V state")
    return fields[1]


def _service_state(run: RunFixed, service: str) -> str:
    result = run(["/usr/bin/systemctl", "is-enabled", service], 10, 64 * 1024)
    value = result.stdout.strip()
    if value in {"enabled", "enabled-runtime", "disabled", "static", "masked", "not-found"}:
        return value
    return "unavailable"


def collect_hyperv_prestate(
    root: Path, run: RunFixed, hardware: dict[str, Any], package_lock: dict[str, Any]
) -> dict[str, Any]:
    if "vm.hyperv" not in hardware.get("profileIds", []):
        raise ValidationError("Hyper-V driver apply is not applicable to detected hardware")
    if package_lock.get("lock", {}).get("exists") is not False or package_lock.get("packageProcesses"):
        raise ValidationError("another package transaction is active")
    config = _strict_object(root / "etc/timeshift/timeshift.json")
    if config.get("btrfs_mode") not in {"true", True}:
        raise ValidationError("Timeshift Btrfs mode is not configured")
    try:
        executable = (root / "usr/bin/timeshift").lstat()
    except OSError:
        executable = None
    if (
        executable is None or not stat.S_ISREG(executable.st_mode)
        or (os.name == "posix" and not executable.st_mode & 0o111)
    ):
        raise ValidationError("Timeshift is unavailable")
    root_mount = _root_mount(run)
    if config.get("backup_device_uuid") != root_mount["filesystemUuid"]:
        raise ValidationError("Timeshift snapshot device does not match the running Btrfs root")
    state = {
        "hardware": hardware,
        "snapshot": {"ready": True, "mode": "btrfs", "root": root_mount},
        "package": {
            "target": "hyperv", "installedVersion": _installed_version(run),
            "artifacts": _package_artifacts(root, run),
            "syncDatabaseSha256": _sync_database_digest(root),
        },
        "packageLock": package_lock,
        "services": {service: _service_state(run, service) for service in HYPERV_SERVICES},
    }
    expected = next(item["version"] for item in state["package"]["artifacts"] if item["name"] == "hyperv")
    if state["package"]["installedVersion"] == expected:
        raise ValidationError("the fixed Hyper-V guest package is already at the planned version")
    return state


def _snapshots(text: str) -> dict[str, dict[str, str]]:
    values = {}
    for line in text.splitlines():
        match = SNAPSHOT_RE.fullmatch(line)
        if match:
            values[match.group("name")] = match.groupdict()
    return values


def _failed_result(plan: dict[str, Any], error: str, snapshot: dict[str, str] | None, changed: bool):
    return {
        "schemaVersion": RESULT_SCHEMA,
        "planId": plan["id"], "planDigest": plan["digest"], "operationId": HYPERV_OPERATION,
        "status": "failed", "changed": changed, "snapshot": snapshot,
        "verifiedState": None, "error": error[:240],
        "rollback": (
            "timeshift-restore-requires-separate-authorization-and-reboot"
            if snapshot else "not-available"
        ),
    }


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _alpm_commit(package_paths: list[str], before_commit: Callable[[], None]) -> None:
    try:
        import pyalpm
        from pycman.config import init_with_config
    except ImportError as exc:
        raise ValidationError("python-pyalpm transaction support is unavailable") from exc
    handle = init_with_config("/etc/pacman.conf")
    try:
        packages = [handle.load_pkg(path) for path in package_paths]
        transaction = handle.init_transaction()
        try:
            for package in packages:
                transaction.add_pkg(package)
            transaction.prepare()
            before_commit()
            transaction.commit()
        finally:
            transaction.release()
    except pyalpm.error as exc:
        raise ValidationError("libalpm Hyper-V package transaction failed") from exc


def apply_hyperv(
    plan: dict[str, Any], run: RunFixed, revalidate: Callable[[], dict[str, Any]], cache_root: Path,
    checkpoint: Callable[[dict[str, str]], None] = lambda snapshot: None,
    commit_packages: Callable[[list[str], Callable[[], None]], None] = _alpm_commit,
) -> dict[str, Any]:
    comment = f"linxira-pre-change-{plan['id']}"
    snapshot = None
    install_started = False
    try:
        cache = cache_root / plan["id"]
        cache.mkdir(mode=0o700, parents=False, exist_ok=False)
        download = run([
            "/usr/bin/pacman", "--sync", "--downloadonly", "--disable-sandbox", "--noconfirm",
            "--cachedir", str(cache),
            "--", "hyperv",
        ], 900, 1024 * 1024)
        if download.returncode != 0:
            raise ValidationError("fixed Hyper-V package download failed")
        expected_files = {item["filename"] for item in plan["preState"]["package"]["artifacts"]}
        downloaded_files = {item.name for item in cache.iterdir() if item.name.endswith((".pkg.tar.zst", ".pkg.tar.xz"))}
        if downloaded_files != expected_files:
            raise ValidationError("downloaded Hyper-V package cohort does not match the plan")
        package_paths = []
        for artifact in plan["preState"]["package"]["artifacts"]:
            package = cache / artifact["filename"]
            signature = package.with_name(package.name + ".sig")
            if package.is_symlink() or not package.is_file() or package.stat().st_size != int(artifact["size"]):
                raise ValidationError("downloaded Hyper-V artifact is missing or has the wrong size")
            if _file_sha256(package) != artifact["sha256"]:
                raise ValidationError("downloaded Hyper-V artifact hash does not match the plan")
            signature_bytes = base64.b64decode(artifact["signature"], validate=True)
            if signature.exists():
                if signature.is_symlink() or _file_sha256(signature) != artifact["signatureSha256"]:
                    raise ValidationError("downloaded Hyper-V signature does not match the plan")
            else:
                descriptor = os.open(signature, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    os.write(descriptor, signature_bytes)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            identity = run(["/usr/bin/pacman", "--query", "--file", "--", str(package)], 30, 64 * 1024)
            if identity.returncode != 0 or identity.stdout.strip().split() != [artifact["name"], artifact["version"]]:
                raise ValidationError("downloaded Hyper-V artifact identity does not match the plan")
            signature_result = run(["/usr/bin/pacman-key", "--verify", str(signature), str(package)], 30, 128 * 1024)
            if signature_result.returncode != 0:
                raise ValidationError("downloaded Hyper-V artifact signature is invalid")
            package_paths.append(str(package))

        if revalidate() != plan["preState"]:
            raise ValidationError("system state changed before package transaction locking")

        def create_snapshot_with_alpm_lock() -> None:
            nonlocal snapshot, install_started
            before_result = run(["/usr/bin/timeshift", "--list", "--scripted"], 30, 1024 * 1024)
            if before_result.returncode not in {0, 1}:
                raise ValidationError("Timeshift snapshot inventory is unavailable")
            before = _snapshots(before_result.stdout)
            snapshot_result = run([
                "/usr/bin/timeshift", "--create", "--scripted", "--comments", comment, "--tags", "O",
            ], 900, 1024 * 1024)
            if snapshot_result.returncode != 0:
                raise ValidationError("pre-change Timeshift snapshot failed")
            after_result = run(["/usr/bin/timeshift", "--list", "--scripted"], 30, 1024 * 1024)
            if after_result.returncode != 0:
                raise ValidationError("created Timeshift snapshot inventory is unavailable")
            after = _snapshots(after_result.stdout)
            created = [name for name in after if name not in before and after[name]["comment"] == comment]
            if len(created) != 1 or after[created[0]]["tags"] != "O":
                raise ValidationError("pre-change Timeshift snapshot could not be verified")
            snapshot = {"name": created[0], "comment": comment, "tag": "O"}
            checkpoint(snapshot)
            install_started = True

        commit_packages(package_paths, create_snapshot_with_alpm_lock)
        enable = run(["/usr/bin/systemctl", "enable", *HYPERV_SERVICES], 30, 128 * 1024)
        if enable.returncode != 0:
            raise ValidationError("Hyper-V integration services could not be enabled")
        services = {service: _service_state(run, service) for service in HYPERV_SERVICES}
        if any(state != "enabled" for state in services.values()):
            raise ValidationError("Hyper-V integration service enablement failed verification")
        verified = []
        for artifact in plan["preState"]["package"]["artifacts"]:
            verify = run(["/usr/bin/pacman", "--query", "--", artifact["name"]], 10, 64 * 1024)
            fields = verify.stdout.strip().split() if verify.returncode == 0 else []
            if fields != [artifact["name"], artifact["version"]]:
                raise ValidationError("installed Hyper-V package cohort failed verification")
            verified.append({"name": artifact["name"], "version": artifact["version"]})
        return {
            "schemaVersion": RESULT_SCHEMA,
            "planId": plan["id"], "planDigest": plan["digest"], "operationId": HYPERV_OPERATION,
            "status": "succeeded", "changed": True, "snapshot": snapshot,
            "verifiedState": {"artifacts": verified, "services": services},
            "rollback": "timeshift-restore-requires-separate-authorization-and-reboot",
        }
    except ValidationError as exc:
        return _failed_result(plan, str(exc), snapshot, install_started)


def validate_result(result: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    if (
        result.get("schemaVersion") != RESULT_SCHEMA or result.get("planId") != plan.get("id")
        or result.get("planDigest") != plan.get("digest")
        or result.get("operationId") != HYPERV_OPERATION or result.get("status") not in {"succeeded", "failed"}
        or not isinstance(result.get("changed"), bool)
        or result.get("digest") != document_digest(result)
    ):
        raise ValidationError("system worker returned an invalid result")
    snapshot = result.get("snapshot")
    if snapshot is not None and (
        not isinstance(snapshot, dict)
        or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2}", str(snapshot.get("name", "")))
        or snapshot.get("comment") != f"linxira-pre-change-{plan['id']}" or snapshot.get("tag") != "O"
    ):
        raise ValidationError("system worker returned an invalid snapshot identity")
    if result["status"] == "succeeded" and (snapshot is None or not isinstance(result.get("verifiedState"), dict)):
        raise ValidationError("system worker omitted successful verification evidence")
    expected_verified = {
        "artifacts": [
            {"name": item["name"], "version": item["version"]}
            for item in plan["preState"]["package"]["artifacts"]
        ],
        "services": {service: "enabled" for service in HYPERV_SERVICES},
    }
    if result["status"] == "succeeded" and (
        result["changed"] is not True or result.get("verifiedState") != expected_verified
        or result.get("rollback") != "timeshift-restore-requires-separate-authorization-and-reboot"
    ):
        raise ValidationError("system worker success claims do not match the plan")
    if result["status"] == "failed" and (
        not isinstance(result.get("error"), str) or not result["error"]
        or result.get("verifiedState") is not None
        or (snapshot is None and (result["changed"] or result.get("rollback") != "not-available"))
        or (snapshot is not None and result.get("rollback") != "timeshift-restore-requires-separate-authorization-and-reboot")
    ):
        raise ValidationError("system worker failure claims are inconsistent")
    return result

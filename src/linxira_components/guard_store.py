"""工作区守护的唯一写路径。

设计前提: 快照由 root 定时器生成, 落在用户碰不到的地方; 恢复永远写新目录。
本模块用纯 os/shutil 实现, 不起子进程 —— 符号链接语义、manifest 原子写与错误分类
必须完全可控, 交给 rsync 或 restic 会把它们退化成对子进程输出的字符串解析。
"""
from __future__ import annotations

import configparser
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import time
from typing import Any

from .errors import ValidationError


CONFIG_PATH = "/etc/linxira/workspace-guard.conf"
REGISTERED_SCHEMA = "org.linxira.components.guard-registration.v1"
MANIFEST_NAME = "guard-manifest.json"
MANIFEST_SCHEMA = "org.linxira.components.guard-manifest.v1"
REGISTERED_NAME = "registered.json"
SNAPSHOT_ID_RE = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}")
GIT = "/usr/bin/git"
DEFAULT_SCHEDULE = "*:0/30"
DEFAULT_KEEP_SCHEDULED = 24
DEFAULT_KEEP_MANUAL = 10
BY_UUID = "/dev/disk/by-uuid"
MOUNT = "/usr/bin/mount"
BLKID = "/usr/bin/blkid"
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
TRIGGERS = ("scheduled", "manual")


def _positive_int(value: str, name: str) -> int:
    text = str(value).strip()
    if not re.fullmatch(r"[0-9]+", text) or int(text) < 1:
        raise ValidationError(f"guard configuration {name} must be a positive integer")
    return int(text)


def read_config(path: str = CONFIG_PATH, owner_uid: int = 0) -> dict[str, Any]:
    """读守护配置。

    owner_uid 是配置必须归属的 uid, 生产环境恒为 0 —— 配置不可读是安全前提,
    不是可配置项。参数存在只是为了让非 root 的测试能覆盖读通路径。
    """
    if not os.path.exists(path):
        return {"configured": False}
    try:
        metadata = os.stat(path)
    except OSError as exc:
        raise ValidationError("guard configuration is unavailable") from exc
    if metadata.st_uid != owner_uid or stat.S_IMODE(metadata.st_mode) not in {0o600, 0o400}:
        raise ValidationError("guard configuration must be root-owned and private")
    parser = configparser.ConfigParser()
    try:
        with open(path, encoding="utf-8") as stream:
            parser.read_file(stream)
    except PermissionError as exc:
        # 配置对普通用户不可读是设计, 不是坏文件。
        raise ValidationError("guard configuration is not readable by this user") from exc
    except (configparser.Error, OSError, UnicodeDecodeError) as exc:
        raise ValidationError("guard configuration is not valid INI") from exc
    store = parser.get("guard", "store", fallback="").strip()
    if not store:
        return {"configured": False}
    return {
        "configured": True,
        "store": store,
        "store_uuid": parser.get("guard", "store_uuid", fallback="").strip() or None,
        "schedule": parser.get("guard", "schedule", fallback=DEFAULT_SCHEDULE).strip() or DEFAULT_SCHEDULE,
        "keep_scheduled": _positive_int(
            parser.get("guard", "keep_scheduled", fallback=str(DEFAULT_KEEP_SCHEDULED)), "keep_scheduled"
        ),
        "keep_manual": _positive_int(
            parser.get("guard", "keep_manual", fallback=str(DEFAULT_KEEP_MANUAL)), "keep_manual"
        ),
    }


def register_workspace(config: dict[str, Any], workspace_path: str) -> dict[str, Any]:
    """把工作区写进守护的登记表。定时器只遍历登记表, 没登记的一律不碰。"""
    if not config.get("configured"):
        return {"ok": False, "error": "guard store is not configured"}
    if not os.path.isabs(workspace_path):
        return {"ok": False, "error": "workspace path must be absolute"}
    workspace = Path(workspace_path)
    if workspace.is_symlink() or not workspace.is_dir():
        return {"ok": False, "error": "workspace is not an existing directory"}
    identifier = workspace_id(workspace_path)
    root = workspace_root(config, identifier)
    document = {
        "schema": REGISTERED_SCHEMA,
        "workspace_id": identifier,
        "workspace_path": os.path.realpath(workspace_path),
        "registered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    try:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(root, 0o700)
        _atomic_write(root, REGISTERED_NAME, document)
    except OSError as exc:
        return {"ok": False, "error": f"guard store is not writable: {exc.strerror or exc}"}
    return {"ok": True, "workspace_id": identifier, "workspace_path": document["workspace_path"]}


def unregister_workspace(config: dict[str, Any], workspace_path: str) -> dict[str, Any]:
    """注销只停掉后续快照, 已有的恢复点一个都不删。"""
    if not config.get("configured"):
        return {"ok": False, "error": "guard store is not configured"}
    if not os.path.isabs(workspace_path):
        return {"ok": False, "error": "workspace path must be absolute"}
    identifier = workspace_id(workspace_path)
    registered = workspace_root(config, identifier) / REGISTERED_NAME
    if not registered.is_file():
        return {"ok": False, "error": "workspace is not registered"}
    try:
        registered.unlink()
    except OSError as exc:
        return {"ok": False, "error": f"registration could not be removed: {exc.strerror or exc}"}
    return {"ok": True, "workspace_id": identifier, "snapshots": len(list_snapshots(config, workspace_path))}


def guard_status(config: dict[str, Any]) -> dict[str, Any]:
    """只读汇总。清单里逐项展开太吵, 这里只给计数。"""
    if not config.get("configured"):
        return {"configured": False, "store": None, "workspaces": [], "snapshot_count": 0}
    workspaces = []
    for directory in _snapshot_directories(config):
        try:
            document = json.loads((directory / REGISTERED_NAME).read_text(encoding="utf-8"))
            path = str(document["workspace_path"])
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
            continue
        workspaces.append(
            {
                "workspace_id": directory.name,
                "workspace_path": path,
                "snapshot_count": len(list_snapshots(config, path)),
            }
        )
    return {
        "configured": True,
        "store": config["store"],
        "schedule": config["schedule"],
        "keep_scheduled": config["keep_scheduled"],
        "keep_manual": config["keep_manual"],
        "workspaces": workspaces,
        "snapshot_count": sum(item["snapshot_count"] for item in workspaces),
    }


def workspace_id(workspace_path: str) -> str:
    """同一路径恒得同一 id; 末段名字只留 [a-z0-9-], 便于人工辨认与排序。"""
    resolved = os.path.realpath(workspace_path)
    digest = hashlib.sha256(resolved.encode()).hexdigest()[:16]
    label = re.sub(r"[^a-z0-9-]", "-", os.path.basename(resolved).lower())[:32]
    return f"{digest}-{label}"


def workspace_root(config: dict[str, Any], identifier: str) -> Path:
    return Path(config["store"]) / "workspaces" / identifier


def ensure_store_mounted(config: dict[str, Any]) -> dict[str, Any]:
    """把守护分区挂到 store 路径上。

    守护盘刻意不进 fstab: 开机不挂载, 没有 root 的 agent 就够不着快照。
    代价是每次开机都要由 root 重新挂 —— 定时器与写操作在动手前先做这件事。
    没有 store_uuid 时不做任何事, 快照就落在 store 目录本身(单机同盘配置)。
    """
    if not config.get("configured"):
        return {"ok": False, "error": "guard store is not configured"}
    store = str(config["store"])
    uuid = str(config.get("store_uuid") or "")
    if not uuid:
        return {"ok": True, "mounted": False, "reason": "no-store-uuid-configured"}
    if not UUID_RE.match(uuid):
        return {"ok": False, "error": "guard configuration has a malformed store UUID"}
    if os.path.ismount(store):
        return {"ok": True, "mounted": True, "already": True}
    device = _device_for_uuid(uuid)
    if device is None:
        return {"ok": False, "error": f"guard partition {uuid} is not present"}
    try:
        Path(store).mkdir(parents=True, exist_ok=True, mode=0o700)
        result = subprocess.run(
            [MOUNT, "-t", "ext4", "-o", "noatime", device, store],
            shell=False, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "error": f"guard partition could not be mounted: {exc}"}
    if result.returncode != 0 or not os.path.ismount(store):
        detail = result.stderr.strip().splitlines()[0][:200] if result.stderr.strip() else f"exit {result.returncode}"
        return {"ok": False, "error": f"guard partition could not be mounted: {detail}"}
    return {"ok": True, "mounted": True, "device": device, "store": store}


def _device_for_uuid(uuid: str) -> str | None:
    """先找 udev 的 by-uuid 链接, 找不到再问 blkid。没有 udev 的环境(容器、早起阶段)
    也能靠 blkid 找到设备。"""
    link = f"{BY_UUID}/{uuid}"
    if os.path.exists(link):
        return link
    try:
        result = subprocess.run(
            [BLKID, "-U", uuid, "-o", "device"],
            shell=False, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    device = result.stdout.strip()
    return device if result.returncode == 0 and device else None


def _atomic_write(directory: Path, name: str, document: dict[str, Any]) -> None:
    payload = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    descriptor, temporary = tempfile.mkstemp(dir=str(directory), prefix=f".{name}.", suffix=".new")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, directory / name)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def write_manifest(snapshot_dir: Path, document: dict[str, Any]) -> None:
    """最后一步写 manifest —— 它的存在就是这次快照完整的标记。"""
    _atomic_write(snapshot_dir, MANIFEST_NAME, document)


def read_manifest(snapshot_dir: Path) -> dict[str, Any] | None:
    try:
        document = json.loads((snapshot_dir / MANIFEST_NAME).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if (
        not isinstance(document, dict)
        or document.get("schema") != MANIFEST_SCHEMA
        or not isinstance(document.get("snapshot_id"), str)
        or not isinstance(document.get("created_at"), str)
        or not isinstance(document.get("trigger"), str)
    ):
        return None
    return document


def _git_facts(workspace_path: str) -> dict[str, Any]:
    def run(*arguments: str) -> subprocess.CompletedProcess[str] | None:
        try:
            return subprocess.run(
                [GIT, "-C", workspace_path, *arguments],
                shell=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            return None

    head = run("rev-parse", "HEAD")
    if head is None or head.returncode != 0:
        # 非 git 目录也允许守护, 这不是错误。
        return {"present": False}
    commit = head.stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        return {"present": False}
    branch = run("rev-parse", "--abbrev-ref", "HEAD")
    status = run("status", "--porcelain")
    return {
        "present": True,
        "head": commit,
        "branch": branch.stdout.strip() if branch is not None and branch.returncode == 0 else None,
        "dirty_files": len([line for line in status.stdout.splitlines() if line.strip()])
        if status is not None and status.returncode == 0
        else 0,
    }


def copy_tree(source: Path, destination: Path, skip_names: frozenset[str] = frozenset()) -> dict[str, int]:
    """全量复制一棵树。符号链接重建链接本身, 不跟随; 特殊文件跳过并计数。

    file_count 只数普通文件 —— 目录与链接是结构, 不是内容。
    """
    if os.path.lexists(destination):
        if destination.is_symlink() or not destination.is_dir() or any(destination.iterdir()):
            raise ValidationError("snapshot destination already exists")
    counters = {"file_count": 0, "byte_size": 0, "skipped_special": 0}
    _copy_into(source, destination, counters, skip_names)
    return counters


def _copy_into(
    source: Path, destination: Path, counters: dict[str, int], skip_names: frozenset[str]
) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(destination, stat.S_IMODE(os.lstat(source).st_mode))
    except OSError:
        pass
    try:
        entries = sorted(os.scandir(source), key=lambda entry: entry.name)
    except OSError:
        return
    for entry in entries:
        if entry.name in skip_names:
            continue
        target = destination / entry.name
        try:
            if entry.is_symlink():
                os.symlink(os.readlink(entry.path), target)
            elif entry.is_dir(follow_symlinks=False):
                _copy_into(Path(entry.path), target, counters, skip_names)
            elif entry.is_file(follow_symlinks=False):
                shutil.copy2(entry.path, target, follow_symlinks=False)
                counters["file_count"] += 1
                counters["byte_size"] += os.lstat(target).st_size
            else:
                counters["skipped_special"] += 1
        except (OSError, ValueError):
            # 单个条目读不到就跳过: 一个坏 socket 不该毁掉整次快照。
            continue


def create_snapshot(config: dict[str, Any], workspace_path: str, trigger: str) -> dict[str, Any]:
    if not config.get("configured"):
        return {"ok": False, "error": "guard store is not configured"}
    if trigger not in TRIGGERS:
        return {"ok": False, "error": f"unknown snapshot trigger: {trigger}"}
    if not os.path.isabs(workspace_path):
        return {"ok": False, "error": "workspace path must be absolute"}
    workspace = Path(workspace_path)
    if workspace.is_symlink() or not workspace.is_dir():
        return {"ok": False, "error": "workspace is not an existing directory"}

    identifier = workspace_id(workspace_path)
    root = workspace_root(config, identifier)
    try:
        root.mkdir(parents=True, exist_ok=True)
        before = {entry.name for entry in os.scandir(root)}
    except OSError as exc:
        return {"ok": False, "error": f"guard store is unavailable: {exc.strerror or exc}"}

    snapshot_id = f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{secrets.token_hex(4)}"
    destination = root / snapshot_id
    try:
        destination.mkdir(exist_ok=False)
    except FileExistsError:
        return {"ok": False, "error": "snapshot ID collision; nothing was written"}
    except OSError as exc:
        return {"ok": False, "error": f"guard store is not writable: {exc.strerror or exc}"}

    try:
        counters = copy_tree(workspace, destination)
    except ValidationError:
        raise
    except OSError as exc:
        return {"ok": False, "error": f"workspace could not be copied: {exc.strerror or exc}"}

    document = {
        "schema": MANIFEST_SCHEMA,
        "snapshot_id": snapshot_id,
        "workspace_id": identifier,
        "workspace_path": os.path.realpath(workspace_path),
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "trigger": trigger,
        "git": _git_facts(workspace_path),
        "file_count": counters["file_count"],
        "byte_size": counters["byte_size"],
        "skipped_special": counters["skipped_special"],
    }
    write_manifest(destination, document)

    after = {entry.name for entry in os.scandir(root)}
    if len(after - before) != 1 or snapshot_id not in after:
        raise ValidationError("snapshot verification failed")

    prune(config, identifier)
    return {"ok": True, "snapshot_id": snapshot_id, "workspace_id": identifier, "manifest": document}


def _snapshot_directories(config: dict[str, Any]) -> list[Path]:
    workspaces = Path(config["store"]) / "workspaces"
    if not workspaces.is_dir():
        return []
    return sorted(entry for entry in workspaces.iterdir() if entry.is_dir() and not entry.is_symlink())


def _locate_snapshot(config: dict[str, Any], snapshot_id: str) -> Path | None:
    for directory in _snapshot_directories(config):
        candidate = directory / snapshot_id
        if candidate.is_dir() and not candidate.is_symlink():
            return candidate
    return None


def _inside(child: str, parent: str) -> bool:
    try:
        resolved = os.path.realpath(parent)
        return os.path.commonpath([os.path.realpath(child), resolved]) == resolved
    except ValueError:
        return False


def restore_snapshot(config: dict[str, Any], snapshot_id: str, restore_target: str) -> dict[str, Any]:
    """恢复到新目录。绝不覆盖, 绝不写进原工作区或守护仓库。"""
    if not config.get("configured"):
        return {"ok": False, "error": "guard store is not configured"}
    if not SNAPSHOT_ID_RE.fullmatch(str(snapshot_id)):
        return {"ok": False, "error": "invalid snapshot ID"}
    snapshot = _locate_snapshot(config, str(snapshot_id))
    if snapshot is None:
        return {"ok": False, "error": "snapshot not found"}
    document = read_manifest(snapshot)
    if document is None:
        return {"ok": False, "error": "snapshot manifest is missing or invalid"}
    if not os.path.isabs(str(restore_target)):
        return {"ok": False, "error": "restore target must be an absolute path"}
    workspace_path = str(document.get("workspace_path", ""))
    if workspace_path and _inside(restore_target, workspace_path):
        return {"ok": False, "error": "restore target must not be inside the workspace"}
    if _inside(restore_target, str(config["store"])):
        return {"ok": False, "error": "restore target must not be inside the guard store"}
    target = Path(restore_target)
    if os.path.lexists(target) and (
        target.is_symlink() or not target.is_dir() or any(target.iterdir())
    ):
        return {"ok": False, "error": "restore target must be empty or absent"}
    try:
        target.mkdir(parents=True, exist_ok=True)
        # guard-manifest.json 是守护的元数据, 不是用户内容。
        counters = copy_tree(snapshot, target, skip_names=frozenset({MANIFEST_NAME}))
    except (OSError, ValidationError) as exc:
        return {"ok": False, "error": f"restore failed: {exc}"}
    return {
        "ok": True,
        "restored": snapshot_id,
        "file_count": counters["file_count"],
        "byte_size": counters["byte_size"],
    }


def list_snapshots(config: dict[str, Any], workspace_path: str) -> list[dict[str, Any]]:
    if not config.get("configured"):
        return []
    root = workspace_root(config, workspace_id(workspace_path))
    if not root.is_dir():
        return []
    snapshots = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir() or entry.is_symlink():
            continue
        document = read_manifest(entry)
        if document is not None:
            snapshots.append(document)
    return sorted(snapshots, key=lambda item: (item["created_at"], item["snapshot_id"]), reverse=True)


def prune(config: dict[str, Any], identifier: str) -> list[str]:
    """按 trigger 分层保留。manifest 缺失或不完整的先删 —— 不完整的备份不算恢复点。"""
    if not config.get("configured"):
        return []
    root = workspace_root(config, identifier)
    if not root.is_dir():
        return []
    complete: dict[str, list[dict[str, Any]]] = {trigger: [] for trigger in TRIGGERS}
    removed: list[str] = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir() or entry.is_symlink():
            continue
        document = read_manifest(entry)
        if document is None or document.get("trigger") not in complete:
            shutil.rmtree(entry, ignore_errors=True)
            removed.append(entry.name)
            continue
        complete[document["trigger"]].append(document)
    for trigger, keep in (("scheduled", config["keep_scheduled"]), ("manual", config["keep_manual"])):
        ordered = sorted(
            complete[trigger], key=lambda item: (item["created_at"], item["snapshot_id"]), reverse=True
        )
        for document in ordered[keep:]:
            shutil.rmtree(root / document["snapshot_id"], ignore_errors=True)
            removed.append(document["snapshot_id"])
    return removed

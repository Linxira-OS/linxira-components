"""root 定时器入口: 每 30 分钟给每个已注册工作区做一次快照。

不依赖 agent 自觉, 也不依赖用户在场 —— 这是整个机制存在的理由。
未配置是正常状态, 不是失败: 守护默认不开。
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

from . import guard_store
from .errors import ValidationError


def _registered_workspaces(config: dict[str, Any]) -> list[tuple[str, str]]:
    workspaces = Path(config["store"]) / "workspaces"
    if not workspaces.is_dir():
        return []
    registered: list[tuple[str, str]] = []
    for directory in sorted(workspaces.iterdir()):
        if not directory.is_dir() or directory.is_symlink():
            continue
        try:
            document = json.loads((directory / guard_store.REGISTERED_NAME).read_text(encoding="utf-8"))
            path = str(document["workspace_path"])
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
            continue
        registered.append((directory.name, path))
    return registered


def main() -> int:
    try:
        config = guard_store.read_config()
    except ValidationError as exc:
        print(f"workspace guard: {exc}", file=sys.stderr)
        return 1
    if not config.get("configured"):
        print("workspace guard is not configured; nothing to snapshot")
        return 0
    mounted = guard_store.ensure_store_mounted(config)
    if not mounted.get("ok"):
        print(f"workspace guard: {mounted.get('error')}", file=sys.stderr)
        return 1
    if mounted.get("mounted"):
        print(f"workspace guard: store mounted at {mounted.get('store', config['store'])}")
    workspaces = _registered_workspaces(config)
    if not workspaces:
        print("workspace guard has no registered workspace; nothing to snapshot")
        return 0
    succeeded = 0
    failed = 0
    for identifier, workspace_path in workspaces:
        try:
            outcome = guard_store.create_snapshot(config, workspace_path, trigger="scheduled")
        except ValidationError as exc:
            print(f"workspace guard: {workspace_path}: {exc}", file=sys.stderr)
            failed += 1
            continue
        if outcome.get("ok"):
            succeeded += 1
            print(f"workspace guard: {workspace_path} -> {outcome['snapshot_id']}")
        else:
            failed += 1
            print(f"workspace guard: {workspace_path}: {outcome.get('error')}", file=sys.stderr)
    print(f"workspace guard: {succeeded} succeeded, {failed} failed")
    return 0 if failed == 0 else 1

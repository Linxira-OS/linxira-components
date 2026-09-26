"""`linxira-components guard` —— 人与 agent 都能用的工作区守护入口。

权限分层:
  list / status              只读, 直调 guard_store, 不需要 root, 不需要授权
  snapshot / restore         写状态, 走 D-Bus 计划 + Polkit 弹窗, agent 可发起
  init / register / unregister  改的是 root 拥有的登记表, 只由管理员执行

为什么 register 不走 Polkit: 它写的是守护仓库自己的登记表, 没有任何用户可见的
副作用, 也没有需要回滚的东西。让用户用管理员身份跑一次就够了, 没必要为它开一个
能被反复触发的提权入口。
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any

from . import guard_store
from .errors import ValidationError


CREATE_OPERATION = "org.linxira.guard.create-workspace-snapshot.v1"
RESTORE_OPERATION = "org.linxira.guard.restore-workspace-snapshot.v1"
BUS_NAME = "org.linxira.Components1"
OBJECT_PATH = "/org/linxira/Components1"
INTERFACE = "org.linxira.Components1"


def _absolute(value: str) -> str:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise argparse.ArgumentTypeError(f"path must be absolute: {value}")
    return str(path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="linxira-components guard")
    subcommands = parser.add_subparsers(dest="command", required=True)

    subcommands.add_parser("init", help="create the guard store skeleton (root)")
    for name, help_text in (("register", "register a workspace (root)"), ("unregister", "stop snapshots for a workspace (root)")):
        command = subcommands.add_parser(name, help=help_text)
        command.add_argument("path", type=_absolute)

    snapshot = subcommands.add_parser("snapshot", help="create one manual snapshot now (asks for authorization)")
    snapshot.add_argument("path", type=_absolute)

    restore = subcommands.add_parser("restore", help="restore a snapshot into a new directory (asks for authorization)")
    restore.add_argument("snapshot_id")
    restore.add_argument("--target", type=_absolute, required=True)

    listing = subcommands.add_parser("list", help="list snapshots of one workspace")
    listing.add_argument("path", type=_absolute)
    listing.add_argument("--json", action="store_true", dest="as_json")

    status = subcommands.add_parser("status", help="report guard configuration and inventory")
    status.add_argument("--json", action="store_true", dest="as_json")
    return parser


def _require_root(command: str) -> None:
    if os.geteuid() != 0:
        print(
            f"ERROR: guard {command} changes root-owned state; run it as the administrator",
            file=sys.stderr,
        )
        raise SystemExit(1)


def _load() -> dict[str, Any]:
    try:
        return guard_store.read_config()
    except ValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


def _emit(document: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(document, ensure_ascii=False, sort_keys=True))
        return
    if isinstance(document, list):
        if not document:
            print("no snapshots")
            return
        for item in document:
            print(
                f"{item['snapshot_id']}  {item['created_at']}  {item['trigger']:9} "
                f"{item['file_count']:>7} files  {item['byte_size']:>12} bytes  {item['workspace_path']}"
            )
        return
    print(json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True))


def _call(operation_id: str, parameters: dict[str, Any]) -> int:
    """经 D-Bus 走 plan -> Polkit -> root helper。授权被拒时如实报错, 不绕路。"""
    try:
        import dbus
        from dbus.mainloop.glib import DBusGMainLoop
    except ImportError:
        print("ERROR: the guarded operations need python-dbus and python-gobject", file=sys.stderr)
        return 1
    DBusGMainLoop(set_as_default=True)
    try:
        bus = dbus.SystemBus()
        interface = dbus.Interface(bus.get_object(BUS_NAME, OBJECT_PATH), INTERFACE)
    except Exception as exc:
        print(f"ERROR: the Linxira components service is unavailable: {exc}", file=sys.stderr)
        return 1

    outcome: list[tuple[str, Any]] = []

    def on_reply(result, _invocation=None) -> None:
        outcome.append(("reply", result))

    def on_error(error, _invocation=None) -> None:
        outcome.append(("error", error))

    def call(method: str, *arguments: Any) -> Any:
        outcome.clear()
        getattr(interface, method)(*arguments, callback=on_reply, error_handler=on_error)
        if not outcome:
            raise RuntimeError(f"{method} returned no reply")
        kind, payload = outcome[0]
        if kind == "error":
            raise RuntimeError(str(payload))
        return payload

    try:
        identifier, plan_json = call(
            "CreateSystemPlan", operation_id, json.dumps(parameters, sort_keys=True)
        )
        plan = json.loads(str(plan_json))
        receipt_id, receipt_json = call("ConfirmAndApplySystemPlan", identifier, plan["digest"])
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    receipt = json.loads(str(receipt_json))
    document = {"planId": identifier, "receipt": receipt}
    print(json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if receipt.get("status") == "succeeded" else 1


def _load_readonly() -> dict[str, Any] | None:
    """只读命令永不失败: 配置读不到就如实说读不到, 不该因此变成错误退出。"""
    try:
        return guard_store.read_config()
    except ValidationError as exc:
        print(f"NOTE: {exc}", file=sys.stderr)
        return None


def _run(args: argparse.Namespace) -> int:
    if args.command == "status":
        config = _load_readonly()
        _emit(guard_store.guard_status(config or {"configured": False}), args.as_json)
        return 0
    if args.command == "list":
        config = _load_readonly()
        _emit(guard_store.list_snapshots(config or {"configured": False}, args.path), args.as_json)
        return 0
    config = _load()
    if not config.get("configured"):
        print("ERROR: guard store is not configured; run: linxira-config workspace-guard enable", file=sys.stderr)
        return 1
    mounted = guard_store.ensure_store_mounted(config)
    if not mounted.get("ok"):
        print(f"ERROR: {mounted.get('error')}", file=sys.stderr)
        return 1
    if args.command == "init":
        _require_root("init")
        store = Path(config["store"])
        (store / "workspaces").mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(store, 0o700)
        _emit({"ok": True, "store": config["store"]}, False)
        return 0
    if args.command == "register":
        _require_root("register")
        outcome = guard_store.register_workspace(config, args.path)
    elif args.command == "unregister":
        _require_root("unregister")
        outcome = guard_store.unregister_workspace(config, args.path)
    elif args.command == "snapshot":
        return _call(CREATE_OPERATION, {"workspace_path": args.path})
    elif args.command == "restore":
        return _call(RESTORE_OPERATION, {"snapshot_id": args.snapshot_id, "restore_target": args.target})
    else:
        raise AssertionError("unreachable command")
    _emit(outcome, False)
    return 0 if outcome.get("ok") else 1


def main(argv: list[str] | None = None) -> int:
    return _run(_parser().parse_args(argv))

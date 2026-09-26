"""工作区守护在 root helper 里的执行入口。

与 driver_worker 同样的分派形状: (plan, run, revalidate) -> result。差别只有两处:
快照不是 timeshift 的, 失败时也没有可回滚的系统变更 —— 守护只往自己的仓库里写,
或者往一个全新的目录里写。run 保留在签名里只为与 apply_guest 一致, 守护不起子进程。
"""
from __future__ import annotations

from typing import Any, Callable

from . import guard_store
from .driver_worker import RESULT_SCHEMA
from .errors import ValidationError


CREATE_OPERATION = "org.linxira.guard.create-workspace-snapshot.v1"
RESTORE_OPERATION = "org.linxira.guard.restore-workspace-snapshot.v1"
CREATE_ROLLBACK = "snapshot-can-be-pruned-no-rollback-needed"
RESTORE_ROLLBACK = "restore-target-is-a-new-directory-nothing-to-roll-back"


def _result(plan: dict[str, Any], status: str, **fields: Any) -> dict[str, Any]:
    document = {
        "schemaVersion": RESULT_SCHEMA,
        "planId": plan["id"],
        "planDigest": plan["digest"],
        "operationId": plan["operationId"],
        "status": status,
        "snapshot": None,
        "changed": False,
        "verifiedState": None,
        "rollback": "not-available",
    }
    document.update(fields)
    return document


def _failed(plan: dict[str, Any], error: str) -> dict[str, Any]:
    return _result(plan, "failed", error=error[:240])


def _parameter(plan: dict[str, Any], name: str) -> str:
    parameters = plan.get("parameters")
    if not isinstance(parameters, dict):
        raise ValidationError("guard plan has no parameters")
    value = parameters.get(name)
    if not isinstance(value, str) or not value:
        raise ValidationError(f"guard plan parameter {name} must be a string")
    return value


def _stale(plan: dict[str, Any], revalidate: Callable[[], dict[str, Any]]) -> dict[str, Any] | None:
    if revalidate() != plan["preState"]:
        return _failed(plan, "system state changed before the guard operation started")
    return None


def execute_create(
    plan: dict[str, Any], run: Callable[..., Any], revalidate: Callable[[], dict[str, Any]]
) -> dict[str, Any]:
    try:
        workspace_path = _parameter(plan, "workspace_path")
        stale = _stale(plan, revalidate)
        if stale is not None:
            return stale
        outcome = guard_store.create_snapshot(guard_store.read_config(), workspace_path, trigger="manual")
    except ValidationError as exc:
        return _failed(plan, str(exc))
    if not outcome.get("ok"):
        return _failed(plan, str(outcome.get("error", "snapshot failed")))
    return _result(
        plan,
        "succeeded",
        changed=True,
        verifiedState={
            "snapshot_id": outcome["snapshot_id"],
            "workspace_id": outcome["workspace_id"],
        },
        rollback=CREATE_ROLLBACK,
    )


def execute_restore(
    plan: dict[str, Any], run: Callable[..., Any], revalidate: Callable[[], dict[str, Any]]
) -> dict[str, Any]:
    try:
        snapshot_id = _parameter(plan, "snapshot_id")
        restore_target = _parameter(plan, "restore_target")
        stale = _stale(plan, revalidate)
        if stale is not None:
            return stale
        outcome = guard_store.restore_snapshot(guard_store.read_config(), snapshot_id, restore_target)
    except ValidationError as exc:
        return _failed(plan, str(exc))
    if not outcome.get("ok"):
        return _failed(plan, str(outcome.get("error", "restore failed")))
    return _result(
        plan,
        "succeeded",
        changed=True,
        verifiedState={
            "target": restore_target,
            "file_count": outcome["file_count"],
            "byte_size": outcome["byte_size"],
        },
        rollback=RESTORE_ROLLBACK,
    )


GUARD_OPERATIONS: dict[str, Callable[[dict[str, Any], Any, Any], dict[str, Any]]] = {
    CREATE_OPERATION: execute_create,
    RESTORE_OPERATION: execute_restore,
}


def validate_guard_result(result: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    """守护结果的形状校验。不复用 driver_worker.validate_result —— 它断言的是
    timeshift 快照的 name/comment/tag, 对守护没有意义。"""
    from .jsonio import document_digest

    if (
        result.get("schemaVersion") != RESULT_SCHEMA
        or result.get("planId") != plan.get("id")
        or result.get("planDigest") != plan.get("digest")
        or result.get("operationId") != plan.get("operationId")
        or result.get("status") not in {"succeeded", "failed"}
        or not isinstance(result.get("changed"), bool)
        or result.get("snapshot") is not None
        or result.get("digest") != document_digest(result)
    ):
        raise ValidationError("guard worker returned an invalid result")
    expected_rollback = CREATE_ROLLBACK if plan["operationId"] == CREATE_OPERATION else RESTORE_ROLLBACK
    if result["status"] == "succeeded":
        if (
            result.get("changed") is not True
            or not isinstance(result.get("verifiedState"), dict)
            or result.get("rollback") != expected_rollback
        ):
            raise ValidationError("guard worker success claims do not match the plan")
    elif (
        not isinstance(result.get("error"), str)
        or not result["error"]
        or result.get("verifiedState") is not None
        or result.get("rollback") != "not-available"
    ):
        raise ValidationError("guard worker failure claims are inconsistent")
    return result

from __future__ import annotations

from collections.abc import Callable, Sequence
import os
from pathlib import Path
import subprocess
from typing import Any

from .catalog import load_catalog
from .catalog_v3 import CatalogV3
from .errors import TransactionError, ValidationError
from .jsonio import atomic_write_json
from .inventory import query_satisfied_package_targets, reconcile_package_delta
from .models import Receipt, validate_confirmation
from .selection import expand_selection, required_license_acceptances


DEFAULT_RECEIPT_DIR = Path("/var/lib/linxira/components/receipts")
DEFAULT_CATALOG_PATH = Path("/usr/share/linxira/catalog/catalog-v3.json")
Runner = Callable[..., subprocess.CompletedProcess[str]]

# Commands that own the pacman database lock while running.
PACMAN_PROCESS_NAMES = frozenset({"pacman", "makepkg", "yay", "paru", "pikaur"})


def _ensure_pacman_lock_available(
    runner: Runner = subprocess.run, root: str | Path = "/"
) -> None:
    """Refuse to run when pacman is active; clear a stale db.lck otherwise.

    pacman refuses to start while /var/lib/pacman/db.lck exists. The lock is
    only valid while a pacman-like process is running; when none is, the lock
    is stale (e.g. left behind by a crashed transaction) and is removed so the
    component transaction can proceed.
    """
    lock = Path(root) / "var/lib/pacman/db.lck"
    if not lock.exists():
        return
    for name in PACMAN_PROCESS_NAMES:
        try:
            probe = runner(
                ["pgrep", "-x", name],
                check=False,
                capture_output=True,
                text=True,
                shell=False,
            )
        except OSError:
            continue
        if probe.returncode == 0:
            raise TransactionError(
                f"pacman is already running ({name}); wait for the transaction to finish and retry"
            )
    try:
        lock.unlink()
    except OSError as exc:
        raise TransactionError(f"failed to remove stale pacman lock: {exc}") from exc


def _effective_uid() -> int:
    return os.geteuid() if hasattr(os, "geteuid") else -1


def _receipt_path(receipt_dir: Path, receipt_id: str) -> Path:
    if receipt_dir.is_symlink():
        raise ValidationError("receipt directory must not be a symlink")
    receipt_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
    if not receipt_dir.is_dir():
        raise ValidationError("receipt path is not a directory")
    return receipt_dir / f"{receipt_id}.json"


def _persist(receipt: Receipt, receipt_dir: Path) -> Path:
    path = _receipt_path(receipt_dir, receipt.id)
    atomic_write_json(receipt_dir, path.name, receipt.to_document())
    return path


def _process_output_summary(result: subprocess.CompletedProcess[str], *, limit: int = 2000) -> str:
    parts = []
    for label, value in (("stderr", result.stderr), ("stdout", result.stdout)):
        text = (value or "").strip()
        if text:
            parts.append(f"{label}:\n{text}")
    if not parts:
        return "pacman produced no output"
    summary = "\n\n".join(parts)
    return summary if len(summary) <= limit else summary[-limit:]


def apply_transaction(
    confirmation: Any,
    *,
    receipt_dir: str | Path = DEFAULT_RECEIPT_DIR,
    catalog_path: str | Path = DEFAULT_CATALOG_PATH,
    runner: Runner = subprocess.run,
    effective_uid: int | None = None,
    pacman: str = "pacman",
) -> dict[str, Any]:
    """Apply a confirmed Arch package target list as root.

    The confirmation is the only client-controlled input. Package names are
    validated before a fixed-argv pacman invocation; shell parsing, arbitrary
    repositories, upgrades, removals and command strings are not accepted.
    """
    validated = validate_confirmation(confirmation)
    catalog = load_catalog(catalog_path, validated["architecture"])
    validate_confirmation(validated, catalog_sha256=catalog.sha256)
    uid = _effective_uid() if effective_uid is None else effective_uid
    if uid != 0:
        raise ValidationError("the transaction backend must run as root")
    if not pacman or "/" in pacman or "\\" in pacman:
        raise ValidationError("pacman executable must be a trusted bare command name")
    receipt_details: dict[str, Any] | None = None
    # 已确认目标全部"镜像自带"（availability.networkRequired=False）时不刷新
    # 同步库：装完 ISO 未联网的机器也必须能装离线应用；任一目标需要网络则
    # 保持原行为（先 --refresh 再安装）。
    needs_refresh = True
    if isinstance(catalog, CatalogV3):
        if validated["schemaVersion"] != "org.linxira.components.confirmation.v2":
            raise ValidationError("Catalog v3 requires a v2 confirmation")
        desired = expand_selection(validated["selection"], catalog)
        for field_name, expected_value in desired.items():
            if field_name not in {"directPackageTargets", "leafRequirements"} and validated[field_name] != expected_value:
                raise ValidationError(f"confirmation {field_name} does not match Catalog v3 selection expansion")
        desired_requirements = {item["id"]: item for item in desired["leafRequirements"]}
        for item in validated["leafRequirements"]:
            expected = desired_requirements.get(item.get("id"))
            if expected is None or any(
                item.get(field_name) != expected[field_name]
                for field_name in expected if field_name != "packageTargets"
            ) or not set(item.get("packageTargets", ())).issubset(expected["packageTargets"]):
                raise ValidationError("confirmation leafRequirements do not match Catalog v3 selection expansion")
        if not set(validated["directPackageTargets"]).issubset(desired["directPackageTargets"]):
            raise ValidationError("confirmation directPackageTargets does not match Catalog v3 selection expansion")
        if validated["executionPackageTargets"] != desired["directPackageTargets"]:
            raise ValidationError("confirmation executionPackageTargets do not match Catalog v3 selection expansion")
        expanded = desired if not desired["directPackageTargets"] else reconcile_package_delta(
            desired,
            query_satisfied_package_targets(
                catalog, runner=runner, pacman=pacman, required=True
            ) or set(),
        )
        expanded["executionPackageTargets"] = desired["directPackageTargets"]
        for field_name, expected_value in expanded.items():
            if validated[field_name] != expected_value:
                raise ValidationError(f"confirmation {field_name} does not match Catalog v3 selection expansion")
        if validated["acceptedLicenseIds"] != required_license_acceptances(
            catalog, expanded["finalLeafIds"]
        ):
            raise ValidationError("confirmation license acceptances do not match selected Catalog leaves")
        receipt_details = {
            "catalogSha256": validated["catalogSha256"],
            "catalogRelease": validated["catalogRelease"],
            "architecture": validated["architecture"],
            "finalLeafIds": validated["finalLeafIds"],
            "selectedBundleIds": validated["selectedBundleIds"],
            "leafRequirements": validated["leafRequirements"],
            "providerRequirements": validated["providerRequirements"],
            "sourceRequirements": validated["sourceRequirements"],
            "pendingItems": validated["pendingItems"],
            "unsupportedItems": validated["unsupportedItems"],
            "directPackageTargets": validated["directPackageTargets"],
            "executionPackageTargets": validated["executionPackageTargets"],
            "acceptedLicenseIds": validated["acceptedLicenseIds"],
        }
        execution_targets = validated["executionPackageTargets"]
        needs_refresh = any(
            item.get("id") not in catalog.leaves
            or catalog.leaves[item["id"]].network_required
            for item in validated["leafRequirements"]
        )
    else:
        if validated["schemaVersion"] != "org.linxira.components.confirmation.v1":
            raise ValidationError("Catalog v2 requires a v1 confirmation")
        profiles = catalog.select(validated["profileIds"])
        applications = catalog.select_applications(validated["applicationIds"])
        expected_targets = sorted(
            {package for profile in profiles for package in profile.packages}
            | {package for application in applications for package in application.packages}
        )
        if validated["directPackageTargets"] != expected_targets:
            raise ValidationError("confirmation package targets do not match the current catalog profiles")
        execution_targets = validated["directPackageTargets"]
        needs_refresh = any(
            entry.network_required for entry in (*profiles, *applications)
        )
    receipt = Receipt(
        request_plan_id=validated["requestPlanId"],
        plan_digest=validated["planDigest"],
        transaction_details=receipt_details,
    )
    receipt_dir_path = Path(receipt_dir)
    _persist(receipt, receipt_dir_path)
    receipt.transition("confirmed", message="Confirmation accepted")
    _persist(receipt, receipt_dir_path)
    receipt.transition(
        "applying",
        message="Applying confirmed Arch package targets"
        + ("" if needs_refresh else " (offline targets; package databases not refreshed)"),
    )
    _persist(receipt, receipt_dir_path)

    if not execution_targets:
        receipt.transition("succeeded", message="No executable Arch package leaves; pending and unsupported items were not run")
        _persist(receipt, receipt_dir_path)
        return receipt.to_document()

    sync_arguments: list[str] = ["--sync"]
    if needs_refresh:
        sync_arguments.append("--refresh")
    command: Sequence[str] = (
        pacman,
        *sync_arguments,
        "--needed",
        "--noconfirm",
        "--",
        *execution_targets,
    )
    _ensure_pacman_lock_available(runner)
    try:
        result = runner(
            list(command),
            check=False,
            capture_output=True,
            text=True,
            shell=False,
            env={"PATH": "/usr/bin:/usr/sbin", "LC_ALL": "C"},
        )
    except OSError as exc:
        receipt.transition("failed", message=f"Unable to execute pacman: {exc}")
        _persist(receipt, receipt_dir_path)
        raise TransactionError(str(exc)) from exc

    if result.returncode != 0:
        output = _process_output_summary(result)
        receipt.transition("failed", message=output[-1000:])
        path = _persist(receipt, receipt_dir_path)
        raise TransactionError(
            f"pacman transaction failed with exit code {result.returncode}\n"
            f"{output}\nReceipt: {path}"
        )

    receipt.transition("succeeded", message="Arch package transaction completed")
    _persist(receipt, receipt_dir_path)
    return receipt.to_document()

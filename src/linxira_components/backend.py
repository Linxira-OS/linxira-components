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
from .models import Receipt, validate_confirmation
from .selection import expand_selection, required_license_acceptances


DEFAULT_RECEIPT_DIR = Path("/var/lib/linxira/components/receipts")
DEFAULT_CATALOG_PATH = Path("/usr/share/linxira/catalog/catalog-v3.json")
Runner = Callable[..., subprocess.CompletedProcess[str]]


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
    receipt_details: dict[str, Any] | None = None
    if isinstance(catalog, CatalogV3):
        if validated["schemaVersion"] != "org.linxira.components.confirmation.v2":
            raise ValidationError("Catalog v3 requires a v2 confirmation")
        expanded = expand_selection(validated["selection"], catalog)
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
            "acceptedLicenseIds": validated["acceptedLicenseIds"],
        }
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
    uid = _effective_uid() if effective_uid is None else effective_uid
    if uid != 0:
        raise ValidationError("the transaction backend must run as root")
    if not pacman or "/" in pacman or "\\" in pacman:
        raise ValidationError("pacman executable must be a trusted bare command name")

    receipt = Receipt(
        request_plan_id=validated["requestPlanId"],
        plan_digest=validated["planDigest"],
        transaction_details=receipt_details,
    )
    receipt_dir_path = Path(receipt_dir)
    _persist(receipt, receipt_dir_path)
    receipt.transition("confirmed", message="Confirmation accepted")
    _persist(receipt, receipt_dir_path)
    receipt.transition("applying", message="Applying confirmed Arch package targets")
    _persist(receipt, receipt_dir_path)

    if not validated["directPackageTargets"]:
        receipt.transition("succeeded", message="No executable Arch package leaves; pending and unsupported items were not run")
        _persist(receipt, receipt_dir_path)
        return receipt.to_document()

    command: Sequence[str] = (
        pacman,
        "--sync",
        "--needed",
        "--noconfirm",
        "--",
        *validated["directPackageTargets"],
    )
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
        output = (result.stderr or result.stdout or "pacman failed").strip()
        receipt.transition("failed", message=output[-1000:])
        _persist(receipt, receipt_dir_path)
        raise TransactionError(f"pacman transaction failed with exit code {result.returncode}")

    receipt.transition("succeeded", message="Arch package transaction completed")
    _persist(receipt, receipt_dir_path)
    return receipt.to_document()

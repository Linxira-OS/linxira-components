from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
from typing import Any, Callable

from .catalog import Catalog, PACKAGE_RE
from .catalog_v3 import CatalogV3
from .errors import ValidationError


INVENTORY_SCHEMA = "org.linxira.components.installed-state.v1"
Runner = Callable[..., subprocess.CompletedProcess[str]]


def query_installed_packages(
    *, runner: Runner = subprocess.run, pacman: str = "pacman", required: bool = True
) -> set[str] | None:
    if not pacman or "/" in pacman or "\\" in pacman:
        raise ValidationError("pacman executable must be a trusted bare command name")
    resolved = shutil.which(pacman)
    if resolved is None:
        if required:
            resolved = pacman
        else:
            return None
    try:
        result = runner(
            [resolved, "-Qq"], check=False, capture_output=True, text=True,
            timeout=30, shell=False, env={"PATH": "/usr/bin:/usr/sbin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        if required:
            raise ValidationError(f"unable to query pacman local package state: {exc}") from exc
        return None
    if result.returncode != 0:
        if required:
            raise ValidationError("pacman local package query failed")
        return None
    return {
        line.strip() for line in result.stdout.splitlines()
        if PACKAGE_RE.fullmatch(line.strip())
    }


def query_sync_groups(
    *, runner: Runner = subprocess.run, pacman: str = "pacman", required: bool = False
) -> dict[str, set[str]] | None:
    if not pacman or "/" in pacman or "\\" in pacman:
        raise ValidationError("pacman executable must be a trusted bare command name")
    resolved = shutil.which(pacman)
    if resolved is None:
        if required:
            resolved = pacman
        else:
            return None
    try:
        result = runner(
            [resolved, "-Sg"], check=False, capture_output=True, text=True,
            timeout=30, shell=False, env={"PATH": "/usr/bin:/usr/sbin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        if required:
            raise ValidationError(f"unable to query pacman sync groups: {exc}") from exc
        return None
    if result.returncode != 0:
        if required:
            raise ValidationError("pacman sync group query failed")
        return None
    groups: dict[str, set[str]] = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 2 and all(PACKAGE_RE.fullmatch(field) for field in fields):
            groups.setdefault(fields[0], set()).add(fields[1])
    return groups


def satisfied_package_targets(
    catalog: CatalogV3,
    installed: set[str],
    *,
    runner: Runner = subprocess.run,
    pacman: str = "pacman",
) -> set[str]:
    satisfied = set(installed)
    group_targets = {
        target
        for leaf in catalog.leaves.values()
        if leaf.provider == "pacman" and leaf.source == "arch" and leaf.artifact_type == "package-group"
        for target in leaf.package_targets
        if target not in installed
    }
    if not group_targets:
        return satisfied
    groups = query_sync_groups(runner=runner, pacman=pacman, required=False) or {}
    satisfied.update(
        target for target in group_targets
        if groups.get(target) and groups[target].issubset(installed)
    )
    return satisfied


def query_satisfied_package_targets(
    catalog: CatalogV3,
    *,
    runner: Runner = subprocess.run,
    pacman: str = "pacman",
    required: bool = True,
) -> set[str] | None:
    installed = query_installed_packages(runner=runner, pacman=pacman, required=required)
    if installed is None:
        return None
    return satisfied_package_targets(catalog, installed, runner=runner, pacman=pacman)


def reconcile_package_delta(expanded: dict[str, Any], installed: set[str]) -> dict[str, Any]:
    reconciled = deepcopy(expanded)
    targets: set[str] = set()
    for requirement in reconciled["leafRequirements"]:
        if requirement["status"] == "ready":
            requirement["packageTargets"] = sorted(
                set(requirement["packageTargets"]) - installed
            )
            targets.update(requirement["packageTargets"])
    reconciled["directPackageTargets"] = sorted(targets)
    return reconciled


def _managed_leaf_ids(receipt_dir: Path, catalog_sha256: str) -> set[str]:
    managed: set[str] = set()
    if not receipt_dir.is_dir() or receipt_dir.is_symlink():
        return managed
    for path in receipt_dir.glob("*.json"):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if (
            isinstance(document, dict)
            and document.get("status") == "succeeded"
            and document.get("catalogSha256") == catalog_sha256
            and isinstance(document.get("leafRequirements"), list)
        ):
            managed.update(
                item["id"] for item in document["leafRequirements"]
                if isinstance(item, dict) and item.get("status") == "ready"
                and isinstance(item.get("id"), str)
            )
    return managed


def _cohort_state(targets: tuple[str, ...], installed: set[str] | None) -> tuple[str, list[str], list[str]]:
    if installed is None or not targets:
        return "unknown", [], list(targets)
    present = sorted(set(targets) & installed)
    missing = sorted(set(targets) - installed)
    state = "installed" if not missing else "partial" if present else "absent"
    return state, present, missing


def collect_inventory(
    catalog: Catalog | CatalogV3,
    *,
    receipt_dir: Path = Path("/var/lib/linxira/components/receipts"),
    runner: Runner = subprocess.run,
    pacman: str = "pacman",
) -> dict[str, Any]:
    installed = query_installed_packages(runner=runner, pacman=pacman, required=False)
    managed = _managed_leaf_ids(receipt_dir, catalog.sha256)
    if isinstance(catalog, CatalogV3):
        reconciled = (
            satisfied_package_targets(catalog, installed, runner=runner, pacman=pacman)
            if installed is not None else None
        )
        cohorts = {
            leaf.id: {
                "state": state,
                "installedPackageTargets": present,
                "missingPackageTargets": missing,
                "managed": leaf.id in managed,
            }
            for leaf in catalog.leaves.values()
            for state, present, missing in [
                _cohort_state(
                    leaf.package_targets,
                    reconciled if leaf.provider == "pacman" and leaf.source == "arch" else None,
                )
            ]
        }
        field = "leaves"
    else:
        cohorts = {
            item.id: {
                "state": state,
                "installedPackageTargets": present,
                "missingPackageTargets": missing,
                "managed": False,
            }
            for item in (*catalog.profiles, *catalog.applications)
            for state, present, missing in [_cohort_state(item.packages, installed)]
        }
        field = "items"
    return {
        "schemaVersion": INVENTORY_SCHEMA,
        "catalogSha256": catalog.sha256,
        "catalogRelease": catalog.release,
        "architecture": catalog.architecture,
        "packageStateAvailable": installed is not None,
        field: cohorts,
    }

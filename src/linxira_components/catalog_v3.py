from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any

from .errors import CatalogError, ValidationError
from .jsonio import loads_strict, sha256_bytes


STABLE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
PACKAGE_RE = re.compile(r"^[a-z0-9@._+-]+$")
ARTIFACT_RE = re.compile(r"^[A-Za-z0-9@._+:/-]+$")
ROLES = ("required", "recommended", "optional")
POLICIES = {"multi", "exclusive", "bounded", "preset"}
LEAF_KINDS = {"application", "component", "desktop", "operation"}


@dataclass(frozen=True)
class Leaf:
    id: str
    kind: str
    provider: str
    source: str
    package_targets: tuple[str, ...]
    available: bool
    unavailable_reason: str
    network_required: bool
    requires_acceptance: bool


@dataclass(frozen=True)
class ChildRef:
    id: str
    role: str


@dataclass(frozen=True)
class Bundle:
    id: str
    policy: str
    max_selected: int | None
    children: tuple[ChildRef, ...]


@dataclass(frozen=True)
class CatalogV3:
    path: Path
    sha256: str
    release: str
    architecture: str
    leaves: dict[str, Leaf]
    bundles: dict[str, Bundle]
    top_level_bundle_ids: tuple[str, ...]
    catalog_version: int = 3

    def descendant_leaf_ids(self, node_id: str) -> frozenset[str]:
        found: set[str] = set()

        def visit(current: str) -> None:
            if current in self.leaves:
                found.add(current)
                return
            for child in self.bundles[current].children:
                visit(child.id)

        visit(node_id)
        return frozenset(found)


def _identifier(value: Any, context: str) -> str:
    if not isinstance(value, str) or not STABLE_ID_RE.fullmatch(value):
        raise CatalogError(f"invalid {context}: {value!r}")
    return value


def _nonempty_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise CatalogError(f"{context} must be a non-empty string")
    return value


def _parse_availability(value: Any, context: str, architecture: str) -> tuple[bool, str, bool]:
    if isinstance(value, bool):
        return value, "" if value else "catalog marks this leaf unavailable", False
    if not isinstance(value, dict):
        raise CatalogError(f"invalid {context}")
    if "status" in value:
        status = value["status"]
        if status not in {"available", "review-channel", "unavailable"}:
            raise CatalogError(f"invalid {context}.status")
        available = status == "available"
    else:
        available = value.get("available", True)
        if not isinstance(available, bool):
            raise CatalogError(f"{context}.available must be boolean")
    reason = value.get("reason", "")
    if not isinstance(reason, str):
        raise CatalogError(f"{context}.reason must be a string")
    architectures = value.get("architectures")
    if architectures is not None:
        if not isinstance(architectures, list) or not architectures or not all(
            isinstance(item, str) and item for item in architectures
        ):
            raise CatalogError(f"{context}.architectures must be a non-empty string array")
        if len(architectures) != len(set(architectures)):
            raise CatalogError(f"{context}.architectures must contain unique values")
        if architecture not in architectures:
            available = False
            reason = reason or f"not available for architecture {architecture}"
    network_required = value.get("networkRequired", False)
    if not isinstance(network_required, bool):
        raise CatalogError(f"{context}.networkRequired must be boolean")
    return available, reason, network_required


def _parse_packages(item: dict[str, Any], context: str, leaf_id: str, provider: str) -> tuple[str, ...]:
    specified = [field for field in ("package", "packages", "artifact") if field in item]
    if len(specified) > 1:
        raise CatalogError(f"{context} must use only one of package, packages, or artifact")
    if not specified:
        values: list[Any] = [leaf_id] if provider == "pacman" else []
    elif specified[0] == "packages":
        raw = item["packages"]
        if not isinstance(raw, list) or not raw:
            raise CatalogError(f"{context}.packages must be a non-empty array")
        values = raw
    elif specified[0] == "artifact":
        artifact = item["artifact"]
        if isinstance(artifact, str):
            values = [artifact]
        elif isinstance(artifact, dict):
            if set(artifact) != {"type", "ids"}:
                raise CatalogError(f"{context}.artifact must contain exactly type and ids")
            if artifact["type"] not in {"package", "package-group", "operation"}:
                raise CatalogError(f"invalid {context}.artifact.type")
            if not isinstance(artifact["ids"], list) or not artifact["ids"]:
                raise CatalogError(f"{context}.artifact.ids must be a non-empty array")
            values = [] if artifact["type"] == "operation" else artifact["ids"]
        else:
            raise CatalogError(f"invalid {context}.artifact")
    else:
        values = [item[specified[0]]]
    packages: list[str] = []
    for value in values:
        pattern = PACKAGE_RE if provider == "pacman" else ARTIFACT_RE
        if not isinstance(value, str) or not pattern.fullmatch(value):
            raise CatalogError(f"invalid {context} artifact target: {value!r}")
        packages.append(value)
    if len(packages) != len(set(packages)):
        raise CatalogError(f"{context} package targets must be unique")
    return tuple(packages)


def _parse_children(value: Any, context: str) -> tuple[ChildRef, ...]:
    refs: list[ChildRef] = []
    if isinstance(value, dict):
        unknown = set(value) - set(ROLES)
        if unknown:
            raise CatalogError(f"{context} has unknown roles: {', '.join(sorted(unknown))}")
        for role in ROLES:
            children = value.get(role, [])
            if not isinstance(children, list):
                raise CatalogError(f"{context}.{role} must be an array")
            refs.extend(ChildRef(_identifier(child, f"{context}.{role} item"), role) for child in children)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            if not isinstance(child, dict) or set(child) != {"id", "role"}:
                raise CatalogError(f"{context}[{index}] must contain exactly id and role")
            if child["role"] not in ROLES:
                raise CatalogError(f"invalid {context}[{index}].role")
            refs.append(ChildRef(_identifier(child["id"], f"{context}[{index}].id"), child["role"]))
    else:
        raise CatalogError(f"{context} must be an object or array")
    ids = [ref.id for ref in refs]
    if not refs:
        raise CatalogError(f"{context} must not be empty")
    if len(ids) != len(set(ids)):
        raise CatalogError(f"{context} contains duplicate references")
    return tuple(refs)


def load_catalog_v3(path: str | Path, architecture: str) -> CatalogV3:
    catalog_path = Path(path)
    try:
        raw = catalog_path.read_bytes()
    except OSError as exc:
        raise CatalogError(f"cannot read catalog {catalog_path}: {exc}") from exc
    try:
        document = loads_strict(raw, source=str(catalog_path))
    except ValidationError as exc:
        raise CatalogError(str(exc)) from exc
    if not isinstance(document, dict):
        raise CatalogError("catalog must be an object")
    if document.get("catalogVersion") != 3 or isinstance(document.get("catalogVersion"), bool):
        raise CatalogError("catalogVersion must be integer 3")
    release = _nonempty_string(document.get("release", "v3-development"), "catalog.release")

    raw_components = document.get("components", [])
    raw_applications = document.get("applications", [])
    raw_desktops = document.get("desktops", [])
    raw_operations = document.get("operations", [])
    raw_bundles = document.get("bundles", [])
    if not all(isinstance(collection, list) for collection in (
        raw_components, raw_applications, raw_desktops, raw_operations
    )):
        raise CatalogError("catalog components, applications, desktops, and operations must be arrays")
    if not isinstance(raw_bundles, list):
        raise CatalogError("catalog bundles must be an array")

    leaves: dict[str, Leaf] = {}
    for collection_name, collection, default_kind in (
        ("components", raw_components, "component"),
        ("applications", raw_applications, "application"),
        ("desktops", raw_desktops, "desktop"),
        ("operations", raw_operations, "operation"),
    ):
        for index, item in enumerate(collection):
            context = f"{collection_name}[{index}]"
            if not isinstance(item, dict):
                raise CatalogError(f"{context} must be an object")
            leaf_id = _identifier(item.get("id"), f"{context}.id")
            if leaf_id in leaves:
                raise CatalogError(f"duplicate stable ID: {leaf_id}")
            kind = item.get("kind", default_kind)
            if kind != default_kind:
                raise CatalogError(f"invalid {context}.kind")
            provider = _identifier(item.get("provider", "unspecified"), f"{context}.provider")
            source = _identifier(item.get("source", "unspecified"), f"{context}.source")
            available, reason, network_required = _parse_availability(
                item.get("availability", True), f"{context}.availability", architecture
            )
            packages = _parse_packages(item, context, leaf_id, provider)
            license_info = item.get("license", {})
            if license_info is not None and not isinstance(license_info, dict):
                raise CatalogError(f"invalid {context}.license")
            requires_acceptance = bool(
                isinstance(license_info, dict) and license_info.get("requiresAcceptance") is True
            )
            if kind == "operation" and packages:
                raise CatalogError(f"{context} operation must not contain package targets")
            leaves[leaf_id] = Leaf(
                leaf_id, kind, provider, source, packages, available, reason, network_required,
                requires_acceptance
            )

    bundles: dict[str, Bundle] = {}
    for index, item in enumerate(raw_bundles):
        context = f"bundles[{index}]"
        if not isinstance(item, dict):
            raise CatalogError(f"{context} must be an object")
        bundle_id = _identifier(item.get("id"), f"{context}.id")
        if bundle_id in leaves or bundle_id in bundles:
            raise CatalogError(f"duplicate stable ID: {bundle_id}")
        selection = item.get("selection", "preset")
        if isinstance(selection, str):
            policy = selection
            max_selected = item.get("maxSelected")
        elif isinstance(selection, dict):
            policy = selection.get("policy", selection.get("mode"))
            max_selected = selection.get("maxSelected")
        else:
            raise CatalogError(f"invalid {context}.selection")
        if policy not in POLICIES:
            raise CatalogError(f"invalid {context} selection policy")
        if policy == "bounded":
            if not isinstance(max_selected, int) or isinstance(max_selected, bool) or max_selected < 1:
                raise CatalogError(f"{context} bounded selection requires positive maxSelected")
        elif max_selected is not None:
            raise CatalogError(f"{context} maxSelected is only valid for bounded selection")
        bundles[bundle_id] = Bundle(bundle_id, policy, max_selected, _parse_children(item.get("children"), f"{context}.children"))

    known = set(leaves) | set(bundles)
    referenced_bundles: set[str] = set()
    for bundle in bundles.values():
        unknown = sorted({child.id for child in bundle.children} - known)
        if unknown:
            raise CatalogError(f"bundle {bundle.id} references unknown IDs: {', '.join(unknown)}")
        referenced_bundles.update(child.id for child in bundle.children if child.id in bundles)

    visiting: list[str] = []
    visited: set[str] = set()

    def check_cycle(bundle_id: str) -> None:
        if bundle_id in visiting:
            cycle = visiting[visiting.index(bundle_id):] + [bundle_id]
            raise CatalogError(f"bundle cycle detected: {' -> '.join(cycle)}")
        if bundle_id in visited:
            return
        visiting.append(bundle_id)
        for child in bundles[bundle_id].children:
            if child.id in bundles:
                check_cycle(child.id)
        visiting.pop()
        visited.add(bundle_id)

    for bundle_id in bundles:
        check_cycle(bundle_id)
    top_level = tuple(sorted(set(bundles) - referenced_bundles))
    return CatalogV3(
        catalog_path, sha256_bytes(raw), release, architecture, leaves, bundles, top_level
    )

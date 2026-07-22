from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .catalog_v3 import CatalogV3, Leaf, ROLES, STABLE_ID_RE
from .errors import CatalogDriftError, ValidationError


SELECTION_SCHEMA = "org.linxira.component-selection.v1"


@dataclass(frozen=True)
class Request:
    path: tuple[str, ...]
    role: str


def _sorted_unique_strings(value: Any, context: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValidationError(f"{context} must be a string array")
    if value != sorted(set(value)):
        raise ValidationError(f"{context} must be de-duplicated and stably sorted")
    return value


def _path(catalog: CatalogV3, value: Any, leaf_id: str) -> tuple[str, ...]:
    if not isinstance(value, str) or not value:
        raise ValidationError(f"requestedBy path for {leaf_id} must be a non-empty string")
    parts = tuple(value.split("/"))
    if any(not STABLE_ID_RE.fullmatch(part) for part in parts) or parts[-1] != leaf_id:
        raise ValidationError(f"invalid requestedBy path for {leaf_id}: {value!r}")
    if len(parts) < 2 or parts[0] not in catalog.bundles:
        raise ValidationError(f"requestedBy path for {leaf_id} must begin with a bundle")
    for parent_id, child_id in zip(parts, parts[1:]):
        parent = catalog.bundles.get(parent_id)
        if parent is None or child_id not in {child.id for child in parent.children}:
            raise ValidationError(f"requestedBy path contains an invalid nested reference: {value}")
    return parts


def _constraint_results(catalog: CatalogV3, selected_ids: set[str]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for bundle in catalog.bundles.values():
        chosen = [
            child.id
            for child in bundle.children
            if selected_ids.intersection(catalog.descendant_leaf_ids(child.id))
        ]
        limit = 1 if bundle.policy == "exclusive" else bundle.max_selected
        results.append({
            "bundleId": bundle.id,
            "policy": bundle.policy,
            "selectedCount": len(chosen),
            "maxSelected": limit,
            "valid": limit is None or len(chosen) <= limit,
        })
    return sorted(results, key=lambda item: item["bundleId"])


def create_bundle_selection(catalog: CatalogV3, bundle_id: str) -> dict[str, Any]:
    if bundle_id not in catalog.bundles:
        raise ValidationError(f"unknown Catalog v3 bundle: {bundle_id}")
    requests: dict[str, set[Request]] = {}
    active_bundles: set[str] = set()
    visiting: set[str] = set()

    def walk(current_id: str, path: tuple[str, ...]) -> None:
        if current_id in visiting:
            raise ValidationError(f"bundle cycle detected at {current_id}")
        visiting.add(current_id)
        active_bundles.add(current_id)
        bundle = catalog.bundles[current_id]
        for child in bundle.children:
            selected = child.role in {"required", "recommended"} or bundle.policy != "preset"
            if not selected:
                continue
            child_path = path + (child.id,)
            if child.id in catalog.leaves:
                leaf = catalog.leaves[child.id]
                if not leaf.available:
                    raise ValidationError(
                        f"bundle {bundle_id} requires unavailable leaf {child.id}: "
                        f"{leaf.unavailable_reason or 'no reason provided'}"
                    )
                requests.setdefault(child.id, set()).add(Request(child_path, child.role))
            else:
                walk(child.id, child_path)
        visiting.remove(current_id)

    walk(bundle_id, (bundle_id,))
    selected_ids = sorted(requests)
    if not selected_ids:
        raise ValidationError(f"bundle {bundle_id} selects no available leaves")
    document = {
        "schemaVersion": SELECTION_SCHEMA,
        "catalogSha256": catalog.sha256,
        "catalogRelease": catalog.release,
        "selectedLeafIds": selected_ids,
        "selectedBundleIds": sorted(active_bundles),
        "leaves": [
            {
                "id": leaf_id,
                "requestedBy": sorted("/".join(request.path) for request in requests[leaf_id]),
                "provenance": sorted({request.role for request in requests[leaf_id]}),
            }
            for leaf_id in selected_ids
        ],
        "userOverrides": [],
        "constraintResults": _constraint_results(catalog, set(selected_ids)),
        "providerRequirements": sorted({catalog.leaves[item].provider for item in selected_ids}),
        "sourceRequirements": sorted({catalog.leaves[item].source for item in selected_ids}),
    }
    return validate_selection(document, catalog)


def required_license_acceptances(catalog: CatalogV3, leaf_ids: list[str] | tuple[str, ...]) -> list[str]:
    return sorted(
        leaf_id for leaf_id in leaf_ids
        if leaf_id in catalog.leaves and catalog.leaves[leaf_id].requires_acceptance
    )


def validate_selection(document: Any, catalog: CatalogV3) -> dict[str, Any]:
    expected = {
        "schemaVersion", "catalogSha256", "catalogRelease", "selectedLeafIds",
        "selectedBundleIds", "leaves", "userOverrides", "constraintResults",
        "providerRequirements", "sourceRequirements",
    }
    if not isinstance(document, dict) or set(document) != expected:
        raise ValidationError("selection document has missing or unknown fields")
    if document["schemaVersion"] != SELECTION_SCHEMA:
        raise ValidationError("unsupported selection document schemaVersion")
    if document["catalogSha256"] != catalog.sha256:
        raise CatalogDriftError("selection catalog digest does not match the current catalog")
    if document["catalogRelease"] != catalog.release:
        raise ValidationError("selection catalog release does not match the current catalog")

    selected_leaf_ids = _sorted_unique_strings(document["selectedLeafIds"], "selectedLeafIds")
    selected_bundle_ids = _sorted_unique_strings(document["selectedBundleIds"], "selectedBundleIds")
    unknown_leaves = sorted(set(selected_leaf_ids) - set(catalog.leaves))
    unknown_bundles = sorted(set(selected_bundle_ids) - set(catalog.bundles))
    if unknown_leaves:
        raise ValidationError(f"selection references unknown application/component IDs: {', '.join(unknown_leaves)}")
    if unknown_bundles:
        raise ValidationError(f"selection references unknown bundle IDs: {', '.join(unknown_bundles)}")
    if not selected_leaf_ids:
        raise ValidationError("selection must contain at least one selected leaf")

    raw_overrides = document["userOverrides"]
    if not isinstance(raw_overrides, list):
        raise ValidationError("userOverrides must be an array")
    overrides: dict[str, bool] = {}
    normalized_overrides: list[dict[str, Any]] = []
    for index, item in enumerate(raw_overrides):
        if not isinstance(item, dict) or set(item) != {"id", "selected"}:
            raise ValidationError(f"userOverrides[{index}] must contain exactly id and selected")
        leaf_id = item["id"]
        if leaf_id not in catalog.leaves:
            raise ValidationError(f"userOverrides[{index}] references an unknown leaf ID")
        if not isinstance(item["selected"], bool) or leaf_id in overrides:
            raise ValidationError("userOverrides must contain unique leaf IDs and boolean states")
        overrides[leaf_id] = item["selected"]
        normalized_overrides.append(item)
    if normalized_overrides != sorted(normalized_overrides, key=lambda item: item["id"]):
        raise ValidationError("userOverrides must be stably sorted")

    raw_leaves = document["leaves"]
    if not isinstance(raw_leaves, list):
        raise ValidationError("selection leaves must be an array")
    submitted: dict[str, tuple[tuple[tuple[str, ...], ...], tuple[str, ...]]] = {}
    for index, item in enumerate(raw_leaves):
        if not isinstance(item, dict) or set(item) != {"id", "requestedBy", "provenance"}:
            raise ValidationError(f"leaves[{index}] must contain exactly id, requestedBy, and provenance")
        leaf_id = item["id"]
        if leaf_id not in catalog.leaves or leaf_id in submitted:
            raise ValidationError(f"leaves[{index}] has an unknown or duplicate leaf ID")
        paths_text = _sorted_unique_strings(item["requestedBy"], f"leaves[{index}].requestedBy")
        provenance = _sorted_unique_strings(item["provenance"], f"leaves[{index}].provenance")
        if not paths_text or not provenance or set(provenance) - (set(ROLES) | {"user"}):
            raise ValidationError(f"leaves[{index}] has invalid requestedBy or provenance")
        submitted[leaf_id] = (tuple(_path(catalog, value, leaf_id) for value in paths_text), tuple(provenance))
    if list(submitted) != selected_leaf_ids:
        raise ValidationError("selection leaves must exactly match selectedLeafIds in stable order")

    selected_bundle_set = set(selected_bundle_ids)
    roots = sorted({path[0] for paths, _ in submitted.values() for path in paths})
    if set(roots) - selected_bundle_set:
        raise ValidationError("requestedBy roots must be present in selectedBundleIds")
    if selected_bundle_set and not roots:
        raise ValidationError("selection has no root bundle")
    requests: dict[str, set[Request]] = {}
    active_bundles: set[str] = set()

    def walk(bundle_id: str, path: tuple[str, ...]) -> None:
        bundle = catalog.bundles[bundle_id]
        active_bundles.add(bundle_id)
        for child in bundle.children:
            child_path = path + (child.id,)
            override = overrides.get(child.id)
            selected = child.role == "required" or (child.role == "recommended" and override is not False)
            if bundle.policy != "preset" and child.role == "optional" and override is None:
                selected = True
            if override is True:
                selected = True
            if child.id in catalog.leaves:
                if selected:
                    requests.setdefault(child.id, set()).add(Request(child_path, child.role))
            elif selected:
                walk(child.id, child_path)

    for root in roots:
        walk(root, (root,))
    for leaf_id, selected in overrides.items():
        if selected and leaf_id in submitted:
            for path in submitted[leaf_id][0]:
                requests.setdefault(leaf_id, set()).add(Request(path, "user"))

    if active_bundles != selected_bundle_set:
        raise ValidationError("selectedBundleIds do not match the effective nested bundle expansion")
    if set(requests) != set(selected_leaf_ids):
        raise ValidationError("selectedLeafIds violate required/recommended/optional selection provenance")
    for leaf_id, selected in overrides.items():
        if not selected and any(request.role == "required" for request in requests.get(leaf_id, set())):
            raise ValidationError(f"userOverrides cannot clear required leaf {leaf_id}")
    for leaf_id, (paths, provenance) in submitted.items():
        expected_paths = tuple(sorted({request.path for request in requests[leaf_id]}))
        expected_provenance = tuple(sorted({request.role for request in requests[leaf_id]}))
        if paths != expected_paths or provenance != expected_provenance:
            raise ValidationError(f"selection provenance does not match catalog references for {leaf_id}")

    expected_constraints = _constraint_results(catalog, set(selected_leaf_ids))
    if document["constraintResults"] != expected_constraints:
        raise ValidationError("selection constraintResults do not match the catalog selection")
    invalid = [result for result in expected_constraints if not result["valid"]]
    if invalid:
        first = invalid[0]
        raise ValidationError(
            f"bundle {first['bundleId']} allows at most {first['maxSelected']} selected child item(s)"
        )
    providers = sorted({catalog.leaves[leaf_id].provider for leaf_id in selected_leaf_ids})
    sources = sorted({catalog.leaves[leaf_id].source for leaf_id in selected_leaf_ids})
    if document["providerRequirements"] != providers or document["sourceRequirements"] != sources:
        raise ValidationError("selection provider/source requirements do not match selected leaves")
    return document


def leaf_status(leaf: Leaf) -> tuple[str, str | None]:
    if not leaf.available:
        return "pending", leaf.unavailable_reason or "leaf is unavailable"
    if leaf.kind == "desktop":
        return "pending", "desktop environments are installed only by the installer"
    if leaf.kind == "operation":
        return "pending", "operation leaves require an explicit non-command action implementation"
    if leaf.provider in {"aur", "conda"}:
        return "pending", f"{leaf.provider} provider is not implemented"
    if leaf.provider != "pacman":
        return "unsupported", f"provider {leaf.provider} is not supported"
    if leaf.source != "arch":
        return "unsupported", "pacman leaves must use the catalog arch source"
    if not leaf.package_targets:
        return "unsupported", "pacman leaf has no catalog-authorized package target"
    return "ready", None


def expand_selection(document: Any, catalog: CatalogV3) -> dict[str, Any]:
    selection = validate_selection(document, catalog)
    submitted = {item["id"]: item for item in selection["leaves"]}
    requirements: list[dict[str, Any]] = []
    targets: set[str] = set()
    pending: list[str] = []
    unsupported: list[str] = []
    for leaf_id in selection["selectedLeafIds"]:
        leaf = catalog.leaves[leaf_id]
        status, reason = leaf_status(leaf)
        packages = list(leaf.package_targets) if status == "ready" else []
        targets.update(packages)
        if status == "pending":
            pending.append(leaf_id)
        elif status == "unsupported":
            unsupported.append(leaf_id)
        requirements.append({
            "id": leaf.id,
            "kind": leaf.kind,
            "requestedBy": submitted[leaf_id]["requestedBy"],
            "provenance": submitted[leaf_id]["provenance"],
            "provider": leaf.provider,
            "source": leaf.source,
            "packageTargets": packages,
            "status": status,
            "reason": reason,
        })
    return {
        "finalLeafIds": list(selection["selectedLeafIds"]),
        "selectedBundleIds": list(selection["selectedBundleIds"]),
        "leafRequirements": requirements,
        "providerRequirements": list(selection["providerRequirements"]),
        "sourceRequirements": list(selection["sourceRequirements"]),
        "pendingItems": pending,
        "unsupportedItems": unsupported,
        "directPackageTargets": sorted(targets),
        "networkRequired": any(catalog.leaves[leaf_id].network_required for leaf_id in selection["selectedLeafIds"]),
    }

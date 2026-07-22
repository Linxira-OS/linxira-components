from __future__ import annotations

from contextlib import redirect_stdout
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from linxira_components.backend import DEFAULT_CATALOG_PATH, apply_transaction  # noqa: E402
from linxira_components.catalog import load_catalog  # noqa: E402
from linxira_components.cli import main  # noqa: E402
from linxira_components.errors import CatalogDriftError, CatalogError, ValidationError  # noqa: E402
from linxira_components.models import create_confirmation, create_request_plan  # noqa: E402
from linxira_components.selection import create_bundle_selection, expand_selection  # noqa: E402


NOW = datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc)


def catalog_document() -> dict:
    def leaf(identifier: str, provider: str, source: str, **extra):
        return {
            "id": identifier,
            "kind": "component",
            "name": {"en": identifier},
            "provider": provider,
            "source": source,
            "availability": True,
            **extra,
        }

    return {
        "catalogVersion": 3,
        "release": "2026.07-design",
        "components": [
            leaf("python-runtime", "pacman", "arch", artifact={"type": "package", "ids": ["python"]}),
            leaf("aur-tool", "aur", "aur"),
            leaf("conda-env", "conda", "bioconda"),
            leaf("flatpak-tool", "flatpak", "flathub"),
        ],
        "applications": [
            {
                "id": "haruna",
                "kind": "application",
                "provider": "pacman",
                "source": "arch",
                "artifact": {"type": "package", "ids": ["haruna"]},
                "availability": {"status": "available", "architectures": ["x86_64"], "networkRequired": True},
            }
        ],
        "operations": [
            {
                "id": "configure-env",
                "kind": "operation",
                "provider": "builtin",
                "source": "catalog",
                "availability": {"status": "available", "architectures": ["x86_64"], "networkRequired": False},
            }
        ],
        "bundles": [
            {
                "id": "workstation",
                "selection": "preset",
                "children": {
                    "required": ["python-stack", "haruna"],
                    "recommended": ["aur-tool"],
                    "optional": ["conda-env", "flatpak-tool", "configure-env"],
                },
            },
            {
                "id": "python-stack",
                "selection": "preset",
                "children": {"required": ["python-runtime"], "recommended": [], "optional": []},
            },
        ],
    }


class V3Fixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.catalog_path = self.directory / "catalog-v3.json"
        self.write_catalog(catalog_document())
        self.catalog = load_catalog(self.catalog_path, "x86_64")

    def test_loads_desktop_leaf_referenced_by_desktop_bundle(self) -> None:
        document = catalog_document()
        document["desktops"] = [{
            "id": "desktop-plasma",
            "kind": "desktop",
            "provider": "pacman",
            "source": "arch",
            "artifact": {"type": "package-group", "ids": ["plasma-meta"]},
            "availability": True,
        }]
        document["bundles"].append({
            "id": "desktop-environments",
            "surface": "desktops",
            "selection": "exclusive",
            "children": {"required": ["desktop-plasma"], "recommended": [], "optional": []},
        })
        self.write_catalog(document)
        catalog = load_catalog(self.catalog_path, "x86_64")

        self.assertEqual(catalog.leaves["desktop-plasma"].kind, "desktop")
        self.assertEqual(catalog.descendant_leaf_ids("desktop-environments"), frozenset({"desktop-plasma"}))
        selection = {
            "schemaVersion": "org.linxira.component-selection.v1",
            "catalogSha256": catalog.sha256,
            "catalogRelease": catalog.release,
            "selectedLeafIds": ["desktop-plasma"],
            "selectedBundleIds": ["desktop-environments"],
            "leaves": [{
                "id": "desktop-plasma",
                "requestedBy": ["desktop-environments/desktop-plasma"],
                "provenance": ["required"],
            }],
            "userOverrides": [],
            "constraintResults": [{
                "bundleId": "desktop-environments",
                "policy": "exclusive",
                "selectedCount": 1,
                "maxSelected": 1,
                "valid": True,
            }, {
                "bundleId": "python-stack",
                "policy": "preset",
                "selectedCount": 0,
                "maxSelected": None,
                "valid": True,
            }, {
                "bundleId": "workstation",
                "policy": "preset",
                "selectedCount": 0,
                "maxSelected": None,
                "valid": True,
            }],
            "providerRequirements": ["pacman"],
            "sourceRequirements": ["arch"],
        }
        plan = expand_selection(selection, catalog)
        self.assertEqual(plan["directPackageTargets"], [])
        self.assertEqual(plan["pendingItems"], ["desktop-plasma"])

    def test_rejects_kind_that_does_not_match_leaf_collection(self) -> None:
        document = catalog_document()
        document["components"][0]["kind"] = "application"
        self.write_catalog(document)
        with self.assertRaisesRegex(CatalogError, r"invalid components\[0\]\.kind"):
            load_catalog(self.catalog_path, "x86_64")

    def test_creates_catalog_bound_selection_for_fixed_bundle(self) -> None:
        document = catalog_document()
        document["bundles"].append({
            "id": "gaming-setup",
            "selection": "preset",
            "children": {
                "required": ["python-runtime"],
                "recommended": ["haruna"],
                "optional": ["aur-tool"],
            },
        })
        self.write_catalog(document)
        catalog = load_catalog(self.catalog_path, "x86_64")
        selection = create_bundle_selection(catalog, "gaming-setup")

        self.assertEqual(selection["selectedLeafIds"], ["haruna", "python-runtime"])
        self.assertEqual(selection["selectedBundleIds"], ["gaming-setup"])
        self.assertEqual(selection["providerRequirements"], ["pacman"])
        self.assertNotIn("aur-tool", selection["selectedLeafIds"])

    def test_cli_plans_fixed_bundle_without_caller_package_ids(self) -> None:
        document = catalog_document()
        document["bundles"].append({
            "id": "gaming-setup",
            "selection": "preset",
            "children": {
                "required": ["python-runtime"],
                "recommended": [],
                "optional": [],
            },
        })
        self.write_catalog(document)
        output = self.directory / "bundle-plan"
        output.mkdir()
        self.assertEqual(main([
            "plan", "--catalog", str(self.catalog_path), "--bundle", "gaming-setup",
            "--output-dir", str(output),
        ]), 0)
        plan = json.loads((output / "request-plan.json").read_text(encoding="utf-8"))
        self.assertEqual(plan["directPackageTargets"], ["python"])

    def test_license_acceptance_is_required_and_bound_into_plan(self) -> None:
        document = catalog_document()
        document["applications"][0]["license"] = {
            "spdx": "LicenseRef-Test",
            "requiresAcceptance": True,
        }
        document["bundles"].append({
            "id": "licensed-setup",
            "selection": "preset",
            "children": {"required": ["haruna"], "recommended": [], "optional": []},
        })
        self.write_catalog(document)
        catalog = load_catalog(self.catalog_path, "x86_64")
        selection = create_bundle_selection(catalog, "licensed-setup")
        with self.assertRaisesRegex(ValidationError, "acceptedLicenseIds"):
            create_request_plan(catalog, [], "x86_64", selection=selection)
        plan = create_request_plan(
            catalog, [], "x86_64", selection=selection, license_acceptances=["haruna"]
        )
        self.assertEqual(plan["acceptedLicenseIds"], ["haruna"])
        confirmation = create_confirmation(plan, catalog)
        self.assertEqual(confirmation["acceptedLicenseIds"], ["haruna"])

    def write_catalog(self, document: dict) -> None:
        self.catalog_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    def selection(self, *, all_optional: bool = True) -> dict:
        leaves = [
            {"id": "aur-tool", "requestedBy": ["workstation/aur-tool"], "provenance": ["recommended"]},
            {"id": "haruna", "requestedBy": ["workstation/haruna"], "provenance": ["required"]},
            {"id": "python-runtime", "requestedBy": ["workstation/python-stack/python-runtime"], "provenance": ["required"]},
        ]
        overrides = []
        if all_optional:
            for leaf_id in ("conda-env", "configure-env", "flatpak-tool"):
                leaves.append({
                    "id": leaf_id,
                    "requestedBy": [f"workstation/{leaf_id}"],
                    "provenance": ["optional", "user"],
                })
                overrides.append({"id": leaf_id, "selected": True})
        leaves.sort(key=lambda item: item["id"])
        selected = [item["id"] for item in leaves]
        providers = sorted({self.catalog.leaves[item].provider for item in selected})
        sources = sorted({self.catalog.leaves[item].source for item in selected})
        return {
            "schemaVersion": "org.linxira.component-selection.v1",
            "catalogSha256": self.catalog.sha256,
            "catalogRelease": self.catalog.release,
            "selectedLeafIds": selected,
            "selectedBundleIds": ["python-stack", "workstation"],
            "leaves": leaves,
            "userOverrides": sorted(overrides, key=lambda item: item["id"]),
            "constraintResults": [
                {"bundleId": "python-stack", "policy": "preset", "selectedCount": 1, "maxSelected": None, "valid": True},
                {"bundleId": "workstation", "policy": "preset", "selectedCount": len(selected), "maxSelected": None, "valid": True},
            ],
            "providerRequirements": providers,
            "sourceRequirements": sources,
        }


class CatalogV3Tests(V3Fixture):
    def test_v3_plan_expands_only_arch_pacman_leaves(self) -> None:
        plan = create_request_plan(
            self.catalog, [], "x86_64", selection=self.selection(), clock=lambda: NOW
        )
        self.assertEqual(plan["schemaVersion"], "org.linxira.components.request-plan.v2")
        self.assertEqual(plan["directPackageTargets"], ["haruna", "python"])
        self.assertEqual(plan["pendingItems"], ["aur-tool", "conda-env", "configure-env"])
        self.assertEqual(plan["unsupportedItems"], ["flatpak-tool"])
        runtime = next(item for item in plan["leafRequirements"] if item["id"] == "python-runtime")
        self.assertEqual(runtime["requestedBy"], ["workstation/python-stack/python-runtime"])
        self.assertEqual(runtime["provider"], "pacman")
        self.assertEqual(runtime["source"], "arch")

    def test_unavailable_leaf_is_recorded_as_pending(self) -> None:
        self.catalog.leaves["aur-tool"] = replace(
            self.catalog.leaves["aur-tool"], available=False, unavailable_reason="review pending"
        )
        plan = create_request_plan(
            self.catalog, [], "x86_64", selection=self.selection(all_optional=False), clock=lambda: NOW
        )
        requirement = next(item for item in plan["leafRequirements"] if item["id"] == "aur-tool")
        self.assertEqual(requirement["status"], "pending")
        self.assertEqual(requirement["reason"], "review pending")

    def test_selection_rejects_catalog_drift_and_nested_path_injection(self) -> None:
        drifted = self.selection()
        drifted["catalogSha256"] = "0" * 64
        with self.assertRaises(CatalogDriftError):
            create_request_plan(self.catalog, [], "x86_64", selection=drifted)

        injected = self.selection()
        runtime = next(item for item in injected["leaves"] if item["id"] == "python-runtime")
        runtime["requestedBy"] = ["workstation/python-runtime"]
        with self.assertRaisesRegex(ValidationError, "nested reference"):
            create_request_plan(self.catalog, [], "x86_64", selection=injected)

    def test_selection_rejects_provenance_and_constraint_tampering(self) -> None:
        provenance = self.selection()
        provenance["leaves"][0]["provenance"] = ["required"]
        with self.assertRaisesRegex(ValidationError, "provenance"):
            create_request_plan(self.catalog, [], "x86_64", selection=provenance)

        constraints = self.selection()
        constraints["constraintResults"][1]["selectedCount"] = 0
        with self.assertRaisesRegex(ValidationError, "constraintResults"):
            create_request_plan(self.catalog, [], "x86_64", selection=constraints)

    def test_selection_rejects_required_override_and_violated_exclusive_constraint(self) -> None:
        required = self.selection()
        required["userOverrides"].append({"id": "python-runtime", "selected": False})
        required["userOverrides"].sort(key=lambda item: item["id"])
        with self.assertRaisesRegex(ValidationError, "cannot clear required"):
            create_request_plan(self.catalog, [], "x86_64", selection=required)

        self.catalog.bundles["workstation"] = replace(
            self.catalog.bundles["workstation"], policy="exclusive"
        )
        exclusive = self.selection()
        exclusive["constraintResults"][1].update({
            "policy": "exclusive", "maxSelected": 1, "valid": False,
        })
        with self.assertRaisesRegex(ValidationError, "at most 1"):
            create_request_plan(self.catalog, [], "x86_64", selection=exclusive)

    def test_v2_ids_are_rejected_for_v3_and_selection_is_rejected_for_v2(self) -> None:
        with self.assertRaisesRegex(ValidationError, "only a selection"):
            create_request_plan(self.catalog, ["workstation"], "x86_64", selection=self.selection())

    def test_cli_accepts_selection_document(self) -> None:
        selection_path = self.directory / "selection.json"
        selection_path.write_text(json.dumps(self.selection()), encoding="utf-8")
        output_dir = self.directory / "out"
        output_dir.mkdir()
        with redirect_stdout(mock.MagicMock()):
            result = main([
                "plan", "--catalog", str(self.catalog_path), "--selection", str(selection_path),
                "--output-dir", str(output_dir),
            ])
        self.assertEqual(result, 0)
        plan = json.loads((output_dir / "request-plan.json").read_text(encoding="utf-8"))
        self.assertEqual(plan["directPackageTargets"], ["haruna", "python"])


class BackendV3Tests(V3Fixture):
    def test_default_catalog_is_canonical_v3(self) -> None:
        self.assertEqual(DEFAULT_CATALOG_PATH, Path("/usr/share/linxira/catalog/catalog-v3.json"))

    def confirmation(self, *, all_optional: bool = True):
        plan = create_request_plan(
            self.catalog, [], "x86_64", selection=self.selection(all_optional=all_optional), clock=lambda: NOW
        )
        return plan, create_confirmation(plan, self.catalog, clock=lambda: NOW)

    def test_apply_runs_only_fixed_catalog_authorized_pacman_targets(self) -> None:
        plan, confirmation = self.confirmation()
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
        receipt = apply_transaction(
            confirmation,
            catalog_path=self.catalog_path,
            receipt_dir=self.directory / "receipts",
            effective_uid=0,
            runner=runner,
        )
        self.assertEqual(
            runner.call_args.args[0],
            ["pacman", "--sync", "--needed", "--noconfirm", "--", "haruna", "python"],
        )
        self.assertFalse(runner.call_args.kwargs["shell"])
        self.assertEqual(receipt["schemaVersion"], "org.linxira.components.receipt.v2")
        self.assertEqual(receipt["finalLeafIds"], plan["finalLeafIds"])
        self.assertEqual(receipt["pendingItems"], ["aur-tool", "conda-env", "configure-env"])
        self.assertEqual(receipt["unsupportedItems"], ["flatpak-tool"])

    def test_rehashed_package_target_injection_is_rejected_before_runner(self) -> None:
        _, confirmation = self.confirmation()
        confirmation["directPackageTargets"].append("rogue")
        ready = next(item for item in confirmation["leafRequirements"] if item["id"] == "python-runtime")
        ready["packageTargets"].append("rogue")
        from linxira_components.jsonio import document_digest

        confirmation["digest"] = document_digest(confirmation)
        runner = mock.Mock()
        with self.assertRaisesRegex(ValidationError, "selection expansion"):
            apply_transaction(
                confirmation,
                catalog_path=self.catalog_path,
                receipt_dir=self.directory / "receipts",
                effective_uid=0,
                runner=runner,
            )
        runner.assert_not_called()

    def test_pending_only_selection_does_not_execute_a_command(self) -> None:
        document = catalog_document()
        document["bundles"] = [{
            "id": "pending-only", "selection": "preset",
            "children": {"required": ["aur-tool"], "recommended": [], "optional": []},
        }]
        self.write_catalog(document)
        catalog = load_catalog(self.catalog_path, "x86_64")
        selection = {
            "schemaVersion": "org.linxira.component-selection.v1",
            "catalogSha256": catalog.sha256,
            "catalogRelease": catalog.release,
            "selectedLeafIds": ["aur-tool"],
            "selectedBundleIds": ["pending-only"],
            "leaves": [{"id": "aur-tool", "requestedBy": ["pending-only/aur-tool"], "provenance": ["required"]}],
            "userOverrides": [],
            "constraintResults": [{"bundleId": "pending-only", "policy": "preset", "selectedCount": 1, "maxSelected": None, "valid": True}],
            "providerRequirements": ["aur"],
            "sourceRequirements": ["aur"],
        }
        plan = create_request_plan(catalog, [], "x86_64", selection=selection, clock=lambda: NOW)
        confirmation = create_confirmation(plan, catalog, clock=lambda: NOW)
        runner = mock.Mock()
        receipt = apply_transaction(
            confirmation, catalog_path=self.catalog_path, receipt_dir=self.directory / "receipts",
            effective_uid=0, runner=runner,
        )
        runner.assert_not_called()
        self.assertEqual(receipt["pendingItems"], ["aur-tool"])


if __name__ == "__main__":
    unittest.main()

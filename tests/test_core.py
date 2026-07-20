from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from uuid import UUID


ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from linxira_components.catalog import load_catalog  # noqa: E402
from linxira_components.backend import apply_transaction  # noqa: E402
from linxira_components.cli import main  # noqa: E402
from linxira_components.errors import (  # noqa: E402
    CatalogDriftError,
    CatalogError,
    DigestError,
    InvalidTransitionError,
    UnknownProfileError,
    UnsafePathError,
    ValidationError,
)
from linxira_components.jsonio import atomic_write_json, document_digest  # noqa: E402
from linxira_components.models import (  # noqa: E402
    ALLOWED_TRANSITIONS,
    Receipt,
    create_confirmation,
    create_request_plan,
    validate_confirmation,
    validate_request_plan,
)


NOW = datetime(2026, 7, 19, 12, 30, tzinfo=timezone.utc)


def catalog_document() -> dict[str, object]:
    def profile(
        profile_id: str,
        packages: list[str],
        order: int,
        *,
        network: bool = True,
    ) -> dict[str, object]:
        return {
            "id": profile_id,
            "name": {"en": profile_id.title(), "zh_CN": profile_id},
            "description": {"en": f"The {profile_id} profile", "zh_CN": profile_id},
            "categories": ["development"],
            "source": "arch",
            "packages": packages,
            "installer": True,
            "availability": {
                "architectures": ["x86_64"],
                "networkRequired": network,
            },
            "review": {"status": "reviewed", "date": "2026-07-19"},
            "presentation": {"recommended": order == 10, "order": order},
        }

    return {
        "$schema": "catalog-v2.schema.json",
        "catalogVersion": 2,
        "release": "2026.07",
        "reviewed": "2026-07-19",
        "sources": [
            {
                "id": "arch",
                "kind": "pacman",
                "trust": "distribution",
                "name": {"en": "Arch", "zh_CN": "Arch"},
            }
        ],
        "categories": [
            {
                "id": "development",
                "name": {"en": "Development", "zh_CN": "Development"},
            }
        ],
        "applications": [
            {
                "id": "haruna",
                "name": {"en": "Haruna", "zh_CN": "Haruna"},
                "description": {"en": "Media player", "zh_CN": "媒体播放器"},
                "categories": ["development"],
                "source": "arch",
                "packages": ["haruna"],
                "installer": True,
                "availability": {"architectures": ["x86_64"], "networkRequired": True},
                "review": {"status": "reviewed", "date": "2026-07-19"},
                "presentation": {"recommended": True, "defaultSelected": True, "order": 10},
            }
        ],
        "profiles": [
            profile("developer", ["python", "git", "shared-tool"], 10),
            profile("science", ["shared-tool", "python-numpy"], 20, network=False),
        ],
    }


class CatalogFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.catalog_path = self.directory / "catalog-v2.json"
        self.write_catalog(catalog_document())

    def write_catalog(self, document: dict[str, object]) -> None:
        self.catalog_path.write_text(
            json.dumps(document, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def load(self):
        return load_catalog(self.catalog_path, "x86_64")


class CatalogTests(CatalogFixture):
    def test_loads_valid_catalog_and_lists_profiles(self) -> None:
        catalog = self.load()
        self.assertEqual([profile.id for profile in catalog.profiles], ["developer", "science"])
        output = io.StringIO()
        with redirect_stdout(output):
            result = main(["list", "--catalog", str(self.catalog_path), "--json"])
        self.assertEqual(result, 0)
        self.assertEqual([item["id"] for item in json.loads(output.getvalue())], ["developer", "science"])

    def test_duplicate_json_key_is_rejected(self) -> None:
        self.catalog_path.write_text(
            '{"catalogVersion":2,"catalogVersion":2}', encoding="utf-8"
        )
        with self.assertRaisesRegex(CatalogError, "duplicate JSON key"):
            self.load()

    def test_unknown_profile_and_profile_injection_are_rejected(self) -> None:
        catalog = self.load()
        with self.assertRaises(UnknownProfileError):
            catalog.select(["missing"])
        with self.assertRaises(UnknownProfileError):
            catalog.select(["developer;touch-pwned"])

    def test_non_arch_source_is_rejected(self) -> None:
        document = catalog_document()
        document["sources"].append(  # type: ignore[union-attr]
            {
                "id": "flathub",
                "kind": "flatpak",
                "trust": "user-opt-in",
                "name": {"en": "Flathub", "zh_CN": "Flathub"},
            }
        )
        document["profiles"][0]["source"] = "flathub"  # type: ignore[index]
        self.write_catalog(document)
        with self.assertRaisesRegex(CatalogError, "source must be"):
            self.load()

    def test_catalog_accepts_non_arch_sources_not_used_by_profiles(self) -> None:
        document = catalog_document()
        document["sources"].append(  # type: ignore[union-attr]
            {
                "id": "bioconda",
                "kind": "conda",
                "trust": "verified-third-party",
                "name": {"en": "Bioconda", "zh_CN": "Bioconda"},
            }
        )
        document["applications"] = []
        document["desktopBundles"] = []
        document["profiles"][0]["applications"] = ["git"]  # type: ignore[index]
        self.write_catalog(document)
        self.assertEqual(len(self.load().profiles), 2)

    def test_architecture_mismatch_is_rejected(self) -> None:
        with self.assertRaisesRegex(CatalogError, "not available"):
            load_catalog(self.catalog_path, "aarch64")

    def test_illegal_package_name_is_rejected(self) -> None:
        document = catalog_document()
        document["profiles"][0]["packages"] = ["git", "$(touch pwned)"]  # type: ignore[index]
        self.write_catalog(document)
        with self.assertRaisesRegex(CatalogError, "invalid profile.*packages item"):
            self.load()

    def test_repository_qualified_package_name_is_rejected(self) -> None:
        document = catalog_document()
        document["profiles"][0]["packages"] = ["core:git"]  # type: ignore[index]
        self.write_catalog(document)
        with self.assertRaisesRegex(CatalogError, "invalid profile.*packages item"):
            self.load()


class PlanTests(CatalogFixture):
    def create_plan(self) -> tuple[object, dict[str, object]]:
        catalog = self.load()
        plan = create_request_plan(
            catalog,
            ["science", "developer", "developer"],
            "x86_64",
            clock=lambda: NOW,
            id_factory=lambda: UUID("11111111-1111-4111-8111-111111111111"),
        )
        return catalog, plan

    def test_multi_profile_plan_is_canonical_and_deduplicated(self) -> None:
        _, plan = self.create_plan()
        self.assertEqual(plan["schemaVersion"], "org.linxira.components.request-plan.v1")
        self.assertEqual(plan["createdAt"], "2026-07-19T12:30:00Z")
        self.assertEqual(plan["profileIds"], ["developer", "science"])
        self.assertEqual(
            plan["directPackageTargets"],
            ["git", "python", "python-numpy", "shared-tool"],
        )
        self.assertTrue(plan["networkRequired"])
        self.assertFalse(plan["systemUpgradeRequired"])
        self.assertEqual(plan["digest"], document_digest(plan))

    def test_plan_cannot_change_validated_architecture(self) -> None:
        catalog = self.load()
        with self.assertRaisesRegex(ValidationError, "architecture differs"):
            create_request_plan(catalog, ["developer"], "aarch64")

    def test_application_only_plan_is_catalog_bound(self) -> None:
        catalog = self.load()
        plan = create_request_plan(
            catalog,
            [],
            "x86_64",
            application_ids=["haruna"],
            clock=lambda: NOW,
        )
        self.assertEqual(plan["profileIds"], [])
        self.assertEqual(plan["applicationIds"], ["haruna"])
        self.assertEqual(plan["directPackageTargets"], ["haruna"])
        confirmation = create_confirmation(plan, catalog, clock=lambda: NOW)
        self.assertEqual(confirmation["applicationIds"], ["haruna"])

    def test_application_only_confirmation_validates(self) -> None:
        catalog = self.load()
        plan = create_request_plan(
            catalog,
            [],
            "x86_64",
            application_ids=["haruna"],
            clock=lambda: NOW,
        )
        confirmation = create_confirmation(plan, catalog, clock=lambda: NOW)

        self.assertIs(validate_confirmation(confirmation), confirmation)

    def test_confirmation_rejects_empty_selection(self) -> None:
        catalog = self.load()
        plan = create_request_plan(
            catalog,
            [],
            "x86_64",
            application_ids=["haruna"],
            clock=lambda: NOW,
        )
        confirmation = create_confirmation(plan, catalog, clock=lambda: NOW)
        confirmation["applicationIds"] = []
        confirmation["digest"] = document_digest(confirmation)

        with self.assertRaisesRegex(
            ValidationError, "must select a profile or application"
        ):
            validate_confirmation(confirmation)

    def test_digest_tamper_is_rejected(self) -> None:
        catalog, plan = self.create_plan()
        plan["directPackageTargets"].append("tampered")  # type: ignore[union-attr]
        with self.assertRaises(DigestError):
            create_confirmation(plan, catalog)  # type: ignore[arg-type]

    def test_rehashed_profile_or_package_injection_is_rejected(self) -> None:
        catalog, plan = self.create_plan()
        injected = deepcopy(plan)
        injected["profileIds"] = ["developer", "injected"]
        injected["digest"] = document_digest(injected)
        with self.assertRaises(UnknownProfileError):
            create_confirmation(injected, catalog)  # type: ignore[arg-type]

        altered = deepcopy(plan)
        altered["directPackageTargets"] = ["git", "python", "rogue-package", "shared-tool"]
        altered["digest"] = document_digest(altered)
        with self.assertRaisesRegex(ValidationError, "do not match"):
            create_confirmation(altered, catalog)  # type: ignore[arg-type]

    def test_catalog_drift_is_rejected_even_when_only_bytes_change(self) -> None:
        catalog, plan = self.create_plan()
        del catalog
        with self.catalog_path.open("a", encoding="utf-8") as stream:
            stream.write(" \n")
        changed_catalog = self.load()
        with self.assertRaises(CatalogDriftError):
            create_confirmation(plan, changed_catalog)  # type: ignore[arg-type]

    def test_confirmation_binds_plan_and_catalog(self) -> None:
        catalog, plan = self.create_plan()
        confirmation = create_confirmation(
            plan,  # type: ignore[arg-type]
            catalog,  # type: ignore[arg-type]
            clock=lambda: NOW,
            id_factory=lambda: UUID("22222222-2222-4222-8222-222222222222"),
        )
        self.assertEqual(confirmation["requestPlanId"], plan["id"])
        self.assertEqual(confirmation["planDigest"], plan["digest"])
        self.assertEqual(confirmation["digest"], document_digest(confirmation))

    def test_noncanonical_timestamp_is_rejected_even_when_rehashed(self) -> None:
        _, plan = self.create_plan()
        plan["createdAt"] = "2026-07-19"
        plan["digest"] = document_digest(plan)
        with self.assertRaisesRegex(ValidationError, "canonical UTC timestamp"):
            validate_request_plan(plan)


class ReceiptTests(unittest.TestCase):
    def receipt(self) -> Receipt:
        return Receipt(
            request_plan_id="11111111-1111-4111-8111-111111111111",
            plan_digest="a" * 64,
            id="22222222-2222-4222-8222-222222222222",
            created_at="2026-07-19T12:30:00Z",
        )

    def test_success_path_and_document(self) -> None:
        receipt = self.receipt()
        for status in ("confirmed", "applying", "succeeded"):
            receipt.transition(status, clock=lambda: NOW)
        document = receipt.to_document()
        self.assertEqual(document["status"], "succeeded")
        self.assertEqual(document["updatedAt"], "2026-07-19T12:30:00Z")
        self.assertEqual(document["digest"], document_digest(document))

    def test_declared_transitions_and_terminal_states(self) -> None:
        self.assertEqual(
            set(ALLOWED_TRANSITIONS),
            {"planned", "confirmed", "applying", "succeeded", "failed", "stale", "interrupted"},
        )
        for terminal in ("succeeded", "failed", "stale", "interrupted"):
            self.assertEqual(ALLOWED_TRANSITIONS[terminal], frozenset())

    def test_illegal_transition_is_rejected(self) -> None:
        with self.assertRaises(InvalidTransitionError):
            self.receipt().transition("succeeded")

    def test_noncanonical_receipt_timestamp_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValidationError, "canonical UTC timestamp"):
            Receipt(
                request_plan_id="11111111-1111-4111-8111-111111111111",
                plan_digest="a" * 64,
                created_at="2026-07-19Z",
            )


class SafetyTests(CatalogFixture):
    def confirmed(self):
        catalog = self.load()
        plan = create_request_plan(catalog, ["developer", "science"], "x86_64", clock=lambda: NOW)
        return catalog, create_confirmation(plan, catalog, clock=lambda: NOW)

    def test_apply_requires_root_before_process_execution(self) -> None:
        _, confirmation = self.confirmed()
        runner = mock.Mock()
        with self.assertRaisesRegex(ValidationError, "run as root"):
            apply_transaction(
                confirmation,
                receipt_dir=self.directory / "receipts",
                catalog_path=self.catalog_path,
                effective_uid=1000,
                runner=runner,
            )
        runner.assert_not_called()

    def test_apply_runs_fixed_pacman_argv_and_persists_succeeded_receipt(self) -> None:
        _, confirmation = self.confirmed()
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, "installed", ""))
        receipt = apply_transaction(
            confirmation,
            receipt_dir=self.directory / "receipts",
            catalog_path=self.catalog_path,
            effective_uid=0,
            runner=runner,
        )
        self.assertEqual(receipt["status"], "succeeded")
        command = runner.call_args.args[0]
        self.assertEqual(command[:5], ["pacman", "--sync", "--needed", "--noconfirm", "--"])
        self.assertEqual(command[5:], ["git", "python", "python-numpy", "shared-tool"])
        self.assertEqual(runner.call_args.kwargs["env"], {"PATH": "/usr/bin:/usr/sbin", "LC_ALL": "C"})
        persisted = list((self.directory / "receipts").glob("*.json"))
        self.assertEqual(len(persisted), 1)
        self.assertEqual(json.loads(persisted[0].read_text(encoding="utf-8"))["status"], "succeeded")

    def test_apply_application_only_transaction_and_persists_receipt(self) -> None:
        catalog = self.load()
        plan = create_request_plan(
            catalog,
            [],
            "x86_64",
            application_ids=["haruna"],
            clock=lambda: NOW,
        )
        confirmation = create_confirmation(plan, catalog, clock=lambda: NOW)
        runner = mock.Mock(
            return_value=subprocess.CompletedProcess([], 0, "installed", "")
        )

        receipt = apply_transaction(
            confirmation,
            receipt_dir=self.directory / "receipts",
            catalog_path=self.catalog_path,
            effective_uid=0,
            runner=runner,
        )

        self.assertEqual(
            runner.call_args.args[0],
            ["pacman", "--sync", "--needed", "--noconfirm", "--", "haruna"],
        )
        self.assertEqual(receipt["status"], "succeeded")
        self.assertEqual(receipt["requestPlanId"], plan["id"])
        self.assertEqual(receipt["planDigest"], plan["digest"])
        persisted = list((self.directory / "receipts").glob("*.json"))
        self.assertEqual(len(persisted), 1)

    def test_apply_records_failed_receipt_when_pacman_fails(self) -> None:
        _, confirmation = self.confirmed()
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 1, "", "package error"))
        with self.assertRaisesRegex(Exception, "exit code 1"):
            apply_transaction(
                confirmation,
                receipt_dir=self.directory / "receipts",
                catalog_path=self.catalog_path,
                effective_uid=0,
                runner=runner,
            )
        persisted = list((self.directory / "receipts").glob("*.json"))
        self.assertEqual(json.loads(persisted[0].read_text(encoding="utf-8"))["status"], "failed")

    def test_output_is_confined_to_plain_filename(self) -> None:
        with self.assertRaises(UnsafePathError):
            atomic_write_json(self.directory, "../escape.json", {"safe": True})
        target = atomic_write_json(self.directory, "safe.json", {"safe": True})
        self.assertEqual(json.loads(target.read_text(encoding="utf-8")), {"safe": True})

    def test_symlink_output_target_is_rejected_when_supported(self) -> None:
        outside = self.directory / "outside.json"
        outside.write_text("unchanged", encoding="utf-8")
        link = self.directory / "linked.json"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are not available to this Windows account")
        with self.assertRaises(UnsafePathError):
            atomic_write_json(self.directory, "linked.json", {"safe": True})
        self.assertEqual(outside.read_text(encoding="utf-8"), "unchanged")


if __name__ == "__main__":
    unittest.main()

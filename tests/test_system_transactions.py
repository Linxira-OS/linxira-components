from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import os
import tempfile
import unittest
from unittest import mock
import sys

from linxira_components.errors import ValidationError
from linxira_components.jsonio import document_digest
from linxira_components.system_transactions import (
    PLAN_SCHEMA,
    RECEIPT_SCHEMA,
    SystemTransactionStore,
    _bounded_process,
)


LOCK_OPERATION = "org.linxira.recovery.pacman-lock-diagnose.v1"
LIVE_OPERATION = "org.linxira.recovery.live-chroot-readiness.v1"
HARDWARE_OPERATION = "org.linxira.hardware.driver-state-diagnose.v1"
HYPERV_OPERATION = "org.linxira.driver.vm-hyperv-guest.v1"
QEMU_OPERATION = "org.linxira.driver.vm-qemu-guest.v1"
VMWARE_OPERATION = "org.linxira.driver.vm-vmware-guest.v1"


class MutableClock:
    def __init__(self):
        self.value = datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.value


class SystemTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "root"
        self.state = Path(self.temporary.name) / "state"
        (self.root / "etc").mkdir(parents=True)
        (self.root / "etc/machine-id").write_text("0123456789abcdef0123456789abcdef\n", encoding="utf-8")
        (self.root / "proc/sys/kernel/random").mkdir(parents=True)
        (self.root / "proc/sys/kernel/random/boot_id").write_text(
            "12345678-1234-4234-9234-123456789abc\n", encoding="utf-8"
        )
        (self.root / "proc/42").mkdir(parents=True)
        (self.root / "proc/42/comm").write_text("pacman\n", encoding="utf-8")
        (self.root / "proc/42/stat").write_text(" ".join(str(value) for value in range(30)), encoding="utf-8")
        (self.root / "var/lib/pacman").mkdir(parents=True)
        (self.root / "var/lib/pacman/db.lck").write_text("", encoding="utf-8")
        self.clock = MutableClock()
        self.store = SystemTransactionStore(
            self.state, self.root, clock=self.clock,
        )

    def test_root_owned_plan_receipt_lifecycle_for_lock_diagnosis(self):
        plan = self.store.create_plan(LOCK_OPERATION, "{}", 1000)
        self.assertEqual(plan["schemaVersion"], PLAN_SCHEMA)
        self.assertEqual(plan["risk"], "read-only")
        self.assertTrue(plan["preState"]["lock"]["exists"])
        self.assertEqual(plan["preState"]["packageProcesses"][0]["program"], "pacman")

        receipt = self.store.confirm_and_apply(plan["id"], plan["digest"], 1000)
        self.assertEqual(receipt["schemaVersion"], RECEIPT_SCHEMA)
        self.assertEqual(receipt["status"], "succeeded")
        self.assertFalse(receipt["changed"])
        self.assertEqual(receipt["digest"], document_digest(receipt))
        self.assertEqual(self.store.get_receipt(receipt["id"], 1000), receipt)
        state = json.loads((self.state / "state" / f"{plan['id']}.json").read_text())
        self.assertEqual(state["status"], "succeeded")
        with self.assertRaisesRegex(ValidationError, "planned state"):
            self.store.confirm_and_apply(plan["id"], plan["digest"], 1000)

    def test_plan_rejects_parameters_tampering_other_caller_and_expiry(self):
        with self.assertRaisesRegex(ValidationError, "exact empty"):
            self.store.create_plan(LOCK_OPERATION, '{"path":"/tmp"}', 1000)
        with self.assertRaisesRegex(ValidationError, "duplicate"):
            self.store.create_plan(LOCK_OPERATION, '{"x":1,"x":2}', 1000)
        plan = self.store.create_plan(LOCK_OPERATION, "{}", 1000)
        with self.assertRaisesRegex(ValidationError, "different caller"):
            self.store.confirm_and_apply(plan["id"], plan["digest"], 1001)
        self.clock.value += timedelta(minutes=11)
        with self.assertRaisesRegex(ValidationError, "expired"):
            self.store.confirm_and_apply(plan["id"], plan["digest"], 1000)

    def test_live_readiness_uses_fixed_findmnt_vector_and_fixed_paths(self):
        for relative in ("mnt/etc/pacman.conf", "mnt/usr/bin/pacman", "mnt/bin/sh", "mnt/etc/fstab", "usr/bin/arch-chroot"):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture", encoding="utf-8")
        result = mock.Mock(
            returncode=0,
            stdout=json.dumps({"filesystems": [{"target": "/mnt", "source": "/dev/vda2"}]}),
            stderr="",
        )
        runner = mock.Mock(return_value=result)
        store = SystemTransactionStore(self.state / "live", self.root, runner=runner, clock=self.clock)
        plan = store.create_plan(LIVE_OPERATION, "{}", 1000)
        self.assertTrue(plan["preState"]["ready"])
        command = runner.call_args.args[0]
        self.assertEqual(command[0], "/usr/bin/findmnt")
        self.assertEqual(command[-1], "/mnt")
        self.assertFalse(runner.call_args.kwargs["shell"])

    def test_live_readiness_rejects_intermediate_symlink(self):
        (self.root / "mnt").mkdir()
        try:
            (self.root / "mnt/etc").symlink_to(self.root / "etc", target_is_directory=True)
        except OSError:
            self.skipTest("directory symlinks are unavailable")
        runner = mock.Mock(return_value=mock.Mock(
            returncode=0, stdout=json.dumps({"filesystems": [{"target": "/mnt"}]}), stderr="",
        ))
        store = SystemTransactionStore(self.state / "symlink", self.root, runner=runner, clock=self.clock)
        plan = store.create_plan(LIVE_OPERATION, "{}", 1000)
        self.assertFalse(plan["preState"]["checks"]["/mnt/etc/pacman.conf"])
        self.assertFalse(plan["preState"]["ready"])

    def test_hardware_diagnosis_uses_fixed_detector_and_strict_document(self):
        detector = {
            "schema_version": 1,
            "detector": {"name": "linxira-chwd-detector", "version": "0.1.0", "upstream_chwd": "1.23.0"},
            "evidence": {
                "pci": [{"bus_id": "0000:00:08.0", "class_id": "0300", "vendor_id": "1414", "device_id": "5353"}],
                "dmi": {"system_vendor": "Microsoft Corporation", "product_name": "Virtual Machine", "chassis_type": "3"},
                "cpu": {"vendor": "GenuineIntel", "family": "6", "model": "106"},
                "virtualization": "microsoft",
            },
            "profile_ids": ["cpu.intel", "vm.hyperv"],
            "warnings": [],
        }
        runner = mock.Mock(return_value=mock.Mock(
            returncode=0, stdout=json.dumps(detector), stderr="",
        ))
        store = SystemTransactionStore(self.state / "hardware", self.root, runner=runner, clock=self.clock)
        plan = store.create_plan(HARDWARE_OPERATION, "{}", 1000)
        self.assertEqual(plan["preState"]["profileIds"], ["cpu.intel", "vm.hyperv"])
        receipt = store.confirm_and_apply(plan["id"], plan["digest"], 1000)
        self.assertFalse(receipt["changed"])
        for call in runner.call_args_list:
            self.assertEqual(call.args[0], ["/usr/bin/linxira-chwd-detector"])
            self.assertFalse(call.kwargs["shell"])
            self.assertEqual(call.kwargs["env"], {"PATH": "/usr/bin", "LC_ALL": "C"})

        runner.return_value.stdout = '{"schema_version":1,"schema_version":1}'
        with self.assertRaisesRegex(ValidationError, "duplicate hardware"):
            store.create_plan(HARDWARE_OPERATION, "{}", 1000)

        malformed = json.loads(json.dumps(detector))
        malformed["profile_ids"] = ["graphics.nvidia"]
        runner.return_value.stdout = json.dumps(malformed)
        with self.assertRaisesRegex(ValidationError, "do not match evidence"):
            store.create_plan(HARDWARE_OPERATION, "{}", 1000)

        malformed = json.loads(json.dumps(detector))
        malformed["evidence"]["pci"][0]["bus_id"] = "outside"
        runner.return_value.stdout = json.dumps(malformed)
        with self.assertRaisesRegex(ValidationError, "PCI value"):
            store.create_plan(HARDWARE_OPERATION, "{}", 1000)

        malformed = json.loads(json.dumps(detector))
        malformed["detector"]["version"] = "01.0.0"
        runner.return_value.stdout = json.dumps(malformed)
        with self.assertRaisesRegex(ValidationError, "version"):
            store.create_plan(HARDWARE_OPERATION, "{}", 1000)

        runner.return_value.stdout = b'{"schema_version":1,"value":"\xff"}'
        with self.assertRaisesRegex(ValidationError, "valid UTF-8"):
            store.create_plan(HARDWARE_OPERATION, "{}", 1000)

    def test_bounded_process_rejects_combined_output_limit(self):
        with self.assertRaisesRegex(ValidationError, "size limit"):
            _bounded_process(
                [sys.executable, "-c", "import sys; sys.stdout.write('x' * 2048)"],
                limit=128,
                timeout=10,
                env=dict(os.environ),
            )

    def test_hyperv_mutation_requires_worker_and_creates_snapshot_bound_receipt(self):
        prestate = {
            "hardware": {"profileIds": ["vm.hyperv"]},
            "snapshot": {"ready": True},
            "package": {"target": "hyperv", "artifacts": [
                {"name": "hyperv", "version": "6.15-1"},
            ]},
        }
        result = {
            "schemaVersion": "org.linxira.components.system-worker-result.v1",
            "planId": "", "planDigest": "", "operationId": HYPERV_OPERATION,
            "status": "succeeded", "changed": True,
            "snapshot": {"name": "2026-07-22_12-00-00", "comment": "", "tag": "O"},
            "verifiedState": {
                "artifacts": [{"name": "hyperv", "version": "6.15-1"}],
                "services": {
                    "hv_kvp_daemon.service": "enabled", "hv_vss_daemon.service": "enabled",
                },
            },
            "rollback": "timeshift-restore-requires-separate-authorization-and-reboot",
        }
        executor = mock.Mock()
        store = SystemTransactionStore(
            self.state / "hyperv", self.root, clock=self.clock, mutation_executor=executor,
        )
        with mock.patch.object(store, "_evidence", return_value=prestate):
            plan = store.create_plan(HYPERV_OPERATION, "{}", 1000)
            result["planId"] = plan["id"]
            result["planDigest"] = plan["digest"]
            result["snapshot"]["comment"] = f"linxira-pre-change-{plan['id']}"
            result["digest"] = document_digest(result)
            executor.return_value = result
            receipt = store.confirm_and_apply(plan["id"], plan["digest"], 1000)
        self.assertEqual(store.operation_action(HYPERV_OPERATION), "org.linxira.components.driver")
        self.assertTrue(receipt["changed"])
        self.assertEqual(receipt["snapshot"]["name"], "2026-07-22_12-00-00")
        executor.assert_called_once_with(plan)

    def test_only_reviewed_guest_operations_have_driver_authorization(self):
        self.assertEqual(self.store.operation_action(QEMU_OPERATION), "org.linxira.components.driver")
        self.assertEqual(self.store.operation_action(VMWARE_OPERATION), "org.linxira.components.driver")
        with self.assertRaisesRegex(ValidationError, "unsupported"):
            self.store.operation_action("org.linxira.driver.vm-virtualbox-guest.v1")

    def test_missing_and_tampered_documents_fail_closed(self):
        with self.assertRaisesRegex(ValidationError, "does not exist"):
            self.store.get_receipt("00000000-0000-0000-0000-000000000000", 1000)
        plan = self.store.create_plan(LOCK_OPERATION, "{}", 1000)
        path = self.state / "plans" / f"{plan['id']}.json"
        value = json.loads(path.read_text())
        value["operationId"] = LIVE_OPERATION
        path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "digest"):
            self.store.confirm_and_apply(plan["id"], plan["digest"], 1000)

    def test_startup_marks_abandoned_apply_state_interrupted(self):
        plan = self.store.create_plan(LOCK_OPERATION, "{}", 1000)
        state_path = self.state / "state" / f"{plan['id']}.json"
        state_path.write_text(json.dumps({
            "id": plan["id"], "status": "applying", "updatedAt": plan["createdAt"],
        }), encoding="utf-8")
        state_path.chmod(0o600)
        SystemTransactionStore(self.state, self.root, clock=self.clock)
        state = json.loads(state_path.read_text())
        self.assertEqual(state["status"], "interrupted")

    def test_startup_recovers_verified_receipt_and_enforces_quota(self):
        plan = self.store.create_plan(LOCK_OPERATION, "{}", 1000)
        receipt = self.store.confirm_and_apply(plan["id"], plan["digest"], 1000)
        state_path = self.state / "state" / f"{plan['id']}.json"
        state_path.write_text(json.dumps({
            "id": plan["id"], "status": "verifying", "updatedAt": plan["createdAt"],
            "receiptId": receipt["id"],
        }), encoding="utf-8")
        state_path.chmod(0o600)
        SystemTransactionStore(self.state, self.root, clock=self.clock)
        self.assertEqual(json.loads(state_path.read_text())["status"], "succeeded")
        with mock.patch("linxira_components.system_transactions.MAX_PLANS_PER_UID", 1):
            with self.assertRaisesRegex(ValidationError, "quota"):
                self.store.create_plan(LOCK_OPERATION, "{}", 1000)
            self.clock.value += timedelta(days=31)
            replacement = self.store.create_plan(LOCK_OPERATION, "{}", 1000)
            self.assertEqual(replacement["creatorUid"], 1000)

    def test_missing_machine_binding_fails_closed(self):
        (self.root / "etc/machine-id").unlink()
        with self.assertRaisesRegex(ValidationError, "machine ID"):
            self.store.create_plan(LOCK_OPERATION, "{}", 1000)

    def test_startup_rejects_receipt_that_does_not_match_plan(self):
        plan = self.store.create_plan(LOCK_OPERATION, "{}", 1000)
        receipt = self.store.confirm_and_apply(plan["id"], plan["digest"], 1000)
        receipt_path = self.state / "receipts" / f"{receipt['id']}.json"
        receipt["operationId"] = LIVE_OPERATION
        receipt["digest"] = document_digest(receipt)
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        receipt_path.chmod(0o600)
        state_path = self.state / "state" / f"{plan['id']}.json"
        state_path.write_text(json.dumps({
            "id": plan["id"], "status": "verifying", "updatedAt": plan["createdAt"],
            "receiptId": receipt["id"],
        }), encoding="utf-8")
        state_path.chmod(0o600)
        SystemTransactionStore(self.state, self.root, clock=self.clock)
        self.assertEqual(json.loads(state_path.read_text())["status"], "interrupted")

    def test_startup_recovers_driver_snapshot_after_worker_result_crash(self):
        store = SystemTransactionStore(self.state / "worker-recovery", self.root, clock=self.clock)
        prestate = {
            "hardware": {"profileIds": ["vm.hyperv"]},
            "snapshot": {"ready": True},
            "package": {"target": "hyperv", "artifacts": [
                {"name": "hyperv", "version": "6.15-1"},
            ]},
        }
        with mock.patch.object(store, "_evidence", return_value=prestate):
            plan = store.create_plan(HYPERV_OPERATION, "{}", 1000)
        state_path = store._path("state", plan["id"])
        store._replace(state_path, {"id": plan["id"], "status": "applying", "updatedAt": plan["createdAt"]})
        snapshot = {
            "name": "2026-07-22_12-00-00",
            "comment": f"linxira-pre-change-{plan['id']}", "tag": "O",
        }
        progress = {
            "schemaVersion": "org.linxira.components.system-worker-progress.v1",
            "planId": plan["id"], "planDigest": plan["digest"],
            "operationId": HYPERV_OPERATION, "snapshot": snapshot,
        }
        progress["digest"] = document_digest(progress)
        store._write_new(store._path("worker-progress", plan["id"]), progress)
        store._path("worker-results", plan["id"]).write_text("{", encoding="utf-8")

        recovered = SystemTransactionStore(store.state_root, self.root, clock=self.clock)
        state = recovered._load(state_path)
        self.assertEqual(state["status"], "failed")
        receipt = recovered.get_receipt(state["receiptId"], 1000)
        self.assertEqual(receipt["snapshot"], snapshot)
        self.assertIn("requires verification", receipt["error"])

    def test_installed_hardware_detector_integration(self):
        detector = Path("/usr/bin/linxira-chwd-detector")
        if not detector.is_file() or not os.access(detector, os.X_OK):
            self.skipTest("installed Linxira hardware detector is unavailable")
        with tempfile.TemporaryDirectory() as directory:
            store = SystemTransactionStore(Path(directory), self.root)
            plan = store.create_plan(HARDWARE_OPERATION, "{}", 1000)
            receipt = store.confirm_and_apply(plan["id"], plan["digest"], 1000)
        self.assertEqual(receipt["status"], "succeeded")
        self.assertIsInstance(receipt["verifiedState"]["profileIds"], list)

    def test_worker_recovery_treats_oneshot_activating_as_running(self):
        store = SystemTransactionStore(self.state / "active-worker", Path("/"), recover=False)
        with mock.patch("linxira_components.system_transactions.subprocess.run") as runner:
            runner.return_value = mock.Mock(returncode=0, stdout="activating\n")
            self.assertTrue(store._worker_is_active("11111111-1111-4111-8111-111111111111"))
            runner.return_value = mock.Mock(returncode=3, stdout="inactive\n")
            self.assertFalse(store._worker_is_active("11111111-1111-4111-8111-111111111111"))


if __name__ == "__main__":
    unittest.main()

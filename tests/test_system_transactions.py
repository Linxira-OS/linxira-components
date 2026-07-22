from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from linxira_components.errors import ValidationError
from linxira_components.jsonio import document_digest
from linxira_components.system_transactions import (
    PLAN_SCHEMA,
    RECEIPT_SCHEMA,
    SystemTransactionStore,
)


LOCK_OPERATION = "org.linxira.recovery.pacman-lock-diagnose.v1"
LIVE_OPERATION = "org.linxira.recovery.live-chroot-readiness.v1"


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


if __name__ == "__main__":
    unittest.main()

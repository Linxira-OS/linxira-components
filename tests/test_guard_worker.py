from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from linxira_components import guard_store, guard_worker
from linxira_components.errors import ValidationError
from linxira_components.jsonio import document_digest


def _plan(operation_id: str, parameters: dict, pre_state: dict) -> dict:
    return {
        "schemaVersion": "org.linxira.components.system-plan.v1",
        "id": "8f0a1c2d-0000-4000-8000-000000000001",
        "operationId": operation_id,
        "parameters": parameters,
        "preState": pre_state,
        "digest": "",
    }


class GuardWorkerTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.store = self.base / "store"
        self.workspace = self.base / "ws"
        self.workspace.mkdir()
        (self.workspace / "a.txt").write_text("hello\n", encoding="utf-8")
        self.config = {
            "configured": True,
            "store": str(self.store),
            "schedule": "*:0/30",
            "keep_scheduled": 24,
            "keep_manual": 10,
        }
        self.addCleanup(self.temporary.cleanup)
        self.original = guard_store.read_config
        guard_store.read_config = lambda *a, **k: self.config  # type: ignore[assignment]
        self.addCleanup(self._restore)

    def _restore(self):
        guard_store.read_config = self.original  # type: ignore[assignment]

    def test_execute_create_reports_a_verified_snapshot(self):
        pre_state = {"configured": True, "store_mode_ok": True, "workspaces": []}
        plan = _plan(guard_worker.CREATE_OPERATION, {"workspace_path": str(self.workspace)}, pre_state)
        plan["digest"] = document_digest({k: v for k, v in plan.items() if k != "digest"})
        result = guard_worker.execute_create(plan, None, lambda: pre_state)
        result["digest"] = document_digest(result)
        self.assertEqual(result["status"], "succeeded")
        self.assertRegex(result["verifiedState"]["snapshot_id"], guard_store.SNAPSHOT_ID_RE)
        self.assertEqual(result["verifiedState"]["workspace_id"], guard_store.workspace_id(str(self.workspace)))
        self.assertEqual(result["rollback"], guard_worker.CREATE_ROLLBACK)
        self.assertTrue(result["changed"])
        self.assertIsNone(result["snapshot"])
        guard_worker.validate_guard_result(result, plan)
        self.assertTrue(
            (guard_store.workspace_root(self.config, result["verifiedState"]["workspace_id"])
             / result["verifiedState"]["snapshot_id"] / "a.txt").is_file()
        )

    def test_execute_create_fails_when_state_drifted(self):
        pre_state = {"configured": True, "store_mode_ok": True, "workspaces": []}
        plan = _plan(guard_worker.CREATE_OPERATION, {"workspace_path": str(self.workspace)}, pre_state)
        plan["digest"] = "0" * 64
        result = guard_worker.execute_create(
            plan, None, lambda: {"configured": True, "store_mode_ok": True, "workspaces": ["drift"]}
        )
        self.assertEqual(result["status"], "failed")
        self.assertIn("state changed", result["error"])
        self.assertEqual(result["rollback"], "not-available")
        self.assertIsNone(result["verifiedState"])

    def test_execute_restore_rejects_an_invalid_snapshot_id(self):
        pre_state = {"configured": True, "store_mode_ok": True, "workspaces": []}
        plan = _plan(
            guard_worker.RESTORE_OPERATION,
            {"snapshot_id": "not-an-id", "restore_target": str(self.base / "out")},
            pre_state,
        )
        result = guard_worker.execute_restore(plan, None, lambda: pre_state)
        self.assertEqual(result["status"], "failed")
        self.assertIn("snapshot", result["error"])
        self.assertFalse((self.base / "out").exists())

    def test_execute_restore_copies_into_a_new_directory(self):
        made = guard_store.create_snapshot(self.config, str(self.workspace), trigger="manual")
        self.assertTrue(made["ok"], made)
        target = self.base / "restored"
        pre_state = {"configured": True, "store_mode_ok": True, "workspaces": []}
        plan = _plan(
            guard_worker.RESTORE_OPERATION,
            {"snapshot_id": made["snapshot_id"], "restore_target": str(target)},
            pre_state,
        )
        result = guard_worker.execute_restore(plan, None, lambda: pre_state)
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["verifiedState"]["target"], str(target))
        self.assertEqual(result["rollback"], guard_worker.RESTORE_ROLLBACK)
        self.assertTrue((target / "a.txt").is_file())
        self.assertFalse((target / guard_store.MANIFEST_NAME).exists())

    def test_validate_rejects_a_result_that_claims_the_wrong_rollback(self):
        pre_state = {"configured": True, "store_mode_ok": True, "workspaces": []}
        plan = _plan(guard_worker.RESTORE_OPERATION, {"snapshot_id": "x", "restore_target": "/tmp/y"}, pre_state)
        plan["digest"] = "0" * 64
        result = guard_worker.execute_restore(plan, None, lambda: pre_state)
        result["status"] = "succeeded"
        result["verifiedState"] = {"target": "/tmp/y", "file_count": 1, "byte_size": 1}
        result["rollback"] = guard_worker.CREATE_ROLLBACK
        result["digest"] = document_digest(result)
        with self.assertRaises(ValidationError):
            guard_worker.validate_guard_result(result, plan)

    def test_every_guard_operation_is_registered(self):
        self.assertEqual(
            set(guard_worker.GUARD_OPERATIONS),
            {guard_worker.CREATE_OPERATION, guard_worker.RESTORE_OPERATION},
        )


if __name__ == "__main__":
    unittest.main()

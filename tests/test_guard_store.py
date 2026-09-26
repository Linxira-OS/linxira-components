from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from linxira_components import guard_store
from linxira_components.errors import ValidationError
from linxira_components.system_transactions import OPERATIONS, REGISTRY_DIGEST, REGISTRY_VERSION


def _config(store: Path, **overrides) -> dict:
    document = {
        "configured": True,
        "store": str(store),
        "schedule": "*:0/30",
        "keep_scheduled": 24,
        "keep_manual": 10,
    }
    document.update(overrides)
    return document


class GuardStoreTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.store = self.base / "store"
        self.workspace = self.base / "ws"
        self.workspace.mkdir()
        self.config = _config(self.store)
        self.addCleanup(self.temporary.cleanup)

    def _write_workspace(self) -> None:
        (self.workspace / ".git").mkdir()
        (self.workspace / ".git" / "config").write_text("[core]\n", encoding="utf-8")
        (self.workspace / "real.txt").write_text("content\n", encoding="utf-8")
        os.symlink("/etc", self.workspace / "link")

    # ── 配置 ────────────────────────────────────────────────

    def test_config_missing_is_not_configured(self):
        self.assertEqual(
            guard_store.read_config(str(self.base / "absent.conf")), {"configured": False}
        )

    def test_config_rejects_group_readable(self):
        path = self.base / "guard.conf"
        path.write_text("[guard]\nstore = /var/lib/linxira/guard\n", encoding="utf-8")
        path.chmod(0o644)
        with self.assertRaises(ValidationError) as caught:
            guard_store.read_config(str(path))
        self.assertIn("root-owned and private", str(caught.exception))

    def test_config_reads_a_private_file(self):
        path = self.base / "guard.conf"
        path.write_text(
            "[guard]\nstore = /var/lib/linxira/guard\nkeep_scheduled = 3\n", encoding="utf-8"
        )
        path.chmod(0o600)
        document = guard_store.read_config(str(path), owner_uid=os.getuid())
        self.assertTrue(document["configured"])
        self.assertEqual(document["store"], "/var/lib/linxira/guard")
        self.assertEqual(document["keep_scheduled"], 3)
        self.assertEqual(document["keep_manual"], 10)
        self.assertEqual(document["schedule"], "*:0/30")

    def test_config_rejects_a_non_positive_retention(self):
        path = self.base / "guard.conf"
        path.write_text("[guard]\nstore = /var/lib/linxira/guard\nkeep_manual = 0\n", encoding="utf-8")
        path.chmod(0o600)
        with self.assertRaises(ValidationError):
            guard_store.read_config(str(path), owner_uid=os.getuid())

    def test_workspace_id_is_stable_and_sanitized(self):
        first = guard_store.workspace_id(str(self.workspace))
        self.assertEqual(first, guard_store.workspace_id(str(self.workspace)))
        label = first.split("-", 1)[1]
        self.assertRegex(label, r"^[a-z0-9-]{1,32}$")
        awkward = self.base / "My Repo (2026)"
        awkward.mkdir()
        self.assertRegex(guard_store.workspace_id(str(awkward)).split("-", 1)[1], r"^[a-z0-9-]+$")

    # ── 快照 ────────────────────────────────────────────────

    def test_create_copies_git_dir_and_rebuilds_symlinks(self):
        self._write_workspace()
        outcome = guard_store.create_snapshot(self.config, str(self.workspace), trigger="manual")
        self.assertTrue(outcome["ok"], outcome)
        snapshot = guard_store.workspace_root(self.config, outcome["workspace_id"]) / outcome["snapshot_id"]
        self.assertTrue((snapshot / ".git" / "config").is_file())
        self.assertTrue((snapshot / "real.txt").is_file())
        self.assertTrue((snapshot / "link").is_symlink())
        self.assertEqual(os.readlink(snapshot / "link"), "/etc")
        # 重建的是链接本身: 快照里不会出现 /etc 的内容。
        copied = [
            entry for entry in snapshot.rglob("*")
            if entry.is_file() and not entry.is_symlink()
            and entry.name != guard_store.MANIFEST_NAME
        ]
        self.assertEqual(outcome["manifest"]["file_count"], len(copied))

    def test_create_fails_when_workspace_missing(self):
        outcome = guard_store.create_snapshot(self.config, str(self.base / "absent"), trigger="manual")
        self.assertFalse(outcome["ok"])
        self.assertIn("not an existing directory", outcome["error"])

    def test_create_refuses_existing_destination(self):
        self._write_workspace()
        destination = self.base / "occupied"
        destination.mkdir()
        (destination / "keep.txt").write_text("keep\n", encoding="utf-8")
        with self.assertRaises(ValidationError) as caught:
            guard_store.copy_tree(self.workspace, destination)
        self.assertIn("already exists", str(caught.exception))
        self.assertEqual((destination / "keep.txt").read_text(encoding="utf-8"), "keep\n")
        self.assertEqual([entry.name for entry in destination.iterdir()], ["keep.txt"])

    def test_a_second_create_never_overwrites_the_first(self):
        self._write_workspace()
        first = guard_store.create_snapshot(self.config, str(self.workspace), trigger="manual")
        second = guard_store.create_snapshot(self.config, str(self.workspace), trigger="manual")
        root = guard_store.workspace_root(self.config, first["workspace_id"])
        self.assertNotEqual(first["snapshot_id"], second["snapshot_id"])
        self.assertTrue((root / first["snapshot_id"] / "real.txt").is_file())
        self.assertTrue((root / second["snapshot_id"] / "real.txt").is_file())

    def test_snapshot_manifest_is_written_last_and_readable(self):
        self._write_workspace()
        outcome = guard_store.create_snapshot(self.config, str(self.workspace), trigger="manual")
        snapshot = guard_store.workspace_root(self.config, outcome["workspace_id"]) / outcome["snapshot_id"]
        document = guard_store.read_manifest(snapshot)
        self.assertEqual(document["schema"], "org.linxira.components.guard-manifest.v1")
        self.assertEqual(document["trigger"], "manual")
        self.assertEqual(document["workspace_path"], os.path.realpath(self.workspace))
        self.assertEqual(document, outcome["manifest"])

    # ── 恢复 ────────────────────────────────────────────────

    def _snapshot(self) -> str:
        self._write_workspace()
        outcome = guard_store.create_snapshot(self.config, str(self.workspace), trigger="manual")
        self.assertTrue(outcome["ok"], outcome)
        return outcome["snapshot_id"]

    def test_restore_rejects_each_unsafe_target(self):
        snapshot_id = self._snapshot()
        occupied = self.base / "occupied"
        occupied.mkdir()
        (occupied / "busy.txt").write_text("busy\n", encoding="utf-8")
        cases = {
            "invalid snapshot ID": ("not-an-id", str(self.base / "out-1")),
            "restore target must be an absolute path": (snapshot_id, "relative/out"),
            "restore target must not be inside the workspace": (
                snapshot_id, str(self.workspace / "inside"),
            ),
            "restore target must not be inside the guard store": (snapshot_id, str(self.store / "x")),
            "restore target must be empty or absent": (snapshot_id, str(occupied)),
        }
        for error, (identifier, target) in cases.items():
            with self.subTest(error=error):
                outcome = guard_store.restore_snapshot(self.config, identifier, target)
                self.assertFalse(outcome["ok"])
                self.assertEqual(outcome["error"], error)
        self.assertTrue((occupied / "busy.txt").is_file())

    def test_restore_rejects_an_unknown_snapshot(self):
        outcome = guard_store.restore_snapshot(self.config, "20260926T000000Z-deadbeef", str(self.base / "x"))
        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["error"], "snapshot not found")

    def test_restore_rejects_a_snapshot_without_manifest(self):
        snapshot_id = self._snapshot()
        snapshot = guard_store.workspace_root(self.config, guard_store.workspace_id(str(self.workspace)))
        (snapshot / snapshot_id / guard_store.MANIFEST_NAME).unlink()
        outcome = guard_store.restore_snapshot(self.config, snapshot_id, str(self.base / "out"))
        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["error"], "snapshot manifest is missing or invalid")

    def test_restore_excludes_manifest_from_output(self):
        snapshot_id = self._snapshot()
        target = self.base / "restored"
        outcome = guard_store.restore_snapshot(self.config, snapshot_id, str(target))
        self.assertTrue(outcome["ok"], outcome)
        self.assertTrue((target / ".git" / "config").is_file())
        self.assertTrue((target / "link").is_symlink())
        self.assertFalse((target / guard_store.MANIFEST_NAME).exists())
        self.assertTrue((self.workspace / "real.txt").is_file())

    # ── 保留策略 ────────────────────────────────────────────

    def test_ensure_store_mounted_is_a_noop_without_a_uuid(self):
        outcome = guard_store.ensure_store_mounted(self.config)
        self.assertTrue(outcome["ok"])
        self.assertFalse(outcome["mounted"])
        self.assertEqual(outcome["reason"], "no-store-uuid-configured")

    def test_ensure_store_mounted_rejects_a_missing_partition(self):
        config = dict(self.config, store_uuid="11111111-2222-4333-8444-555555555555")
        outcome = guard_store.ensure_store_mounted(config)
        self.assertFalse(outcome["ok"])
        self.assertIn("is not present", outcome["error"])

    def test_ensure_store_mounted_rejects_a_malformed_uuid(self):
        outcome = guard_store.ensure_store_mounted(dict(self.config, store_uuid="not-a-uuid"))
        self.assertFalse(outcome["ok"])
        self.assertIn("malformed", outcome["error"])

    def test_prune_keeps_counts_and_drops_incomplete(self):
        self._write_workspace()
        root = guard_store.workspace_root(self.config, guard_store.workspace_id(str(self.workspace)))
        root.mkdir(parents=True)
        for trigger, count in (("scheduled", 30), ("manual", 12)):
            stamp = "20260101" if trigger == "scheduled" else "20260201"
            month = "01" if trigger == "scheduled" else "02"
            for index in range(count):
                identifier = f"{stamp}T{index:06d}Z-{index:08x}"
                directory = root / identifier
                directory.mkdir()
                guard_store.write_manifest(directory, {
                    "schema": guard_store.MANIFEST_SCHEMA,
                    "snapshot_id": identifier,
                    "workspace_id": "w",
                    "workspace_path": str(self.workspace),
                    "created_at": f"2026-{month}-{1 + index:02d}T00:00:00Z",
                    "trigger": trigger,
                    "file_count": 1,
                    "byte_size": 1,
                    "skipped_special": 0,
                })
        broken = root / "20260101T000000Z-99999999"
        broken.mkdir()
        (broken / "half-copied.txt").write_text("partial\n", encoding="utf-8")

        removed = guard_store.prune(self.config, guard_store.workspace_id(str(self.workspace)))
        self.assertIn(broken.name, removed)
        self.assertFalse(broken.exists())
        remaining = [guard_store.read_manifest(entry) for entry in root.iterdir()]
        self.assertEqual(len(remaining), 34)
        self.assertEqual(sum(1 for item in remaining if item["trigger"] == "scheduled"), 24)
        self.assertEqual(sum(1 for item in remaining if item["trigger"] == "manual"), 10)

    def test_list_snapshots_is_newest_first(self):
        self._write_workspace()
        first = guard_store.create_snapshot(self.config, str(self.workspace), trigger="manual")
        second = guard_store.create_snapshot(self.config, str(self.workspace), trigger="scheduled")
        listed = guard_store.list_snapshots(self.config, str(self.workspace))
        self.assertEqual({item["snapshot_id"] for item in listed}, {first["snapshot_id"], second["snapshot_id"]})
        self.assertEqual(
            [item["created_at"] for item in listed],
            sorted((item["created_at"] for item in listed), reverse=True),
        )


class GuardRegistryTest(unittest.TestCase):
    def test_operations_registry_contains_guard_entries(self):
        create = OPERATIONS["org.linxira.guard.create-workspace-snapshot.v1"]
        restore = OPERATIONS["org.linxira.guard.restore-workspace-snapshot.v1"]
        self.assertEqual(create["lockDomain"], "workspace-guard")
        self.assertEqual(restore["lockDomain"], "workspace-guard")
        for operation in (create, restore):
            self.assertEqual(operation["action"], "org.linxira.components.recovery")
            # read-only 的 plan 在 confirm_and_apply 里根本不执行, 守护必须避开它。
            self.assertNotEqual(operation["risk"], "read-only")
        self.assertEqual(REGISTRY_VERSION, "2026.09.26.1")
        self.assertEqual(len(REGISTRY_DIGEST), 64)

    def test_evidence_never_carries_snapshot_counts(self):
        import inspect

        source = inspect.getsource(
            __import__("linxira_components.system_transactions", fromlist=["x"])
            .SystemTransactionStore._workspace_guard_evidence
        )
        for volatile in ("snapshot_count", "free_bytes", "created_at"):
            self.assertNotIn(volatile, source)


if __name__ == "__main__":
    unittest.main()

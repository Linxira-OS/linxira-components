from __future__ import annotations

import json
import base64
import hashlib
import io
from pathlib import Path
import tempfile
import tarfile
import unittest

from linxira_components.driver_worker import (
    GUEST_SPECS,
    HYPERV_OPERATION,
    QEMU_OPERATION,
    VMWARE_OPERATION,
    apply_hyperv,
    collect_hyperv_prestate,
    validate_result,
)
from linxira_components.errors import ValidationError
from linxira_components.jsonio import document_digest


class FixedResults:
    def __init__(self):
        self.calls = []
        self.list_count = 0

    def __call__(self, command, timeout, limit):
        self.calls.append((command, timeout, limit))
        if command[0] == "/usr/bin/findmnt":
            stdout = json.dumps({"filesystems": [{
                "target": "/", "source": "/dev/vda2", "fstype": "btrfs",
                "fsroots": "/@", "uuid": "11111111-2222-3333-4444-555555555555",
                "avail": 8 * 1024**3, "size": 32 * 1024**3,
            }]})
            return type("Result", (), {"returncode": 0, "stdout": stdout, "stderr": ""})()
        if "--print" in command:
            return type("Result", (), {
                "returncode": 0,
                "stdout": "hyperv\t6.15-1\thttps://mirror.invalid/hyperv.pkg.tar.zst\n",
                "stderr": "",
            })()
        if command[:3] == ["/usr/bin/pacman", "--query", "--"]:
            return type("Result", (), {"returncode": 1, "stdout": "", "stderr": ""})()
        if command[:2] == ["/usr/bin/systemctl", "is-enabled"]:
            return type("Result", (), {"returncode": 1, "stdout": "not-found\n", "stderr": ""})()
        raise AssertionError(command)


class DriverWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "etc/timeshift").mkdir(parents=True)
        (self.root / "etc/timeshift/timeshift.json").write_text(
            json.dumps({
                "btrfs_mode": "true", "backup_device_uuid": "11111111-2222-3333-4444-555555555555",
            }), encoding="utf-8"
        )
        (self.root / "etc/pacman.conf").write_text("[options]\n[core]\n", encoding="utf-8")
        (self.root / "usr/bin").mkdir(parents=True)
        (self.root / "usr/bin/timeshift").write_text("fixture", encoding="utf-8")
        (self.root / "usr/bin/timeshift").chmod(0o755)
        (self.root / "var/lib/pacman/sync").mkdir(parents=True)
        package_bytes = b"signed package fixture"
        signature = b"detached signature fixture"
        description = (
            "%NAME%\nhyperv\n\n%VERSION%\n6.15-1\n\n"
            "%FILENAME%\nhyperv.pkg.tar.zst\n\n"
            f"%CSIZE%\n{len(package_bytes)}\n\n"
            f"%SHA256SUM%\n{hashlib.sha256(package_bytes).hexdigest()}\n\n"
            f"%PGPSIG%\n{base64.b64encode(signature).decode()}\n\n"
        ).encode()
        with tarfile.open(self.root / "var/lib/pacman/sync/core.db", "w:gz") as archive:
            member = tarfile.TarInfo("hyperv-6.15-1/desc")
            member.size = len(description)
            archive.addfile(member, io.BytesIO(description))
        self.package_bytes = package_bytes
        self.signature = signature

    def test_collect_binds_fixed_hyperv_artifact_snapshot_and_repository(self):
        run = FixedResults()
        state = collect_hyperv_prestate(
            self.root,
            run,
            {"profileIds": ["cpu.intel", "vm.hyperv"]},
            {"lock": {"exists": False}, "packageProcesses": []},
        )
        self.assertTrue(state["snapshot"]["ready"])
        self.assertEqual(state["package"]["targets"], ["hyperv"])
        self.assertEqual(state["package"]["artifacts"][0]["version"], "6.15-1")
        self.assertEqual(run.calls[0][0][0], "/usr/bin/findmnt")
        self.assertIn("%n\t%v\t%l", run.calls[2][0])

    def test_guest_adapter_registry_keeps_platform_packages_and_units_fixed(self):
        self.assertEqual(GUEST_SPECS[QEMU_OPERATION].packages, ("qemu-guest-agent", "spice-vdagent"))
        self.assertEqual(dict(GUEST_SPECS[QEMU_OPERATION].services), {
            "qemu-guest-agent.service": "static", "spice-vdagentd.socket": "static",
        })
        self.assertEqual(GUEST_SPECS[VMWARE_OPERATION].packages, ("open-vm-tools",))
        self.assertEqual(dict(GUEST_SPECS[VMWARE_OPERATION].services), {
            "vmtoolsd.service": "enabled", "vmware-vmblock-fuse.service": "enabled",
        })
        self.assertNotIn("org.linxira.driver.vm-virtualbox-guest.v1", GUEST_SPECS)

    def test_qemu_and_vmware_results_are_operation_and_service_bound(self):
        for operation_id in (QEMU_OPERATION, VMWARE_OPERATION):
            spec = GUEST_SPECS[operation_id]
            artifacts = [{"name": name, "version": "1.0-1"} for name in spec.packages]
            plan = {
                "id": "11111111-1111-4111-8111-111111111111", "digest": "plan-digest",
                "operationId": operation_id, "preState": {"package": {"artifacts": artifacts}},
            }
            result = {
                "schemaVersion": "org.linxira.components.system-worker-result.v1",
                "planId": plan["id"], "planDigest": plan["digest"], "operationId": operation_id,
                "status": "succeeded", "changed": True,
                "snapshot": {
                    "name": "2026-07-22_12-00-00",
                    "comment": f"linxira-pre-change-{plan['id']}", "tag": "O",
                },
                "verifiedState": {"artifacts": artifacts, "services": dict(spec.services)},
                "rollback": "timeshift-restore-requires-separate-authorization-and-reboot",
            }
            result["digest"] = document_digest(result)
            self.assertEqual(validate_result(result, plan), result)
            result["operationId"] = HYPERV_OPERATION
            result["digest"] = document_digest(result)
            with self.assertRaisesRegex(ValidationError, "invalid result"):
                validate_result(result, plan)

    def test_apply_requires_verified_snapshot_before_fixed_pacman(self):
        calls = []
        list_count = 0

        cache_root = self.root / "cache"
        cache_root.mkdir()
        signature_b64 = base64.b64encode(self.signature).decode()
        def run(command, timeout, limit):
            nonlocal list_count
            calls.append(command)
            if command[:2] == ["/usr/bin/timeshift", "--list"]:
                list_count += 1
                stdout = "" if list_count == 1 else (
                    "0  >  2026-07-22_12-00-00  O  "
                    "linxira-pre-change-11111111-1111-4111-8111-111111111111\n"
                )
                return type("Result", (), {"returncode": 0, "stdout": stdout})()
            if command[:2] == ["/usr/bin/timeshift", "--create"]:
                return type("Result", (), {"returncode": 0, "stdout": "created"})()
            if "--downloadonly" in command:
                cache = Path(command[command.index("--cachedir") + 1])
                (cache / "hyperv.pkg.tar.zst").write_bytes(self.package_bytes)
                return type("Result", (), {"returncode": 0, "stdout": "downloaded"})()
            if command[0] == "/usr/bin/pacman-key":
                return type("Result", (), {"returncode": 0, "stdout": "valid"})()
            if command[:2] == ["/usr/bin/systemctl", "enable"]:
                return type("Result", (), {"returncode": 0, "stdout": "enabled"})()
            if command[:2] == ["/usr/bin/systemctl", "is-enabled"]:
                return type("Result", (), {"returncode": 0, "stdout": "enabled\n"})()
            if "--upgrade" in command:
                return type("Result", (), {"returncode": 0, "stdout": "installed"})()
            if command[:2] == ["/usr/bin/pacman", "--query"]:
                return type("Result", (), {"returncode": 0, "stdout": "hyperv 6.15-1\n"})()
            raise AssertionError(command)

        plan = {
            "id": "11111111-1111-4111-8111-111111111111", "digest": "digest",
            "operationId": HYPERV_OPERATION,
            "preState": {"package": {"installedVersion": None, "artifacts": [
                {
                    "name": "hyperv", "version": "6.15-1", "location": "https://mirror.invalid/hyperv.pkg.tar.zst",
                    "filename": "hyperv.pkg.tar.zst", "size": str(len(self.package_bytes)),
                    "sha256": hashlib.sha256(self.package_bytes).hexdigest(), "signature": signature_b64,
                    "signatureSha256": hashlib.sha256(self.signature).hexdigest(), "repository": "core",
                },
            ]}},
        }
        result = apply_hyperv(
            plan, run, lambda: plan["preState"], cache_root,
            commit_packages=lambda paths, before: before(),
        )
        self.assertTrue(result["changed"])
        self.assertEqual(result["snapshot"]["name"], "2026-07-22_12-00-00")
        self.assertEqual(result["verifiedState"]["services"], {
            "hv_kvp_daemon.service": "enabled", "hv_vss_daemon.service": "enabled",
        })
        self.assertFalse(any(command[:2] == ["/usr/bin/pacman", "--upgrade"] for command in calls))
        download = next(command for command in calls if "--downloadonly" in command)
        self.assertIn("--disable-sandbox", download)

    def test_apply_failure_after_snapshot_keeps_rollback_identity(self):
        list_count = 0
        cache_root = self.root / "failed-cache"
        cache_root.mkdir()
        signature_b64 = base64.b64encode(self.signature).decode()
        def run(command, timeout, limit):
            nonlocal list_count
            if command[:2] == ["/usr/bin/timeshift", "--list"]:
                list_count += 1
                stdout = "" if list_count == 1 else (
                    "0  >  2026-07-22_12-00-00  O  "
                    "linxira-pre-change-11111111-1111-4111-8111-111111111111\n"
                )
                return type("Result", (), {"returncode": 0, "stdout": stdout})()
            if command[:2] == ["/usr/bin/timeshift", "--create"]:
                return type("Result", (), {"returncode": 0, "stdout": "created"})()
            if "--downloadonly" in command:
                cache = Path(command[command.index("--cachedir") + 1])
                (cache / "hyperv.pkg.tar.zst").write_bytes(self.package_bytes)
                return type("Result", (), {"returncode": 0, "stdout": "downloaded"})()
            if command[0] == "/usr/bin/pacman-key":
                return type("Result", (), {"returncode": 0, "stdout": "valid"})()
            if command[:2] == ["/usr/bin/pacman", "--query"]:
                return type("Result", (), {"returncode": 0, "stdout": "hyperv 6.15-1\n"})()
            raise AssertionError(command)
        plan = {
            "id": "11111111-1111-4111-8111-111111111111", "digest": "digest",
            "operationId": HYPERV_OPERATION,
            "preState": {"package": {"installedVersion": None, "artifacts": [
                {
                    "name": "hyperv", "version": "6.15-1", "location": "https://mirror.invalid/hyperv.pkg.tar.zst",
                    "filename": "hyperv.pkg.tar.zst", "size": str(len(self.package_bytes)),
                    "sha256": hashlib.sha256(self.package_bytes).hexdigest(), "signature": signature_b64,
                    "signatureSha256": hashlib.sha256(self.signature).hexdigest(), "repository": "core",
                },
            ]}},
        }
        def fail_commit(paths, before):
            before()
            raise ValidationError("transaction failed after snapshot")
        result = apply_hyperv(
            plan, run, lambda: plan["preState"], cache_root, commit_packages=fail_commit,
        )
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["changed"])
        self.assertEqual(result["snapshot"]["name"], "2026-07-22_12-00-00")

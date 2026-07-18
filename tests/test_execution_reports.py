# -*- coding: utf-8 -*-

import io
import json
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import XiaohaCleanerAuto as auto
import xiaoha_cleaner as core


class ExecutionReportTest(unittest.TestCase):
    def make_target(self, root):
        target = root / "server-data"
        owned = target / "resources" / "[local]" / "hgadmin"
        owned.mkdir(parents=True)
        (owned / "fxmanifest.lua").write_text(
            "fx_version 'cerulean'\nauthor 'XIAOHA'\n",
            encoding="utf-8",
        )
        return target, owned

    def run_auto(self, arguments):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = auto.main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_scan_failure_writes_terminal_scan_report(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            output = root / "scan-report"
            code, stdout, stderr = self.run_auto([
                "scan", str(root / "missing"), "--output", str(output),
            ])
            self.assertEqual(code, 1)
            self.assertIn("JSON report:", stdout)
            self.assertIn("Target is not an existing directory", stderr)
            payload = json.loads(
                (output / "scan-report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(payload["status"], "scan-failed")
            self.assertEqual(payload["operation"], "scan")
            self.assertTrue(payload["terminal"])
            self.assertTrue(payload["finished_at"])
            self.assertEqual(payload["operations"], [])
            self.assertFalse(payload["partial_changes_possible"])
            self.assertFalse((output / "cleanup_database.sql").exists())

    def test_preflight_failure_rewrites_run_report(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            target, owned = self.make_target(root)
            plan = core.build_plan(target)
            owned.rename(root / "removed-after-scan")
            with self.assertRaisesRegex(RuntimeError, "Resource disappeared"):
                core.clean_target(plan, root / "quarantine")
            report = next((root / "quarantine").rglob("run-report.json"))
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "failed-preflight")
            self.assertTrue(payload["terminal"])
            self.assertEqual(payload["phase"], "preflight")
            self.assertIn("Resource disappeared", payload["error"])
            self.assertEqual(payload["operations"], [])
            self.assertFalse(payload["partial_changes_possible"])

    def test_clean_failure_reports_complete_rollback(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            target, owned = self.make_target(root)
            (target / "server.cfg").write_text("ensure hgadmin\n", encoding="utf-8")
            plan = core.build_plan(target)

            with mock.patch.object(
                core, "backup_and_edit", side_effect=RuntimeError("edit boom")
            ):
                with self.assertRaisesRegex(RuntimeError, "edit boom"):
                    core.clean_target(plan, root / "quarantine")

            report = next((root / "quarantine").rglob("run-report.json"))
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "failed-rolled-back")
            self.assertFalse(payload["filesystem_partial_changes_possible"])
            self.assertFalse(payload["partial_changes_possible"])
            self.assertTrue(owned.is_dir())

    def test_clean_failure_reports_incomplete_rollback(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            target, owned = self.make_target(root)
            (target / "server.cfg").write_text("ensure hgadmin\n", encoding="utf-8")
            plan = core.build_plan(target)

            def fail_with_conflict(*_args, **_kwargs):
                owned.mkdir(parents=True)
                (owned / "user-created.txt").write_text("keep", encoding="utf-8")
                raise RuntimeError("edit boom")

            with mock.patch.object(
                core, "backup_and_edit", side_effect=fail_with_conflict
            ):
                with self.assertRaisesRegex(RuntimeError, "Rollback errors"):
                    core.clean_target(plan, root / "quarantine")

            report = next((root / "quarantine").rglob("run-report.json"))
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "failed-rollback-incomplete")
            self.assertTrue(payload["filesystem_partial_changes_possible"])
            self.assertTrue(payload["partial_changes_possible"])
            self.assertIn("Restore target already exists", payload["error"])
            self.assertTrue((owned / "user-created.txt").is_file())
            self.assertEqual(payload["rollback"]["conflict_operations"], 1)
            self.assertEqual(
                len(payload["rollback"]["pending_restore_operations"]), 1
            )

    def test_post_write_hash_failure_is_fully_rolled_back(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            target, owned = self.make_target(root)
            server_cfg = target / "server.cfg"
            original_text = "ensure hgadmin\n"
            server_cfg.write_text(original_text, encoding="utf-8")
            plan = core.build_plan(target)
            edited_bytes = plan["edits"]["configs"][0]["_new_bytes"]
            original_snapshot = core.path_snapshot_sha256

            def fail_after_write(path):
                path = Path(path)
                if path == server_cfg and path.read_bytes() == edited_bytes:
                    raise OSError("hash after write failed")
                return original_snapshot(path)

            with mock.patch.object(
                core, "path_snapshot_sha256", side_effect=fail_after_write
            ):
                with self.assertRaisesRegex(RuntimeError, "hash after write failed"):
                    core.clean_target(plan, root / "quarantine")

            report = next((root / "quarantine").rglob("run-report.json"))
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "failed-rolled-back")
            self.assertFalse(payload["partial_changes_possible"])
            self.assertEqual(
                server_cfg.read_text(encoding="utf-8"), original_text
            )
            self.assertTrue(owned.is_dir())
            self.assertTrue(all(
                item["status"] == "restored"
                for item in payload["rollback"]["operation_results"]
            ))

    def test_file_failure_keeps_database_requested_and_prints_report_path(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            target, _ = self.make_target(root)
            (target / "server.cfg").write_text("ensure hgadmin\n", encoding="utf-8")
            quarantine = root / "quarantine"
            with mock.patch.object(
                core, "backup_and_edit", side_effect=RuntimeError("file boom")
            ):
                code, stdout, _ = self.run_auto([
                    "clean", str(target), "--yes",
                    "--quarantine-root", str(quarantine),
                    "--apply-sql", "--yes-drop-tables",
                    "--mysql-uri", "mysql://root:secret@localhost/testdb",
                    "--mysql-command", sys.executable,
                ])
            self.assertEqual(code, 1)
            self.assertIn("Quarantine/report:", stdout)
            payload = json.loads(
                next(quarantine.rglob("run-report.json")).read_text(encoding="utf-8")
            )
            self.assertEqual(payload["status"], "failed-rolled-back")
            self.assertTrue(payload["database_execution"]["requested"])
            self.assertEqual(payload["database_execution"]["database"], "testdb")
            self.assertEqual(payload["database_execution"]["status"], "not-started")

    def test_database_marker_failure_keeps_terminal_applied_report(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            target, _ = self.make_target(root)
            quarantine = root / "quarantine"
            original_write_bytes = Path.write_bytes

            def guarded_write_bytes(path, data):
                if Path(path).name == "database-cleanup-applied.json":
                    raise OSError("marker disk full")
                return original_write_bytes(path, data)

            with mock.patch.object(core, "apply_sql_file", return_value=""), mock.patch.object(
                Path, "write_bytes", new=guarded_write_bytes
            ):
                code, _, stderr = self.run_auto([
                    "clean", str(target), "--yes",
                    "--quarantine-root", str(quarantine),
                    "--apply-sql", "--yes-drop-tables",
                    "--mysql-uri", "mysql://root:secret@localhost/testdb",
                    "--mysql-command", sys.executable,
                ])
            self.assertEqual(code, 0)
            self.assertIn("marker disk full", stderr)
            report = next(quarantine.rglob("run-report.json"))
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "cleaned-database-applied")
            self.assertTrue(payload["terminal"])
            self.assertTrue(payload["database_execution"]["applied"])
            self.assertEqual(payload["database_execution"]["marker_status"], "failed")
            self.assertFalse((report.parent / "database-cleanup-applied.json").exists())

    def test_clean_database_failure_updates_same_report(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            target, _ = self.make_target(root)
            quarantine = root / "quarantine"
            secret_uri = "mysql://tester:super-secret@127.0.0.1/testdb"

            def fail_database(*_args, **_kwargs):
                pending = next(quarantine.rglob("run-report.json"))
                payload = json.loads(pending.read_text(encoding="utf-8"))
                self.assertEqual(
                    payload["status"], "filesystem-cleaned-database-pending"
                )
                self.assertFalse(payload["terminal"])
                self.assertIsNone(payload["finished_at"])
                raise RuntimeError(
                    "database boom ``` super-secret " + secret_uri +
                    " MYSQL_PWD=super-secret"
                )

            with mock.patch.object(core, "apply_sql_file", side_effect=fail_database):
                code, stdout, stderr = self.run_auto([
                    "clean", str(target), "--yes",
                    "--quarantine-root", str(quarantine),
                    "--apply-sql", "--yes-drop-tables",
                    "--mysql-uri", secret_uri,
                    "--mysql-command", sys.executable,
                ])
            self.assertEqual(code, 1)
            report = next(quarantine.rglob("run-report.json"))
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(
                payload["status"], "filesystem-cleaned-database-failed"
            )
            self.assertTrue(payload["terminal"])
            self.assertTrue(payload["database_partial_changes_possible"])
            self.assertFalse(payload["filesystem_partial_changes_possible"])
            self.assertTrue(payload["operations"])
            self.assertEqual(payload["database_execution"]["status"], "failed")
            serialized = report.read_text(encoding="utf-8")
            self.assertNotIn("super-secret", serialized)
            self.assertNotIn(secret_uri, serialized)
            self.assertNotIn("super-secret", stdout)
            self.assertNotIn("super-secret", stderr)
            markdown = report.with_suffix(".md").read_text(encoding="utf-8")
            self.assertIn("## 已执行文件操作", markdown)
            self.assertIn("## 注意事项", markdown)
            self.assertNotIn("```text", markdown)

    def test_clean_database_success_records_marker_and_hashes(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            target, _ = self.make_target(root)
            quarantine = root / "quarantine"
            with mock.patch.object(core, "apply_sql_file", return_value=""):
                code, _, _ = self.run_auto([
                    "clean", str(target), "--yes",
                    "--quarantine-root", str(quarantine),
                    "--apply-sql", "--yes-drop-tables",
                    "--mysql-uri", "mysql://root@127.0.0.1/testdb",
                    "--mysql-command", sys.executable,
                ])
            self.assertEqual(code, 0)
            report = next(quarantine.rglob("run-report.json"))
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "cleaned-database-applied")
            self.assertTrue(payload["terminal"])
            self.assertFalse(payload["partial_changes_possible"])
            self.assertTrue(payload["database_execution"]["applied"])
            self.assertTrue(Path(payload["database_execution"]["marker"]).is_file())
            self.assertTrue(payload["operations"][0]["content_sha256"])

    def test_restore_conflict_is_reported_without_overwrite(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            target, owned = self.make_target(root)
            plan = core.build_plan(target)
            run_dir, _, reports = core.clean_target(plan, root / "quarantine")
            owned.mkdir(parents=True)
            (owned / "user-change.txt").write_text("keep", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "Restore target already exists"):
                core.restore_report(reports[0])
            payload = json.loads(
                (run_dir / "restore-report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(payload["status"], "restore-conflict")
            self.assertEqual(payload["conflict_operations"], 1)
            self.assertTrue(payload["filesystem_partial_changes_possible"])
            self.assertTrue(payload["terminal"])
            self.assertTrue((owned / "user-change.txt").is_file())
            self.assertTrue((run_dir / "restore-report.md").is_file())

    def test_restore_edit_conflict_keeps_user_change_and_restores_other_items(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            target, owned = self.make_target(root)
            server_cfg = target / "server.cfg"
            server_cfg.write_text("ensure hgadmin\n", encoding="utf-8")
            plan = core.build_plan(target)
            run_dir, _, reports = core.clean_target(plan, root / "quarantine")

            server_cfg.write_text("ensure user_resource\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "Edited file changed after clean"):
                core.restore_report(reports[0])

            payload = json.loads(
                (run_dir / "restore-report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(payload["status"], "restore-conflict")
            self.assertEqual(payload["conflict_operations"], 1)
            self.assertGreaterEqual(payload["successful_operations"], 1)
            self.assertEqual(
                server_cfg.read_text(encoding="utf-8"), "ensure user_resource\n"
            )
            self.assertTrue(owned.is_dir())

    def test_mixed_restore_failure_takes_priority_over_conflict(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            target = root / "server-data"
            target.mkdir()
            run_dir = root / "quarantine" / "run"
            run_dir.mkdir(parents=True)
            edit_path = target / "server.cfg"
            edit_path.write_text("current\n", encoding="utf-8")
            move_source = target / "conflict-resource"
            move_source.mkdir()
            move_destination = run_dir / "resources" / "conflict-resource"
            move_destination.mkdir(parents=True)
            report = run_dir / "run-report.json"
            report.write_text(json.dumps({
                "tool": "fivem-xiaoha-cleaner",
                "version": core.VERSION,
                "operation": "clean",
                "status": "cleaned",
                "target": str(target),
                "operations": [
                    {
                        "type": "move",
                        "kind": "resource",
                        "source": str(move_source),
                        "destination": str(move_destination),
                    },
                    {
                        "type": "edit",
                        "kind": "config",
                        "path": str(edit_path),
                        "backup": str(run_dir / "backups" / "missing.cfg"),
                    },
                ],
            }), encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "Restore completed with errors"):
                core.restore_report(report)
            payload = json.loads(
                (run_dir / "restore-report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(payload["status"], "restore-failed")
            self.assertEqual(payload["failed_operations"], 1)
            self.assertEqual(payload["conflict_operations"], 1)

    def test_incomplete_rollback_restore_uses_only_pending_operations(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            target, owned = self.make_target(root)
            (target / "server.cfg").write_text("ensure hgadmin\n", encoding="utf-8")
            plan = core.build_plan(target)

            def fail_with_conflict(*_args, **_kwargs):
                owned.mkdir(parents=True)
                (owned / "user-created.txt").write_text("remove me", encoding="utf-8")
                raise RuntimeError("edit boom")

            with mock.patch.object(
                core, "backup_and_edit", side_effect=fail_with_conflict
            ):
                with self.assertRaises(RuntimeError):
                    core.clean_target(plan, root / "quarantine")
            report = next((root / "quarantine").rglob("run-report.json"))
            shutil.rmtree(str(owned))

            restore_path, result = core.restore_report(report)
            self.assertEqual(result["status"], "restored")
            self.assertEqual(result["operations"], 1)
            self.assertTrue(restore_path.is_file())
            self.assertTrue((owned / "fxmanifest.lua").is_file())

    def test_invalid_quarantine_root_writes_safe_setup_report_outside_target(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            target, owned = self.make_target(root)
            invalid_root = target / "reports-inside-target"
            code, stdout, _ = self.run_auto([
                "clean", str(target), "--yes",
                "--quarantine-root", str(invalid_root),
            ])
            self.assertEqual(code, 1)
            self.assertIn("Quarantine/report:", stdout)
            reports = list((root / "_xiaoha_quarantine").rglob("run-report.json"))
            self.assertEqual(len(reports), 1)
            payload = json.loads(reports[0].read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "failed-setup")
            self.assertFalse(invalid_root.exists())
            self.assertTrue(owned.is_dir())

    def test_forged_root_target_report_is_rejected_before_restore(self):
        with tempfile.TemporaryDirectory() as temp_text:
            run_dir = Path(temp_text)
            report = run_dir / "run-report.json"
            report.write_text(json.dumps({
                "tool": "fivem-xiaoha-cleaner",
                "version": core.VERSION,
                "operation": "clean",
                "status": "cleaned",
                "target": str(run_dir.anchor),
                "operations": [{
                    "type": "edit",
                    "kind": "config",
                    "path": str(Path(run_dir.anchor) / "forged.cfg"),
                    "backup": str(run_dir / "backup.cfg"),
                }],
            }), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "existing non-root directory"):
                core.restore_report(report)
            payload = json.loads(
                (run_dir / "restore-report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(payload["status"], "restore-failed-validation")
            self.assertEqual(payload["operation_results"], [])

    def test_standalone_sql_failure_has_sanitized_report(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            sql_file = root / "cleanup_database.sql"
            sql_file.write_text("SELECT 1;\n", encoding="utf-8")
            with mock.patch.object(
                core, "apply_sql_file",
                side_effect=RuntimeError(
                    "client echoed do-not-leak MYSQL_PWD=do-not-leak"
                ),
            ):
                code, stdout, stderr = self.run_auto([
                    "apply-sql", str(sql_file),
                    "--mysql-uri", "mysql://tester:do-not-leak@localhost/testdb",
                    "--mysql-command", sys.executable,
                    "--yes-drop-tables",
                ])
            self.assertEqual(code, 1)
            report = next(root.rglob("database-report.json"))
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "database-failed")
            self.assertTrue(payload["terminal"])
            self.assertTrue(payload["database_partial_changes_possible"])
            self.assertNotIn("do-not-leak", report.read_text(encoding="utf-8"))
            self.assertNotIn("do-not-leak", stdout)
            self.assertNotIn("do-not-leak", stderr)
            expected_hash = core.sha256_bytes(sql_file.read_bytes())
            self.assertEqual(payload["database_execution"]["sql_sha256"], expected_hash)
            self.assertEqual(payload["operations"][0]["sql_sha256"], expected_hash)

    def test_auto_config_failure_writes_clean_setup_report(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            target, _ = self.make_target(root)
            quarantine = root / "quarantine"
            code, stdout, _ = self.run_auto([
                "clean", str(target), "--yes",
                "--quarantine-root", str(quarantine),
                "--apply-sql", "--yes-drop-tables",
            ])
            self.assertEqual(code, 1)
            self.assertIn("Quarantine/report:", stdout)
            report = next(quarantine.rglob("run-report.json"))
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "failed-setup")
            self.assertEqual(payload["phase"], "setup")
            self.assertTrue(payload["terminal"])
            self.assertFalse(payload["partial_changes_possible"])


if __name__ == "__main__":
    unittest.main()

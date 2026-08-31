# -*- coding: utf-8 -*-

import datetime
import tempfile
import unittest
from pathlib import Path

import XiaohaCleanerGui as gui
import xiaoha_cleaner as core


class GuiContractTest(unittest.TestCase):
    def test_executable_build_embeds_per_monitor_v2_manifest(self):
        build_script = (
            Path(__file__).absolute().parent.parent / "tools" / "Build-Executable.ps1"
        ).read_text(encoding="utf-8-sig")
        self.assertIn("PerMonitorV2, PerMonitor", build_script)
        self.assertIn("--manifest", build_script)

    def test_dpi_math_matches_windows_display_scaling(self):
        self.assertEqual(gui.logical_pixels(940, 96), 940)
        self.assertEqual(gui.logical_pixels(940, 144), 1410)
        self.assertEqual(gui.logical_pixels(720, 192), 1440)
        self.assertAlmostEqual(gui.tk_scaling_for_dpi(96), 96.0 / 72.0)
        self.assertAlmostEqual(gui.tk_scaling_for_dpi(144), 2.0)

    def test_console_encoding_configuration_is_safe_without_reconfigure(self):
        class MinimalStream(object):
            pass

        original_stdout = gui.sys.stdout
        original_stderr = gui.sys.stderr
        try:
            gui.sys.stdout = MinimalStream()
            gui.sys.stderr = MinimalStream()
            import importlib.util
            launcher_path = Path(__file__).absolute().parent.parent / "xiaoha-cleaner.py"
            spec = importlib.util.spec_from_file_location("xiaoha_public_launcher", str(launcher_path))
            launcher = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(launcher)
            launcher.configure_console_encoding()
        finally:
            gui.sys.stdout = original_stdout
            gui.sys.stderr = original_stderr

    def test_source_and_frozen_cli_commands_preserve_arguments(self):
        arguments = ["scan", r"D:\FiveM Server\resources", "--output", r"D:\报告"]
        source = gui.cli_command(
            arguments,
            executable=r"C:\Python\python.exe",
            frozen=False,
            launcher_path=r"C:\Cleaner\xiaoha-cleaner.py",
        )
        frozen = gui.cli_command(
            arguments,
            executable=r"C:\Cleaner\xiaoha-cleaner.exe",
            frozen=True,
        )
        self.assertEqual(source[:2], [r"C:\Python\python.exe", r"C:\Cleaner\xiaoha-cleaner.py"])
        self.assertEqual(source[2:], arguments)
        self.assertEqual(frozen, [r"C:\Cleaner\xiaoha-cleaner.exe"] + arguments)

    def test_unique_output_directory_uses_persistent_root(self):
        fixed = datetime.datetime(2026, 8, 31, 12, 34, 56, 789000)
        path = gui.unique_output_directory(
            "scan",
            base=Path(r"C:\Users\Tester\AppData\Local\XiaohaCleaner\reports"),
            now=fixed,
            token="abc12345",
        )
        self.assertEqual(path.name, "scan-20260831-123456-789-abc12345")
        self.assertEqual(path.parent.name, "reports")

    def test_report_paths_are_recovered_from_cli_output(self):
        scan = gui.extract_report_path("JSON report: D:\\reports\\scan-report.json", "scan")
        clean = gui.extract_report_path("Quarantine/report: D:\\quarantine\\run-1", "clean")
        restore = gui.extract_report_path("Restore report: D:\\quarantine\\restore-report.json", "restore")
        self.assertEqual(str(scan), r"D:\reports\scan-report.json")
        self.assertEqual(str(clean), r"D:\quarantine\run-1\run-report.json")
        self.assertEqual(str(restore), r"D:\quarantine\restore-report.json")

    def test_target_validation_rejects_program_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.assertIn("程序自身目录", gui.target_validation_error(temp_dir, app_dir=temp_dir))

    def test_core_default_reports_do_not_use_script_directory(self):
        root = core.default_report_root()
        self.assertEqual(root.name, "reports")
        self.assertEqual(root.parent.name, "XiaohaCleaner")
        self.assertNotEqual(root, Path(core.__file__).absolute().parent / "reports")


if __name__ == "__main__":
    unittest.main()

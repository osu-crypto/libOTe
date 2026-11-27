"""Fast CPU-only checks for the CUDA runner's process ownership.

Run directly with Python; no CUDA device or third-party test package is needed.
"""
import argparse
import ctypes
import os
from pathlib import Path
import sys
import tempfile
import unittest

from cuda_test_process import (all_selected_tests_passed, positive_seconds, run_bounded,
                               sanitizer_reports_no_errors_or_leaks)


def process_running(pid):
    if os.name == "nt":
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
        if not handle:
            error = ctypes.get_last_error()
            if error == 87:  # ERROR_INVALID_PARAMETER: PID no longer exists.
                return False
            raise ctypes.WinError(error)
        try:
            result = kernel.WaitForSingleObject(handle, 0)
            if result == 258:  # WAIT_TIMEOUT
                return True
            if result != 0:  # WAIT_OBJECT_0
                raise ctypes.WinError(ctypes.get_last_error())
            return False
        finally:
            kernel.CloseHandle(handle)
    try:
        # A killed orphan can briefly await reaping by init; it executes no work.
        stat = Path(f"/proc/{pid}/stat").read_text()
        return stat[stat.rfind(")") + 2] != "Z"
    except FileNotFoundError:
        return False


class ProcessOwnershipTests(unittest.TestCase):
    def test_selection_summary_requires_every_test(self):
        self.assertTrue(all_selected_tests_passed("\x1b[32m    All Passed (2)\n", 2))
        for output in ("All Passed (0)", "All Passed (-1)", "All Passed (1)", "Passed (2)",
                       "All Passed (2)\nAll Passed (1)",
                       "All Passed (2)\n skipped (1)", "Skipped - unavailable\nAll Passed (2)"):
            self.assertFalse(all_selected_tests_passed(output, 2))
        self.assertFalse(all_selected_tests_passed("All Passed (0)", 0))

    def test_every_sanitizer_summary_must_be_clean(self):
        leaks = "========= LEAK SUMMARY: 0 bytes leaked in 0 allocations\n"
        errors = "========= ERROR SUMMARY: 0 errors\n"
        self.assertTrue(sanitizer_reports_no_errors_or_leaks(leaks + errors))
        self.assertFalse(sanitizer_reports_no_errors_or_leaks(errors))
        self.assertFalse(sanitizer_reports_no_errors_or_leaks(leaks))
        for summary in ("LEAK SUMMARY: 8 bytes leaked in 1 allocations", "ERROR SUMMARY: 1 error",
                        "LEAK SUMMARY: -1 bytes leaked in 0 allocations", "ERROR SUMMARY: -1 errors"):
            self.assertFalse(sanitizer_reports_no_errors_or_leaks(leaks + errors + summary))

    def test_time_budget_must_be_positive_seconds(self):
        self.assertEqual(positive_seconds("90"), 90)
        for value in ("0", "-1", "no", "1.5"):
            with self.assertRaises(argparse.ArgumentTypeError):
                positive_seconds(value)

    def test_exit_status_is_preserved(self):
        with tempfile.TemporaryFile(mode="w+") as log:
            for code in (0, 7):
                self.assertEqual(run_bounded(
                    [sys.executable, "-c", f"raise SystemExit({code})"],
                    stdout=log, timeout=5), code)

    def test_timeout_retires_parent_and_child(self):
        base = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory(prefix="runner-check-", dir=base) as directory:
            root = Path(directory).resolve()
            self.assertEqual(root.parent, base)  # Cleanup remains inside this directory.
            marker = root / "pids.txt"
            parent = ("import os,subprocess,sys,time; from pathlib import Path; "
                      "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
                      "Path(sys.argv[1]).write_text(f'{os.getpid()} {child.pid}'); "
                      "time.sleep(60)")
            with tempfile.TemporaryFile(mode="w+") as log:
                self.assertEqual(run_bounded(
                    [sys.executable, "-c", parent, str(marker)], stdout=log, timeout=2), 124)
                log.seek(0)
                self.assertIn("process tree terminated", log.read())
            for pid in map(int, marker.read_text().split()):
                self.assertFalse(process_running(pid), f"process {pid} outlived the runner")


if __name__ == "__main__":
    unittest.main()

"""Fast CPU-only checks for the CUDA runner's process ownership.

Run directly with Python; no CUDA device or third-party test package is needed.
"""
import ctypes
import os
from pathlib import Path
import sys
import tempfile
import unittest

from cuda_test_process import run_bounded


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

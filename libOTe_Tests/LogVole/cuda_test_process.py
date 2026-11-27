"""Run a bounded test command; retire its process tree on timeout or interruption."""
import argparse
import os
import re
import signal
import subprocess


def positive_seconds(value):
    try:
        seconds = int(value)
    except ValueError:
        seconds = 0
    if seconds <= 0:
        raise argparse.ArgumentTypeError("expected a positive number of seconds")
    return seconds


def all_selected_tests_passed(output, expected):
    summaries = re.findall(r"All Passed \((-?\d+)\)", output)
    return (expected > 0 and summaries == [str(expected)]
            and not re.search(r"skipped (?:\(|-)", output, re.IGNORECASE))


def sanitizer_reports_no_errors_or_leaks(output):
    leaks = re.findall(r"LEAK SUMMARY:[ \t]*([^\r\n]*)", output)
    errors = re.findall(r"ERROR SUMMARY:[ \t]*([^\r\n]*)", output)
    return bool(leaks and errors
                and all(summary.strip() == "0 bytes leaked in 0 allocations" for summary in leaks)
                and all(summary.strip() == "0 errors" for summary in errors))


def _kill_tree(process):
    try:
        if os.name == "nt":
            # Killing the parent first loses the ancestry needed to retire
            # Compute Sanitizer's instrumented child processes.
            result = subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW, check=False)
            if result.returncode and process.poll() is None:
                raise RuntimeError("Could not terminate the test process tree")
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)


def run_bounded(command, *, stdout, timeout, env=None):
    options = dict(stdout=stdout, stderr=subprocess.STDOUT, env=env)
    if os.name == "nt":
        options["creationflags"] = subprocess.CREATE_NO_WINDOW
    else:
        # A dedicated process group limits cleanup to this command's children.
        options["start_new_session"] = True
    process = subprocess.Popen(command, **options)
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(process)
        print("Test time limit exceeded; process tree terminated.",
              file=stdout, flush=True)
        return 124
    except BaseException:
        _kill_tree(process)
        raise

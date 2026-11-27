"""Verify GPU A/B runner behavior with no GPU or frontend processes."""

import argparse
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import run_gpu_ab as runner


FOOTER = (
    "LogVole local n:\x1b[32m    16\x1b[0m pbits:55 p:18014398509481993 "
    "online-bytes:553 ||   220 ms\x1b[0m\n"
)


class RunnerTests(unittest.TestCase):
    def test_footer(self):
        self.assertEqual(runner.parse_footer(FOOTER, 16), {
            "n": 16, "pbits": 55, "prime": 18014398509481993,
            "online_bytes": 553, "frontend_ms": 220,
        })
        invalid = (
            "", FOOTER + FOOTER, FOOTER.replace("220 ms", "oops ms"),
            FOOTER.replace("pbits:55", "pbits:56"),
        )
        for footer in invalid:
            with self.subTest(footer=footer), self.assertRaises(ValueError):
                runner.parse_footer(footer, 16)
        with self.assertRaises(ValueError):
            runner.parse_footer(FOOTER, 32)

    def test_order(self):
        self.assertEqual(list(runner.trial_order(2)), [
            "baseline", "candidate", "candidate", "baseline",
            "candidate", "baseline", "baseline", "candidate",
        ])

    def test_lock(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "gpu-benchmark.lock"
            with self.assertRaises(ValueError), runner.benchmark_lock(path):
                with self.assertRaises(RuntimeError), runner.benchmark_lock(path):
                    pass
                self.assertTrue(path.is_file())
                raise ValueError("interrupted comparison")
            self.assertFalse(path.exists())

    def test_failure_and_summary(self):
        with tempfile.TemporaryDirectory() as temp:
            cases = (
                (0, FOOTER, 0), (57, FOOTER, 57), (124, "", 124), (0, "", 1),
            )
            for status, footer, expected_exit in cases:
                with self.subTest(status=status, expected_exit=expected_exit):
                    args = argparse.Namespace(
                        output_dir=Path(temp) / f"{status}-{expected_exit}", mode="golden",
                        baseline=Path("A"), candidate=Path("B"),
                        baseline_revision="a", candidate_revision="b",
                        compiler="compiler", cuda_version="cuda", cuda_arch="arch",
                        n=16, threads=1, warmup_blocks=1, blocks=1, timeout=1,
                    )

                    def capture(command, path, timeout):
                        if command[0] == "nvidia-smi":
                            return 0, 1.0
                        path.write_text(footer, encoding="utf-8")
                        return status, 1.0

                    with patch.object(runner, "capture", capture):
                        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                            self.assertEqual(runner.run_comparison(args), expected_exit)

                    report = json.loads((args.output_dir / "report.json").read_text(encoding="utf-8"))
                    self.assertTrue(report["smoke"])
                    self.assertTrue(report["workload_note"])
                    self.assertIn("relation verification", report["measurement_scope"])
                    self.assertEqual(report["complete"], expected_exit == 0)
                    self.assertEqual(len(report["trials"]), 1 if expected_exit else 8)
                    if expected_exit:
                        self.assertEqual(report["trials"][0]["returncode"], status)
                        self.assertEqual(report["summaries"], {})
                    else:
                        for label in ("baseline", "candidate"):
                            self.assertEqual(report["summaries"]["golden"][label], {
                                "samples": 2, "median_frontend_ms": 220,
                                "min_frontend_ms": 220, "max_frontend_ms": 220,
                            })


if __name__ == "__main__":
    unittest.main()

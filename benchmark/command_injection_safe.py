"""Benchmark: command injection — SAFE (no user input to shell)."""

import subprocess


def run_fixed():
    subprocess.run(["ls", "-la"], shell=False)


def run_with_list():
    args = ["echo", "hello"]
    subprocess.call(args, shell=False)

"""Benchmark: command injection — VULNERABLE (user input to shell)."""

import os
import subprocess


def run_user_cmd():
    user_input = input("Enter command: ")
    os.system(user_input)


def run_with_subprocess():
    cmd = input("Command: ")
    subprocess.call(cmd, shell=True)

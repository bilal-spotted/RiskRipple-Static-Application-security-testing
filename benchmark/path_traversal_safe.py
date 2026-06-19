"""Benchmark: path traversal — SAFE (fixed path, no user in path)."""

import os


def read_file(filename):
    base = "/data/safe/"
    full = os.path.normpath(os.path.join(base, filename))
    if not full.startswith(base):
        return None
    with open(full) as f:
        return f.read()

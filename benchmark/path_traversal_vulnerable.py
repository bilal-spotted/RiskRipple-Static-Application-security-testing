"""Benchmark: path traversal — VULNERABLE (user input in path)."""


def read_file(filename):
    with open(filename) as f:
        return f.read()


def load_user_file(user_input):
    path = "/data/" + user_input
    return read_file(path)

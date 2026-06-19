"""Benchmark: weak crypto — SAFE."""

import hashlib
import secrets


def hash_password(pwd):
    return hashlib.sha256(pwd.encode()).hexdigest()


def checksum(data):
    return hashlib.sha256(data).hexdigest()


def gen_token():
    return secrets.token_urlsafe(32)

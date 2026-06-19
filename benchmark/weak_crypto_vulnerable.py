"""Benchmark: weak crypto — VULNERABLE."""

import hashlib
import random


def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()


def checksum(data):
    return hashlib.sha1(data).hexdigest()


def gen_token():
    return str(random.randint(0, 10**9))

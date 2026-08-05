"""Benchmark: secret exposure — VULNERABLE (hardcoded secrets)."""

API_KEY = "sk-1234567890abcdef"
PASSWORD = "admin123"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"


def connect():
    return API_KEY

"""Benchmark: secret exposure — SAFE (env/config)."""

import os


def get_api_key():
    return os.environ.get("API_KEY", "")


def get_password():
    from config import settings

    return getattr(settings, "PASSWORD", "")

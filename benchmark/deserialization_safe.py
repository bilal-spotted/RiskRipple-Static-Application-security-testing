"""Benchmark: unsafe deserialization — SAFE."""

import json

import yaml


def load_config(data):
    return json.loads(data)


def parse_yaml(text):
    return yaml.safe_load(text)

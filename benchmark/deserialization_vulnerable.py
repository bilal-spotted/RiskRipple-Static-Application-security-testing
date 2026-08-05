"""Benchmark: unsafe deserialization — VULNERABLE."""

import pickle

import yaml


def load_config(data):
    return pickle.loads(data)


def parse_yaml(text):
    return yaml.load(text)

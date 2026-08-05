import os
import pickle
from urllib import request

import yaml


def run(cmd):
    os.system(cmd)


def load_data(data):
    return pickle.loads(data)


def parse_yaml(text):
    return yaml.load(text)


def unsafe_eval(x):
    eval(x)


def taint_demo_command():
    """Taint flow: input() -> os.system (command injection)."""
    user = input()
    os.system(user)


def taint_demo_sql():
    """Taint flow: request.args -> cursor.execute (SQL injection)."""
    name = request.args["name"]
    query = "SELECT * FROM users WHERE name=" + name
    cursor.execute(query)

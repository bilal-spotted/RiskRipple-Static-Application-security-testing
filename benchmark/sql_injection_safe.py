"""Benchmark: SQL injection — SAFE (parameterized)."""


class Cursor:
    def execute(self, sql, params=None):
        pass


def get_user(cursor, name):
    cursor.execute("SELECT * FROM users WHERE name=?", (name,))


def search(cursor, term):
    cursor.execute("SELECT * FROM items WHERE id=%s", (term,))

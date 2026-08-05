"""Benchmark: SQL injection — VULNERABLE (string concatenation)."""


# Simulated DB cursor for demo
class Cursor:
    def execute(self, sql):
        pass


def get_user(cursor, name):
    query = "SELECT * FROM users WHERE name='" + name + "'"
    cursor.execute(query)


def search(cursor, term):
    cursor.execute("SELECT * FROM items WHERE id=" + term)

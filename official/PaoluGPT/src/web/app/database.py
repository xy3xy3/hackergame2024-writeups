import sqlite3

def execute_query(s: str, fetch_all: bool = False):
    conn = sqlite3.connect("file:/tmp/data.db?mode=ro", uri=True)
    cur = conn.cursor()
    res = cur.execute(s)
    if fetch_all:
        return res.fetchall()
    else:
        return res.fetchone()

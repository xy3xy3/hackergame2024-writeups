#!/usr/bin/env python3
import sqlite3
import uuid
from pathlib import Path
import json
import random
import os

if os.environ.get("LOCAL_DEBUGGING"):
    flag1 = "submit your payload to get real flag1"
    flag2 = "submit your payload to get real flag2"
else:
    with open("/flag1") as f:
        flag1 = f.read()
    with open("/flag2") as f:
        flag2 = f.read()

corpus = []
with open("output.jsonl") as f:
    for l in f:
        corpus.append(json.loads(l))

# randomly select 1000
SIZE = 1000
selected = random.sample(corpus, SIZE)
del corpus
uuids = {str(uuid.uuid4()) for _ in range(len(selected))}
while len(uuids) < SIZE:
    uuids.add(str(uuid.uuid4()))
uuids = list(uuids)

flags_idx = random.sample(range(10, 991), 2)

Path("/tmp/data.db").unlink(missing_ok=True)

conn = sqlite3.Connection("/tmp/data.db")
cur = conn.cursor()
cur.execute("create table messages (id text primary key, title text, contents text, shown boolean)")
for idx, item in enumerate(selected):
    if idx not in flags_idx:
        cur.execute("insert into messages values (?, ?, ?, true)", (uuids[idx], item["input"], item["output"]))
    if idx == flags_idx[0]:
        item["output"] += "\n" * 114514 + flag1
        cur.execute("insert into messages values (?, ?, ?, true)", (uuids[idx], item["input"], item["output"]))
    elif idx == flags_idx[1]:
        item["output"] += "\n" * 191981 + flag2
        cur.execute("insert into messages values (?, ?, ?, false)", (uuids[idx], item["input"], item["output"]))

conn.commit()

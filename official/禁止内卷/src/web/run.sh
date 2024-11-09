#!/bin/bash -e

cp -r /web /tmp/web
cd /tmp/web
python3 prerun.py
exec flask run --reload --host 0

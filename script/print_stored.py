#!/usr/bin/env python3
import base64
import json
import os
import sys


def print_store(file):
    _json_txt = open(file, "r").read()
    _data = json.loads(_json_txt)
    p = os.path.split(file)
    print(20*"=", " ", base64.b64decode(p[-1]), " ", 20*"=")
    print(json.dumps(_data, indent=2))

if __name__ == "__main__":
    file = sys.argv[1]
    print_store(file)

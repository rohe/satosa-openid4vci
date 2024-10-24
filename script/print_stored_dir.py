#!/usr/bin/env python3
import base64
import json
import os
import sys


def print_stored(file):
    _json_txt = open(file, "r").read()
    _data = json.loads(_json_txt)
    p = os.path.split(file)
    print(20*"=", " ", base64.b64decode(p[-1]), f" {p[-1]}", 20*"=")
    print(json.dumps(_data, indent=2))

def storage_names(directory):
    for f in os.listdir(directory):
        if f.endswith('.lock'):
            continue
        else:
            fname = os.path.join(directory, f)
            print_stored(fname)

if __name__ == "__main__":
    dir = sys.argv[1]
    storage_names(dir)
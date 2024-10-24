#!/usr/bin/env python3
import base64
import os
import sys


def storage_names(directory):
    for fname in os.listdir(directory):
        if fname.endswith('.lock'):
            continue
        else:
            print(base64.b64decode(fname))

if __name__ == "__main__":
    dir = sys.argv[1]
    storage_names(dir)
#!/usr/bin/env python3
import sys
import json
import yaml

fp=open(sys.argv[1],"r")
_dict = json.load(fp)
print(yaml.dump(_dict))
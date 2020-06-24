#!/usr/bin/env python
# coding=utf-8

import json

def load_json(file_path):
    with open(file_path, 'r') as f:
        dict_data = json.load(f)
        f.close()

    return dict_data


def dump_dict_to_file(file_path, dict_data):
    with open(file_path, 'w') as f:
        json.dump(dict_data, f, indent=4)


def deduplication():

    cve_json = load_json(file_path)
    result_json = {}
    for key, value in cve_json.items():
        prj_name = value["prjname"]
        if result_json
        result_json[prj_name] = value



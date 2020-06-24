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

def check_specify_cveno(cve_list, low_count, high_count):
    if len(cve_list) >= low_count and len(cve_list) <= high_count:
        return True

    return False


def select_many_cve(file_path, low_count, high_count):
    many_cve_json = {}
    cve_json = load_json(file_path)
    for key, value in cve_json.items():
        cveno = value["cveno"]
        if check_specify_cveno(cveno, low_count, high_count):
            many_cve_json[key] = value

    dump_dict_to_file('many_cve.json', many_cve_json)


select_many_cve("333.json", 50, 70)


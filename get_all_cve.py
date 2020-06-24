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


def write_list_to_file(file_path, list_data):
    with open(file_path, 'w') as f:
        for line in list_data:
            f.write(line+'\n')


def select_many_cve(file_path):
    all_cve = []
    cve_json = load_json(file_path)
    for key, value in cve_json.items():
        all_cve.extend(value["cveno"])

    print(len(all_cve))

    deduplication_all_cve = list(set(all_cve))
    print(len(deduplication_all_cve))

    write_list_to_file('all_cve.json', deduplication_all_cve)


select_many_cve("test.json")

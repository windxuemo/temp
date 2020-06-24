#!/usr/bin/env python
# coding=utf-8

import json

def load_json(file_path):
    with open(file_path, 'r') as f:
        dict_data = json.load(f)
        f.close()

    return dict_data

def print_cve_prj_name(file_path):
    cve_json = load_json(file_path)
    cve_prj_name_v = []
    cve_prj_name = []
    cve_no = []

    i = 0
    for key, value in cve_json.items():
        i = i +1
        cve_prj_name_v.append(key)
        prj_name = value["prjname"]
        cve_prj_name.append(prj_name)

        cve_no.extend(value["cveno"])


    print("PRJ count:")
    print("    Before deduplication: %d" %i)


    print("    After deduplication: %d" %(len(list(set(cve_prj_name)))))


    print("CVE count:")
    print("    Before deduplication: %d" %(len(cve_no)))
    print("    After deduplication: %d" %(len(list(set(cve_no)))))



print_cve_prj_name("test.json")

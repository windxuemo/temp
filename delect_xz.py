#!/usr/bin/env python
# coding=utf-8

import os
import json
import urllib.request

def load_json(file_path):
    with open(file_path, 'r') as f:
        dict_data = json.load(f)
        f.close()

    return dict_data


def dump_dict_to_file(file_path, dict_data):
    with open(file_path, 'w') as f:
        json.dump(dict_data, f, indent=4)



def check_source(url):

    file_name = os.path.basename(url)
    ext = os.path.splitext(file_name)[-1]
    if 'xz' in ext:
        return True

    return False

def scan_source(file_path):
    bin_prj = {}

    cve_json = load_json(file_path)
    for key, value in cve_json.items():
        srclink = value["srclink"]
        if check_source(srclink) is True:
            continue

        bin_prj[key] = value


    dump_dict_to_file('10-30_cve_good_srclink_bin_prj.json', bin_prj)


scan_source('10-30_cve_good_srclink_prj.json')

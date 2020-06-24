#!/usr/bin/env python
# coding=utf-8

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



def check_200(url):
    try:
        resp = urllib.request.urlopen(url, timeout=10)
    except Exception as e:
        print("bad %s" %(url))
        return False
    else:
        print(url, resp.getcode())
        resp.close()
        return True

def scan_good_srclink(file_path):
    good_srclink_prj = {}
    cve_json = load_json(file_path)
    for key, value in cve_json.items():
        srclink = value["srclink"]
        if check_200(srclink) is False:
            continue
        good_srclink_prj[key]  = value

    dump_dict_to_file('50-70_cve_good_srclink_prj.json', good_srclink_prj)


scan_good_srclink("50-70_cve.json")



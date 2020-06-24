#!/usr/bin/env python
# coding=utf-8

import requests

url = "https://www.zhihu.com/finds"

response= requests.get(url)
status= response.status_code
if status != 404:
    print(url)
    print(status)

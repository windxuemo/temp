#!/usr/bin/env python
# coding=utf-8

import urllib2

req = urllib2.Request('http://www.zhihu.com/finsjlsgf')
try:
    resp = urllib2.urlopen(req)
except urllib2.HTTPError as e:
    if e.code == 404:
        # do something...
        print("404")
    else:
        print(e.code)
except urllib2.URLError as e:
    print("error")
else:
    # 200
    body = resp.read()
    print("good")

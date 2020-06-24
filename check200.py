#!/usr/bin/env python
# coding=utf-8
import time
import urllib.request
from threading import Thread

class GetUrlThread(Thread):
    def __init__(self, url):
        self.url = url
        super(GetUrlThread, self).__init__()

    def run(self):
        resp = urllib.request.urlopen(self.url)
        print(self.url, resp.getcode())

def get_responses():
    # urls = ['https://dev.to', 'https://www.ebay.com', 'https://www.github.com']
    urls = ['http://widehat.opensuse.org/opensuse/update/leap/15.0/oss/x86_64/texlive-2017.20170520-lp150.9.3.1.x86_64.rpm', 'http://www.zhihu.com/find']
    start = time.time()
    threads = []
    for url in urls:
        t = GetUrlThread(url)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    print("Elapsed time: %s" % (time.time()-start))

get_responses()


test = urllib.request.urlopen("https://www.zhihu.com/fsind")
print(test.getcode())

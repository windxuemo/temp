# -*- coding: utf-8 -*-

import socket
target_host = '127.0.0.1'
target_port = 8080
#建立socket对象,建立包含AF_INET,和SOCK_STREAM参数的socket对象。AF_INET参数锁门我们使用IPV4地址，SOCK_STREAM说明这是一个TCP客户端
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#连接客户端
client.connect((target_host, target_port))
 
#send some data
client.send('dddd'.encode())
 
#get some data
# response = client.recv(4096)


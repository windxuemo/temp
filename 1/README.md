# analyse_template
## 模板介绍
- template1.py(测试testserver/server) 在recvfrom系统调用时，进行污点标记，然后符号化，在程序结束的时候，会对污点所经过的分支进行约束求解，得出探索出的新结果(可以到达另一个新分支)
- template2.py(测试tftpserverp/tftpserver) 和template1.py 功能一样。区别是 在下一次调用recvfrom的时候，分析上一轮的约束，得出新的结果（因为有些程序，客户端无法控制被测程序结束，可借鉴此方法）
- template3.py(测试testserver/server) 分析程序找到合适的位置，对recv后的接受地址进行符号化，并打快照，然后设置 “目的地址”（想要到达的地址）， 然后设置 证明失败的地址（当程序执行经过此地址，并且没有经过 “目的地址”，则证明输入的数据无法抵达目的地址），当失败后，约束求解得出新结果，恢复到快照位置，将新结果写到内存，然后继续求解，直到 到达 “目的地址”


## 问题
- 由于测试例子较为简单，需要找其它程序测试
- 其中tftpserver在测试的时候只对tftpserver此模块进行了符号执行（在没有过滤libc库的时候，triton 发生crash，经测试，只要triton开启符号执行就crash，不是使用过程中 将新结果写入内存发生的问题）
- 从测试过程中，发现triton对被测程序的普遍适用性太低，易crash（问题不好排查）

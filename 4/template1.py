#!/usr/bin/env python
## -*- coding: utf-8 -*-

from triton  import *
from pintool import *

import pdb


# 标记污染长度
TAINTING_SIZE = 10

# recvfrom 参数信息
RECV_INFO = None

RESULT_FILE = '/tmp/result.txt'


Triton = getTritonContext()

def append_file(data):
    with open(RESULT_FILE, 'a') as f:
        f.write(data + '\n')

def mycb(inst):
    if inst.isTainted():
        print(inst)
        append_file(str(inst))
    return


def my_callback_syscall_entry(threadId, std):

    global RECV_INFO
    # print('entry: %d' % getSyscallNumber(std))

    # 如果系统调用号为45，则进行处理
    if getSyscallNumber(std) == SYSCALL64.RECVFROM:

        # arg0 = getSyscallArgument(std, 0)
        arg1 = getSyscallArgument(std, 1)
        arg2 = getSyscallArgument(std, 2)

        # recv 函数的 参数1 是存放数据的地址，参数2是长度  
        RECV_INFO = {'buff': arg1, 'size': arg2}




def my_callback_syscall_exit(threadId, std):

    global RECV_INFO

    if RECV_INFO is not None:
        buff = RECV_INFO['buff']

        offset = 0
        # 根据 污染长度 来对 recv函数接受数据的地址开始标记为污点
        while offset != TAINTING_SIZE:
            # Triton.taintMemory(buff + offset)
            concreteValue = getCurrentMemoryValue(buff + offset)
            Triton.setConcreteMemoryValue(buff + offset, concreteValue)
            Triton.symbolizeMemory(MemoryAccess(buff + offset, CPUSIZE.BYTE))
            offset += 1

        taint_addr = '[+] %02d bytes tainted from the (%#x) pointer' %(offset, buff)
        append_file(taint_addr)

        RECV_INFO = None



# Constraint solving
def taint_analyse():

    pco = Triton.getPathConstraints()
    # astCtxt = Triton.getAstContext()
    for pc in pco:
        # If it is not a direct jump
        # 多分支
        if pc.isMultipleBranches():
            brs = pc.getBranchConstraints()
            for br in  brs:
                # 当前执行路径经过的分支
                if br['isTaken'] == True:
                    models = Triton.getModel(br['constraint'])
                    passed_branch = 'Branches passed this time: %s' % (models)
                    append_file(passed_branch)
                    print('Branches passed this time: %s' % (models))

                # 经过翻转可以到达的新分支
                if br['isTaken'] == False:
                    models = Triton.getModel(br['constraint'])
                    flipping_branch = 'Branches accessible by flipping: %s' % (models)
                    append_file(flipping_branch)
                    print('Branches accessible by flipping: %s' % (models))

    return

def fini():
    taint_analyse()


if __name__ == '__main__':

    # 从main函数开始插桩
    startAnalysisFromSymbol('main')

    Triton.setMode(MODE.ALIGNED_MEMORY, True)

    # 添加白名单，意味着只插桩此模块
    setupImageWhitelist(['server'])

    # Add callback

    # 系统调用函数执行之前的回调函数
    insertCall(my_callback_syscall_entry, INSERT_POINT.SYSCALL_ENTRY)
    # 系统调用函数执行之后的回调函数
    insertCall(my_callback_syscall_exit, INSERT_POINT.SYSCALL_EXIT)
    # 指令级别插桩，每条执行执行前的回调
    insertCall(mycb, INSERT_POINT.BEFORE)

    insertCall(fini,     INSERT_POINT.FINI)

    # Run the instrumentation - Never returns
    runProgram()



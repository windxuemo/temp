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

def appendFile(data):
    with open(RESULT_FILE, 'a') as f:
        f.write(data + '\n')

def writeFile(data):
    with open(RESULT_FILE, 'w') as f:
        f.write(data + '\n')


def callbackSyscallEntry(threadId, std):

    global RECV_INFO
    # print('entry: %d' % getSyscallNumber(std))

    # 如果系统调用号为45，则进行处理
    if getSyscallNumber(std) == SYSCALL64.RECVFROM:

        # arg0 = getSyscallArgument(std, 0)
        arg1 = getSyscallArgument(std, 1)
        arg2 = getSyscallArgument(std, 2)

        # recv 函数的 参数1 是存放数据的地址，参数2是长度  
        RECV_INFO = {'buff': arg1, 'size': arg2}




def callbackSyscallExit(threadId, std):

    global RECV_INFO

    if RECV_INFO is not None:
        buff = RECV_INFO['buff']

        offset = 0
        # 根据 污染长度 来对 recv函数接受数据的地址开始标记为污点
        while offset != TAINTING_SIZE:
            Triton.taintMemory(buff + offset)
            concreteValue = getCurrentMemoryValue(buff + offset)
            Triton.setConcreteMemoryValue(buff + offset, concreteValue)
            Triton.symbolizeMemory(MemoryAccess(buff + offset, CPUSIZE.BYTE))
            offset += 1

        # taint_addr = '[+] %02d bytes tainted from the (%#x) pointer' %(offset, buff)

        RECV_INFO = None



# Constraint solving
def getNewInput():

    pco = Triton.getPathConstraints()
    # astCtxt = Triton.getAstContext()
    branchList=[]
    for pc in pco:
        # If it is not a direct jump
        # 多分支
        branch = {}
        if pc.isMultipleBranches():
            brs = pc.getBranchConstraints()
            for br in  brs:
                # 当前执行路径经过的分支
                branch['srcAddr'] = br['srcAddr']
                if br['isTaken'] == True:
                    models = Triton.getModel(br['constraint'])
                    if models:
                        branch['passedAddr'] = br['dstAddr']
                        passedBranch = 'Branches passed this time: %s' % (models)
                        # appendFile(passedBranch)
                        print('Branches passed this time: %s' % (models))
                    else:
                        branch.clear()
                        continue

                # 经过翻转可以到达的新分支
                if br['isTaken'] == False:
                    models = Triton.getModel(br['constraint'])
                    if models:
                        branch['flippingAddr'] = br['dstAddr']

                        condition = {}
                        for k, v in list(models.items()):
                            print(v.getId())
                            print(v.getValue())
                            condition[v.getId()] = v.getValue()

                        if condition:
                            branch['flippingCondition'] = condition
                        flippingBranch = 'Branches accessible by flipping: %s' % (models)
                        # appendFile(flippingBranch)
                        print('Branches accessible by flipping: %s' % (models))
                    else:
                        branch.clear()
                        continue

            if branch:
                branchList.append(branch)
     
    writeFile(str(branchList))

    return

def fini():
    getNewInput()


if __name__ == '__main__':

    # 从main函数开始插桩
    startAnalysisFromSymbol('main')

    Triton.setMode(MODE.ALIGNED_MEMORY, True)

    # 添加白名单，意味着只插桩此模块
    setupImageWhitelist(['server', 'libc'])

    # Add callback

    # 系统调用函数执行之前的回调函数
    insertCall(callbackSyscallEntry, INSERT_POINT.SYSCALL_ENTRY)
    # 系统调用函数执行之后的回调函数
    insertCall(callbackSyscallExit, INSERT_POINT.SYSCALL_EXIT)
    # 指令级别插桩，每条执行执行前的回调
    # insertCall(mycb, INSERT_POINT.BEFORE)

    insertCall(fini,     INSERT_POINT.FINI)

    # Run the instrumentation - Never returns
    runProgram()



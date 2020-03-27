#!/usr/bin/env python
## -*- coding: utf-8 -*-

from triton  import *
from pintool import *

import pdb


# 标记污染长度
TAINTING_SIZE = 10

# recvfrom 参数信息
RECV_INFO = None

# 当程序循环调用recvfrom的时候，每一次recv后会得到新的路径，在下一轮recv后会求解最新一轮执行的路径约束
IS_NEW_PATH = False
RESULT_FILE = '/tmp/result.txt'


Triton = getTritonContext()

def appendFile(data):
    with open(RESULT_FILE, 'a') as f:
        f.write(data + '\n')

def mycb(inst):
    if inst.isTainted():
        print(inst)
        appendFile(str(inst))
    return

# 将参数标记为污点
def tainting(threadId):
    # pdb.set_trace()
    # argc
    rdi = getCurrentRegisterValue(Triton.registers.rdi)
    # argv
    rsi = getCurrentRegisterValue(Triton.registers.rsi)

    while rdi > 1:
        argv = getCurrentMemoryValue(rsi + ((rdi-1) * CPUSIZE.QWORD), CPUSIZE.QWORD)
        offset = 0
        while offset != TAINTING_SIZE:
            Triton.taintMemory(argv + offset)
            concreteValue = getCurrentMemoryValue(argv + offset)
            Triton.setConcreteMemoryValue(argv + offset, concreteValue)
            Triton.symbolizeMemory(MemoryAccess(argv + offset, CPUSIZE.BYTE))
            offset += 1
        print('[+] %02d bytes tainted from the argv[%d] (%#x) pointer' %(offset, rdi-1, argv))
        rdi -= 1

    return




# Constraint solving
def taintAnalyse():

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
                    passedBranch = 'Branches passed this time: %s' % (models)
                    appendFile(passedBranch)
                    print('Branches passed this time: %s' % (models))

                # 经过翻转可以到达的新分支
                if br['isTaken'] == False:
                    models = Triton.getModel(br['constraint'])
                    flippingBranch = 'Branches accessible by flipping: %s' % (models)
                    appendFile(flippingBranch)
                    print('Branches accessible by flipping: %s' % (models))

    return

def fini():
    taintAnalyse()


if __name__ == '__main__':

    # 从main函数开始插桩
    startAnalysisFromSymbol('main')

    Triton.setMode(MODE.ALIGNED_MEMORY, True)

    # 添加白名单，意味着只插桩此模块
    setupImageWhitelist(['server'])

    # Add callback
    # 指令级别插桩，每条执行执行前的回调
    insertCall(mycb, INSERT_POINT.BEFORE)

    insertCall(fini,     INSERT_POINT.FINI)

    # Run the instrumentation - Never returns
    runProgram()



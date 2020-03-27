#!/usr/bin/env python
## -*- coding: utf-8 -*-

from triton  import *
from pintool import *

import pdb


# 标记污染长度
TAINTING_SIZE = 10
TAINTING_OFFSET = 0

# recvfrom 参数信息
RECV_INFO = None
IS_NEW_PATH = None

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


# 在这里添加条件来控制流程
def cbeforeSymProc(inst):
    global BUFF_ADDR
    global OLD_INPUTS
    global NEW_INPUTS
    global LAST_INPUT

    # 根据需要设置创建快照的地址，可以是在污染刚被标记后的位置
    # if inst.getAddress() == 0x4008e9 and isSnapshotEnabled() == False:
    if inst.getAddress() == 0x400939 and isSnapshotEnabled() == False:
        data = getCurrentMemoryValue(BUFF_ADDR, CPUSIZE.BYTE)
        NEW_INPUTS = list([{BUFF_ADDR:data}])

        # print('[+] Take a snapshot at the prologue of the function')
        takeSnapshot()

    # 设置输入
    if inst.getAddress() == 0x400939:
        seed = NEW_INPUTS[0]
        # print("seed: %s" %(seed))
        setNewInput(seed)
        LAST_INPUT = seed
        OLD_INPUTS += [dict(seed)]
        del NEW_INPUTS[0]
            
	buff = BUFF_ADDR
        data = getCurrentMemoryValue(buff, CPUSIZE.BYTE*4)
        # print('sys_recvfrom, buff data: %x ' %(data))
                        
    
        # 回到快照处
        restoreSnapshot()



def callbackSyscallEntry(threadId, std):

    global RECV_INFO
    global IS_NEW_PATH

    global TAINTING_OFFSET
    print('entry: %d' % getSyscallNumber(std))

    # 如果系统调用号为45，则进行处理
    if getSyscallNumber(std) == SYSCALL64.RECVFROM:
        pdb.set_trace()

        # recv函数接受数据后已经执行过一轮了，在第二次进入调用recv的时候，进行上一轮的污点分析和求解（推荐的方式是程序每次执行后使其正常退出，然后在退出的时候进行分析求解，这里仅提供另一个方式）
        
        if isSnapshotEnabled() == False:
            takeSnapshot()
        if IS_NEW_PATH is True:
            if TAINTING_OFFSET > TAINTING_SIZE:
                exit(0)
            TAINTING_OFFSET = TAINTING_OFFSET + 1
            restoreSnapshot()
            # Reset
            #IS_NEW_PATH = None exit(0) 

        # arg0 = getSyscallArgument(std, 0)
        arg1 = getSyscallArgument(std, 1)
        arg2 = getSyscallArgument(std, 2)

        # recv 函数的 参数1 是存放数据的地址，参数2是长度  
        RECV_INFO = {'buff': arg1, 'size': arg2}




def callbackSyscallExit(threadId, std):

    global RECV_INFO
    global IS_NEW_PATH
    global TAINTING_OFFSET

    if RECV_INFO is not None:
        buff = RECV_INFO['buff']

        offset = 0
        # 根据 污染长度 来对 recv函数接受数据的地址开始标记为污点
        # while offset != TAINTING_SIZE:
        #     Triton.taintMemory(buff + offset)
        #     concreteValue = getCurrentMemoryValue(buff + offset)
        #     Triton.setConcreteMemoryValue(buff + offset, concreteValue)
        #     Triton.symbolizeMemory(MemoryAccess(buff + offset, CPUSIZE.BYTE))
        #     offset += 1

        Triton.taintMemory(buff + TAINTING_OFFSET)
        concreteValue = getCurrentMemoryValue(buff + TAINTING_OFFSET)
        Triton.setConcreteMemoryValue(buff + TAINTING_OFFSET, concreteValue)
        Triton.symbolizeMemory(MemoryAccess(buff + TAINTING_OFFSET, CPUSIZE.BYTE))

        taint_addr = '[+] tainted from the (%#x) pointer' %(buff+TAINTING_OFFSET)
        print(taint_addr)

        RECV_INFO = None
        IS_NEW_PATH = True





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
    insertCall(mycb, INSERT_POINT.BEFORE)


    # Run the instrumentation - Never returns
    runProgram()



#!/usr/bin/env python
## -*- coding: utf-8 -*-

from triton  import *
from pintool import *

import pdb
import os


# recvfrom syscall parameter information
RECV_INFO = None

IS_OK = False

BUFF_ADDR = None

NEW_INPUTS = list()
LAST_INPUT = dict()
OLD_INPUTS = list()

RESULT_FILE = '/tmp/result.txt'

Triton = getTritonContext()


def appendFile(data):
    with open(RESULT_FILE, 'a') as f:
        f.write(data + '\n')


# 设置新的输入
def setNewInput(seed):
    # Clean symbolic state
    Triton.concretizeAllRegister()
    Triton.concretizeAllMemory()
    for address, value in list(seed.items()):
        setCurrentMemoryValue(address, value)
        Triton.taintMemory(address)
        Triton.taintMemory(address+1)
        concreteValue = getCurrentMemoryValue(address)
        Triton.setConcreteMemoryValue(address, concreteValue)
        Triton.symbolizeMemory(MemoryAccess(address, CPUSIZE.BYTE))
        Triton.symbolizeMemory(MemoryAccess(address+1, CPUSIZE.BYTE))

        # data = getCurrentMemoryValue(BUFF_ADDR, CPUSIZE.BYTE*4)
        # print('sys_recvfrom, buff data: %x ' %(data))
    return



# 在这里添加条件来控制流程
def cbeforeSymProc(inst):
    global IS_OK
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
                        
    
    # 设置想要到达的地址位置
    #if inst.getAddress() == 0x400970:
    # if inst.getAddress() == 0x400953:
    if inst.getAddress() == 0x400994:
        # pdb.set_trace()
        IS_OK = True
        appendFile("Successfully arrived !")
        appendFile("Successful input: %s" %(LAST_INPUT))
        exit(0)
    
    # 设置一个地址，在到达这个地址的时候，并且没有到达目的位置，则可以确定此轮输入无法到达目的位置
    # if (inst.getAddress() == 0x400958) and (IS_OK is not True):
    if (inst.getAddress() == 0x40099e) and (IS_OK is not True):
        newInputs = getNewInput()
        # print("inputs: %s" %(newInputs))
        for inputs in newInputs:
            if inputs not in OLD_INPUTS and inputs not in NEW_INPUTS:
                NEW_INPUTS += [dict(inputs)]
                # print('NEW_INPUTS %s' % (NEW_INPUTS))

        appendFile("Failed to arrive !")
        # 回到快照处
        restoreSnapshot()


def callbackSyscallEntry(threadId, std):

    global RECV_INFO
    global BUFF_ADDR

    # 64: System call number of recvfrom is 45
    if getSyscallNumber(std) == SYSCALL64.RECVFROM:
 
        arg0 = getSyscallArgument(std, 0)
        arg1 = getSyscallArgument(std, 1)
        arg2 = getSyscallArgument(std, 2)
	
        RECV_INFO = {'buff': arg1, 'size': arg2}
        BUFF_ADDR = arg1



def callbackSyscallExit(threadId, std):

    global RECV_INFO

    if RECV_INFO is not None:
	buff = RECV_INFO['buff']

        Triton.taintMemory(buff)
        concreteValue = getCurrentMemoryValue(buff)
        Triton.setConcreteMemoryValue(buff, concreteValue)
        Triton.symbolizeMemory(MemoryAccess(buff, CPUSIZE.BYTE))
            

        RECV_INFO = None



def getNewInput(): 

    inputs = list()
    pco = Triton.getPathConstraints()
    astCtxt = Triton.getAstContext()
    previousConstraints = astCtxt.equal(astCtxt.bvtrue(), astCtxt.bvtrue())
    for pc in pco:
        # If it is not a direct jump
        if pc.isMultipleBranches():
            brs = pc.getBranchConstraints()
            for br in  brs:
                if br['isTaken'] == False:
                    models = Triton.getModel(astCtxt.land([previousConstraints, br['constraint']]))
                    if models:
                        seed = dict()
                        # print('Branches accessible by flipping: %s' % (models))

                        for k, v in list(models.items()):
                            symVar = Triton.getSymbolicVariable(k)
                            # 将地址和新的输入添加到seed
                            seed.update({symVar.getOrigin(): v.getValue()})

                        if seed:
                            inputs.append(seed)
        previousConstraints = astCtxt.land([previousConstraints, pc.getTakenPredicate()])

    Triton.clearPathConstraints()

    return inputs






if __name__ == '__main__':

    Triton.setArchitecture(ARCH.X86_64)

    startAnalysisFromSymbol('main')

    Triton.setMode(MODE.ALIGNED_MEMORY, True)
    # setupImageWhitelist(['server', 'libc'])
    setupImageBlacklist(["ld-linux"])

    # Add callback
    insertCall(callbackSyscallEntry, INSERT_POINT.SYSCALL_ENTRY)
    insertCall(callbackSyscallExit, INSERT_POINT.SYSCALL_EXIT)
    insertCall(cbeforeSymProc,    INSERT_POINT.BEFORE_SYMPROC)

    # Run the instrumentation - Never returns
    runProgram()

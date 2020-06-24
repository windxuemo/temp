import sys
import os
import shutil
import logging
import pefile
import pdb


class BitError(Exception):
    pass


def createDir(dirPath):
    if os.path.exists(dirPath) == False:
        os.makedirs(dirPath)

    return dirPath


def getFileType(filePath):
    return os.path.splitext(filePath)[-1]


def checkEXEBit(EXEPath):
    pe = pefile.PE(EXEPath)
    if 267 == pe.OPTIONAL_HEADER.Magic:
        return 32
    elif 523 == pe.OPTIONAL_HEADER.Magic:
        return 64
    else:
        raise BitError('Cannot analyze this bit(magic: %d) exe' %(pe.OPTIONAL_HEADER.Magic))


def staticDector(binList):

    binRootPath = createDir(BIN_ROOT_PATH)

    newDir = os.path.join(binRootPath, str(len(os.listdir(binRootPath))))
    newBinPath = createDir(newDir)

    for bin in binList:
        shutil.copyfile(bin, newBinPath)

    analysisBinCommand =  ANALYSIS_BIN_COMMAND_PRE + newBinPath
    os.system(analysisBinCommand)

    # 生成的json文件放到一个列表中
    resultList=[]

    for f in os.listdir(newBinPath):
        if '.json' == getFileType(f):
            resultList.append(os.path.abspath(f))

    return resultList



def  CfgGenerate(EXEPath):

    cfgRootPath = createDir(CFG_OUTPUT_ROOT_PATH)

    newDir = os.path.join(cfgRootPath, str(len(os.listdir(cfgRootPath))))
    newCfgPath = createDir(newDir)

    bit = checkEXEBit(EXEPath)

    if 32 == bit:
        os.system(GETCFG_COMMAND_32 + newCfgPath + ' ' + EXEPath)
    elif 64 == bit:
        os.system(GETCFG_COMMAND_64 + newCfgPath + ' ' + EXEPath)

    return CFG_OUTPUT_ROOT_PATH


BIN_ROOT_PATH = os.path.normpath('./temp/')
HOBOT_PATH = os.path.normpath('C:/Users/test/Hobot/')

ANALYSIS_BIN_JAR = os.path.join(HOBOT_PATH, 'hobot-analysis/binary/hobot-analysis-bin.jar')

ANALYSIS_BIN_COMMAND_PRE = 'java -jar ' + ANALYSIS_BIN_JAR + ' -p='


GETCFG_JAR = os.path.join(HOBOT_PATH, 'CFGtool/getcfg/getcfg.jar')
IDA32_PATH = os.path.join(HOBOT_PATH, 'CFGtool/getcfg/IDA7.0/idat.exe')
IDA64_PATH = os.path.join(HOBOT_PATH, 'CFGtool/getcfg/IDA7.0/idat64.exe')
IDA_INCLUDE_PATH = os.path.join(HOBOT_PATH, 'CFGtool/getcfg/include')

GETCFG_COMMAND_32 = 'java -jar' + ' ' + IDA32_PATH + ' ' + IDA_INCLUDE_PATH
GETCFG_COMMAND_64 = 'java -jar' + ' ' + IDA64_PATH + ' ' + IDA_INCLUDE_PATH

CFG_OUTPUT_ROOT_PATH = os.path.normpath('./cfg')


if __name__ == "__main__":
    # pdb.set_trace()
    if len(sys.argv)!=3:
        print ("argument count wrong!")
    else:
        logging.info("static dector begin")
        staticDector(sys.argv[1])
        logging.info("static dector over")

        logging.info("cfg generate begin")
        CfgGenerate(sys.argv[2])
        logging.info("cfg generate over")

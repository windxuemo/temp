#!/usr/bin/env python
# coding=utf-8


import sys
import os
import subprocess
import logging
import time

import pdb



LOGGER = None


# Specify the path of triton 
PRE_COMMAND = '/home/test/pin-2.14-71313-gcc.4.4.7-linux/source/tools/Triton/build/triton ' +  ' '

# Specify the path of triton plugin
LOCAL_PLUGIN_PATH = './analysePlugin.py'

LOG_FILE = 'nsisAnalyse.log'

def setLogger():

    global LOGGER
    
    baseName = os.path.splitext(os.path.basename(__file__))[0]

    LOGGER = logging.getLogger(baseName)
    LOGGER.setLevel(logging.DEBUG)

    # For debug
    handlerPrint = logging.StreamHandler()
    handlerPrint.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s - %(module)s - %(levelname)s - %(message)s")
    handlerPrint.setFormatter(formatter)
    LOGGER.addHandler(handlerPrint)


    # For logging
    handlerWrite = logging.FileHandler(filename=LOG_FILE)
    handlerWrite.setLevel(logging.WARNING)
    formatter = logging.Formatter("%(asctime)s - %(module)s - %(levelname)s - %(message)s")
    handlerWrite.setFormatter(formatter)
    LOGGER.addHandler(handlerWrite)


def py2Download(url, filePath):
    import urllib2
    f = urllib2.urlopen(url)
 
    # Open our local file for writing
    with open(filePath, "wb") as local_file:
        local_file.write(f.read())
 

def py3Download(url, filePath):
    import urllib.request
    urllib.request.urlretrieve(url, filePath)


def downloader(url, filePath):
    try:
        if sys.version_info.major == 2:
            py2Download(url, filePath)
        else:
            py3Download(url, filePath)

    except Exception as e:
        LOGGER.error('Exception: %s', str(e))
        LOGGER.error ("%s download failed!" , url)
        return None
    return filePath


# Execute external command
def execCmdReout(command, keepRunning = True, output = True,  returnCode = False):
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, universal_newlines=True, executable='/bin/bash')
    procOutput = proc.communicate()[0]

    if proc.returncode != 0 and not keepRunning:
        LOGGER.debug('< ' + command + ' > run failed!')
        sys.exit(1)
    if output :
        LOGGER.debug(procOutput)
    if returnCode :
        return proc.returncode, procOutput
        # return proc.returncode
    else :
        return procOutput


def  writeFile(data, filePath):
    with open(filePath, 'w+') as the_file:
        the_file.write(data)



# Instrumentation and analyze the program
def analyse(pluginPath, programPath, args=''):

    command = PRE_COMMAND + pluginPath + ' ' + programPath + ' ' + args
    LOGGER.debug('command: [%s]' %(command))

    try:
        returncode,output = execCmdReout(command, output=False, returnCode=True)
        if returncode != 0:
            LOGGER.error(output)
            LOGGER.error('[ %s ] exec failed!', command)
            return None
	                

    except Exception as e:
        LOGGER.error('Exception: %s', str(e))
        LOGGER.error('[ %s ] exec failed!', command)
        return None

    return output



def autoAnalyse(analyseScriptPath, clientScript, programPath, args=None):

    url = analyseScriptPath

    pluginPath = LOCAL_PLUGIN_PATH
    if None == downloader(url, pluginPath):
        LOGGER.error ("downloader failed!")
        return None

    if args:
    	output = analyse(pluginPath, programPath, args)
    else:
    	output = analyse(pluginPath, programPath)

    if None == output:
        LOGGER.error('Analyse failed!')
        return None


    return output



# if __name__ == "__main__":
# 
#     setLogger()
#     # pdb.set_trace()
#     result = autoAnalyse('http://127.0.0.1:8000/template1.py', '/home/test/soft/self_test/server')
#     if None == result:
#         LOGGER.debug('failed!')
#         time.sleep(3)
#     print(result)
#     time.sleep(3)

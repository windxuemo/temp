#!/usr/bin/env python
# coding=utf-8


import sys
import os
import subprocess
import logging
import time
import ast
import json

from multiprocessing import Pool


RESULT_FILE = '/tmp/result.txt'

LOGGER = None

# Specify the path of triton
PRE_COMMAND = '/home/work/pin-2.14-71313-gcc.4.4.7-linux/source/tools/Triton/build/triton ' +  ' '

# Specify the path of triton plugin
# LOCAL_PLUGIN_PATH = './temp_analyse_script.py'

# LOCAL_CLIENT_PATH = './temp_client_script.py'

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
    if sys.version_info.major == 2:
        py2Download(url, filePath)
    else:
        py3Download(url, filePath)


def readFile(filePath):
    with open(filePath, 'r') as f:
        return f.read()


def formatBranch(branch):

    flippingStyle = {
        "normal": {
        "color": "red"
        }
    }

    passedStyle = {
        "normal": {
        "color": "green"
        }
    }


    # Parent node
    node1 = {}
    node1['name'] = hex(branch['srcAddr'])
    node1['itemStyle'] = passedStyle
    link = {}

    # Child nodes that have passed
    node2 = {}
    node2['name'] = hex(branch['passedAddr'])
    node2['itemStyle'] = passedStyle

    # Child nodes to flip
    node3 = {}
    node3['name'] = hex(branch['flippingAddr'])
    node3['itemStyle'] = flippingStyle

    # The path that has been passed
    link1 = {}
    link1['source'] = hex(branch['srcAddr'])
    link1['target'] = hex(branch['passedAddr'])
    link1['name'] = ''

    # The path that need to be flipped over
    link2 = {}
    link2['source'] = hex(branch['srcAddr'])
    link2['target'] = hex(branch['flippingAddr'])
    link2['name'] = str(branch['flippingCondition'])

    # Nodes
    branchNodes=[]
    nodes = [node1, node2, node3]
    branchNodes.extend(nodes)

    # Links
    branchLinks=[]
    links = [link1, link2]
    branchLinks.extend(links)

    branch = {}
    branch['data'] = branchNodes
    branch['links'] = branchLinks

    return branch



# Format the result of symbolic execution
def formatResult(listData):

    branchs = []
    for branch in listData:
        if isinstance(branch, dict):
            try:
                branch = formatBranch(branch)
            except Exception as e:
                LOGGER.error(str(e))
                raise RuntimeError('The result is malformed !')

            branchs.append(branch)

    return branchs


def getResult(filePath):


    data = readFile(filePath)
    result = data
    try:
        # List type string to list object
        branchList = ast.literal_eval(data)
    except Exception as e:
        LOGGER.info(str(e))

    else:
        if isinstance(branchList, list):
            try:
                branchs = formatResult(branchList)
            except Exception as e:
                LOGGER.info(str(e))

            result = branchs

    finally:
        return result



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



# Instrumentation and analyze the program
def analyse(pluginPath, programPath, args=''):

    command = PRE_COMMAND + pluginPath + ' ' + programPath + ' ' + args
    LOGGER.debug('command: [%s]' %(command))

    try:

        returncode, output = execCmdReout(command, output=False, returnCode=True)

    except Exception as e:
        LOGGER.error(str(e))
        LOGGER.error('[ %s ] exec failed!', command)
        raise RuntimeError('Trion instrumentation failed !')

    if returncode != 0:
        LOGGER.error(output)
        LOGGER.error('[ %s ] exec failed!', command)
        raise RuntimeError('Trion instrumentation failed !')

    return output



def clientInput(clientScript):
    command = 'python ' + clientScript
    LOGGER.debug('command: [%s]' %(command))

    try:

        returncode, output = execCmdReout(command, output=False, returnCode=True)


    except Exception as e:
        LOGGER.error(str(e))
        LOGGER.error('[ %s ] exec failed!', command)
        raise RuntimeError('Client failed to send data !')

    if returncode != 0:
        LOGGER.error(output)
        LOGGER.error('[ %s ] exec failed!', command)
        raise RuntimeError('Client failed to send data !')

    return output



def autoAnalyse(analyseScriptPath, clientScriptPath, programPath, args=''):


    plugin_url = analyseScriptPath
    client_url = clientScriptPath


    pluginPath = './temp_analyse_script.py'
    clientPath = './temp_client_script.py'

    # Download Triton plugin
    try:
        downloader(plugin_url, pluginPath)
    except Exception as e:
        LOGGER.error (str(e))
        LOGGER.error ("plugin_url <%s>  downloader failed!" % (plugin_url))
        return None

    try:
        downloader(client_url, clientPath)
    except Exception as e:
        LOGGER.error (str(e))
        LOGGER.error ("client_url <%s>  downloader failed!" % (plugin_url))
        return None

    pool = Pool(processes=2)
    serverResult = []
    clientResult = []

    try:
        serverResult.append(pool.apply_async(analyse, args=(pluginPath,programPath, args,)))

        # Wait for the program under test to start
        time.sleep(20)

        # Execute script and send data
        clientResult.append(pool.apply_async(clientInput, args=(clientPath,)))

        pool.close()
        pool.join()
    except Exception as e:
        LOGGER.error(e)
        LOGGER.error("Symbolic failed!")

    time.sleep(5)

    if not os.path.isfile(RESULT_FILE):
        return None

    result = getResult(RESULT_FILE)
    print(result)

    return result



setLogger()


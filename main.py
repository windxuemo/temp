#coding:utf-8
from flask import Flask, request
from flask_restful import Resource, Api
#ifrom sqlalchemy import create_engine
from json import dumps
import json
from flask_jsonpify import jsonify
from flask import after_this_request
import sys
import os
import time
import logging
from concurrent.futures import ThreadPoolExecutor
import requests
import shutil
sys.path.append('..')
# import autoinstall.nsisAutoInstall as aInstall
# import staticDector.nsisStaticDector as sDector
# import nsisfuzz.nsisAutoFuzz as nsisFuzz
import nsisAnalyse

import pdb

app = Flask(__name__,static_folder='static')
api = Api(app)
webDirPath, webfileName = os.path.split(os.path.abspath(__file__))
executor = ThreadPoolExecutor(max_workers=5)
webUrl="http://192.168.3.19:8988"
workUrl="http://192.168.101.10:8000"
staticInterface='/api/ReceiveData/ScanData'
installInterface='/api/ReceiveData/InsertData'
fuzzInterface='/api/ReceiveData/FuzzData'
CFGInterface='/api/ReceiveData/CFGData'
taintInterface='/api/ReceiveData/TaintData'
dotFileRelativePath='/static/dotfile/'
logging.basicConfig(level=logging.INFO)
targetDict= {}
def addDict(key,value):
    #维护targetDict
    logging.info(targetDict)
    logging.info(key)
    if (key in targetDict)==False:
        targetDict[key]=value
        logging.info(targetDict)
        return True
    else:
        logging.error("此安装文件已在对应表中,目标字典插入失败")
        return False


def delDict(key):
    #删除targetDict中的某个key
    try:
        targetDict.pop(key)
    except Exception as e:
        logging.error(e)

def postData(postUrl,result):
    r = requests.post(postUrl,json=result)
    logging.info(r.status_code)
    #print(jsonify(result))

def backgroundAnalyse(pluginScript, clientScript, id, args):
    #后台实现自动化分析的函数
    print('backgroundAnalyse')
    try:
        # procPath =targetDict[id]
        procPath ='/home/test/self_test/server'
        logging.info(procPath)
        analyseResult=nsisAnalyse.autoAnalyse(pluginScript, clientScript, procPath, args)
    except Exception as e:
        logging.error(e)
    logging.info(analyseResult)
    # postResult={'id':id,'status':'1','action':'install','result':installResult}
    # postData(webUrl+installInterface,postResult)


@app.route('/')
def index():
    result={'status':'Hello'}
    return jsonify(result)

@app.route('/receive',methods=['POST','OPTIONS','GET'])
def receive():
    #调试接口，模拟WEB服务器，测试是否能够收到调度服务器的包
    logging.info(request.headers)
    getJson=request.get_json()
    print(getJson)
    logging.info(getJson)
    return 'Done'

@app.route('/dispatch/down',methods=['POST','OPTIONS','GET'])
def down():
    #安装文件的接口
    logging.info(request.headers)
    getJson=request.get_json()
    logging.info(getJson)
    try:
        nAction=getJson['action']
        nPath=str(getJson['path'])
        nHash=getJson['hash']
        nId=getJson['id']
        nToken=getJson['token']
        logging.info(nToken,nAction,nPath,nHash,nId)
        if addDict(nId,nPath)==False:
            result={'id':nId,'status':'ID重复!'}
            return jsonify(result)
        else:
            result={'id':nId,'status':'1'}
            return jsonify(result)
    except KeyError:
        result={'id':nId,'status':'KeyError'}
        return jsonify(result)

@app.route('/dispatch/install',methods=['POST','OPTIONS','GET'])
def install():
    logging.info(request.headers)
    getJson=request.get_json()
    logging.info(getJson)
    try:
        nAction=getJson['action']
        nId=getJson['id']
        if nAction!='install':
            result={'id':nId,'action':'Keyerror'}
            return jsonify(result)
    except Exception as e :
        logging.error(e)
    else:
        logging.info(targetDict)
        executor.submit(backgroundInstall,nId)
        result={'id':nId,'status':'1','action':'install'}
        return jsonify(result)

@app.route('/dispatch/sampledown',methods=['POST','GET'])
def fuzz():
    #接受Fuzz的输入脚本的处理函数
    logging.info(request.headers)
    getJson=request.get_json()
    logging.info(getJson)
    try:
        nAction=getJson['action']
        nPath=str(getJson['path'])
        nHash=getJson['hash']
        nId=getJson['id']
        nToken=getJson['token']
        nScriptId=getJson['sampleid']
        logging.debug(nToken,nAction,nPath,nHash,nId,nScriptId)
        #TODO: 添加样本对应关系
        executor.submit(backgroundFuzz,nPath)
        result={'id':nId,'status':'1','action':'fuzz'}
        return jsonify(result)
    except KeyError:
        result={'id':'1','status':'KeyError'}
        return jsonify(result)

@app.route('/dispatch/dector',methods=['POST','GET'])
def dector():
    #静态扫描的接口
    logging.info(request.headers)
    getJson=request.get_json()
    logging.info(getJson)
    try:
        nAction=getJson['action']
        nId=getJson['id']
        nToken=getJson['token']
        logging.info(nToken,nAction,nId)
    except KeyError:
        result={'id':'1','status':'KeyError'}
        return jsonify(result)
    else :
        executor.submit(backgroundStatic,nId)
        result={'id':'1','status':'1','action':'static'}
        return jsonify(result)

@app.route('/dispatch/networkfuzz',methods=['POST','GET'])
def networkfuzz():
    #静态扫描的接口
    logging.info(request.headers)
    getJson=request.get_json()
    logging.info(getJson)
    try:
        nAction=getJson['action']
        nId=getJson['id']
        nToken=getJson['token']
        nproc_path=getJson['proc_path']
        ntarget_ip=getJson['target_ip']
        ntarget_port=getJson['target_port']
        nprotocol=getJson['protocol']
        nload=getJson['load']
        logging.info(nToken,nAction,nId)
    except KeyError:
        result={'id':'1','status':'KeyError'}
        return jsonify(result)
    else :
        #executor.submit(backgroundStatic,nId)
        result={'id':nId,'status':'1','action':'networkfuzz'}
        return jsonify(result)

@app.route('/dispatch/symbolic',methods=['POST','OPTIONS','GET'])
def symbolic():
    #安装文件的接口
    print('symbolic')
    logging.info(request.headers)
    getJson=request.get_json()
    logging.info(getJson)
    try:
        print('===============')
        pdb.set_trace()
        nId=getJson['id']
        nAction=getJson['action']
        nPath=str(getJson['proc_path'])
        nArgs=getJson['proc_args']
        nPluginScript=getJson['plugin_script']
        nClientScript=getJson['client_script']
        logging.info(nId, nAction, nPath, nArgs, nPluginScript, nClientScript)

        # executor.submit(backgroundAnalyse,nId)
        backgroundAnalyse(nPluginScript, nClientScript, nId, nArgs)

        result={'id':nId,'status':'1', 'action': 'symbolic'}
        return jsonify(result)
    except KeyError:
        result={'id':nId,'status':'KeyError'}
        logging.info(result)
        return jsonify(result)


if __name__ == '__main__':
     app.run(host='0.0.0.0',port='8000',debug=True)

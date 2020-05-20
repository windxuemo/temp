#coding:utf-8
from flask import Flask, request
from flask_restful import Resource, Api
from sqlalchemy import create_engine
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
import pickle
import psutil
import atexit
import pdb
sys.path.append('..')
# import autoinstall.AutoInstall as aInstall
# import staticDector.nsisStaticDector as sDector
# import nsisfuzz.nsisAutoFuzz as nsisFuzz

import nsisAnalyse


app = Flask(__name__,static_folder='static')
api = Api(app)
webDirPath, webfileName = os.path.split(os.path.abspath(__file__))
executor = ThreadPoolExecutor(max_workers=5)
webUrl="http://10.1.1.24:80"
workUrl="http://192.168.3.23:1080"
staticInterface='/api/ReceiveScan/ScanData'
installInterface='/api/ReceiveInsert/InsertData'
fuzzInterface='/api/ReceiveData/FuzzData'
CFGInterface='/api/ReceiveScan/CFGData'
taintInterface='/api/ReceiveTaint/Taint'
symbolicInterface='/api/ReceiveSymbolic/SymbolicData'
dotFileRelativePath='/static/dotfile/'
networkfuzz_interface='/api/ReceiveNetworkFuzz/NetworkFuzz'


store_file="target_list.dict"
targetDict= {}
TOKEN="test_token"
WORK_URL=""

def locate_id(pattern,str_list,id_list):
    '''
    pattern 搜索字符串,默认为返回的json文件名
    '''
    search_len=len(str_list)
    for i in range(search_len):
        if pattern.find(str_list[i])!=-1:
            logging.debug("find %s id is %s"%(str_list[i],id_list[i]))
            break
        else:
            pass
    if i<search_len:
        return id_list[i]
    else:
        logging.error("locate id from str_list failed")
        return -1

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



def backgroundInstall(id):
    #后台实现自动化安装的函数
    try:
        path=targetDict[id]
        logging.info(path)
        installResult=aInstall.autoInstall(path)
    except Exception as e:
        logging.error(e)
    postResult={'id':id,'status':'ok','action':'install','result':installResult}
    logging.debug(json.dumps(postResult,indent=4))
    postData(webUrl+installInterface,postResult)

def backgroundInstall_url(url):
    #后台实现自动化安装的函数
    try:
        installResult=aInstall.autoInstall(url)
    except Exception as e:
        logging.error(e)
    logging.info(installResult)
    postResult={'id':id,'status':'ok','action':'install','result':installResult}
    postData(webUrl+installInterface,postResult)

def backgroundCFG(cfg_list):
    '''
    cfg_list : [
        {
            "id":"1",
            "path":"c:/user/test/a.exe"
        }
        ]
    '''
    try:
        logging.debug(cfg_list)
        for each_dict in cfg_list:
            tid=each_dict['id']
            logging.debug("before enter cfg generate")
            logging.debug(each_dict)
            result_dir=sDector.CfgGenerate(each_dict['path'])
            logging.debug(result_dir)
            for each_dot_file in os.listdir(result_dir):
                each_dot_file=os.path.join(result_dir,each_dot_file)
                logging.debug("reading %s"%(each_dot_file))
                dot_fp=open(each_dot_file,'r')
                dot_content=dot_fp.read()
                dot_result={
                    'id':tid,'action':'CFG',
                'fileName':os.path.basename(each_dot_file),
                'fileInfo':dot_content
                }
                logging.debug( json.dumps(dot_result,indent=4))
                postData(webUrl+CFGInterface,dot_result)
    except Exception as e:
        logging.error(e)
    logging.debug("exit backgroundCFG")

def backgroundStatic(raw_target_list):
    '''
    #后台实现静态漏洞扫描的函数
    raw_target_list: 由web直接提取出来的需要扫描的文件list以及其id
    [
        {
            "fId": "01-1", //子体ID
            "fPath": "c:/123.exe"
        },
        {
            "fId": "01-2", //子体ID
            "fPath": "c:/123.dll"
        }
    }
    '''
    logging.debug(raw_target_list)
    target_list=[]
    target_id_list=[]
    tmp_cfg_list=[]
    try:
        #if targetDict.has_key(id):
        #    anaylsePath=targetDict[id]
        all_dector_len=len(raw_target_list)
        for each_dector_dict in raw_target_list:
            target_list.append(each_dector_dict['fPath'])
            target_id_list.append(each_dector_dict['fId'])
        staticResultList=sDector.staticDector(target_list)
        #TODO:还没弄好
    except Exception as e:
        logging.error(e)
    logging.debug(staticResultList)
    for curResultPath in staticResultList:
        logging.debug(curResultPath)
        with open(curResultPath,'r') as f:
            staticResult=json.loads(f.read())
        tmp_id=locate_id(os.path.basename(curResultPath),target_list,target_id_list)
        #logging.info(staticResult)
        staticResult['id']=tmp_id
        #for debugger
        staticResult['action']='static'
        staticResult['status']='ok'
        logging.debug('Before postdata')
        logging.debug(json.dumps(staticResult,indent=4) )
        postData(webUrl+staticInterface,staticResult)
        logging.debug('After postdata')
        tmp_save_path=curResultPath.strip(".json")#去掉Json名得到存储路径
        tmp_cfg_dict={}
        tmp_cfg_dict['id']=tmp_id
        tmp_cfg_dict['path']=tmp_save_path
        tmp_cfg_list.append(tmp_cfg_dict)
    logging.info('start CGFinterface')
    executor.submit(backgroundCFG,tmp_cfg_list)
    logging.info("backgroundstatic ready to exit")

def backgroundFuzz(id,proc_path,target_ip,target_port,load,protocol,auto_path):
    #后台调度Fuzz的函数
    try:
        logging.debug('start network fuzz')
        logging.debug("proc_path %s auto_path %s"%(proc_path,auto_path))
        logging.debug("checking proc_moniter status")
        #TODO 检查proc_moniter是否正常启动
        fuzz_template_path=os.path.join(webDirPath,"../nsisfuzz/fuzz_template.py")
        start_fuzz_cmd="start python %s exp -ip %s -port %s -over %s -proc \"%s\" -auto %s -temp %s"%(
            fuzz_template_path,target_ip,target_port,load,proc_path,auto_path,protocol
        )
        logging.debug(start_fuzz_cmd)
        #TODO 现在用start 在管理员权限下 启动需要过UAC
        os.system(start_fuzz_cmd)
        time.sleep(6)
        #TODO 检查客户端是否正常启动
        result={"id":id,"token":TOKEN,"action":"networkfuzz","basic_url":WORK_URL,'status':'ok'}
        logging.debug(json.dumps(result,indent=4))
        postData(webUrl+networkfuzz_interface,result)
    except Exception as e:
        logging.error(e)

def backgroundAnalyse(nId, pluginScript, clientScript, nPath, args):
    #后台实现自动化分析的函数
    print('backgroundAnalyse')
    try:
        procPath = nPath
        # procPath ='/home/work/temp/work/tftpserversp/tftpserver'
        logging.info(procPath)
        analyseResult=nsisAnalyse.autoAnalyse(pluginScript, clientScript, procPath, args)
    except Exception as e:
        logging.error(e)
    logging.info(analyseResult)
    postResult={'id':nId,'status':'ok','token': '22222', 'action':'symbolicexec','result': analyseResult}
    postData(webUrl+symbolicInterface ,postResult)


def backgroundTaintAnalyse(nId, pluginScript, clientScript, nPath, args):
    #后台实现自动化分析的函数
    logging.info('backgroundTaintAnalyse')
    try:
        procPath = nPath
        # procPath ='/home/work/temp/work/tftpserversp/tftpserver'
        logging.info(procPath)
        analyseResult=nsisAnalyse.autoAnalyse(pluginScript, clientScript, procPath, args)
    except Exception as e:
        logging.error(e)
    logging.info(analyseResult)
    postResult={'id':nId,'status':'ok','token': '22222', 'action':'taint','result': analyseResult}
    logging.info(postResult)
    postData(webUrl+taintInterface, postResult)




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
            result={'id':nId,'status':'ok'}
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
        result={'id':nId,'status':'ok','action':'install'}
        return jsonify(result)

@app.route('/dispatch/url_install',methods=['POST','OPTIONS','GET'])
def url_install():
    #TODO 留出独立调试自动安装的接口   
    logging.info(request.headers)
    getJson=request.get_json()
    logging.info(getJson)
    try:
        nurl=getJson['url']
    except Exception as e :
        logging.error(e)
    else:
        executor.submit(backgroundInstall_url,nurl)
        result={'id':'debug','status':'ok','action':'install'}
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
        result={'id':nId,'status':'ok','action':'fuzz'}
        return jsonify(result)
    except KeyError:
        result={'id':'1','status':'KeyError'}
        return jsonify(result)

@app.route('/dispatch/dector',methods=['POST','GET'])
def dector():
    #静态扫描的接口
    logging.debug(request.headers)
    getJson=request.get_json()
    logging.debug(getJson)
    try:
        nAction=getJson['action']
        #nId=getJson['id']
        nToken=getJson['token']
        n_target=getJson['target']
        logging.debug(n_target)
    except KeyError:
        result={'id':'1','status':'KeyError'}
        return jsonify(result)
    else :
        executor.submit(backgroundStatic,n_target)
        result={'id':'1','status':'ok','action':'static'}
        return jsonify(result)

@app.route('/debug/cfg',methods=['POST','GET'])
def debug_cfg():
    logging.debug(request.headers)
    getJson=request.get_json()
    logging.debug(getJson)
    try:
        nlist=getJson['cfg_list']
    except KeyError:
        result={'id':'1','status':'KeyError'}
        return jsonify(result)
    else :
        executor.submit(backgroundCFG,nlist)
        result={'id':'1','status':'ok','action':'static'}
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
        auto_path=getJson['auto_path']
        nload=getJson['load']
        logging.info(nToken,nAction,nId)          
    except KeyError:
        result={'id':'1','status':'KeyError'}
        return jsonify(result)
    else :
        executor.submit(backgroundFuzz,nId,nproc_path,ntarget_ip,ntarget_port,nload,nprotocol,auto_path)
        result={'id':nId,'status':'ok','action':'networkfuzz'}
        return jsonify(result)

@app.route('/dispatch/sfuzz',methods=['POST','GET'])
def sfuzz():
    #文件模糊测试接口
    logging.info(request.headers)
    getJson=request.get_json()
    logging.info(getJson)
    try:
        nAction=getJson['action']
        nId=getJson['id']
        #nToken=getJson['token']
        nproc_path=getJson['proc_path']
        nseed_path=getJson['seeds_path']
        ncheck_non=getJson['check_non']
        logging.info(nToken,nAction,nId)          
    except KeyError:
        result={'id':'1','status':'KeyError'}
        result['actoin']=nAction
        return jsonify(result)
    else :
        executor.submit(background_sfuzz,getJson)#后台实现文件模糊测试的函数，
        result={'id':nId,'status':'ok','action':'sfuzz'}
        result['actoin']=nAction
        return jsonify(result)

@app.route('/dispatch/taint',methods=['POST','OPTIONS','GET'])
def taint():
    #安装文件的接口
    print('taint')
    logging.info(request.headers)
    getJson=request.get_json()
    logging.info(getJson)
    try:
        print('===============')
        # pdb.set_trace()
        nId=getJson['id']
        nAction=getJson['action']
        nPath=str(getJson['proc_path'])
        nArgs=getJson['proc_args']
        nPluginScript=getJson['plugin_script']
        nClientScript=getJson['client_script']
        # logging.info(nId, nAction, nPath, nArgs, nPluginScript, nClientScript)

        # executor.submit(backgroundAnalyse,nId)
        # backgroundAnalyse(nPluginScript, nClientScript, nId, nArgs)
        executor.submit(backgroundTaintAnalyse, nId, nPluginScript, nClientScript, nPath, nArgs)
        # backgroundTaintAnalyse(nId, nPluginScript, nClientScript, nPath, nArgs)

        result={'id':nId,'status':'ok', 'action': 'taint'}
        return jsonify(result)
    except KeyError:
        result={'id':nId,'status':'KeyError'}
        logging.info(result)
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
        # pdb.set_trace()
        nId=getJson['id']
        nAction=getJson['action']
        nPath=str(getJson['proc_path'])
        nArgs=getJson['proc_args']
        nPluginScript=getJson['plugin_script']
        nClientScript=getJson['client_script']
        # logging.info(nId, nAction, nPath, nArgs, nPluginScript, nClientScript)

        # executor.submit(backgroundAnalyse,nId)
        # backgroundAnalyse(nPluginScript, nClientScript, nId, nArgs)
        executor.submit(backgroundAnalyse, nId, nPluginScript, nClientScript, nPath, nArgs)
        # backgroundAnalyse(nId, nPluginScript, nClientScript, nPath, nArgs)

        result={'id':nId,'status':'ok', 'action': 'symbolic'}
        return jsonify(result)
    except KeyError:
        result={'id':nId,'status':'KeyError'}
        logging.info(result)
        return jsonify(result)





def load_dict(filename=store_file):
    global targetDict
    f = open(filename,'rb')
    tmp=pickle.load(f)
    if type(tmp).__name__=='dict':
        targetDict=tmp
    f.close()

@atexit.register
def store_dict(filename=store_file):
    global targetDict
    f = open(filename,'wb')
    pickle.dump(targetDict,f)
    f.close()

def net():
    '''
    获取网卡信息
    '''
    netcard_info = None
    info = psutil.net_if_addrs()
    for k,v in info.items():
        for item in v:
            print(item)
            if item[0] == 2 and not item[1]=='127.0.0.1' and item[1].find('10.38.')!=-1:
                netcard_info=(k,item[1])
    print(netcard_info)
    return netcard_info

def init_setting():
    global WORK_URL
    load_dict(store_file)
    logging.basicConfig(level=logging.DEBUG)
    work_ip=net()[1]
    WORK_URL="http://%s:%d/"%(work_ip,26000)

if __name__ == '__main__':
    init_setting()
    app.run(host='0.0.0.0',port='1080',debug=True)

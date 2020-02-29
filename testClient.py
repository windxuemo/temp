#coding：utf-8
#!/usr/bin/python3
import requests
'''
@author:simp1e
@purpose:用于对各个网络接口进行测试，包含外部和内部接口
'''

'''
1.上传同步接口, 一次交互 ==> upload_1_web 代表 从web发出的同步数据包
2.自动化安装接口，两次交互 ==> install_1_web , install_2_work 分别代表 自动化安装接口 第一次交互从web发出的数据包， 第二次交互从work发出的数据包
3.静态扫描接口，两次交互 ==> static_1_web, static_2_work 分别代表 静态扫描接口 第一次交互从web发出的数据包， 第二次交互从work发出的数据包
4.网络协议模糊测试，两次交互 ==> network_1_web, network_2_work 分别代表 网络协议模糊测试接口 第一次交互从web发出的数据包， 第二次交互从work发出的数据包
5.

接口调试工作流程：
交互双方提供自己主动发出的数据包JSON样例，然后自己使用使用此测试程序中的对方样例模拟对方发包，先测试自己的服务工作是否符合，双方调试通过后再联合测试。
例如: 我是work服务器开发方，我需要模拟WEB给我发包，因此使用本测试程序伪装成为WEB服务器向我在写的WEB服务器发包进行测试，工作流程及结果符合预期即可。
另外，需要保证自己的服务器给WE服务器发送的数据包和描述的一致

作为web开发方，应该使用testClient.py
'''
upload_1_web =  0 #
install_1_web =  1 #
install_2_work =  2 #
static_1_web =  3
static_2_work =  4
network_1_web =  5
network_2_work =  6
string=[]
string.append("模拟WEB测试上传同步接口")
string.append("模拟WEB测试安装接口:第一次交互")
string.append("模拟WORK测试安装接口:第二次交互")
string.append("模拟WEB测试静态扫描接口:第一次交互")
string.append("模拟WORK测试静态扫描接口:第二次交互")
string.append("模拟WEB测试网络协议模糊测试接口:第一次交互")
string.append("模拟WORK测试网络协议模糊测试接口:第二次交互")
data = {}
interface = {}
web_test=[upload_1_web,install_1_web,static_1_web,network_1_web]
work_test=[install_2_work,static_2_work,network_2_work]
data[upload_1_web]=  None
data[install_1_web] = None
data[install_2_work] = None
data[static_1_web] = None 
data[static_2_work] = None
data[network_1_web] = {
    "id":"01", 
    "action":"networkfuzz", 
    "token" : "test_token",
    "proc_path": "c:/users/xxx/desktop/test.exe", 
    "target_ip": "127.0.0.1", 
    "target_port": "69", 
    "protocol": "ftp", 
    "load": "udp", 
}
data[network_2_work] = None
interface[upload_1_web] = "/dispatch/down"
interface[install_1_web] = "/dispatch/install"
interface[install_2_work] = "/api/ReceiveData/InsertData"
interface[static_1_web] = "/dispatch/dector"
interface[static_2_work] = "/api/ReceiveData/ScanData"
interface[network_1_web] ="/dispatch/networkfuzz" 
interface[network_2_work] = "/api/ReceiveData/NetworkBasic"

if __name__ == "__main__":
    monitor=int(input("模拟哪一方: 1. WEB服务器 2. work服务器").strip())
    if monitor==1:
        print("现在本测试程序模拟WEB服务器向work服务器发包")
        work_host=input("输入待测work服务器url：").strip()
        while 1:
            for i in web_test:
                print("输入 %d => %s"%(i,string[i]))
            choice = int(input("输入 -1 结束\n选择:").strip())
            if choice==-1:
                break
            else:
                r = requests.post(work_host+interface[choice], json=data[choice])
                print(r.text)
    elif monitor==2:
        print("现在本测试程序模拟work服务器向WEB服务器发包")
        web_host=input("输入待测WEB服务器url：").strip()
        while 1:
            for i in work_test:
                print("输入 %d => %s"%(i,string[i]))
            choice = int(input("输入 -1 结束\n选择:").strip())
            if choice==-1:
                break
            else:
                r = requests.post(web_host+interface[choice], json=data[choice])
                print(r.text)
    else:
        print("输入有误!")
        exit()


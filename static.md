moduleSet：被测项目包含的组件名称列表

bugSetHigh：被测项目包含的高威胁漏洞列表

bugSetMiddle：被测项目包含的中威胁漏洞列表

bugSetLow：被测项目包含的低威胁漏洞列表

moduleList：被测项目包含的组件列表详细信息

module_name：组件名称

module_version：组件版本

module_bugcount：组件漏洞数目

bug_high：高威胁漏洞数目

bug_middle：中威胁漏洞数目

bug_low：低威胁漏洞数目

bugDetailList：漏洞详细信息列表

bugno：bug编号

bug_origin：漏洞来源

bug_releasetime：发布时间

bug_typename：漏洞类型名

bug_typeurl：漏洞类型链接

bug_level：严重等级

bug_score：评分分数

basicscore：cvss2.0基本评分

availabilityscore：cvss2.0可利用性评分

impactscore：cvss2.0影响评分

triggerflag：是否为可触发漏洞标识

bug_url：漏洞链接

bug_scoreurl：漏洞评分链接

bug_description：描述

basicscore3：cvss3.0基本评分

availabilityscore3：cvss3.0可利用性评分

impactscore3：cvss3.0影响评分

triggerpath：可触发漏洞路径

triggerline：漏洞处罚行号

bug_fix_time：修复时间

bug_fix_version：修复版本

L


```
{
  "id": '1',
  'action':'static',
  'status': '0/1',
  "moduleSet": [
    "okular#17.12.2"
  ],
  "bugSetHigh": ["CVE-2019-1000801"],
  "bugSetMiddle": [
    "CVE-2018-1000801"
  ],
  "bugSetLow": [],
  "moduleList": [
    {
      "module_name": "okular",
      "module_version": "17.12.2",
      "module_bugcount": 1,
      "bug_high": 0,
      "bug_middle": 1,
      "bug_low": 0,
      "bugDetailList": [
        {
          "bugno": "CVE-2018-1000801",
          "bug_origin": "NVD",
          "bug_releasetime": "2018-09-06 10:29:00",
          "bug_typename": "CWE-22",
          "bug_typeurl": "http://cwe.mitre.org/data/definitions/22.html",
          "bug_level": "2",
          "bug_score": 4.3,
          "basicscore": 4.3,
          "availabilityscore": 8.6,
          "impactscore": 2.9,
          "triggerflag": "",
          "bug_url": "http://cve.mitre.org/cgi-bin/cvename.cgi?name\u003dCVE-2018-1000801",
          "bug_scoreurl": "https://nvd.nist.gov/vuln/detail/CVE-2018-1000801",
          "bug_description": "okular version 18.08 and earlier contains a Directory Traversal vulnerability in function \"unpackDocumentArchive(...)\" in \"core/document.cpp\" that can result in Arbitrary file creation on the user workstation. This attack appear to be exploitable via he victim must open a specially crafted Okular archive. This issue appears to have been corrected in version 18.08.1",
          "basicscore3": 0.0,
          "availabilityscore3": 1.8,
          "impactscore3": 3.6,
          "triggerpath": "",
          "triggerline": "",
          "bug_fix_time": "",
          "bug_fix_version": ""
        }
      ]
    }
  ]
}
```
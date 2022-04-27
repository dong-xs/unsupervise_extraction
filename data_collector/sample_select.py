#encoding:utf-8
'''
    本py文件的作用是找出NVD中共同包含5个或4个第三方站点的CVE编号
'''

import pandas as pd

content=pd.read_csv('../data/DongPaper_nvd_info.csv', encoding='ANSI')    #通过记事本可以查看文件的编码格式，结果发现为ANSI编码格式的

third_link=content['hyperlink'].values.tolist()    #转换为了一个list

domain_list=[                       #此次拟筛选的5个第三方站点
    'exchange.xforce.ibmcloud.com',
    # 'www.exploit-db.com',
    'www.openwall.com',
    'oval.cisecurity.org',
    'security.gentoo.org'
    # 'lists.opensuse.org',
    # 'securityreason.com',
    # 'github.com'
]

cveid=content['cveid'].tolist()
length=len(cveid)
cves=[]
for i in range(length):
    values=[]
    for detail in eval(third_link[i]):    #遍历每个列表中的字典
        value=list(detail.values())[0].split('//')
        if len(value)>=2:
            values.append(value[1].split('/')[0])
    values=list(set(values))
    count=0
    for item in values:
        if item in domain_list:
            count+=1
    if count==4:            #同时包含4个站点
        cves.append(cveid[i])

print(cves)
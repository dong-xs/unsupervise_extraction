#encoding:utf-8
import json
import pandas as pd

# res = pd.read_csv('./data/DongPaper_cve_hyperlink_info.csv', encoding='UTF-8', index_col=False)
#
# cves=res['cve_id'].tolist()
# exploitdb=res['exploit_db_info'].tolist()
# openwall=res['openwall_info'].tolist()
# length=len(cves)


#该段代码是找出既存在于exploitdb又存在于openwall的cveid，其最终目的是想要找到这两个站点披露的信息与NVD存在偏差，这也是本文的motivation
# count=[]
# for i in range(length):
#     if len(eval(exploitdb[i]))!=0 and len(eval(openwall[i]))!=0:
#         count.append(cves[i])
#
# with open('./data/common_cves.txt','w') as f:
#     for item in count:
#         f.write(item+'\n')
# f.close()


#该段代码是找出那些在exploitdb或openwall中包含两条及以上披露信息的cveid
# double_site=[]
# for i in range(length):
#     if len(eval(exploitdb[i]))>1 or len(eval(openwall[i]))>1:
#         double_site.append(cves[i])
#
# with open('./data/double_site_cves.txt','w') as f:
#     for item in double_site:
#         f.write(item+'\n')
# f.close()


#exploitdb提交规则可以参照：https://www.exploit-db.com/submit
#又一个漏洞众测平台，可通过该平台进行漏洞披露：http://www.hackerone.com     #消息来源：https://www.freebuf.com/articles/web/224609.html

# from nltk.corpus import wordnet as wn
# print(wn.synsets('dog'))
# assert 0


# nvd_res = pd.read_csv('./data/DongPaper_nvd_info.csv', encoding='gbk', index_col=False)
# hyperlinks=nvd_res['hyperlink'].tolist()
#
# print(hyperlinks[0])
domain_list=[
    'http://exchange.xforce.ibmcloud.com',
    'http://www.exploit-db.com',
    'http://www.openwall.com',
    'https://oval.cisecurity.org',
    'http://security.gentoo.org'
]


# 这是一种查看文本中每一行数据编码格式的方法
# f=open('./data/DongPaper_nvd_info.csv','rb')
# i=0
# while True:
#     i+=1
#     print(i)
#     line=f.readline()
#     if not line:
#         break
#     else:
#         try:
#             line.decode('utf-8')
#         except:
#             print(str(line))

# from pattern.text.en import wordnet as wn
# print(wn.synsets('car'))


# import spacy
# nlp=spacy.load('en_core_web_md')
#
# sent='Stack-based buffer overflow in VideoLAN VLC media player 0.9.x before 0.9.6 might allow user-assisted attackers to execute arbitrary code via an an invalid RealText (rt) subtitle file related to the ParseRealText function in modules/demux/subtitle.c.'
# from spacy import displacy
# displacy.render(nlp(sent),style='dep',jupyter=True,options={'distance':90})


# import os
# import shutil    #用于文件移动的第三方库
#
# determination= r'./data/exploits_new/'
# if not os.path.exists(determination):
#     os.makedirs(determination)
#
# def file_move(path_n):
#
#
# path = r'./data/exploits'
# folders=os.listdir(path)    #一级目录
# for folder in folders:
#     dir=path+'/'+str(folder)
#     files=os.listdir(dir)
#     for file in files:
#         if file.endswith('.rb'):
#             source=str(dir)+"/"+str(file)
#             deter=determination+str(file)
#             shutil.copy(source,deter)
#         else:
#             new_dir=dir+'/'+str(file)

# with open('./data/exploits/aix/rpc_cmsd_opcode21.rb',encoding='utf-8') as f:
#     content=f.readlines()
#     f.close()
#
# print(content)
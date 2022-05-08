#encoding:utf-8

'''
    py文件说明：
        该py文件用于统计NVD的第三方超链中，各个第三方站点的比例，从而选择出我想要的数据源

        经过对统计后的各第三方站点数据量统计发现，可以考虑使用以下五个站点作为公开源：
            http://exchange.xforce.ibmcloud.com         #35792
            http://www.exploit-db.com                   #12844,该站点的数据太乱了，是不是可以不考虑了
            http://www.openwall.com                     #11051
            https://oval.cisecurity.org                 #10286
            http://security.gentoo.org                  #10048
            http://securityreason.com  <待定>           #6401,该站点也是极其不规则，也包括代码等内容
            http://packetstormsecurity.com   <待定>     #6111，该站点是蒲觉非推荐的一个站点，但是该站点内容也是太乱了



            APU提供的站点虽然从NVD得到的数据较少，但是MSF/modules下的每个站点都可以与CVE编号进行链接，
            目标站点为：https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits
            这个站点可以重点考虑为数据源。

            还需要继续对各个站点进行调研，经过继续深入调研发现，满足条件的站点太少，主要包括两个方面：
                （1）我需要找那种公开披露漏洞的第三方站点，而不是针对某个产品或平台的披露站点
                （2）我需要那种内容全是代码或文本描述的页面，而不是两种情况经常交织且多变的情况。
            基于上述情况，选择4个站点（除开Exploit-DB）作为研究对象即可。
'''

import pandas as pd

content=pd.read_csv('../data/DongPaper_nvd_info.csv', encoding='ANSI')    #通过记事本可以查看文件的编码格式，结果发现为ANSI编码格式的

third_link=content['hyperlink'].values.tolist()    #转换为了一个list

final=[]   #将所有拆分出来的域名存放在这个列表中了
for ind,item in enumerate(third_link):
    for detail_link in eval(item):
        if isinstance(detail_link,dict):
            for key,value in detail_link.items():
                if "//" not in value:
                    continue
                else:
                    first_split=value.split('//')[1]
                    second_split=first_split.split('/')[0]
                    final.append(second_split)

from collections import Counter
static_value=Counter(final)     #统计每个域名出现的次数
sorted_value=sorted(static_value.items(),key=lambda x:x[1],reverse=True)     #按统计次数逆序排列

sorted_value_head=['http://'+item[0] for item in sorted_value]
sorted_value_tail=[item[1] for item in sorted_value]
rebuild_sorted_value=[]
for item in range(len(sorted_value_head)):
    rebuild_sorted_value.append((sorted_value_head[item],sorted_value_tail[item]))

print(len(rebuild_sorted_value))
for item in rebuild_sorted_value[:100]:     #排行前20的第三方站点
    print(item)

with open('../data/third_part_cve_site_top50.txt', 'w') as f:
    for item in rebuild_sorted_value[:100]:
        f.write(str(item)[1:-1]+'\n')
f.close()
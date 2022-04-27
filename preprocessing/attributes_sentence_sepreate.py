# encoding:utf-8
'''
    该py文件的作用是：
        （1）将各个列表的属性以及每个文本内容中的句子找出来；
        （2）将各个漏洞报告中

    根据exploitdb.submit提供的提交报告格式，主要包括以下几个字段：（其实可以发现，很多属性具有相同的属性，可以将这些属性合并，然后用一个最长公共子串匹配的形式来判定就可以了）
        [exploit title,title]:标题
        [google dork,dork,dorks]:谷歌搜索关键字
        date:发现漏洞日期
        [exploit author,author]:漏洞发现人
        [vendor homepage,vendor information,vendor]:供应商主页
        [software link,software]:漏洞影响应用下载链接
        [version,version affected]:影响版本
        tested on:在什么系统上进行测试
        cve:
    还可以在此基础上扩充一下：
        vulnerability type:
        product:
        application:
        summary:
        platform:
        Discovered by:
        source:
        name:与title同义，也常与product name一同出现，还可以表示为component

    openwall站点的属性相对就很明确：
        (1)Date:
        (2)From:
        (3)To:
        (4)Subject:
        (5)CC:
'''
import pandas as pd

# content = pd.read_csv('../data/DongPaper_cve_hyperlink_info_5sites.csv', encoding='ANSI')
# exploit = content['exploit_db_info'].values.tolist()
# IBM = content['IBM_info'].values.tolist()
# openwall = content['openwall_info'].values.tolist()
# oval = content['oval_info'].values.tolist()
# gentoo = content['gentoo_info'].values.tolist()
# cveid=content['_id'].tolist()

# 存放来自两个站点中每个文本的内容，存放形式为列表
# new_exploit = [list(eval(i)[0].values())[0] for i in exploit if len(eval(i)) != 0]
# new_IBM= [list(eval(i)[0].values())[0] for i in IBM if len(eval(i)) != 0]
# new_openwall = [list(eval(i)[0].values())[0] for i in openwall if len(eval(i)) != 0]
# new_oval = [list(eval(i)[0].values())[0] for i in oval if len(eval(i)) != 0]
# new_gentoo = [list(eval(i)[0].values())[0] for i in gentoo if len(eval(i)) != 0]

IBM_test='[{"https://exchange.xforce.ibmcloud.com/vulnerabilities/46376":{"title":"VLC Media Player RealText demuxer buffer overflow","description":"VLC Media Player is vulnerable to a stack-based buffer overflow, caused by improper bounds checking by the RealText demuxer. By persuading a victim to open a specially-crafted RealText subtitle file, a remote attacker could overflow a buffer and execute arbitrary code on the system with elevated privileges or cause the application to crash.","result":"Gain Access"}}]'
oval_test='[{"https://oval.cisecurity.org/repository/search/definition/oval%3Aorg.mitre.oval%3Adef%3A14329":"Stack-based buffer overflow in VideoLAN VLC media player 0.9.x before 0.9.6 might allow user-assisted attackers to execute arbitrary code via an an invalid RealText (rt) subtitle file related to the ParseRealText function in modules/demux/subtitle.c.  NOTE: this issue was SPLIT from CVE-2008-5032 on 20081110."}]'
gentoo_test='[{"http://security.gentoo.org/glsa/glsa-200812-24.xml":{"description":"Tobias Klein reported the following vulnerabilities:","version":"<0.9.8a","impact":"A remote attacker could entice a user to open a specially crafted CUE     image file, RealMedia file or RealText subtitle file, possibly     resulting in the execution of arbitrary code with the privileges of the     user running the application."}}]'
openwall_test='[{"http://www.openwall.com/lists/oss-security/2008/11/05/4":"Date: Wed, 5 Nov 2008 23:17:11 +0200\nFrom: R茅mi Denis-Courmont <rem@...eolan.org>\nTo: oss-security@...ts.openwall.com\nSubject: VideoLAN security advisory 0810\n\nSummary           : Buffer overflows in VLC RealText and CUE demuxers\nDate              : November 2008\nAffected versions : VLC media player 0.9.5 down to 0.5.0\nID                : VideoLAN-SA-0810\nCVE reference     : None yet.\n\n\n- Details -\n\nWhen parsing the header of an invalid CUE image file or an invalid RealText \nsubtitle file, stack-based buffer overflows might occur. \n\n\n- Impact -\n\nIf successful, a malicious third party could trigger execution of arbitrary \ncode within the context of the VLC media player. \n\n\n- Threat mitigation -\n\nExploitation of this issue requires the user to explicitly open a specially \ncrafted file. \n\n\n- Workarounds -\n\nThe user should refrain from opening files from untrusted third parties or \naccessing untrusted remote sites (or disable the VLC browser plugins), until \nthe patch is applied. \nAlternatively, the VCD and Subtitles plugins (libvcd_plugin.* and \nlibsubtitle_plugin.*) can be removed manually from the VLC plugin \ninstallation directory. However, this will prevent use of subtitle files and \nVideo CD altogether.\n\n\n- Solution -\n\nVLC media player 0.9.6 addresses this issue. Patches for older versions are \navailable from the official VLC source code repository 0.9-bugfix branch. \n\n\n- Credits -\n\nThese vulnerabilities were reported by Tobias Klein. \n\n\n- References -\n\nThe VideoLAN project\n\thttp://www.videolan.org/ \nTobias Klein\n\thttp://www.trapkit.de/advisories/ \n\n\n- History -\n\n3 November 2008\n\tVendor notification.\n4 November 2008\n\tInternal patches for VLC development version and 0.9-bugfix tree.\n5 November 2008\n\tInitial security advisory.\n\tVLC media player 0.9.6 released.\n\n-- \nR茅mi Denis-Courmont,\non behalf of the VideoLAN project"},{"http://www.openwall.com/lists/oss-security/2008/11/05/5":"Date: Wed, 5 Nov 2008 23:30:34 +0100\nFrom: Nico Golde <oss-security+ml@...lde.de>\nTo: oss-security@...ts.openwall.com\nSubject: CVE id request: vlc\n\nHi,\ncan I get a CVE id for:\nhttp://www.videolan.org/security/sa0810.html\n\nCheers\nNico\n\n-- \nNico Golde - http://www.ngolde.de - nion@...ber.ccc.de - GPG: 0x73647CFF\nFor security reasons, all text in this mail is double-rot13 encrypted.\n\nContent of type \"application/pgp-signature\" skipped"},{"http://www.openwall.com/lists/oss-security/2008/11/10/13":"Date: Mon, 10 Nov 2008 21:10:47 +0100\nFrom: Nico Golde <oss-security+ml@...lde.de>\nTo: oss-security@...ts.openwall.com, coley@...re.org, rem@...eolan.org\nSubject: Re: CVE id request: vlc\n\nHi,\n* Steven M. Christey <coley@...us.mitre.org> [2008-11-10 19:09]:\n> ======================================================\n> Name: CVE-2008-5032\n> Status: Candidate\n> URL: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5032\n> Reference: MLIST:[oss-security] 20081105 CVE id request: vlc\n> Reference: URL:http://www.openwall.com/lists/oss-security/2008/11/05/5\n> Reference: MLIST:[oss-security] 20081105 VideoLAN security advisory 0810\n> Reference: URL:http://www.openwall.com/lists/oss-security/2008/11/05/4\n> Reference: MISC:http://www.trapkit.de/advisories/TKADV2008-011.txt\n> Reference: MISC:http://www.trapkit.de/advisories/TKADV2008-012.txt\n> Reference: CONFIRM:http://git.videolan.org/?p=vlc.git;a=commitdiff;h=5f63f1562d43f32331006c2c1a61742de031b84d\n> Reference: CONFIRM:http://git.videolan.org/?p=vlc.git;a=commitdiff;h=e3cef651125701a2e33a8d75b815b3e39681a447\n> Reference: CONFIRM:http://www.videolan.org/security/sa0810.html\n> \n> Multiple stack-based buffer overflows in VideoLAN VLC media player\n> 0.5.0 through 0.9.5 allow user-assisted attackers to execute arbitrary\n> code via (1) the header of an invalid CUE image file, related to\n> modules/access/vcd/cdrom.c; or (2) an invalid RealText (rt) subtitle\n> file, related to the ParseRealText function in\n> modules/demux/subtitle.c.\n\nCould you split that up into two CVE ids? I ask because the \nrealtext issue doesn\'t affect versions < 0.9.x which is the \ncase for the version we have in Debian so I can not use a \nfixed version + not-affected for one CVE id in our security \ntracker.\n\nKind regards\nNico\n-- \nNico Golde - http://www.ngolde.de - nion@...ber.ccc.de - GPG: 0x73647CFF\nFor security reasons, all text in this mail is double-rot13 encrypted.\n\nContent of type \"application/pgp-signature\" skipped"}]'

IBM_test_description=list(eval(IBM_test)[0].values())[0]['description']
oval_test_description=list(eval(oval_test)[0].values())[0]
gentoo_test_impact=list(eval(gentoo_test)[0].values())[0]['impact']
gentoo_test_description=list(eval(gentoo_test)[0].values())[0]['description']

import spacy

nlp = spacy.load('en_core_web_md')
# nlp.max_length = 1500000

def get_sent(docs):
    '''
    该函数用于将文本段中的句子提取出来，主要针对exploit-db、openwall这一类的站点
    :param docs:
    :return:
    '''
    counts=docs.count('\n\n')
    detail=docs.split('\n\n',counts)           #按“”
    connect_sent=[]
    for value in detail[1:]:
        print(value)
        temp_sent=''
        for item in value.split('\n',value.count('\n')):
            if item.startswith('>'):
                item=item.replace('>','').strip()
            temp_sent=temp_sent+" "+item
        connect_sent.append(temp_sent)
    return connect_sent

#暂时不用下面这个函数
def split_by_spacy(txt):
    '''

    :param txt: 每一个文本
    :return: spacy分句的文本块
    '''
    doc = nlp(txt)
    value = []
    for sent in doc.sents:
        value.append(str(sent))
    return value

# step2：将包含在属性中的值提取出来，并且从该文本块中删除出来【是否可以构建一个大约200维的属性表格】

exploit_db_attrs_dict = ['title', 'dork', 'date', 'author', 'vendor', 'software', 'version',
                         'tested on', 'cve', 'vulnerability type', 'product', 'application',
                         'platform', 'discovered by', 'source', 'name', 'summary','description']

openwall_attrs_dict = ['Date', 'From', 'To', 'Subject', 'CC']

# step3：针对那些留下的文本，先将句子进行重组【需要确定一下重组的规则】
# step4：判断每一个句子，若一个句子满足“主语+谓语”或“宾语+被动谓语”的形式，那么该文本可以构成一个完整的句子。

def split_by_tag(text,tag):     #考虑到exploitdb中每一段结束后都将使用“\r\n\r\n”作为一个块的结束
    tag_value=text.count(tag)
    split_reslut=text.split(tag,tag_value)
    return [item.strip() for item in split_reslut]

exp_db_test=new_exploit[0]

split_result=split_by_tag(exp_db_test,'\r\n\r\n')


def longestCommonSequence(str1, str2):  # 求两个字符串的最长公共子序列
    len1 = len(str1)
    len2 = len(str2)

    record = [[0 for i in range(len2 + 1)] for j in range(len1 + 1)]
    for i in range(len1):
        for j in range(len2):
            if str1[i] == str2[j]:
                record[i + 1][j + 1] = record[i][j] + 1
            elif record[i + 1][j] > record[i][j + 1]:
                record[i + 1][j + 1] = record[i + 1][j]
            else:
                record[i + 1][j + 1] = record[i][j + 1]
    return record[-1][-1]

assert 0

attrs = {}
for item in exp_db_test:
    key = item.split(":")[0].replace("#", '').strip()
    value = item.split(":")[1]
    if key in exploit_db_attrs_dict:
        attrs[key] = value
    else:
        for detail_attr in exploit_db_attrs_dict:
            common_len = longestCommonSequence(detail_attr, key)
            if common_len / len(detail_attr) >= 0.95 or str(common_len) in str(detail_attr):
                attrs[key] = value
assert 0

def explotit_db_sentence_recongnization(txt):
    '''

    :param txt: spacy识别出的句子文本
    :return: 每个句子文本中包含的所有句子
    使用了spacy进行二次句子的分段
    '''
    doc = nlp(txt)
    value = []  # 用于存放spacy识别出的各个分句结果
    for sent in doc.sents:
        value.append(str(sent))
    print(value)
    detail_sentence_recongnization_exploitdb(value[0])
    # 遍历每个分句结果，每个分句结果中包含\r,\n,
    # 每一个句子最后以\r\n共同作为结尾，
    # 而如果一行为空的话，则该行的字符串为\r


def detail_sentence_recongnization_exploitdb(spacy_sent_text):
    print(spacy_sent_text)
    assert 0
    tag_count = spacy_sent_text.count('\r\n')
    content = spacy_sent_text.split('\r\n', tag_count)
    length = len(content)
    null_index = []  # 记录所有空字符的位置

    for item in range(length):
        if len(content[item]) == 0:
            null_index.append(item)

    temp_sent = []
    for i in range(len(null_index) - 1):
        start = null_index[i] + 1
        end = null_index[i + 1]
        temp_sent.append(content[start:end])

    temp_sent.insert(0, content[0:null_index[0]])  # 添加起始位置的字符
    temp_sent.insert(len(temp_sent), content[null_index[-1] + 1:length])  # 添加结束位置的字符

    final_sent = []  # 用于存放最终的句子结构
    # 遍历temp_sent中每个元素，分为三个部分：长度为1，长度为2，长度大于2

    # for item in temp_sent:
    #     if len(item) == 1:
    #         final_sent.append(item[0])
    #     elif len(item) == 2:
    #         if item[0].endswith(":"):
    #             final_sent.append(" ".join([item[0], item[1]]))
    #         elif item[0][-1]!='.':#.endswith(".") and item[1][0].islower():
    #             final_sent.append(" ".join([item[0], item[1]]))
    #         else:
    #             final_sent.append(item[0])
    #             final_sent.append(item[1])
    #     elif len(item) >= 2:
    #         detail_len = len(item)
    #         for i in range(0, detail_len - 1):
    #             print(i)
    #             if item[i].endswith(":") or item[i][-1] != '.':# and item[i + 1][0].islower()):  # 如果当前文本以“：”结束，则下一个文本必定为当前文本的后续;
    #                                                                                           # 如果当前文本为小写字第开头且上一个文本不以句号结束，则两者必定为紧邻的两个文本。
    #                 item[i + 1] = item[i] + ' ' + item[i + 1]
    #                 item[i] = ''
    #             # if item[i][-1] != '.' and item[i + 1][0].islower():
    #             #     item[i + 1] = item[i] + ' ' + item[i + 1]
    #             #     item[i] = ''
    #         item = [value for value in item if len(value) != 0]

    for item in temp_sent:
        print(item)
    print('+++++++++++++++++++++++++++++++++++')
    for items in final_sent:
        print(items)


explotit_db_sentence_recongnization(new_exploit[1])

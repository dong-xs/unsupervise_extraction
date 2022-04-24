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

content = pd.read_csv('../data/DongPaper_cve_hyperlink_info_5sites.csv', encoding='ANSI')
# exploit = content['exploit_db_info'].values.tolist()
IBM = content['IBM_info'].values.tolist()
openwall = content['openwall_info'].values.tolist()
oval = content['oval_info'].values.tolist()
gentoo = content['gentoo_info'].values.tolist()
cveid=content['cveid'].tolist()

# 存放来自两个站点中每个文本的内容，存放形式为列表
# new_exploit = [list(eval(i)[0].values())[0] for i in exploit if len(eval(i)) != 0]
for i in range(len(IBM)):
    if len(eval(IBM[i]))!=0:
        print(cveid[i])
        print(list(eval(IBM[i])[0].values())[0])
    if i==10:
        assert 0

assert 0
new_IBM= [list(eval(i)[0].values())[0] for i in IBM if len(eval(i)) != 0]
new_openwall = [list(eval(i)[0].values())[0] for i in openwall if len(eval(i)) != 0]
new_oval = [list(eval(i)[0].values())[0] for i in oval if len(eval(i)) != 0]
new_gentoo = [list(eval(i)[0].values())[0] for i in gentoo if len(eval(i)) != 0]

print(new_IBM)
import spacy

nlp = spacy.load('en_core_web_md')
nlp.max_length = 1500000

def get_sent(docs):
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

print(get_sent(new_openwall[50]))

assert 0

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

# 分站点进行处理，先看exploit_db
# step1:使用spacy分成文本块



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

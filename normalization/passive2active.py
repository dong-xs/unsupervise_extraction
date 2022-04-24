import spacy
import pattern.text.en as en

noundict = {'i':'me', 'we':'us', 'you':'you', 'he':'him', 'she':'her', 'they':'them', 'them':'they', 'her':'she', 'him':'he', 'us':'we', 'me':'i'}

def nouninv(noun):
    n = noun.lower()
    if n in noundict:
        return noundict[n]
    return noun

nlp = spacy.load("en_core_web_md")

def pass2act(doc, rec=False):    #这里的输入是一个文本块
    parse = nlp(doc)     #构建一个spacy的解析类parse
    # print(doc)
    # print([item.tag_ for item in parse])
    # for token in parse:
    #     print('{0}({1}) <-- {2} -- {3}({4})'.format(token.text, token.tag_, token.dep_, token.head.text, token.head.tag_))

    newdoc = ''

    # Init parts of sentence to capture:
    subjpass = ''     #用于存放被动时态的主语
    subj = ''
    verb = ''
    verbtense = ''
    adverb = {'bef':'', 'aft':''}
    part = ''
    prep = ''
    agent = ''
    aplural = False
    advcltree = None
    # aux = list(list(nlp('. .').sents)[0]) # start with 2 'null' elements
    # aux = list(list(nlp('. .').doc)[0])  # start with 2 'null' elements
    aux = ''
    xcomp = ''
    punc = '.'
    # Analyse dependency tree:
    # https://blog.csdn.net/weixin_44826203/article/details/121253732
    for word in parse:  # 针对每一句话中的每一个词
        if word.dep_ == 'advcl':    #advcl:状语从句修饰语
            if word.head.dep_ in ('ROOT', 'auxpass'):      #若当前词的前头依赖关系为ROOT或者被动助词aux，被动助词是修饰被动动词的助动词be等
                advcltree = word.subtree
        if word.dep_ == 'nsubjpass':    #被动名词主语，即被动动词主语位置的非从句成分
            if word.head.dep_ == 'ROOT':
                subjpass = ''.join(w.text_with_ws.lower() if w.tag_ not in ('NNP','NNPS') else w.text_with_ws for w in word.subtree).strip()
        if word.dep_ == 'nsubj':        #名词主语
            subj = ''.join(w.text_with_ws.lower() if w.tag_ not in ('NNP','NNPS') else w.text_with_ws for w in word.subtree).strip()
            if word.head.dep_ == 'auxpass':   #被动助词：指修饰被动动词的辅助词，如be、get、become等
                if word.head.head.dep_ == 'ROOT':
                    subjpass = subj
        if word.dep_ in ('advmod','npadvmod','oprd'):
            #oprd是指对象谓语，是一个小短语中的非VP谓语，其功能类似于对象的谓语：https://blog.csdn.net/weixin_43975374/article/details/107481079
            #npadvmod：名词短语作为副词修饰语
            #advmod：状语/副词修饰语，一个副词或副词短语来修饰另一个词
            if word.head.dep_ == 'ROOT':
                if verb == '':
                    adverb['bef'] = ''.join(w.text_with_ws.lower() if w.tag_ not in ('NNP','NNPS') else w.text_with_ws for w in word.subtree).strip()
                else:
                    adverb['aft'] = ''.join(w.text_with_ws.lower() if w.tag_ not in ('NNP','NNPS') else w.text_with_ws for w in word.subtree).strip()
        if word.dep_ == 'auxpass':
            if word.head.dep_ == 'ROOT':
                if not subjpass:
                    subjpass = subj
        if word.dep_ in ('aux','auxpass','neg'):
            #neg是否定修饰词，其是一个副词，为其头部赋予否定意义
            #aux是助词，是一种辅助动词或情态动词，它能提供关于主动词的进一步信息
            if word.head.dep_ == 'ROOT':
                aux += [word]

        if word.dep_ == 'ROOT':             #找一个词的前提条件是该词必须是一个“ROOT”的依存词
            verb = word.text
            if word.tag_ == 'VB':
                verbtense = en.INFINITIVE    #动词时态为不定式
            elif word.tag_ == 'VBD':
                verbtense = en.PAST          #过去时态
            elif word.tag_ == 'VBG':
                verbtense = en.PRESENT       #现在分词时态
                verbaspect = en.PROGRESSIVE
            elif word.tag_ == 'VBN':         #过去分词时态
                verbtense = en.PAST
            else:
                try:    #此处的处理是针对那种依存分析时出错的情况
                    if word.tag_ in ['VB','VBD','VBG','VBN']:     #在这儿发现，en.tenses(attr)中的参数attr必须是一个动词，且其依存词为"ROOT"，这对依存解析
                        verbtense = en.tenses(word.text)[0][0]
                    else:
                        continue
                except IndexError:
                    pass
        if word.dep_ == 'prt':    #prt是指助词，即短语动词中的介词，构成助-动结构
            if word.head.dep_ == 'ROOT':
                part = ''.join(w.text_with_ws.lower() if w.tag_ not in ('NNP','NNPS') else w.text_with_ws for w in word.subtree).strip()
        if word.dep_ == 'prep':   #prep是指介词修饰语，即任何修饰其中心词含义的介词短语
            if word.head.dep_ == 'ROOT':
                prep = ''.join(w.text_with_ws.lower() if w.tag_ not in ('NNP','NNPS') else w.text_with_ws for w in word.subtree).strip()
        if word.dep_.endswith('obj'):     #若当前词的依赖标签以宾语结尾
            if word.head.dep_ == 'agent':
                if word.head.head.dep_ == 'ROOT':
                    agent = ''.join(w.text + ', ' if w.dep_=='appos' else (w.text_with_ws.lower() if w.tag_ not in ('NNP','NNPS') else w.text_with_ws) for w in word.subtree).strip()
                    aplural = word.tag_ in ('NNS','NNPS')
        if word.dep_ in ('xcomp','ccomp','conj'):
            #xcomp：一个开放的从句补语 (xcomp) 是一个没有内部主语的子句，它修饰了 ADJP|ADVP|VP|SINV|SQ
            #ccomp： 是一个带有内部主语的从句，它修饰 ADJP|ADVP|NML|NP|WHNP|VP|SINV|SQ 的头部。
            #conj：最左边连词的依存关系。
            if word.head.dep_ == 'ROOT':
                xcomp = ''.join(w.text_with_ws.lower() if w.tag_ not in ('NNP','NNPS') else w.text_with_ws for w in word.subtree).strip()
                that = xcomp.startswith('that')
                xcomp = pass2act(xcomp, True).strip(' .')
                if not xcomp.startswith('that') and that:
                    xcomp = 'that '+xcomp
        if word.dep_ == 'punct' and not rec:
            if word.text != '"':
                punc = word.text

    # exit if not passive:
    if subjpass == '':
        # newdoc += str(sent) + ' '
        newdoc += str(parse) + ' '
        # continue

    # if no agent is found:
    if agent == '':
        # what am I gonna do? BITconEEEEEEECT!!!!
        # newdoc += str(sent) + ' '
        newdoc += str(parse) + ' '
        # continue

    # invert nouns:
    agent = nouninv(agent)
    subjpass = nouninv(subjpass)

    # FUCKING CONJUGATION!!!!!!!!!!!!!:
    auxstr = ''
    num = en.SINGULAR if not aplural or agent in ('he','she') else en.PLURAL
    aux.append(aux[0])
    verbaspect = None
    for (pp, p, a, n) in zip(aux,aux[1:],aux[2:],aux[3:]):
        if a.lemma_ == '.':
            continue

        if a.lemma_ == 'not':
            if p.lemma_ == 'be':
                if n.lemma_ == 'be':
                    verbtense = en.tenses(a.text)[0][0]
                    auxstr += en.conjugate('be',tense=en.tenses(p.text)[0][0],number=num) + ' '
                    verbaspect = en.PROGRESSIVE
                else:
                    auxstr += en.conjugate('do',tense=en.tenses(p.text)[0][0],number=num) + ' '
                    verbtense = en.INFINITIVE
            auxstr += 'not '
        elif a.lemma_ == 'be':
            if p.lemma_ == 'be':
                verbtense = en.tenses(a.text)[0][0]
                auxstr += en.conjugate('be',tense=en.tenses(a.text)[0][0],number=num) + ' '
                verbaspect = en.PROGRESSIVE
            elif p.tag_ == 'MD':
                verbtense = en.INFINITIVE
        elif a.lemma_ == 'have':
            num == en.PLURAL if p.tag_ == 'MD' else num
            auxstr += en.conjugate('have',tense=en.tenses(a.text)[0][0],number=num) + ' '
            if n.lemma_ == 'be':
                verbaspect = en.PROGRESSIVE
                verbtense = en.tenses(n.text)[0][0]
        else:
            auxstr += a.text_with_ws
    auxstr = auxstr.lower().strip()

    if verbaspect:
        verb = en.conjugate(verb,tense=verbtense,aspect=verbaspect)
    else:
        verb = en.conjugate(verb,tense=verbtense)

    advcl = ''
    if advcltree:
        for w in advcltree:
            if w.pos_ == 'VERB' and en.tenses(w.text)[0][4] == en.PROGRESSIVE:
                advcl += 'which ' + en.conjugate(w.text,tense=en.tenses(verb)[0][0]) + ' '
            else:
                advcl += w.text_with_ws

    newsent = ' '.join(list(filter(None, [agent,auxstr,adverb['bef'],verb,part,subjpass,adverb['aft'],advcl,prep,xcomp])))+punc
    if not rec:
        newsent = newsent[0].upper() + newsent[1:]
    newdoc += newsent + ' '
    return newdoc

# docs='CMS Pentest report can be found here:https://securelayer7.net/download/pdf/SecureLayer7-Pentest-report-Pagekit-CMS.pdf'
# docs='The car is sold to the man.'
docs='the downloaded file is deleted by the malware.'

print(pass2act(docs))

prev = ''
acts = ''

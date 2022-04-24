#encoding:utf-8

strs='We want to obtain the address of a string so that we can make the Nenuphar.std.properties HashTable* point to it and hence control its structure.'
str1='I have a dog, and my sister likes him very much!'
import spacy
nlp=spacy.load('en_core_web_md')
nlp.max_length=1500000

import neuralcoref
neuralcoref.add_to_pipe(nlp)

doc=nlp(str1)

# 各函数的使用详情可见github页面：https://github.com/huggingface/neuralcoref

print(doc._.has_coref)
print(doc._.coref_clusters)
print(doc._.coref_resolved)
print(doc._.coref_scores)
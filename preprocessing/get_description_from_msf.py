#encoding:utf-8

import os

path='../data/exploits_new/'
dir_list=os.listdir(path)

dir_list=[path+str(item) for item in dir_list]

def get_description(file_path):
    with open(file_path) as f:
        content=f.readlines()
        f.close()

    start_index,end_index=0,0
    length=len(content)

    for i in range(length):
        # if content[i].strip()=="'Description'    => %q{":
        if content[i].strip().startswith("'Description'"):
            start_index=i+1
            break
    for j in range(i+1,length):
        if content[j].strip()=='},':
            end_index=j
            break

    description=content[start_index:end_index]

    description=' '.join([item.strip() for item in description])

    return description

def get_cve(file_path):
    with open(file_path,encoding='utf-8') as f:
        content=f.readlines()
        f.close()
    length = len(content)
    indexes=0

    for i in range(length):
        if "'CVE'" in content[i]:
            indexes=i
            break

    if indexes!=0:
        temp_cve=content[indexes].split(',')[1][:-2].strip()[1:-1]
        cve='CVE-'+str(temp_cve)
        return cve
    else:
        return None

for item in dir_list:
    print(item)
    print(get_cve(item))
    print(get_description(item))
    print('===================================')
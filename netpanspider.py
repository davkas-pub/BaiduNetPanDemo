# coding=utf-8
# @Time : 2018/2/11 11:49
# @Author : 李飞
# -*- coding:utf-8 -*-

import time
import json
import re
import requests
import execjs
import base64
from urllib.parse import urlencode
from requests_toolbelt import MultipartEncoder
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from hashlib import md5
from zlib import crc32
# import progressbar
import sys
from contextlib import closing
import time
import os
from io import BytesIO

try:
    requests.packages.urllib3.disable_warnings()
except:
    pass


# class BufferReader(MultipartEncoder):
#     """将multipart-formdata转化为stream形式的Proxy类
#     """
#     def __init__(self, fields, boundary=None, callback=None, cb_args=(), cb_kwargs=None):
#         self._callback = callback
#         self._progress = 0
#         self._cb_args = cb_args
#         self._cb_kwargs = cb_kwargs or {}
#         super(BufferReader, self).__init__(fields, boundary)
#
#     def read(self, size=None):
#         chunk = super(BufferReader, self).read(size)
#         self._progress += int(len(chunk))
#         self._cb_kwargs.update({
#             'size': self._len,
#             'progress': self._progress
#         })
#         if self._callback:
#             try:
#                 self._callback(*self._cb_args, **self._cb_kwargs)
#             except:  # catches exception from the callback
#                 # raise CancelledError('The upload was cancelled.')
#                 pass
#         return chunk

class BufferReader(BytesIO):
    """
    """

    def __init__(self, filebytes, callback=None):
        self._callback = callback
        self._progress = 0
        self._size = len(filebytes)
        super(BufferReader, self).__init__(filebytes)

    def read(self, size=-1):
        chunk_size = 8192
        chunk = BytesIO.read(self, chunk_size)
        self._progress += int(len(chunk))
        if self._callback:
            self._callback(self._size, self._progress)
        return chunk


class PCSBase():
    def __init__(self, username, password):
        self.session = requests.session()
        self.headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_4) AppleWebKit/537.36 '
                                      '(KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
                        }
        self.session.get('https://pan.baidu.com', headers=self.headers, verify=False)
        self.username = username
        self.password = password
        self.user = {}
        self.cur_gid = self.get_gid()
        self.cur_callback = self.get_callback()
        self.cur_time = self._get_curtime()
        self._initiate()  # 登录成功，并获取session.cookies

    def _initiate(self):
        self.user['token'] = self.get_token()
        # print("token:%s" %(self.get_token()))
        self.login()
        # print("cookies:%s" %(session.cookies['BDUSS']))

    def _get_runntime(self):
        """
        :param path: 加密js的路径,注意js中不要使用中文！估计是pyexecjs处理中文还有一些问题
        :return: 编译后的js环境，不清楚pyexecjs这个库的用法的请在github上查看相关文档
        """
        phantom = execjs.get()  # 这里必须为phantomjs设置环境变量，否则可以写phantomjs的具体路径
        with open('login.js', 'r') as f:
            source = f.read()
        return phantom.compile(source)

    def get_gid(self):
        return self._get_runntime().call('getGid')

    def get_callback(self):
        return self._get_runntime().call('getCallback')

    def _get_curtime(self):
        return int(time.time() * 1000)
        # 抓包也不是百分百可靠啊,这里?getapi一定要挨着https://passport.baidu.com/v2/api/写，才会到正确的路由

    def get_token(self):
        get_data = {
            'tpl': 'netdisk',
            'subpro': 'netdisk_web',
            'apiver': 'v3',
            'tt': self.cur_time,
            'class': 'login',
            'gid': self.cur_gid,
            'logintype': 'basicLogin',
            'callback': self.cur_callback
        }
        self.headers.update(
            dict(Referer='http://pan.baidu.com/', Accept='*/*', Connection='keep-alive', Host='passport.baidu.com'))
        resp = self.session.get(url='https://passport.baidu.com/v2/api/?getapi', params=get_data, headers=self.headers,
                                verify=False)
        if resp.status_code == 200 and self.cur_callback in resp.text:
            # 如果json字符串中带有单引号，会解析出错，只有统一成双引号才可以正确的解析
            # data = eval(re.search(r'.*?\((.*)\)', resp.text).group(1))
            data = json.loads(re.search(r'.*?\((.*)\)', resp.text).group(1).replace("'", '"'))
            return data.get('data').get('token')
        else:
            print('获取token失败')
            return None

    def get_rsa_key(self):
        get_data = {
            'token': self.user['token'],
            'tpl': 'netdisk',
            'subpro': 'netdisk_web',
            'apiver': 'v3',
            'tt': self.cur_time,
            'gid': self.cur_gid,
            'callback': self.cur_callback
        }
        resp = self.session.get(url='https://passport.baidu.com/v2/getpublickey', headers=self.headers, params=get_data)
        if resp.status_code == 200 and self.cur_callback in resp.text:
            data = json.loads(re.search(r'.*?\((.*)\)', resp.text).group(1).replace("'", '"'))
            return data.get('pubkey'), data.get('key')
        else:
            print('获取rsa key失败')
            return None

    def encript_password(self, pubkey):
        """
        import rsa
        使用rsa库加密（法一）
        pub = rsa.PublicKey.load_pkcs1_openssl_pem(pubkey.encode('utf-8'))
        encript_passwd = rsa.encrypt(password.encode('utf-8'), pub)
        return base64.b64encode(encript_passwd).decode('utf-8')

        """
        # pubkey必须为bytes类型
        pub = RSA.importKey(pubkey.encode('utf-8'))
        # 构造“加密器”
        encryptor = PKCS1_v1_5.new(pub)
        # 加密的内容必须为bytes类型
        encript_passwd = encryptor.encrypt(self.password.encode('utf-8'))
        return base64.b64encode(encript_passwd).decode('utf-8')

    def login(self):
        cur_pubkey, cur_key = self.get_rsa_key()
        encript_password = self.encript_password(cur_pubkey)
        post_data = {
            'staticpage': 'http://pan.baidu.com/res/static/thirdparty/pass_v3_jump.html',
            'charset': 'utf-8',
            'token': self.user['token'],
            'tpl': 'netdisk',
            'subpro': 'netdisk_web',
            'apiver': 'v3',
            'tt': self.cur_time,
            'codestring': '',
            'safeflg': 0,
            'u': 'http://pan.baidu.com/disk/home',
            'isPhone': '',
            'detect': 1,
            'gid': self.cur_gid,
            'quick_user': 0,
            'logintype': 'basicLogin',
            'logLoginType': 'pc_loginBasic',
            'idc': '',
            'loginmerge': 'true',
            'foreignusername': '',
            'username': self.username,
            'password': encript_password,
            'mem_pass': 'on',
            # 返回的key
            'rsakey': cur_key,
            'crypttype': 12,
            'ppui_logintime': 33554,
            'countrycode': '',
            'callback': 'parent.' + self.cur_callback
        }
        resp = self.session.post(url='https://passport.baidu.com/v2/api/?login', data=post_data, headers=self.headers)
        if 'err_no=0' in resp.text:
            print('登录成功')
            self.user['BDUSS'] = self.session.cookies['BDUSS']
        else:
            print('登录失败')
            self.user['BDUSS'] = None

    def _request(self, url, data=None, files=None, extra_params=None, callback=None):
        params = {
            'app_id': "250528",
            'BDUSS': self.user['BDUSS'],
            't': str(int(time.time())),
            'bdstoken': self.user['token']
        }
        if extra_params:
            params.update(extra_params)
        # print("params:%s" %params)
        baibupan_header = {"Referer": "http://pan.baidu.com/disk/home",
                           "User-Agent": "netdisk;4.6.2.0;PC;PC-Windows;10.0.10240;WindowsBaiduYunGuanJia"}
        header = dict(baibupan_header.items())
        if data or files:
            api = '%s?%s' % (url, urlencode(params))
            # print("api:%s" %api)
            if data:
                res = self.session.post(api, data=data, verify=False, headers=header)
                return res
            else:
                # print(callback==None)
                (filedata, contenttype) = requests.packages.urllib3.filepost.encode_multipart_formdata(files)
                body = BufferReader(filedata, callback=callback)
            # print("body:%s" %type(body))
            header.update({
                "Content-Type": contenttype
            })
            # print("header:%s" %header)
            res = self.session.post(api, data=body, verify=False, headers=header)
            return res

        else:
            res = self.session.get(url, params=params, verify=False, headers=header, stream=True)

        return res


class PCS(PCSBase):
    def __init__(self, username, password):
        self.username = username
        self.password = password
        super(PCS, self).__init__(self.username, self.password)

    def upload(self, remote_path, file_handler, callback=None):
        params = {
            'method': 'upload',
            'path': remote_path,
            'ondup': "newcopy"
        }
        files = {'file': (str(int(time.time())), file_handler)}
        url = 'https://{0}/rest/2.0/pcs/file'.format('pcs.baidu.com')
        response = self._request(url, files=files, extra_params=params, callback=callback)
        return response

    def rapid_upload(self, remote_path, file_handler, callback=None):
        params = {
            'method': "rapidupload",
            'path': remote_path,
            'ondup': "newcopy"
        }
        url = 'https://{0}/rest/2.0/pcs/file'.format('pcs.baidu.com')
        file_handler.seek(0, 2)
        _BLOCK_SIZE = 2 ** 20  # 1MB大小
        # print(_BLOCK_SIZE)
        content_length = file_handler.tell()
        # print(content_length)
        file_handler.seek(0)

        # 校验段为前 256KB
        first_256bytes = file_handler.read(256 * 1024)
        slice_md5 = md5(first_256bytes).hexdigest()

        content_crc32 = crc32(first_256bytes).conjugate()
        content_md5 = md5(first_256bytes)

        count = 1
        while True:
            block = file_handler.read(_BLOCK_SIZE)
            if callback:
                callback(size=content_length, progress=count * _BLOCK_SIZE)
            count = count + 1
            if not block:
                break
            # 更新crc32和md5校验值
            content_crc32 = crc32(block, content_crc32).conjugate()
            content_md5.update(block)
        data = {
            'content-length': content_length,
            'content-md5': content_md5.hexdigest(),
            'slice-md5': slice_md5,
            'content-crc32': '%d' % (content_crc32.conjugate() & 0xFFFFFFFF)
        }
        response = self._request(url, data=data, extra_params=params, callback=callback)
        return response

    def download(self, remote_path, local_path, callback=None):
        params = {
            'method': "download",
            'path': remote_path
        }
        # 兼容原有域名pcs.baidu.com；使用新域名d.pcs.baidu.com，则提供更快、更稳定的下载服务
        url = 'https://{0}/rest/2.0/pcs/file'.format('d.pcs.baidu.com')
        with closing(self._request(url, extra_params=params)) as response:
            chunk_size = 1024  # 单次请求最大值
            count = 1
            total_size = int(response.headers['content-length'])  # 内容体总大小
            with open(local_path, 'wb') as file:
                for data in response.iter_content(chunk_size=chunk_size):
                    file.write(data)
                    self.progressbar(size=total_size, progress=count * chunk_size, progress_title="正在下载",
                                     finish_title="下载完成")
                    count = count + 1

    def progressbar(self, size=None, progress=None, progress_title="正在上传", finish_title="上传完成"):
        # size：文件总字节数 progress：当前传输完成字节数
        # print("{0} / {1}".format(size, progress))
        if progress < size:
            sys.stdout.write(progress_title + "： " + str(int((progress / size) * 100)) + ' % ' + "\r")
            sys.stdout.flush()
        else:
            progress = size
            sys.stdout.write(finish_title + "： " + str(int((progress / size) * 100)) + ' % ' + "\n")


if __name__ == '__main__':
    username = "18382321517"
    password = "901211feifei"
    pcs = PCS(username, password)
    res = pcs.upload("/hello/word.js", open("login.js", 'rb').read(), callback=pcs.progressbar)
    print(res.content.decode('utf-8'))
    res = pcs.rapid_upload("/hello/word.js", open("login.js", 'rb'), callback=pcs.progressbar)
    print(res.content.decode('utf-8'))
    pcs.download("/hello/word.js", "temp.js")

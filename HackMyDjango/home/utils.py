import os
import string
import uuid
import re
from urllib.parse import urlparse
import socket
from struct import unpack
from requests.utils import requote_uri
from django.contrib.sites import requests

from djangoStudy.settings import UPLOAD_PICS_ALLOWED_EXTENSIONS,UPLOAD_ZIP_ALLOWED_EXTENSIONS


def allowed_pics(filename):
    return '.' in filename and filename.split('.')[-1].lower() in UPLOAD_PICS_ALLOWED_EXTENSIONS

def allowed_zip_file(filename):
    return '.' in filename and filename.split('.')[-1].lower() in UPLOAD_ZIP_ALLOWED_EXTENSIONS
def random_filename(filename):
    ext = os.path.splitext(filename)[1]
    random = f"{uuid.uuid4().hex}{ext}"
    return random_filename

def secure_filename(filename):
    if not re.match(r'^[a-zA-Z0-9_.]+$', filename):
        return False
    if not re.match(r'.*[a-zA-Z0-9]$', filename):
        return False
    dot_counts = filename.count('.')
    if dot_counts >1 :
        return False
    return True

def secure_path(path):
    if not re.match(r'^[a-zA-Z0-9:_./\\]+$', path):
        return False
    # 检查路径必须以字母或数字结尾
    if not re.match(r'.*[a-zA-Z0-9]$', path):
        return False
    return True


# def ip2long(ip_addr):
#     return unpack("!L", socket.inet_aton(ip_addr))[0]
#
#
# def is_inner_ipaddress(ip):
#     ip = ip2long(ip)
#     return ip2long('127.0.0.0') >> 24 == ip >> 24 or \
#     ip2long('10.0.0.0') >> 24 == ip >> 24 or \
#     ip2long('172.16.0.0') >> 20 == ip >> 20 or \
#     ip2long('192.168.0.0') >> 16 == ip >> 16


import re
import socket
from struct import unpack
from urllib.parse import urlparse, urljoin



def check_ssrf(url):
    hostname = urlparse(url).hostname

    def ip2long(ip_addr):
        return unpack("!L", socket.inet_aton(ip_addr))[0]

    def is_inner_ipaddress(ip):
        ip = ip2long(ip)
        return (ip2long('127.0.0.0') >> 24 == ip >> 24 or
                ip2long('10.0.0.0') >> 24 == ip >> 24 or
                ip2long('172.16.0.0') >> 20 == ip >> 20 or
                ip2long('192.168.0.0') >> 16 == ip >> 16)

    try:
        # 检查 URL 格式是否正确
        if not re.match(r"^https?://.*/.*$", url):
            raise BaseException("URL format error")

        # 获取 URL 对应的 IP 地址
        ip_address = socket.getaddrinfo(hostname, 'http')[0][4][0]

        # 检查 IP 地址是否为内网地址
        if is_inner_ipaddress(ip_address):
            raise BaseException("Inner IP address attack")

        return True, "success"
    except BaseException as e:
        return False, str(e)
    except Exception:
        return False, "unknown error"


def is_safe_redirect(url):
    try:
        r = requests.get(url, allow_redirects=False)
        while r.is_redirect:
            location = r.headers['Location']

            # 检查重定向的 URL 是否存在 SSRF 攻击风险
            succ, errstr = check_ssrf(location)
            if not succ:
                raise Exception('SSRF Attack: ' + errstr)

            # 发起新请求，检查下一个重定向
            r = requests.get(location, allow_redirects=False)

        return True, "No SSRF detected"

    except Exception as e:
        return False, str(e)


def secure_url(url):
    ssrf_success, ssrf_message = check_ssrf(url)
    redirect_success, redirect_message = is_safe_redirect(url)

    if ssrf_success and redirect_success:
        return True
    else:
        return False

from django import forms
forms.Form



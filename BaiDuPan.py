# -*-coding:utf-8-*-

"""
    @:author cc
    @:time 2019.6

"""
import pickle
import requests
import json, re
import time, sys, random, os
import rsa, base64
import getpass
from urllib.parse import unquote, quote, urlencode

logFileName = str(time.asctime()).replace(':', '/') + "_log.txt"
logFileName=logFileName[:10]+logFileName[-13:]


class Logger():
    def __init__(self, filename=logFileName):
        self.terminal = sys.stdout
        self.log = open(filename, "a+")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        self.log.flush()


path = os.path.abspath(os.path.dirname(__file__))
type = sys.getfilesystemencoding()
sys.stdout = Logger()


cookieFile = '_Cookies'
specialCharact = 'echo: '
error = 'Error:\t'
warn = 'Warn:\t'
notice = 'Notice:\t'
success = 'Success:\t'
fail = 'Fail:\t'


class BaseLogin():
    def __init__(self, usn, psd):
        self.req = requests.session()
        self.usn = usn
        self.psd = psd
        global cookieFile
        cookieFile = usn + cookieFile

    def safeReq(self, url, cookies=None, method='GET', data=None, params=None, maxFailTime=5):
        try:
            if 'get' in method.lower():
                resp = requests.post(url, cookies=cookies, headers=self.headers, params=params)
            elif 'post' in method.lower():
                resp = requests.post(url, cookies=cookies, headers=self.headers, params=params, data=data)
            elif 'sgt' in method.lower():
                resp = self.req.get(url, headers=self.headers, params=params)
            elif 'spt' in method.lower():
                resp = self.req.post(url, headers=self.headers, params=params, data=data)
        except:
            if maxFailTime < 0:
                print(specialCharact)
                print(specialCharact, error, '未访问到数据')
                print(specialCharact)
                return None
            print(specialCharact, fail, '请求失败,休息5秒')
            time.sleep(5)
            return self.safeReq(url, cookies=cookies, method=method, data=data, params=params,
                                maxFailTime=maxFailTime - 1)
        else:
            return resp

    def _getCallBack(self):
        i = 2147483648 * random.random()
        loop = '0123456789abcdefghijklmnopqrstuvwxyz'
        n = i
        a = []
        while n != 0:
            a.append(loop[int(n) % 36])
            n = int(n / 36)
        a.reverse()
        a = ''.join(a)
        return 'bd__cbs__' + a

    def getToken(self):
        params = {
            'tpl': 'netdisk',
            'subpro': 'netdisk_web',
            'apiver': 'v3',
            'tt': self._getTT(),
            'class': 'login',
            'gid': self._getGid(),
            'logintype': 'dialogLogin',
            'callback': self._getCallBack(),
            'alg': 'v3',
            'sig': 'L0RCUXc2S2xwNkNpUldiKzlpZHlYcnBDdWEwZEhyR1M0cTVSbHpwTGN1NzFxTzg5MDd1V1BwN3J4bFZySE1lcQ==',
            'elapsed': '68',
            'shaOne': '00f9f8a0ecf76ffe2eb2782197fa3dd8fb5bb4fb'
        }

        url = 'https://passport.baidu.com/v2/api/?getapi'
        try:
            _resp = self.req.get(url, params=params)
            # _resp=self.safeReq(url,method='SGT',params=params)
            if _resp == None:
                return None
        except:
            print(specialCharact, fail, 'Token请求失败')
            sys.exit()
        else:
            text = _resp.content.decode('utf-8')
            print(text)
            try:
                text = text.replace(' ', '')
                token = re.search("token\":\"(.*?)\"", text).group(1)
            except:
                print(specialCharact, error, 'Token请求出错')
                sys.exit()

            else:
                self.token = token

    def _getGid(self):
        pattern = 'xxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
        result = ''
        for i in range(len(pattern)):
            n = pattern[i]
            if pattern[i] == 'x' or pattern[i] == 'y':
                e = pattern[i]
                t = int(16 * random.random()) | 0
                if e == 'x':
                    n = t | 8
                else:
                    n = 3 & t | 8
                n = hex(n).strip('0x')
            result += n
        return str(result.upper())

    def _getTT(self):
        return str(time.time())[:14].replace('.', '')

    def _getTowKeys(self):
        params = {
            'token': self.token,
            'tpl': 'netdisk',
            'subpro': 'netdisk_web',
            'apiver': 'v3',
            'tt': self._getTT(),
            'gid': self._getGid(),
            'callback': self._getCallBack()
        }
        url = 'https://passport.baidu.com/v2/getpublickey?'
        try:
            # _resp = self.req.get(url, params=params)
            _resp = self.safeReq(url, method='SGT', params=params)
            if _resp == None:
                return None
        except:
            print(specialCharact, fail, "秘钥请求失败")
            sys.exit()
        else:
            text = _resp.content.decode('utf-8')
            try:
                pubKey = re.search("\"pubkey\":'(.*?)'", text).group(1)[:-2].replace(r'\n', '\n')
                key = re.search("\"key\":'(.*?)'", text).group(1).replace(r'\n', '\n')
            except:
                print(specialCharact, fail, "密钥获取失败")
                sys.exit()
            else:
                self.pubKey = pubKey
                self.key = key

    def _encryptPassword(self):
        pubKey = rsa.PublicKey.load_pkcs1_openssl_pem(self.pubKey)
        encriptPassword = rsa.encrypt(self.psd.encode('utf-8'), pubKey)
        self.encryptPassword = base64.b64encode(encriptPassword)

    def preTasks(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0'
        }
        self.req.get('http://www.baidu.com', headers=self.headers)
        self.getToken()
        self._getTowKeys()
        self._encryptPassword()

    def loginByPhoneChecker(self, text):
        authtoken = unquote(re.search("&authtoken=(.*?)&", text).group(1))
        loginproxy = unquote(re.search("&loginproxy=(.*?)&", text.replace(' ', '')).group(1))
        lstr = unquote(re.search("&lstr=(.*?)&", text).group(1))
        ltoken = unquote(re.search("&ltoken=(.*?)&", text).group(1))
        tpl = unquote(re.search("&tpl=(.*?)&", text).group(1))

        """  发送验证码 """
        # print(re.search("&loginproxy=(.*?)&", text.replace(' ', '')).group(1))

        sUrl = 'https://passport.baidu.com/v2/sapi/authwidgetverify'
        params = {
            'authtoken': unquote(authtoken),
            'type': 'mobile',
            'apiver': 'v3',
            'verifychannel': '',
            'action': 'send',
            'vcode': '',
            'questionAndAnswer': '',
            'needsid': '',
            'rsakey': '',
            'countrycode': '',
            'subpro': 'netdisk_web',
            'u': 'https://pan.baidu.com/disk/home',
            'lstr': lstr,
            'ltoken': ltoken,
            'tpl': tpl,
            'callback': self._getCallBack()
        }

        resp = self.req.get(sUrl, params=params)

        text = resp.content.decode('utf-8')
        # print(text)

        if "110000" in text:
            print(specialCharact, "通过手机验证，手机验证码发送成功")

            url = 'https://passport.baidu.com/v2/sapi/authwidgetverify?'
            vcode = input(specialCharact + "\n手机验证码？\n" + specialCharact)
            params = {
                'authtoken': authtoken,
                'type': 'mobile',
                'jsonp': '1',
                'apiver': 'v3',
                'action': 'check',
                'vcode': vcode,
                'questionAndAnswer': '',
                'needsid': '',
                'rsakey': '',
                'countrycode': '',
                'subpro': 'netdisk_web',
                'u': 'https://pan.baidu.com/disk/home',
                'lstr': lstr,
                'ltoken': ltoken,
                'tpl': tpl,
                'callback': self._getCallBack()
            }

            # resp = self.req.get(url,params=params)
            resp = self.safeReq(url, method='SGT', params=params)
            if resp == None:
                return None
            text = resp.content.decode('utf-8')
            # print(text)
            if "\"errno\":\'110000\'" in text:
                # resp = self.req.get(loginproxy)
                resp = self.safeReq(loginproxy, method='SGT')
                text = resp.content.decode('utf-8')
                # print(text)
                # print(resp.cookies.items())
                # print(self.req.cookies.items())

                if 'error=0' in text:
                    print(specialCharact, success, "登陆成功")

                    loginUrlEncoded = ''
                    try:
                        loginUrl = re.search(r"encodeURI\(\'(.*?)\'\)", text.replace(' ', '')).group(1)

                        # print(loginUrl)

                    except:
                        print(specialCharact, fail, "未访问到登录网址")
                    else:
                        loginUrlEncoded = unquote(loginUrl.replace('\\', ''))
                    # print(loginUrlEncoded)

                    # resp = self.req.get(loginUrlEncoded)
                    resp = self.safeReq(loginUrlEncoded, method='SGT')
                    if resp == None:
                        return None
                    text = resp.content.decode('utf-8')
                    self.dumpCookies()

    def dumpCookies(self):

        with open(cookieFile, 'wb') as fs:
            pickle.dump(requests.utils.dict_from_cookiejar(self.req.cookies), fs)

        with open(cookieFile + '.txt', 'w') as fp:
            for cookie in self.req.cookies.items():
                key, value = cookie
                fp.write(key + ':' + value + '\n')

        print(specialCharact, success, 'Cookie 保存成功')

    def loadCookiesFromInput(self):
        COOKIESDict = {}
        inputText = input(specialCharact + notice + "请输入COOKIES字段:").replace(' ', '')

        for line in inputText.split(";"):
            if len(line) > 0:
                key, value = line.split('=')[0], line.split('=')[-1]
                COOKIESDict.update({key: value})

        cookies = requests.utils.cookiejar_from_dict(COOKIESDict)

        self.req.cookies = cookies
        self.dumpCookies()
        print(specialCharact, success, 'Cookie 加载成功')

    def loadCookies(self):

        self.req.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0',
            }
        if os.path.exists(cookieFile):
            with open(cookieFile, 'rb') as fp:
                cookies = requests.utils.cookiejar_from_dict(pickle.load(fp))
                self.req.cookies = cookies
            print(specialCharact, success, 'Cookie 加载成功')

    def goLogin(self):
        self.preTasks()

        captcha = ''
        codeString = ''
        result = ''
        while True:
            data = {'staticpage': 'http://www.baidu.com/cache/user/html/v3Jump.html',
                    'charset': 'UTF-8',
                    'token': self.token,
                    'tpl': 'pp',
                    'subpro': '',
                    'apiver': 'v3',
                    'tt': self._getTT(),
                    'codestring': codeString,
                    'isPhone': 'false',
                    'safeflg': '0',
                    'u': 'https://passport.baidu.com/',
                    'quick_user': '0',
                    'logLoginType': 'pc_loginBasic',
                    'loginmerge': 'true',
                    'logintype': 'basicLogin',
                    'username': self.usn,
                    'password': self.encryptPassword,
                    'verifycode': captcha,
                    'mem_pass': 'on',
                    'rsakey': self.key,
                    'crypttype': 12,
                    'ppui_logintime': '50928',
                    'callback': 'parent.' + self._getCallBack()
                    }

            url = 'https://passport.baidu.com/v2/api/?login'
            try:
                # _resp=self.req.post(url,data=data)
                _resp = self.safeReq(url, method='SPT', data=data)
                if _resp == None:
                    return None
            except:
                print(specialCharact, fail, "登陆失败")
                sys.exit()
            else:
                result = _resp.content.decode('utf-8')
                if 'err_no=257' in result or 'err_no=6' in result:
                    codeString = re.search("codeString=(.*?)&", result).group(1)
                    captchaUrl = "https://passport.baidu.com/cgi-bin/genimage?" + codeString
                    # resp = self.req.get(captchaUrl)
                    resp = self.safeReq(captchaUrl, method='SGT')
                    if resp == None:
                        return None
                    open('captcha.png', 'wb').write(resp.content)

                    print('\n\n', specialCharact, success, '验证码已成功保存在当前路径下，请阅读验证码并输入\n\n')

                    captcha = input(specialCharact + "验证码？\n" + specialCharact)
                    os.remove('captcha.png')
                    continue
                break

        """  手机验证码 """

        if '120021' in result:
            print(specialCharact, notice, "需要外部验证\n\n")
            self.loginByPhoneChecker(result)

    def login(self):
        print(cookieFile)
        if not os.path.exists(cookieFile):
            print(specialCharact, notice, '未发现配置文件，进行登录操作' + ' .' * 6)
            self.loadCookiesFromInput()
            # self.goLogin()
        else:
            print(specialCharact, notice, '发现配置文件，进行Cookie加载操作' + ' .' * 6)
            self.loadCookies()


class NetFileSaver(BaseLogin):
    """
        1、  主要用于分享链接提取并保存在指定路径的类 (p.s.还可创建目录）
        2、  只需调用save函数即可保存指定链接文件
        3、  初始化参数说明：
            @:param usn 用户名 str
            @:param psd 账号密码 str

        4、  save 函数 参数说明：
            @:param url  分享的链接 str
            @:param code 分享密码 str 内容可为空
            @:param directoryName 保存路径 str
    """

    def __init__(self, usn, psd):
        super().__init__(usn, psd)
        self.login()
        self.bdStoken = 'undefined'
        self.directoryExits = False
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0'
        }
        self.COOKIES = self.req.cookies

    def _getLogid(self):
        t = str(time.time()).split('.')
        t = t[0] + '6590' + '.' + t[-1] + '340251756'
        return base64.b64encode(t.encode()).decode()

    def createNewDiretory(self, pathName):
        params = {
            'a': 'commit',
            'channel': 'chunlei',
            'web': '1',
            'app_id': '250528',
            'bdstoken': self.bdStoken,
            'logid': self._getLogid(),
            'clienttype': '0'
        }

        url = 'https://pan.baidu.com/api/create?'

        data = {
            'path': '/' + pathName,
            'isdir': '1',
            'block_list': '[]',
        }

        resp = requests.post(url, headers=self.headers, params=params, cookies=self.COOKIES, data=data)
        # resp = self.safeReq(url, method='POST', cookies=self.COOKIES,data=data)

        if resp == None:
            return None
        text = resp.content.decode('utf-8')

        if json.loads(text)["errno"] == 0:
            return True
        else:
            return text

    def _needCode(self, shortUrl, code):

        vCodeStr = ''
        vCode = ''
        while True:
            data = {
                "pwd": code,
                'vcode': vCode,
                'vcode_str': vCodeStr
            }
            params = {
                'surl': self.surl,
                't': str(time.time())[:14].replace('.', ''),
                'channel': 'chunlei',
                'web': '1',
                'app_id': '250528',
                'bdstoken': self.bdStoken,
                'logid': self._getLogid(),
                'clienttype': '0'
            }

            verifyUrl = "http://pan.baidu.com/share/verify?" + urlencode(params)
            resp = self.req.post(verifyUrl, headers=self.headers, data=data)

            cookieDict = requests.utils.dict_from_cookiejar(resp.cookies)
            requests.utils.add_dict_to_cookiejar(self.req.cookies, cookieDict)
            self.COOKIES = self.req.cookies

            # resp = self.safeReq(verifyUrl, method='SPT', data=data)
            if resp == None:
                return None
            verifyResult = json.loads(resp.content)

            if not verifyResult:
                return verifyResult

            if verifyResult['errno'] == -62:
                print(specialCharact)
                print(specialCharact, notice, "需要手动输入验证码\tSaving" + ' .' * 6)
                captchaUrl = 'https://pan.baidu.com/api/getcaptcha?'
                params = {
                    'prod': 'shareverify',
                    'web': '1',
                    't': str(time.process_time()),
                    'channel': 'chunlei',
                    'web': '1',
                    'app_id': '250528',
                    'bdstoken': self.bdStoken,
                    'logid': self._getLogid(),
                    'clienttype': '0'
                }
                # vReq = requests.get(captchaUrl, params=params,cookies=self.req.cookies,headers=self.headers)
                vReq = self.safeReq(captchaUrl, method='GET', cookies=self.req.cookies, params=params)
                text = vReq.content.decode('utf-8')
                if vReq == None:
                    return None
                cookieDict = requests.utils.dict_from_cookiejar(vReq.cookies)
                requests.utils.add_dict_to_cookiejar(self.req.cookies, cookieDict)
                self.COOKIES = self.req.cookies

                vCodeStr = json.loads(text)['vcode_str']
                imageUrl = json.loads(text)['vcode_img']
                if len(imageUrl) > 0:
                    # resp = self.req.get(imageUrl.replace('\\', ''))
                    resp = self.safeReq(imageUrl.replace('\\', ''), method='SGT')
                    if resp == None:
                        return None
                    with open('captcha.png', 'wb') as fp:
                        fp.write(resp.content)
                    vCode = input(
                        specialCharact + success + "验证码已保存在当前路径\n" + specialCharact + notice + "请输入验证码\n" + specialCharact + '\t')
                    os.remove('captcha.png')
                    continue

            # print(self.req.cookies)

            break

    def _goSaveFiles(self, data, directoryName):

        if data is not None:
            data = data.group(1)

            # print(data)

            dataLst = json.loads(data)
            try:
                fileLst = dataLst['file_list']['list']
                uk = dataLst['uk']
                shareId = dataLst['shareid']
            except:
                print(specialCharact)
                print(specialCharact, error, '未访问到数据')
                print(specialCharact)
                return None
            else:

                fidLst = []

                for file in fileLst:
                    fsid = file['fs_id']
                    fidLst.append(fsid)

                saveUrl = "https://pan.baidu.com/share/transfer?"
                params = {
                    'shareid': shareId,
                    'from': uk,
                    'channel': 'chunlei',
                    'web': '1',
                    'app_id': '250528',
                    'bdstoken': self.bdStoken,
                    'logid': self._getLogid(),
                    'clienttype': '0'
                }

                data = {
                    'fsidlist': str(fidLst),
                    'path': '/' + directoryName
                }

                # resp = requests.post(saveUrl, params=params, data=data, cookies=self.req.cookies, headers=self.headers)
                resp = self.safeReq(saveUrl, method='POST', params=params, data=data, cookies=self.req.cookies)
                if resp == None:
                    return None
                text = resp.content.decode('utf-8')

                if json.loads(text)["errno"] == 0:
                    return True

                elif json.loads(text)["errno"] == 12:
                    print(specialCharact)
                    print(specialCharact, warn, '目录已存在该文件')
                    print(specialCharact)
                    self.directoryExits = True
                    return True
                else:
                    return text
        else:
            print(specialCharact)
            print(specialCharact, error, '未访问到数据')
            print(specialCharact)
            return None

    def _getShareContent(self, shortUrl, code):
        # print(shortUrl)
        try:
            self.surl = re.search("/s/[1]?(.*)", shortUrl).group(1)
        except:
            return

        targetUrl = 'https://pan.baidu.com/share/init?surl=' + self.surl

        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.1'
        }

        resp = self.req.get(shortUrl, headers=self.headers)

        # resp = self.safeReq(shortUrl, method='SGT')

        if resp == None:
            return None
        text = resp.content.decode('utf-8')

        # print(text)
        # print(resp.url)

        if '不存在' in text or '失踪' in text or '涉及侵权' in text or '删除' in text or '晚了' in text:
            print(specialCharact)
            print(specialCharact, fail, '很遗憾，链接失效')
            print(specialCharact)
            return None

        bdStoken = re.search("bdstoken\"\:\"(.*?)\"", text.replace(' ', ''))

        if bdStoken:
            self.bdStoken = bdStoken.group(1)
        else:
            bdReq = requests.get(shortUrl, headers=self.headers, cookies=self.req.cookies)

            # bdReq=self.safeReq(shortUrl,cookies=self.req.cookies)
            if bdReq == None:
                return None
            bdText = bdReq.content.decode('utf-8')

            cookieDict = requests.utils.dict_from_cookiejar(bdReq.cookies)
            requests.utils.add_dict_to_cookiejar(self.req.cookies, cookieDict)

            bdStoken = re.search("bdstoken\"\:\"(.*?)\"", bdText.replace(' ', ''))
            if bdStoken:
                self.bdStoken = bdStoken.group(1)
            else:
                return None

        if '提取码' in text:
            self.headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0',
                'Referer': targetUrl
            }
            print(specialCharact, notice, '\t需要输入提取码')
            if len(code) > 0:
                print(specialCharact, success, '\t已获取提取码，进行传递', ' .' * 6)
                # print(shortUrl,code)
                self._needCode(shortUrl, code)

                resp = requests.get(shortUrl, headers=self.headers, cookies=self.COOKIES)

                # resp=self.safeReq(shortUrl,method='GET',cookies=self.req.cookies)
                # if resp == None:
                #     return None
                text = resp.content.decode('utf-8')

                # print(text)

            else:
                print(specialCharact, error, '\t提取码为空')
                return None

        elif len(code) == 0:
            print(specialCharact, notice, '\t不需要输入提取码')

            self.headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0',
                'Referer': shortUrl
            }
            matcher = re.search("bdstoken\":\"(.*?)\"", text.replace(' ', ''))
            if matcher is not None:
                self.bdStoken = matcher.group(1)
                # print(self.bdStoken)
        # print(text)
        data = re.search("yunData\.setData\(({.*})", text.replace(' ', ''))

        return data

    def selfSave(self, filename, directoryName, startNumber=0):
        with open(filename, 'r', encoding='utf-8') as fp:
            lines = list(set(fp.readlines()))
            count = len(lines) - startNumber
            for line in lines[startNumber:]:
                try:
                    data = json.loads(line)
                except:
                    print(line)
                    print("出现错误")
                    continue
                url = data['url']
                code = data['code']
                self.save(url, code, directoryName)
                print(specialCharact, '还剩：', str(count))
                count -= 1

            print(specialCharact, fileName,"文件内容保存完毕")

    def save(self, url, code, directoryName):
        """
        调用该函数可保存指定链接文件

        参数说明：
            @:param url  分享的链接 str
            @:param code 分享密码 str 内容可为空
            @:param directoryName 保存路径 str
        """

        data = self._getShareContent(url, code)

        print(specialCharact, '已获取数据')

        # print(data)
        if data is not None:
            if not self.directoryExits:
                reslt = self.createNewDiretory(directoryName)
                if reslt == True:
                    print(specialCharact)
                    print(specialCharact, success, '\t', directoryName + '\t-->\t创建成功')
                    print(specialCharact)
                    self.directoryExits = True
                else:
                    print(specialCharact, fail, '\t', directoryName + '\t-->\t创建失败')
                    return

            reslt = self._goSaveFiles(data, directoryName)
            if reslt == True:
                print(specialCharact, success, 'Save\t\t-->\t', directoryName)
            else:
                print(specialCharact, fail, '保存失败\t\t-->\t', directoryName)

    def simplePath(self, fileName, savePath, startNumber=0):
        with open(fileName, 'r', encoding='utf-8') as fp:
            lines = list(set(fp.readlines()))
            count = len(lines) - startNumber
            for line in lines[startNumber:]:
                self.directoryExits = False
                data = json.loads(line)
                url = data['url']
                code = data['code']
                savePathFin = savePath + '/' + data['title']
                self.save(url, code, savePathFin)
                print(specialCharact, '还剩：', str(count))
                count -= 1


if __name__ == '__main__':
    print(specialCharact,time.asctime())
    print(specialCharact, '进入系统')
    while True:
        userName = 'cfb109'
        passWord = '5'
        userName = input(specialCharact + "请输入您的用户名\n" + specialCharact + '\t')
        passWord = getpass.getpass(specialCharact + '\n' + specialCharact + "请输入您的密码\n" + specialCharact + '\t')

        if len(userName) != 0 and len(passWord) != 0:
            saver = NetFileSaver(userName, passWord)
            fileName = 'songList.json'
            fileName = input(specialCharact + "请输入文件名\n" + specialCharact + '\t')
            savePath = input(specialCharact + '\n' + specialCharact + "请输入保存路径名称\n" + specialCharact + '\t')
            print(specialCharact, notice, "1:所有文件保存在同一路径")
            print(specialCharact, notice, "2:所有文件保存在不同路径(默认)")
            choice = input(specialCharact + notice + "请输入您的选择？\n")
            if '1' in choice:
                saver.selfSave(fileName, savePath)
            else:
                saver.simplePath(fileName, savePath)

        else:
            print(specialCharact, error, '密码格式不正确,重新输入')

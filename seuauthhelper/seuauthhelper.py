"""seuauthhelper.py

This library provides a Python interface for interacting with the Southeast University (SEU) authentication system.

It offers functionality to:
- Login with username and password
- Handle CAPTCHA recognition
- Support SMS 2FA
- Verify login status
- Authenticate services

The module communicates with the SEU auth portal endpoints to facilitate these operations.

Example usage:

    import os
    import pickle
    from seuauthhelper import SEUAuthHelper

    username = "230123456"
    password = "L3tMe1n!"

    helper = SEUAuthHelper()

    if os.path.exists('cookies.pkl'):
        with open('cookies.pkl', 'rb') as f:
            cookies = pickle.load(f)
        helper.update_cookies(cookies)
        print("Cookies loaded")
    else:
        print("No saved cookies found")

    status = helper.login(username, password)
    if status == 0:
        print("Login successful")
    elif status == 2:
        # SMS 2FA required
        helper.send_sms_2fa(username)
        sms_code = input("Enter SMS code: ")
        status = helper.login(username, password, sms_code)
    
    redr_url = helper.auth_service("http://ehall.seu.edu.cn/gsapp/sys/jzxxtjapp/*default/index.do")

Note: This module is specific to the SEU CAS Single Sign-On system and requires valid credentials.

Scratched by tonkov
"""

import requests
import json
import ddddocr
import socket
import sys
import hashlib
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import pickle


class SEUAuthHelper(object):
    _URL_AUTHPAGE = "https://auth.seu.edu.cn/dist/#/dist/main/login"
    _URL_VERIFYTGT = "https://auth.seu.edu.cn/auth/casback/verifyTgt"
    _URL_NEEDCAPTCHA = "https://auth.seu.edu.cn/auth/casback/needCaptcha"
    _URL_GETCAPTCHA = "https://auth.seu.edu.cn/auth/casback/getCaptcha"
    _URL_GETCIPHERKEY = "https://auth.seu.edu.cn/auth/casback/getChiperKey"
    _URL_CASLOGIN = "https://auth.seu.edu.cn/auth/casback/casLogin"
    _URL_SENDSTAGE2CODE = "https://auth.seu.edu.cn/auth/casback/sendStage2Code"

    _USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0"

    def __init__(self,
                 sess_override: requests.Session = requests.Session(),
                 allow_header_override: bool = True) -> None:
        """Initialize the SEUAuthHelper instance.

        Args:
            sess_override (requests.Session, optional): A custom requests session to use for HTTP requests. Defaults to a new session.
            allow_header_override (bool, optional): Whether to set default headers (User-Agent and Content-Type) on the session. Defaults to True. Disabling this may cause authentication issues.
        """
        self._sess = sess_override
        if allow_header_override:
            self._sess.headers.update({
                "User-Agent": self._USER_AGENT,
                "Content-Type": "application/json"
            })
        self._ocr = ddddocr.DdddOcr(show_ad=False)
        
        hostname = socket.gethostname()
        ipaddr = socket.gethostbyname(hostname)
        sysinfo = sys.platform + "; " + hostname + "; " + ipaddr
        self._fake_fingerprint = hashlib.md5(sysinfo.encode()).hexdigest()
    
    @property
    def sess_cookies(self) -> requests.cookies.RequestsCookieJar:
        """Get the current cookies from the session. Use with pickle to save cookies."""
        return self._sess.cookies
    
    def update_cookies(self,
                           new_cookies: requests.cookies.RequestsCookieJar) -> None:
        """Update the session cookies with new cookies. Use with pickle to load saved cookies.

        Args:
            new_cookies (requests.cookies.RequestsCookieJar, optional): The new cookies to add.
        """
        self._sess.cookies.update(new_cookies)

    def empty_cookies(self) -> None:
        """Clear all cookies from the session."""
        self._sess.cookies.clear()

    @property
    def sess(self) -> requests.sessions.Session:
        """Get the current requests session."""
        return self._sess
    
    def switch_session(self, new_sess: requests.sessions.Session = requests.sessions.Session()) -> None:
        """Switch to a new requests session.

        Args:
            new_sess (requests.sessions.Session, optional): The new session to use. Defaults to a new session.
        """
        self._sess = new_sess

    @property
    def is_login(self) -> bool:
        """Check if the user is currently logged in.

        Returns:
            bool: True if logged in, False otherwise.
        """
        resp = self._sess.post(self._URL_VERIFYTGT, data=json.dumps({}))
        resptxt = resp.text
        respdict = json.loads(resptxt)
        return respdict["success"]

    @property
    def need_captcha(self) -> bool:
        """Check if CAPTCHA is required for login.

        Returns:
            bool: True if CAPTCHA is needed, False otherwise.
        """
        resp = self._sess.get(self._URL_NEEDCAPTCHA)
        resptxt = resp.text
        respdict = json.loads(resptxt)
        if respdict["code"] == 200:
            return False
        elif respdict["code"] == 4000:
            return True
        else:
            raise ValueError("Unexpected response from needcaptcha API: %s" % resptxt)

    # def update_phone_otp(self, phone_number: str) -> bool:

    def login(self, username: str, passwd: str, sms2fa: str = "") -> int:
        """Attempt to log in with username and password, optionally with SMS 2FA.

        Args:
            username (str): The username for login.
            passwd (str): The password for login.
            sms2fa (str, optional): The SMS 2FA code if required. Defaults to "".

        Returns:
            int: Login status code.
                - 0: Login successful.
                - 1: Already logged in.
                - 2: SMS 2FA required (request and prompt for sms2fa, then call again).
                - -1: Wrong password.
                - -2: Wrong CAPTCHA.
                - -3: Wrong SMS 2FA code.

        Raises:
            ValueError: If an unexpected response is received from the login API.
        """
        if self.is_login:
            return 1  # Already logged in
        
        captchacode = ""
        if self.need_captcha:
            resp = self._sess.get(self._URL_GETCAPTCHA)
            respctnt = resp.content
            captchacode = self._ocr.classification(respctnt)

        resp = self._sess.post(self._URL_GETCIPHERKEY)
        pubKeyText = ('-----BEGIN RSA PUBLIC KEY-----\n' +
                      json.loads(resp.text)['publicKey']
                      .replace('-', '+')
                      .replace('_', '/') +
                      '\n-----END RSA PUBLIC KEY-----')
        pubKey = RSA.import_key(pubKeyText)
        encModule = PKCS1_v1_5.new(pubKey)
        enc_passwd = encModule.encrypt(passwd.encode())
        enc_b64_passwd = base64.b64encode(enc_passwd).decode()

        payload = {
            "service": "",
            "username": username,
            "password": enc_b64_passwd,
            "captcha": captchacode,
            "rememberMe": True,
            "loginType": "account",
            "wxBinded": False,
            "mobilePhoneNum": "",
            "fingerprint": self._fake_fingerprint
        }

        if sms2fa != "":
            enc_sms2fa = encModule.encrypt(sms2fa.encode())
            enc_b64_sms2fa = base64.b64encode(enc_sms2fa).decode()
            payload["mobileVerifyCode"] = enc_b64_sms2fa

        resp = self._sess.post(self._URL_CASLOGIN, data=json.dumps(payload))
        resptxt = resp.text
        respdict = json.loads(resptxt)
        if respdict['code'] == 402:
            return -1 # Wrong password
        elif respdict['code'] == 4001:
            return -2 # Wrong captcha
        elif respdict['code'] == 503:
            return -3 # Wrong SMS 2FA code
        elif respdict['code'] == 502:
            return 2 # SMS 2FA required
        elif respdict['code'] == 200:
            return 0 # Login success
        else:
            raise ValueError("Unexpected response from cas login API: %s" % resptxt)

    def send_sms_2fa(self, username: str) -> int:
        """Send SMS 2FA code to the user's phone.

        Args:
            username (str): The username to send the SMS to.

        Returns:
            int: Status code.
                - 0: SMS sent successfully.
                - -1: Invalid login state.

        Raises:
            ValueError: If an unexpected response is received from the API.
        """
        payload = {"userId": username}
        resp = self._sess.post(self._URL_SENDSTAGE2CODE, data=json.dumps(payload))
        resptxt = resp.text
        respdict = json.loads(resptxt)

        if respdict['code'] == 200:
            return 0 # SMS sent successfully
        elif respdict['code'] == 5002:
            return -1 # Invalid login state
        else:
            raise ValueError("Unexpected response from sendStage2Code API: %s" % resptxt)
    
    def auth_service(self, service_url: str) -> str | None:
        """Authenticate access to a service and get the redirect URL. Reuqires valid login session.

        Args:
            service_url (str): The URL of the service to authenticate.

        Returns:
            str | None: The redirect URL for the authenticated service, or None if authentication fails.
        """
        payload = {"service": service_url}
        resp = self._sess.post(self._URL_VERIFYTGT, data=json.dumps(payload))

        resptxt = resp.text
        respdict = json.loads(resptxt)
        if "redirectUrl" not in respdict.keys():
            return None
        return respdict["redirectUrl"]
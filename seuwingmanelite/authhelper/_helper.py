import base64
import hashlib
import socket
import ssl
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
import ddddocr
import requests
import urllib3.poolmanager

class SEUAuthHelper:
    """Generic helper class for SEU service authentication."""

    _LOGIN_STATE_CACHE_DURATION = 10  # seconds

    _URL_AUTHPAGE = "https://auth.seu.edu.cn/dist/#/dist/main/login"
    _URL_VERIFYTGT = "https://auth.seu.edu.cn/auth/casback/verifyTgt"
    _URL_NEEDCAPTCHA = "https://auth.seu.edu.cn/auth/casback/needCaptcha"
    _URL_GETCAPTCHA = "https://auth.seu.edu.cn/auth/casback/getCaptcha"
    _URL_GETCIPHERKEY = "https://auth.seu.edu.cn/auth/casback/getChiperKey"
    _URL_CASLOGIN = "https://auth.seu.edu.cn/auth/casback/casLogin"
    _URL_SENDSTAGE2CODE = "https://auth.seu.edu.cn/auth/casback/sendStage2Code"

    _DEFAULT_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0",
        "sec-ch-ua": '"Microsoft Edge";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"'
    }

    def __init__(self):
        self._sess = self._create_legacy_session()
        self._ocr = ddddocr.DdddOcr(show_ad=False)
        hostname = socket.gethostname()
        ipaddr = socket.gethostbyname(hostname)
        sysinfo = sys.platform + "; " + hostname + "; " + ipaddr
        self._fake_fingerprint = hashlib.md5(sysinfo.encode()).hexdigest()

        self._valid_login_timestamp = 0

    def auth_service(self, service_url: str, autoredirect: bool = True) -> int | dict:
        """Authenticate a service. Requires valid login session.

        Args:
            service_url (str): The URL of the service to authenticate.
            autoredirect (bool, optional): If True, automatically follow the redirect URL if authentication succeeds. Defaults to True.

        Returns:
            int or dict: If autoredirect is True, returns 0 on success (redirect followed), -1 on failure, -2 if not logged in.
                         If autoredirect is False, returns the full response dictionary from the API.
        """

        if not self._login_check():
            return -2  # Login state invalid

        resp = self._sess.post(self._URL_VERIFYTGT, json={"service": service_url})
        respdict = resp.json()

        if autoredirect:
            if "redirectUrl" not in respdict.keys():
                return -1
            elif respdict["redirectUrl"] is None:
                return -1
            else:
                self._sess.get(respdict["redirectUrl"])
                return 0
        else:
            return respdict

    def login(self, usernm_arg: str, passwd_arg: str, sms2fa_arg: str = "") -> int:
        """Attempt to log in with username and password, optionally with SMS 2FA.

        Args:
            usernm_input (str): The username for login.
            passwd_input (str): The password for login.
            sms2fa_input (str, optional): The SMS 2FA code if required. Defaults to "".

        Returns:
            int: Login status code.
                - 0: Login successful.
                - 1: Already logged in.
                - 2: SMS 2FA required (request and prompt for sms2fa, then try again).
                - -1: Wrong password.
                - -2: Wrong CAPTCHA.
                - -3: Wrong SMS 2FA code.

        Raises:
            ValueError: If an unexpected response is received from the login API.
        """

        if self._login_check():
            return 1  # Already logged in
        
        captchacode = ""
        if self.need_captcha:
            resp = self._sess.get(self._URL_GETCAPTCHA)
            respctnt = resp.content
            captchacode = self._ocr.classification(respctnt)

        resp = self._sess.post(self._URL_GETCIPHERKEY)
        pubkey_txt = ('-----BEGIN RSA PUBLIC KEY-----\n' +
                      resp.json()['publicKey']
                      .replace('-', '+')
                      .replace('_', '/') +
                      '\n-----END RSA PUBLIC KEY-----')
        public_key = serialization.load_pem_public_key(pubkey_txt.encode())
        encrypted = public_key.encrypt(
            passwd_arg.encode(),
            padding.PKCS1v15()
        )
        enc_b64_passwd = base64.b64encode(encrypted).decode()

        payload = {
            "service": "",
            "username": usernm_arg,
            "password": enc_b64_passwd,
            "captcha": captchacode,
            "rememberMe": True,
            "loginType": "account",
            "wxBinded": False,
            "mobilePhoneNum": "",
            "fingerPrint": self._fake_fingerprint
        }
        if sms2fa_arg != "":
            encrypted_sms = public_key.encrypt(
                sms2fa_arg.encode(),
                padding.PKCS1v15()
            )
            enc_b64_sms2fa = base64.b64encode(encrypted_sms).decode()
            payload["mobileVerifyCode"] = enc_b64_sms2fa
        resp = self._sess.post(self._URL_CASLOGIN, json=payload)
        respdict = resp.json()
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
            raise ValueError(f"Unexpected response from cas login API:\n{resp.text}")

    def send_sms_2fa(self, usernm_arg: str) -> int:
        """Send SMS 2FA code to the user's phone.

        Args:
            usernm_arg (str): The username to send the SMS to.
        Returns:
            int: Status code.
                - 0: SMS sent successfully.
                - -1: Invalid login state.

        Raises:
            ValueError: If an unexpected response is received from the API.
        """

        resp = self._sess.post(self._URL_SENDSTAGE2CODE, json={"userId": usernm_arg})
        respdict = resp.json()

        if respdict['code'] == 200:
            return 0 # SMS sent successfully
        elif respdict['code'] == 5002:
            return -1 # Invalid login state
        else:
            raise ValueError(f"Unexpected response from sendStage2Code API:\n{resp.text}")

    @property
    def is_login(self) -> bool:
        return self._login_check()

    @property
    def need_captcha(self) -> bool:
        """Check if CAPTCHA is required for login.

        Returns:
            bool: True if CAPTCHA is needed, False otherwise.
        """
        resp = self._sess.get(self._URL_NEEDCAPTCHA)
        respdict = resp.json()
        if respdict["code"] == 200:
            return False
        elif respdict["code"] == 4000:
            return True
        else:
            raise ValueError(f"Unexpected response from needcaptcha API:\n{resp.text}")

    @property
    def sess(self) -> requests.Session:
        """Get the current session."""

        return self._sess
    
    @sess.deleter
    def sess(self):
        """Clear the current session."""

        self._sess = self._create_legacy_session()

    @property
    def sess_cookies(self) -> requests.cookies.RequestsCookieJar:
        """Get the current cookies from the session. Intended to use with pickle."""

        return self._sess.cookies
    
    @sess_cookies.setter
    def sess_cookies(self, cookies_input: requests.cookies.RequestsCookieJar):
        """Set the current cookies for the session. Intended to use with pickle."""

        self._sess.cookies = cookies_input
        
    @sess_cookies.deleter
    def sess_cookies(self):
        """Clear the current cookies in the session."""

        self._sess.cookies.clear()

    @classmethod
    def _create_legacy_session(cls) -> requests.Session:
        """Create a legacy session with a custom SSL adapter for HTTPS connections.

        Returns:
            requests.Session: A session configured with legacy SSL support and default headers.
        """

        class _CustomHttpAdapter (requests.adapters.HTTPAdapter):
            def __init__(self, ssl_context=None, **kwargs):
                self.ssl_context = ssl_context
                super().__init__(**kwargs)
            def init_poolmanager(self, connections, maxsize, block=False):
                self.poolmanager = urllib3.poolmanager.PoolManager(
                    num_pools=connections, maxsize=maxsize,
                    block=block, ssl_context=self.ssl_context)

        legacy_sess = requests.Session()
        ctx = ssl._create_unverified_context()
        ctx.options |= 0x40000  # Allow unsafe legacy renegotiation

        legacy_sess.mount('https://', _CustomHttpAdapter(ssl_context=ctx))
        legacy_sess.verify = False
        legacy_sess.headers.update(cls._DEFAULT_HEADERS)

        return legacy_sess

    def _login_check(self, clearcache = False) -> bool:
        """Check login status with caching to avoid frequent API calls.

        Returns True if cached as valid within _LOGIN_STATE_CACHE_DURATION seconds.
        Otherwise, queries the API and updates the cache timestamp if valid.

        Args:
            clearcache (bool): If True, clears the cache before checking, used for forcing api check. Defaults to False.

        Returns:
            bool: True if logged in, False otherwise.
        """

        if clearcache:
            self._valid_login_timestamp = 0

        if time.time() - self._valid_login_timestamp < self._LOGIN_STATE_CACHE_DURATION:
            return True
        else:
            resp = self._sess.post(self._URL_VERIFYTGT, json={})
            loginstate = resp.json()["success"]

            if loginstate:
                self._valid_login_timestamp = time.time()
            else:
                self._valid_login_timestamp = 0

            return loginstate

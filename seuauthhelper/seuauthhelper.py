import requests
import json

class SEUAuthHelper(object):
    _URL_AUTHPAGE = "https://auth.seu.edu.cn/dist/#/dist/main/login"
    _URL_VERIFYTGT = "https://auth.seu.edu.cn/auth/casback/verifyTgt"
    _URL_NEEDCAPTCHA = "https://auth.seu.edu.cn/auth/casback/needCaptcha"
    _USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0"

    def __init__(self,
                 sess_override: requests.sessions.Session = requests.sessions.Session(),
                 ua_override: bool = True) -> None:
        self.sess = sess_override
        if ua_override:
            self.sess.headers.update({"User-Agent": self._USER_AGENT})
            

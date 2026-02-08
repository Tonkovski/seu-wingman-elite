import json
import requests

class SEUWlanHelper(object):
    """Helper class for SEU Campus LAN auth services."""

    _URL_STATCHK = "https://w.seu.edu.cn/drcom/chkstatus?callback="
    _URL_FIND_MAC_ALL = "https://w.seu.edu.cn:802/eportal/?c=Portal&a=find_mac&user_account=%s" # Broken, won't display all MACs, try seuselfservicehelper instead
    _URL_FIND_MAC_BY_IP = "https://w.seu.edu.cn:802/eportal/?c=Portal&a=find_mac&wlan_user_ip=%s"
    _URL_LOGIN_BIND = "https://w.seu.edu.cn:802/eportal/?c=Portal&a=login&login_method=1&user_account=,0,%s&user_password=%s&wlan_user_ip=%s"
    _URL_LOGIN_UNBIND = "https://w.seu.edu.cn:802/eportal/?c=Portal&a=unbind_mac&wlan_user_ip=%s"

    def __init__(self):
        self.sess = requests.Session()
        self._conn_ip = None
        self._conn_mac = None

    def bind_login(self, account: str, passwd: str, bind_ip: str)-> int:
        """Login and bind device to IP with credentials.

        Args:
            account (str): User account.
            passwd (str): User password.
            bind_ip (str): IP address to bind.

        Returns:
            int: 0 on success, -1 wrong credentials, -2 device overlimit, -3 no device attached.
        """

        resp = self.sess.get(self._URL_LOGIN_BIND % (account, passwd, bind_ip))
        resptxt = resp.text
        respdict = json.loads(resptxt[resptxt.find("(")+1:resptxt.rfind(")")])
        self.chk_status()
        if respdict["result"] == "1":
            return 0
        elif respdict["msg"] == "bGRhcCBhdXRoIGVycm9y":
            return -1   # Wrong user/pwd combination
        elif respdict["msg"] == "SW4gdXNlICE=":
            return -2   # Device overlimit
        elif respdict["msg"][:10] == "V2VsY29tZS" or "ret_code" == 2:
            return 0
        elif respdict["msg"] == "" and "ret_code" == 1:
            return -3   # No device attached to IP

    def chk_status(self) -> bool:
        """Check the online status of the local device.

        Returns:
            bool: True if connected, False otherwise.

        Note:
            Updates conn_ip and conn_mac properties.
        """

        resp = self.sess.get(self._URL_STATCHK)
        resptxt = resp.text
        respdict = json.loads(resptxt[resptxt.find("(")+1:resptxt.rfind(")")])

        self._conn_ip = respdict["v46ip"]
        if respdict["result"] == 1:
            self._conn_mac = respdict["olmac"]
            return True
        else:
            self._conn_mac = None
            return False

    def get_info_by_ip(self, query_ip: str) -> dict | None:
        """Query device information by IP address.

        Args:
            query_ip (str): The IP address to query.

        Returns:
            dict or None: Info dict of connected device, None if IP is unbinded/offline.
        """
        resp = self.sess.get(self._URL_FIND_MAC_BY_IP % query_ip)
        resptxt = resp.text
        respdict = json.loads(resptxt[resptxt.find("(")+1:resptxt.rfind(")")])
        if respdict["result"] != "1":
            return None
        else:
            return respdict["list"][0]

    def kick_ip(self, kick_ip: str) -> int:
        """Kick/unbind device from IP.

        Args:
            kick_ip (str): IP address to unbind.

        Returns:
            int: 0 on success, -1 on failure (e.g., IP already offline).
        """
        resp = self.sess.get(self._URL_LOGIN_UNBIND % kick_ip)
        resptxt = resp.text
        respdict = json.loads(resptxt[resptxt.find("(")+1:resptxt.rfind(")")])
        self.chk_status()
        if respdict["result"] == "1":
            return 0
        else:
            return -1

    @property
    def conn_ip(self) -> str | None:
        """Get the connected IP address. Returns None if chk_status() has not been called or device is offline."""

        return self._conn_ip

    @property
    def conn_mac(self) -> str | None:
        """Get the connected MAC address. Returns None if chk_status() has not been called or device is offline."""

        return self._conn_mac
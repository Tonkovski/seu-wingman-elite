"""seuwlanhelper.py

This library provides a Python interface for interacting with the Southeast University (SEU) campus wireless network authentication system.

It offers functionality to:
- Check online status of local and remote devices, including MAC address queries.
- Login and kick (unbind) local and remote devices.

Example usage:

    from seuwlanhelper import SEUWlanHelper

    your_account = "230123456"
    your_password = "L3tMe1n!"
    remote_ip = "10.201.666.777"

    # Check local device status
    helper = SEUWlanHelper()
    if helper.chk_status():
        print(f"Connected to IP: {helper.conn_ip}, MAC: {helper.conn_mac}")
    else:
        print("Not connected")

    # Check remote device status
    info_dict = helper.get_info_by_ip(remote_ip)
    if info_dict is not None:
    remote_mac = helper.fetch_mac_from_dict(info_dict)
    remote_account = helper.fetch_account_from_dict(info_dict)
    

    # See function docs for return values
    # Local device login/bind
    result = helper.bind_login(your_account, your_password, helper.conn_ip)

    # Remote device login/bind
    result = helper.bind_login(your_account, your_password, remote_ip)

    # Local/remote device kick/unbind
    result = helper.kick_ip(helper.conn_ip)
    result = helper.kick_ip(remote_ip)

Note: This library is specific to the SEU campus network and require valid credentials.

Scratched by tonkov
"""

import requests
import json

class SEUWlanHelper(object):
    _URL_STATCHK = "https://w.seu.edu.cn/drcom/chkstatus?callback="
    _URL_FIND_MAC_ALL = "https://w.seu.edu.cn:802/eportal/?c=Portal&a=find_mac&user_account=%s" # Broken, won't display all MACs
    _URL_FIND_MAC_BY_IP = "https://w.seu.edu.cn:802/eportal/?c=Portal&a=find_mac&wlan_user_ip=%s"
    _URL_LOGIN_BIND = "https://w.seu.edu.cn:802/eportal/?c=Portal&a=login&login_method=1&user_account=,0,%s&user_password=%s&wlan_user_ip=%s"
    _URL_LOGIN_UNBIND = "https://w.seu.edu.cn:802/eportal/?c=Portal&a=unbind_mac&wlan_user_ip=%s"

    def __init__(self, auth_session:requests.Session=requests.Session()) -> None:
        """Initialize the SEUWlanHelper instance.

        Args:
            auth_session (requests.Session, optional): A custom requests session to use for HTTP requests. Defaults to a new session.
        """
        self.sess = auth_session
        self._conn_ip = None
        self._conn_mac = None

    @property
    def conn_ip(self) -> str | None:
        """Get the connected IP address. Returns None if chk_status() has not been called."""
        return self._conn_ip

    @property
    def conn_mac(self) -> str | None:
        """Get the connected MAC address. Returns None if chk_status() has not been called."""
        return self._conn_mac

    def chk_status(self) -> bool:
        """Check the online status of the local device.

        Returns True if connected, False otherwise. Updates conn_ip and conn_mac properties.
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

    def fetch_mac_from_dict(self, datadict: dict) -> str | None:
        """Extract MAC address from device info dict, or None if invalid."""
        if datadict is None:
            return None
        else:
            return datadict["online_mac"]
    
    def fetch_account_from_dict(self, datadict: dict) -> str | None:
        """Extract user account from device info dict, or None if invalid."""
        if datadict is None:
            return None
        else:
            return datadict["user_account"]

    def bind_login(self, account: str, passwd: str, bind_ip)-> int:
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

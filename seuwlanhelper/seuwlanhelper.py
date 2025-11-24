"""SEU WLAN Helper Module

This module provides a Python interface for interacting with the Southeast University (SEU) campus wireless network authentication system.

It offers functionality to:
- Check online status of local and remote devices, including MAC address queries
- Login and kick (unbind) local and remote devices

The module communicates with the SEU WLAN portal endpoints to facilitate these operations.

Example usage:

    from seuwlanhelper import SEUWlanHelper

    your_account = "230123456"
    your_password = "L3tMe1n!"
    remote_ip = "10.201.666.777"

    # Check local device status
    helper = SEUWlanHelper()
    if helper.chkStatus():
        print(f"Connected to IP: {helper.conn_ip}, MAC: {helper.conn_mac}")
    else:
        print("Not connected")

    # Check remote device status
    info_dict = helper.getInfoByIp(remote_ip)
    if info_dict is not None:
    remote_mac = helper.fetchMacFromDict(info_dict)
    remote_account = helper.fetchAccountFromDict(info_dict)
    

    # See function docs for return values
    # Local device login/bind
    result = helper.bindLogin(your_account, your_password, helper.conn_ip)

    # Remote device login/bind
    result = helper.bindLogin(your_account, your_password, remote_ip)

    # Local/remote device kick/unbind
    result = helper.kickIp(helper.conn_ip)
    result = helper.kickIp(remote_ip)

Note: This module is specific to the SEU campus network and require valid credentials.

Scratched by tonkov
Version: 0.1
"""

import requests
import json

class SEUWlanHelper(object):
    _url_statchk = "https://w.seu.edu.cn/drcom/chkstatus?callback="
    _url_find_mac_all = "https://w.seu.edu.cn:802/eportal/?c=Portal&a=find_mac&user_account=%s" # Broken, won't display all MACs
    _url_find_mac_by_ip = "https://w.seu.edu.cn:802/eportal/?c=Portal&a=find_mac&wlan_user_ip=%s"
    _url_login_bind = "https://w.seu.edu.cn:802/eportal/?c=Portal&a=login&login_method=1&user_account=,0,%s&user_password=%s&wlan_user_ip=%s"
    _url_login_unbind = "https://w.seu.edu.cn:802/eportal/?c=Portal&a=unbind_mac&wlan_user_ip=%s"

    def __init__(self, auth_session=requests.sessions.Session()) -> None:
        self.sess = auth_session
        self.conn_ip = None
        self.conn_mac = None

    def chkStatus(self) -> bool:
        """Check the online status of the local device.

        Returns True if connected, False otherwise. Updates conn_ip and conn_mac attributes.
        """
        resp = self.sess.get(self._url_statchk)
        resptxt = resp.text
        respdict = json.loads(resptxt[resptxt.find("(")+1:resptxt.rfind(")")])

        self.conn_ip = respdict["v46ip"]
        if respdict["result"] == 1:
            self.conn_mac = respdict["olmac"]
            return True
        else:
            self.conn_mac = None
            return False

    def getInfoByIp(self, query_ip: str) -> dict | None:
        """Query device information by IP address.

        Args:
            query_ip (str): The IP address to query.

        Returns:
            dict or None: Info dict of connected device, None if IP is unbinded/offline.
        """
        resp = self.sess.get(self._url_find_mac_by_ip % query_ip)
        resptxt = resp.text
        respdict = json.loads(resptxt[resptxt.find("(")+1:resptxt.rfind(")")])
        if respdict["result"] != "1":
            return None
        else:
            return respdict["list"][0]

    def fetchMacFromDict(self, datadict: dict) -> str | None:
        """Extract MAC address from device info dict, or None if invalid."""
        if datadict is None:
            return None
        else:
            return datadict["online_mac"]
    
    def fetchAccountFromDict(self, datadict: dict) -> str | None:
        """Extract user account from device info dict, or None if invalid."""
        if datadict is None:
            return None
        else:
            return datadict["user_account"]

    def bindLogin(self, account: str, passwd: str, bind_ip)-> int:
        """Login and bind device to IP with credentials.

        Args:
            account (str): User account.
            passwd (str): User password.
            bind_ip (str): IP address to bind.

        Returns:
            int: 0 on success, -1 wrong credentials, -2 device overlimit, -3 no device attached.
        """
        resp = self.sess.get(self._url_login_bind % (account, passwd, bind_ip))
        resptxt = resp.text
        respdict = json.loads(resptxt[resptxt.find("(")+1:resptxt.rfind(")")])
        self.chkStatus()
        print(respdict)
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
        
    def kickIp(self, kick_ip: str) -> int:
        """Kick/unbind device from IP.

        Args:
            kick_ip (str): IP address to unbind.

        Returns:
            int: 0 on success, -1 on failure (e.g., IP already offline).
        """
        resp = self.sess.get(self._url_login_unbind % kick_ip)
        resptxt = resp.text
        respdict = json.loads(resptxt[resptxt.find("(")+1:resptxt.rfind(")")])
        self.chkStatus()
        print(respdict)
        if respdict["result"] == "1":
            return 0
        else:
            return -1

if __name__ == "__main__":
    pass
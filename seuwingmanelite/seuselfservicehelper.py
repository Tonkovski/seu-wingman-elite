"""seuselfservicehelper.py

This tool lib provides a Python interface for interacting with the Southeast University (SEU) self-service portal.

It offers functionality to:
- Authenticate with the self-service portal
- Get online device lists
- Manage MAC address bindings

Note: This lib is specific to the SEU self-service system and requires valid credentials.

Scratched by tonkov
"""

from .seuauthhelper import SEUAuthHelper
import json
import requests
import re

class SEUSelfserviceHelper(SEUAuthHelper):
    """
    Helper class for SEU self-service operations.

    This class provides methods to interact with the SEU self-service portal,
    including authentication, getting online lists, binding/unbinding MAC addresses, etc.
    """

    _URL_PORTAL = "https://selfservice.seu.edu.cn/Self/"
    _URL_DASHBOARD = "https://selfservice.seu.edu.cn/Self/dashboard"
    _URL_GETONLINELIST = "https://selfservice.seu.edu.cn/Self/dashboard/getOnlineList"
    _URL_MYMAC = "https://selfservice.seu.edu.cn/Self/service/myMac"
    _URL_GETMACLIST = "https://selfservice.seu.edu.cn/Self/service/getMacList"
    _URL_UNBINDMAC = "https://selfservice.seu.edu.cn/Self/service/unbindmac"
    _URL_REFRESHACCOUNT = "https://selfservice.seu.edu.cn/Self/dashboard/refreshaccount"

    @property
    def is_service_authed(self) -> bool:
        """Check if the service is authenticated.

        Returns:
            bool: True if authenticated, False otherwise.

        Raises:
            ValueError: If an unexpected HTTP response code is received from the dashboard.
        """
        resp = self._sess.get(self._URL_DASHBOARD, allow_redirects=False)
        if resp.status_code == 302:
            return False
        elif resp.status_code == 200:
            return True
        else:
            raise ValueError(f"Unexpected response code for selfservice dashboard: {resp.status_code}")

    def auth_service(self) -> int:
        """Authenticate with self-service portal. Requires a valid login session.

        Returns:
            int: 0 if authentication succeeds, -1 if it fails.
        """
        return super().auth_service(self._URL_PORTAL)

    def get_online_list(self) -> dict | None:
        """Get the list of online devices.

        Returns:
            dict | None: Dictionary containing the online list or None if request failed.
            
        Note:
            Each dictionary contains device info with keys: 'brasid', 'downFlow', 'hostName', 'ip', 
            'loginTime', 'mac', 'sessionId', 'terminalType', 'upFlow', 'useTime', 'userId'.
        """
        resp = self._sess.get(self._URL_GETONLINELIST, allow_redirects=False)
        if resp.status_code != 200:
            return None
        resptxt = resp.text
        respdict = json.loads(resptxt)
        return respdict

    def get_bind_list(self) -> dict | None:
        """Get the list of bound MAC addresses.

        Returns:
            dict | None: Dictionary containing the bound MAC list or None if request failed.
            
        Note: 
            The returned dictionary typically contains a list of binded devices, 
            where each device is represented as ['isonline', 'MAC', 'type', 'onlinetime', 'IP'].
        """
        resp = self._sess.get(self._URL_GETMACLIST, allow_redirects=False)
        if resp.status_code != 200:
            return None
        resptxt = resp.text
        respdict = json.loads(resptxt)
        return respdict['rows']
    
    def unbind_mac(self, macaddr: str) -> int:
        """Unbind a MAC address.

        Args:
            macaddr (str): The MAC address to unbind. Format: "1A2B3C4D5E6F"

        Returns:
            int: 0 on success, -1 if login expired.

        Raises:
            ValueError: If CSRF token is invalid or unexpected response.
        """
        resp = self._sess.get(self._URL_MYMAC, allow_redirects=False)
        if resp.status_code != 200:
            return -1 # Login expired
        resptxt = resp.text
        
        refresh_csrf_match_pattern = r"csrftoken: '([a-f0-9\-]{36})',"
        unbind_csrf_match_pattern = r"\"&ajaxCsrfToken=\" \+ '([a-f0-9\-]{36})';"
        refresh_csrftoken = re.search(refresh_csrf_match_pattern, resptxt).group(1)
        unbind_csrftoken = re.search(unbind_csrf_match_pattern, resptxt).group(1)

        payload = {
            "mac": macaddr,
            "ajaxCsrfToken": unbind_csrftoken
        }
        resp = self._sess.get(self._URL_UNBINDMAC, params=payload, allow_redirects=False)
        if resp.status_code == 403:
            raise ValueError("CSRF token invalid when unbinding MAC. The service logic might have changed.")
        else:
            if resp.status_code == 302:
                if resp.headers["Location"] == "myMac":
                    payload = {"ajaxCsrfToken": refresh_csrftoken}
                    self._sess.get(self._URL_REFRESHACCOUNT, allow_redirects=False)
                    return 0
        raise ValueError(f"Unexpected response for mac unbinding: {resp.status_code}")

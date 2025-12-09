"""I got vital devices that I want to keep online all the time.
Unfortunately everytime I log in my iPad, those precious servers got kicked offline.

I want to auto-manage online devices and keep those vital devices online all the time.

Note: This script is for demonstration purpose only. DO NOT USE IT AS IS.
Make your own main.py instead of using this one.
"""

from seuwingmanelite import SEUSelfserviceHelper, SEUWlanHelper
import pickle
import os

myaccount = "230123456"
mypwd = "L3tMeInPlz!"

MAC_MANAGEMENT_DEVICE = "00000000001A"
MAC_VITAL_DEVICE_LIST = ["00000000002B", "00000000003C"]
MAC_REGULAR_DEVICE_LIST = ["00000000004D", "00000000005E"]

# Method 1: Local deployment on vital device.
# Put in crontab, daemon, or simply loop run it.
# Pros:
#   - No need for advanced SSO login handling.
#   - Simple and easy.
# Cons:
#   - Requires the script to be deployed on the vital device.
#   - Unable to achieve centralized management of multiple devices.
def method_1():
    wlan_helper = SEUWlanHelper()
    if wlan_helper.chk_status():
        print(f"This device is online with IP {wlan_helper.conn_ip} and MAC {wlan_helper.conn_mac}.")
    else:
        print("This device is offline, logging in...")
        resp_code = wlan_helper.bind_login(myaccount, mypwd, wlan_helper.conn_ip)
        if resp_code == 0:
            print("Login successful.")
        else:
            print(f"Login failed with code {resp_code}.")  # Check documentation for code meanings.

# Method 2: Advanced centralized management.

# Pros:
#   - Can be deployed on any campus network device other than vital ones.
#   - Centralized management of multiple devices.
# Cons:
#   - The management device must be online first.
#   - Requires pickle with cookies for better performancd.

def method_2():
    # Use method 1 to keep the management device online first.

    if not wlan_helper.chk_status():
        raise ValueError("Your device is offline")

    wlan_helper = SEUWlanHelper()
    selfservice_helper = SEUSelfserviceHelper(wlan_helper.sess)

    # Optional
    if os.path.exists('cookies.pkl'):
        with open('cookies.pkl', 'rb') as f:
            cookies = pickle.load(f)
        selfservice_helper.update_cookies(cookies)
    
    if not selfservice_helper.is_logged_in():
        print("Not logged in, performing SSO login...")
        login_result = selfservice_helper.login(myaccount, mypwd)
        if login_result == 2:
            selfservice_helper.send_sms_2fa()
            sms_code = input("Enter the SMS code sent to your phone: ")
            login_result = selfservice_helper.login(myaccount, mypwd, sms_code)
            # Check and handle login_result according to documentation.

    if not selfservice_helper.is_service_authed:
        selfservice_helper.auth_service()

    bindlist = selfservice_helper.get_bind_list() 
    # Get a list of lists, the inner lists look like ['isonline', 'MAC', 'type', 'onlinetime', 'IP']
    # e.g. 
    # [["0", "00000000002B", "#PC", "2025-12-09 00:00:00", "10.201.123.123"], 
    #  ["1", "00000000004D", "#mobile terminal", "2025-12-09 00:00:00", "10.201.124.124"]]
    for i in bindlist:
        if i[1] in MAC_VITAL_DEVICE_LIST:
            if i[0] == "0":  # Offline
                resp_code = wlan_helper.bind_login(myaccount, mypwd, i[4])
                #Check doc and handle resp_code

    # Kick unimportant devices if needed
    selfservice_helper.unbind_macs(MAC_REGULAR_DEVICE_LIST[0])

# Reminder again, this script is for demonstration purpose only, make your own main.py instead of using this one.
METHOD_CHOICES = 1
if __name__ == "__main__":
    if METHOD_CHOICES == 1:
        method_1()
    elif METHOD_CHOICES == 2:
        method_2()

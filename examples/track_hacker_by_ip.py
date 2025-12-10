"""Someone tried to brute-force my ssh from campus network. My system logs showed his IP address.

I want to track his campus user ID and report him.

Note: This script is for demonstration purpose only. DO NOT USE IT AS IS.

Warning: The example provided might be intrusive and might violate privacy policies when used improperly. Use it responsibly and ethically.
"""

ATTACKER_IP = "10.201.123.123"
from seuwingmanelite import SEUWlanHelper

wlan_helper = SEUWlanHelper()

print(wlan_helper.fetch_account_from_dict(wlan_helper.get_info_by_ip(ATTACKER_IP)))
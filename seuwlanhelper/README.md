# SEU WLAN Helper

A Python module for interacting with the Southeast University (SEU) campus wireless network authentication system.

## Features

- Check online status of local and remote devices, including MAC address queries
- Login and kick (unbind) local and remote devices

## Installation

Clone or download the repository and ensure you have the required dependencies:

```bash
pip install requests
```

## Usage

```python
from seuwlanhelper import SEUWlanHelper

# Initialize helper
helper = SEUWlanHelper()

# Check local device status
if helper.chk_status():
    print(f"Connected to IP: {helper.conn_ip}, MAC: {helper.conn_mac}")
else:
    print("Not connected")

# Check remote device status
remote_ip = "10.201.666.777"
info_dict = helper.get_info_by_ip(remote_ip)
if info_dict is not None:
    remote_mac = helper.fetch_mac_from_dict(info_dict)
    remote_account = helper.fetch_account_from_dict(info_dict)
    print(f"Remote device: MAC {remote_mac}, Account {remote_account}")

# Login/bind to IP
account = "your_account"
password = "your_password"
result = helper.bind_login(account, password, remote_ip)
if result == 0:
    print("Login successful")
elif result == -1:
    print("Wrong credentials")
# See docstrings for other return codes

# Kick/unbind device
result = helper.kick_ip(remote_ip)
if result == 0:
    print("Kick successful")
else:
    print("Kick failed")
```

## API Reference

See the docstrings in `seuwlanhelper.py` for detailed method documentation.

## Note

This module is specific to the SEU campus network and requires valid credentials.

## Author

Scratched by tonkov

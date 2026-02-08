#!/bin/bash

USERNAME="230123456"
PASSWORD=""

URL_STATCHK="https://w.seu.edu.cn/drcom/chkstatus?callback="
URL_LOGIN_BIND="https://w.seu.edu.cn:802/eportal/?c=Portal&a=login&login_method=1&user_account=,0,%s&user_password=%s&wlan_user_ip=%s"

conn_ip=""
conn_mac=""

chk_status() {
    resp=$(curl -s "$URL_STATCHK")
    json=$(echo "$resp" | sed 's/.*callback(//' | sed 's/).*//')
    result=$(echo "$json" | grep -o '"result":[0-9]*' | cut -d: -f2)
    v46ip=$(echo "$json" | grep -o '"v46ip":"[^"]*"' | cut -d'"' -f4)
    conn_ip="$v46ip"
    if [ "$result" -eq 1 ]; then
        olmac=$(echo "$json" | grep -o '"olmac":"[^"]*"' | cut -d'"' -f4)
        conn_mac="$olmac"
        return 0
    else
        conn_mac=""
        return 1
    fi
}

bind_login() {
    account="$1"
    passwd="$2"
    ip="$3"
    url=$(printf "$URL_LOGIN_BIND" "$account" "$passwd" "$ip")
    resp=$(curl -s "$url")
    json=$(echo "$resp" | sed 's/.*callback(//' | sed 's/).*//')
    result=$(echo "$json" | grep -o '"result":"[^"]*"' | cut -d'"' -f4)
    msg=$(echo "$json" | grep -o '"msg":"[^"]*"' | cut -d'"' -f4)
    ret_code=$(echo "$json" | grep -o '"ret_code":[0-9]*' | cut -d: -f2)
    if [ "$result" = "1" ]; then
        return 0
    elif [ "$msg" = "bGRhcCBhdXRoIGVycm9y" ]; then
        return 1  # Wrong credentials
    elif [ "$msg" = "SW4gdXNlICE=" ]; then
        return 2  # Device overlimit
    elif [[ "$msg" == V2VsY29tZS* ]] || [ "$ret_code" -eq 2 ]; then
        return 0
    elif [ -z "$msg" ] && [ "$ret_code" -eq 1 ]; then
        return 3  # No device attached
    else
        return 4  # Unknown error
    fi
}

chk_status
if [ $? -eq 0 ]; then
    :
    # echo "Already online"
else
    if [ -z "$conn_ip" ]; then
        # echo "Failed to get IP address"
        exit 1
    fi
    bind_login "$USERNAME" "$PASSWORD" "$conn_ip"
    case $? in
        0)
            # echo "Login successful"
            ;;
        1)
            # echo "Login failed: Wrong credentials"
            exit 1
            ;;
        2)
            # echo "Login failed: Device overlimit"
            exit 1
            ;;
        3)
            # echo "Login failed: No device attached"
            exit 1
            ;;
        *)
            # echo "Login failed: Unknown error"
            exit 1
            ;;
    esac
fi

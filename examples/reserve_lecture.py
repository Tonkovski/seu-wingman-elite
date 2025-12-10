"""I want to get that online lecture so that I can earn my credit while playing Wolfenstein in my dorm.

Note: This script is for demonstration purpose only. DO NOT USE IT AS IS.
Make your own main.py instead of using this one.
"""

from seuwingmanelite import SEULectureHelper
import pickle
import os

myaccount = "230123456"
mypwd = "L3tMeInPlz!"

lecture_helper = SEULectureHelper()

# Optional, load and store cookies for better performance
if os.path.exists('cookies.pkl'):
    with open('cookies.pkl', 'rb') as f:
        cookies = pickle.load(f)
    lecture_helper.update_cookies(cookies)


# Of course we need to login and auth first
if not lecture_helper.is_logged_in():
    print("Not logged in, performing SSO login...")
    login_result = lecture_helper.login(myaccount, mypwd)
    if login_result == 2:
        lecture_helper.send_sms_2fa()
        sms_code = input("Enter the SMS code sent to your phone: ")
        login_result = lecture_helper.login(myaccount, mypwd, sms_code)
        # Check and handle login_result according to documentation.
if not lecture_helper.is_service_authed:
    lecture_helper.auth_service()

# Some queries
activity_list = lecture_helper.query_activity_list()
my_list = lecture_helper.query_my_list()

# Add some logic to choose which lecture to reserve

target_wid = "a1b2c3d4e5f678901234567890abcdef"
reserve_result = lecture_helper.rsrv_lect(target_wid)
# Handle result according to documentation, add loop if necessary.

# Optional, store cookies for better performance next time
with open('cookies.pkl', 'wb') as f:
    pickle.dump(lecture_helper.sess.cookies, f)
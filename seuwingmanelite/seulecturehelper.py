from .seuauthhelper import SEUAuthHelper
import json
import base64

class SEULectureHelper(SEUAuthHelper):
    _URL_INDEX = "https://ehall.seu.edu.cn/gsapp/sys/jzxxtjapp/*default/index.do"
    _URL_AUTHSERVICE = "http://ehall.seu.edu.cn/gsapp/sys/jzxxtjapp/*default/index.do" # Exactly same as index, but with http
    _URL_QUERYACTIVITYLIST = "https://ehall.seu.edu.cn/gsapp/sys/jzxxtjapp/hdyy/queryActivityList.do"
    _URL_VCODE = "https://ehall.seu.edu.cn/gsapp/sys/jzxxtjapp/hdyy/vcode.do"
    _URL_YYSAVE = "https://ehall.seu.edu.cn/gsapp/sys/jzxxtjapp/hdyy/yySave.do"
    _URL_QUERYMYACTIVITYLIST = "https://ehall.seu.edu.cn/gsapp/sys/jzxxtjapp/hdyy/queryMyActivityList.do"

    @property
    def is_service_authed(self) -> bool:
        """Check if the service is authenticated.

        Returns:
            bool: True if authenticated, False otherwise.

        Raises:
            ValueError: If an unexpected HTTP response code is received.
        """
        resp = self._sess.get(self._URL_INDEX, allow_redirects=False)
        if resp.status_code == 302:
            return False
        elif resp.status_code == 200:
            return True
        else:
            raise ValueError("Unexpected HTTP response code from dashboard: %d" % resp.status_code)

    def auth_service(self) -> int:
        """Authenticate with self-service portal. Requires a valid login session.

        Returns:
            int: 0 if authentication succeeds, -1 if it fails.
        """
        return super().auth_service(self._URL_AUTHSERVICE)
    
    def query_activity_list(self) -> list | None:
        """Query the list of lecture activities.

        Returns:
            list | None: Current existing activity list. None if request failed.

        Notes:
            The returned dict structure in the list is as follows, with dummy data shown:
            {
                "WID": "a1b2c3d4e5f678901234567890abcdef",    // Activity unique identifier
                "JZMC": "【线上】【人文历史】从立德树人到生为首位",    // Lecture name, "讲座名称"
                "JZXL": "b2c3d4e5f678901234567890abcdef12",    // Lecture series identifier, "讲座系列"
                "JZJB": "周树人",    // Lecture guest, "讲座嘉宾"
                "JZSJ": "2025-12-12 19:00:00",    // Lecture time, "讲座时间"
                "HDJSSJ": "2025-12-12 21:00:00",    // Activity end time, "活动结束时间"
                "JZDD": "腾讯会议",    // Lecture location, "讲座地点"
                "ZJR": "周树人",    // Lecturer, "主讲人"
                "JZJS": "介绍我们是如何立德树人生为首位的。",    // Lecture description, "讲座介绍"
                "HDZRS": "350",    // Activity capacity, "活动总人数"
                "ZBF": "人文学院",    // Organizer, "主办方"
                "SZXQ": "3",    // Campus, "所在校区", {"1": "四牌楼校区", "2": "九龙湖校区", "3": "丁家桥校区", "4": "苏州校区", "5": "无锡分校"}
                "YYKSSJ": "2025-12-1 19:00:00",    // Reservation start time, "预约开始时间"
                "YYJSSJ": "2025-12-2 12:00:00",    // Reservation end time, "预约结束时间"
                "JZHB": "316k2i2l2pku3p432nda38812vrc3ooh161",    
                "FBZT": "1",    // Release status, "发布状态", {"-1": "未发布", "0": "已保存未发布", "1": "已发布"}
                "ZJRJS": "鲁迅，原名李大钊，浙江周树人。",    // Lecturer introduction, "主讲人介绍"
                "SFKSYY": 0,    // Whether reservation is open, "是否开始预约"
                "JZXL_DISPLAY": "人文与科学素养系列讲座_人文历史",    // Lecture series display name
                "YYRS": 0,    // Number of reservations, "预约人数"
                "SFXSYQFK": "0",    // Probably means "是否学生疫情防控"
                "SFYXYQFK": "0",    // Probably means "是否优先疫情防控"
                "RN": 1,    // What the hell is this?
                "XTDQSJ": "2025-11-30 09:30:01"    // Current system time, "系统当前时间"
            }
        """
        payload = {"pageIndex": 1, "pageSize": 1000}
        resp = self._sess.post(self._URL_QUERYACTIVITYLIST, params=payload, allow_redirects=False)
        if resp.status_code == 302:
            return None
        elif resp.status_code == 200:
            resptxt = resp.text
            respdict = json.loads(resptxt)
            return respdict['datas']
        else:
            raise ValueError("Unexpected HTTP response code from queryActivityList: %d" % resp.status_code)

    def query_my_list(self) -> list | None:
        """Query the list of current user's reserved activities.

        Returns:
            list | None: Current reserved activity list. None if request failed.

        Notes:
            The returned dict structure in the list is as follows, with dummy data shown:
            {
                "XH": "250123",    // Student ID, "学号"
                "YYSJ": "2025-09-01 09:12:34",    // Reservation time, "预约时间"
                "YYIP": "2409:1234::1, 10.201.123.123, 10.64.123.123",    // Reservation IP, "预约IP", format may change
                "SFDK": "1",    // Whether checked in, "是否打卡"
                "SFWY": "0",    // Whether absent, "是否违约"
                "HD_WID": "a1b2c3d4e5f678901234567890abcdef",    // Activity unique identifier, "活动WID"
                "YYM": "206",    // Reservation code, "预约码"
                "WID": "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",    // Unique identifier, for reservation per chance?
                "JZMC": "【线上】【人文历史】哈基米南北路多",    // Lecture name, "讲座名称"
                "JZSJ": "2025-09-02 18:30:00",    // Lecture time, "讲座时间"
                "HDJSSJ": "2025-09-02 20:30:00",    // Activity end time, "活动结束时间"
                "JZDD": "腾讯会议",    // Lecture location, "讲座地点"
                "ZJR": "叮咚鸡",    // Lecturer, "主讲人"
                "JZJS": "哈基米文化由来已久，因此，本讲座希望引领听众初步熟悉哈基米文化，领略文化内涵。",    // Lecture description, "讲座介绍"
                "HDZRS": "800",    // Activity capacity, "活动总人数"
                "SZXQ": "1",    // Campus, "所在校区", {"1": "四牌楼校区", "2": "九龙湖校区", "3": "丁家桥校区", "4": "苏州校区", "5": "无锡分校"}
                "YYKSSJ": "2025-09-01 09:10:00",    // Reservation start time, "预约开始时间"
                "YYJSSJ": "2025-09-01 09:30:00",    // Reservation end time, "预约结束时间"
                "JZHB": "fh464fs34gfd2fe33f3v26572t3s30f1841",    // Lecture poster, "讲座海报"
                "ZJRJS": "叮咚鸡，大狗叫。",    // Lecturer introduction, "主讲人介绍"
                "FBZT": "1",    // Release status, "发布状态"
                "JZXL": "b2c3d4e5f678901234567890abcdef12",    // Lecture series identifier, "讲座系列"
                "ZBF": "东南大学研究生会",    // Organizer, "主办方"
                "JZXL_DISPLAY": "人文与科学素养系列讲座-其他",    // Lecture series display name, "讲座系列DISPLAY"
                "SFXSYQFK": "1",    // Probably means "是否学生疫情防控"
                "SFYXYQFK": "0",    // Probably means "是否优先疫情防控"
                "SFYXQXYY": "0",    // What the hell is this?
                "SFXSPJ": "0",    // What the hell is this?
                "SFYXPJ": "0",    // What the hell is this?
                "RN": 1,    // What the hell is this?
                "XTDQSJ": "2025-12-3 09:30:01"    // Current system time, "系统当前时间"
            }
        """
        payload = {"pageIndex": 1, "pageSize": 1000}
        resp = self._sess.post(self._URL_QUERYMYACTIVITYLIST, params=payload, allow_redirects=False)
        if resp.status_code == 302:
            return None
        elif resp.status_code == 200:
            resptxt = resp.text
            respdict = json.loads(resptxt)
            return respdict['datas']
        else:
            raise ValueError("Unexpected HTTP response code from queryMyActivityList: %d" % resp.status_code)


    def rsrv_lect(self, wid: str) -> int:
        """Reserve a lecture activity.

        Args:
            wid (str): The unique identifier of the activity to reserve.

        Returns:
            int: 0 if reservation succeeds, -1 if login expired, -2 if verification code error,
                 -3 if reservation not open, -4 if capacity reached or invalid activity.

        Raises:
            ValueError: If an unexpected HTTP response or error message is received.
        """
        resp = self._sess.get(self._URL_VCODE, allow_redirects=False)
        if resp.status_code == 302:
            return -1 # Login expired
        elif resp.status_code != 200:
            raise ValueError("Unexpected HTTP response while requesting for vcode: %d" % resp.status_code)
        
        image_str = json.loads(resp.text)['result']
        vcode_rawimg = base64.b64decode(image_str.split('64,')[1])
        vcode_str = self._ocr.classification(vcode_rawimg)
        
        rsv_data = {
            'HD_WID': wid,
            'vcode': vcode_str
        }

        payload = {'paramJson': json.dumps(rsv_data)}
        resp = self._sess.post(self._URL_YYSAVE, params=payload, allow_redirects=False)
        if resp.status_code == 302:
            return -1 # Login expired
        elif resp.status_code != 200:
            raise ValueError("Unexpected HTTP response while reserving lecture: %d" % resp.status_code)
        
        resptxt = resp.text
        respdict = json.loads(resptxt)
        if respdict['success'] == True:
            return 0
        else:
            err_msg = respdict['msg']
            if err_msg == "验证码错误，请重试！注意不要同时使用多台设备进行预约操作。":
                return -2
            elif err_msg == "尚未开放预约":
                return -3
            elif err_msg == "当前活动预约人数已满，请重新选择":
                return -4    # Capacity reached or invalid activity wid
            else:
                raise ValueError(f"Unexpected error message while reserving lecture: {err_msg}")

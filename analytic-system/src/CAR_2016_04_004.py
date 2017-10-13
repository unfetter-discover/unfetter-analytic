# code: utf-8
'''
NOTICE

This software was produced for the U. S. Government
under Basic Contract No. W15P7T-13-C-A802, and is
subject to the Rights in Noncommercial Computer Software
and Noncommercial Computer Software Documentation
Clause 252.227-7014 (FEB 2012)

Copyright 2016 The MITRE Corporation. All Rights Reserved.
'''

'''
CAR-2016-04-004: Successful Local Account Login
'''

CAR_NUMBER = "CAR_2016_04_004"
CAR_NAME = "Successful Local Account Login"
CAR_DESCRIPTION = "The successful use of Pass The Hash for lateral movement between workstations would trigger event ID 4624 with an event level of information, from the security log. " \
    "This behavior would be a LogonType of 3 using NTLM authenticiation where it is not a domain login and not the ANONYMOUS LOGON account"
ATTACK_TACTIC = "Defense Evasion"
CAR_URL = "https://car-.mitre.org/wiki/CAR-2016-04-004"
ES_INDEX = "winevent_security*"
ES_TYPE = "winevent_security"
ALERT_INDEX = "sitaware"
INDICATOR_ID = "indicator--7522721a-b267-4b21-ad38-910044ce4720"
class CAR_2016_04_004():

    def __init__(self):
        self.car_data = dict(car_name=CAR_NAME,
                             car_number=CAR_NUMBER,
                             car_description=CAR_DESCRIPTION,
                             car_url=CAR_URL,
                             alert_index=ALERT_INDEX,
                             alert_type=CAR_NUMBER,
                             es_type=ES_TYPE,
                             indicator_id=INDICATOR_ID, es_index=ES_INDEX)

    def analyze(self, rdd, begin_timestamp, end_timestamp):
        end = end_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
        begin = begin_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
        rdd = rdd.filter(lambda item: (item[1]["data_model"]["fields"]["event_code"] == 4624))
        rdd = rdd.map(lambda item: (
            item[0],
            {
                "event_code": item[1]["data_model"]["fields"]["event_code"],
                "hostname": item[1]["data_model"]["fields"]["hostname"],
                "@timestamp": item[1]["@timestamp"],
                "data_model": item[1]["data_model"],
                "logon_type": item[1]["LogonType"],
                "authentication_package_name": item[1]["AuthenticationPackageName"],
                "target_user_name": item[1]["TargetUserName"],
                'car_id': CAR_NUMBER,
                'car_name': CAR_NAME,
                'car_description': CAR_DESCRIPTION,
                'car_url': CAR_URL}))
        rdd = rdd.filter(lambda item: (item[1]['target_user_name'] != "ANONYMOUS LOGON"))
        rdd = rdd.filter(lambda item: (item[1]['logon_type'] == "3"))
        rdd = rdd.filter(lambda item: (item[1]['authentication_package_name'] == 'NTLM'))
        rdd = rdd.filter(lambda item: (item[1]["@timestamp"] <= end))
        rdd = rdd.filter(lambda item: (item[1]["@timestamp"] >= begin))
        return rdd

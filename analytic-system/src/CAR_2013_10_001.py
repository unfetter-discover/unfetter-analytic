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
CAR_2013_10_001: User Login Activity Monitoring.
'''

CAR_NUMBER = "CAR_2013_10_001"
CAR_NAME = "User Login Activity Monitoring"
CAR_DESCRIPTION = "Monitoring logon and logoff events for hosts on the "\
    "network is very important for situational awareness. This "\
    "information can be used as both an indicator of unusual activity "\
    "as well as to corroborate activity seen elsewhere."
CAR_URL = "https://car.mitre.org/wiki/CAR-2013-10-001"
ES_INDEX = "winevent_security-*"
ES_TYPE = "winevent_security"
ALERT_INDEX = "sitaware"
INDICATOR_ID = "indicator--f04e6079-0439-47f1-8a3b-d16d459461a9"

class CAR_2013_10_001():
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
        end = end_timestamp.strftime("%Y-%m-%dT%H:%M.%SZ")
        begin = begin_timestamp.strftime("%Y-%m-%dT%H:%M.%SZ")
        rdd = rdd.filter(lambda item: (item[1]["@timestamp"] <= end))
        rdd = rdd.filter(lambda item: (item[1]["@timestamp"] >= begin))

        ''' Login/Logoff EventIDs. Using a list for flexibility '''
        logon_events = [528, 4624]
        logoff_events = [538, 4634]

        ''' Logon and logoff events have different field names, which means we need to break up the filter and mapping into two RDDs and then union them '''

        ''' Filter logon events '''
        logon_rdd = rdd.filter(lambda item: (item[1]["data_model"]["fields"]["event_code"] in logon_events))
        logon_rdd = logon_rdd.map(lambda item: (
            item[0],
            {
                "@timestamp": item[1]["@timestamp"],
                "event_code": item[1]["data_model"]["fields"]["event_code"],
                "hostname": item[1]["data_model"]["fields"]["hostname"],
                "log_name": item[1]["data_model"]["fields"]["log_name"],
                "data_model": item[1]["data_model"],
                "car_id": CAR_NUMBER,
                "car_name": CAR_NAME,
                "car_description": CAR_DESCRIPTION,
                "car_url": CAR_URL,
                "logon_type": item[1]["LogonType"],
                "user_sid": item[1]["SubjectUserSid"],
                "user_name": item[1]["SubjectUserName"],
                "logon_id": item[1]["SubjectLogonId"],
                "category": item[1]["Category"]
            }))

        ''' Filter logoff events '''
        logoff_rdd = rdd.filter(lambda item: (item[1]["data_model"]["fields"]["event_code"] in logoff_events))

        logoff_rdd = logoff_rdd.map(lambda item: (
            item[0],
            {
                "@timestamp": item[1]["@timestamp"],
                "event_code": item[1]["data_model"]["fields"]["event_code"],
                "hostname": item[1]["data_model"]["fields"]["hostname"],
                "log_name": item[1]["data_model"]["fields"]["log_name"],
                "data_model": item[1]["data_model"],
                "car_id": CAR_NUMBER,
                "car_name": CAR_NAME,
                "car_description": CAR_DESCRIPTION,
                "car_url": CAR_URL,
                "logon_type": item[1]["LogonType"],
                "user_sid": item[1]["TargetUserSid"],
                "user_name": item[1]["TargetUserName"],
                "logon_id": item[1]["TargetLogonId"],
                "category": item[1]["Category"]
            }))

        rdd = logon_rdd.union(logoff_rdd)

        return rdd

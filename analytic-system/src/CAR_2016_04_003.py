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
CAR-2016-04-003: User Activity from Stopping Windows Defensive Services
'''

CAR_NUMBER = "CAR_2016_04_003"
CAR_NAME = "User Activity from Stopping Windows Defensive Services"
CAR_DESCRIPTION = "Spyware and malware remain a serious problem and Microsoft developed security services, Windows Defender and Windows Firewall, " \
    "to combat this threat. In the event Windows Defender or Windows Firewall is turned off, administrators should correct the issue immediately " \
    "to prevent the possibility of infection or further infection and investigate to determine if caused by crash or user manipulation. " 
ATTACK_TACTIC = "Defense Evasion"
CAR_URL = "https://car.mitre.org/wiki/CAR-2016-04-003"
ES_INDEX = "winevent_system-*"
ES_TYPE = "winevent_system"
ALERT_INDEX = "alert"
INDICATOR_ID = "indicator--23977a6f-b9b6-44a7-84f3-40add71e1b75"
# Windows Security event 5025


class CAR_2016_04_003():
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
        rdd = rdd.filter(lambda item: (item[1]['data_model']['fields']['event_code'] == 7036))
        rdd = rdd.filter(lambda item: (item[1]["@timestamp"] <= end))
        rdd = rdd.filter(lambda item: (item[1]["@timestamp"] >= begin))
        rdd = rdd.filter(lambda item: (item[1]["param1"] in ["Windows Defender", "Windows Firewall"]))
        rdd = rdd.filter(lambda item: (item[1]["param2"] == "stopped"))
        rdd = rdd.map(lambda item: (item[0],
                                    {'event_code': item[1]["data_model"]["fields"]["event_code"],
                                     'hostname': item[1]["data_model"]["fields"]["hostname"],
                                     '@timestamp': item[1]["@timestamp"],
                                     'data_model': item[1]["data_model"],
                                     'service_name': item[1]["param1"],
                                     'service_action': item[1]["param2"],
                                     'car_id': CAR_NUMBER,
                                     'car_name': CAR_NAME,
                                     'car_description': CAR_DESCRIPTION,
                                     'car_url': CAR_URL}))

        return rdd

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
CAR-2016-04-002: User Activity from Clearing Event Logs
'''

CAR_NUMBER = "CAR_2016_04_002"
CAR_NAME = "User Activity from Clearing Event Logs"
CAR_DESCRIPTION = "It is unlikely that event log data would be cleared during normal operations, and it is likely " \
    "that malicious attackers may try to cover their tracks by clearing an event log. When an event log gets cleared, it " \
    "is suspicious. Alerting when a Clear Event Log is generated could point to this intruder technique. Centrally " \
    "collecting events has the added benefit of making it much harder for attackers to cover their tracks. Event " \
    "Forwarding permits sources to forward multiple copies of a collected event to multiple collectors, thus enabling " \
    "redundant event collection. Using a redundant event collection model can minimize the single point of failure risk."
ATTACK_TACTIC = "Defense Evasion"
CAR_URL = "https://car.mitre.org/wiki/CAR-2016-04-002"
ALERT_INDEX = "alert"
ES_INDEX = "winevent_*"
ES_TYPE = ""
INDICATOR_ID = "indicator--c5e8bc82-d425-49bd-af71-77b908ddf8a9"

class CAR_2016_04_002():
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
        rdd = rdd.filter(lambda item: (item[1]["@timestamp"] <= end_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")))
        rdd = rdd.filter(lambda item: (item[1]["@timestamp"] >= begin_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")))
        rdd = rdd.map(lambda item: (
            item[0],
            {
                "event_code": item[1]["data_model"]["fields"]["event_code"],
                "hostname": item[1]["data_model"]["fields"]["hostname"],
                "log_name": item[1]["data_model"]["fields"]["log_name"],
                "data_model": item[1]["data_model"],
                "@timestamp": item[1]["@timestamp"],
                "car_id": CAR_NUMBER,
                "car_name": CAR_NAME,
                "car_description": CAR_DESCRIPTION,
                "car_url": CAR_URL
            }))
        rdd = rdd.filter(lambda item: (
            ((item[1]["event_code"] in [1100, 1102]) and (item[1]["log_name"] == "Security")) or
            ((item[1]["event_code"] == 104) and (item[1]["log_name"] == "System"))))
        return rdd

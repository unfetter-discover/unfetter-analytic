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
CAR-2014-03-006: Detecting DLL execution via rundll32.exe.
'''

CAR_NUMBER = "CAR_2014_03_006"
CAR_NAME = "RunDLL32.exe monitoring"
CAR_DESCRIPTION = "Adversaries may find it necessary to use Dyanamic-link Libraries (DLLs) to evade defenses. " \
    "One way these DLLs can be executed is through the use of the built-in Windows utility RunDLL32, which allows " \
    "a user to execute code in a DLL, providing the name and optional arguments to an exported entry point."
ATTACK_TACTIC = "Defense Evasion"
CAR_URL = "https://car.mitre.org/wiki/CAR-2014-03-006"
ALERT_INDEX = "sitaware"
ES_INDEX = "sysmon-*"
ES_TYPE = "sysmon_process"
INDICATOR_ID = "indicator--7e34ebee-8014-4e1a-a3a8-639f5afb3e61"

class CAR_2014_03_006():
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
        rdd = rdd.filter(lambda item: (item[1]["data_model"]["action"] == "create"))
        rdd = rdd.map(lambda item: (
            item[0],
            {
                "data_model": item[1]["data_model"],
                "@timestamp": item[1]["@timestamp"],
                "exe": item[1]["data_model"]["fields"]["exe"],
                "car_id": CAR_NUMBER,
                "car_name": CAR_NAME,
                "car_description": CAR_DESCRIPTION,
                "car_url": CAR_URL
            }))

        rdd = rdd.filter(lambda item: (
            (item[1]["exe"].upper() == "RUNDLL32.EXE")
        ))
        return rdd

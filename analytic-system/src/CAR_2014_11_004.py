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
CAR-2014-11-004: Remote PowerShell Sessions
'''

CAR_NUMBER = "CAR_2014_11_004"
CAR_NAME = "Remote PowerShell Sessions"
CAR_DESCRIPTION = "According to ATT&CK, PowerShell can be used over WinRM to remotely run commands on a host. When a remote PowerShell session starts, svchost.exe executes wsmprovhost.exe"
ATTACK_TACTIC = "Execution, Lateral Movement"
CAR_URL = "https://car.mitre.org/wiki/CAR-2014-11-004"
ALERT_INDEX = "alert"
ES_INDEX = "sysmon-*"
ES_TYPE = "sysmon_process"
INDICATOR_ID = "indicator--b422e825-8abe-4b8a-865c-bf3b90295f8e"

class CAR_2014_11_004():
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
                "parent_exe": item[1]["data_model"]["fields"]["parent_exe"],
                "car_id": CAR_NUMBER,
                "car_name": CAR_NAME,
                "car_description": CAR_DESCRIPTION,
                "car_url": CAR_URL
            }))

        rdd = rdd.filter(lambda item: (
            ((item[1]["parent_exe"].upper() == "SVCHOST.EXE") and (item[1]["exe"].upper() == "WSMPROVHOST.EXE"))
        ))
        return rdd

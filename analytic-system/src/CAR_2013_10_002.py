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
CAR_2013_10_002: DLL injection via Load Library.
'''

CAR_NUMBER = "CAR_2013_10_002"
CAR_NAME = "DLL Injection via Load Library"
CAR_DESCRIPTION = "Microsoft Windows allows for processes to remotely create threads within other processes of the same privilege level. " \
    "This functionality is provided via the Windows API CreateRemoteThread. Both Windows and third-party software use this ability for " \
    "legitimate purposes. For example, the Windows process csrss.exe creates threads in programs to send signals to registered callback routines."
CAR_URL = "https://car.mitre.org/wiki/CAR-2013-10-002"
ALERT_INDEX = "alert"
ES_INDEX = "sysmon-*"
ES_TYPE = "sysmon_thread"
INDICATOR_ID = "indicator--b60b69f6-2d4c-41d1-8d3b-cfbf64e98bc2"

class CAR_2013_10_002():
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

        # If there are image paths that you considered approved for remote thread creation, they should listed in good_image_paths
        good_image_paths = []

        rdd = rdd.filter(lambda item: (item[1]["@timestamp"] <= end_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")))
        rdd = rdd.filter(lambda item: (item[1]["@timestamp"] >= begin_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")))
        
        rdd = rdd.map(lambda item: (
            item[0],
            {
                "action": item[1]["data_model"]["action"],
                "start_function": item[1]["data_model"]["fields"]["start_function"],
                "source_image_path": item[1]["data_model"]["fields"]["source_image_path"],
                "data_model": item[1]["data_model"],
                "@timestamp": item[1]["@timestamp"],
                "car_id": CAR_NUMBER,
                "car_name": CAR_NAME,
                "car_description": CAR_DESCRIPTION,
                "car_url": CAR_URL
            }))
        rdd = rdd.filter(lambda item: (item[1]["action"] == "create"))
        rdd = rdd.filter(lambda item: (
            (item[1]["start_function"].upper() in ["LOADLIBRARYA", "LOADLIBRARYW"]) and
            (item[1]["source_image_path"].upper() not in good_image_paths)
        ))
        return rdd

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
import re

'''
CAR-2014-11-002: Outlier Parents of Cmd
'''

CAR_NUMBER = "CAR_2014_11_002"
CAR_NAME = "Outlier Parents of Cmd"
CAR_DESCRIPTION = "Many programs create command prompts as part of their normal operation " \
    "including malware used by attackers. This analytic attempts to identify suspicious programs " \
    "spawning cmd.exe by looking for programs that do not normally create cmd.exe."
ATTACK_TACTIC = "Execution"
CAR_URL = "https://car.mitre.org/wiki/CAR-2014-11-002"
ALERT_INDEX = "sitaware"
ES_INDEX = "sysmon-*"
ES_TYPE = "sysmon_process"
INDICATOR_ID = "indicator--7079f46e-c99e-4f19-bb04-fda80da486f3"
class CAR_2014_11_002():
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
        rdd = rdd.filter(lambda item: (item[1]["@timestamp"] <= end))
        rdd = rdd.filter(lambda item: (item[1]["@timestamp"] >= begin))

        rdd = rdd.filter(lambda item: (item[1]['data_model']['action'] == "create"))

        # Map in the CAR information and rename fields the analytic needs for ease of use
        # This needs to happen after the filter on process create, or some of the fields won't be there
        rdd = rdd.map(lambda item: (
            item[0],
            {'@timestamp': item[1]["@timestamp"],
             'car_id': CAR_NUMBER,
             'car_name': CAR_NAME,
             'car_description': CAR_DESCRIPTION,
             'attack_tactic': ATTACK_TACTIC,
             'car_url': CAR_URL,
             'hostname': item[1]["data_model"]["fields"]["hostname"],
             'exe': item[1]["data_model"]["fields"]["exe"],
             'parent_exe': item[1]["data_model"]["fields"]["parent_exe"],
             'data_model': item[1]["data_model"]
             }))

        rdd = rdd.filter(lambda item: (item[1]['exe'] == "cmd.exe"))
               
            

        return rdd

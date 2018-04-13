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
import itertools
from datetime import datetime
from datetime import timedelta

'''
CAR_2013_03_001: Simultaneous Logins on a Host
'''

CAR_NUMBER = "CAR_2018_03_001"
CAR_NAME = "Powershell with Encoded arguments"
CAR_DESCRIPTION = "Powershell running with Encoded Arguments"
ATTACK_TACTIC = "Defense Evasion"
CAR_URL = "https://attack.mitre.org/wiki/Technique/T1140"
ES_INDEX = "winlogbeat-*"
ES_TYPE = "doc"
INDICATOR_ID = "indicator--a98a7044-b118-464e-b8a6-f18e97591ab0"
ALERT_INDEX = "alert"


class CAR_2018_03_001():
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
        print("Total Records = {}".format(len(rdd.collect())))

        print begin
        print end
        # Filter events based on begin and end time

        rdd = rdd.filter(lambda item: (item[1]['@timestamp'] <= end))
        rdd = rdd.filter(lambda item: (item[1]['@timestamp'] >= begin))

        # filter on process create
        print("After date selection = {}".format(len(rdd.collect())))
        rdd = rdd.filter(lambda item: (
            item[1]['log_name'] == 'Microsoft-Windows-Sysmon/Operational'))
        rdd = rdd.filter(lambda item: (
            item[1]['data_model']['fields']['event_code'] == 1))
        print("Total for event id 1 = {}".format(len(rdd.collect())))

        rdd = rdd.filter(lambda item: (
            item[1]['data_model']['fields']['exe'] == "powershell.exe"))

        print("Just using powershell = {}".format(len(rdd.collect())))

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
             'event_code': item[1]['data_model']['fields']['event_code'],
             'exe': item[1]['data_model']['fields']['exe'],
             'parent_exe': item[1]["data_model"]['fields']['parent_exe'],
             'utc_time': item[1]["data_model"]['fields']["utc_time"],
             'command_line': item[1]["data_model"]['fields']["command_line"],
             'indicator_id': INDICATOR_ID,
             'pid': item[1]["data_model"]["fields"]["pid"],
             'ppid': item[1]["data_model"]["fields"]["ppid"],
             'hostname': item[1]["data_model"]["fields"]["hostname"],
             'process_guid': item[1]["data_model"]["fields"]["process_guid"],
             'parent_process_guid': item[1]["data_model"]["fields"]["parent_process_guid"],
             'event_data': item[1]['data_model']['fields']
             }))

        # Get a list of all the process_guid for CMD.exe that were not created by explorer.exe
        # reg_cmd_rdd = rdd.filter(lambda item: (
        #    item[1]['exe'] == "cmd.exe")).filter(lambda item: (item[1]['parent_exe'] != "explorer.exe"))
        # guid_list = reg_cmd_rdd.map(lambda item: (item[1]['process_guid'])).collect()

        # Filter for all the reg.exe, created by cmd.exe, but cmd.exe was not created by explorer.exe

        return rdd

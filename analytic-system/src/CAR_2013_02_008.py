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

CAR_NUMBER = "CAR_2013_02_008"
CAR_NAME = "Simultaneous Logins on a Host"
CAR_DESCRIPTION = "Multiple users logged into a single machine at the same time, or even within the same hour, do not typically occur in networks we have observed."
ATTACK_TACTIC = "Lateral Movement"
CAR_URL = "https://car.mitre.org/wiki/CAR-2013-02-008"
ES_INDEX = "winevent_security-*"
ES_TYPE = "winevent_security"
INDICATOR_ID = "indicator--a98a7044-b118-464e-b8a6-f18e97591ab0"
ALERT_INDEX = "sitaware"

class CAR_2013_02_008():
    def __init__(self):

        self.car_data = dict(car_name=CAR_NAME,
                             car_number=CAR_NUMBER,
                             car_description=CAR_DESCRIPTION,
                             car_url=CAR_URL,
                             alert_index=ALERT_INDEX,
                             alert_type=CAR_NUMBER,
                             es_type=ES_TYPE,
                             indicator_id=INDICATOR_ID, es_index=ES_INDEX)

    # Some logon activity is part of the normal operation of the operating system.
    # We remove the noise to try and identify legitmate users logons.

    def analyze(self, rdd, begin_timestamp, end_timestamp):
        # Evalutes each tuple in the list to determine if the user logged in close to another.
        # TODO: Make sure we are using the correct datetime. Event Time
        ignore_username_list = ['ANONYMOUS LOGON']
        include_logon_type = ['2', '3', '9', '10']

        def identifyLogon(logon_list, max_minutes):
            # Convert the event_time to UTC time
            # TODO - Move away from "event_time" and store the event time in the data_model
            for item in logon_list:
                item[1]['utc_datetime'] = datetime.strptime(item[1]['utc_time'], "%Y-%m-%dT%H:%M:%SZ")
            logon_list = sorted(logon_list, key=lambda item: item[1]['utc_datetime'])
            bad_logons = []
            for index in range(1, len(logon_list)):
                # If the user changed, and if the difference between user logon is less than an hour
                if (logon_list[index - 1][1]['user_sid'] != logon_list[index][1]['user_sid']) and \
                   ((logon_list[index][1]['utc_datetime'] - logon_list[index - 1][1]['utc_datetime']).total_seconds() <= max_minutes * 60):
                    # Since this means that users had logons during an hour period, the pair are suspect.   Both events are flagged
                    bad_logons.append(logon_list[index][0])
                    bad_logons.append(logon_list[index - 1][0])
            return bad_logons

        end = end_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
        begin = begin_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
        # Filter the event codes for logon
        rdd = rdd.filter(lambda item: (item[1]['data_model']['fields']['event_code'] in [528, 4624]))
        # Filter to only the dates/duration provided

        rdd = rdd.filter(lambda item: (item[1]["@timestamp"] <= end))
        rdd = rdd.filter(lambda item: (item[1]["@timestamp"] >= begin))
        # Ignore the usernames
        rdd = rdd.filter(lambda item: (item[1]["data_model"]["fields"]["user"] not in ignore_username_list))
        # Use only Logon Types for users that log in
        rdd = rdd.filter(lambda item: (item[1]["data_model"]["fields"]["logon_type"] in include_logon_type))
        rdd = rdd.map(lambda item: (
            item[0],
            {'hostname': item[1]["data_model"]["fields"]["hostname"],
                'user_sid': item[1]["data_model"]["fields"]["user_sid"],
                'username': item[1]["data_model"]["fields"]["user"],
                'utc_time': item[1]["data_model"]["fields"]["utc_time"],
                '@timestamp': item[1]["@timestamp"],
                'logon_type': item[1]["data_model"]["fields"]["logon_type"],
                'data_model': item[1]["data_model"],
                'car_id': CAR_NUMBER,
                'car_name': CAR_NAME,
                'car_description': CAR_DESCRIPTION,
                'attack_tactic': ATTACK_TACTIC,
                'car_url': CAR_URL}
        ))

        # Convert RDD to (K,V) where K is hostname and V is the rest of the desired data
        working_rdd = rdd.map(lambda item: ((item[1]['hostname']), (item[0], item[1])))
        # Group by the Hostname
        working_rdd = working_rdd.groupByKey()
        # For each host, determine if there were simultaneous logons
        working_rdd = working_rdd.map(lambda item: (identifyLogon(item[1], 60)))
        # output all the results as a list of ElasticID's that are suspcious logons
        output = list(itertools.chain.from_iterable(working_rdd.collect()))
        # Filter out all the elastic documents that WERE NOT suspicious.
        rdd = rdd.filter(lambda item: (item[0] in output))
        return rdd

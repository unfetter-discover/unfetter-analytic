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
from datetime import datetime
from datetime import timedelta



'''
CAR_2013_04_002: Quick execution of a series of suspicious commands.
'''

CAR_NUMBER = "CAR_2013_04_002"
CAR_NAME = "Quick execution of a series of suspicious commands"
CAR_DESCRIPTION = "Certain commands are frequently used by malicious actors "\
    "and infrequently used by normal users. By looking for execution of "\
    "these commands in short periods of time we can see not only when a "\
    "malicious user was on the system by also get an idea of what it was "\
    "they were doing"
ATTACK_TACTIC = "Discovery, Credential Access, Lateral Movement, Persistence, Privilege Escalation, Defense Evasion, Execution"
ALERT_INDEX = "sitaware"
CAR_URL = "https://car.mitre.org/wiki/CAR-2013-04-002"
ES_INDEX = "sysmon-*"
ES_TYPE = "sysmon_process"
INDICATOR_ID = "indicator--c5e8bc82-d425-49bd-af71-77b908ddf8a9"


class CAR_2013_04_002():

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

        rdd = rdd.filter(lambda item: (item[1]['data_model']['action'] == "create"))

        # Map in the CAR information and rename fields the analytic needs for ease of use
        # This needs to happen after the filter on process create, or some of the fields won't be there
        rdd = rdd.map(lambda item: (
            item[0],
            {'@timestamp': item[1]["@timestamp"],
             'event_code': item[1]["data_model"]["fields"]["event_code"],
             'exe': item[1]["data_model"]["fields"]["exe"],
             'parent_exe': item[1]["data_model"]["fields"]["parent_exe"],
             'utc_time': item[1]["data_model"]["fields"]["utc_time"],
             'command_line': item[1]["data_model"]["fields"]["command_line"],
             'pid': item[1]["data_model"]["fields"]["pid"],
             'ppid': item[1]["data_model"]["fields"]["ppid"],
             'hostname': item[1]["data_model"]["fields"]["hostname"],
             'process_guid': item[1]["data_model"]["fields"]["process_guid"],
             'parent_process_guid': item[1]["data_model"]["fields"]["parent_process_guid"],
             'action': item[1]["data_model"]["action"],
             'data_model': item[1]["data_model"]
             }))

        # Filter events based on begin and end time
        rdd = rdd.filter(lambda item: (item[1]['@timestamp'] <= end))
        rdd = rdd.filter(lambda item: (item[1]['@timestamp'] >= begin))

        # Return true if the provided exe is in the list of suspicious commands, false if it is not.
        def isSuspiciousCommand(exe):
                ''' List of suspicious commands '''
                # Most of these are straight forward matches, but some like net* stand in for netstat, netsh, and the net * commmands
                suspicious_commands = [
                    'arp.*',
                    'at.*',
                    'attrib.*',
                    'cscript.*',
                    'dsquery.*',
                    'hostname.*',
                    'ipconfig.*',
                    'mimikatz.*',
                    'nbstat.*',
                    'net.*',
                    'nslookup.*',
                    'ping.*',
                    'quser.*',
                    'qwinsta.*',
                    'reg.*',
                    'runas.*',
                    'sc.*',
                    'schtasks.*',
                    'ssh.*',
                    'svchost.*',
                    'systeminfo.*',
                    'taskkill.*',
                    'telnet.*',
                    'tracert.*',
                    'wscript.*',
                    'xcopy.*']

                # This regex could be precompiled, but Python caches it internally anyway so there's no real speed benefit
                regexes = '(?:%s)' % '|'.join(suspicious_commands)
                if re.match(regexes, exe):
                    return True
                return False

        # Given a list of suspicious processes per host, determine which ones fall within <interval> minutes of each other
        # Aggregate those into a rolling window
        # Return (elastic id, [{window_start, window_end, [commands]}])
        def group_suspicous_processes(grouped_event_list, interval):
            aggs = []
            converted_aggs = []

            # Convert the utc_time string to a python datetime
            # TODO make this more pythonic with a lambda
            for item in grouped_event_list:
                item[1]['utc_datetime'] = datetime.strptime(item[1]['utc_time'], "%Y-%m-%d %H:%M:%S.%f")

            # order by the time the command was executed
            grouped_event_list = sorted(grouped_event_list, key=lambda item: item[1]['utc_datetime'])

            # For each command
            for item in grouped_event_list:
                command_time = item[1]['utc_datetime']
                if not aggs:
                    first_command = [command_time, command_time, [item[1]['exe']]]
                    aggs.append(first_command)
                else:
                    last_command = aggs.pop()

                    # if the command_time falls within the window update the end_time and update the list of commands
                    if(last_command[0] + timedelta(minutes=interval) > command_time):
                        last_command[1] = command_time
                        last_command[2].append(item[1]['exe'])
                        aggs.append(last_command)
                    # if the command falls outside the current window start a new window
                    else:
                        new_command = [command_time, command_time, [item[1]['exe']]]
                        aggs.append(last_command)
                        aggs.append(new_command)

            # python datetime objects aren't JSON serializable, which causes problems for pySpark
            # the simplest solution is to return the datetime objects as strings
            # keep only those aggregates where the size is greater than one
            for agg in aggs:
                if len(agg[2]) > 1:
                    converted_aggs.append({"start_time" : agg[0].isoformat(), "end_time" : agg[1].isoformat(), "commands": tuple(agg[2])})
            
            
            # TODO for now just output the first elastic ID as the key. We should figure out the correct long term solution
            return (grouped_event_list[0][0], converted_aggs)

        # Filter down to commands of interest
        rdd = rdd.filter(lambda item: (isSuspiciousCommand(item[1]['exe'])))

        # Convert RDD to (K, V) where K is (hostname, ppid) and V is (elastic key, event data)
        rdd = rdd.map(lambda item: ((item[1]['hostname'], item[1]['ppid']), (item[0], item[1])))

        rdd = rdd.groupByKey()

        # Assume the list of suspicious commands per (hostname, ppid) is relatively small
        # Given at iterable of all the commands, sort them and do a pairwise comparison to see how many fall within our time requirement
 
        rdd = rdd.map(lambda item: (item[0], group_suspicous_processes(item[1], 30)))

            # The data structure returned by group_suspicous_processes is (hostname, ppid)(elastic_id, alert_data_dict_list)
        # Where alet_data_dict_list is a list of groups of suspicous commands. Each entry in the list is a dictionary.

        #TODO: This only uses the first element returned from group_suspicous_processes. We need to get all of them, possibly using flatMap or flatMapValues?
        rdd = rdd.map(lambda item: (
            item[1][0],
            {'@timestamp': item[1][1][0]["start_time"],
             'end_time': item[1][1][0]["end_time"], 
             'car_id': CAR_NUMBER,
             'car_name': CAR_NAME,
             'car_description': CAR_DESCRIPTION,
             'attack_tactic': ATTACK_TACTIC,
             'car_url': CAR_URL,
             'commands': item[1][1][0]["commands"],
             'hostname': item[0][0]
             }))

        return rdd

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
CAR-2014-05-002: Services launching Cmd
'''

CAR_NUMBER = "CAR_2014_05_002"
CAR_NAME = "Services launching Cmd"
CAR_DESCRIPTION = "Windows runs the Service Control Manager (SCM) within the process services.exe. Windows launches services as independent " \
    "processes or DLL loads within a svchost.exe group. To be a legitimate service, a process (or DLL) must have the appropriate service entry " \
    "point SvcMain. If an application does not have the entry point, then it will timeout (default is 30 seconds) and the process will be " \
    "killed. To survive the timeout, adversaries and red teams can create services that direct to cmd.exe with the flag /c, followed by the " \
    "desired command. The /c flag causes the command shell to run a command and immediately exit. As a result, the desired program will remain " \
    "running and it will report an error starting the service. This analytic will catch that command prompt instance that is used to launch the " \
    "actual malicious executable."
ATTACK_TACTIC = "Persistence, Privilege Escalation"
CAR_URL = "https://car.mitre.org/wiki/CAR-2014-05-002"
ALERT_INDEX = "alert"
ES_INDEX = "sysmon-*"
ES_TYPE = "sysmon_process"
INDICATOR_ID = "indicator--90c35f49-cb87-4b33-bf8e-d15aa59671d2"

class CAR_2014_05_002():
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
            ((item[1]["parent_exe"].upper() == "SERVICES.EXE") and (item[1]["exe"].upper() == "CMD.EXE"))
        ))
        return rdd

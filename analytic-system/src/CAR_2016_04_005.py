# code: utf-8
'''
NOTICE

This software was produced for the U. S. Government
under Basic Contract No. W15P7T-13-C-A802, and is
subject to the Rights in Noncommercial Computer Software
and Noncommercial Computer Software Documentation
Clause 252.227-7014 (FEB 2012)

2016 The MITRE Corporation. All Rights Reserved.
'''

'''
CAR_2016_04_004
'''

CAR_NUMBER = "CAR_2016_04_005"
CAR_NAME = "Successful Remote Account Login"
CAR_DESCRIPTION = "A remote desktop logon, through RDP, may be typical of a system administrator or IT support, but only from select workstations.  Monitoring remote desktop logons and comparing to known/approved originating systems can detect lateral movement of an adversary."
CAR_URL = "http://attack.mitre.org"
ES_INDEX = "winevent_security*"
ES_TYPE = "winevent_security"
ALERT_INDEX = "sitaware"
INDICATOR_ID = "indicator--ab50dc6b-3389-4228-96ea-4f5543426785"

class CAR_2016_04_005():
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
        rdd = rdd.filter(lambda item: (item[1]['data_model']['fields']['event_code'] == 4624))
        rdd = rdd.filter(lambda item: (item[1]['AuthenticationPackageName'] == 'Negotiate'))
        # Need to filter for "Target Username" but that might not show up if its not a remote login

        # Error of "information" is not matching what I'm finding the logs.  Going to remove for now
        rdd = rdd.filter(lambda item: (item[1]['data_model']['fields']['severity'] in ["Information", "Error"]))

        rdd = rdd.map(lambda item: (
            item[0],
            {
                "event_code": item[1]["data_model"]["fields"]["event_code"],
                "hostname": item[1]["data_model"]["fields"]["hostname"],
                "@timestamp": item[1]["@timestamp"],
                "data_model": item[1]["data_model"],
                "logon_type": item[1]["LogonType"],
                "authentication_package_name": item[1]["AuthenticationPackageName"],
                "target_user_name": item[1]["TargetUserName"],
                "car_number": CAR_NUMBER,
                "car_name": CAR_NAME,
                "car_url": CAR_URL,
                "car_description": CAR_DESCRIPTION}))

        rdd = rdd.filter(lambda item: (item[1]["logon_type"] == "10"))
        rdd = rdd.filter(lambda item: (item[1]["@timestamp"] <= end))
        rdd = rdd.filter(lambda item: (item[1]["@timestamp"] >= begin))
        return rdd

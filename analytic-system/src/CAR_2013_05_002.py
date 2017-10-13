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
CAR-2013-05-002: Suspicious Run Locations.
'''

CAR_NUMBER = "CAR_2013_05_002"
CAR_NAME = "Suspicious Run Locations"
CAR_DESCRIPTION = "In Windows, files should never execute out of certain "\
    "directory locations. Any of these, locations may exist for a variety "\
    "of reasons, and executables may be present in the directory but should "\
    "not execute. As a result, some defenders make the mistake of ignoring "\
    "these directories and assuming that a process will never run from one. "\
    "There are known TTPs that have taken advantage of this fact to go "\
    "undetected. This fact should inform defenders to monitor these "\
    "directories more closely, knowing that they should never contain "\
    "running processes."
CAR_URL = "https://car.mitre.org/wiki/CAR-2013-05-002"
ES_INDEX = "sysmon-*"
ES_TYPE = "sysmon_process"
ALERT_INDEX = "alert"
INDICATOR_ID = "indicator--ede3b60f-d0c2-4c39-b1c7-8d094c7f92cf"


class CAR_2013_05_002():
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

        # Return true if the given image path for an executable is suspicious
        # Systems with drives besides C: should include additional Tasks and debug directories
        def is_suspicious(image_path):
            ''' List of suspicious commands '''
            suspicious_locations = [
                'C:\\\\RECYCLER\\\\.*',
                'C:\\\\SystemVolumeInformation\\\\.*',
                'C:\\\\Windows\\\\Tasks\\\\.*',
                'C:\\\\Windows\\\\debug\\\\.*']

            regexes = '(?:%s)' % '|'.join(suspicious_locations)
            if re.match(regexes, image_path, re.IGNORECASE):
                return True
            return False

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
             'car_url': CAR_URL,
             'image_path': item[1]["data_model"]["fields"]["image_path"],
             'data_model': item[1]["data_model"]
             }))

        # Filter events that occur in a suspicious location
        rdd = rdd.filter(lambda item: (is_suspicious(item[1]['image_path'])))

        return rdd

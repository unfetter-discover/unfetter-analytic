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

from importlib import import_module
import argparse
import datetime
import es_helper
import re
import pdb
import sys
import requests
import json
import logging

"""This is the main user interface to the CAR analytics code.  This python program will start, accept and validate
arguments, and create the desired CAR analytic class, and will call the class's analytics."""

DESCRIPTION_STRING = 'Description'
CAR_HELP = 'Provide a car number in the form of "CAR_YYYY_MM_XXXX'
DURATION_HELP = 'How much time to analyze.'
END_HELP = "UTC last date/time to analyze.  Default is Now"
TEST_HELP = "Include if you do not want to write the alert to ElasticSearch"
BEGIN_HELP = "UTC beginning date/time to analyze"
POST_HELP = "Posts the alert from an analytic to the local Unfetter-Discover system"


# TODO
# http://stackoverflow.com/questions/11415570/directory-path-types-with-argparse

def valid_date(s):
    """For the argument parser, validates that the passed value is a valid time/date string"""

    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime(s, fmt)
        except ValueError:
            pass
    msg = "-e is not a valid date: '{0}'.".format(s)
    raise argparse.ArgumentTypeError(msg)


class valid_duration(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        # Duration will be in minutes.  So, we will multiply input by
        # multiplier to convert to minutes
        dur_lookup = {"min": 1, "hour": 60, "day": 60 * 24}
        error_msg = "-d should be followed by [min|day|hour] and then a positive, integer value"
        if (values[0] not in dur_lookup.keys()):
            raise argparse.ArgumentError(self, error_msg)
        try:
            int(values[1])
            if values[1] <= 0:
                raise argparse.ArgumentError(self, error_msg)
            setattr(namespace, self.dest, values)
            return True
        except:
            raise argparse.ArgumentError(self, error_msg)


class valid_CAR(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        # Will convert the input CAR_YYYY_MM_XXX into the proper format.  Assuming we will allow:
        # .py at the end, - and _ as delimiters.
        error_msg = "The CAR value must be the format of CAR-2015-04-002"
        CAR_value = values
        if CAR_value[-3:].lower() == ".py":
            CAR_value = CAR_value[:-3]
        CAR_value = CAR_value.replace('-', '_').split('_')
        if len(CAR_value) != 4:
            raise argparse.ArgumentError(self, error_msg)
        CAR_value[0] = CAR_value[0].upper()
        if CAR_value[0] != "CAR":
            raise argparse.ArgumentError(self, error_msg)
        if (len(CAR_value[1]) != 4) or (len(CAR_value[2]) != 2) or (len(CAR_value[3]) != 3):
            raise argparse.ArgumentError(self, error_msg)
        try:
            year = int(CAR_value[1])
            month = int(CAR_value[2])
            index = int(CAR_value[3])
            if ((year < 0) or (month < 0) or (year < 0)):
                raise argparse.ArgumentError(self, error_msg)
        except:
            raise argparse.ArgumentError(self, error_msg)
        return_CAR = "_".join(CAR_value)
        setattr(namespace, self.dest, return_CAR)
        return True


def printHeader():
    y = "\033[1;93m"
    o = "\033[0m"
    b_w = "\033[0;107m"
    analytic = []

    analytic.append(" _   _          __        _    _               ")
    analytic.append("| | | | _ __   / _|  ___ | |_ | |_  ___  _ __  ")
    analytic.append("| | | || '_ \ | |_  / _ \| __|| __|/ _ \| '__| ")
    analytic.append("| |_| || | | ||  _||  __/| |_ | |_|  __/| |    ")
    analytic.append(" \___/ |_| |_||_|   \___| \__| \__|\___||_|    ")
    analytic.append("    _                   _         _    _       ")
    analytic.append("   / \    _ __    __ _ | | _   _ | |_ (_)  ___ ")
    analytic.append("  / _ \  | '_ \  / _` || || | | || __|| | / __|")
    analytic.append(" / ___ \ | | | || (_| || || |_| || |_ | || (__ ")
    analytic.append("/_/   \_\|_| |_| \__,_||_| \__, | \__||_| \___|")
    analytic.append("                           |___/               ")
    bulb = []
    bulb.append("           " + o)
    bulb.append(y + "  ..---..  " + o)
    bulb.append(y + " /.......\\" + o)
    bulb.append(y + "|.........|" + o)
    bulb.append(y + ":.........;" + o)
    bulb.append(y + " \\  \~/  /" + o)
    bulb.append(y + "  `, Y ,'  " + o)
    bulb.append("   |===|   ")
    bulb.append("   |===|   ")
    bulb.append("    \_/    ")
    bulb.append("           ")
    bulb.append("           ")

    print "\n\n\n"
    for i in range(0, 11):
        print analytic[i],
        print "  ",
        print bulb[i]
    print "\n\n"
    # print header
    print b_w + " " * (len(analytic[1]) + len(bulb[1])) + o + "\n\n"


def postSTIXStore(car_data):
    now = datetime.datetime.utcnow()
    sighting = {'data':{'type':'sightings',
                        'attributes':{
                            'created':now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                            'version':'1',
                            'modified':now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                            'summary':car_data['car_name'],
                            'sighting_of_ref':car_data['indicator_id']
                        }}}

    url = 'http://cti-stix-store:3000/cti-stix-store-api/sightings'
    headers = {'Accept' : 'application/vnd.api+json',
               'Content-Type' : 'application/vnd.api+json'}
    response = requests.post(url, headers=headers, data=json.dumps(sighting))
    if response.status_code >= 400:
        print "Error posting to Unfetter-Discover: Code %s" %response.status_code
    else:
        print "Alert sent to Unfetter-Discover"

def printCARHeader(car_data):
    print "\033[0;97m%s\033[0m\n" %car_data["car_name"]
    print "CAR Number: %s\n\n" %car_data["car_number"]
    print car_data["car_description"]
    print "\n\n"
    return

def buildArgument():
    now = datetime.datetime.utcnow()
    parser = argparse.ArgumentParser(description=DESCRIPTION_STRING)
    parser.add_argument('-c', help=CAR_HELP, dest='car_number', required=True, action=valid_CAR)
    parser.add_argument(
        '-e', help=END_HELP, dest='end', required=False,
        default=now, type=valid_date)
    parser.add_argument('-b', help=BEGIN_HELP, dest='begin', required=False, type=valid_date)
    parser.add_argument('-d', help=DURATION_HELP, required=False,
                        dest='duration', action=valid_duration,
                        default=['min', 60], nargs=2)
    parser.add_argument('-t', help=TEST_HELP, dest='test',
                        action='store_const', const=True, default=False)
    parser.add_argument('-p', help=POST_HELP, dest='post_stix',
                        action='store_const', const=True, default=False)

    args = parser.parse_args()

    return args, parser

if __name__ == '__main__':
    dur_lookup = {"min": 1, "hour": 60, "day": 60 * 24}
    args, parser = buildArgument()
    # if (args.end is not now) and (args.begin is not None) and (args.duration is not None):
    #    parser.error("You can not pick all three -d, -b, -e")
    # if args.duration is None:
    #    duration = 60
    # else:
    # I think I need to remove the above.  Duration is being set as a default.  If End and Begin are submitted, then
    #  duration is remoted

    duration = int(args.duration[1]) * dur_lookup[args.duration[0]]
    mod = import_module(args.car_number)
    met = getattr(mod, args.car_number)
    if (args.begin is None):
        args.begin = args.end - datetime.timedelta(minutes=duration)
    elif (args.end is None):
        args.end = args.begin + datetime.timedelta(minutes=duration)
    else:
        if args.begin >= args.end:
            parser.error("The end date (-e) is before the begin date (-b)")
    analytic = met()
    rdd = es_helper.get_rdd(analytic.car_data["es_index"], analytic.car_data["es_type"])
    printHeader()
    printCARHeader(analytic.car_data)
    rdd = analytic.analyze(rdd, args.begin, args.end)
    if args.test is False:
        es_helper.alert(rdd, analytic.car_data["alert_index"], analytic.car_data["car_number"])
        if args.post_stix and (not rdd.isEmpty()):
            postSTIXStore(analytic.car_data)
    else:
        es_helper.printAlert(rdd)

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

import argparse
import datetime
import pdb
import sys
import json
import logging
from stix2 import Sighting
from stix2 import ObservedData
from stix2 import parse
from pymongo import MongoClient


import random

import pprint


# TODO
# http://stackoverflow.com/questions/11415570/directory-path-types-with-argparse

def create_IP():
    return(".".join(map(str, (random.randint(0, 255)
                              for _ in range(4)))))


def create_hostname():
    return("hostname_"+str(random.randint(0, 20)))


def post_stix_store(owner, sighting_data, observed_data_input):
    client = MongoClient("localhost", 27018)
    db = client['stix']
    stixCollection = db['stix']
    now = datetime.datetime.utcnow()
    search_observables = {}
    for key, value in observed_data_input.iteritems():
        search_observables['stix.objects.0.'+key] = value
    print "************"
    print search_observables
    print "************"
    observable_data = stixCollection.find_one({"$and": [search_observables]})
    if (observable_data):
        print("in if")
        pprint.pprint(observable_data)
        observable_id = observable_data["_id"]
        observed_object = ObservedData(
            number_observed=observable_data["stix"]["number_observed"]+1,
            id=observable_id,
            created_by_ref=observable_data["stix"]["created_by_ref"],
            first_observed=observable_data["stix"]["first_observed"],
            last_observed=now,
            objects={
                "0": observed_data_input
            }
        )
        observed_data = {
            '_id': observed_object.id,
            '_v': 0,
            'stix': observed_object
        }
        observed_id = stixCollection.find_one_and_update(
            {'_id': observed_object.id},
            {'$inc': {'stix.count': 1}},
            {'stix.last_observed': now.strftime("%Y-%m-%dT%H:%M:%SZ")})
    else:
        print("in else")
        observed_object = ObservedData(
            number_observed=1,
            created_by_ref=owner,
            first_observed=now,
            last_observed=now,
            objects={
                "0": observed_data_input
            }
        )
        observed_data = {
            '_id': observed_object.id,
            '_v': 0,
            'stix': observed_object
        }
        observed_id = stixCollection.insert_one(observed_data).inserted_id

    sighting_object = Sighting(
        count=1,
        first_seen=now,
        last_seen=now,
        sighting_of_ref=sighting_data['indicator_id'],
        observed_data_refs=[observed_object.id],
        where_sighted_refs=sighting_data['where_sighted_refs'],
        created_by_ref=sighting_data['where_sighted_refs'],
        custom_properties={
            "x_unfetter_asset": sighting_data['asset']
        }
    )
    sighting = {
        '_id': sighting_object.id,
        '_v': 0,
        "stix": sighting_object
    }

    sighting_id = stixCollection.insert_one(sighting).inserted_id
    pprint.pprint("**************************************")
    pprint.pprint(stixCollection.find_one({'_id': sighting_id}))
    pprint.pprint(stixCollection.find_one({'_id': observed_id}))


if __name__ == '__main__':
    # if (args.end is not now) and (args.begin is not None) and (args.duration is not None):
    #    parser.error("You can not pick all three -d, -b, -e")
    # if args.duration is None:
    #    duration = 60
    # else:
    # I think I need to remove the above.  Duration is being set as a default.  If End and Begin are submitted, then
    #  duration is remoted

    # https://car.mitre.org/wiki/CAR-2014-04-003

    # the powershell extension should have an observable for the powershell.exe file.
    # sighting, indicator,

    sighting_1 = {
        "name": "Powershell Execution",
        "indicator_id": "indicator--20ab0b2d-9a79-4bd3-a9c6-d6aed0880287",
        "asset": {
            "ip": create_IP(),
            "hostname": create_hostname()},
        "observed_data_refs": "observed-data--c5070cf2-f563-44b2-b6e7-d9684d56223a",
        "where_sighted_refs": "identity--4ac44385-691d-411a-bda8-027c61d68e99"
    }
    observable_data_1 = {
        "type": "file",
        "name": "PowerShell.exe",
        "magic_number_hex": "4D5A"
    }
    # CAR-2013-02-012
    observable_data_2 = {
        "type": "file",
        "name": "PowerShell.exe",
        "magic_number_hex": "4D5A"
    }
    sighting_2 = {
        "name": "User Logged in to Multiple Hosts",
        "indicator_id": "indicator--48d2d0eb-c2bd-4777-b389-7bd3804de89c",
        "asset": {
            "ip": create_IP(),
            "hostname": create_hostname()},
        "observed_data_refs": "observed-data--e998d38c-0808-4327-b4d9-c4a615b8723b",
        "where_sighted_refs": "identity--4ac44385-691d-411a-bda8-027c61d68e99"
    }

    post_stix_store(
        "identity--4ac44385-691d-411a-bda8-027c61d68e99", sighting_1, observable_data_1)
    post_stix_store(
        "identity--4ac44385-691d-411a-bda8-027c61d68e99", sighting_2, observable_data_2)

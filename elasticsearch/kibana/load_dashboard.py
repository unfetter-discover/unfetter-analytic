#!/bin/env python

"""Migrate all the kibana dashboard from SOURCE_HOST to DEST_HOST.

This script may be run repeatedly, but any dashboard changes on
DEST_HOST will be overwritten if so.

"""

import urllib2, urllib, json,pdb
DEST_HOST = "localhost"


def http_post(url, data):
    request = urllib2.Request(url, data)
    return urllib2.urlopen(request).read()


def http_put(url, data):
    opener = urllib2.build_opener(urllib2.HTTPHandler)
    request = urllib2.Request(url, data)
    request.get_method = lambda: 'PUT'
    return opener.open(request).read()


if __name__ == '__main__':
    # All the dashboards (assuming we have less than 9999) from
    # kibana, ignoring those with _type: temp.
    f = open("kibana_dashboard.json", "r")
    jsonString = f.read()
    old_dashboards_raw = json.loads(jsonString)
    for doc in old_dashboards_raw['hits']['hits']:
        put_url = "http://%s:9200/.kibana/%s/%s" % (DEST_HOST, urllib.quote(doc["_type"]), urllib.quote(doc["_id"]))
        print http_put(put_url, json.dumps(doc["_source"]))

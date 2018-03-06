'''
NOTICE

This software was produced for the U. S. Government
under Basic Contract No. W15P7T-13-C-A802, and is
subject to the Rights in Noncommercial Computer Software
and Noncommercial Computer Software Documentation
Clause 252.227-7014 (FEB 2012)

2016 The MITRE Corporation. All Rights Reserved.
'''

from pyspark import SparkContext, SparkConf
import json

ES_IP = "elasticsearch"
ES_PORT = "9200"


def get_rdd(es_index, es_type):

    if es_type is "":
        resource = es_index
    else:
        resource = es_index + "/" + "doc"
    es_read_conf = {
        "es.nodes": ES_IP,
        "es.port": ES_PORT,
        "es.resource": resource,
        "es.index.read.missing.as.empty": 'yes'
    }
    conf = SparkConf().setAppName("Unfetter")
    sc = SparkContext(conf=conf)
    rdd = sc.newAPIHadoopRDD(
        inputFormatClass="org.elasticsearch.hadoop.mr.EsInputFormat",
        keyClass="org.apache.hadoop.io.NullWritable",
        valueClass="org.elasticsearch.hadoop.mr.LinkedMapWritable",
        conf=es_read_conf)
    return rdd


def printAlert(rdd):
    '''Will print out the alert'''
    if rdd.isEmpty():
        print "No Alerts Found"
    else:
        print json.dumps(rdd.collect(), sort_keys=True, indent=2, separators=(': '))
    return


def alert(rdd, alert_index, car_number):
    '''Writes out one or more alert documents to ElasticSearch'''
    if rdd.isEmpty():
        print "No Alerts Found\n\n"
    else:
        print "%d new alerts\n\n" % rdd.count()
        es_write_conf = {
            "es.nodes": ES_IP,
            "es.port": ES_PORT,
            "es.resource": alert_index+"/"+"doc"
        }
        rdd.saveAsNewAPIHadoopFile(
            path='-',
            outputFormatClass="org.elasticsearch.hadoop.mr.EsOutputFormat",
            keyClass="org.apache.hadoop.io.NullWritable",
            valueClass="org.elasticsearch.hadoop.mr.LinkedMapWritable",
            conf=es_write_conf)
    return

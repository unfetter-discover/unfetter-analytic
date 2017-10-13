#!/bin/bash
# setting up prerequisites

sudo /opt/logstash/bin/plugin install logstash-filter-translate

exec /docker-entrypoint.sh elasticsearch


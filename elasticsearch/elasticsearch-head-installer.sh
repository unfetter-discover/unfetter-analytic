#!/bin/bash

# Wrapper to import system https proxy settings and install the elasticsearch-head plugin
# Skip installation if it's already installed
# This script needs to be run as sudo

echo $(/usr/share/elasticsearch/bin/plugin list) | grep "head" > /dev/null
if [ $? -ne 0 ] ; then
    JAVA_PROXY_SETTINGS=""
    if [ -n "$https_proxy" ] ; then
        echo $https_proxy | grep "@"
        if [ $? -eq 0 ] ; then # If variable has username and password, parse it this way
            PROXY_HOST=$(echo $https_proxy | sed 's/http\(s\)\{0,1\}:\/\/.*@\(.*\):.*/\2/')
            PROXY_PORT=$(echo $https_proxy | sed 's/http\(s\)\{0,1\}:\/\/.*@.*:\(.*\)/\2/' | tr -d "/")
            USERNAME=$(echo $https_proxy | sed 's/https?:\/\/\(.*\)@.*/\1/'|awk -F: '{print $1}')
            PASSWORD=$(echo $https_proxy | sed 's/https?:\/\/\(.*\)@.*/\1/'|awk -F: '{print $2}')
        else # If it doesn't have username and password, use this to parse it
            PROXY_HOST=$(echo $https_proxy | sed 's/http\(s\)\{0,1\}:\/\/\(.*\):.*/\2/')
            PROXY_PORT=$(echo $https_proxy | sed 's/http\(s\)\{0,1\}:\/\/.*:\(.*\)/\2/' | tr -d "/")
        fi

        JAVA_PROXY_SETTINGS="-Dhttps.proxyHost=$PROXY_HOST -Dhttps.proxyPort=$PROXY_PORT"
        if [ -n "$USERNAME" -a -n "$PASSWORD" ] ; then
            JAVA_PROXY_SETTINGS=$JAVA_PROXY_SETTINGS + "-Dhttps.proxyUser=$USERNAME -Dhttps.proxyPassword=$PASSWORD"
        fi
    fi

    /usr/share/elasticsearch/bin/plugin $JAVA_PROXY_SETTINGS install mobz/elasticsearch-head
else
    echo Elasticsearch head plugin installed. Skipping.
fi

/docker-entrypoint.sh elasticsearch
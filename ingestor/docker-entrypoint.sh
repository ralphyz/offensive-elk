#!/bin/bash

#Create the data directories
mkdir /data/errors 2>/dev/null
mkdir /data/new 2>/dev/null
mkdir /data/processed 2>/dev/null
mkdir /data/queue 2>/dev/null
chmod -R 777 /data/*

#Wait for things to come online:
sleep 45s

#Add an index to Elastisearch
curl -XPUT 'elasticsearch:9200/nmap-vuln-to-es'

#Create the Dashboard in Kibana
curl -XPOST 'kibana:5601/api/saved_objects/_bulk_create' -H 'Content-Type: application/json' -H 'kbn-xsrf: true' -d '@./dashboard.json'

#Set the default Kibana Index (from Elasticsearch)
curl -XPOST -H "Content-Type: application/json" -H "kbn-xsrf: true" -d '{"value":"1efd5fb0-fa1c-11e8-a744-67bcb2c52976"}' http://kibana:5601/api/kibana/settings/defaultIndex

#Call the FileMonitor Python script
#-u tells python to ignore the stdout and stderr bufferes, and immediately print messages (useful for docker log viewing)
/usr/local/bin/python -u /opt/OffensiveELK/FileMonitor.py


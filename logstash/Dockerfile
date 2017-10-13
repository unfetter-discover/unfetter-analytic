FROM docker.elastic.co/logstash/logstash:5.6.1
LABEL mantained="Unfetter"
LABEL description="Basic logstash docker file"



RUN  logstash-plugin install --no-verify logstash-filter-translate


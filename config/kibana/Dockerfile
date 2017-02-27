FROM kibana:4.5.4

RUN apt-get update && apt-get install -y netcat bzip2

COPY entrypoint.sh /tmp/entrypoint.sh
RUN chmod +x /tmp/entrypoint.sh
CMD ["/tmp/entrypoint.sh"]

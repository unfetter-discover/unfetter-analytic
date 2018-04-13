FROM openjdk:8-jre
LABEL mantained="Unfetter"
LABEL description="Installation and configuration of Apache Spark"



RUN apt-get -y update
RUN apt-get -y install build-essential checkinstall
RUN apt-get -y install libreadline-gplv2-dev libncursesw5-dev libssl-dev libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev


############################
# Install Scala
############################

RUN echo "*** Installing Scala ****"
WORKDIR /tmp


RUN wget http://downloads.typesafe.com/scala/2.11.7/scala-2.11.7.tgz?_ga=1.204864528.1236579178.1455238364 -O scala-2.11.7.tgz -q \
    && tar -xf scala-2*.tgz \
    && mkdir /usr/local/scala \
    && mv scala-2*/* /usr/local/scala/



############################
# Install Spark 
############################

RUN echo  "*** Installing Spark ***"
RUN wget http://archive.apache.org/dist/spark/spark-2.2.1/spark-2.2.1-bin-hadoop2.6.tgz -q \
    && tar -xf spark-2.2*.tgz \
    && mkdir /usr/local/spark \
    && mv spark-2.2*/* /usr/local/spark/
#This will quiet the INFO and WARN to console when testing.
COPY log4j.properties /usr/local/spark/conf
COPY spark-defaults.conf /usr/local/spark/conf

RUN echo "*** Installing Elasticsearch-hadoop ****"
RUN wget http://download.elastic.co/hadoop/elasticsearch-hadoop-6.1.1.zip -q \
    #&& mkdir /usr/local/spark/jars \
    && unzip elasticsearch-hadoop-6*.zip \ 
    && mv elasticsearch-hadoop-6.1.1/dist/elasticsearch-hadoop-6.1.1.jar /usr/local/spark/jars/elasticsearch-hadoop.jar \
    && rm -r elasticsearch-hadoop*


############################
# Install Spark 
############################

RUN echo "*** Install Python ***"
WORKDIR /tmp
RUN wget https://www.python.org/ftp/python/2.7.12/Python-2.7.12.tgz \
    && tar -xvf Python-2.7.12.tgz  

RUN cd Python-2.7.12 \
    && ./configure \
    && make 

RUN apt-get -y install python-pip

RUN pip install requests
RUN pip install stix2
RUN pip install pymongo

COPY src /usr/share/unfetter/src
#ENTRYPOINT /usr/share/unfetter/run.sh
# Need to figure out how to do this
COPY .bashrc ~/.bashrc
# su vagrant
#RUN source ~/.bashrc
ENV PATH $PATH:/tmp/Python-2.7.12
ENV SPARK_HOME /usr/local/spark
ENV PATH $PATH:$SPARK_HOME/bin
ENV PS1 "\w\\$> \[$(tput sgr0)\]"
WORKDIR /usr/share/unfetter/src

ENTRYPOINT /usr/share/unfetter/src/run.sh
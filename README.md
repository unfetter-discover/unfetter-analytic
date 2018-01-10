



# Unfetter
Welcome to the Unfetter project, a reference implementation inspired by The MITRE Corporation's <a href="https://car.mitre.org">Cyber Analytics Repository</a> (CAR) and <a href="https://attack.mitre.org">Adversarial Tactics, Techniques, and Common Knowledge</a> (ATT&CK&trade;) projects.

This reference implementation provides a framework for collecting events (process creation, network connections, Window Event Logs, etc.) from a client machine (Windows 7) and performing CAR analytics to detect potential adversary activity.

The goal of this effort is to enable analytic developers, malware analysts, or infrastructure owners to experiment with existing adversary detection analytics or create additional analytics. Efforts have been made to simplify the installation and setup of this reference implementation. While scalable components have been used, this is meant to be a development system. A production architecture would need to be further developed to run in a large scale environment.

Please see our webpage for more details: https://www.unfetter.io.

## System Requirements

* [Docker](https://www.docker.com/)
* [Docker Compose](https://www.docker.com/products/docker-compose)
* [VirtualBox](https://www.virtualbox.org/wiki/VirtualBox)
* [Vagrant](https://www.vagrantup.com)

## Project Setup
Unfetter Analytic uses three different systems to really work.  First, is the analytic system, based on an ELK stack with Apache Spark on top.  The second, is the Unfetter Discover Web service.  The third system is any Windows machine that can generate Sysmon and Windows Events and ship to the Unfetter Analytic system.  

Details for setting up this project are at https://iadgov.github.io/unfetter/analytic-setup.html

To quickly get the Unfetter Analytic and Unfetter Discover systems running, follow these steps.


Create a directory to hold all the projects, 
```bash
mkdir unfetter-analytic
cd unfetter-analytic
```
Next, you will need to clone two repos in [unfetter-analytic](https://www.github.com/unfetter-analytic).  
```bash
 git clone https://github.com/unfetter-analytic/unfetter.git
 git clone https://github.com/unfetter-analytic/windows-example.git
 ```
 Next, change directories into the unfetter directory, which houses the docker-compose.yml files, and run docker-compose
 ```
 cd unfetter
 docker-compose up
```
### Kibana
After running the `docker-compose` command, you can view the Kibana application at:
http://localhost:5601/


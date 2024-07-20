FROM ubuntu:22.04

# Define working directory.
WORKDIR /

RUN apt-get update && apt-get upgrade -y && apt-get install -y python3 python3-pip net-tools iputils-ping iproute2 vim 
RUN pip3 install scapy ipaddr pyyaml

RUN mkdir -p /etc/fibbing/

COPY ./config.yaml /etc/fibbing/config.yaml
COPY ./fibbing_controller.py /usr/bin/fibbing_controller

RUN chmod +x /usr/bin/fibbing_controller

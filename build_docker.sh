#!/bin/bash

# Clean all docker containers
docker rm $(docker ps -aq)

# Create container
docker build --no-cache -t=fibbing-controller-ubuntu ./controller


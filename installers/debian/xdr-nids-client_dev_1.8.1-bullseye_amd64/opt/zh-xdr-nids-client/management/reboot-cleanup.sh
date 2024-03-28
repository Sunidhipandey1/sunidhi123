#!/bin/bash

# Copyright : Whizhack Technologies, India
# Authors : Team Devops

sudo systemctl stop xdr-nids-net;


# Stopping and removing all the containers
sudo docker container stop $(docker container ls -aq);
sudo docker container rm $(docker container ls -aq);

# Performing a normal system pruning.
sudo docker system prune -f;
sudo docker volume prune -f;
sudo docker network prune -f;

# Removing stray volumes or networks.
sudo docker volume rm $(docker volume ls -q) -f;
sudo docker network rm $(docker network ls -q);

# Reboot the system.
sudo reboot;

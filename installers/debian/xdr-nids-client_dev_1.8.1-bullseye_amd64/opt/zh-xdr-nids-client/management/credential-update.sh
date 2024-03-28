#!/bin/bash

# Copyright : Whizhack Technologies, India
# Authors : Team Devops

# Updating the awscli.
sudo /aws/install --update;

# Logging into the repository.
sudo aws ecr get-login-password --region us-east-2 | sudo docker login --username AWS --password-stdin 406116439221.dkr.ecr.us-east-2.amazonaws.com;

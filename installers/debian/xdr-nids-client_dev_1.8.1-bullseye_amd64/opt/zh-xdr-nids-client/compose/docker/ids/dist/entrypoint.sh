#!/bin/bash

# Download the latest EmergingThreats OPEN ruleset

# Download ETPro rules
wget https://rules.emergingthreatspro.com/5797379469362616/suricata-7.0.2/etpro.rules.tar.gz -P /root/dist/

# Extract the downloaded tarball
tar -xvf /root/dist/etpro.rules.tar.gz -C /root/dist/ && \

# Remove the downloaded tarball
rm -rf /root/dist/etpro.rules.tar.gz && \

# Copy rules to Suricata rules directory
cp /root/dist/rules/* /var/lib/suricata/rules/

suricata-update --local /var/lib/suricata/rules/ --no-test && \
suricata-update update-sources && \
suricata-update --no-reload
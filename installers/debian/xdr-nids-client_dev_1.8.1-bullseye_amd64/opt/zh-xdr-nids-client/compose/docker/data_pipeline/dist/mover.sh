#!/bin/bash

cat /app/xdr_alert.json >> /var/log/data/processed_data/xdr_alert.json
cat /app/xdr_incident.json >> /var/log/data/processed_data/xdr_incident.json
cat /app/xdr_event.json >> /var/log/data/processed_data/xdr_event.json

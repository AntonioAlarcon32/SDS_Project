#!/bin/bash

cp ./telegraf.conf /etc/telegraf/telegraf.conf

systemctl restart telegraf
systemctl restart influxdb
systemctl restart grafana-server
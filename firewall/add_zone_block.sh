#!/bin/bash

curl -X POST -d '{"ip_src":"10.0.1.0/24","ip_dst":"10.0.3.0/24","priority":"1500","datapath_id":"2"}' http://localhost:8080/firewall
curl -X POST -d '{"ip_src":"10.0.2.0/24","ip_dst":"10.0.3.0/24","priority":"1500","datapath_id":"2"}' http://localhost:8080/firewall
curl -X POST -d '{"ip_src":"10.0.4.0/24","ip_dst":"10.0.3.0/24","priority":"1500","datapath_id":"2"}' http://localhost:8080/firewall

curl -X POST -d '{"ip_src":"10.0.2.0/24","ip_dst":"10.0.1.0/24","priority":"1500","datapath_id":"2"}' http://localhost:8080/firewall
curl -X POST -d '{"ip_src":"10.0.3.0/24","ip_dst":"10.0.1.0/24","priority":"1500","datapath_id":"2"}' http://localhost:8080/firewall
curl -X POST -d '{"ip_src":"10.0.4.0/24","ip_dst":"10.0.1.0/24","priority":"1500","datapath_id":"2"}' http://localhost:8080/firewall

curl -X POST -d '{"ip_src":"10.0.1.0/24","ip_dst":"10.0.2.0/24","priority":"1500","datapath_id":"2"}' http://localhost:8080/firewall
curl -X POST -d '{"ip_src":"10.0.3.0/24","ip_dst":"10.0.2.0/24","priority":"1500","datapath_id":"2"}' http://localhost:8080/firewall
curl -X POST -d '{"ip_src":"10.0.4.0/24","ip_dst":"10.0.2.0/24","priority":"1500","datapath_id":"2"}' http://localhost:8080/firewall

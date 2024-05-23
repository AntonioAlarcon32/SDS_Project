# Ryu Enterprise Controller
Project done for SDS, trying to simulate a enterprise network with SDN switches and controllers

## Execution

Run the following commands in this order

```bash
  sudo ryu-controller controller.py
  sudo -E python3 topology.py
```
It's recommended to open a Xterm in h4 (Monitoring App) and execute

```bash
  python3 monitoring/monitoring_app.py
```

## Snort

```bash
  sudo apt install snort
```

```bash
sudo mv snort.conf /etc/snort/
sudo mv project.rules /etc/snort/rules/
```

```bash
sudo snort -i s1-snort -c /etc/snort/snort.conf
```

```bash
  ./configure_snort_interface.sh
```

## Monitoring

In the mininet shell, write 
```bash
xterm h4
```
Then, write this command in the new shell to start the monitoring service
```bash
python3 monitoring/monitoring_app.py
```

## Telegraf & Grafana

```bash
cd telegraf
sudo ./configuration.sh
```
The dashboard can be imported from grafana

## Zone blocking

A firewall can be configured between networks, for test run 

```bash
  ./firewall/add_zone_block.sh
```

```bash
  ./firewall/del_zone_block.sh
```

The requests follow this pattern

```bash
curl -X POST -d 
'{"ip_src":"10.0.2.0/24",
"ip_dst":"10.0.1.0/24",
"priority":"1500",
"datapath_id":"2"}' 
http://localhost:8080/firewall
```
Change method to DELETE for removing them

## Attack simulation

### FTP Bruteforce

Open XTerm in h2, and execute 

```bash
python3 attacks/bruteforce_ftp.py
```
After X attempts, the MAC address will be banned from the network

### DDoS

Open h1, and execute 
```bash
python3 attacks/tcp_dos.py
```
or 
```bash
python3 attacks/dns_dos.py
```
If traffic flow is enough, Snort will be toggled and all traffic will be redirected to the honeypot server.
<h2>FriendlyWAF</h2>
____

<h4>FriendlyWAF is A OpenSource Web Application Firewall</h4>

<h5>Owner Netwerkfix and sponser by Netwerkfix.com</h5>
<a href="https://friendlywaf.com/">FriendlyWAF.com</a>


<h4>Specifications / recommended: not tested.</h4>
Small	30,000 Req/s	4vCore	4Gb Ram	1gbps	DDoS Prot of DC
Medium	100,000 Req/s	8vCore	16Gb Ram	5gbps	DDoS Prot of DC
Large	500,000 Req/s	12vCore	32Gb Ram	10gbps	DDoS Prot of DC
Extra Large	1,000,000 Req/s	16vCore	32Gb Ram	25gbps	DDoS Prot of DC


Step.1
Download Debian 12.2


Step.2
Update the system

$ apt update && apt upgrade -y

Step.3
Allow IPV4 forward

$ sudo nano /etc/sysctl.conf
++++++++
#net.ipv4.ip_forward=1
+++++++
net.ipv4.ip_forward=1
+++++
Uncommend it

Step.4
Install tools

$ apt install sudo nano ethtool curl cmake wget bind9 apache2 unzip nload docker iptables-persistent docker-compose git build-essential libpcap-dev libpcre3-dev libnet1-dev zlib1g-dev luajit hwloc libdumbnet-dev bison flex liblzma-dev openssl libssl-dev pkg-config libhwloc-dev cmake cpputest libsqlite3-dev uuid-dev libcmocka-dev libnetfilter-queue-dev libmnl-dev autotools-dev libluajit-5.1-dev libunwind-dev libfl-dev -y

Step.5
Install Webmin

$ sudo apt install software-properties-common apt-transport-https
$ curl -fsSL https://download.webmin.com/jcameron-key.asc | sudo gpg --dearmor -o /usr/share/keyrings/webmin.gpg
$ sudo nano /etc/apt/sources.list
+++++++
deb [signed-by=/usr/share/keyrings/webmin.gpg] http://download.webmin.com/download/repository sarge contrib
++++++
past this in that config

Step.6
Update
$ apt update

Step.7
Install Webmin
$ sudo apt install webmin -y
$ sudo systemctl enable --now webmin

Step.8
install Nginx Proxy or a Reverse proxy Manager
find it online, recommed with docker not diret on host best is on Docker compose

Step.9
Download the script or check it on this github called by Installer-Friendlywaf.sh

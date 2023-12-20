<h2>FriendlyWAF</h2>
____

<h4>FriendlyWAF is A OpenSource Web Application Firewall</h4>

<h5>Owner Netwerkfix and sponser by Netwerkfix.com</h5>

<h4>Specifications / recommended: not tested.</h4>
Small	5,000 Req/s	4vCore	4Gb Ram	1gbps	DDoS Prot of DC <br>
Medium	10,000 Req/s	8vCore	16Gb Ram	5gbps	DDoS Prot of DC<br>
Large	20,000 Req/s	12vCore	32Gb Ram	10gbps	DDoS Prot of DC<br>
Extra Large	50,000 Req/s	16vCore	32Gb Ram	25gbps	DDoS Prot of DC<br><br>


Step.1<br>
Download Debian 12.2<br>


Step.2<br>
Update the system<br>

$ apt update && apt upgrade -y<br>

Step.3<br>
Allow IPV4 forward<br>

$ sudo nano /etc/sysctl.conf<br>
++++++++<br>
#net.ipv4.ip_forward=1<br>
+++++++<br>
net.ipv4.ip_forward=1<br>
+++++<br>
Uncommend it<br>

Step.4<br>
Install tools<br>

$ apt install sudo nano ethtool curl cmake wget bind9 apache2 unzip nload docker iptables-persistent docker-compose git build-essential libpcap-dev libpcre3-dev libnet1-dev zlib1g-dev luajit hwloc libdumbnet-dev bison flex liblzma-dev openssl libssl-dev pkg-config libhwloc-dev cmake cpputest libsqlite3-dev uuid-dev libcmocka-dev libnetfilter-queue-dev libmnl-dev autotools-dev libluajit-5.1-dev libunwind-dev libfl-dev -y<br>

Step.5<br>
Install Webmin<br>

$ sudo apt install software-properties-common apt-transport-https<br>
$ curl -fsSL https://download.webmin.com/jcameron-key.asc | sudo gpg --dearmor -o /usr/share/keyrings/webmin.gpg<br><br>
$ sudo nano /etc/apt/sources.list<br>
+++++++<br>
deb [signed-by=/usr/share/keyrings/webmin.gpg] http://download.webmin.com/download/repository sarge contrib<br>
++++++<br>
past this in that config<br>

Step.6<br>
Update<br>
$ apt update<br>

Step.7<br>
Install Webmin<br>
$ sudo apt install webmin -y<br>
$ sudo systemctl enable --now webmin<br>

Step.8<br>
install Nginx Proxy or a Reverse proxy Manager<br>
find it online, recommed with docker not diret on host best is on Docker compose<br>

Step.9<br>
Download the script or check it on this github called by Installer-Friendlywaf.sh<br>

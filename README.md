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

$ apt install sudo nano ethtool curl cmake wget unzip ufw nload git build-essential libpcap-dev libpcre3-dev libnet1-dev zlib1g-dev luajit hwloc libdumbnet-dev bison flex liblzma-dev openssl libssl-dev pkg-config libhwloc-dev cmake cpputest libsqlite3-dev uuid-dev libcmocka-dev libnetfilter-queue-dev libmnl-dev autotools-dev libluajit-5.1-dev libunwind-dev libfl-dev -y

$ sudo apt install software-properties-common apt-transport-https

Step.5<br>
Install Nginx Proxy Manager on the host its self = Reverse Proxy with Lets Encrypt SSL<br>

$ sh -c "$(wget --no-cache -qO- https://raw.githubusercontent.com/ej52/proxmox/main/install.sh)" -s --app nginx-proxy-manager

Step.6<br>
Download the script or check it on this github called by Installer-Friendlywaf.sh<br>

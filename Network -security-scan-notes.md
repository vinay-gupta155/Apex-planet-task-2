1. ReconnaissancePassive Recon
(No direct contact with target):
WHOIS: Query domain ownership, contacts,
name servers using whois domain.com.
Nslookup: Resolve DNS records (A, MX, TXT)
for subdomains and IPs.
Google Dorking: Advanced Google searches
like site:target.com filetype:pdf,
intitle:"login" inurl:admin site:target.com.
Shodan: Search exposed devices/services
by domain/IP/country
 (e.g., hostname:target.com port:80).
Active Recon (Direct interaction):
Ping Sweep: Scan IP range for live hosts:
 nmap -sn 192.168.1.0/24 or
fping -a -g 192.168.1.0/24.
Banner Grabbing: Connect to ports for
service info: nc target 80 (HTTP),
telnet target 21 (FTP) to read banners
 revealing versions.�2. Port Service
ScanningUse Nmap on Metasploitable:TCP SYN Scan: nmap -sS -p- target_ip
(stealthy, common ports).UDP Scan: nmap -sU
 target_ip (noisy, for UDP services).
Service Version: nmap -sV -sS target_ip
 (detects software versions).
OS Detection: nmap -O target_ip (fingerprint OS).
Save output: nmap -oX scan.xml target_ip for reports.
Vulnerability ScanningInstall OpenVAS
(Kali: sudo apt install openvas) or
Nessus Essentials.Launch OpenVAS,
   create target (Metasploitable2 IP),
   run scan.Analyze report: Categorize vulnerabilities as
    Critical, High, Medium, Low; note CVEs and fixes.
    4. Packet Analysis with WiresharkStart
     capture on lab interface: wireshark.Generate
 traffic: Browse HTTP, login FTP, query DNS on
Metasploitable2.Filters:http contains "password"
(credentials).ftp.data contains "user|pass"
(unencrypted FTP logins).tcp.flags.syn==1
 and tcp.flags.ack==0 (SYN flood).Simulate
SYN flood: hping3 --flood -S target_ip and
capture.�5. Firewall BasicsOn Kali/Metasploitable2,
use iptables:Allow port 80: sudo iptables
-A INPUT -p tcp --dport 80 -j ACCEPT.Deny
 port 22: sudo iptables -A INPUT -p tcp --dport 22 -j
DROP.Save rules: sudo iptables-save > /etc/iptables.rules.Test: 
Run Nmap scan, verify blocked ports.

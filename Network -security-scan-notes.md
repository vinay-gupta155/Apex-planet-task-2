Reconnaissance is the process of gathering information about a target, often stealthily, to prepare for action. It commonly refers to military scouting of enemy positions or cyber efforts to profile networks and vulnerabilities.

Core Concept: Reconnaissance involves preliminary surveys to identify strengths, weaknesses, and layouts without direct confrontation. In military terms, it uses patrols or aircraft to map terrain and enemy forces. Cyber versions collect public data like domain records or employee details passively. 

Types: 
1)Passive: Gathers open-source info without touching the target, such as social media scans or WHOIS lookups.       
2)Active: Directly probes with tools like port scanners to detect vulnerabilities. 

Applications: Military reconnaissance spots exploitable gaps in defenses. In cybersecurity, it precedes attacks by revealing entry points. Ethical hackers use it to test defenses proactively. 

Passive reconnaissance: it uses public sources to gather target info without direct contact, minimizing detection risk. Techniques like WHOIS, nslookup, Google dorking, and Shodan exemplify this by querying open databases and search engines.

1)WHOIS Queries: WHOIS lookups reveal domain registration details, such as owner names, emails, addresses, and name servers, from public registries without touching the target. Tools like whois command-line pull this data passively. No logs created on the target's side.          

2)NSLookup: NSLookup queries DNS servers for domain records, like IP addresses, mail exchangers, or subdomains, using public resolvers. It maps network structure indirectly via existing DNS responses. Remains passive as it avoids target interaction.       

3)Google Dorking: Google dorking employs advanced search operators (e.g., site:, filetype:) to uncover sensitive public info like exposed files, directories, or employee details on websites. Examples include "site:target.com filetype:pdf confidential". Extracts data from indexed web content stealthily.                   

4)Shodan: Shodan scans the internet for exposed devices, ports, and services, acting as a search engine for IoT and servers. Users query banners, vulnerabilities, or geolocations passively from its database. Reveals global attack surfaces without personal probing. 

Active reconnaissance: it involves direct interaction with the target, unlike passive methods, to map networks and services. Ping sweeps and banner grabbing are key techniques that send probes, risking detection by security tools.    

1)Ping Sweep: Ping sweep sends ICMP echo requests (pings) across an IP range to identify live hosts responding with echo replies. Tools like Nmap or fping automate this for network discovery and vulnerability spotting. Firewalls often block ICMP, prompting TCP/UDP alternatives.   

2)Banner Grabbing: Banner grabbing connects to open ports to elicit service banners revealing software versions, like "Apache 2.4.7". Tools such as Netcat or Nmap fetch this data actively, aiding exploit selection. It exposes versions for targeted attacks if unpatched. 

port and service scanning:
Nmap: it performs port and service scanning by sending probes to target IP addresses to check which ports listen for connections and identify running services. It categorizes ports as open, closed, or filtered, helping map networks for security audits. 

Basic Usage: Run nmap [target] to scan the top 1,000 TCP ports on a host like an IP or domain. For all 65,535 ports, use nmap -p- [target], though it takes longer. Add -sS for stealth SYN scans that avoid full connections. 

Port Scanning TypesTCP SYN Scan (-sS): Sends SYN packets; open ports reply with SYN-ACK, then reset without completing handshake.TCP Connect Scan (-sT): Full three-way handshake to confirm open ports reliably.UDP Scan (-sU): Probes UDP ports; open ones may reply, closed send ICMP unreachable. 

Service DetectionUse -sV to probe open ports for service versions, like detecting Apache on port 80 from banners. Combine with -A for OS detection, scripts, and traceroute. Output shows port, state, and service details clearly. 

Nmap offers dozens of commands and options for detailed port scanning, service detection, and network mapping. Core syntax is nmap [scan type] [options] [target], where targets can be IPs, ranges (192.168.1.1-255), or domains. Always run with sudo for raw socket access on Linux.

Essential Scan Types
nmap-sS target: TCP SYN scan (stealthy, default for root users; sends SYN, checks SYN-ACK).

nmap -sT target: TCP Connect scan (full handshake, no root needed).

nmap -sU target: UDP scan (slow, checks responses or ICMP errors).

nmap -sV target: Version detection (probes open ports for service/software details).

nmap -O target: OS detection (fingerprinting based on TCP/IP stack).

nmap -A target: Aggressive (includes -sV, -O, script scan, traceroute). 

Vulnerability scanning:

OpenVAS: it is an open-source vulnerability scanner that automates testing for thousands of known security flaws across networks, hosts, and applications. It uses Network Vulnerability Tests (NVTs) updated daily from feeds like CVE to detect issues and prioritize them by severity. 
Installation and Setup:

Install OpenVAS (now part of Greenbone Vulnerability Manager or GVM) on Kali Linux via sudo apt install gvm. Run sudo gvm-setup to create an admin user and download feeds (takes hours initially). Start with sudo gvm-start, then access https://127.0.0.1:9392 in a browser using admin credentials. Update feeds regularly with sudo greenbone-feed-sync. 

Creating Targets and Scans:

Define a Target: Go to Configuration > Targets > New; enter IP, range (e.g., 192.168.1.0/24), or domain, plus ports (default all).

Create a Task: Scans > Tasks > New; select target, choose scan config (e.g., "Full and fast" for balanced speed/depth), set credentials if needed.Launch the task monitor progress under Scans dashboard

Wireshark: it is the focus of capturing and analyzing network traffic (high/medium/low level) to identify vulnerabilities, filter packets, and detect attacks like SQL injection from unencrypted HTTP traffic. It enables deep inspection of protocols, payloads, and anomalies in real-time or from PCAP files. 

Core Objectives: 

Capture live traffic or analyze saved captures to examine packet details like headers, payloads, and protocols (HTTP, TCP, etc.). Filter for specific traffic (e.g., unencrypted HTTP for credentials) and detect exploits such as SQL injection or XSS in requests. Perform syslog analysis for errors or unusual patterns. 

Key Wireshark Steps: 
Capture Setup: Select interface (e.g., Ethernet/WiFi) > Start capture; apply capture filters like "host 192.168.1.1" or "port 80".Display Filters: Post-capture, use filters like "http contains 'password'", "http.request.method == POST", or "tcp.port == 443" to isolate traffic.Follow Streams: Right-click packet > Follow > TCP/HTTP Stream to reconstruct sessions, view plaintext data.Export Objects: File > Export Objects > HTTP to save files leaked in responses.

firewall basics:focusing on creating simple rules to block unwanted ports while allowing specific traffic, essential for network security in ethical hacking. It teaches rule syntax, testing with scans, and delivery of reports with demos. 

Core Objectives: Understand firewall roles in filtering inbound/outbound traffic based on ports, IPs, or protocols to prevent unauthorized access. Create basic iptables rules on Linux for stateful inspection (e.g., allow established connections, drop others). Test rules using Nmap scans pre/post-configuration to verify blocking. 

Key Steps for iptables Rules: 
View Rules: sudo iptables -L -n -v lists chains (INPUT, OUTPUT, FORWARD).
Default Policy: sudo iptables -P INPUT DROP blocks all incoming by default.
Allow Specific: sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT permits SSH; -s 192.168.1.0/24 restricts to subnet.
Allow Loopback/Established: sudo iptables -A INPUT -i lo -j ACCEPT; sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT.
Save Rules: sudo netfilter-persistent save. 
Testing and Delivery:
Pre-Scan: nmap -p 1-1000 target shows open ports.
Post-Rule Scan: Verify blocks (filtered ports).
Demo Video: Record rule setup, scans, and analysis.
Report: Screenshot rules, scan diffs, explain evasion attempts. 

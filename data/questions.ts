export const CEH_DUMP_QUESTIONS = [
  {
    id: 1,
    question:
      "Jason, a certified ethical hacker, is hired by a major e-commerce company to evaluate their network's security. As part of his reconnaissance, Jason is trying to gain as much information as possible about the company's public-facing servers without arousing suspicion. His goal is to find potential points of entry and map out the network infrastructure for further examination. Which technique should Jason employ to gather this information without alerting the company's intrusion detection systems (IDS)?",
    options: [
      "Jason should use a DNS zone transfer to gather information about the company's servers.",
      "Jason should use passive reconnaissance techniques such as WHOIS lookups, NS lookups, and web research.",
      "Jason should directly connect to each server and attempt to exploit known vulnerabilities.",
      "Jason should perform a ping sweep to identify all the live hosts in the company's IP range.",
    ],
    correctAnswer: 1,
  },
  {
    id: 2,
    question:
      "James is working as an ethical hacker at Technix Solutions. The management ordered James to discover how vulnerable its network is towards footprinting attacks. James took the help of an open-source framework for performing automated reconnaissance activities. This framework helped James in gathering information using free tools and resources. What is the framework used by James to conduct footprinting and reconnaissance activities?",
    options: [
      "OSINT framework",
      "WebSploit Framework",
      "SpeedPhish Framework",
      "Browser Exploitation Framework",
    ],
    correctAnswer: 0,
  },
  {
    id: 3,
    question:
      "Leverox Solutions hired Arnold, a security professional, for the threat intelligence process. Arnold collected information about specific threats against the organization. From this information, he retrieved contextual information about security events and incidents that helped him disclose potential risks and gain insight into attacker methodologies. He collected the information from sources such as humans, social media, and chat rooms as well as from events that resulted in cyberattacks. In this process, he also prepared a report that includes identified malicious activities, recommended courses of action, and warnings for emerging attacks. What is the type of threat intelligence collected by Arnold in the above scenario?",
    options: [
      "Strategic threat intelligence",
      "Tactical threat intelligence",
      "Operational threat intelligence",
      "Technical threat intelligence",
    ],
    correctAnswer: 2,
  },
  {
    id: 4,
    question:
      "What is the common name for a vulnerability disclosure program opened by companies in platforms such as HackerOne",
    options: [
      "Vulnerability hunting program",
      "Bug bounty program",
      "White-hat hacking program",
      "Ethical hacking program",
    ],
    correctAnswer: 1,
  },
  {
    id: 5,
    question:
      "During an ethical hacking engagement, you have been assigned to evaluate the security of a large organization's network. While examining the network traffic, you notice numerous incoming requests on various ports from different locations that show a pattern of an orchestrated attack. Based on your analysis, you deduce that the requests are likely to be automated scripts being run by unskilled hackers. What type of hacker classification does this scenario most likely represent",
    options: [
      "Black Hats trying to exploit system vulnerabilities for malicious intent.",
      "White Hats conducting penetration testing to identify security weaknesses.",
      "Gray Hats testing system vulnerabilities to help vendors improve security.",
      "Script Kiddies trying to compromise the system using pre-made scripts.",
    ],
    correctAnswer: 3,
  },
  {
    id: 6,
    question:
      "Which among the following is the best example of the third step (delivery) in the cyber kill chain?",
    options: [
      "An intruder creates malware to be used as a malicious attachment to an email.",
      "An intruder's malware is triggered when a target opens a malicious email attachment.",
      "An intruder's malware is installed on a targets machine.",
      "An intruder sends a malicious attachment via email to a target.",
    ],
    correctAnswer: 3,
  },
  {
    id: 7,
    question:
      "Louis, a professional hacker, had used specialized tools or search engines to encrypt all his browsing activity and navigate anonymously to obtain sensitive/hidden information about official government or federal databases. After gathering the information, he successfully performed an attack on the target government organization without being traced. Which of the following techniques is described in the above scenario?",
    options: [
      "Website footprinting",
      "VPN footprinting",
      "Dark web footprinting",
      "VoIP footpriting",
    ],
    correctAnswer: 2,
  },
  {
    id: 8,
    question:
      "Clark, a professional hacker, was hired by an organization to gather sensitive information about its competitors surreptitiously. Clark gathers the server IP address of the target organization using Whois footprinting. Further, he entered the server IP address as an input to an online tool to retrieve information such as the network range of the target organization and to identify the network topology and operating system used in the network. What is the online tool employed by Clark in the above scenario?",
    options: ["ARIN", "Baidu", "DuckDuckGo", "AOL"],
    correctAnswer: 0,
  },
  {
    id: 9,
    question:
      "A penetration tester is performing the footprinting process and is reviewing publicly available information about an organization by using the Google search engine. Which of the following advanced operators would allow the pen tester to restrict the search to the organization's web domain?",
    options: ["[location:]", "[site:]", "[link:]", "[allinurl:]"],
    correctAnswer: 1,
  },
  {
    id: 10,
    question:
      "Becky has been hired by a client from Dubai to perform a penetration test against one of their remote offices. Working from her location in Columbus, Ohio, Becky runs her usual reconnaissance scans to obtain basic information about their network. When analyzing the results of her Whois search, Becky notices that the IP was allocated to a location in Le Havre, France. Which regional Internet registry should Becky go to for detailed information?",
    options: ["LACNIC", "APNIC", "RIPE", "ARIN"],
    correctAnswer: 2,
  },
  {
    id: 11,
    question:
      "A certified ethical hacker is conducting a Whois footprinting activity on a specific domain. The individual is leveraging various tools such as Batch IP Converter and Whois Analyzer Pro to retrieve vital details but is unable to gather complete Whois information from the registrar for a particular set of data. As the hacker, what might be the probable data model being utilized by the domain's registrar for storing and looking up Whois information?",
    options: [
      "Thick Whois model working correctly",
      "Thick Whois model with a malfunctioning server",
      "Thin Whois model working correctly",
      "Thin Whois model with a malfunctioning server",
    ],
    correctAnswer: 2,
  },
  {
    id: 12,
    question:
      "A certified ethical hacker is carrying out an email footprinting exercise on a targeted organization using eMailTrackerPro. They want to map out detailed information about the recipient's activities after receiving the email. Which among the following pieces of information would NOT be directly obtained from eMailTrackerPro during this exercise?",
    options: [
      "The email accounts related to the domain of the organization",
      "The time recipient spent reading the email",
      "Geolocation of the recipient",
      "Type of device used to open the email",
    ],
    correctAnswer: 0,
  },
  {
    id: 13,
    question:
      "A Certified Ethical Hacker is attempting to gather information about a target organization's network structure through network footprinting. During the operation, they encounter ICMP blocking by the target system's firewall. The hacker wants to ascertain the path that packets take to the host system from a source, using an alternative protocol. Which of the following actions should the hacker consider next?",
    options: [
      "Use UDP Traceroute in the Linux operating system by executing the 'traceroute' command with the destination IP or domain name.",
      "Use the ARIN Whois database search tool to find the network range of the target network.",
      "Use the ICMP Traceroute on the Windows operating system as it is the default utility.",
      "Utilize the Path Analyzer Pro to trace the route from the source to the destination target systems.",
    ],
    correctAnswer: 0,
  },
  {
    id: 14,
    question:
      "As a Certified Ethical Hacker, you are conducting a footprinting and reconnaissance operation against a target organization. You discover a range of IP addresses associated with the target using the SecurityTrails tool. Now, you need to perform a reverse DNS lookup on these IP addresses to find the associated domain names, as well as determine the nameservers and mail exchange (MX) records. Which of the following DNSRecon commands would be most effective for this purpose?",
    options: [
      "dnsrecon -r 192.168.1.0/24 -n nsl.example.com -t axfr",
      "dnsrecon -r 162.241.216.0/24 -n nsl.example.com -t std",
      "dnsrecon -r 10.0.0.0/24 -n nsl.example.com -t zonewalk",
      "dnsrecon -r 162.241.216.0/24 -d example.com -t brt",
    ],
    correctAnswer: 1,
  },
  {
    id: 15,
    question:
      "Your company suspects a potential security breach and has hired you as a Certified Ethical Hacker to investigate. You discover evidence of footprinting through search engines and advanced Google hacking techniques. The attacker utilized Google search operators to extract sensitive information. You further notice queries that indicate the use of the Google Hacking Database (CHDB) with an emphasis on VPN footprinting. Which of the following Google advanced search operators would be the LEAST useful in providing the attacker with sensitive VPN-related information?",
    options: [
      "intitle: This operator restricts results to only the pages containing the specified term in the title",
      "location: This operator finds information for a specific location",
      "inurl: This operator restricts the results to only the pages containing the specified word in the URL",
      "link: This operator searches websites or pages that contain links to the specified website or page",
    ],
    correctAnswer: 3,
  },
  {
    id: 16,
    question:
      "During a reconnaissance mission, an ethical hacker uses Maltego, a popular footprinting tool, to collect information about a target organization. The information includes the target's Internet infrastructure details (domains, DNS names, Netblocks, IP address information). The hacker decides to use social engineering techniques to gain further information. Which of the following would be the least likely method of social engineering to yield beneficial information based on the data collected?",
    options: [
      "Shoulder surfing to observe sensitive credentials input on the target's computers",
      "Eavesdropping on internal corporate conversations to understand key topics",
      "Impersonating an ISP technical support agent to trick the target into providing further network details",
      "Dumpster diving in the target company's trash bins for valuable printouts",
    ],
    correctAnswer: 3,
  },
  {
    id: 17,
    question:
      "A skilled ethical hacker was assigned to perform a thorough OS discovery on a potential target. They decided to adopt an advanced fingerprinting technique and sent a TCP packet to an open TCP port with specific flags enabled. Upon receiving the reply, they noticed the flags were SYN and ECN-Echo. Which test did the ethical hacker conduct and why was this specific approach adopted?",
    options: [
      "Test 3: The test was executed to observe the response of the target system when a packet with URC, PSH, SYN, and FIN flags was sent, thereby identifying the OS",
      "Test 1: The test was conducted because SYN and ECN-Echo flags enabled to allow the hacker to probe the nature of the response and subsequently determine the OS fingerprint",
      "Test 6: The hacker selected this test because a TCP packet with the ACK flag enabled sent to a closed TCP port would yield more information about the OS",
      "Test 2: This test was chosen because a TCP packet with no flags enabled is known as a NULL packet and this would allow the hacker to assess the OS of the target",
    ],
    correctAnswer: 1,
  },
  {
    id: 18,
    question:
      "A penetration tester was assigned to scan a large network range to find live hosts. The network is known for using strict TCP filtering rules on its firewall, which may obstruct common host discovery techniques. The tester needs a method that can bypass these firewall restrictions and accurately identify live systems. What host discovery technique should the tester use?",
    options: [
      "ICMP Timestamp Ping Scan",
      "UDP Ping Scan",
      "ICMP ECHO Ping Scan",
      "TCP SYN Ping Scan Feedback",
    ],
    correctAnswer: 1,
  },
  {
    id: 19,
    question:
      "Harris is attempting to identify the OS running on his target machine. He inspected the initial TTL in the IP header and the related TCP window size and obtained the following results: TTL: 64 – Window Size: 5840",
    options: ["Linux OS", "Windows OS", "Mac OS", "Solaris OS"],
    correctAnswer: 0,
  },
  {
    id: 20,
    question:
      "In a large organization, a network security analyst discovered a series of packet captures that seem unusual. The network operates on a switched Ethernet environment. The security team suspects that an attacker might be using a sniffer tool. Which technique could the attacker be using to successfully carry out this attack, considering the switched nature of the network?",
    options: [
      "The attacker might be compromising physical security to plug into the network directly.",
      "The attacker is probably using a Trojan horse with in-built sniffing capability.",
      "The attacker might be implementing MAC flooding to overwhelm the switch's memory.",
      "The attacker might be using passive sniffing, as it provides significant stealth advantages.",
    ],
    correctAnswer: 2,
  },
  {
    id: 21,
    question:
      'You are a penetration tester and are about to perform a scan on a specific server. The agreement that you signed with the client contains the following specific condition for the scan: "The attacker must scan every port on the server several times using a set of spoofed source IP addresses." Suppose that you are using Nmap to perform this scan. What flag will you use to satisfy this requirement?',
    options: ["The -D flag", "The -g flag", "The -A flag", "The -f flag"],
    correctAnswer: 0,
  },
  {
    id: 22,
    question:
      "During a red team assessment, a CEH is given a task to perform network scanning on the target network without revealing its IP address. They are also required to find an open port and the services available on the target machine. What scanning technique should they employ, and which command in Zenmap should they use?",
    options: [
      'Use the IDLE/IPID header scan technique with the command "-sI"',
      'Use UDP Raw ICMP Port Unreachable Scanning with the command "-sU"',
      'Use the ACK flag probe scanning technique with the command "sA"',
      'Use SCTP INIT Scan with the command "-sY"',
    ],
    correctAnswer: 0,
  },
  {
    id: 23,
    question:
      "Techno Security Inc. recently hired John as a penetration tester. He was tasked with identifying open ports in the target network and determining whether the ports are online and any firewall rule sets are encountered. John decided to perform a TCP SYN ping scan on the target network. Which of the following Nmap commands must John use to perform the TCP SYN ping scan?",
    options: [
      "nmap -sn -PA < target IP address >",
      "nmap -sn -PO < target IP address >",
      "nmap -sn -PS < target IP address >",
      "nmap -sn -PP < target IP address >",
    ],
    correctAnswer: 2,
  },
  {
    id: 24,
    question:
      "Which is the first step followed by Vulnerability Scanners for scanning a network?",
    options: [
      "Checking if the remote host is alive",
      "Firewall detection",
      "OS Detection",
      "TCP/UDP Port scanning",
    ],
    correctAnswer: 0,
  },
  {
    id: 25,
    question:
      "You are attempting to run an Nmap port scan on a web server. Which of the following commands would result in a scan of common ports with the least amount of noise in order to evade IDS?",
    options: [
      "nmap -sT -O -T0",
      "nmap -sP -p-65535 -T5",
      "nmap -A – Pn",
      "nmap -A –host-timeout 99 -T1",
    ],
    correctAnswer: 0,
  },
  {
    id: 26,
    question:
      "Consider the Nmap output, What command-line parameter could you use to determine the type and version number of the web server?",
    options: ["-Pn", "-V", "-sS", "-sV"],
    correctAnswer: 3,
  },
  {
    id: 27,
    question:
      "A penetration tester is tasked with gathering information about the subdomains of a target organization's website. The tester needs a versatile and efficient solution for the task. Which of the following options would be the most effective method to accomplish this goal?",
    options: [
      "Employing a tool like Sublist3r, which is designed to enumerate the subdomains of websites using OSINT",
      "Utilizing the Harvester tool to extract email addresses related to the target domain using a search engine like Google or Bing",
      "Analyzing LinkedIn profiles to find employees of the target company and their job titles",
      "Using a people search service, such as Spokeo or Intelius, to gather information about the employees of the target organization",
    ],
    correctAnswer: 0,
  },
  {
    id: 28,
    question:
      "Consider a scenario where a Certified Ethical Hacker is attempting to infiltrate a company's network without being detected. The hacker intends to use a stealth scan on a BSD-derived TCP/IP stack, but he suspects that the network security devices may be able to detect SYN packets. Based on this information, which of the following methods should he use to bypass the detection mechanisms and why?",
    options: [
      "Maimon Scan, because it is very similar to NULL, FIN, and Xmas scans, but the probe used here is FIN/ACK",
      "Xmas Scan, because it can pass through filters undetected, depending on the security mechanisms installed",
      "ACK Flag Probe Scan, because it exploits the vulnerabilities within the BSD-derived TCP/IP stack",
      "TCP Connect/Full-Open Scan, because it completes a three way handshake with the target machine",
    ],
    correctAnswer: 2,
  },
  {
    id: 29,
    question:
      "A security analyst uses Zenmap to perform an ICMP timestamp ping scan to acquire information related to the current time from the target host machine. Which of the following Zenmap options must the analyst use to perform the ICMP timestamp ping scan?",
    options: ["-PY", "-Pn", "-PP", "-PU"],
    correctAnswer: 2,
  },
  {
    id: 30,
    question:
      "An ethical hacker is hired to conduct a comprehensive network scan of a large organization that strongly suspects potential intrusions into their internal systems. The hacker decides to employ a combination of scanning tools to obtain a detailed understanding of the network. Which sequence of actions would provide the most comprehensive information about the network's status?",
    options: [
      "Initiate with Nmap for a ping sweep, then use Metasploit to scan for open ports and services, and finally use Hping3 to perform remote OS fingerprinting.",
      "Use Hping3 for an ICMP ping scan on the entire subnet, then use Nmap for a SYN scan on identified active hosts, and finally use Metasploit to exploit identified vulnerabilities.",
      "Start with Hping3 for a UDP scan on random ports, then use Nmap for a version detection scan, and finally use Metasploit to exploit detected vulnerabilities.",
      "Begin with NetScanTools Pro for a general network scan, then use Nmap for OS detection and version detection, and finally perform an SYN flooding with Hping3.",
    ],
    correctAnswer: 0,
  },
  {
    id: 31,
    question:
      "Sam is a penetration tester hired by Inception Tech, a security organization. He was asked to perform port scanning on a target host in the network. While performing the given task, Sam sends FIN/ACK probes and determines that an RST packet is sent in response by the target host, indicating that the port is closed. What is the port scanning technique used by Sam to discover open ports?",
    options: [
      "IDLE/IPID header scan",
      "TCP Maimon scan",
      "ACK flag probe scan",
      "Xmas scan",
    ],
    correctAnswer: 1,
  },
  {
    id: 32,
    question: "What is the following command used for?",
    options: [
      "Retrieving SQL statements being executed on the database",
      "Searching database statements at the IP address given",
      "Creating backdoors using SQL injection",
      "Enumerating the databases in the DBMS for the URL",
    ],
    correctAnswer: 3,
  },
  {
    id: 33,
    question:
      "Henry is a penetration tester who works for XYZ organization. While performing enumeration on a client organization, he queries the DNS server for a specific cached DNS record. Further, by using this cached record, he determines the sites recently visited by the organization's user. What is the enumeration technique used by Henry on the organization?",
    options: [
      "DNS cache poisoning",
      "DNS zone walking",
      "DNSSEC zone walking",
      "DNS cache snooping",
    ],
    correctAnswer: 3,
  },
  {
    id: 34,
    question:
      "In an attempt to damage the reputation of a competitor organization, Hailey, a professional hacker, gathers a list of employee and client email addresses and other related information by using various search engines, social networking sites, and web spidering tools. In this process, she also uses an automated tool to gather a list of words from the target website to further perform a brute-force attack on the previously gathered email addresses.",
    options: ["Orbot", "CeWL", "Psiphon", "Shadowsocks"],
    correctAnswer: 1,
  },
  {
    id: 35,
    question:
      "John, a professional hacker, targeted an organization that uses LDAP for accessing distributed directory services. He used an automated tool to anonymously query the LDAP service for sensitive information such as usernames, addresses, departmental details, and server names to launch further attacks on the target organization. What is the tool employed by John to gather information from the LDAP service?",
    options: ["ike-scan", "Zabasearch", "JXplorer", "EarthExplorer"],
    correctAnswer: 2,
  },
  {
    id: 36,
    question:
      "Calvin, a grey-hat hacker, targets a web application that has design flaws in its authentication mechanism. He enumerates usernames from the login form of the web application, which requests users to feed data and specifies the incorrect field in case of invalid credentials. Later, Calvin uses this information to perform social engineering. Which of the following design flaws in the authentication mechanism is exploited by Calvin?",
    options: [
      "Verbose failure messages",
      "Password reset mechanism",
      "User impersonation",
      "Insecure transmission of credentials",
    ],
    correctAnswer: 0,
  },
  {
    id: 37,
    question:
      "As a certified ethical hacker, you are tasked with gaining information about an enterprise's internal network. You are permitted to test the network's security using enumeration techniques. You successfully obtain a list of usernames using email IDs and execute a DNS Zone Transfer. Which enumeration technique would be most effective for your next move given that you have identified open TCP ports 25 (SMTP) and 139 (NetBIOS Session Service)?",
    options: [
      "Perform a brute force attack on Microsoft Active Directory to extract valid usernames",
      "Use SNMP to extract usernames given the community strings",
      "Exploit the NetBIOS Session Service on TCP port 139 to gain unauthorized access to the file system",
      "Exploit the NFS protocol on TCP port 2049 to gain control over a remote system",
    ],
    correctAnswer: 2,
  },
  {
    id: 38,
    question:
      "A Certified Ethical Hacker (CEH) is given the task to perform an LDAP enumeration on a target system. The system is secured and accepts connections only on secure LDAP. The CEH uses Python for the enumeration process. After successfully installing LDAP and establishing a connection with the target, he attempts to fetch details like the domain name and naming context but is unable to receive the expected response. Considering the circumstances, which of the following is the most plausible reason for this situation?",
    options: [
      "The system failed to establish a connection due to an incorrect port number.",
      "The enumeration process was blocked by the target system's intrusion detection system.",
      "The Python version installed on the CEH's machine is incompatible with the Idap3 library.",
      "The secure LDAP connection was not properly initialized due to a lack of 'use_ssl = True' in the server object creation.",
    ],
    correctAnswer: 3,
  },
  {
    id: 39,
    question:
      "Being a Certified Ethical Hacker (CEH), a company has brought you on board to evaluate the safety measures in place for their network system. The company uses a network time protocol server in the demilitarized zone. During your enumeration, you decide to run a ntptrace command. Given the syntax: ntptrace [-n] [-m maxhosts] [servername/IP_address], which command usage would best serve your objective to find where the NTP server obtains the time from and to trace the list of NTP servers connected to the network?",
    options: [
      "ntptrace -m 5192.168.1.1",
      "ntptrace -n localhost",
      "ntptrace 192.168.1.1",
      "ntptrace -n -m 5192.168.1.1",
    ],
    correctAnswer: 2,
  },
  {
    id: 40,
    question:
      "A post-breach forensic investigation revealed that a known vulnerability in Apache Struts was to blame for the Equifax data breach that affected 143 million customers. A fix was available from the software vendor for several months prior to the intrusion. This is likely a failure in which of the following security processes?",
    options: [
      "Vendor risk management",
      "Security awareness training",
      "Patch management",
      "Secure development lifecycle",
    ],
    correctAnswer: 2,
  },
  {
    id: 41,
    question:
      "XYZ company recently discovered a potential vulnerability on their network, originating from misconfigurations. It was found that some of their host servers had enabled debugging functions and unknown users were granted administrative permissions. As a Certified Ethical Hacker, what would be the most potent risk associated with this misconfiguration?",
    options: [
      "Unauthorized users may perform privilege escalation using unnecessarily created accounts",
      "An attacker may carry out a Denial-of-Service assault draining the resources of the server in the process",
      "An attacker may be able to inject a malicious DLL into the current running process",
      "Weak encryption might be allowing man-in-the-middle attacks, leading to data tampering",
    ],
    correctAnswer: 0,
  },
  {
    id: 42,
    question:
      "During a recent vulnerability assessment of a major corporation's IT systems, the security team identified several potential risks. They want to use a vulnerability scoring system to quantify and prioritize these vulnerabilities. They decide to use the Common Vulnerability Scoring System (CVSS). Given the characteristics of the identified vulnerabilities, which of the following statements is the most accurate regarding the metric types used by CVSS to measure these vulnerabilities?",
    options: [
      "Base metric represents the inherent qualities of a vulnerability.",
      "Temporal metric represents the inherent qualities of a vulnerability.",
      "Temporal metric involves measuring vulnerabilities based on a specific environment or implementation.",
      "Environmental metric involves the features that change during the lifetime of the vulnerability.",
    ],
    correctAnswer: 0,
  },
  {
    id: 43,
    question:
      "What piece of hardware on a computer's motherboard generates encryption keys and only releases a part of the key so that decrypting a disk on a new piece of hardware is not possible?",
    options: ["TPM", "GPU", "CPU", "UEFI"],
    correctAnswer: 0,
  },
  {
    id: 44,
    question:
      "In your cybersecurity class, you are learning about common security risks associated with web servers. One topic that comes up is the risk posed by using default server settings. Why is using default settings on a web server considered a security risk, and what would be the best initial step to mitigate this risk?",
    options: [
      "Default settings allow unlimited login attempts; setup account lockout",
      "Default settings reveal server software type; change these settings",
      "Default settings cause server malfunctions; simplify the settings",
      "Default settings enable auto-updates; disable and manually patch",
    ],
    correctAnswer: 1,
  },
  {
    id: 45,
    question:
      "Your company has been receiving regular alerts from its IDS about potential intrusions. On further investigation, you notice that these alerts have been false positives triggered by certain goodware files. In response, you are planning to enhance the IDS with YARA rules, reducing these false positives while improving the detection of real threats. Based on the scenario and the principles of YARA and IDS, which of the following strategies would best serve your purpose?",
    options: [
      "Writing YARA rules specifically to identify the goodware files triggering false positives",
      "Implementing YARA rules that focus solely on known malware signatures",
      "Incorporating YARA rules to detect patterns in all files regardless of their nature",
      "Creating YARA rules to examine only the private database for intrusions",
    ],
    correctAnswer: 0,
  },
  {
    id: 46,
    question:
      "What information security law or standard aims at protecting stakeholders and the general public from accounting errors and fraudulent activities within organizations?",
    options: ["SOX", "PCI-DSS", "FISMA", "ISO/IEC 27001:2013"],
    correctAnswer: 0,
  },
  {
    id: 47,
    question:
      "Given below are different steps involved in the vulnerability-management life cycle. 1) Remediation 2) Identify assets and create a baseline 3) Verification 4) Monitor 5) Vulnerability scan 6) Risk assessment Identify the correct sequence of steps involved in vulnerability management.",
    options: [
      "2 → 1 → 5 → 6 → 4 → 3",
      "2 → 4 → 5 → 3 → 6 → 1",
      "1 → 2 → 3 → 4 → 5 → 6",
      "2 → 5 → 6 → 1 → 3 → 4",
    ],
    correctAnswer: 3,
  },
  {
    id: 48,
    question:
      "Morris, an attacker, wanted to check whether the target AP is in a locked state. He attempted using different utilities to identify WPS-enabled APs in the target wireless network. Ultimately, he succeeded with one special command-line utility. Which of the following command-line utilities allowed Morris to discover the WPS-enabled APs?",
    options: ["net view", "wash", "ntptrace", "macof"],
    correctAnswer: 1,
  },
  {
    id: 49,
    question:
      "You are an ethical hacker contracted to conduct a security audit for a company. During the audit, you discover that the company's wireless network is using WEP encryption. You understand the vulnerabilities associated with WEP and plan to recommend a more secure encryption method. Which of the following would you recommend as a suitable replacement to enhance the security of the company's wireless network?",
    options: [
      "Open System authentication",
      "SSID broadcast disabling",
      "WPA2-PSK with AES encryption",
      "MAC address filtering",
    ],
    correctAnswer: 2,
  },
  {
    id: 50,
    question:
      "Larry, a security professional in an organization, has noticed some abnormalities in the user accounts on a web server. To thwart evolving attacks, he decided to harden the security of the web server by adopting a few countermeasures to secure the accounts on the web server. Which of the following countermeasures must Larry implement to secure the user accounts on the web server?",
    options: [
      "Limit the administrator or root-level access to the minimum number of users.",
      "Enable all non-interactive accounts that should exist but do not require interactive login.",
      "Enable unused default user accounts created during the installation of an OS.",
      "Retain all unused modules and application extensions.",
    ],
    correctAnswer: 0,
  },
  {
    id: 51,
    question:
      "An IT company has just implemented new security controls to their network and system setup. As a Certified Ethical Hacker, your responsibility is to assess the possible vulnerabilities in the new setup. You are given the information that the network and system are adequately patched with the latest updates, and all employees have gone through recent cybersecurity awareness training. Considering the potential vulnerability sources, what is the best initial approach to vulnerability assessment?",
    options: [
      "Conducting social engineering tests to check if employees can be tricked into revealing sensitive information",
      "Evaluating the network for inherent technology weaknesses prone to specific types of attacks",
      "Checking for hardware and software misconfigurations to identify any possible loopholes",
      "Investigating if any ex employees still have access to the company's system and data",
    ],
    correctAnswer: 2,
  },
  {
    id: 52,
    question:
      "An organization is performing a vulnerability assessment for mitigating threats. James, a pen tester, scanned the organization by building an inventory of the protocols found on the organization's machines to detect which ports are attached to services such as an email server, a web server, or a database server. After identifying the services, he selected the vulnerabilities on each machine and started executing only the relevant tests. What is the type of vulnerability assessment solution that James employed in the above scenario?",
    options: [
      "Product-based solutions",
      "Service-based solutions",
      "Tree-based assessment",
      "Inference-based assessment",
    ],
    correctAnswer: 3,
  },
  {
    id: 53,
    question:
      "An organization suspects a persistent threat from a cybercriminal. They hire an ethical hacker, John, to evaluate their system security. John identifies several vulnerabilities and advises the organization on preventive measures. However, the organization has limited resources and opts to fix only the most severe vulnerability. Subsequently, a data breach occurs exploiting a different vulnerability. Which of the following statements best describes this scenario?",
    options: [
      "The organization is not at fault because they used their resources as per their understanding.",
      "The organization is at fault because it did not fix all identified vulnerabilities.",
      "John is at fault because he did not emphasize the necessity of patching all vulnerabilities.",
      "Both the organization and John share responsibility because they did not adequately manage the vulnerabilities.",
    ],
    correctAnswer: 3,
  },
  {
    id: 54,
    question:
      "At what stage of the cyber kill chain theory model does data exfiltration occur?",
    options: [
      "Command and control",
      "Installation",
      "Weaponization",
      "Actions on objectives",
    ],
    correctAnswer: 3,
  },
  {
    id: 55,
    question:
      "Bill has been hired as a penetration tester and cyber security auditor for a major credit card company. Which information security standard is most applicable to his role?",
    options: ["HITECH", "PCI-DSS", "Sarbanes-Oxley Act", "FISMA"],
    correctAnswer: 1,
  },
  {
    id: 57,
    question:
      "John, a disgruntled ex-employee of an organization, contacted a professional hacker to exploit the organization. In the attack process, the professional hacker installed a scanner on a machine belonging to one of the victims and scanned several machines on the same network to identify vulnerabilities to perform further exploitation. What is the type of vulnerability assessment tool employed by John in the above scenario?",
    options: [
      "Agent-based scanner",
      "Proxy scanner",
      "Cluster scanner",
      "Network-based scanner",
    ],
    correctAnswer: 0,
  },
  {
    id: 58,
    question:
      "In the process of implementing a network vulnerability assessment strategy for a tech company, the security analyst is confronted with the following scenarios. Which of the following is a limitation of vulnerability scanning software?",
    options: [
      "Vulnerability scanning software is not immune to software engineering flaws that might lead to serious vulnerabilities being missed",
      "Vulnerability scanning software cannot define the impact of an identified vulnerability on different business operations",
      "Vulnerability scanning software is limited in its ability to detect vulnerabilities at a given point in time",
      "Vulnerability scanning software is limited in its ability to perform live tests on web applications to detect errors or unexpected behavior",
    ],
    correctAnswer: 1,
  },
  {
    id: 59,
    question:
      "Given the complexities of an organization's network infrastructure, a threat actor has exploited an unidentified vulnerability, leading to a major data breach. As a Certified Ethical Hacker (CEH), you are tasked with enhancing the organization's security stance. To ensure a comprehensive security defense, you recommend a certain security strategy. Which of the following best represents the strategy you would likely suggest and why?",
    options: [
      "Develop an in-depth Risk Management process, involving identification, assessment, treatment, tracking, and review of risks to control the potential effects on the organization.",
      "Establish a Defense-in-Depth strategy, incorporating multiple layers of security measures to increase the complexity and decrease the likelihood of a successful attack.",
      "Adopt a Continual/Adaptive Security Strategy involving ongoing prediction, prevention, detection, and response actions to ensure comprehensive computer network defense.",
      "Implement an Information Assurance (IA) policy focusing on ensuring the integrity, availability, confidentiality, and authenticity of information systems.",
    ],
    correctAnswer: 2,
  },
  {
    id: 60,
    question:
      "A large organization has recently performed a vulnerability assessment using Nessus Professional, and the security team is now preparing the final report. They have identified a high-risk vulnerability, named XYZ, which could potentially allow unauthorized access to the network. In preparing the report, which of the following elements would NOT be typically included in the detailed documentation for this specific vulnerability?",
    options: [
      "Proof of concept (PoC) of the vulnerability, if possible, to demonstrate its potential impact on the system.",
      "The list of all affected systems within the organization that are susceptible to the identified vulnerability.",
      "The CVE ID of the vulnerability and its mapping to the vulnerability's name, XYZ.",
      "The total number of high, medium, and low-risk vulnerabilities detected throughout the network.",
    ],
    correctAnswer: 0,
  },
  {
    id: 61,
    question:
      "A large e-commerce organization is planning to implement a vulnerability assessment solution to enhance its security posture. They require a solution that imitates the outside view of attackers, performs well-organized inference-based testing, scans automatically against continuously updated databases, and supports multiple networks. Given these requirements, which type of vulnerability assessment solution would be most appropriate?",
    options: [
      "Product-based solution installed on a private network",
      "Tree-based assessment approach",
      "Inference-based assessment solution",
      "Service-based solution offered by an auditing firm",
    ],
    correctAnswer: 3,
  },
  {
    id: 62,
    question:
      "An attacker decided to crack the passwords used by industrial control systems. In this process, he employed a loop strategy to recover these passwords. He used one character at a time to check whether the first character entered is correct; if so, he continued the loop for consecutive characters. If not, he terminated the loop. Furthermore, the attacker checked how much time the device took to finish one complete password authentication process, through which he deduced how many characters entered are correct. What is the attack technique employed by the attacker to crack the passwords of the industrial control systems?",
    options: [
      "HMI-based attack",
      "Side-channel attack",
      "Buffer overflow attack",
      "Denial-of-service attack",
    ],
    correctAnswer: 1,
  },
  {
    id: 63,
    question:
      "As a certified ethical hacker, you are performing a system hacking process for a company that is suspicious about its security system. You found that the company's passwords are all known words, but not in the dictionary. You know that one employee always changes the password by just adding some numbers to the old password. Which attack is most likely to succeed in this scenario?",
    options: [
      "Brute-Force Attack",
      "Hybrid Attack",
      "Password Spraying Attack",
      "Rule-based Attack",
    ],
    correctAnswer: 1,
  },
  {
    id: 64,
    question:
      "Infecting a system with malware and using phishing to gain credentials to a system or web application are examples of which phase of the ethical hacking methodology?",
    options: [
      "Maintaining access",
      "Reconnaissance",
      "Scanning",
      "Gaining access",
    ],
    correctAnswer: 3,
  },
  {
    id: 65,
    question:
      "John, a professional hacker, performs a network attack on a renowned organization and gains unauthorized access to the target network. He remains in the network without being detected for a long time and obtains sensitive information without sabotaging the organization. Which of the following attack techniques is used by John?",
    options: [
      "Advanced persistent threat",
      "Insider threat",
      "Spear-phishing sites",
      "Diversion theft",
    ],
    correctAnswer: 0,
  },
  {
    id: 66,
    question:
      "An ethical hacker is attempting to crack NTLM hashed passwords from a Windows SAM file using a rainbow table attack. He has dumped the on-disk contents of the SAM file successfully and noticed that all LM hashes are blank. Given this scenario, which of the following would be the most likely reason for the blank LM hashes?",
    options: [
      "The Windows system is Vista or a later version, where LM hashes are disabled by default.",
      "The passwords exceeded 14 characters in length and therefore, the LM hashes were set to a 'dummy' value.",
      "The Windows system is using the Kerberos authentication protocol as the default method.",
      "The SAM file has been encrypted using the SYSKEY function.",
    ],
    correctAnswer: 0,
  },
  {
    id: 67,
    question:
      "Attacker Simon targeted the communication network of an organization and disabled the security controls of NetNTLMv1 by modifying the values of LMCompatibilityLevel, NTLMMinClientSec, and RestrictSendingNTLMTraffic. He then extracted all the non-network logon tokens from all the active processes to masquerade as a legitimate user to launch further attacks. What is the type of attack performed by Simon?",
    options: [
      "Dictionary attack",
      "Internal monologue attack",
      "Rainbow table attack",
      "Combinator attack",
    ],
    correctAnswer: 1,
  },
  {
    id: 68,
    question:
      "A network security analyst, while conducting penetration testing, is aiming to identify a service account password using the Kerberos authentication protocol. They have a valid user authentication ticket (TGT) and decided to carry out a Kerberoasting attack. In the scenario described, which of the following steps should the analyst take next?",
    options: [
      "Carry out a passive wire sniffing operation using Internet packet sniffers",
      "Request a service ticket for the service principal name of the target service account",
      "Extract plaintext passwords, hashes, PIN codes, and Kerberos tickets using a tool like Mimikatz",
      "Perform a PRobability INfinite Chained Elements (PRINCE) attack",
    ],
    correctAnswer: 1,
  },
  {
    id: 69,
    question:
      "A malicious user has acquired a Ticket Granting Service from the domain controller using a valid user's Ticket Granting Ticket in a Kerberoasting attack. He exhorted the TGS tickets from memory for offline cracking. But the attacker was stopped before he could complete his attack. The system administrator needs to investigate and remediate the potential breach. What should be the immediate step the system administrator takes?",
    options: [
      "Invalidate the TGS the attacker acquired",
      "Delete the compromised user's account",
      "Change the NTLM password hash used to encrypt the ST",
      "Perform a system reboot to clear the memory",
    ],
    correctAnswer: 0,
  },
  {
    id: 70,
    question:
      "A security analyst is preparing to analyze a potentially malicious program believed to have infiltrated an organization's network. To ensure the safety and integrity of the production environment, the analyst decided to use a sheep dip computer for the analysis. Before initiating the analysis, what key step should the analyst take?",
    options: [
      "Connect the sheep dip computer to the organization's internal network.",
      "Install the potentially malicious program on the sheep dip computer.",
      "Store the potentially malicious program on an external medium, such as a CD-ROM.",
      "Run the potentially malicious program on the sheep dip computer to determine its behavior.",
    ],
    correctAnswer: 2,
  },
  {
    id: 71,
    question:
      "Which IOS jailbreaking technique patches the kernel during the device boot so that it becomes jailbroken after each successive reboot?",
    options: [
      "Semi-untethered jailbreaking",
      "Semi-tethered jailbreaking",
      "Untethered jailbreaking",
      "Tethered jailbreaking",
    ],
    correctAnswer: 2,
  },
  {
    id: 72,
    question:
      "An IT security team is conducting an internal review of security protocols in their organization to identify potential vulnerabilities. During their investigation, they encounter a suspicious program running on several computers. Further examination reveals that the program has been logging all user keystrokes. How can the security team confirm the type of program and what countermeasures should be taken to ensure the same attack does not occur in the future?",
    options: [
      "The program is a keylogger; the team should employ intrusion detection systems and regularly update the system software.",
      "The program is a keylogger; the team should educate employees about phishing attacks and maintain regular backups.",
      "The program is a Trojan; the team should regularly update antivirus software and install a reliable firewall.",
      "The program is spyware; the team should use password managers and encrypt sensitive data.",
    ],
    correctAnswer: 0,
  },
  {
    id: 73,
    question:
      "Recently, the employees of a company have been receiving emails that seem to be from their colleagues, but with suspicious attachments. When opened, these attachments appear to install malware on their systems. The IT department suspects that this is a targeted malware attack. Which of the following measures would be the most effective in preventing such attacks?",
    options: [
      "Applying the latest patches and updating software programs",
      "Disabling Autorun functionality on all drives",
      "Regularly scan systems for any new files and examine them",
      "Avoiding the use of outdated web browsers and email software",
    ],
    correctAnswer: 0,
  },
  {
    id: 74,
    question:
      "Mirai malware targets IoT devices. After infiltration, it uses them to propagate and create botnets that are then used to launch which types of attack?",
    options: [
      "Birthday attack",
      "MITM attack",
      "Password attack",
      "DDoS attack",
    ],
    correctAnswer: 3,
  },
  {
    id: 75,
    question:
      "Which of the following Metasploit post-exploitation modules can be used to escalate privileges on Windows systems?",
    options: ["getuid", "autoroute", "keylogrecorder", "getsystem"],
    correctAnswer: 3,
  },
  {
    id: 76,
    question:
      "Which type of malware spreads from one system to another or from one network to another and causes similar types of damage as viruses do to the infected system?",
    options: ["Rootkit", "Worm", "Adware", "Trojan"],
    correctAnswer: 1,
  },
  {
    id: 77,
    question:
      "Security administrator John Smith has noticed abnormal amounts of traffic coming from local computers at night. Upon reviewing, he finds that user data have been exfiltrated by an attacker. AV tools are unable to find any malicious software, and the IDS/IPS has not reported on any non-whitelisted programs. What type of malware did the attacker use to bypass the company's application whitelisting?",
    options: [
      "Logic bomb malware",
      "Zero-day malware",
      "Phishing malware",
      "File-less malware",
    ],
    correctAnswer: 3,
  },
  {
    id: 78,
    question:
      "In the process of setting up a lab for malware analysis, a cybersecurity analyst is tasked to establish a secure environment using a sheep dip computer. The analyst must prepare the testbed while adhering to best practices. Which of the following steps should the analyst avoid when configuring the environment?",
    options: [
      "Installing malware analysis tools on the guest OS",
      "Installing multiple guest operating systems on the virtual machine(s)",
      "Simulating Internet services using tools such as INetSim",
      "Connecting the system to the production network during the malware analysis",
    ],
    correctAnswer: 3,
  },
  {
    id: 79,
    question:
      "A large corporate network is being subjected to repeated sniffing attacks. To increase security, the company's IT department decides to implement a combination of several security measures. They permanently add the MAC address of the gateway to the ARP cache, switch to using IPv6 instead of IPv4, implement the use of encrypted sessions such as SSH instead of Telnet, and use Secure File Transfer Protocol instead of FTP. However, they are still faced with the threat of sniffing. Considering the countermeasures, what should be their next step to enhance network security?",
    options: [
      "Use HTTP instead of HTTPS for protecting usernames and passwords",
      "Implement network scanning and monitoring tools",
      "Enable network identification broadcasts",
      "Retrieve MAC addresses from the OS",
    ],
    correctAnswer: 1,
  },
  {
    id: 80,
    question:
      "Martin, a Certified Ethical Hacker (CEH), is conducting a penetration test on a large enterprise network. He suspects that sensitive information might be leaking out of the network. Martin decides to use network sniffing as part of his testing methodology. Which of the following sniffing techniques should Martin employ to get a comprehensive understanding of the data flowing across the network?",
    options: ["DNS Poisoning", "ARP Poisoning", "Raw Sniffing", "MAC Flooding"],
    correctAnswer: 2,
  },
  {
    id: 81,
    question:
      "You are using a public Wi-Fi network inside a coffee shop. Before surfing the web, you use your VPN to prevent intruders from sniffing your traffic. If you did not have a VPN, how would you identify whether someone is performing an ARP spoofing attack on your laptop?",
    options: [
      "You cannot identify such an attack and must use a VPN to protect your traffic.",
      "You should use netstat to check for any suspicious connections with another IP address within the LAN.",
      "You should check your ARP table and see if there is one IP address with two different MAC addresses.",
      "You should scan the network using Nmap to check the MAC addresses of all the hosts and look for duplicates.",
    ],
    correctAnswer: 2,
  },
  {
    id: 82,
    question:
      "You are a cybersecurity consultant for a major airport that offers free Wi-Fi to travelers. The management is concerned about the possibility of 'Evil Twin' attacks, where a malicious actor sets up a rogue access point that mimics the legitimate one. They are looking for a solution that would not significantly impact the user experience or require travelers to install additional software. What is the most effective security measure you could recommend that fits these constraints, considering the airport's unique operational environment?",
    options: [
      "Use MAC address filtering on the airport's Wi-Fi network",
      "Display a captive portal page that warns users about the possibility of Evil Twin attacks",
      "Regularly change the SSID of the airport's Wi-Fi network",
      "Implement WPA3 encryption for the airport's Wi-Fi network",
    ],
    correctAnswer: 1,
  },
  {
    id: 83,
    question:
      "Which of the following tactics uses malicious code to redirect users' web traffic?",
    options: ["Spear-phishing", "Pharming", "Spimming", "Phishing"],
    correctAnswer: 1,
  },
  {
    id: 84,
    question:
      "Miley, a professional hacker, decided to attack a target organization's network. To perform the attack, she used a tool to send fake ARP messages over the target network to link her MAC address with the target system's IP address. By performing this, Miley received messages directed to the victim's MAC address and further used the tool to intercept steal, modify, and block sensitive communication to the target system.",
    options: ["Gobbler", "DerpNSpoof", "BetterCAP", "Wireshark"],
    correctAnswer: 2,
  },
  {
    id: 85,
    question:
      "Which type of attack attempts to overflow the content-addressable memory (CAM) table in an Ethernet switch?",
    options: [
      "MAC flooding",
      "Evil twin attack",
      "DNS cache flooding",
      "DDoS attack",
    ],
    correctAnswer: 0,
  },
  {
    id: 86,
    question:
      "Robin, a professional hacker, targeted an organization's network to sniff all the traffic. During this process, Robin plugged in a rogue switch to an unused port in the LAN with a priority lower than any other switch in the network so that he could make it a root bridge that will later allow him to sniff all the traffic in the network. What is the attack performed by Robin in the above scenario?",
    options: [
      "STP attack",
      "ARP spoofing attack",
      "VLAN hopping attack",
      "DNS poisoning attack",
    ],
    correctAnswer: 0,
  },
  {
    id: 87,
    question:
      "An ethical hacker has been tasked with assessing the security of a major corporation's network. She suspects the network uses default SNMP community strings. To exploit this, she plans to extract valuable network information using SNMP enumeration. Which tool could best help her to get the information without directly modifying any parameters within the SNMP agent's management information base (MIB)?",
    options: [
      "Nmap, with a script to retrieve all running SNMP processes and associated ports",
      "OpUtils, are mainly designed for device management and not SNMP enumeration",
      "SnmpWalk, with a command to change an OID to a different value",
      "snmp-check (snmp_enum Module) to gather a wide array of information about the target",
    ],
    correctAnswer: 3,
  },
  {
    id: 88,
    question:
      "An attacker can employ many methods to perform social engineering against unsuspecting employees, including scareware. What is the best example of a scareware attack?",
    options: [
      "A banner appears to a user stating, 'Your Amazon order has been delayed. Click here to find out your new delivery date.'",
      "A pop-up appears to a user stating, 'You have won a free cruise! Click here to claim your prize!'",
      "A pop-up appears to a user stating, 'Your computer may have been infected with spyware. Click here to install an anti-spyware tool to resolve this issue.'",
      "A banner appears to a user stating, 'Your account has been locked. Click here to reset your password and unlock your account.'",
    ],
    correctAnswer: 2,
  },
  {
    id: 89,
    question:
      "A multinational organization has recently faced a severe information security breach. Investigations reveal that the attacker had a high degree of understanding of the organization's internal processes and systems. This knowledge was utilized to bypass security controls and corrupt valuable resources. Considering this event, the security team is contemplating the type of attack that occurred and the steps they could have taken to prevent it. Choose the most plausible type of attack and a countermeasure that the organization could have employed:",
    options: [
      "Distribution attack and the organization could have ensured software and hardware integrity checks.",
      "Active attack and the organization could have used network traffic analysis.",
      "Passive attack and the organization should have used encryption techniques.",
      "Insider attacks and the organization should have implemented robust access control and monitoring.",
    ],
    correctAnswer: 3,
  },
  {
    id: 90,
    question:
      "Sophia is a shopping enthusiast who spends significant time searching for trendy outfits online. Clark, an attacker, noticed her activities several times and sent a fake email containing a deceptive page link to her social media page displaying all-new and trendy outfits. In excitement, Sophia clicked on the malicious link and logged in to that page using her valid credentials. Which of the following tools is employed by Clark to create the spoofed email?",
    options: ["Slowloris", "PyLoris", "PLCinject", "Evilginx"],
    correctAnswer: 3,
  },
  {
    id: 91,
    question:
      "An experienced cyber attacker has created a fake LinkedIn profile, successfully impersonating a high ranking official from a well-established company, to execute a social engineering attack. The attacker then connected with other employees within the organization, receiving invitations to exclusive corporate events and gaining access to proprietary project details shared within the network. What advanced social engineering technique has the attacker primarily used to exploit the system and what is the most likely immediate threat to the organization?",
    options: [
      "Baiting and Involuntary Data Leakage",
      "Whaling and Targeted Attacks",
      "Spear Phishing and Spam",
      "Pretexting and Network Vulnerability",
    ],
    correctAnswer: 3,
  },
  {
    id: 92,
    question:
      "A large corporation is planning to implement preventive measures to counter a broad range of social engineering techniques. The organization has implemented a signature-based IDS, intrusion detection system, to detect known attack payloads and network flow analysis to monitor data entering and leaving the network. The organization is deliberating on the next step. Considering the information provided about various social engineering techniques, what should be the organization's next course of action?",
    options: [
      "Organize regular employee awareness training regarding social engineering techniques and preventive measures",
      "Deploy more security personnel to physically monitor key points of access",
      "Set up a honeypot to attract potential attackers into a controlled environment for analysis",
      "Implement endpoint detection and response solution to oversee endpoint activities",
    ],
    correctAnswer: 0,
  },
  {
    id: 93,
    question:
      "A large organization is investigating a possible identity theft case where an attacker has created a new identity by combining multiple pieces of information from different victims to open a new bank account. The attacker also managed to receive government benefits using a fraudulent identity. Given the circumstances, which type of identity theft is the organization dealing with?",
    options: [
      "Child Identity Theft",
      "Social Identity Theft",
      "Synthetic Identity Theft",
      "Identity Cloning and Concealment",
    ],
    correctAnswer: 2,
  },
  {
    id: 94,
    question:
      "A company recently experienced a debilitating social engineering attack that led to substantial identity theft. An inquiry found that the employee inadvertently provided critical information during an innocuous phone conversation. Considering the specific guidelines issued by the company to thwart social engineering attacks, which countermeasure would have been the most successful in averting the incident?",
    options: [
      "Adopt a robust software policy that restricts the installation of unauthorized applications.",
      "Conduct comprehensive training sessions for employees on various social engineering methodologies and the risks associated with revealing confidential data.",
      "Reinforce physical security measures to limit access to sensitive zones within the company premises, thereby warding off unauthorized intruders.",
      "Implement a well-documented change management process for modifications related to hardware or software.",
    ],
    correctAnswer: 1,
  },
  {
    id: 95,
    question:
      "A large enterprise has been experiencing sporadic system crashes and instability, resulting in limited access to its web services. The security team suspects it could be a result of a Denial of Service (DoS) attack. A significant increase in traffic was noticed in the network logs, with patterns suggesting packet sizes exceeding the prescribed size limit. Which among the following DoS attack techniques best describes this scenario?",
    options: [
      "Smurf attack",
      "UDP flood attack",
      "Ping of Death attack",
      "Pulse wave attack",
    ],
    correctAnswer: 2,
  },
  {
    id: 96,
    question:
      "In an advanced digital security scenario, a multinational enterprise is being targeted with a complex series of assaults aimed to disrupt operations, manipulate data integrity, and cause serious financial damage. As the Lead Cybersecurity Analyst with CEH and CISSP certifications, your responsibility is to correctly identify the specific type of attack based on the following indicators:",
    options: [
      "Watering Hole Attack",
      "Privilege Escalation Attack",
      "Rowhammer Attack",
      "Side-Channel Attack",
    ],
    correctAnswer: 3,
  },
  {
    id: 97,
    question:
      "A well-resourced attacker intends to launch a highly disruptive DDoS attack against a major online retailer. The attacker aims to exhaust all the network resources while keeping their identity concealed. Their method should be resistant to simple defensive measures such as IP-based blocking. Based on these objectives, which of the following attack strategies would be most effective?",
    options: [
      "The attacker should initiate a volumetric flood attack using a single compromised machine to overwhelm the retailer's network bandwidth",
      "The attacker should instigate a protocol-based SYN flood attack, consuming connection state tables on the retailer's servers",
      "The attacker should leverage a botnet to launch a Pulse Wave attack, sending high-volume traffic pulses at regular intervals",
      "The attacker should execute a simple ICMP flood attack from a single IP, exploiting the retailer's ICMP processing",
    ],
    correctAnswer: 2,
  },
  {
    id: 98,
    question:
      "A sophisticated attacker targets your web server with the intent to execute a Denial of Service (DoS) attack. His strategy involves a unique mixture of TCP SYN, UDP, and ICMP floods, using 'r' packets per second. Your server, reinforced with advanced security measures, can handle 'h' packets per second before it starts showing signs of strain. If 'r' surpasses 'h', it overwhelms the server, causing it to become unresponsive. In a peculiar pattern, the attacker selects 'r' as a composite number and 'h' as a prime number, making the attack detection more challenging. Considering 'r=2010' and different values for 'h', which of the following scenarios would potentially cause the server to falter?",
    options: [
      "h=1987 (prime): The attacker's packet rate exceeds the server's capacity, causing potential unresponsiveness.",
      "h=2003 (prime): The server can manage more packets than the attacker is sending, hence it stays operational.",
      "h=1993 (prime): Despite being less than 'r', the server's prime number capacity keeps it barely operational, but the risk of falling is imminent.",
      "h=1999 (prime): Despite the attacker's packet flood, the server can handle these requests, remaining responsive.",
    ],
    correctAnswer: 0,
  },
  {
    id: 99,
    question:
      "Jake, a network security specialist, is trying to prevent network level session hijacking attacks in his company. While studying different types of such attacks, he learns about a technique where an attacker inserts their machine into the communication between a client and a server, making it seem like the packets are flowing through the original path. This technique is primarily used to reroute the packets. Which of the following types of network level session hijacking attacks is Jake studying?",
    options: [
      "TCP/IP Hijacking",
      "RST Hijacking",
      "UDP Hijacking",
      "Man-in-the-middle Attack Using Forged ICMP and ARP Spoofing",
    ],
    correctAnswer: 3,
  },
  {
    id: 100,
    question:
      "As the chief security officer at SecureMobile, you are overseeing the development of a mobile banking application. You are aware of the potential risks of man-in-the-middle (MitM) attacks where an attacker might intercept communication between the app and the bank's servers. Recently, you have learned about a technique used by attackers where they use rogue Wi-Fi hotspots to conduct MitM attacks. To prevent this type of attack, you plan to implement a security feature in the mobile app. What should this feature accomplish?",
    options: [
      "It should prevent the app from communicating over a network if it detects a rogue access point.",
      "It should require users to change their password every 30 days.",
      "It should require two-factor authentication for user logins.",
      "It should prevent the app from connecting to any unencrypted Wi-Fi networks.",
    ],
    correctAnswer: 3,
  },
  {
    id: 101,
    question:
      "Bella, a security professional working at an IT firm, finds that a security breach has occurred while transferring important files. Sensitive data, employee usernames, and passwords are shared in plaintext, paving the way for hackers to perform successful session hijacking. To address this situation, Bella implemented a protocol that sends data using encryption and digital certificates. Which of the following protocols is used by Bella?",
    options: ["HTTPS", "FTPS", "IP", "FTP"],
    correctAnswer: 1,
  },
  {
    id: 102,
    question:
      "A security analyst is investigating a potential network-level session hijacking incident. During the investigation, the analyst finds that the attacker has been using a technique in which they injected an authentic-looking reset packet using a spoofed source IP address and a guessed acknowledgment number. As a result, the victim's connection was reset. Which of the following hijacking techniques has the attacker most likely used?",
    options: [
      "Blind hijacking",
      "RST hijacking",
      "TCP/IP hijacking",
      "UDP hijacking",
    ],
    correctAnswer: 1,
  },
  {
    id: 103,
    question:
      "In an advanced persistent threat scenario, an adversary follows a detailed set of procedures in the cyber kill chain. During one such instance, the adversary has successfully gained access to a corporate network and now attempts to obfuscate malicious traffic within legitimate network traffic. Which of the following actions would most likely be part of the adversary's current procedures?",
    options: [
      "Initiating DNS tunneling to communicate with the command-and-control server.",
      "Employing data staging techniques to collect and aggregate sensitive data.",
      "Conducting internal reconnaissance using PowerShell scripts.",
      "Establishing a command-and-control server to communicate with compromised systems.",
    ],
    correctAnswer: 0,
  },
  {
    id: 104,
    question:
      "During a comprehensive security assessment, your cybersecurity team at XYZ Corp stumbles upon signs that point toward a possible Advanced Persistent Threat (APT) infiltration in the network infrastructure. These sophisticated threats often exhibit subtle indicators that distinguish them from other types of cyberattacks. To confirm your suspicion and adequately isolate the potential APT, which of the following actions should you prioritize?",
    options: [
      "Scrutinize for repeat network login attempts from unrecognized geographical regions",
      "Search for proof of a spear-phishing attempt, such as the presence of malicious emails or risky attachments",
      "Vigilantly monitor for evidence of zero-day exploits that manage to evade your firewall or antivirus software",
      "Investigate for anomalies in file movements or unauthorized data access attempts within your database system",
    ],
    correctAnswer: 3,
  },
  {
    id: 105,
    question:
      "Kate dropped her phone and subsequently encountered an issue with the phone's internal speaker. Thus, she is using the phone's loudspeaker for phone calls and other activities. Bob, an attacker, takes advantage of this vulnerability and secretly exploits the hardware of Kate's phone so that he can monitor the loudspeaker's output from data sources such as voice assistants, multimedia messages, and audio files by using a malicious app to breach speech privacy.",
    options: [
      "aLTEr attack",
      "SIM card attack",
      "Spearphone attack",
      "Man-in-the-disk attack",
    ],
    correctAnswer: 2,
  },
  {
    id: 106,
    question:
      "Kevin, a professional hacker, wants to penetrate CyberTech Inc's network. He employed a technique, using which he encoded packets with Unicode characters. The company's IDS cannot recognize the packets, but the target web server can decode them. What is the technique used by Kevin to evade the IDS system?",
    options: [
      "Session splicing",
      "Obfuscating",
      "Desynchronization",
      "Urgency flag",
    ],
    correctAnswer: 1,
  },
  {
    id: 107,
    question:
      "Which of the following protocols can be used to secure an LDAP service against anonymous queries?",
    options: ["NTLM", "WPA", "RADIUS", "SSO"],
    correctAnswer: 0,
  },
  {
    id: 108,
    question:
      "A cyber attacker has initiated a series of activities against a high-profile organization following the Cyber Kill Chain Methodology. The attacker is presently in the 'Delivery' stage. As an Ethical Hacker, you are trying to anticipate the adversary's next move. What is the most probable subsequent action from the attacker based on the Cyber Kill Chain Methodology?",
    options: [
      "The attacker will exploit the malicious payload delivered to the target organization and establish a foothold.",
      "The attacker will initiate an active connection to the target system to gather more data.",
      "The attacker will start reconnaissance to gather as much information as possible about the target.",
      "The attacker will attempt to escalate privileges to gain complete control of the compromised system.",
    ],
    correctAnswer: 0,
  },
  {
    id: 109,
    question:
      "An organization has been experiencing intrusion attempts despite deploying an Intrusion Detection System (IDS) and Firewalls. As a Certified Ethical Hacker, you are asked to reinforce the intrusion detection process and recommend a better rule-based approach. The IDS uses Snort rules and the new recommended tool should be able to complement it. You suggest using YARA rules with an additional tool for rule generation. Which of the following tools would be the best choice for this purpose and why?",
    options: [
      "YaraRET – Because it helps in reverse engineering Trojans to generate YARA rules",
      "Koodous – Because it combines social networking with antivirus signatures and YARA rules to detect malware",
      "AutoYara – Because it automates the generation of YARA rules from a set of malicious and benign files",
      "yarGen – Because it generates YARA rules from strings identified in malware files while removing strings that also appear in goodware files",
    ],
    correctAnswer: 3,
  },
  {
    id: 110,
    question:
      "Dayn, an attacker, wanted to detect if any honeypots are installed in a target network. For this purpose, he used a time-based TCP fingerprinting method to validate the response to a normal computer and the response of a honeypot to a manual SYN request. Which of the following techniques is employed by Dayn to detect honeypots?",
    options: [
      "Detecting the presence of Snort_inline honeypots",
      "Detecting the presence of Sebek-based honeypots",
      "Detecting honeypots running on VMware",
      "Detecting the presence of Honeyd honeypots",
    ],
    correctAnswer: 3,
  },
  {
    id: 111,
    question:
      "As a part of an ethical hacking exercise, an attacker is probing a target network that is suspected to employ various honeypot systems for security. The attacker needs to detect and bypass these honeypots without alerting the target. The attacker decides to utilize a suite of techniques. Which of the following techniques would NOT assist in detecting a honeypot?",
    options: [
      "Probing system services and observing the three-way handshake",
      "Implementing a brute force attack to verify system vulnerability",
      "Analyzing the MAC address to detect instances running on VMware",
      "Using honeypot detection tools like Send-Safe Honeypot Hunter",
    ],
    correctAnswer: 1,
  },
  {
    id: 112,
    question: "Which Nmap switch helps evade IDS or firewalls?",
    options: ["-n/-R", "-oN/-oX/-oG", "-D", "-T"],
    correctAnswer: 3,
  },
  {
    id: 113,
    question:
      "Taylor, a security professional, uses a tool to monitor her company's website, analyze the website's traffic, and track the geographical location of the users visiting the company's website. Which of the following tools did Taylor employ in the above scenario?",
    options: ["WebSite-Watcher", "Webroot", "WAFW00F", "Web-Stat"],
    correctAnswer: 3,
  },
  {
    id: 114,
    question:
      "You have been hired as an intern at a start-up company. Your first task is to help set up a basic web server for the company's new website. The team leader has asked you to make sure the server is secure from common threats. Based on your knowledge from studying for the CEH exam, which of the following actions should be your priority to secure the web server?",
    options: [
      "Installing a web application firewall",
      "Limiting the number of concurrent connections to the server",
      "Encrypting the company's website with SSL/TLS",
      "Regularly updating and patching the server software",
    ],
    correctAnswer: 2,
  },
  {
    id: 116,
    question:
      "What are common files on a web server that can be misconfigured and provide useful information for a hacker such as verbose error messages?",
    options: ["administration.config", "idq.dll", "php.ini", "httpd.conf"],
    correctAnswer: 2,
  },
  {
    id: 117,
    question:
      "As part of a college project, you have set up a web server for hosting your team's application. Given your interest in cybersecurity, you have taken the lead in securing the server. You are aware that hackers often attempt to exploit server misconfigurations. Which of the following actions would best protect your web server from potential misconfiguration-based attacks?",
    options: [
      "Enabling multi-factor authentication for users",
      "Regularly backing up server data",
      "Implementing a firewall to filter traffic",
      "Performing regular server configuration audits",
    ],
    correctAnswer: 3,
  },
  {
    id: 118,
    question:
      "A 'Server-Side Includes' attack refers to the exploitation of a web application by injecting scripts in HTML pages or executing arbitrary code remotely. Which web-page file type, if it exists on the web server, is a strong indication that the server is vulnerable to this kind of attack?",
    options: [".stm", ".html", ".cms", ".rss"],
    correctAnswer: 0,
  },
  {
    id: 119,
    question:
      "Calvin, a software developer, uses a feature that helps him auto-generate the content of a web page without manual involvement and is integrated with SSI directives. This leads to a vulnerability in the developed web application as this feature accepts remote user inputs and uses them on the page. Hackers can exploit this feature and pass malicious SSI directives as input values to perform malicious activities such as modifying and erasing server files. What is the type of injection attack Calvin's web application is susceptible to?",
    options: [
      "Server-side template injection",
      "Server-side includes injection",
      "Server-side JS injection",
      "CRLF injection",
    ],
    correctAnswer: 1,
  },
  {
    id: 120,
    question:
      "Scenario: Joe turns on his home computer to access personal online banking. When he enters the URL www.bank.com, the website is displayed, but it prompts him to re-enter his credentials as if he has never visited the site before. When he examines the website URL closer, he finds that the site is not secure and the web address appears different. What type of attack he is experiencing?",
    options: [
      "DHCP spoofing",
      "DNS hijacking",
      "DoS attack",
      "ARP cache poisoning",
    ],
    correctAnswer: 1,
  },
  {
    id: 121,
    question:
      "During a penetration test, an ethical hacker is exploring the security of a complex web application. The application heavily relies on JavaScript for client-side input sanitization, with an apparent assumption that this alone is adequate to prevent injection attacks. During the investigation, the ethical hacker also notices that the application utilizes cookies to manage user sessions but does not enable the HttpOnly flag. This lack of flag potentially exposes the cookies to client-side scripts. Given these identified vulnerabilities, what would be the most effective strategy for the ethical hacker to exploit this application?",
    options: [
      "Instigate a Distributed Denial of Service (DDoS) attack to overload the server, capitalizing on potential weak server-side security.",
      "Launch a Cross-Site Scripting (XSS) attack, aiming to bypass the client-side sanitization and exploit the exposure of session cookies.",
      "Implement an SQL Injection attack to take advantage of potential unvalidated input and gain unauthorized database access.",
      "Employ a brute-force attack to decipher user credentials, considering the lack of server-side validation.",
    ],
    correctAnswer: 1,
  },
  {
    id: 122,
    question:
      "Gilbert, a web developer, uses a centralized web API to reduce complexity and increase the integrity of updating and changing data. For this purpose, he uses a web service that uses HTTP methods such as PUT, POST, GET, and DELETE and can improve the overall performance, visibility, scalability, reliability, and portability of an application. What is the type of web service API mentioned in the above scenario?",
    options: ["RESTful API", "REST API", "JSON-RPC", "SOAP API"],
    correctAnswer: 0,
  },
  {
    id: 123,
    question:
      "Joel, a professional hacker, targeted a company and identified the types of websites frequently visited by its employees. Using this information, he searched for possible loopholes in these websites and injected a malicious script that can redirect users from the web page and download malware onto a victim's machine. Joel waits for the victim to access the infected web application so as to compromise the victim's machine. Which of the following techniques is used by Joel in the above scenario?",
    options: [
      "MarioNet attack",
      "Clickjacking attack",
      "DNS rebinding attack",
      "Watering hole attack",
    ],
    correctAnswer: 3,
  },
  {
    id: 124,
    question:
      "Judy created a forum. One day, she discovers that a user is posting strange images without writing comments. She immediately calls a security expert, who discovers that the following code is hidden behind those images:",
    options: [
      "This php file silently executes the code and grabs the user's session cookie and session ID.",
      "The code injects a new cookie to the browser.",
      "The code is a virus that is attempting to gather the user's username and password.",
      "The code redirects the user to another site.",
    ],
    correctAnswer: 0,
  },
  {
    id: 125,
    question:
      "Ron, a security professional, was pen testing web applications and SaaS platforms used by his company. While testing, he found a vulnerability that allows hackers to gain unauthorized access to API objects and perform actions such as view, update, and delete sensitive data of the company. What is the API vulnerability revealed in the above scenario?",
    options: [
      "Code injections",
      "No ABAC validation",
      "Business logic flaws",
      "Improper use of CORS",
    ],
    correctAnswer: 1,
  },
  {
    id: 126,
    question:
      "Gregory, a professional penetration tester working at Sys Security Ltd., is tasked with performing a security test of web applications used in the company. For this purpose, Gregory uses a tool to test for any security loopholes by hijacking a session between a client and server. This tool has a feature of intercepting proxy that can be used to inspect and modify the traffic between the browser and target application. This tool can also perform customized attacks and can be used to test the randomness of session tokens. Which of the following tools is used by Gregory in the above scenario?",
    options: ["CxSAST", "Wireshark", "Nmap", "Burp Suite"],
    correctAnswer: 3,
  },
  {
    id: 127,
    question:
      "During your summer internship at a tech company, you have been asked to review the security settings of their web server. While inspecting, you notice the server reveals detailed error messages to users, including database query errors and internal server errors. As a cybersecurity beginner, what is your understanding of this setting, and how would you advise the company?",
    options: [
      "Suppress detailed error messages, as they can expose sensitive information.",
      "Retain the setting as it aids in troubleshooting user issues.",
      "Implement stronger encryption to secure the error messages.",
      "Increase the frequency of automated server backups.",
    ],
    correctAnswer: 0,
  },
  {
    id: 128,
    question:
      "A penetration tester is conducting an assessment of a web application for a financial institution. The application uses form-based authentication and does not implement account lockout policies after multiple failed login attempts. Interestingly, the application displays detailed error messages that disclose whether the username or password entered is incorrect. The tester also notices that the application uses HTTP headers to prevent clickjacking attacks but does not implement Content Security Policy (CSP). With these observations, which of the following attack methods would likely be the most effective for the penetration tester to exploit these vulnerabilities and attempt unauthorized access?",
    options: [
      "The tester could launch a Cross Site Scripting (XSS) attack to steal authenticated session cookies, potentially bypassing the clickjacking protection.",
      "The tester could exploit a potential SQL Injection vulnerability to manipulate the application's database.",
      "The tester could execute a Brute Force attack, leveraging the lack of account lockout policy and the verbose error messages to guess the correct credentials.",
      "The tester could execute a Man in-the-Middle (MitM) attack to intercept and modify the HTTP headers for a Clickjacking attack.",
    ],
    correctAnswer: 2,
  },
  {
    id: 129,
    question:
      "As part of a penetration testing team, you've discovered a web application vulnerable to Cross-Site Scripting (XSS). The application sanitizes inputs against standard XSS payloads but fails to filter out HTML-encoded characters. On further analysis, you've noticed that the web application uses cookies to track session IDs. You decide to exploit the XSS vulnerability to steal users' session cookies. However, the application implements HTTPOnly cookies, complicating your original plan. Which of the following would be the most viable strategy for a successful attack?",
    options: [
      "Build an XSS payload using HTML encoding and use it to exploit the server-side code, potentially disabling the HTTPOnly flag on cookies.",
      "Create a sophisticated XSS payload that leverages HTML encoding to bypass the input sanitization, and then use it to redirect users to a malicious site where their cookies can be captured.",
      "Develop a browser exploit to bypass the HTTPOnly restriction, then use a HTML-encoded XSS payload to retrieve the cookies.",
      "Utilize an HTML-encoded XSS payload to trigger a buffer overflow attack, forcing the server to reveal the HTTPOnly cookies.",
    ],
    correctAnswer: 1,
  },
  {
    id: 130,
    question:
      "An ethical hacker is testing a web application of a financial firm. During the test, a 'Contact Us' form's input field is found to lack proper user input validation, indicating a potential Cross-Site Scripting (XSS) vulnerability. However, the application has a stringent Content Security Policy (CSP) disallowing inline scripts and scripts from external domains but permitting scripts from its own domain. What would be the hacker's next step to confirm the XSS vulnerability?",
    options: [
      "Utilize a script hosted on the application's domain to test the form",
      "Try to disable the CSP to bypass script restrictions",
      "Load a script from an external domain to test the vulnerability",
      "Inject a benign script inline to the form to see if it executes",
    ],
    correctAnswer: 0,
  },
  {
    id: 131,
    question:
      "An ethical hacker is testing the security of a website's database system against SQL Injection attacks. They discover that the IDS has a strong signature detection mechanism to detect typical SQL injection patterns. Which evasion technique can be most effectively used to bypass the IDS signature detection while performing a SQL Injection attack?",
    options: [
      "Employ IP fragmentation to obscure the attack payload",
      "Leverage string concatenation to break identifiable keywords",
      "Implement case variation by altering the case of SQL statements",
      "Use Hex encoding to represent the SQL query string",
    ],
    correctAnswer: 3,
  },
  {
    id: 133,
    question:
      "Clark is a professional hacker. He created and configured multiple domains pointing to the same host to switch quickly between the domains and avoid detection. Identify the behavior of the adversary in the above scenario.",
    options: [
      "Use of DNS tunneling",
      "Unspecified proxy activities",
      "Data staging",
      "Use of command-line interface",
    ],
    correctAnswer: 1,
  },
  {
    id: 134,
    question:
      "As an IT Security Analyst, you've been asked to review the security measures of an e-commerce website that relies on a SQL database for storing sensitive customer data. Recently, an anonymous tip has alerted you to a possible threat: a seasoned hacker who specializes in SQL Injection attacks may be targeting your system. The site already employs input validation measures to prevent basic injection attacks, and it blocks any user inputs containing suspicious patterns. However, this hacker is known to use advanced SQL Injection techniques. Given this situation, which of the following strategies would the hacker most likely adopt to bypass your security measures?",
    options: [
      "The hacker may try to use SQL commands which are less known and less likely to be blocked by your system's security",
      "The hacker might employ a 'blind' SQL Injection attack, taking advantage of the application's true or false responses to extract data bit by bit",
      "The hacker could deploy an 'out-of-band' SQL Injection attack, extracting data via a different communication channel, such as DNS or HTTP requests",
      "The hacker may resort to a DDoS attack instead, attempting to crash the server and thus render the e-commerce site unavailable",
    ],
    correctAnswer: 1,
  },
  {
    id: 135,
    question:
      "Which of the following web vulnerabilities would an attacker be attempting to exploit if they delivered the following input",
    options: ["IDOR", "SQLi", "XXE", "XXS"],
    correctAnswer: 2,
  },
  {
    id: 136,
    question:
      "While performing a security audit of a web application, an ethical hacker discovers a potential vulnerability. The application responds to logically incorrect queries with detailed error messages that divulge the underlying database's structure. The ethical hacker decides to exploit this vulnerability further. Which type of SQL Injection attack is the ethical hacker likely to use?",
    options: [
      "Blind/Inferential SQL Injection",
      "UNION SQL Injection",
      "In-band SQL Injection",
      "Error-based SQL Injection",
    ],
    correctAnswer: 3,
  },
  {
    id: 137,
    question:
      "In an intricate web application architecture using an Oracle database, you, as a security analyst, have identified a potential SQL Injection attack surface. The database consists of 'x' tables, each with 'y' columns. Each table contains 'z' records. An attacker, well-versed in SQLi techniques, crafts 'u' SQL payloads, each attempting to extract maximum data from the database. The payloads include 'UNION SELECT' statements and 'DBMS_XSLPROCESSOR.READ2CLOB' to read sensitive files. The attacker aims to maximize the total data extracted 'E=xyz*u'. Assuming 'x=4', 'y=2', and varying 'z' and 'u', which situation is likely to result in the highest extracted data volume?",
    options: [
      "z=550, u=2: Here, the attacker formulates 2 SQL payloads and directs them towards tables containing 550 records, impacting all columns and tables.",
      "z=500, u=3: The attacker creates 3 SQL payloads and targets tables with 500 records each, exploiting all columns and tables.",
      "z=600, u=2: The attacker devises 2 SQL payloads, each aimed at tables holding 600 records, affecting all columns across all tables.",
      "z=400, u=4: The attacker constructs 4 SQL payloads, each focusing on tables with 400 records, influencing all columns of all tables.",
    ],
    correctAnswer: 3,
  },
  {
    id: 138,
    question:
      "You're the security manager for a tech company that uses a database to store sensitive customer data. You have implemented countermeasures against SQL injection attacks. Recently, you noticed some suspicious activities and suspect an attacker is using SQL injection techniques. The attacker is believed to use different forms of payloads in his SQL queries. In the case of a successful SQL injection attack, which of the following payloads would have the most significant impact?",
    options: [
      "UNION SELECT NULL, NULL, NULL — : This payload manipulates the UNION SQL operator, enabling the attacker to retrieve data from different database tables",
      "' OR '1'='l: This payload manipulates the WHERE clause of an SQL statement, allowing the attacker to view unauthorized data",
      "' OR username LIKE '%': This payload uses the LIKE operator to search for a specific pattern in a column",
      "' OR 'a'='a; DROP TABLE members; –: This payload combines the manipulation of the WHERE clause with a destructive action, causing data loss",
    ],
    correctAnswer: 3,
  },
  {
    id: 139,
    question:
      "CyberTech Inc. recently experienced SQL injection attacks on its official website. The company appointed Bob, a security professional, to build and incorporate defensive strategies against such attacks. Bob adopted a practice whereby only a list of entities such as the data type, range, size, and value, which have been approved for secured access, is accepted. What is the defensive technique employed by Bob in the above scenario?",
    options: [
      "Blacklist validation",
      "Enforce least privileges",
      "Output encoding",
      "Whitelist validation",
    ],
    correctAnswer: 3,
  },
  {
    id: 140,
    question:
      "Consider a hypothetical situation where an attacker, known for his proficiency in SQL Injection attacks, is targeting your web server. This adversary meticulously crafts 'q' malicious SQL queries, each inducing a delay of 'd' seconds in the server response. This delay in response is an indicator of a potential attack. If the total delay, represented by the product 'q*d', crosses a defined threshold 'T', an alert is activated in your security system. Furthermore, it is observed that the attacker prefers prime numbers for 'q', and 'd' follows a pattern in the Fibonacci sequence. Now, consider 'd=13' seconds (a Fibonacci number) and various values of 'q' (a prime number) and 'T'. Which among the following scenarios will most likely trigger an alert?",
    options: [
      "q=11, T=150: Here, the total delay induced by the attacker ('q*d' = 143 seconds) does not surpass the threshold, so the security system remains dormant.",
      "q=13, T=180: In this case, the total delay caused by the attacker ('q*d' = 169 seconds) breaches the threshold, likely leading to the triggering of a security alert.",
      "q=17, T=220: Even though the attacker increases 'q', the total delay ('q*d' = 221 seconds) just surpasses the threshold, possibly activating an alert.",
      "q=19, T=260: Despite the attacker's increased effort, the total delay ('q*d' = 247 seconds) does not exceed the threshold, thus no alert is triggered.",
    ],
    correctAnswer: 2,
  },
  {
    id: 141,
    question:
      "As a cybersecurity professional, you are responsible for securing a high-traffic web application that uses MySQL as its backend database. Recently, there has been a surge of unauthorized login attempts, and you suspect that a seasoned black-hat hacker is behind them. This hacker has shown proficiency in SQL Injection and appears to be using the 'UNION' SQL keyword to trick the login process into returning additional data. However, your application's security measures include filtering special characters in user inputs, a method usually effective against such attacks. In this challenging environment, if the hacker still intends to exploit this SQL Injection vulnerability, which strategy is he most likely to employ?",
    options: [
      "The hacker tries to manipulate the 'UNION' keyword in such a way that it triggers a database error, potentially revealing valuable information about the database's structure.",
      "The hacker attempts to bypass the special character filter by encoding his malicious input, which could potentially enable him to successfully inject damaging SQL queries.",
      "The hacker alters his approach and injects a DROP TABLE' statement, a move that could potentially lead to the loss of vital data stored in the application's database.",
      "The hacker switches tactics and resorts to a 'time-based blind' SQL Injection attack, which would force the application to delay its response, thereby revealing information based on the duration of the delay.",
    ],
    correctAnswer: 1,
  },
  {
    id: 142,
    question:
      "This type of injection attack does not show any error message. It is difficult to exploit as it returns information when the application is given SQL payloads that elicit a true or false response from the server. By observing the response, an attacker can extract sensitive information. What type of attack is this?",
    options: [
      "Error-based SQL injection",
      "Blind SQL injection",
      "Time-based SQL injection",
      "Union SQL injection",
    ],
    correctAnswer: 1,
  },
  {
    id: 143,
    question:
      "An attacker identified that a user and an access point are both compatible with WPA2 and WPA3 encryption. The attacker installed a rogue access point with only WPA2 compatibility in the vicinity and forced the victim to go through the WPA2 four-way handshake to get connected. After the connection was established, the attacker used automated tools to crack WPA2-encrypted messages.",
    options: [
      "Cache-based attack",
      "Side-channel attack",
      "Timing-based attack",
      "Downgrade security attack",
    ],
    correctAnswer: 3,
  },
  {
    id: 144,
    question:
      "Bobby, an attacker, targeted a user and decided to hijack and intercept all their wireless communications. He installed a fake communication tower between two authentic endpoints to mislead the victim. Bobby used this virtual tower to interrupt the data transmission between the user and real tower, attempting to hijack an active session. Upon receiving the user's request, Bobby manipulated the traffic with the virtual tower and redirected the victim to a malicious website. What is the attack performed by Bobby in the above scenario?",
    options: [
      "Wardriving",
      "aLTEr attack",
      "Jamming signal attack",
      "KRACK attack",
    ],
    correctAnswer: 1,
  },
  {
    id: 145,
    question:
      "An attacker utilizes a Wi-Fi Pineapple to run an access point with a legitimate-looking SSID for a nearby business in order to capture the wireless password. What kind of attack is this?",
    options: [
      "War driving attack",
      "Evil-twin attack",
      "Phishing attack",
      "MAC spoofing attack",
    ],
    correctAnswer: 1,
  },
  {
    id: 146,
    question:
      "As the lead security engineer for a retail corporation, you are assessing the security of the wireless networks in the company's stores. One of your main concerns is the potential for 'Wardriving' attacks, where attackers drive around with a Wi-Fi-enabled device to discover vulnerable wireless networks. Given the nature of the retail stores, you need to ensure that any security measures you implement do not interfere with customer experience, such as their ability to access in-store Wi-Fi. Taking into consideration these factors, which of the following would be the most suitable measure to mitigate the risk of Wardriving attacks?",
    options: [
      "Implement WPA3 encryption for the store's Wi-Fi network",
      "Disable SSID broadcasting",
      "Limit the range of the store's wireless signals",
      "Implement MAC address filtering",
    ],
    correctAnswer: 0,
  },
  {
    id: 147,
    question:
      "The security team of Debry Inc. decided to upgrade Wi-Fi security to thwart attacks such as dictionary attacks and key recovery attacks. For this purpose, the security team started implementing cutting-edge technology that uses a modern key establishment protocol called the simultaneous authentication of equals (SAE), also known as dragonfly key exchange, which replaces the PSK concept. What is the Wi-Fi encryption technology implemented by Debry Inc.?",
    options: ["WPA2", "WPA3", "WEP", "WPA"],
    correctAnswer: 1,
  },
  {
    id: 148,
    question:
      "This wireless security protocol allows 192-bit minimum-strength security protocols and cryptographic tools to protect sensitive data, such as GCMP-256, HMAC-SHA384, and ECDSA using a 384-bit elliptic curve. Which is this wireless security protocol?",
    options: [
      "WPA3-Personal",
      "WPA2-Enterprise",
      "WPA3-Enterprise",
      "WPA2-Personal",
    ],
    correctAnswer: 2,
  },
  {
    id: 149,
    question:
      "You are a cybersecurity trainee tasked with securing a small home network. The homeowner is concerned about potential 'Wi-Fi eavesdropping,' where unauthorized individuals could intercept the wireless communications. What would be the most effective first step to mitigate this risk, considering the simplicity and the residential nature of the network?",
    options: [
      "Disable the network's SSID broadcast",
      "Enable MAC address filtering",
      "Enable encryption on the wireless network",
      "Reduce the signal strength of the wireless router",
    ],
    correctAnswer: 2,
  },
  {
    id: 150,
    question:
      "George is a security professional working for iTech Solutions. He was tasked with securely transferring sensitive data of the organization between industrial systems. In this process, he used a short-range communication protocol based on the IEEE 203.15.4 standard. This protocol is used in devices that transfer data infrequently at a low rate in a restricted area, within a range of 10-100 m. What is the short-range wireless communication technology George employed in the above scenario?",
    options: ["MQTT", "NB-IoT", "LPWAN", "Zigbee"],
    correctAnswer: 3,
  },
  {
    id: 151,
    question:
      "Which wireless security protocol replaces the personal pre shared key (PSK) authentication with Simultaneous Authentication of Equals (SAE) and is therefore resistant to offline dictionary attacks?",
    options: ["WPA2-Enterprise", "ZigBee", "WPA3-Personal", "Bluetooth"],
    correctAnswer: 2,
  },
  {
    id: 152,
    question:
      "As an IT intern, you have been asked to help set up a secure Wi-Fi network for a local coffee shop. The owners want to provide free Wi-Fi to their customers, but they are concerned about potential security risks. They are looking for a simple yet effective solution that would not require a lot of technical knowledge to manage. Which of the following security measures would be the most suitable in this context?",
    options: [
      "Enable MAC address filtering",
      "Disable the network's SSID broadcast",
      "Implement WPA2 or WPA3 encryption",
      "Require customers to use VPN when connected to the Wi-Fi",
    ],
    correctAnswer: 2,
  },
  {
    id: 153,
    question:
      "Clark, a professional hacker, attempted to perform a Btlejacking attack using an automated tool, Btlejack, and hardware tool, micro:bit. This attack allowed Clark to hijack, read, and export sensitive information shared between connected devices. To perform this attack, Clark executed various btlejack commands. Which of the following commands was used by Clark to hijack the connections?",
    options: [
      "btlejack -f 0x129f3244 -j",
      "btlejack -d /dev/ttyACM0 -d /dev/ttyACM2 -s",
      "btlejack -f 0x9c68fd30 -t -m 0x1fffffffff",
      "btlejack -c any",
    ],
    correctAnswer: 2,
  },
  {
    id: 154,
    question:
      "As the Chief Information Security Officer (CISO) at a large university, you are responsible for the security of a campus-wide Wi-Fi network that serves thousands of students, faculty, and staff. Recently, there has been a rise in reports of unauthorized network access, and you suspect that some users are sharing their login credentials. You are considering deploying an additional layer of security that could effectively mitigate this issue. What would be the most suitable measure to implement in this context?",
    options: [
      "Deploy a VPN for the entire campus",
      "Enforce a policy of regularly changing Wi-Fi passwords",
      "Implement network segmentation",
      "Implement 802.1X authentication",
    ],
    correctAnswer: 3,
  },
  {
    id: 155,
    question:
      "A group of hackers were roaming around a bank office building in a city, driving a luxury car. They were using hacking tools on their laptop with the intention to find a free-access wireless network. What is this hacking process known as?",
    options: [
      "GPS mapping",
      "Spectrum analysis",
      "Wireless sniffing",
      "Wardriving",
    ],
    correctAnswer: 3,
  },
  {
    id: 156,
    question:
      "As a junior security analyst for a small business, you are tasked with setting up the company's first wireless network. The company wants to ensure the network is secure from potential attacks. Given that the company's workforce is relatively small and the need for simplicity in managing network security, which of the following measures would you consider a priority to protect the network?",
    options: [
      "Hide the network SSID",
      "Establish a regular schedule for changing the network password",
      "Enable WPA2 or WPA3 encryption on the wireless router",
      "Implement a MAC address whitelist",
    ],
    correctAnswer: 2,
  },
  {
    id: 157,
    question:
      "Attacker Rony installed a rogue access point within an organization's perimeter and attempted to intrude into its internal network. Johnson, a security auditor, identified some unusual traffic in the internal network that is aimed at cracking the authentication mechanism. He immediately turned off the targeted network and tested for any weak and outdated security mechanisms that are open to attack. What is the type of vulnerability assessment performed by Johnson in the above scenario?",
    options: [
      "Application assessment",
      "Wireless network assessment",
      "Host-based assessment",
      "Distributed assessment",
    ],
    correctAnswer: 1,
  },
  {
    id: 158,
    question:
      "Jake, a professional hacker, installed spyware on a target iPhone to spy on the target user's activities. He can take complete control of the target mobile device by jailbreaking the device remotely and record audio, capture screenshots, and monitor all phone calls and SMS messages.",
    options: ["Zscaler", "DroidSheep", "Androrat", "Trident"],
    correctAnswer: 3,
  },
  {
    id: 159,
    question:
      "Jacob works as a system administrator in an organization. He wants to extract the source code of a mobile application and disassemble the application to analyze its design flaws. Using this technique, he wants to fix any bugs in the application, discover underlying vulnerabilities, and improve defense strategies against attacks. What is the technique used by Jacob in the above scenario to improve the security of the mobile application?",
    options: [
      "Social engineering",
      "App sandboxing",
      "Jailbreaking",
      "Reverse engineering",
    ],
    correctAnswer: 3,
  },
  {
    id: 160,
    question:
      "As a security consultant, you are advising a startup that is developing an IoT device for home security. The device communicates with a mobile app, allowing homeowners to monitor their homes in real time. The CEO is concerned about potential Man-in-the-Middle (MitM) attacks that could allow an attacker to intercept and manipulate the device's communication. Which of the following solutions would best protect against such attacks?",
    options: [
      "Limit the range of the IoT device's wireless signals.",
      "Use CAPTCHA on the mobile app's login screen.",
      "Frequently change the IoT device's IP address.",
      "Implement SSL/TLS encryption for data transmission between the IoT device and the mobile app.",
    ],
    correctAnswer: 3,
  },
  {
    id: 161,
    question:
      "John, a professional hacker, targeted CyberSol Inc., an MNC. He decided to discover the IoT devices connected in the target network that are using default credentials and are vulnerable to various hijacking attacks. For this purpose, he used an automated tool to scan the target network for specific types of IoT devices and detect whether they are using the default, factory-set credentials. What is the tool employed by John in the above scenario?",
    options: [
      "Azure IoT Central",
      "AT&T IoT Platform",
      "IoTSeeker",
      "IoT Inspector",
    ],
    correctAnswer: 2,
  },
  {
    id: 162,
    question:
      "Geena, a cloud architect, uses a master component in the Kubernetes cluster architecture that scans newly generated pods and allocates a node to them. This component can also assign nodes based on factors such as the overall resource requirement, data locality, software/hardware/policy restrictions, and internal workload interventions. Which of the following master components is explained in the above scenario?",
    options: [
      "Kube-scheduler",
      "Etcd cluster",
      "Kube-controller-manager",
      "Kube-apiserver",
    ],
    correctAnswer: 0,
  },
  {
    id: 163,
    question:
      "You are a cybersecurity consultant at SecureIoT Inc. A manufacturing company has contracted you to strengthen the security of their Industrial IoT (IIoT) devices used in their operational technology (OT) environment. They are concerned about potential attacks that could disrupt their production lines and compromise safety. They have an advanced firewall system in place, but you know this alone is not enough. Which of the following measures should you suggest to provide comprehensive protection for their IoT devices?",
    options: [
      "Increase the frequency of changing passwords on all IIoT devices.",
      "Implement network segmentation to separate IIoT devices from the rest of the network.",
      "Rely on the existing firewall and install antivirus software on each IIoT device.",
      "Use the same encryption standards for IoT devices as for IT devices.",
    ],
    correctAnswer: 1,
  },
  {
    id: 164,
    question:
      "What is the port to block first in case you are suspicious that an IoT device has been compromised?",
    options: ["443", "48101", "80", "22"],
    correctAnswer: 1,
  },
  {
    id: 165,
    question:
      "Mike, a security engineer, was recently hired by BigFox Ltd. The company recently experienced disastrous DoS attacks. The management had instructed Mike to build defensive strategies for the company's IT infrastructure to thwart DoS/DDoS attacks. Mike deployed some countermeasures to handle jamming and scrambling attacks. What is the countermeasure Mike applied to defend against jamming and scrambling attacks?",
    options: [
      "Implement cognitive radios in the physical layer",
      "Disable TCP SYN cookie protection",
      "Allow the usage of functions such as gets and strcpy",
      "Allow the transmission of all types of addressed packets at the ISP level",
    ],
    correctAnswer: 0,
  },
  {
    id: 166,
    question:
      "Robert, a professional hacker, is attempting to execute a fault injection attack on a target IoT device. In this process, he injects faults into the power supply that can be used for remote execution, also causing the skipping of key instructions. He also injects faults into the clock network used for delivering a synchronized signal across the chip.",
    options: [
      "Optical, electromagnetic fault injection (EMFI)",
      "Temperature attack",
      "Power/clock/reset glitching",
      "Frequency/voltage tampering",
    ],
    correctAnswer: 2,
  },
  {
    id: 167,
    question:
      "You are a cybersecurity consultant for a healthcare organization that utilizes Internet of Medical Things (IoMT) devices, such as connected insulin pumps and heart rate monitors, to provide improved patient care. Recently, the organization has been targeted by ransomware attacks. While the IT infrastructure was unaffected due to robust security measures, they are worried that the IoMT devices could be potential entry points for future attacks. What would be your main recommendation to protect these devices from such threats?",
    options: [
      "Disable all wireless connectivity on IoMT devices.",
      "Regularly change the IP addresses of all IoMT devices.",
      "Use network segmentation to isolate IoMT devices from the main network.",
      "Implement multi-factor authentication for all IoMT devices.",
    ],
    correctAnswer: 2,
  },
  {
    id: 169,
    question:
      "As a cybersecurity analyst at IoT Defend, you are working with a large utility company that uses Industrial Control Systems (ICS) in its operational technology (OT) environment. The company has recently integrated IoT devices into this environment to enable remote monitoring and control. They want to ensure these devices do not become a weak link in their security posture. To identify potential vulnerabilities in the IoT devices, which of the following actions should you recommend as the first step?",
    options: [
      "Use stronger encryption algorithms for data transmission between IoT devices.",
      "Conduct a vulnerability assessment specifically for the IoT devices.",
      "Implement network segmentation to isolate IoT devices from the rest of the network.",
      "Install the latest antivirus software on each IoT device.",
    ],
    correctAnswer: 1,
  },
  {
    id: 170,
    question:
      "As a cybersecurity analyst at TechSafe Inc., you are working on a project to improve the security of a smart home system. This IoT-enabled system controls various aspects of the home, from heating and lighting to security cameras and door locks. Your client wants to ensure that even if one device is compromised, the rest of the system remains secure. Which of the following strategies would be most effective for this purpose?",
    options: [
      "Advise using a dedicated network for the smart home system, separate from the home's main Wi-Fi network.",
      "Propose frequent system resets to clear any potential malware.",
      "Suggest implementing two-factor authentication for the smart home system's mobile app.",
      "Recommend using a strong password for the smart home system's main control panel.",
    ],
    correctAnswer: 0,
  },
  {
    id: 171,
    question:
      "You are a cybersecurity consultant for a smart city project. The project involves deploying a vast network of IoT devices for public utilities like traffic control, water supply, and power grid management. The city administration is concerned about the possibility of a Distributed Denial of Service (DDoS) attack crippling these critical services. They have asked you for advice on how to prevent such an attack. What would be your primary recommendation?",
    options: [
      "Implement IP address whitelisting for all IoT devices.",
      "Deploy network intrusion detection systems (IDS) across the IoT network.",
      "Implement regular firmware updates for all IoT devices.",
      "Establish strong, unique passwords for each IoT device.",
    ],
    correctAnswer: 1,
  },
  {
    id: 172,
    question:
      "According to the NIST cloud deployment reference architecture, which of the following provides connectivity and transport services to consumers?",
    options: [
      "Cloud connector",
      "Cloud carrier",
      "Cloud provider",
      "Cloud broker",
    ],
    correctAnswer: 1,
  },
  {
    id: 173,
    question:
      "Alex, a cloud security engineer working in Eyecloud Inc. is tasked with isolating applications from the underlying infrastructure and stimulating communication via well-defined channels. For this purpose, he used an open-source technology that helped him in developing, packaging, and running applications; further, the technology provides PaaS through OS-level virtualization, delivers containerized software packages, and promotes fast software delivery. What is the cloud technology employed by Alex in the above scenario?",
    options: [
      "Virtual machine",
      "Serverless computing",
      "Zero trust network",
      "Docker",
    ],
    correctAnswer: 3,
  },
  {
    id: 174,
    question:
      "Alice, a professional hacker, targeted an organization's cloud services. She infiltrated the target's MSP provider by sending spear-phishing emails and distributed custom-made malware to compromise user accounts and gain remote access to the cloud service. Further, she accessed the target customer profiles with her MSP account, compressed the customer data, and stored them in the MSP. Then, she used this information to launch further attacks on the target organization. Which of the following cloud attacks did Alice perform in the above scenario?",
    options: [
      "Cloud cryptojacking",
      "Cloud hopper attack",
      "Man-in-the-cloud (MITC) attack",
      "Cloudborne attack",
    ],
    correctAnswer: 1,
  },
  {
    id: 175,
    question:
      "Joe works as an IT administrator in an organization and has recently set up a cloud computing service for the organization. To implement this service, he reached out to a telecom company for providing Internet connectivity and transport services between the organization and the cloud service provider. In the NIST cloud deployment reference architecture, under which category does the telecom company fall in the above scenario?",
    options: [
      "Cloud broker",
      "Cloud consumer",
      "Cloud carrier",
      "Cloud auditor",
    ],
    correctAnswer: 2,
  },
  {
    id: 176,
    question:
      "You are a security analyst for CloudSec, a company providing cloud security solutions. One of your clients, a financial institution, wants to shift its operations to a public cloud while maintaining a high level of security control. They want to ensure that they can monitor all their cloud resources continuously and receive real-time alerts about potential security threats. They also want to enforce their security policies consistently across all cloud workloads. Which of the following solutions would best meet these requirements?",
    options: [
      "Deploy a Cloud Access Security Broker (CASB).",
      "Use multi-factor authentication for all cloud user accounts.",
      "Implement a Virtual Private Network (VPN) for secure data transmission.",
      "Use client-side encryption for all stored data.",
    ],
    correctAnswer: 0,
  },
  {
    id: 177,
    question:
      "You are a cloud security expert at CloudGuard Inc. working with a client who plans to transition their infrastructure to a public cloud. The client expresses concern about potential data breaches and wants to ensure that only authorized personnel can access certain sensitive resources. You propose implementing a Zero Trust security model. Which of the following best describes how the Zero Trust model would enhance the security of their cloud resources?",
    options: [
      "It encrypts all data stored in the cloud, ensuring only authorized users can decrypt it.",
      "It ensures secure data transmission by implementing SSL/TLS protocols.",
      "It uses multi-factor authentication for all user accounts.",
      "It operates on the principle of least privilege, verifying each request as if it is from an untrusted source, regardless of its location.",
    ],
    correctAnswer: 3,
  },
  {
    id: 179,
    question:
      "Thomas, a cloud security professional, is performing security assessment on cloud services to identify any loopholes. He detects a vulnerability in a bare-metal cloud server that can enable hackers to implant malicious backdoors in its firmware. He also identified that an installed backdoor can persist even if the server is reallocated to new clients or businesses that use it as an IaaS. What is the type of cloud attack that can be performed by exploiting the vulnerability discussed in the above scenario?",
    options: [
      "Metadata spoofing attack",
      "Cloudborne attack",
      "Man-in-the-cloud (MITC) attack",
      "Cloud cryptojacking",
    ],
    correctAnswer: 1,
  },
  {
    id: 180,
    question:
      "As a security analyst for SkySecure Inc., you are working with a client that uses a multi-cloud strategy, utilizing services from several cloud providers. The client wants to implement a system that will provide unified security management across all their cloud platforms. They need a solution that allows them to consistently enforce security policies, identify and respond to threats, and maintain visibility of all their cloud resources. Which of the following should you recommend as the best solution?",
    options: [
      "Use a hardware-based firewall to secure all cloud resources.",
      "Implement separate security management tools for each cloud platform.",
      "Use a Cloud Access Security Broker (CASB).",
      "Rely on the built-in security features of each cloud platform.",
    ],
    correctAnswer: 2,
  },
  {
    id: 181,
    question:
      "Abel, a cloud architect, uses container technology to deploy applications/software including all its dependencies, such as libraries and configuration files, binaries, and other resources that run independently from other processes in the cloud environment. For the containerization of applications, he follows the five-tier container technology architecture. Currently, Abel is verifying and validating image contents, signing images, and sending them to the registries. Which of the following tiers of the container technology architecture is Abel currently working in?",
    options: [
      "Tier-1: Developer machines",
      "Tier-2: Testing and accreditation systems",
      "Tier-4: Orchestrators",
      "Tier-3: Registries",
    ],
    correctAnswer: 1,
  },
  {
    id: 182,
    question:
      "As a cybersecurity consultant, you are working with a client who wants to migrate their data to a Software as a Service (SaaS) cloud environment. They are particularly concerned about maintaining the privacy of their sensitive data, even from the cloud service provider. Which of the following strategies would best ensure the privacy of their data in the SaaS environment?",
    options: [
      "Encrypt the data client-side before uploading to the SaaS environment and manage encryption keys independently.",
      "Rely on the cloud service provider's built-in security features.",
      "Implement a Virtual Private Network (VPN) for accessing the SaaS applications.",
      "Use multi-factor authentication for all user accounts accessing the SaaS applications",
    ],
    correctAnswer: 0,
  },
  {
    id: 183,
    question:
      "Tony wants to integrate a 128-bit symmetric block cipher with key sizes of 128, 192, or 256 bits into a software program, which involves 32 rounds of computational operations that include substitution and permutation operations on four 32-bit word blocks using 8-variable S-boxes with 4-bit entry and 4-bit exit. Which of the following algorithms includes all the above features and can be integrated by Tony into the software program?",
    options: ["TEA", "Serpent", "CAST-128", "RC5"],
    correctAnswer: 1,
  },
  {
    id: 184,
    question:
      "Your company, Encryptor Corp, is developing a new application that will handle highly sensitive user information. As a cybersecurity specialist, you want to ensure this data is securely stored. The development team proposes a method where data is hashed and then encrypted before storage. However, you want an added layer of security to verify the integrity of the data upon retrieval. Which of the following cryptographic concepts should you propose to the team?",
    options: [
      "Apply a digital signature mechanism.",
      "Switch to elliptic curve cryptography.",
      "Implement a block cipher mode of operation.",
      "Suggest using salt with hashing.",
    ],
    correctAnswer: 0,
  },
  {
    id: 185,
    question:
      "Harper, a software engineer, is developing an email application. To ensure the confidentiality of email messages, Harper uses a symmetric-key block cipher having a classical 12- or 16-round Feistel network with a block size of 64 bits for encryption, which includes large 8 × 32-bit S-boxes (S1, S2, S3, S4) based on bent functions, modular addition and subtraction, key-dependent rotation, and XOR operations. This cipher also uses a masking key (Km1) and a rotation key (Kr1) for performing its functions. What is the algorithm employed by Harper to secure the email messages?",
    options: ["AES", "CAST-128", "GOST block cipher", "DES"],
    correctAnswer: 1,
  },
  {
    id: 188,
    question:
      "Rebecca, a security professional, wants to authenticate employees who use web services for safe and secure communication. In this process, she employs a component of the Web Service Architecture, which is an extension of SOAP, and it can maintain the integrity and confidentiality of SOAP messages.",
    options: ["WS-Policy", "WS-Security", "WSDL", "WS-Work Processes"],
    correctAnswer: 1,
  },
  {
    id: 190,
    question:
      "John wants to send Marie an email that includes sensitive information, and he does not trust the network that he is connected to. Marie gives him the idea of using PGP. What should John do to communicate correctly using this type of encryption?",
    options: [
      "Use Marie's public key to encrypt the message.",
      "Use his own public key to encrypt the message.",
      "Use his own private key to encrypt the message.",
      "Use Marie's private key to encrypt the message.",
    ],
    correctAnswer: 0,
  },
  {
    id: 191,
    question:
      "Your company, SecureTech Inc., is planning to transmit some sensitive data over an unsecured communication channel. As a cyber security expert, you decide to use symmetric key encryption to protect the data. However, you must also ensure the secure exchange of the symmetric key. Which of the following protocols would you recommend to the team to achieve this?",
    options: [
      "Utilizing SSH for secure remote logins to the servers.",
      "Applying the Diffie-Hellman protocol to exchange the symmetric key.",
      "Switching all data transmission to the HTTPS protocol.",
      "Implementing SSL certificates on your company's web servers.",
    ],
    correctAnswer: 1,
  },
  {
    id: 192,
    question:
      "You are a cybersecurity specialist at CloudTech Inc., a company providing cloud-based services. You are managing a project for a client who wants to migrate their sensitive data to a public cloud service. To comply with regulatory requirements, the client insists on maintaining full control over the encryption keys even when the data is at rest on the cloud. Which of the following practices should you implement to meet this requirement?",
    options: [
      "Rely on Secure Sockets Layer (SSL) encryption for data at rest.",
      "Encrypt data client-side before uploading to the cloud and retain control of the encryption keys.",
      "Use the cloud service provider's default encryption and key management services.",
      "Use the cloud service provider's encryption services but store keys on-premises.",
    ],
    correctAnswer: 1,
  },
  {
    id: 193,
    question:
      "Sam, a web developer, was instructed to incorporate a hybrid encryption software program into a web application to secure email messages. Sam used an encryption software, which is a free implementation of the OpenPGP standard that uses both symmetric-key cryptography and asymmetric-key cryptography for improved speed and secure key exchange. What is the encryption software employed by Sam for securing the email messages?",
    options: ["SMTP", "S/MIME", "GPG", "PGP"],
    correctAnswer: 2,
  },
  {
    id: 194,
    question:
      "This form of encryption algorithm is a symmetric key block cipher that is characterized by a 128-bit block size, and its key size can be up to 256 bits. Which among the following is this encryption algorithm?",
    options: [
      "HMAC encryption algorithm",
      "Twofish encryption algorithm",
      "Blowfish encryption algorithm",
      "IDEA",
    ],
    correctAnswer: 1,
  },
  {
    id: 195,
    question:
      "You are the chief security officer at AlphaTech, a tech company that specializes in data storage solutions. Your company is developing a new cloud storage platform where users can store their personal files. To ensure data security, the development team is proposing to use symmetric encryption for data at rest. However, they are unsure of how to securely manage and distribute the symmetric keys to users. Which of the following strategies would you recommend to them?",
    options: [
      "Use HTTPS protocol for secure key transfer.",
      "Use hash functions to distribute the keys.",
      "Implement the Diffie-Hellman protocol for secure key exchange.",
      "Use digital signatures to encrypt the symmetric keys.",
    ],
    correctAnswer: 2,
  },
  {
    id: 196,
    question:
      "You are the chief cybersecurity officer at CloudSecure Inc., and your team is responsible for securing a cloud-based application that handles sensitive customer data. To ensure that the data is protected from breaches, you have decided to implement encryption for both data-at-rest and data-in-transit. The development team suggests using SSL/TLS for securing data in transit. However, you want to also implement a mechanism to detect if the data was tampered with during transmission. Which of the following should you propose?",
    options: [
      "Switch to using SSH for data transmission.",
      "Use the cloud service provider's built-in encryption services.",
      "Implement IPsec in addition to SSL/TLS.",
      "Encrypt data using the AES algorithm before transmission.",
    ],
    correctAnswer: 2,
  },
  {
    id: 198,
    question:
      "BitLocker encryption has been implemented for all the Windows-based computers in an organization. You are concerned that someone might lose their cryptographic key. Therefore, a mechanism was implemented to recover the keys from Active Directory. What is this mechanism called in cryptography?",
    options: [
      "Key archival",
      "Key renewal",
      "Certificate rollover",
      "Key escrow",
    ],
    correctAnswer: 3,
  },
  {
    id: 199,
    question:
      "As a cybersecurity consultant for SafePath Corp, you have been tasked with implementing a system for secure email communication. The key requirement is to ensure both confidentiality and non-repudiation. While considering various encryption methods, you are inclined towards using a combination of symmetric and asymmetric cryptography. However, you are unsure which cryptographic technique would best serve the purpose. Which of the following options would you choose to meet these requirements?",
    options: [
      "Apply asymmetric encryption with RSA and use the private key for signing.",
      "Use the Diffie-Hellman protocol for key exchange and encryption.",
      "Use symmetric encryption with the AES algorithm.",
      "Apply asymmetric encryption with RSA and use the public key for encryption.",
    ],
    correctAnswer: 0,
  },
];

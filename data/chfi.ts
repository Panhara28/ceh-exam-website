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
    id: 217,
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
      "Title 18, Section 2703(f)"
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
      "A sheepdip computer defers a denial of service attack"
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
      "policy of separation"
    ],
    correctAnswer: 2,
  },
  {
    id: 268,
    question:
      "How many characters long is the fixed-length MD5 algorithm checksum of a critical system file?",
    options: [
      "128",
      "64",
      "32",
      "16"
    ],
    correctAnswer: 3,
  },
  {
    id: 269,
    question:
      "You are working on a thesis for your doctorate degree in Computer Science. Your thesis is based on HTML, DHTML, and other web-based languages and how they have evolved over the years.\nYou navigate to archive.org and view the HTML code of news.com. You then navigate to the current news.com website and copy over the source code. While searching through the code, you come across something abnormal: What have you found?",
    options: [
      "Web bug",
      "CGI code",
      "Trojan.downloader",
      "Blind bug"
    ],
    correctAnswer: 0,
  },
  {
    id: 270,
    question:
      "You are using DriveSpy, a forensic tool and want to copy 150 sectors where the starting sector is 1709 on the primary hard drive. Which of the following formats correctly specifies these sectors?",
    options: [
      "0:1000, 150",
      "0:1709, 150",
      "1:1709, 150",
      "0:1709-1858"
    ],
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
      "The attacker has installed a backdoor"
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
      "brandmark law"
    ],
    correctAnswer: 0,
  },
  {
    id: 273,
    question:
      "What file structure database would you expect to find on floppy disks?",
    options: [
      "NTFS",
      "FAT32",
      "FAT16",
      "FAT12"
    ],
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
      "ARP redirect"
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
      "one byte at the beginning of the file"
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
      "Secure delete programs work by completely overwriting the file in one go"
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
      "Approach the websites for evidence"
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
      "central processing attack"
    ],
    correctAnswer: 1,
  },
  {
    id: 279,
    question:
      "The offset in a hexadecimal code is:",
    options: [
      "The last byte after the colon",
      "The 0x at the beginning of the code",
      "The 0x at the end of the code",
      "The first byte after the colon"
    ],
    correctAnswer: 1,
  },
  {
    id: 280,
    question:
      "It takes _____________ mismanaged case/s to ruin your professional reputation as a computer forensics examiner?",
    options: [
      "by law, three",
      "quite a few",
      "only one",
      "at least two"
    ],
    correctAnswer: 2,
  },
  {
    id: 281,
    question:
      "With the standard Linux second extended file system (Ext2fs), a file is deleted when the inode internal link count reaches ________.",
    options: [
      "0",
      "10",
      "100",
      "1"
    ],
    correctAnswer: 0,
  }, {
    id: 282,
    question:
      "When examining the log files from a Windows IIS Web Server, how often is a new log file created?",
    options: [
      "the same log is used at all times",
      "a new log file is created everyday",
      "a new log file is created each week",
      "a new log is created each time the Web Server is started"
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
      "HKEY_CURRENT_USER"
    ],
    correctAnswer: 0,
  },
  {
    id: 284,
    question:
      "An employee is attempting to wipe out data stored on a couple of compact discs (CDs) and digital video discs (DVDs) by using a large magnet. You inform him that this method will not be effective in wiping out the data because CDs and DVDs are ______________ media used to store large amounts of data and are not affected by the magnet.",
    options: [
      "logical",
      "anti-magnetic",
      "magnetic",
      "optical"
    ],
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
      "It doesn't matter as all replies are faked"
    ],
    correctAnswer: 3,
  },
  {
    id: 286,
    question:
      "What does the acronym POST mean as it relates to a PC?",
    options: [
      "Primary Operations Short Test",
      "PowerOn Self Test",
      "Pre Operational Situation Test",
      "Primary Operating System Test"
    ],
    correctAnswer: 1,
  },
  {
    id: 287,
    question:
      "Which legal document allows law enforcement to search an office, place of business, or other locale for evidence relating to an alleged crime?",
    options: [
      "bench warrant",
      "wire tap",
      "subpoena",
      "search warrant"
    ],
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
      "All forms should be placed in the report file because they are now primary evidence in the case."
    ],
    correctAnswer: 1,
  },
  {
    id: 289,
    question:
      "The MD5 program is used to:",
    options: [
      "wipe magnetic media before recycling it",
      "make directories on an evidence disk",
      "view graphics files on an evidence drive",
      "verify that a disk is not altered when you examine it"
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
      "with the hard drive in the suspect PC, check the date and time in the system's CMOS"
    ],
    correctAnswer: 0,
  }
];

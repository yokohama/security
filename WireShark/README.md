# ARP

| a | b |
| - | - |
| Opcode 1: ARP requests | arp.opcode == 1 |
| Opcode 2: ARP responses | ap.opcode == 2 |
| Hunt: Arp scanning | arp.dst.hw_mac==00:00:00:00:00:00 |
| Hunt: Possible ARP poisoning detection | arp.duplicate-address-detected or arp.duplicate-address-frame |
| Hunt: Possible ARP flooding from detection | ((arp) && (arp.opcode == 1)) && (arp.src.hw_mac == target-mac-address) |

# ICMP
| Hunt: Encapsulated protocol signs in ICMP payload | data.len > 64 and icmp |

# DNS
| Hunt: DNS tunneling | dns.qry.name.len > 15 and !mdns |
- !mdns ignore local link device query.

# FTP
| 230: User login | ftp.response.code == 230 |
| 231: User logout | ftp.response.code == 231 |
| 331: Valid username | ftp.response.code == 331 |
| 430: Invalid username or password | ftp.response.code == 430 |
| 530: No login, invalid password | ftp.response.code == 530 | 
| USER: Usernamea | ftp.request.command == "USER" |
| PASS: Password | ftp.request.command == "PASS" |
| HUNT: Bruteforce signal: List failed login attempts. | ftp.response.code == 530 |
| HUNT: Bruteforce signal: List target username. | (ftp.response.code == 530) and (ftp.response.arg contains "username") |
| HUNT: Password spray signal: List targets for a static password. | (ftp.request.command == "PASS" ) and (ftp.request.arg == "password") |

# HTTP
| HUNT: Audit tools info like Nmap, Nikto, Wfuzz and sqlmap in the user agent field. | (http.user_agent contains "sqlmap") or (http.user_agent contains "Nmap") or (http.user_agent contains "Wfuzz") or (http.user_agent contains "Nikto") |

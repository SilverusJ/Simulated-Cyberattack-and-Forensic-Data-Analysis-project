# Simulated-Cyberattack-and-Forensic-Data-Analysis-project

## Objective

This project is the analysis of a simulated Remote Desktop Protocol (RDP) brute-force attack on a Windows Server system. The attack was conducted from a Kali Linux VM against a Windows 10/Server VM, with forensic analysis performed on a separate VM. The primary tools used in this investigation were Wireshark, NetworkMiner, and Windows Event Viewer.

### Skills Learned

- Capturing and analyzing network traffic using Wireshark
- Identifying suspicious communication patterns
- Extracting network artifacts and understanding protocol-level interactions
- Cybersecurity Attack Techniques
- Understanding RDP brute-force attack methodologies
- Recognizing common network infiltration strategies
- Examining Windows Event Viewer logs
- Correlating network events with system-level activities

### Tools Used

- Wireshark: For capturing and analyzing network traffic
- NetworkMiner: For extracting and analyzing network artifacts from PCAP files
- Windows Event Viewer: For examining system logs on the victim VM
- Hydra: For conducting the RDP brute-force attack

## Network Structure
- The network consisted of three main components:
- Attacker VM (Kali Linux)
- Victim VM (Windows 10/Server)
- Forensics VM (Kali Linux and Windows)

## Attack Scenario
An attacker conducted a brute-force attack on the victim's Windows Server, exploiting an open RDP port (TCP 3389). 

![Screenshot 2024-12-05 032045](https://github.com/user-attachments/assets/6861b89a-76d4-41d4-bfa3-9b812b926cc1)

## Data Collection and Analysis

**Wireshark Analysis**

Wireshark was used to capture and analyze network traffic between the attacker and victim VMs.
Key Findings:

- High volume of TCP connections to port 3389 (RDP)
- Multiple failed login attempts followed by a successful connection
- Suspicious data transfers post-authentication

![Screenshot 2024-12-05 032427](https://github.com/user-attachments/assets/7bd42b12-55cf-44a2-a9cf-cf2e0e2cd87f)

![Screenshot 2024-12-05 033749](https://github.com/user-attachments/assets/28f1a121-6fd2-4420-a0cb-18ea60ee9519)


**NetworkMiner Analysis**

NetworkMiner was employed to extract and analyze network artifacts from the captured PCAP files.
Key Findings:

- Identified the attacker's IP address and operating system
- Extracted files transferred during the RDP session
- Detected potential malware signatures in the network stream

![Screenshot 2024-12-05 034429](https://github.com/user-attachments/assets/4d2544f2-5779-473e-a568-6a19e76b5e0f)



**Windows Event Viewer Analysis**

Windows Event Viewer logs were examined on the victim VM to correlate network findings with system events.
Key Findings:

- Multiple failed login attempts from the attacker's IP address
- Successful login event corresponding to the brute-force attack
  
![Screenshot 2024-12-05 032618](https://github.com/user-attachments/assets/bc24f1bd-348f-4dc3-a098-b82b7db77acb)

![Screenshot 2024-12-05 032541](https://github.com/user-attachments/assets/d9159b37-d42b-418e-9633-a7cb3bbfb606)


## Conclusion

The analysis confirms an  RDP brute-force attack The attacker attempted to  exploit weak RDP security configurations to gain unauthorized access. Implementing the recommended security measures can significantly reduce the risk of similar attacks in the future.




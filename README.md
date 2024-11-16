# Security Event Analysis

## Objective

The primary purpose of this project is to simulate an attack scenario in a controlled environment to generate telemetry and analyze logs for potential detection methods. This involves creating malware, setting up a reverse shell listener, executing the malware on a target Windows virtual machine, and then reviewing telemetry in Splunk with Sysmon data.

### Skills Learned

- Understanding of how to perform port scanning and reconnaissance using nmap to identify open ports and services on a target machine.
- Ability to create a basic reverse TCP shell payload using msfvenom and package it as a malicious executable for testing.
- Ability to configure and use Metasploit's multi-handler to establish and manage Command and Control (C2) connections.
- Enhanced knowledge of how to generate and analyze telemetry data by executing malware and observing system behavior with Sysmon and Splunk.
- Proficiency in setting up and configuring Sysmon logs within Splunk to effectively monitor and analyze security events for threat detection.


### Tools Used

- VirtualBox: For setting up virtual machines running Kali Linux and Windows.
- Splunk: For ingesting, indexing, and analyzing Sysmon logs.
- Sysmon: For generating detailed telemetry on system events.
- PowerShell: For executing Sysmon executable to install the service.
- Task Manager and Command Prompt: For verifying network connections and inspecting process details on the Windows machine.
- nmap: For port scanning and reconnaissance.
- msfvenom: For creating a reverse TCP shell payload and generating malware.
- Metasploit Framework: Specifically the multi-handler for managing Command and Control (C2) connections.
- Python (HTTP Server): For hosting and distributing the malware.
- Windows Defender: To disable real-time protection for testing purposes.


## Steps

### Step 1

VirtualBox with Kali Linux and Windows 10 installed, along with configured Splunk and Sysmon on the Windows machine.
The two virtual machines were configured to reside on the same internal network, eliminating Internet connection and access to the host machine.
The target Windows machine was assigned the IP address 192.168.2.30 and the attacker Kali Linux machine was assigned the IP address 192.168.2.31.
Splunk and Sysmon were installed on the Windows machine.

![Security_Event_Analysis drawio](https://github.com/user-attachments/assets/324005b5-6c35-4d33-96ff-e421dbc0c953) 

(Network diagram)



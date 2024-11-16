# Detection Lab

## Objective

The primary purpose of this project is to simulate an attack scenario in a controlled environment to generate telemetry and analyze logs for potential detection methods. This involves creating basic malware, setting up a reverse shell listener, executing the malware on a target Windows virtual machine, and then reviewing telemetry in Splunk with Sysmon data to gain insights into detection opportunities.

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
- Task Manager and Command Prompt: For verifying network connections and inspecting process details on the Windows machine.
- nmap: For port scanning and reconnaissance.
- msfvenom: For creating a reverse TCP shell payload and generating malware.
- Metasploit Framework: Specifically the multi-handler for managing Command and Control (C2) connections.
- Python (HTTP Server): For hosting and distributing the malware.
- Windows Defender: To disable real-time protection for testing purposes.


## Steps
drag & drop screenshots here or use imgur and reference them using imgsrc

Every screenshot should have some text explaining what the screenshot is about.

Example below.

*Ref 1: Network Diagram*


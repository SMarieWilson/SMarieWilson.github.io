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

### Step 1: Setting up the machines

I created a Kali Linux (Attacker) and Windows 10 (Target) virtual machines on VirtualBox and configured Splunk and Sysmon on the Windows machine. The two virtual machines were configured to reside on the same internal network, eliminating Internet connection and access to the host machine. The target Windows machine was assigned the IP address 192.168.2.30 and the attacker Kali Linux machine was assigned the IP address 192.168.2.31. Configuring Splunk included creating an index and naming it "endpoint" in order to ingest Sysmon logs and the Splunk add-on for Sysmon was enabled to parse the logs. Remote Desktop was enabled on the Target machine to open Port 3389.


![Security_Event_Analysis drawio](https://github.com/user-attachments/assets/d1739c7f-0a4f-4d8a-a2e5-5ac5a272977f)

(Network diagram)
<br><br><br>
![internal_network](https://github.com/user-attachments/assets/2df1ae2d-ffed-4e60-8069-ee12cba84a52)

(Internal Network created)
<br><br><br>
![windows_ipv4](https://github.com/user-attachments/assets/0c3c7af4-44c0-4b0f-8aa4-5ad6273cffd4)

(IP address assigned to Target machine)
<br><br><br>
![ipconfig_1](https://github.com/user-attachments/assets/aba1096d-e398-490b-b6a5-49c83f2fca83)

(ipconfig shows the assigned IP address)
<br><br><br>
![kalilinux_ipv4](https://github.com/user-attachments/assets/f0f277d3-7e95-4e11-b58f-595154721603)

(IP address assigned to the Attacker machine)
<br><br><br>
![ipa_1](https://github.com/user-attachments/assets/e6e73321-1e16-4f9a-87e3-b108e7572b4c)

(ip a shows the assigned IP address)
<br><br><br>
![windows_ping_kalilinux](https://github.com/user-attachments/assets/e81a7845-8874-49fa-abbb-53bd12fa916e)

(Pinging the Attacker machine from the Target machine)
<br><br><br>
![installed_sysmon_PS](https://github.com/user-attachments/assets/94f3b311-a138-40ba-9a03-d2a61e0f1b4f)

(Sysmon64 executed and installed)
<br><br><br>
![index_endpoint](https://github.com/user-attachments/assets/63b70eb0-50b4-42fc-bdda-77f5e69ce325)

(Sysmon index named "endpoint" created)
<br><br><br>
![rdp_on](https://github.com/user-attachments/assets/45488b6a-a507-4c44-b55c-a2c21218d20b)

(Remote Desktop enabled)
<br><br><br>
![nmap_scan](https://github.com/user-attachments/assets/6c95cb6a-5ff4-49dd-9714-4ec64462bc09)

(Nmap scan ran on the Target machine to discover open ports)
<br><br><br>

### Step 2: Creating and Configuring malware

I used msfvenom to create malware, selecting windows/x64/meterpreter_reverse_tcp as the payload. The Attacker machine's IP address was specified as the listening host (lhost) and the default Port 4444 was used as the listening port (lport). The malware was saved as an executable named giftList.pdf.exe.

![malware_created](https://github.com/user-attachments/assets/13762ba1-ca05-4ef6-94f1-a1922fa1a124)

(Reverse TCP malware created)
<br><br><br>

### Step 3: Configuring the handler

I opened up Metasploit with msfconsole and set up a multi-handler using exploit/multi/handler, putting me in the exploit itself and changing the payload from generic shell to reverse TCP. I changed lhost to the Attacker machine's IP address. I started the handler to listen for incoming connections by typing "exploit."

![updated_lhost](https://github.com/user-attachments/assets/4f3f1c98-1efc-454d-839c-d2aec2520826)

(Malware payload is changed from generic to reverse TCP and lhost is changed to Attacker machine's IP address)
<br><br><br>
![handler_meterpreter_session](https://github.com/user-attachments/assets/d98490f6-6b2b-4388-9189-30824c24572d)

(Start handler)
<br><br><br>

### Step 4: Setting up file sharing on Kali and executing the malware on Windows

I started a Python HTTP server on the Attacker machine to share the malware on the Target machine. I disabled Windows Defender real-time protection on the Target machine. I then accessed the web browser to download and execute the malware on the Target machine. I ran netstat -anob to confirm a connection to the Attacker machine's IP and listening port and acertain the process ID of the running malware.

![python_http_server(2)](https://github.com/user-attachments/assets/6073597d-992d-4bfd-b178-9b1157a918b2)

(Python HTTP server started)
<br><br><br>
![real-time_protection_off](https://github.com/user-attachments/assets/1de9ed11-35a2-4e9e-83ed-0dc8a6a08269)

(Disabled Windows Defender real-time protection)
<br><br><br>
![access_malware_windows](https://github.com/user-attachments/assets/25902f71-a4f3-4af4-98e5-971b5d036102)

(Web browser accessed on the Target machine to download the malware)
<br><br><br>
![netstat_kalilinux](https://github.com/user-attachments/assets/9095dfac-da95-4d20-81b8-f59c8bcf714e)

(Netstat -anob ran to confirm connection to Attacker machine's IP and listening port and to identify the process ID)
<br><br><br>
![malware_task_manager](https://github.com/user-attachments/assets/5fd13ffd-9e39-4d96-b9e6-54a4348b50b6)

(Malware executed and running on the Target machine)
<br><br><br>

### Step 5: Interacting with the compromised Windows machine

I looked at the handler on the Attacker machine to confirm an open shell and then established a shell to the Target machine. I then ran commands on the Target machine (i.e., net user, net localgroup, and ipconfig) from the Attacker machine to simulate attacker activity and generate telemetry.

![meterpreter_shell](https://github.com/user-attachments/assets/ec391f41-bfbe-453a-b606-d58d95e85017)

(Shell on the Attacker machine running commands on the Target machine)
<br><br><br>
![ipconfig_2_from_kali](https://github.com/user-attachments/assets/51d34f7e-41bb-4056-a647-7bc7399fea57)

(ipconfig command ran on Target machine from Attacker machine)
<br><br><br>

### Step 6: Analyzing telemetry in Splunk

In Splunk, I queried the Attacker machine's IP address, the malware name, and the parent GUID to see the events fed into the "endpoint" index.

![splunk_malware_search](https://github.com/user-attachments/assets/f54e150d-38ca-4f44-b3d3-68ee8c1948d2)

(Malware query in Splunk)
<br><br><br>
![splunk_EventCode-1_process](https://github.com/user-attachments/assets/8669524c-1120-49ed-b5ce-676d72f6cd62)

(Event code 1: Process creation)
<br><br><br>
![Splunk_EventCode-1_parent_guid_search](https://github.com/user-attachments/assets/43c7118d-8853-47ba-a6d5-6af4b9a55708)

(GUID query in Splunk)
<br><br><br>
![Splunk_EventCode-1_parent_guid_search_result](https://github.com/user-attachments/assets/fa8309ee-4ea7-41d5-a085-6c2b8aa244a8)

(Parent GUID query result in Splunk)


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

### Step 1: Set up the machines

I created a Kali Linux and Windows 10 virtual machines on VirtualBox and configured Splunk and Sysmon on the Windows machine. The two virtual machines were configured to reside on the same internal network, eliminating Internet connection and access to the host machine. The target Windows machine was assigned the IP address 192.168.2.30 and the attacker Kali Linux machine was assigned the IP address 192.168.2.31. Configuring Splunk included creating an index and naming it "endpoint" in order to ingest Sysmon logs and the Splunk add-on for Sysmon was enabled to parse the logs. Remote Desktop was enabled on the Target machine to open Port 3389.


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

I opened up Metasploit with msfconsole and set up a multi-handler using exploit/multi/handler, putting me in the exploit itself and changing the payload from generic shell to reverse TCP. I changed lhost to the Attacker machine's IP address.

![updated_lhost](https://github.com/user-attachments/assets/4f3f1c98-1efc-454d-839c-d2aec2520826)

(Malware payload is changed from generic to reverse TCP and lhost is changed to Attacker machine's IP address)


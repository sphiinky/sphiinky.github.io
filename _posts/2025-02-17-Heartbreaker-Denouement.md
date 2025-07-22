---
title: "HTB Heartbreaker-Denouement Cloud Challenge Walkthrough with ELK"
date: 2025-02-17 09:52:24 +0300
categories: [HTB]
tags: [htb sherlocks, Writeup]


image:
  path: /assets/images/posts/2025-02-17-Heartbreaker-Denouement/00.png
---

Recently, I set up `Elasticsearch` and `Kibana` on my machine, so I decided to revisit this challenge. Since it involves working with a large dataset, it’s a great opportunity to become more familiar with the **ELK stack**. Additionally, I wanted to test how efficiently the lab could be solved without relying on `jq` and other text manipulation tools in the terminal.

### Description:

Your digital forensics expertise is critical to determine whether data exfiltration has occurred from the customer’s environment. Initial findings include a compromised AWS credential, indicating a potential unauthorized access. This investigation follows from a customer report of leaked data allegedly for sale on the darknet market. By examining the compromised server and analyzing the provided AWS logs, it will not only validate the customer's breach report but also provide valuable insights into the attacker's tactics, enabling a more comprehensive response.

### Tasks:

1. What type of scanning technique was used to discover the web path of the victim's web server? Specify the name of the corresponding MITRE sub-technique.
2. It seems a web request possibly could have been rerouted, potentially revealing the web server's web path to the Threat Actor. What specific HTML status code might have provided this information?
3. In the initial payload submitted by the threat actor exploiting a weakness in the web server, what file on the server was targeted?
4. What is the name of the vulnerability exploited by the Threat Actor to access the cloud metadata?
5. What time (UTC) did the Threat Actor first access the cloud metadata service of the web server instance?
6. To gain insight into the database content, can you provide the name of at least one table?
7. Which AWS API call functions similarly to the 'whoami' command in Windows or Linux?
8. The compromised AWS IAM credentials were exploited by the Threat Actor. Can you identify the regions where they were used successfully? Separate regions by comma and in ascending order.
9. The compromised IAM account's early access may have enabled the Threat Actor to obtain the public IP addresses of running instances before the web server attack. What API call could have exposed this information?
10. Looks like the Threat Actor used multiple IP addresses. What is the total number of unsuccessful requests made by the Threat Actor as seen in the CloudTrail logs?
11. Can you identify the AWS identities linked to successful API calls potentially used by the threat actor to reveal infrastructure details? Exclude any identity-related calls. Separate ARNs by comma and in ascending order.
12. Evidence suggests that a couple of AWS RDS databases were targeted. Can you identify all DB snapshots that were created by the Threat Actor? Separate identifiers by commas and in ascending order.
13. The threat actor successfully exfiltrated data to their account. Can you identify the AWS account ID they used?
14. Which MITRE Technique ID corresponds to the activity described in Question 13?


## Walkthrough:

From the tasks and description, we know that a web server has been compromised, and our goal is to trace the attacker through the CloudTrail logs. Therefore, I will start by analyzing the artifacts from the web server.
### Web server: 

At the beginning of the challenge you are giving a `HeartBreakerDenouement.zip` which contains: 

```bash
$ ll
total 2372
drwxrwxrwx 1 sphinky sphinky    4096 Feb 16 15:01 ./
drwxrwxrwx 1    7474    7474    4096 Feb 12 10:15 ../
drwxrwxrwx 1 sphinky sphinky    4096 Mar 15  2024 AWS/
-rwxrwxrwx 1 sphinky sphinky 2427902 Mar 13  2024 uac-uswebapp00-linux-20240313145552.tar.gz
```

`AWS` is the directory containing the cloud trails while `uac-uswebapp00-linux-20240313145552.tar.gz` contains files gathered from the IR team. I will go directly to the server logs at `[root]/var/log/apache2`, we got this:
```bash
$ ll
total 2296
drwxrwxrwx 1 sphinky sphinky    4096 Feb 16 12:22 ./
drwxrwxrwx 1 sphinky sphinky    4096 Feb 16 12:22 ../
-rwxrwxrwx 1 sphinky sphinky 2209091 Mar 13  2024 access.log
-rwxrwxrwx 1 sphinky sphinky  137119 Mar 13  2024 error.log
-rwxrwxrwx 1 sphinky sphinky       0 Mar 12  2024 other_vhosts_access.log
```
I will start with `access.log` and get back to `error.log` later. I will use `fluentbit` which is a lightweight log processor and forwarder to parse and send the `access.log`. Here is the part related to the configuration I used in this challenge:
```bash
$ sudo cat /etc/fluent-bit/fluent-bit.conf 
[INPUT]
    Name        tail
    Path        /path/to/access.log
    Parser      access_log_parser
    Tag         htb
    Refresh_Interval 5
    Read_From_Head On

[OUTPUT]
    Name        es
    Match       htb
    Host        localhost
    Port        9200
    Index       htb_access_log_heartbreaker-denouement
    HTTP_User   user
    HTTP_Passwd pass
    tls         On
    tls.verify  Off
    Type        _doc
    Suppress_Type_Name On
    Generate_ID On
$ sudo cat /etc/fluent-bit/parsers.conf
[PARSER]
    Name        access_log_parser
    Format      regex
    Regex       (?<ip_src>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) .*?\[(?<timestamp>.*?) .{4,10}\] "(?<method>\w{3,5}) (?<uri>\S+) .*?" (?<status_code>\d{3}) \S+ "(?<url>\S+)" "(?<user_agent>.+)"
    Time_Key    timestamp
    Time_Format %d/%b/%Y:%H:%M:%S
```

Next I send the log data to `elastic` and opened `kibana` to start working with it. I can see the data is parsed correctly as fields appear and immediately see a single source IP `35.169.66.138` in nearly all the logs 

![](/assets/images/posts/2025-02-17-Heartbreaker-Denouement/01.png)
I will add `35.169.66.138` in a filter to only include this IP and check the `status_code` and `method` to see what was happening
![](/assets/images/posts/2025-02-17-Heartbreaker-Denouement/02.png)
That a huge amount of `404` in a small time span which indicate this user was trying to fuzz the web server for hidden files or directories, likely as part of a reconnaissance or enumeration attempt. In **MITRE** that corresponds to `Active Scanning` and the **sub-technique** is `Wordlist Scanning`.

Next I will create a new `Aggregation based visualization` as a `Data table` to get more insights about what did the attacker get from the server. I will include the suspect IP and exclude the `status_code:404`and `403`. In `Metrics` I will choose `count` as I want only the number of occurrence, and in `Buckets` I will create 3 `Split rows` one for `status_code`, one for `method` and the other for `uri`. 
![](/assets/images/posts/2025-02-17-Heartbreaker-Denouement/03.png)
We can see a single redirection with `status_code 301` and there is 20 successful `post` requests. Since the `post` requests were successful we need to know more about what happened. The `access.log` won't provide us with anything new so I will go to `error.log` and look around the time those `post` requests were made. Here what we got:

```
[Wed Mar 13 14:03:17.482267 2024] [php7:notice] [pid 399] [client 35.169.66.138:35892] Request: POST /wb-loanapp-tracker.php Input: , referer: http://3.144.237.152/wb-loanapp-tracker.php
[Wed Mar 13 14:03:21.501887 2024] [php7:notice] [pid 399] [client 35.169.66.138:35892] Request: POST /wb-loanapp-tracker.php Input: , referer: http://3.144.237.152/wb-loanapp-tracker.php
[Wed Mar 13 14:05:05.451538 2024] [php7:notice] [pid 408] [client 35.169.66.138:42982] Request: POST /wb-loanapp-tracker.php Input: askdjmzxcnqw3e, referer: http://3.144.237.152/wb-loanapp-tracker.php
[Wed Mar 13 14:05:17.635598 2024] [php7:notice] [pid 410] [client 35.169.66.138:48240] Request: POST /wb-loanapp-tracker.php Input: file:///etc/passwd, referer: http://3.144.237.152/wb-loanapp-tracker.php
[Wed Mar 13 14:05:48.612192 2024] [php7:notice] [pid 23239] [client 35.169.66.138:50362] Request: POST /wb-loanapp-tracker.php Input: file:///etc/nginx/nginx.conf, referer: http://3.144.237.152/wb-loanapp-tracker.php
[Wed Mar 13 14:05:48.614921 2024] [php7:warn] [pid 23239] [client 35.169.66.138:50362] PHP Warning:  file_get_contents(file:///etc/nginx/nginx.conf): failed to open stream: No such file or directory in /var/www/html/wb-loanapp-tracker.php on line 107, referer: http://3.144.237.152/wb-loanapp-tracker.php
```
From the previous lines we see a keyword `Input` which carry something related to what was sent with the request like `askdjmzxcnqw3e`, `file:///etc/passwd` and `file:///etc/nginx/nginx.conf` but only the last one returned `failed to open stream: No such file or directory` which indicated the previous requested returned what was requested. 

The following lines in `error.log` carry:
```
[Wed Mar 13 14:06:21.695943 2024] [php7:notice] [pid 412] [client 35.169.66.138:52712] Request: POST /wb-loanapp-tracker.php Input: http://169.254.169.254, referer: http://3.144.237.152/wb-loanapp-tracker.php
[Wed Mar 13 14:06:30.584637 2024] [php7:notice] [pid 415] [client 35.169.66.138:35750] Request: POST /wb-loanapp-tracker.php Input: http://169.254.169.254/latest, referer: http://3.144.237.152/wb-loanapp-tracker.php
[Wed Mar 13 14:06:40.887829 2024] [php7:notice] [pid 404] [client 35.169.66.138:41200] Request: POST /wb-loanapp-tracker.php Input: http://169.254.169.254/latest/meta-data, referer: http://3.144.237.152/wb-loanapp-tracker.php
[Wed Mar 13 14:07:12.865444 2024] [php7:notice] [pid 401] [client 35.169.66.138:36720] Request: POST /wb-loanapp-tracker.php Input: http://169.254.169.254/latest/meta-data/identity-credentials, referer: http://3.144.237.152/wb-loanapp-tracker.php
[Wed Mar 13 14:07:20.392011 2024] [php7:notice] [pid 430] [client 35.169.66.138:37916] Request: POST /wb-loanapp-tracker.php Input: http://169.254.169.254/latest/meta-data/identity-credentials/ec2, referer: http://3.144.237.152/wb-loanapp-tracker.php
[Wed Mar 13 14:07:29.324690 2024] [php7:notice] [pid 399] [client 35.169.66.138:40632] Request: POST /wb-loanapp-tracker.php Input: http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/, referer: http://3.144.237.152/wb-loanapp-tracker.php
[Wed Mar 13 14:07:40.641033 2024] [php7:notice] [pid 408] [client 35.169.66.138:53194] Request: POST /wb-loanapp-tracker.php Input: http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance, referer: http://3.144.237.152/wb-loanapp-tracker.php
[Wed Mar 13 14:08:28.660610 2024] [php7:notice] [pid 410] [client 35.169.66.138:43118] Request: POST /wb-loanapp-tracker.php Input: http://169.254.169.254/latest/meta-data/identity-credentials/iam, referer: http://3.144.237.152/wb-loanapp-tracker.php
[Wed Mar 13 14:08:28.664143 2024] [php7:warn] [pid 410] [client 35.169.66.138:43118] PHP Warning:  file_get_contents(http://169.254.169.254/latest/meta-data/identity-credentials/iam): failed to open stream: HTTP request failed! HTTP/1.0 404 Not Found\r\n in /var/www/html/wb-loanapp-tracker.php on line 107, referer: http://3.144.237.152/wb-loanapp-tracker.php
```

which all of them carry an input sent to `http://169.254.169.254`. So the vulnerable server is making requests on behalf of the attacker, which is an example of `Server Side Request Forgery` (SSRF), and the threat actor accessed the cloud metadata for the first time in the same time the first request was made.

Task 6 requires the name of at least one table of the database, this info could be obtained from this file `\[root\]/home/ubuntu/.mysql_history`

### Cloud trails: 

I will start by preparing all the cloud trails to send it to `elastic`. In the `AWS` directory I will run those commands to find, extract and aggregate the json files:
```bash
$ find . -type f -name "*.gz" -exec sh -c 'gunzip "{}"' \;
$ find . -name *json -exec cat {} \; > phase1.json
$ jq -c '.Records[]' phase1.json | jq -s -c 'sort_by(.eventTime)' > phase2.json
$ jq -c .[] phase2.json > phase3.json
$ cat phase3.json | sort | uniq > final.json
```

And for `fluentbit` configuration I will use this (there is already a json parser):
```bash
[INPUT]
    Name        tail
    Path        /path/to/final.json
    Parser      json
    Tag         htb_Heartbreaker_Denouement
    Refresh_Interval 5
    Buffer_Chunk_Size 512KB
    Buffer_Max_Size 1MB
    Read_From_Head On
    Exit_On_EOF On

[OUTPUT]
    Name        es
    Match       htb_Heartbreaker_Denouement
    Host        localhost
    Port        9200
    Index       htb_heart_breakerdenouement
    HTTP_User   user
    HTTP_Passwd pass
    tls         On
    tls.verify  Off
    Type        _doc
    Suppress_Type_Name On
    Replace_Dots On
    Trace_Error       On
    Trace_Output      On
    Generate_ID On
```
Now moving to `kibana`, and not like the `access.log` the attacker IP is not that obvious so I will try to get using the `Visualization` in `kibana`. I will create a new `aggreation based` visualization and I will choose it `Data table`. The aggregation will be by `Count` by `terms` and in `Buckets` I will make a `Split rows` with field `sourceIPAddress.keyword`.  
![](/assets/images/posts/2025-02-17-Heartbreaker-Denouement/04.png)
We can see the attacker IP the same as the `access.log`, but since there could be more than one IP for the threat actor I will keep looking. I will eliminate domain names like `cloudtrail.amazonaws.com` and look for the `userAgent` to see if I could see some anomaly. I will change the `Split rows` to carry the `userAgent.keyword` field and make a `Split table` that carry `sourceIPAddress.keyword`   
![](/assets/images/posts/2025-02-17-Heartbreaker-Denouement/05.png)
I am not familiar with valid user agents used in cloud, but `AWS internal` seems valid. The attacker IP `35.169.66.138` user two agents, one carry the word `Python/3.7.0` and the other carry `os/linux#3.6.0-kail1`. We see another IP use the same `os/linux#3.6.0-kail1` userAgent and we should suspect that is another IP for the threat actor. Now I will get some metrices about the `eventName` which describes the AWS API actions.
![](/assets/images/posts/2025-02-17-Heartbreaker-Denouement/06.png)
I did some search about some of them to try to imagine what the attacker was trying to do. The `GetCallerIdentity` is the AWS API call function similarly to the **whoami**.
I will continue exploring the data and found an interesting field called `errorCode` which indicates a requested action couldn't be completed. I will see how many unsuccessful requests made by the Threat Actor with this filter:
![](/assets/images/posts/2025-02-17-Heartbreaker-Denouement/07.png)
That make a total `742` of unsuccessful requests made by the Threat Actor. Next I will focus on this single IP `35.169.66.138` and see which regions was he able to make successful requests to:
![](/assets/images/posts/2025-02-17-Heartbreaker-Denouement/08.png)
He made it to only two regions `us-east-1,us-east-2`. Next I will check what actions did he made by checking the `eventName` field:
![](/assets/images/posts/2025-02-17-Heartbreaker-Denouement/09.png)
Searching about those API give an Idea of what the attacker was doing. There is a task that asks about how did the treat actor obtain the public IP addresses of running instances before the web server attack, he was able to do so using the `DescribeInstances` API call. Next task asks about the AWS identities linked to successful API calls from the previous task, getting that would be easy with the same filter just change the field in the `Split rows` to `userIdentity.arn`:
![](/assets/images/posts/2025-02-17-Heartbreaker-Denouement/10.png)
The next task is about the DB snapshots that was taken, from the API list we made for the attackers IP we could see an API called `CreateDBSnapshot` associated with the `34.202.84.37` IP, So we filter with those values:
![](/assets/images/posts/2025-02-17-Heartbreaker-Denouement/11.png)
The values we need is stored in the `responseElements.dBSnapshotIdentifier` field. Now we want to know the AWS account ID to which the attacker successfully exfiltrated data to. Again answering all of those questions require exploring the data fields and knowing the functionality of the used API calls made by the attacker. One of the API is called `ModifyDBSnapshotAttribute` which is used to **modify the attributes of an Amazon RDS database snapshot**. This allows you to change permissions, such as making the snapshot publicly accessible or sharing it with specific AWS accounts. I will filter with this API and get the account ID from the `requestParameters.valuesToAdd` field:
![](/assets/images/posts/2025-02-17-Heartbreaker-Denouement/12.png)
This exfiltration behaviour corresponds to the MITRE technique `Transfer Data to Cloud Account` (T1537).


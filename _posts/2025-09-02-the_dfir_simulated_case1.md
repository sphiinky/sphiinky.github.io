---
title: "The DFIR Report simulated case1 walkthrough"
date: 2025-09-02 01:59:22 +0300
categories: [The DFIR Report]
tags: [the dfir report, Writeup, Recorded Video, ELK]
description: A walkthrough using ELK Stack's Timeline and Event Analyzer features to investigate and reconstruct a network intrusion. .
image:
  path: /assets/images/posts/2025-09-02-the_dfir_simulated_case1/00.png
---




<div style="position: relative; padding-bottom: 56.25%; height: 0; overflow: hidden;">
  <iframe src="https://www.youtube.com/embed/trCk7OW67eM" 
          style="position: absolute; top: 0; left: 0; width: 100%; height: 100%;" 
          frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen>
  </iframe>
</div>


### Artifacts and report template

[github](https://github.com/The-DFIR-Report/DFIR-Artifacts)

### StarkTech Incident Report 

[notion](https://www.notion.so/StarkTech-Incident-Report-23bb727b13738086a5c3f6db80e67e3a)

### Logstach conf

Used this configuration to send json files for elasticsearch on WSLv2

```
input {
  file {
    path => "/mnt/d/*.json"
    start_position => "beginning"
    sincedb_path => "NUL"
    codec => json 
  }
}

filter {
  date {
    match => ["Timestamp", "yyyy-MM-dd HH:mm:ss.SSS Z"]
    target => "@timestamp"  # Overwrite the default @timestamp field
  }
}

output {
  # stdout {
    # codec => rubydebug
  # }

  elasticsearch {
    hosts => ["http://localhost:9200"]
    index => "the_dfir_log"
    user => "elastic"
    password => "skvovv57sJg6=ExkK8_T"
    ssl_certificate_verification => false
  }
}
```

### Winlogbeat

Used this configuration to send sysmon raw evtx files to elasticsearch which helped to have event analyzer in security app

```

winlogbeat.event_logs:

    - name: 'D:\The DFIR Report\2025_analyst_kape\H.CVI6VVTBHM3FG\files5-C.b3fd34138d23e431\uploads\auto\C%3A\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%254Operational.evtx'
    - name: 'D:\The DFIR Report\2025_analyst_kape\H.CVI6VVTBHM3FG\desktop6-C.6e0994f03e86db7c\uploads\auto\C%3A\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%254Operational.evtx'
    - name: 'D:\The DFIR Report\2025_analyst_kape\H.CVI6VVTBHM3FG\dc1-C.11f6731fb786b22a\uploads\auto\C%3A\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%254Operational.evtx'

setup.template.settings:
  index.number_of_shards: 1

setup.kibana:
    host: "http://172.22.210.35:5601/"


output.elasticsearch:
 hosts: ["http://localhost:9200"]
 username: "elastic"
 password: "skvovv57sJg6=ExkK8_T"
 ssl.verification_mode: none
 pipeline: "winlogbeat-%{[agent.version]}-sysmon"

```

### SuperTimeline query

Still need to reduce some noise. The data view for it is both winlogbeat and the_dfir_log

```
((process.pid : (3236) and process.name : "spoolsv.exe") or (process.pid : (8776 or 8068) and process.name : "notepad.exe") and not event.action : "Image Loaded") or ((process.name : "pythonw.exe" and (not event.action : "Image Loaded" or file.name : "python311.dll") and not event.action : "FileCreate")) or (event.code : (1116 or 5001)) or ((event.code : 4624 and winlog.event_data.SubjectUserSid : S-1-0-0 and winlog.event_data.LogonProcessName : "NtLmSsp " and winlog.event_data.KeyLength : 0)  or (user.name : admin143 and winlog.event_data.LogonType.keyword : 7 and event.code : 4624) ) or ((event.code : ("1") and not data_stream.dataset.keyword :  ("windows.sysmon_operational" ) and not process.name : ( "wevtutil.exe" or "WerFault.exe" or "AgentPackageHeartbeat.exe"  or "sdbinst.exe" or "rundll32.exe" or "taskkill.exe" ) and not process.parent.name : ("msiexec.exe" or "8-0-11.exe") and not (process.name : "sc.exe" and process.parent.name : "svchost.exe")) or (event.code : 4104 and not powershell.file.script_block_text: ("requires -version 3.0*" or *# Copyright © 2008, Microsoft* or "*Set-StrictMode*" or "*Function*" ) and not winlog.process.pid : (3568 or 6520 or 4692) and not powershell.file.script_block_text  : ("$global:?" or "{$_.Name}" or "{(Format-DiskSpaceMB $_.Space) + \"MB\"}" or "prompt")))
```

If you need to import the Supertimeline save this into .ndjson and import it

```
{"savedObjectId":"adde9530-5af3-4d4c-a4fe-f1a158e5df06","version":"WzQxNzEsMzZd","columns":[{"columnHeaderType":"not-filtered","id":"@timestamp","type":"date"},{"columnHeaderType":"not-filtered","id":"host.name"},{"columnHeaderType":"not-filtered","id":"event.action"},{"columnHeaderType":"not-filtered","id":"event.type"},{"columnHeaderType":"not-filtered","id":"process.command_line"},{"columnHeaderType":"not-filtered","id":"powershell.file.script_block_text"},{"columnHeaderType":"not-filtered","id":"process.name"},{"columnHeaderType":"not-filtered","id":"process.parent.name"},{"columnHeaderType":"not-filtered","id":"user.name"},{"columnHeaderType":"not-filtered","id":"message"},{"columnHeaderType":"not-filtered","id":"winlog.event_data.Path"},{"columnHeaderType":"not-filtered","id":"winlog.event_data.TargetImage"},{"columnHeaderType":"not-filtered","id":"file.path"},{"columnHeaderType":"not-filtered","id":"dns.question.name"},{"columnHeaderType":"not-filtered","id":"destination.ip"},{"columnHeaderType":"not-filtered","id":"destination.port"},{"columnHeaderType":"not-filtered","id":"winlog.event_data.AuthenticationPackageName"},{"columnHeaderType":"not-filtered","id":"source.ip"}],"dataProviders":[],"dataViewId":"ec866aee-1d4e-4382-b419-c24847210f9f","description":"","eqlOptions":{"eventCategoryField":"event.category","query":"","size":100,"tiebreakerField":"","timestampField":"@timestamp"},"eventType":"all","filters":[],"indexNames":["dfir*","winlogbeat-*"],"kqlMode":"filter","kqlQuery":{"filterQuery":{"kuery":{"kind":"kuery","expression":"((process.pid : (3236) and process.name : \"spoolsv.exe\") or (process.pid : (8776 or 8068) and process.name : \"notepad.exe\") and not event.action : \"Image Loaded\") or ((process.name : \"pythonw.exe\" and (not event.action : \"Image Loaded\" or file.name : \"python311.dll\") and not event.action : \"FileCreate\")) or (event.code : (1116 or 5001)) or ((event.code : 4624 and winlog.event_data.SubjectUserSid : S-1-0-0 and winlog.event_data.LogonProcessName : \"NtLmSsp \" and winlog.event_data.KeyLength : 0)  or (user.name : admin143 and winlog.event_data.LogonType.keyword : 7 and event.code : 4624) ) or ((event.code : (\"1\") and not data_stream.dataset.keyword :  (\"windows.sysmon_operational\" ) and not process.name : ( \"wevtutil.exe\" or \"WerFault.exe\" or \"AgentPackageHeartbeat.exe\"  or \"sdbinst.exe\" or \"rundll32.exe\" or \"taskkill.exe\" ) and not process.parent.name : (\"msiexec.exe\" or \"8-0-11.exe\") and not (process.name : \"sc.exe\" and process.parent.name : \"svchost.exe\")) or (event.code : 4104 and not powershell.file.script_block_text: (\"requires -version 3.0*\" or *# Copyright © 2008, Microsoft* or \"*Set-StrictMode*\" or \"*Function*\" ) and not winlog.process.pid : (3568 or 6520 or 4692) and not powershell.file.script_block_text  : (\"$global:?\" or \"{$_.Name}\" or \"{(Format-DiskSpaceMB $_.Space) + \\\"MB\\\"}\" or \"prompt\")))"},"serializedQuery":"{\"bool\":{\"should\":[{\"bool\":{\"should\":[{\"bool\":{\"filter\":[{\"bool\":{\"should\":[{\"match\":{\"process.pid\":\"3236\"}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"match_phrase\":{\"process.name\":\"spoolsv.exe\"}}],\"minimum_should_match\":1}}]}},{\"bool\":{\"filter\":[{\"bool\":{\"filter\":[{\"bool\":{\"should\":[{\"bool\":{\"should\":[{\"match\":{\"process.pid\":\"8776\"}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"match\":{\"process.pid\":\"8068\"}}],\"minimum_should_match\":1}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"match_phrase\":{\"process.name\":\"notepad.exe\"}}],\"minimum_should_match\":1}}]}},{\"bool\":{\"must_not\":{\"bool\":{\"should\":[{\"match_phrase\":{\"event.action\":\"Image Loaded\"}}],\"minimum_should_match\":1}}}}]}}],\"minimum_should_match\":1}},{\"bool\":{\"filter\":[{\"bool\":{\"should\":[{\"match_phrase\":{\"process.name\":\"pythonw.exe\"}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"bool\":{\"must_not\":{\"bool\":{\"should\":[{\"match_phrase\":{\"event.action\":\"Image Loaded\"}}],\"minimum_should_match\":1}}}},{\"bool\":{\"should\":[{\"match_phrase\":{\"file.name\":\"python311.dll\"}}],\"minimum_should_match\":1}}],\"minimum_should_match\":1}},{\"bool\":{\"must_not\":{\"bool\":{\"should\":[{\"match_phrase\":{\"event.action\":\"FileCreate\"}}],\"minimum_should_match\":1}}}}]}},{\"bool\":{\"should\":[{\"bool\":{\"should\":[{\"match\":{\"event.code\":\"1116\"}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"match\":{\"event.code\":\"5001\"}}],\"minimum_should_match\":1}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"bool\":{\"filter\":[{\"bool\":{\"should\":[{\"match\":{\"event.code\":\"4624\"}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"match\":{\"winlog.event_data.SubjectUserSid\":\"S-1-0-0\"}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"match_phrase\":{\"winlog.event_data.LogonProcessName\":\"NtLmSsp \"}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"match\":{\"winlog.event_data.KeyLength\":\"0\"}}],\"minimum_should_match\":1}}]}},{\"bool\":{\"filter\":[{\"bool\":{\"should\":[{\"match\":{\"user.name\":\"admin143\"}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"term\":{\"winlog.event_data.LogonType.keyword\":{\"value\":\"7\"}}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"match\":{\"event.code\":\"4624\"}}],\"minimum_should_match\":1}}]}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"bool\":{\"filter\":[{\"bool\":{\"should\":[{\"match_phrase\":{\"event.code\":\"1\"}}],\"minimum_should_match\":1}},{\"bool\":{\"must_not\":{\"bool\":{\"should\":[{\"term\":{\"data_stream.dataset.keyword\":{\"value\":\"windows.sysmon_operational\"}}}],\"minimum_should_match\":1}}}},{\"bool\":{\"must_not\":{\"bool\":{\"should\":[{\"bool\":{\"should\":[{\"match_phrase\":{\"process.name\":\"wevtutil.exe\"}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"match_phrase\":{\"process.name\":\"WerFault.exe\"}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"match_phrase\":{\"process.name\":\"AgentPackageHeartbeat.exe\"}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"match_phrase\":{\"process.name\":\"sdbinst.exe\"}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"match_phrase\":{\"process.name\":\"rundll32.exe\"}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"match_phrase\":{\"process.name\":\"taskkill.exe\"}}],\"minimum_should_match\":1}}],\"minimum_should_match\":1}}}},{\"bool\":{\"must_not\":{\"bool\":{\"should\":[{\"bool\":{\"should\":[{\"match_phrase\":{\"process.parent.name\":\"msiexec.exe\"}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"match_phrase\":{\"process.parent.name\":\"8-0-11.exe\"}}],\"minimum_should_match\":1}}],\"minimum_should_match\":1}}}},{\"bool\":{\"must_not\":{\"bool\":{\"filter\":[{\"bool\":{\"should\":[{\"match_phrase\":{\"process.name\":\"sc.exe\"}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"match_phrase\":{\"process.parent.name\":\"svchost.exe\"}}],\"minimum_should_match\":1}}]}}}}]}},{\"bool\":{\"filter\":[{\"bool\":{\"should\":[{\"match\":{\"event.code\":\"4104\"}}],\"minimum_should_match\":1}},{\"bool\":{\"must_not\":{\"bool\":{\"should\":[{\"bool\":{\"should\":[{\"match_phrase\":{\"powershell.file.script_block_text\":\"requires -version 3.0*\"}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"query_string\":{\"fields\":[\"powershell.file.script_block_text\"],\"query\":\"*# Copyright © 2008, Microsoft*\"}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"match_phrase\":{\"powershell.file.script_block_text\":\"*Set-StrictMode*\"}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"match_phrase\":{\"powershell.file.script_block_text\":\"*Function*\"}}],\"minimum_should_match\":1}}],\"minimum_should_match\":1}}}},{\"bool\":{\"must_not\":{\"bool\":{\"should\":[{\"bool\":{\"should\":[{\"match\":{\"winlog.process.pid\":\"3568\"}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"match\":{\"winlog.process.pid\":\"6520\"}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"match\":{\"winlog.process.pid\":\"4692\"}}],\"minimum_should_match\":1}}],\"minimum_should_match\":1}}}},{\"bool\":{\"must_not\":{\"bool\":{\"should\":[{\"bool\":{\"should\":[{\"match_phrase\":{\"powershell.file.script_block_text\":\"$global:?\"}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"match_phrase\":{\"powershell.file.script_block_text\":\"{$_.Name}\"}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"match_phrase\":{\"powershell.file.script_block_text\":\"{(Format-DiskSpaceMB $_.Space) + \\\"MB\\\"}\"}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"match_phrase\":{\"powershell.file.script_block_text\":\"prompt\"}}],\"minimum_should_match\":1}}],\"minimum_should_match\":1}}}}]}}],\"minimum_should_match\":1}}],\"minimum_should_match\":1}}"}},"title":"SuperTimeline","templateTimelineId":null,"templateTimelineVersion":null,"dateRange":{"start":"2024-08-27T21:00:00.000Z","end":"2025-08-28T13:59:58.273Z"},"savedQueryId":null,"created":1756754554463,"createdBy":"elastic","updated":1756755929235,"updatedBy":"elastic","timelineType":"default","sort":[{"columnId":"@timestamp","columnType":"date","sortDirection":"asc"}],"savedSearchId":null,"eventNotes":[],"globalNotes":[],"pinnedEventIds":[]}

```


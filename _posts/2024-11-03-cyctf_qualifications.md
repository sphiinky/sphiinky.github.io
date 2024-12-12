---
title: "CyCTF Qualifications Injection forensics walkthrough"
date: 2024-11-03 05:59:22 +0300
categories: [CTF]
tags: [CTF, Writeup]
description: Walkthrough on how to use text manipulation in WSL to handle huge log files.
image:
  path: /assets/images/posts/2024-11-03-cyctfQal/cover.png
---

Felt a bit lazy to explain how to solve this challenge, so I recorded this video.


<div style="position: relative; padding-bottom: 56.25%; height: 0; overflow: hidden;">
  <iframe src="https://www.youtube.com/embed/kO6OJOxQJuc" 
          style="position: absolute; top: 0; left: 0; width: 100%; height: 100%;" 
          frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen>
  </iframe>
</div>








Here is the most commands/scripts used in the video with the outputs


```bash
$ cat access.log.1 | cut -d '"' -f 2 | sort | uniq -c | sort -n
      1 GET /DVWA/dvwa/css/login.css HTTP/1.1
      1 GET /DVWA/dvwa/images/login_logo.png HTTP/1.1
      1 POST /DVWA/security.php HTTP/1.1
      1 POST /DVWA/vulnerabilities/sqli_blind/?FTcz=4233%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23 HTTP/1.1
      1 POST /DVWA/vulnerabilities/sqli_blind/?SDwl=7966%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23 HTTP/1.1
      1 POST /DVWA/vulnerabilities/sqli_blind/?byWu=4655%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23 HTTP/1.1
      1 POST /DVWA/vulnerabilities/sqli_blind/?jLOC=7427%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23 HTTP/1.1
      2 GET /DVWA/index.php HTTP/1.1
      2 POST /DVWA/login.php HTTP/1.1
      3 GET /DVWA/login.php HTTP/1.1
      4 OPTIONS * HTTP/1.0
      5 GET /DVWA/security.php HTTP/1.1
  16042 POST /DVWA/vulnerabilities/sqli_blind/ HTTP/1.1
```

```bash
$ cat error.log.1 | grep -v "Operator GE matched" | awk -F'msg ' '{print $2}' | cut -d "]" -f 1 | sort | uniq -c | sort -n
      4 "Detects MySQL and PostgreSQL stored procedure/function injections"   no
      4 "Detects conditional SQL injection attempts"
      4 "Looking for basic sql injection. Common attack string for mysql, oracle and others"
      4 "NoScript XSS InjectionChecker: HTML Injection"
      4 "OS File Access Attempt"
      4 "PHP Injection Attack: High-Risk PHP Function Call Found"
      4 "Remote Command Execution: Unix Shell Code Found"
      4 "XSS Attack Detected via libinjection"
      4 "XSS Filter - Category 1: Script Tag Vector"
      8 "Remote Command Execution: Unix Shell Expression Found"
     11
     16 "Detects MySQL UDF injection and other data/structure manipulation attempts"
     16 "Detects SQL benchmark and sleep injection attempts including conditional queries"
     24 "Path Traversal Attack (/../)"
     24 "Remote Command Execution: Windows Command Injection"
     36 "Detects blind sqli tests using sleep() or benchmark()"
    684 "Detects concatenated basic SQL injection and SQLLFI attempts"
  10219 "SQL Injection Attack: Common DB Names Detected"
  10863 "Detects MSSQL code execution and information gathering attempts"
  16001 "SQL Injection Attack Detected via libinjection"
  16046 "Found User-Agent associated with security scanner"  no
```

```bash

$ cat error.log.1 | grep "Remote Command Execution: Unix Shell Expression Found" | awk -F 'data "' '{print $2}' | cut -d "]" -f1 | uniq
```

**html extractor**
```bash
#!/bin/bash

# Input file
input_file="modsec_audit.log.1"

# Initialize counter
counter=1

# Use grep to extract HTML blocks and loop through each match
grep -ozP '(?s)(<!DOCTYPE\s*html>.*?</html>)' "$input_file" | while IFS= read -r -d '' match; do
    # Write each match to a numbered file
    echo "$match" > "$counter.html"
    echo "Wrote content to $counter.html"
    ((counter++))
done
```


```bash

$ sha1sum * | cut -d " " -f1 | sort | uniq -c
sha1sum: data: Is a directory
   8285 e2e1ccf9a99028f6a066516515c1ec17fbd9015b
   7053 fce0f39ce1991103a1bc2e38801a7a2ce9de5cdb
$ diff ./html/1.html ./html/3001.html
```


**get correct query**
```bash
awk '/id=1%20AND/ {id_line = $0} /Content-Length: 1406/ && id_line {print id_line; id_line = ""}' modsec_audit.log.1 > all.txt
while IFS= read -r line; do   printf '%b\n' "$(echo -e "$line" | sed 's/%/\\x/g')"; done < all.txt > decoded_file
grep ">" decoded_file > final_decoded
grep "SELECT" final_decoded > final_final_decoded
cat final_final_decoded | cut -d "&" -f1  > file1
cat file1 | cut -d ">" -f1 | uniq > file2

```

```bash
while IFS= read -r line; do
#    echo "Searching for: $line"
    last_match=$(tac file1 | grep -F "$line" | head -n 1)
    if [[ -n $last_match ]]; then
        echo "$last_match"
    else
        echo "No match found for '$line'"
    fi
done < file2

```



```bash
./match.sh  > match.txt
```

**2 digits python script**

```python
import re

def convert_single_digit_to_double_digit(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    updated_lines = []
    for line in lines:
        # Replace single-digit numbers with two-digit representation
        updated_line = re.sub(r'\b([0-9])\b', lambda x: f"{int(x.group(0)):02d}", line)
        updated_lines.append(updated_line)

    # Write the updated lines back to a new file or overwrite the existing file
    with open('updated_' + file_path, 'w') as updated_file:
        updated_file.writelines(updated_lines)

    print(f"Updated lines written to 'updated_{file_path}'")

# Change 'your_file.txt' to the path of your input file
convert_single_digit_to_double_digit('match.txt')

```

```bash
$ cat final_bgd | cut -d ">" -f 2 | sed 's/^0\+//;s/^$/0/' | tr "\n" "," > solve.py
```

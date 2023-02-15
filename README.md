## :exclamation: Another Small personal Project POC form my side. Completely Free and Open Source. Doesn't belong to my Company's Asset!

### Main Idea: Dynamic Evasion

![image](https://user-images.githubusercontent.com/61424547/218156540-e0b6ee2b-e478-49a2-88b7-b8ef805c63ff.png)

Actually this image made me to do this Project. (Thanks to [@matterpreter](https://twitter.com/matterpreter))

#### 1. First dumping the Hooked Function and then wait for User Input => Name of implant to download From remote.
#### 2. Once the implant is ready (Doesn't use any hooked functions which are dumped previously), the implant is hosted on the payload Server and inputed as implant name into this PE Loader.
#### 3. Then implant Header needs to edited using any hex editor, in my case => I edited from **`MZ`** to **`ÉZ`** and then Downloaded from the Website in that state. This is done just to trick **`EDR`** that the downloaded binary is not any PE binary. Much much thanks to [@peterwintrsmith](https://twitter.com/peterwintrsmith) for this suggestion! :smile:

**Editing Demon.exe (HavocC2 bin)**:
![image](https://user-images.githubusercontent.com/61424547/219120555-3c790d82-cd0b-4753-b959-49acb776a94c.png)


**Before the Usage of this PE header _EDITING_ technique**:
![image](https://user-images.githubusercontent.com/61424547/219118762-4c20a8ea-909a-493d-a6b8-f61c3b216d2d.png)

**After the Usage of this PE header _EDITING_ technique**:
![image](https://user-images.githubusercontent.com/61424547/219119758-f8290593-a9cf-4b3f-a6d1-338f8e3ce5b3.png)

### Demo:

https://user-images.githubusercontent.com/61424547/219202618-6fcc9a3c-63df-4745-8ac9-cd1351ec87da.mp4

Video Link: https://drive.google.com/file/d/1Y7MqPWR13fY0WqNGUTXPgYVbiMy-j41d/view?usp=sharing

### Internal Findings:

1. Bypassing [Get-InjectedThread.ps1](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2) by [@jaredcatkinson](https://twitter.com/jaredcatkinson?lang=en):

I used EnumThreadWindows not CreateRemoteThread, to run shellcode version of ntdll in-memory!

![image](https://user-images.githubusercontent.com/61424547/219207475-646cc69b-d330-46ab-be8f-e63daad81943.png)

2. Bypassing [DefenderCheck](https://github.com/matterpreter/DefenderCheck): by [@matterpreter](https://twitter.com/matterpreter)

![image](https://user-images.githubusercontent.com/61424547/219206363-014dffc6-6874-409f-8fc1-4025aab01b12.png)

3. AntiScan.me Scan:

![image](https://user-images.githubusercontent.com/61424547/219206667-cb056b22-8ebb-4fdc-ad77-642854517750.png)

4. [Capa](https://github.com/mandiant/capa) Scan:

![image](https://user-images.githubusercontent.com/61424547/219207726-b8f6e07e-6ca9-4ef1-a9e9-648e15d5615a.png)

5. [Moneta](https://github.com/forrest-orr/moneta) Scan: 

![image](https://user-images.githubusercontent.com/61424547/219208072-e3598689-d56d-438c-8168-f68d1d9f7a93.png)

6. [Pe-sieve](https://github.com/hasherezade/pe-sieve) Scan:

```diff
PS C:\Users\HP\Desktop\Tools\DefenseTools> .\pe-sieve64.exe /pid 18164 /shellc /data 3
PID: 18164
Output filter: no filter: dump everything (default)
Dump mode: autodetect (default)
[-] Could not set debug privilege
[*] Using raw process!
[*] Scanning: C:\Users\HP\Desktop\Windows\MaldevTechniques\3.Evasions\CheckHook_PELoader\checkHooks-n-load.exe
[*] Scanning: C:\Windows\System32\ntdll.dll
[*] Scanning: C:\Windows\System32\kernel32.dll
[*] Scanning: C:\Windows\System32\KERNELBASE.dll
[*] Scanning: C:\Windows\System32\user32.dll
[*] Scanning: C:\Windows\System32\win32u.dll
[*] Scanning: C:\Windows\System32\gdi32.dll
[*] Scanning: C:\Windows\System32\gdi32full.dll
[*] Scanning: C:\Windows\System32\winhttp.dll
[*] Scanning: C:\Windows\System32\msvcp_win.dll
[*] Scanning: C:\Windows\System32\ucrtbase.dll
[*] Scanning: C:\Windows\System32\sechost.dll
[*] Scanning: C:\Windows\System32\rpcrt4.dll
[*] Scanning: C:\Windows\System32\imm32.dll
[*] Scanning: C:\Windows\System32\ws2_32.dll
[*] Scanning: C:\Windows\System32\advapi32.dll
[*] Scanning: C:\Windows\System32\msvcrt.dll
[*] Scanning: C:\Windows\System32\combase.dll
[*] Scanning: C:\Windows\System32\webio.dll
[*] Scanning: C:\Windows\System32\mswsock.dll
[*] Scanning: C:\Windows\System32\IPHLPAPI.DLL
[*] Scanning: C:\Windows\System32\winnsi.dll
[*] Scanning: C:\Windows\System32\nsi.dll
[*] Scanning: C:\Windows\System32\sspicli.dll
[*] Scanning: C:\Windows\System32\crypt32.dll
[*] Scanning: C:\Windows\System32\mscoree.dll
[*] Scanning: C:\Windows\System32\oleaut32.dll
[*] Scanning: C:\Windows\System32\shell32.dll
[*] Scanning: C:\Windows\System32\cryptsp.dll
[*] Scanning: C:\Windows\System32\wkscli.dll
[*] Scanning: C:\Windows\System32\netapi32.dll
[*] Scanning: C:\Windows\System32\samcli.dll
[*] Scanning: C:\Windows\System32\srvcli.dll
[*] Scanning: C:\Windows\System32\netutils.dll
[*] Scanning: C:\Windows\System32\dhcpcsvc.dll
[*] Scanning: C:\Windows\System32\schannel.dll
[*] Scanning: C:\Windows\System32\mskeyprotect.dll
[*] Scanning: C:\Windows\System32\ntasn1.dll
[*] Scanning: C:\Windows\System32\ncrypt.dll
[*] Scanning: C:\Windows\System32\bcrypt.dll
[*] Scanning: C:\Windows\System32\ncryptsslp.dll
[*] Scanning: C:\Windows\System32\bcryptprimitives.dll
[*] Scanning: C:\Windows\System32\msasn1.dll
[*] Scanning: C:\Windows\System32\rsaenh.dll
[*] Scanning: C:\Windows\System32\CRYPTBASE.dll
[*] Scanning: C:\Windows\System32\gpapi.dll
[*] Scanning: C:\Windows\System32\dpapi.dll
Scanning workingset: 298 memory regions.
[!] Scanning detached: 00007FF770A10000 : C:\Users\HP\Desktop\Windows\MaldevTechniques\3.Evasions\CheckHook_PELoader\checkHooks-n-load.exe
[-] Could not read the remote PE at: 00007FF770A10000
[*] Workingset scanned in 985 ms
[+] Report dumped to: process_18164
[!] Image size at: 7ff770a10000 undetermined, using calculated size: 2f000
[*] Dumped module to: C:\Users\HP\Desktop\Tools\DefenseTools\\process_18164\7ff770a10000.checkHooks-n-load.exe as VIRTUAL
[*] Dumped module to: C:\Users\HP\Desktop\Tools\DefenseTools\\process_18164\7ffe237e0000.kernel32.dll as REALIGNED
[*] Dumped module to: C:\Users\HP\Desktop\Tools\DefenseTools\\process_18164\140000000.exe as REALIGNED
[*] Dumped module to: C:\Users\HP\Desktop\Tools\DefenseTools\\process_18164\29883e50000.shc as VIRTUAL
[+] Dumped modified to: process_18164
[+] Report dumped to: process_18164
---
PID: 18164
---
SUMMARY:

Total scanned:      46
Skipped:            0
-
-Hooked:             1
Replaced:           0
Hdrs Modified:      0
IAT Hooks:          0
-Implanted:          2
-Implanted PE:       2
Implanted shc:      0
Unreachable files:  0
-Other:              1
-
-Total suspicious:   4
---
```

### Resourses:
1. [@peterwintrsmith](https://twitter.com/peterwintrsmith) and [@Jean_Maes_1994](https://twitter.com/Jean_Maes_1994), as always helping and guiding me! :smile:!
2. https://stackoverflow.com/questions/38672719/post-request-in-winhttp-c
3. https://github.com/aaaddress1/RunPE-In-Memory
4. [detecting-hooked-syscall-functions](https://www.ired.team/offensive-security/defense-evasion/detecting-hooked-syscall-functions) by [@spotheplanet](https://twitter.com/spotheplanet)
5. [posts.specterops.io](https://posts.specterops.io/adventures-in-dynamic-evasion-1fe0bac57aa) by [@matterpreter](https://twitter.com/matterpreter)
6. [@SEKTOR7net](https://twitter.com/SEKTOR7net) as always for his [Evasion Course](https://institute.sektor7.net/rto-win-evasion)!

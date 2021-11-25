# fsociety - Writeup

## Problem
We believe that there is an SSH Password inside password protected 'ZIP' folder. Can you crack the 'ZIP' folder and get the SSH password?

## Solution
1. For this challenge, we are presented with a zip file that we do not know the password to, and we have to extract the text file inside to obtain the flag.
2. The first thing that we have to do, is to brute force the password of the zip file. To do that, we will be using `fcrackzip` and the password that we have obtained is `justdoit`
```code
kali@kali:~/Desktop$ fcrackzip -u -D -p rockyou.txt fsociety.zip


PASSWORD FOUND!!!!: pw == justdoit
```
3. After obtaining the password, we are able to access the text file to view the contents.
```code
*****************************************************************************************
Encrypted SSH credentials to access Blume ctOS : 

MDExMDEwMDEgMDExMDAxMTAgMDEwMTExMTEgMDExMTEwMDEgMDAxMTAwMDAgMDExMTAxMDEgMDEwMTExMTEgMDExMDAwMTEgMDEwMDAwMDAgMDExMDExMTAgMDEwMTExMTEgMDAxMDAxMDAgMDExMDExMDEgMDAxMTAwMTEgMDExMDExMDAgMDExMDExMDAgMDEwMTExMTEgMDExMTAxMTEgMDExMDEwMDAgMDEwMDAwMDAgMDExMTAxMDAgMDEwMTExMTEgMDExMTAxMDAgMDExMDEwMDAgMDAxMTAwMTEgMDEwMTExMTEgMDExMTAwMTAgMDAxMTAwMDAgMDExMDAwMTEgMDExMDEwMTEgMDEwMTExMTEgMDExMDEwMDEgMDExMTAwMTEgMDEwMTExMTEgMDExMDAwMTEgMDAxMTAwMDAgMDAxMTAwMDAgMDExMDEwMTEgMDExMDEwMDEgMDExMDExMTAgMDExMDAxMTE=

*****************************************************************************************
```
4. However, we realize that the contents are decoded in Base64 and so we have to decode the contents. The results of the decoded contents are shown below:
```code
01101001 01100110 01011111 01111001 00110000 01110101 01011111 01100011 01000000 01101110 01011111 00100100 01101101 00110011 01101100 01101100 01011111 01110111 01101000 01000000 01110100 01011111 01110100 01101000 00110011 01011111 01110010 00110000 01100011 01101011 01011111 01101001 01110011 01011111 01100011 00110000 00110000 01101011 01101001 01101110 01100111
```
5. Now, we realize that the decoded contents are in the binary format, and all that is remaining is to convert them into text as shown below:
```code
if_y0u_c@n_$m3ll_wh@t_th3_r0ck_is_c00king
```
## Flag
flag : HTB{if_y0u_c@n_$m3ll_wh@t_th3_r0ck_is_c00king}

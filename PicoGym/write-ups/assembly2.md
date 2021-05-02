# Some Assembly Required 2 - Writeup

## Problem
http://mercury.picoctf.net:61778/index.html

## Solution
1. Similiar to [Some Assembly Required 1](https://github.com/joelczk/CTF/blob/main/PicoGym/write-ups/assembly1.md/), this challenge requires the use of web assembly. 
2. Visiting the website, we are presented with an input field for us to submit the flag.
3. We will try to submit `aaa` into the input field, and we realise that we will see and `incorrect` text below the input field.
4. Using developer tools to view the web assembly, we are presented with the following:
```code
(data (i32.const 1024) "xakgK\5cNs((j:l9<mimk?:k;9;8=8?=0?>jnn:j=lu\00\00")
)
```
5. We realise that the flag is in the form of gibberish text (Likely XOR) and is unlikely to be the flag.
6. We will analyze the text in the magic module in [CyberChef](https://gchq.github.io/CyberChef/), and we are presented with the following outputs as shown in the link [here](https://gchq.github.io/CyberChef/#recipe=Magic(5,true,false,'picoct')&input=eGFrZ0tcNWNOcygoajpsOTxtaW1rPzprOzk7OD04Pz0wPz5qbm46aj1sdQ)
7. We can then conclude that the flag is `picoCTF{  b2d14eaec72c31305075876bff2b5d}`

## Flag
flag : picoCTF{  b2d14eaec72c31305075876bff2b5d}
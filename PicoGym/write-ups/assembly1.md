# Some Assembly Required 1 - Writeup

## Problem
http://mercury.picoctf.net:55336/index.html

## Solution
1. Looking at the question name, we might guess that some form of assembly is required in this question, probably web assmebly. 
2. Visiting the website, we are presented with an input field for us to submit the flag.
3. We will try to submit `aaa` into the input field, and we realise that we will see and `incorrect` text below the input field.
4. Using developer tools to view the web assembly, we are presented with the following:
```code
  (data (i32.const 1024) "picoCTF{51e513c498950a515b1aab5e941b2615}\00\00")
)
```
5. Using the flag that we have found, we try to submit the flag into the input field, and we see that the text below the input field is now changed to `correct`

## Flag
flag : picoCTF{51e513c498950a515b1aab5e941b2615}

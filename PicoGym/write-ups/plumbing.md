# Plumbing - Writeup

## Problem
Sometimes you need to handle process data outside of a file. Can you find a way to keep the output from this program and search for the flag? Connect to jupiter.challenges.picoctf.org 4427.

## Solution
1. Connecting to the CTF server, we realise that we are presented with a continuous stream of text. 
2. We will then have to redirect the output to a text file to be able to view the text and find the flag.
```code
$ nc jupiter.challenges.picoctf.org 4427 > output.txt
```
3. Analysing the text inside the text file, we are able to find the flag.
```code
Not a flag either
Not a flag either
I don't think this is a flag either
picoCTF{digital_plumb3r_5ea1fbd7}
I don't think this is a flag either
Not a flag either
Not a flag either
```

## Flag
flag : picoCTF{digital_plumb3r_5ea1fbd7}

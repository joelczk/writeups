# Extensions - Writeup

## Problem
This is a really weird text file TXT? Can you find the flag?

## Solution
1. Trying to open the file, we realise that we are unable to do so as the file is either corrupted or the file extensions might have been wrong. 
2. Viewing the file in a hex editor, we realise that the file headers are `89 50 4E 47` which corresponds to a PNG file. 
3. Changing the extension of the `flag.txt` file to a `flag.png` file, we are now able to open the file and obtain the flag. 

## Flag
flag : picoCTF{now_you_know_about_extensions}

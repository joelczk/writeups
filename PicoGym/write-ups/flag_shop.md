# flag_shop - Writeup

## Problem
There's a flag shop selling stuff, can you buy a flag? Connect with nc jupiter.challenges.picoctf.org 9745.

## Solution
1. Reading the source code, we notice that this might be an integer overflow problem. If we entered a sufficiently large number for `number_flags`, `total_cost` might potentially be overflowed.
![Image of source code](https://github.com/joelczk/CTF/blob/main/PicoGym/images/flag_shop/code.PNG)
<<<<<<< HEAD
2. Compiling and testing on our local machine, we realised that giving a sufficiently large number for `number_flags` will give a negative value for `total_cost`, and the balance will also be greater than 10000. This shows that the exploit has been successful.
![Image of source code](https://github.com/joelczk/CTF/blob/main/PicoGym/images/flag_shop/code.PNG)
=======
2. Compiling and testing on our local machine, we realised that giving a sufficiently large number for `number_flags` will give a negative value for `total_cost`.
3. We also realised that we will have a value greater than 10000 for our balance, which shows that the exploit has been successfuly
>>>>>>> f5f3f9d48b95c86088f6fe1d055412f3c35651ed
4. Now, we will run this exploit on the remote machine to get the flag.

## Flag
flag : picoCTF{m0n3y_bag5_65d67a74}

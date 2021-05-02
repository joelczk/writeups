# flag_shop - Writeup

## Problem
There's a flag shop selling stuff, can you buy a flag? Connect with nc jupiter.challenges.picoctf.org 9745.

## Solution
1. Reading the source code, we notice that this might be an integer overflow problem. If we entered a sufficiently large number for `number_flags`, `total_cost` might potentially be overflowed.
```code
if(number_flags > 0) {
    int total_cost = 0;
    total_cost = 900*number_flags;
    printf("\nThe final cost is: %d\n", total_cost);
    if(total_cost <= account_balance){
        account_balance = account_balance - total_cost;
        printf("\nYour current balance after transaction: %d\n\n", account_balance);
    } else{
        printf("Not enough funds to complete purchase\n");
    }                 
}
```
2. Compiling and testing on our local machine, we realised that giving a sufficiently large number for `number_flags` will give a negative value for `total_cost`.We also realised that we will have a value greater than 10000 for our balance, which shows that the exploit has been successful.
```code
These knockoff Flags cost 900 each, enter desired quantity
3000000

The final cost is: -1594967296

Your current balance after transaction: 1594968396
```
3. Now, we will run this exploit on the remote machine to get the flag.

## Flag
flag : picoCTF{m0n3y_bag5_65d67a74}

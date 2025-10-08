# zip++

## Solution

The program we are given is meant to compress our input by just listing the number of times a character appears in a row next to each character, and it does this for as long as it is given data. This is a horrible explanation, just see below.

```
data to compress :
aaaaaaaaa
compressed data : 61090A01
data to compress : 
aaabbbaaaaa
compressed data : 6103620361050A01
```
If we look into the program we can see that the input and output buffers in `vuln` are relatively similar in length:
```c
char input [768];
byte output [772];
```
However, if we think about this, if we input something such as `asasasasasasasasa` where each character is different from the previous, the output should end up being twice as long as the input. Thus, we should have a buffer overflow, which we can see when we try this:
```

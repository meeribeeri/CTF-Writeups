# Character Assassination
## Solution

For this challenge, we are given the source code of the binary and the binary itself , [character-assassination](./character_assassination).
Running the binary, we see that it forces every odd indexed character lowercase and every even indexed character uppercase, when starting the index at 1.

```
AAAAAAAAAAAAAAA
aAaAaAaAaAaAaAa
```

Looking at the source code, we see that it does this with two arrays lower[] and upper[]. We can also see that flag is stored in an array just before upper[].

```c
ARRAYS HERE
```

In main, there is a for loop that uses the value of each character (e.g. 0x61 for 'a') as the index for each array. 

```c
MAIN LOOP
```

However, each array is only 127 bytes long, and the max value a byte can be is 255. Therefore, we can read values out of the array bounds by giving it chars that, when converted into an integer, has a value greater than about 127.

Doing this shows us that when reading out of bounds for lower[], those being the first, third, fifth, seventh, and so on characters, we end up read values in upper[]

```
example
```

However, doing this with upper, such as the second character of our input, starts reading flag values. Thus, we can just make a loop and read the whole value of the flag like this.

## Script

```py
code
```

## Flag

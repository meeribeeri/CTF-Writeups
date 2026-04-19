# tea-cash

## Solution
This challenge tests if you know how tcache chunks are laid out. Essentially, each free chunk has a pointer to the next free chunk, and so when malloc is called, the chunk at the start of the list is used if the size matches, and the tcache head now points to what that chunk was pointing to. There are some good visuals you can look up if you want.

All the challenge asks is to be given those pointers in memory. The first pointer is given by the program, the rest are known as the chunks are sequential in memory, and in this case are all the same size. I did have issues with the challenge at first, but that was due to it not running properly for some unknown reasons. I came back to it after a bit and it worked.
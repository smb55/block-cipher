# block-cipher

A python implementation of a block cipher using elements from the AES and DES systems.

Please note that currently only two bytes has been allocated for the counter so the maximum blocks is 2^16. With an 8-byte block size this means the maximum file size for this program is ~500kb.

There has been no input sanitisaion or error handling done. File inputs are basic strings so paths may not work, only files located in the working
are currently tested as working.

Key Schedule Generation 

Use python secrets module to generate a (true?) random 128 bit (16 byte / 4 word) key 
Create 12 64-bit (8 byte / 2 word) keys from this 128-bit seed key with the following process: 
Working with 4-byte words, process is similar to AES: 
First four words are the four words in the original key. 
To get 5th word, 4th word is put through the g-function, then XOR’d with the 1st word.  
To get 6th word, 5th word is XOR with 2nd word 
To get 7th word, 6th word is XOR with 3rd word 
To get 8th word, 7th word is XOR with 4th word. 
To get 9th word, 8th word is put through g-function then XOR with 5th word 
… and so on, just like AES key schedule until we have 24 4-byte words. 
This is enough to make 12 2-word / 4-byte / 64-bit round keys. 
 
The g-function is similar to AES as well. 4 bytes (a word) is fed in, the bytes are rotated one place left, and then all four bytes are substituted with the AES s-box. This part is the same as AES. For the final step of the g-function, instead of doing another substitution table, I simply flip all of the bits in the first byte by XORing it with FF. 

Block Encryption 

To encrypt a block: 
First rearrange the bytes in the block according to the following table (permutation): 
perm = [6, 1, 3, 8, 2, 7, 5, 4] 
I made this table up – it seems like a reasonably good permutation, it takes 11 rounds to repeat and moves the bytes around a lot. 
Next, substitute all the bytes with the AES s-box (substitution) 
Its possible substituting only half would be better, not sure, need to think about it 
Then use the round key to XOR with the data (key mixing) 
Repeat for 12 rounds with the 12 different keys 

Mode of Operation 

Counter mode 

6 byte IV + 2 byte counter is combined for each block 
The 8 byte combo is encrypted with the block encryption algorithm above for each block required to exceed the length of the input file  
Excess length is trimmed off, resulting in a keystream matching file length 
XOR is used to encrypt the file with the keystream 

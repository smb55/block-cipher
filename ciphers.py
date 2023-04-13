#!/usr/bin/env python3
import secrets
import sys
from pathlib import Path

##################
##################
# BLOCK CIPHER FUNCTIONS AND CONSTANTS
##################
##################

# specify the s-box lookup table as a dictionary (this is the exact AES s-box)
sbox = {
    0x00: 0x63, 0x01: 0x7c, 0x02: 0x77, 0x03: 0x7b, 0x04: 0xf2, 0x05: 0x6b, 0x06: 0x6f, 0x07: 0xc5,
    0x08: 0x30, 0x09: 0x01, 0x0a: 0x67, 0x0b: 0x2b, 0x0c: 0xfe, 0x0d: 0xd7, 0x0e: 0xab, 0x0f: 0x76,
    0x10: 0xca, 0x11: 0x82, 0x12: 0xc9, 0x13: 0x7d, 0x14: 0xfa, 0x15: 0x59, 0x16: 0x47, 0x17: 0xf0,
    0x18: 0xad, 0x19: 0xd4, 0x1a: 0xa2, 0x1b: 0xaf, 0x1c: 0x9c, 0x1d: 0xa4, 0x1e: 0x72, 0x1f: 0xc0,
    0x20: 0xb7, 0x21: 0xfd, 0x22: 0x93, 0x23: 0x26, 0x24: 0x36, 0x25: 0x3f, 0x26: 0xf7, 0x27: 0xcc,
    0x28: 0x34, 0x29: 0xa5, 0x2a: 0xe5, 0x2b: 0xf1, 0x2c: 0x71, 0x2d: 0xd8, 0x2e: 0x31, 0x2f: 0x15,
    0x30: 0x04, 0x31: 0xc7, 0x32: 0x23, 0x33: 0xc3, 0x34: 0x18, 0x35: 0x96, 0x36: 0x05, 0x37: 0x9a,
    0x38: 0x07, 0x39: 0x12, 0x3a: 0x80, 0x3b: 0xe2, 0x3c: 0xeb, 0x3d: 0x27, 0x3e: 0xb2, 0x3f: 0x75,
    0x40: 0x09, 0x41: 0x83, 0x42: 0x2c, 0x43: 0x1a, 0x44: 0x1b, 0x45: 0x6e, 0x46: 0x5a, 0x47: 0xa0, 
    0x48: 0x52, 0x49: 0x3b, 0x4a: 0xd6, 0x4b: 0xb3, 0x4c: 0x29, 0x4d: 0xe3, 0x4e: 0x2f, 0x4f: 0x84, 
    0x50: 0x53, 0x51: 0xd1, 0x52: 0x00, 0x53: 0xed, 0x54: 0x20, 0x55: 0xfc, 0x56: 0xb1, 0x57: 0x5b, 
    0x58: 0x6a, 0x59: 0xcb, 0x5a: 0xbe, 0x5b: 0x39, 0x5c: 0x4a, 0x5d: 0x4c, 0x5e: 0x58, 0x5f: 0xcf, 
    0x60: 0xd0, 0x61: 0xef, 0x62: 0xaa, 0x63: 0xfb, 0x64: 0x43, 0x65: 0x4d, 0x66: 0x33, 0x67: 0x85, 
    0x68: 0x45, 0x69: 0xf9, 0x6a: 0x02, 0x6b: 0x7f, 0x6c: 0x50, 0x6d: 0x3c, 0x6e: 0x9f, 0x6f: 0xa8, 
    0x70: 0x51, 0x71: 0xa3, 0x72: 0x40, 0x73: 0x8f, 0x74: 0x92, 0x75: 0x9d, 0x76: 0x38, 0x77: 0xf5, 
    0x78: 0xbc, 0x79: 0xb6, 0x7a: 0xda, 0x7b: 0x21, 0x7c: 0x10, 0x7d: 0xff, 0x7e: 0xf3, 0x7f: 0xd2, 
    0x80: 0xcd, 0x81: 0x0c, 0x82: 0x13, 0x83: 0xec, 0x84: 0x5f, 0x85: 0x97, 0x86: 0x44, 0x87: 0x17, 
    0x88: 0xc4, 0x89: 0xa7, 0x8a: 0x7e, 0x8b: 0x3d, 0x8c: 0x64, 0x8d: 0x5d, 0x8e: 0x19, 0x8f: 0x73, 
    0x90: 0x60, 0x91: 0x81, 0x92: 0x4f, 0x93: 0xdc, 0x94: 0x22, 0x95: 0x2a, 0x96: 0x90, 0x97: 0x88, 
    0x98: 0x46, 0x99: 0xee, 0x9a: 0xb8, 0x9b: 0x14, 0x9c: 0xde, 0x9d: 0x5e, 0x9e: 0x0b, 0x9f: 0xdb, 
    0xa0: 0xe0, 0xa1: 0x32, 0xa2: 0x3a, 0xa3: 0x0a, 0xa4: 0x49, 0xa5: 0x06, 0xa6: 0x24, 0xa7: 0x5c, 
    0xa8: 0xc2, 0xa9: 0xd3, 0xaa: 0xac, 0xab: 0x62, 0xac: 0x91, 0xad: 0x95, 0xae: 0xe4, 0xaf: 0x79, 
    0xb0: 0xe7, 0xb1: 0xc8, 0xb2: 0x37, 0xb3: 0x6d, 0xb4: 0x8d, 0xb5: 0xd5, 0xb6: 0x4e, 0xb7: 0xa9, 
    0xb8: 0x6c, 0xb9: 0x56, 0xba: 0xf4, 0xbb: 0xea, 0xbc: 0x65, 0xbd: 0x7a, 0xbe: 0xae, 0xbf: 0x08, 
    0xc0: 0xba, 0xc1: 0x78, 0xc2: 0x25, 0xc3: 0x2e, 0xc4: 0x1c, 0xc5: 0xa6, 0xc6: 0xb4, 0xc7: 0xc6, 
    0xc8: 0xe8, 0xc9: 0xdd, 0xca: 0x74, 0xcb: 0x1f, 0xcc: 0x4b, 0xcd: 0xbd, 0xce: 0x8b, 0xcf: 0x8a, 
    0xd0: 0x70, 0xd1: 0x3e, 0xd2: 0xb5, 0xd3: 0x66, 0xd4: 0x48, 0xd5: 0x03, 0xd6: 0xf6, 0xd7: 0x0e, 
    0xd8: 0x61, 0xd9: 0x35, 0xda: 0x57, 0xdb: 0xb9, 0xdc: 0x86, 0xdd: 0xc1, 0xde: 0x1d, 0xdf: 0x9e, 
    0xe0: 0xe1, 0xe1: 0xf8, 0xe2: 0x98, 0xe3: 0x11, 0xe4: 0x69, 0xe5: 0xd9, 0xe6: 0x8e, 0xe7: 0x94, 
    0xe8: 0x9b, 0xe9: 0x1e, 0xea: 0x87, 0xeb: 0xe9, 0xec: 0xce, 0xed: 0x55, 0xee: 0x28, 0xef: 0xdf, 
    0xf0: 0x8c, 0xf1: 0xa1, 0xf2: 0x89, 0xf3: 0x0d, 0xf4: 0xbf, 0xf5: 0xe6, 0xf6: 0x42, 0xf7: 0x68, 
    0xf8: 0x41, 0xf9: 0x99, 0xfa: 0x2d, 0xfb: 0x0f, 0xfc: 0xb0, 0xfd: 0x54, 0xfe: 0xbb, 0xff: 0x16
}

# specify the byte permutation table
perm = [7, 6, 1, 8, 4, 3, 5, 2]

#### Key, key schedule, and IV generation functions

def load_key(keyFileName):
    '''This function loads a 16 byte key from filename and returns it as a list four 4-bye bytearrays.'''
    with keyFileName.open(mode='rb') as f:
        data = f.read()
        wordList = [bytearray(data[i:i+4]) for i in range(0, 16, 4)]
        return wordList

def generate_key(keyFileName):
    '''This function generates an initial 16 byte key. It saves the key as a single byte array to the filename specified
    and returns the key as four 4-byte words (bytearrays), ready to be expanded with the generate_key_words function.'''
    # generate the key as a four 4-bye word list
    wordList = [bytearray(secrets.token_bytes(4)) for i in range(4)]  
    # convert it to a single bytearray for saving
    fullKey = bytearray()
    for word in wordList:
        fullKey.extend(word)  
    # save the key to the specified filename
    with keyFileName.open(mode='wb') as f:
        f.write(fullKey)

    return wordList

# define a function to create 24 words based on the original 4-word key, to be used to populate the key schedule
def generate_key_words(words):
    '''This recursive function takes a list of 4-byte words (bytearrays) and returns an expanded 24 word list.
    Pass it the original 16-byte key as a list of four 4-byte words (as bytearrays), and 24 words will be 
    returned that can be assembled into the 12 8-byte round keys.'''

    if len(words) == 24:
        return words
    else:
        # every 4th word should be put through the g function first
        if len(words) % 4 == 0:
            # run the last word through the g function, XOR it with the word 3 places behind, and then append the result
            words.append(bytearray([a ^ b for a, b in zip(gfunc(words[-1]), words[-4])]))
        
        # otherwise the final word just gets XOR'd with the word 3 places behind, and appended
        else:
            words.append(bytearray([a ^ b for a, b in zip(words[-1], words[-4])]))

        # then we run the function again - will continue until the list is 24 words long. At this point it will return the list
        # of 24 bytearrays back up the chain to the original function call.
        return generate_key_words(words)

def gfunc(word):
    '''This function transforms a four-byte array in three ways. It rotates the bytes one position right, then performs
    an s-box substitution, and then flips all of the bits in the first byte.'''
    # rotate the bytes in the word one position right
    rotatedArray = word[3:] + word[:3]
    # substiture the array with the sbox
    substitutedArray = bytearray([sbox[int(i)] for i in rotatedArray])
    # flip the bits in the first byte of the word by XORing with ff then return it
    return bytearray([substitutedArray[0] ^ 0xff, substitutedArray[1], substitutedArray[2], substitutedArray[3]])

def generate_key_schedule(keyWords):
    '''This function assembles the list of 24 words into a list of 12 8-byte keys'''
    keyList = []
    # iterate through the list of words and concat each pair into a single 8-byte bytes object
    for i in range(0, 24, 2):
        keyList.append(bytes(keyWords[i] + keyWords[i+1]))
    return keyList

def generate_iv():
    '''Return a random 4 byte IV as bytes.'''
    return secrets.token_bytes(4)

#### functions to build the keystream and transform the data

def encrypt(input, keySchedule):
    '''This function runs the encryption algorithm on the input block, with provided keySchedule. Input must be 8 bytes.
    keySchedule must be a list of 12 8-byte keys.'''
    # convert the input into a bytearray
    data = bytearray(input)
    # run 12 rounds of encryption (as long as a 12 item list of keys has been provided)
    for key in keySchedule:
        # first permutate the order of the bytes and then run the s-box substitution
        data = sbox_sub(permutate(data))
        # mix with the key using XOR
        data = bytearray([dataByte ^ keyByte for dataByte, keyByte in zip(data, bytearray(key))])

    return bytes(data)

def permutate(data):
    '''This function rearranges the bytes in an 8-byte array according to the set permutation table.'''
    return bytearray([data[i-1] for i in perm])

def sbox_sub(data):
     '''This function substitutes all bytes in the data bytearray with their matching entry in the s-box'''
     return bytearray([sbox[int(i)] for i in data])   

def build_keystream(numBlocks, excessLen):
    '''This function builds the synchronous stream cipher used to encrypt/decrypt the plaintext. Input args are the
     number of blocks and the amount of excess bytes that need to be trimmed at the end.'''
    keyStream = bytearray()
    # encrypt each of the IV+counter combos in turn and add them to the key stream
    for i in range(numBlocks):
        ivValue = next(gen_iv_blocks(iv))
        keyStream.extend(encrypt(ivValue, keySchedule))

    # remove the excess bytes to match the original file length (if there are excess bytes)
    if excessLen != 0:
        keyStream = keyStream[:(excessLen * -1)]
    
    return bytes(keyStream)

def gen_iv_blocks(iv):
    '''This is a generator function that will generate the next iv + counter combo to be encrypted by the block cipher.
    takes the iv as argument and will yield successive iv+counter values until the counter hits 4 bytes and it breaks.'''
    i = 0
    while True:
        counter = i.to_bytes(4, byteorder='big')
        i += 1
        yield iv + counter

##################
##################
# SHARED FUNCTIONS
##################
##################

def transform(opFile, keyStream):
    '''This function transforms the file by XORing it with the provided keystream.
    File and keystream must be binary files the same length.'''
    return(bytes(data ^ key for data, key in zip(opFile, keyStream)))

##################
##################
# SHARED MAIN PROGRAM CODE - INPUTS
##################
##################

# string flags collected: cipher(s/b) mode(d/e) newKey(n/e) 
# paths collected: keyFileName sourceFileName destFileName

# select stream or block cipher
cipher = input("[S]tream or [B]lock cipher? ").lower()
# select encryption or decryption
mode = input("[D]ecrypt or [E]ncrypt? ").lower()
if mode == 'd':
    # load the key
    keyFileName = Path(input("Provide the path to the key you would like to load: "))
elif mode == 'e':
    if not cipher == 's':
        # select new or existing key - block cipher only
        newKey = input("Use a [n]ew or [e]xisting key? " ).lower()

        if newKey == 'n':
            # for new key, select where to save it and generate it
            keyFileName = Path(input("Provide a path and filename for where the key should be saved: "))
        elif newKey == 'e':
            # for existing key, specify location and load it
            keyFileName = Path(input("Provide the path to the key you would like to load: "))
        else:
            print("Invalid key selection. Please choose n or e.")
            sys.exit()

else:
    print("Invalid mode selection. Please choose e or d.")
    sys.exit()

# set the location of the source file
sourceFileName = Path(input("Enter the path to the source file: "))
# set the destination for the transformed data
destFileName = Path(input("Enter the path and filename for the destination file: "))

##################
##################
# BLOCK CIPHER MAIN PROGRAM
##################
##################

if cipher == 'b':
    # if mode is decryption
    if mode == 'd':
        rawKey = load_key(keyFileName)
        # load the source file
        with sourceFileName.open(mode='rb') as f:
            opFileRaw = f.read()

        # retrieve the IV from the end of the message
        iv = opFileRaw[-4:]
        opFile = opFileRaw[:-4]

    # if mode is encryption
    else:
        # generate or load key
        if newKey == 'n':
            rawKey = generate_key(keyFileName)
        else:
            rawKey = load_key(keyFileName)
        # open source file
        with sourceFileName.open(mode='rb') as f:
            opFile = f.read()

        # create an IV
        iv = generate_iv()

    #### at this point all further operations are the same for encryption and decryption so we can group them together.

    # build the key schedule
    keySchedule = generate_key_schedule(generate_key_words(rawKey))

    # calc number of blocks and the number of bytes that need to be removed from the end of the keystream to match th input file length
    fullBlocks = len(opFile) // 8

    if len(opFile) % 8 != 0:
        numBlocks = fullBlocks + 1
        excessLen = 8 - (len(opFile) % 8)
    else:
        numBlocks = fullBlocks
        excessLen = 0

    # run the block cipher to build the keystream
    keyStream = build_keystream(numBlocks, excessLen)

    # encrypt/decrypt by XORing the input with the keystream
    outputData = transform(opFile, keyStream)

    # if mode is encrypt, append the iv to the output
    if mode == 'e':
        outputData += iv

    # write the output to the specified file
    with destFileName.open(mode='wb') as f:
        f.write(outputData)

##################
##################
# STREAM CIPHER MAIN PROGRAM
##################
##################

elif cipher == 's':
    if mode == 'e':
        # in encryption mode first load the source file to be encrypted
        with sourceFileName.open(mode='rb') as f:
            sourceFile = f.read()
        
        #create a key with length equal to source file length
        key = secrets.token_bytes(len(sourceFile))
        #  write it to file
        with keyFileName.open(mode='wb') as f:
            f.write(key)

        # use the transform function to XOR the data with the key, then save it to file
        with destFileName.open(mode='wb') as f:
            f.write(transform(sourceFile, key))

    elif mode == 'd':
        # in decryption mode, load the source file to be decrypted
        with sourceFileName.open(mode='rb') as f:
            sourceFile = f.read()
        # load the key from the specified path
        with keyFileName.open(mode='rb') as f:
            key = f.read()

        # use the transform function to XOR the data with the key, then save it to file
        with destFileName.open(mode='wb') as f:
            f.write(transform(sourceFile, key))

    else:
        # bad input
        print("Invalid mode selected. Please enter d or e.")


else:
    # bad input
    print("Invalid cipher selected. Please enter b or s.")

print("Operation complete.")
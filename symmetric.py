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
    '''This function loads a 16 byte key from filename and returns it as a list of two 8-bye bytearrays.'''
    with keyFileName.open(mode='rb') as f:
        data = f.read()
        keyList = [bytearray(data[i:i+8]) for i in range(0, 16, 8)]
        return keyList

def generate_key(keyFileName):
    '''This function generates an initial 16 byte key. It saves the key as a single bytes file to the filename specified
    and returns the key as two 8-byte sub keys (as bytearrays), ready to be expanded with the generate_key_schedule function.'''
    # generate the key as a four 4-bye word list
    keyList = [bytearray(secrets.token_bytes(8)) for i in range(2)]  
    # convert it to a single bytearray for saving
    fullKey = bytearray()
    for key in keyList:
        fullKey.extend(key)  
    # save the key to the specified filename
    with keyFileName.open(mode='wb') as f:
        f.write(bytes(fullKey))

    return keyList

# define a function to create 24 words based on the original 4-word key, to be used to populate the key schedule
def generate_key_schedule(keys, totalKeys):
    '''This recursive function takes a list of 8-byte keys (bytearrays) and returns an expanded key list size totalKeys.
    Pass it the original 16-byte key as a list of two 8-byte keys (as bytearrays), and 12 keys will be 
    returned that can be used as the 12 8-byte round keys. totalKeys MUST be a multiple of 2.'''
    if len(keys) == totalKeys:
        return keys
    else:
        # generate the next key and add it to the keys
        # transform the last key by permutating then sbox substituting
        firstTransform = sbox_sub(permutate(keys[-1]))
        # then XOR the result with the second last key, and add the result to the keys list
        newKey = bytearray([a ^ b for a, b, in zip(firstTransform, keys[-2])])
        keys.append(newKey)
   
        # then we run the function again - will continue until the list is 24 words long. At this point it will return the list
        # of 24 bytearrays back up the chain to the original function call.
        return generate_key_schedule(keys, totalKeys)

def generate_iv():
    '''Return a random 8 byte IV as bytes.'''
    return secrets.token_bytes(8)

#### functions to build the keystream and transform the data

def encrypt(input, keySchedule):
    '''This function runs the encryption algorithm on the input block, with provided keySchedule. Input must be 16 bytes.
    keySchedule must be a list of 12 8-byte keys.'''
    # convert the input into a bytearray
    #print("New Block:")
    # split the block in two halves
    dataOne = bytearray(input[:8])
    dataTwo = bytearray(input[8:])
    #print("Initial Data:", data)
    # run 12 rounds of encryption (as long as a 12 item list of keys has been provided)
    for key in keySchedule:
        # first swap the halves
        dataOne, dataTwo = dataTwo, dataOne
        # then permutate the order of the bytes and then run the s-box substitution on dataOne
        dataOne = sbox_sub(permutate(dataOne))
        # mix dataOne with the key using XOR
        dataOne = bytearray([dataByte ^ keyByte for dataByte, keyByte in zip(dataOne, bytearray(key))])
        # XOR the new dataOne with dataTwo to get new dataTwo
        dataTwo = bytearray([dataByte ^ keyByte for dataByte, keyByte in zip(dataOne, dataTwo)])
        #print(data)
    
    # combine the halves
    output = dataOne + dataTwo

    return bytes(output)

def permutate(data):
    '''This function rearranges the bytes in an 8-byte array according to the set permutation table.'''
    return bytearray([data[i-1] for i in perm])

def sbox_sub(data):
     '''This function substitutes all bytes in the data bytearray with their matching entry in the s-box'''
     return bytearray([sbox[int(i)] for i in data])   

def build_keystream(numBlocks, excessLen, keySchedule, iv):
    '''This function builds the synchronous stream cipher used to encrypt/decrypt the plaintext. Input args are the
     number of blocks, the amount of excess bytes that need to be trimmed at the end, the key schedule, and the iv.'''
    keyStream = bytearray()
    # encrypt each of the IV+counter combos in turn and add them to the key stream
    ivGen = gen_iv_blocks(iv)
    for i in range(numBlocks):
        ivValue = next(ivGen)
        #print("IV:", ivValue)
        keyStream.extend(encrypt(ivValue, keySchedule))

    # remove the excess bytes to match the original file length (if there are excess bytes)
    if excessLen != 0:
        keyStream = keyStream[:(excessLen * -1)]
    
    return bytes(keyStream)

def gen_iv_blocks(iv):
    '''This is a generator function that will generate the next iv + counter combo to be encrypted by the block cipher.
    takes the iv as argument and will yield successive iv+counter values until the counter hits 8 bytes and it breaks.'''
    i = 0
    while True:
        counter = i.to_bytes(8, byteorder='big')
        i += 1
        yield (iv + counter)

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
# STREAM CIPHER FUNCTIONS
##################
##################


def extend_key(key, length):    
    keyparts = [key[1008:1016], key[1016:1024]]
    remaining = length - 1024
    moreKeys = remaining // 8 + 1
    extrakey = 8 - (remaining % 8)
    newKeys = generate_key_schedule(keyparts, moreKeys)
    
    for newKey in newKeys:
        key += newKey
    key = key[:-extrakey]
    return key

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
        iv = opFileRaw[-8:]
        opFile = opFileRaw[:-8]

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
    keySchedule = generate_key_schedule(rawKey,12)

    # calc number of blocks and the number of bytes that need to be removed from the end of the keystream to match th input file length
    fullBlocks = len(opFile) // 16

    if len(opFile) % 16 != 0:
        numBlocks = fullBlocks + 1
        excessLen = 16 - (len(opFile) % 16)
    else:
        numBlocks = fullBlocks
        excessLen = 0

    # run the block cipher to build the keystream
    keyStream = build_keystream(numBlocks, excessLen, keySchedule, iv)

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
        # for new key, select where to save it and generate it
        keyFileName = Path(input("Provide a path and filename for where the key should be saved: "))
        
        morekeys = 0
        # in encryption mode first load the source file to be encrypted
        with sourceFileName.open(mode='rb') as f:
            sourceFile = f.read()
        
        # create a key with length equal to source file length
        if len(sourceFile) <= 1024:
            seedKey = secrets.token_bytes(len(sourceFile))
            key = seedKey
        else: #if the sourcefile is longer than 1024 bytes
            seedKey = secrets.token_bytes(1024)
            key = extend_key(seedKey, len(sourceFile))
        
        #  write the seed key to file
        with keyFileName.open(mode='wb') as f:
            f.write(seedKey)

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
        
        # if the file is larger than 1024 bytes, extend the key
        if len(sourceFile) > 1024:
            key = extend_key(key, len(sourceFile))

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


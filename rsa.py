#!/usr/bin/env python3

import random
import sys
from pathlib import Path
from binascii import hexlify

##### PRIME NUMBER GENERATION FUNCTIONS

# Bendersky, E. (2022, 1 August). Efficient modular exponentiation algorithms. 
# https://eli.thegreenplace.net/2009/03/28/efficient-modular-exponentiation-algorithms 
def expo(a, b, c):
    '''This function manually replaces the Python built-in pow() function. It calculates and returns a^b (mod c) using the
    square and multiply method. This function requires a value for c, it will not work without a modulus.'''
    # start result at 1
    result = 1
    # take the initial value modulo c
    a %= c
    # loop through each of the bits in the binary representation of b. We do this by doing an integer divide '//' which
    # effectively gives us a right-shift. If we start at the least significant bit (right side) and continually right shift, we
    # loop through each bit in the number b, as per the multiply and square algorithm
    while b > 0:
        # if the bit is a 1 (ie b%2 = 1) then we multiply and take the modulus c
        if b % 2 == 1:
            result = (result * a) % c
        # and then regardless of whether its a 1 or 0, we always square (and then mod c)
        a = (a * a) % c
        # we then integer divide b by 2 to right-shift the bits and begin the loop again with the next bit
        b //= 2

    return result

# Chia, T. (2013, 28 June). Python implementation of the Miller-Rabin Primality Test. https://gist.github.com/Ayrx/5884790 
def miller_rabin(n, k=5):
    '''This function tests whether a number is likely prime or not using the Miller-Rabin test. Arguments are the number to be tested
    and number of rounds. Default is set to 5.'''
    # function taken from https://gist.github.com/Ayrx/5884790 with slight adaptations for python3.
    # handle simple cases first
    if n == 2 or n == 3 or n == 5 or n == 7:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    
    # decompose n-1 into the product of an odd number d and a power of 2 by increasing s until d is odd
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    # perform k tests 
    for i in range(k):
        # choose a random witness to test
        a = random.randrange(2, n - 1)
        x = expo(a, d, n)
        # if x is one or n-1 the test is inconclusive and we need to skip to the next witness
        if x == 1 or x == n - 1:
            continue
        # otherwise continually square x up to s-1 times, and test whether it is = n - 1. If a match is found the test is 
        # not conclusive and we continue.
        for _ in range(s - 1):
            x = expo(x, 2, n)
            if x == n - 1:
                break
        else:
            # if a round ends without finding an x = n - 1, it indicates the number is composite.
            return False
    # if all of the rounds are inconclusive, then it is likely the number is prime.
    return True

def generate_prime(bits=512):
    '''This function returns a number that is likely prime based on Miller-Rabin test defined in miller_rabin(). Input is bit length of output prime.
    Default is 512 bits.'''
    while True:
        # Ensure the prime number candidate is an odd number (otherwise it can't be prime) by setting the Least Significant Bit (LSB) to 1. Also set the 
        # Most Significant Bit (MSB) to 1 using OR with 1 and the << shift operation to ensure the generated number is big enough.
        possiblePrime = random.getrandbits(bits - 1) | (1 << (bits - 1)) | 1  
        if miller_rabin(possiblePrime):
            return possiblePrime


##### RSA KEY GENERATION FUNCTIONS

def generate_pqn(length):
    '''This function generates the p, q and n for an RSA key (n) of the bit-length provided in the argument.'''
    key = 0
    while key.bit_length() != length:
        # Sometimes the primes generated for p and q will be small and result in an n value 1 bit shorter than intended, so need
        # this loop to retry if this happens, until the length of n is correct.
        primes = []
        for i in range(2):
            primes.append(generate_prime(length//2))
        key = primes[0] * primes[1]

    return primes[0], primes[1], key

def gcd(a, b):
    '''Compute the greatest common divisor of a and b using the Euclidean algorithm.'''
    # loop until b is zero
    while b != 0:
        # each iteration substitute (a, b) for (a % b, b) then switch their places so the larger number is on the left
        a, b = b, a % b
    return a

def find_coprime(phi):
    '''Find a small coprime number e for the given phi. Use e = 65537 as the default'''
    # start with industry standard default e
    e = 65537
    # if its not coprime with phi, loop through other options until it is
    while gcd(e, phi) != 1:
        e -= 2
    return e

# Wikibooks. (2021, 12 February). Algorithm Implementation/Mathematics/Extended Euclidean algorithm. 
# https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
def extended_gcd(a, b):
    '''Return the GCD, x, and y for the equation ax + by = gcd(a, b) using the Extended Euclidean Algorithm.'''
    # this is the end point of the recursive formula. When b becomes 0, gcd is a and x, y, are 1, 0. This should be returned up the chain
    if b == 0:
        return a, 1, 0
    else:
        # this is the recursive part, if b is not zero, we divide a by b, take the remainder as the new a, and then since it is smaller than b, switch a and b
        # then run the function again on the new a and b. This will continue until it hits an end point at b = 0, and which point this level of the function
        # returns a, 1, 0 while the other levels return gcd, y, x-(a//b)*y
        gcd, x, y = extended_gcd(b, a % b)
        return gcd, y, x - (a // b) * y

def find_modular_inverse(e, phi):
    '''Find the modular inverse d of e with respect to phi using the Extended Euclidean Algorithm.'''
    # use the extended_gcd() function to find x
    gcd, x, y = extended_gcd(e, phi)
    if gcd != 1:
        # in this case no mod inverse exists
        raise ValueError("No modular inverse exists for the provided values.")
    else:
        return x % phi

def generate_key(size):
    '''This function generates an RSA keypair of size bits. It will return values in this format: [n, e, d]'''
    # generate p q and n using the prime number functions
    p, q, n = generate_pqn(size)
    # calculate phi, e, and d
    phi = (p - 1) * (q - 1)
    e = find_coprime(phi)
    d = find_modular_inverse(e, phi)
    return [n, e, d]

#### HASHING FUNCTIONS AND CONSTANTS

# specify the s-box lookup table as a dictionary (this is the exact AES s-box)
# Daemen, J., & Rijmen, V. (1999). AES proposal: rijndael. 
# https://www.researchgate.net/publication/2237728_AES_proposal_rijndael 
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
# specify the seed value for the hash function. This was randomly generated with Python secrets module.
hashSeedHex = "65B148EE48CE7431"
hashSeed = bytes.fromhex(hashSeedHex)

def permute(data):
    '''This function rearranges the bytes in an 8-byte array according to the set permutation table.'''
    return bytearray([data[i-1] for i in perm])

def sbox_sub(data):
     '''This function substitutes all bytes in the data bytearray with their matching entry in the s-box'''
     return bytearray([sbox[int(i)] for i in data])

def pad(data):
    '''This function will pad the input data with empty bytes until it is evenly divisible by 8, then return the data.'''
    # calculate padding length
    paddingLen = 8 - (len(data) % 8) if len(data) % 8 != 0 else 0
    # add padding to the data
    return data + bytes([0] * paddingLen)

def hash_block(seed, input):
     '''This function takes two 8-byte inputs and runs 9 rounds of the hash algorithm on them, returning a single 8-byte output.
     In each round the seed is permutated, substituted, and then XOR'd with the input block. The transformed seed is then returned.'''
     for i in range(9):
        # permute then substitute the left side
        seed = sbox_sub(permute(seed))
        # XOR the leftside with the right side
        seed = [leftByte ^ rightByte for leftByte, rightByte in zip(seed, input)]
     return seed

def hash(inputFile):
    '''This function will hash the input file and return a 8-byte output. The input file must be a multiple of 8 bytes.
     Use the pad function to pad the input file before passing it to this function.'''
    # load the data
    with Path(inputFile).open('rb') as f:
        data = f.read()
    
    # pad the data
    inputData = pad(data)
    # set the initial hash to the seed
    currentHash = hashSeed
    # run each block of input data through the hash algorithm, transforming the seed each time
    for i in range(0, len(inputData), 8):
        block = inputData[i:i+8]
        currentHash = hash_block(currentHash, block)
    # return the final hash value
    return bytes(currentHash)

#### MAIN PROGRAM FUNCTIONS

## HELPER FUNCTIONS

def load_key(fileName):
    '''This function loads either a public or private key and returns the key as a tuple in the format (n, d/e)'''
    keyPath = Path(fileName)
    with keyPath.open('r') as keyFile:
        # assign the first value to n
        n = int(keyFile.readline().strip(), 16)
        # assign the second value to d or e depending on key type
        key_component = int(keyFile.readline().strip(), 16)
    return (n, key_component)

## MENU ITEMS

def create_key():
    '''This function takes a file name and creates a 1024-bit  RSA keypair. The keys are stored in hex as text files with two lines. 
    Line one is n, line two is d or e depending if its the private or public key.'''
    keyName = input("Please provide the file name (including path if desired) for the key. Do NOT include a file extension:\n")
    privKeyName = keyName + "_private.txt"
    pubKeyName = keyName + "_public.txt"
    key = generate_key(1024)
    privKey = (key[0], key[2])
    pubKey = (key[0], key[1])

    # save the private key to a file
    privKeyPath = Path(privKeyName)
    with privKeyPath.open('w') as privKeyFile:
        privKeyFile.write(f"{privKey[0]:x}\n")
        privKeyFile.write(f"{privKey[1]:x}\n")
    print("Saved private key:", privKeyName)

    # save the public key to a file
    pubKeyPath = Path(pubKeyName)
    with pubKeyPath.open('w') as pubKeyFile:
        pubKeyFile.write(f"{pubKey[0]:x}\n")
        pubKeyFile.write(f"{pubKey[1]:x}\n")
    print("Saved public key:", pubKeyName)

    # take some input to hold the terminal open so the result can be seen
    print("Operation complete.")
    x = input("\nPress Enter to continue.")

def encrypt():
    '''This function loads a public key and a file, encrypts the file via RSA with the public key, and then saves the output file in binary format.
    Multiple blocks of encryption are not supported so file size must be smaller than 1024 bits.'''
    keyPath = input("Please provide the filename (including path if necessary) of the public key you would like to encrypt with:\n")
    inputFileName = input("Please provide the filename (including path if necessary) of the input file you would like to encrypt:\n")
    outputFileName = input("Please provide the filename (including path if necessary) of the output file you would like to save:\n")

    n, e = load_key(keyPath)

    with Path(inputFileName).open('rb') as f:
        fileData = f.read()

    # check if the input file is smaller than n
    if len(fileData) * 8 < n.bit_length():
        # encrypt the data as a single block using RSA algorithm. First convert it to an integer
        intData = int.from_bytes(fileData, 'big')
        # then raise it to power e mod n as per the RSA algorithm
        encryptedData = expo(intData, e, n)

        # save the encrypted data to a new binary file
        with Path(outputFileName).open('wb') as f:
            # convert the resulting integer back to bytes before saving. 
            encryptedBytes = encryptedData.to_bytes((encryptedData.bit_length() + 7) // 8, 'big')
            f.write(encryptedBytes)

    else:
        print("Error: The input file is too large to be encrypted. Maximum 1023 bits.")

    # take some input to hold the terminal open so the result can be seen
    print("Operation complete.")
    x = input("\nPress Enter to continue.")

def decrypt():
    '''This function loads an encrypted binary file and a private key, then decrypts the data and saves the output to a file. User must
    specify the correct file extension when naming their file.'''
    keyPath = input("Please provide the filename (including path if necessary) of the private key you would like to decrypt with:\n")
    inputFileName = input("Please provide the filename (including path if necessary) of the input file you would like to decrypt:\n")
    outputFileName = input("Please provide the filename (including path if necessary) of the output file you would like to save (include correct file extension):\n")

    # set n and d from the private key
    n, d = load_key(keyPath)

    # load the data
    with Path(inputFileName).open('rb') as f:
        encryptedData = f.read()

    # first convert the data to an integer
    intEncryptedData = int.from_bytes(encryptedData, 'big')
    # then decrypt the data using the RSA algorithm
    decryptedData = expo(intEncryptedData, d, n)

    # save the decrypted data to a new file in binary format
    with Path(outputFileName).open('wb') as f:
        decryptedBytes = decryptedData.to_bytes((decryptedData.bit_length() + 7) // 8, 'big')
        f.write(decryptedBytes)

    # take some input to hold the terminal open so the result can be seen
    print("Operation complete.")
    x = input("\nPress Enter to continue.")

def sign():
    '''This function creates a digest (hash) of the input file and then encrypts it with the input key (which should be a private key, 
    however this is not enforced). It then saves the digital signature to the output file.'''
    # ask the user for the input/output paths
    keyPath = input("Please provide the filename (including path if necessary) of the private key you would like to sign with:\n")
    inputFileName = input("Please provide the filename (including path if necessary) of the input file you would like to sign:\n")
    outputFileName = input("Please provide the filename (including path if necessary) of the output file for the signature (include correct file extension):\n")

    # load the private key
    n, d = load_key(keyPath)

    # create the hash and convert it to an integer
    digest = int.from_bytes(hash(inputFileName), 'big')
    # encrypt the digest with the private key to form the signature
    signature = expo(digest, d, n)

    # save the signature (encrypted digest) to the output file
    with Path(outputFileName).open('wb') as f:
        signatureBytes = signature.to_bytes((signature.bit_length() + 7) // 8, 'big')
        f.write(signatureBytes)

    # take some input to hold the terminal open so the result can be seen
    print("Operation complete.")
    x = input("\nPress Enter to continue.")

def verify():
    '''This function loads an input data file, an input signature file, and a key (this should be a public key but this is not enforced).
    It then verifies if the signature is a valid signature created with the matching key, for the input data file.'''
    keyPath = input("Please provide the filename (including path if necessary) of the public key you would like to verify the signature with:\n")
    sigPath = input("Please provide the filename (including path if necessary) of the signature file you would like to verify:\n")
    inputFileName = input("Please provide the filename (including path if necessary) of the input file you would like to compare to the signature:\n")

    # create the digest (hash) of the input data (as an integer)
    fileDigest = int.from_bytes(hash(inputFileName), 'big')

    # load the signature data
    with Path(sigPath).open('rb') as f:
        sigData = f.read()

    # load public key
    n, e = load_key(keyPath)

    # decrypt the signature to retrieve the digest
    # first convert the data to an integer
    intSigData = int.from_bytes(sigData, 'big')
    # then decrypt the data using the RSA algorithm
    sigDigest = expo(intSigData, e, n)

    if fileDigest == sigDigest:
        print("Digests match. Signature verified successfully.")
    else:
        print("Digests do not match. Signature INVALID.")

    # take some input to hold the terminal open so the result can be seen

    x = input("\nPress Enter to continue.")

def create_hash():
    '''This function creates a 64-bit hash of the input file, and displays it in the terminal in hex.'''
    inputFileName = input("Please provide the filename (including path if necessary) of the input file you would like to create a digest for:\n")
    print("Operation complete. Hash: ", hexlify(hash(inputFileName)))

    # take some input to hold the terminal open so the result can be seen

    x = input("\nPress Enter to continue.")

def exit():
    sys.exit()

#### MAIN PROGRAM 

functions = {
        'C': create_key,
        'E': encrypt,
        'D': decrypt,
        'S': sign,
        'V': verify,
        'H': create_hash,
        'X': exit}

while True:
    # user selects the mode
    mode = input('''What would you like to do:
    [C]reate a new key
    [E]ncrypt with public key
    [D]ecrpt with private key
    [S]ign a message with a private key
    [V]erify a signature with a public key
    [H]ash a file to create a digest
    e[X]it program
    Selection:  ''').upper()
    
    # select the correct function to run. Run it if it exists, otherwise print error and repeat
    function = functions.get(mode)
    if function:
        function()
    else:
        print("Invalid option, please try again.")
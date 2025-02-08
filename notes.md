
# Ch5 Cryptography Notes
- Modern cryptographic algorithms depend on 1 way problems.
- For eg., its easy to create an alg that returns product of 2 large primes. But getting the prime factors of a large number is way difficult.

## Keyword Ciphers and One Time Pads
- Keyword ciphers are substitution ciphers. These are vulnerable to freq analysis.
- To fix this, One-Time Pad was invented.
- One Time pad or Vernam Cipher ???

## Private Key / Symmetric Key Cryptography
- Single key for enc and decr
- weakness - single key needs to be shared to everyone
### Block and Stream Ciphers
- Block ciphers - encrypt a block(typically 64) of bits at a time. THese are what majority of algs are. More resource intensive and complex to implement.
- Block mode defines specific processes and operations used by the cipher.
- Block ciphers work better with messages whose size is pre-known.
- Stream ciphers - encrypt one bit at a time. better for data of unknown size

### Symmetric Key Algorithms
- DES, 3DES, AES
- DES - 56 bit key, block cipher, length of the key determines strength of the alg. Range of possible keys = 2^56
- Differences bw AES and 3DES
- 3DES is 3 rounds DES, AES is a whole new alg
- AES uses longer and stronger keys, and longer block length
- 3DES is slower than AES

## Asymmetric Crytography
- public key for encryption and private key for decryption
- currently no methos exists to discover the private key using the public key
- No key sharing
### Asymmetric Key Algs
- RSA
- Elliptic Curve Cryptography
- Advantages of ECC
- short keys with high strength
- easy impl on hardware with less processing and memory.
- eg. SHA2, Elliptic Curve Digital Signature Alg

### Hash Functions
- keyless cryptography
- similar messages produce very different hashes


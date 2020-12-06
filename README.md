# Kiribi-Crypto
Kiribi EC Crypto Module

### Introduction
EC Crypto classes and interfaces based on
the ***safe*** elliptic curve 25519.

### Features
* EC Crypto classes and interfaces based on
the ***safe*** elliptic curve 25519.
* [Encodable](https://github.com/Igram-doo/Kiribi-IO) Digital Signatures.
* Key Exchange.
* [Encodable](https://github.com/Igram-doo/Kiribi-IO) SignedObjects.

### Overview
EC Crypto classes and interfaces based on
the ***safe*** elliptic curve 25519.

##### Keys
Public and private keys associated with elliptic curve 25519.

##### Key Exchange
Key exchange is the mechanism to securely exchange public keys and generate a shared secret key. The shared secret key utilized by this module is a 128 bit AES key. Once the key exchange is complete, data can be securely transfered between endpoints.

##### Signatures
Signatures are crypto-graphic quantities which can be used to authenticate data. The``Signature``class provided by this module is functionally equivalent to the standard java``Signature``class.

##### Signed Data
Signed data are crypto-graphic quantities which encapsulate data and a signature. The``SignedData``class provided by this module is functionally equivalent to the standard java``SignedData``class.

##### Key Store
Wrapper for a KeyStore.

### Code Example

	KeyPair pair = KeyGenerator.generateKeyPair();

### Module Dependencies
##### Requires
* java.base
* rs.igram.kiribi.io

##### Exports
* rs.igram.kiribi.crypto

### To Do
* Determine minimum supported Java version.
* More KeyStore unit tests.


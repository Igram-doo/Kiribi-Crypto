# Kiribi-Crypto
Kiribi EC Crypto Module

### Introduction
EC Crypto classes and interfaces based on
the ***safe*** elliptic curve 25519.

### Features
* EC Crypto classes and interfaces based on
the ***safe*** elliptic curve 25519.
* Encodable Digital Signatures.
* Key Exchange.
* Encodable SignedObjects.

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

### Code Example

	KeyPair pair = KeyGenerator.generateKeyPair();

### Module Dependencies
##### Requires
* java.base
* rs.igram.kiribi.io

##### Exports
* rs.igram.kiribi.crypto

### Requirements
To do

### To Do
* Determine minimum supported Java version.
* Standard encodings for public and private keys.
* Standard KeySpec classes for public and private keys.
* Standard KeyFactory.
* Standard KeyGenerator.
* Standard Signature.
* Security Provider.
* Self-signed Certiciate generation.
* Keystore support.

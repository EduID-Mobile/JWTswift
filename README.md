# JWTswift
[![Carthage compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/Carthage/Carthage)

A basic swift implementation of JSON Object Signing and Encryption(JOSE) for iOS-Devices to communicate with the server or another end points. This library implements only the basic requirement, algorithms, format in [JWS](https://tools.ietf.org/html/rfc7515), [JWK](https://tools.ietf.org/html/rfc7517), [JWA](https://tools.ietf.org/html/rfc7518).

This library fully uses the native iOS security framework and common crypto (**iOS 10** required).

- [Installing](#installing)
- [Functions](#functions)
- [Structure](#structure)
- [Basics](#basics)
- [Usage](#usage)
  - [Key](#key)
  - [KeyStore](#keystore)
  - [KeyChain](#keychain)
  - [JWS](#jws)

## Installing ##

To install this library [carthage](https://github.com/Carthage/Carthage) would be required : 
If help is needed, tutorial of using carthage could be find [here](https://www.raywenderlich.com/165660/carthage-tutorial-getting-started-2)

add this line to your Cartfile 
```shell
  github "BLC-HTWChur/JWTswift"
  ```
  
## Functions ##
These are the main functions of this libary: 

* Import a public key from a certificate (.der)
* Import a private key from a pem data (#PKCS1)
* Import public key from a jwks data
* Generate a [thumbprint](https://tools.ietf.org/html/rfc7638#section-3.1) for a key (kid) with hash function SHA256
* Saving, Loading, and Delete Key into / from the keychain
* Convert jwk data into a Key object, which is required for the saving function
* JWS basic functionalities : Sign, Verify, and Parsing the data(Payload, Header)

## Structure ##

![alt text](https://github.com/BLC-HTWChur/JWTswift/blob/master/JWTswift.png "JWTswift structure")
  
## Basics ##

After finish embedding the xcode project with the library, this library could be used easily with a normal import statement

```shell
   import JWTswift
   ```
   
## Usage ##

### Key ###
This is just a simple object class to help the user manage the key object in a project.
The key object contains a pair of key id and a SecKey variable

### KeyStore ###
The main purpose of this library is in this object class

This object is needed to be initialize for the first time :
```shell
//Generate an empty keystore
  var keystore  = KeyStore.init()

//Generate with key
  var keystore = KeyStore.init(withKey key: 'Key')
 
//Generate with collection of Keys, take an array of keys
  var keystore = KeyStore.init(withKeys keys: '[Key]')
```
  
**Adding key to the keystore**

This following function takes a key object as a parameter, and returns Boolean value.
False if the key doesn't have any kid, and true if successful.
 ```shell
    keystore.addKey('keyobject') 
 ```
 
 **Delete key**
 
 This following function deletes a specific key from a keystore class, and returns Boolean value.
 False if the no specific key found on the keystore.
 ```shell
    keystore.deleteKey('keyobject')
```
This following funtion delete all keys in keystore.
```shell
    keystore.deleteAll()
```
    
**Key retrieval**

To retrieve key from the keystore you need the kid as parameter.
This function returns a key object when successful and nil when there isn't any key found in the keystore.
Kid is a String format.
```shell
  keystore.getKey(withKid: "kid string")
``` 

**Import public key from certificate in app bundle**

This following function help the user to import and extract the public key from a *.Der* format certificate and put it into the keystore. Kid will be generated for the key as well.
As parameter a string path of the certificate is required
Method returns a kid String which could be used to retrieve the key from the keystore afterwards, and nil if there is any problem on importing process.

```shell
  keystore.getPublicKeyFromCertificateInBundle(resourcePath : 'string path to .der certificate')
```

**Import private key from .pem(#PKCS1) data in bundle**

Importing the RSA private key from RSA256 from a .pem format data, this pem data should be in #PKCS1 structure.
A string path is required as parameter and also an identifier to retrieve the key, since no kid generated on the importing process of private key.
Method returnst the identifier back which could be used to retrieve the key from the keystore afterwards, and nil if there is any problem on importing process.

```shell
  keystore.getPrivateKeyFromPemInBundle(resourcePath: 'string path to pem data', identifier: 'string to identify')
```

**Retrieving key id from jwks data in bundle**

This function retrieving the keyid from the jwks data in the bundle, this only works when there is only one key on the jwks since the method only look for the first key inside the jwks.
As parameter a string path to the jwks data is required, and the method will return a kid string as result or nil if there isn't any kid found.

```shell
  keystore.getPrivateKeyIDFromJWKSinBundle(resourcePath: 'string path to jwks')
```

**Convert jwks to key collection**

There are two methods for this function, the first one is to deal with jwks, which the iOS device get from the server, and the other one to extract the public key from the bundle. Kid will be generated if there isn't any found inside the jwk.

```shell
  //convert jwks from server, take data as parameter
  keystore.jwksToKeyFromServer(jwksSourceData: 'jwks in data format')
  
  //convert jwks from bundle, take path as parameter
  keystore.jwksToKeyFromBundle(jwksPath: 'string path to jwks')
```

**Convert jwk to Key**

Method that enables the user to convert a single jwk dictionary object into a key object.
This is only work for rsa public key.
Method returns a key object if successful, and nil if there is any error occurred

```shell
  keystore.jwkToKey(jwkDict: 'jwk dictionary [String: Any]')
```

**Convert pem to jwk**

A class function to convert a *#PKCS1* public key data into a jwk in dictionary format [String : Any]
Function takes a Data of pem key and an optional string kid, when there is no kid added as parameter, the function will generate kid automatically with the help of hash SHA256 method.

```shell
  KeyStore.pemToJWK(pemData: 'data of the public key pem', kid? = 'string kid')
```

**Convert Key to JWK**

A *class* function to convert Key object into a jwk in dictionary format [String : Any].
It takes Key as parameter.
Return nil if there is any error occured.

```shell
  KeyStore.keyToJwk(key: 'key object')
```

**Generate KID**

These *class* methods are used to generate a kid string for a public key.

```shell
  //the first one take key object as parameter and return key object as well as result with kid inside
  KeyStore.createKIDfromKey(Key: 'key object as parameter)
  
  //this following method takes a jwk in dictionary format [String: Any], return a kid string in return
  // NOTICE: kid string is not added inside the jwk dictionary!
  KeyStore.createKIDfromJWK(jwksDict: 'jwk in dictionary format)
```

**Generate KeyPair**

An extra *class* method which generate a key pair objects with kid included inside.
Key type is required as parameter, but for now only RSA(kSecAtttrKeyType) is upported.
As result this method returns a dictionary [String : Key] with two specific keys 
      1. "public" -> dictionary keys to retrieve the generated public Key object
      2. "private" -> dictionary keys to retrieve the generated private Key object
  
```shell
  KeyStore.generateKeyPair(keyType: 'kSecAttrKeyTypeRSA as String')
```

### KeyChain ###

A specific wrapper class to help the user to save, load, and delete Key / KeyPair in the keychain.
No initialization is needed for this class

**Save**

Functions to save Key/ keypair into the keychain a tag string is needed as a parameter.
Tag string is a string that you need to retrieve the key later from the keychain, there is no specific rules or format for this tag.
Methods return boolean as result, true when successful, otherwise false.
Saving a keypair separately is NOT possible in this keychain.
(Ex. if you want to save private key after saved its public key before, you need to delete the public key first and save both as a keypair)
```shell
  //save key pair
  KeyChain.saveKeyPair(tagString: 'any string tag', keyPair : 'Key pair in dictionary format with keys "public", and "private" ')
  
  //save single Key
  KeyChain.saveKey(tagString: 'any string tag', keyToSave: 'Key object')
```

**Load**

Functions to load key/ key pair from the keychain.
As a parameter the tag string is required, make sure the tag string is the same as the one is used on the saving process.
Methods return a key object or key pair in dictionary  as result, or nil if no specific key found

```shell
  //this would return a key pair in dictionary [String : Key] format (keys : "public" and "private") or nil if any error occurrs
  KeyChain.loadKeyPair(tagString: 'string tag')
  
  //This would return a single key object as result or nil if any error occurs
  KeyChain.loadKey(tagString: 'string tag')
```

**Delete**
Functions to delete a specific key or keypair inside the keychain
Return Boolean value as result, true if the deletion is successful and false when not

```shell
  //deleting a key pair
  KeyChain.deleteKeyPair(tagString: 'string tag of the keypair', keyPair: 'Keypair dictionary, user want to delete')
  
  //deleting a single key
  KeyChain.deleteKey(tagString: 'string tag of the key', keyToDelete: 'key object')
```

### JWS ###

**Initialization**
```shell
  //could do an empty initialization
  var jws = JWS.init()
  
  //recommended is init with payload dictionary
  var jws  = JWS.init(payloadDict: 'dictionary contains payload data in [String : Any] format')
```

**Sign**

Takes a key as parameter, to sign the data, and algoritm (JWSAlgorithm).
Currently only *JWSAlgorithm.RS256* algorithm is supported.
Function returns a complete string of Base64URL encoded JWS with 2 dots as separator ( header.payload.signature )

```shell
  //jws should has payload data inside it, before this function is called
  jws.Sign(key: 'Key object used to sign', alg: 'JWSAlgorithm.RS256')
```

**Verify**

Verify function is a *static* function to verify the authenticity of the jws, if the jws really sent by the desired sender.
```shell
  JWS.verify(jwsToverify: 'a based64URL encoded jws string', key: 'Key object to verify')
```

**Parse header and payload**

Static functions, which return Dictionary format[String : Any] of the header and payload.
This functions takes a whole JWS encoded string as parameter.
```shell
  JWS.parseJWSheader(stringJWS : 'JWS string')
  
  JWS.parseJWSpayload(stringJWS : 'JWS string')
```

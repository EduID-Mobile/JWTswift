# JWTswift
[![Carthage compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/Carthage/Carthage)

A basic swift implementation of JSON Object Signing and Encryption(JOSE) for iOS-Devices to communicate with the server or another end points. This library implements only the basic requirement, algorithms, format in [JWS](https://tools.ietf.org/html/rfc7515), [JWK](https://tools.ietf.org/html/rfc7517), [JWA](https://tools.ietf.org/html/rfc7518).

This library fully uses the native iOS security framework and common crypto (**iOS 10** required).

- [Installing](#installing)
- [Functions](#functions)
- [Basics](#basics)
- [Usage](#usage)
  - [Key](#key)
  - [KeyStore](#keystore)

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
  var keystore = KeyStore.init(withKey key: Key)
 
//Generate with collection of Keys, take an array of keys
  var keystore = KeyStore.init(withKeys keys: [Key])
```
  
Adding key to the keystore
 ```shell
    //This following function takes a key object as a parameter, and returns Boolean value
    //false if the key doesn't have any kid, and true if successful
    keystore.addKey(Key) 
 ```
 
 Delete key
 ```shell
    //This following function deletes a specific key from a keystore class, and returns Boolean value
    //false if the no specific key found on the keystore
    keystore.deleteKey(Key)
   
    //This following funtion delete all keys in keystore
    keystore.deleteAll()
```
    
Key retrieval
```shell
  //To retrieve key from the keystore you need the kid as parameter
  //This function returns a key object when successful and nil when there isn't any key found in the keystore
  //kid is a String format
  keystore.getKey(withKid: kid)
```  

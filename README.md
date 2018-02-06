# JWTswift
[![Carthage compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/Carthage/Carthage)

A basic swift implementation of JSON Object Signing and Encryption(JOSE) for iOS-Devices to communicate with the server or another end points. This library implements only the basic requirement, algorithms, format in JWS, JWK, JWA, this library fully uses the native iOS security framework and common crypto.

- [Installing](#installing)
- [Basics](#basics)

## Installing ##

To install this library [carthage](https://github.com/Carthage/Carthage) would be required : 
If help is needed, tutorial of using carthage could be find [here](https://www.raywenderlich.com/165660/carthage-tutorial-getting-started-2)

add this line to your Cartfile 
```shell
  github "BLC-HTWChur/JWTswift"
  ```
  
## Basics ##

After finish embedding the xcode project with the library, this library could be used easily with a normal import statement

```shell
   import JWTswift
   ```

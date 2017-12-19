//
//  JWTswiftTests.swift
//  JWTswiftTests
//
//  Created by Blended Learning Center on 19.12.17.
//  Copyright © 2017 Blended Learning Center. All rights reserved.
//

import XCTest
@testable import JWTswift

class JWTswiftTests: XCTestCase {
    let bundle = Bundle(identifier: "ch.htwchur.JWTswift")
    var pubPath : URL!
    var keyman : KeyManager!
    var dict : [String: String]!
    
    override func setUp() {
        super.setUp()
//        pubPath = Bundle.main.url(forResource: "eduid_pub", withExtension: "jwks") || NOT FOR FRAMEWORK
        
        pubPath = bundle?.url(forResource: "eduid_pub", withExtension: "jwks")
        keyman = KeyManager(resourcePath: pubPath.path)
//        print("public key path : \(pubPath.path)")
        dict = [
            "e"  : "AQAB",
            "kty" : "RSA",
            "n" : "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"]
        
    }
    
    override func tearDown() {
        pubPath = nil
        keyman = nil
        dict = nil
        super.tearDown()
    }
    
    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }
    
    
    
    func testTransformingJWKintoPEMandSavingIntoKeychain(){
        //JWK TO PEM PKCS#1 save to keychain, retrieve the pem from keychain and convert it back to JWK
        let keyStr = keyman.jwksToPem()
        let keyData = Data(base64Encoded: keyStr!)
        
        let options : [String : Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA as String,
                                        kSecAttrKeyClass as String: kSecAttrKeyClassPublic as String,
                                        kSecAttrKeySizeInBits as String : 2048,
                                        ]
        var error : Unmanaged<CFError>?
        let publickey = SecKeyCreateWithData(keyData! as CFData, options as CFDictionary, &error)
        XCTAssertNil(error , "ERROR while creating SecKey")
        let attributes = SecKeyCopyAttributes(publickey!) as NSDictionary!
        print(attributes!)
        
        XCTAssertTrue(SecKeyIsAlgorithmSupported(publickey!, SecKeyOperationType.encrypt, .rsaEncryptionPKCS1))
        print("KEYSTR : \(keyStr!)")
        let keyFromChain = SecKeyCopyExternalRepresentation(publickey!, &error) as Data!
        XCTAssertNotNil(keyFromChain)
        print("key : \(String(describing: keyFromChain?.base64EncodedString() ))")
        print("Key hex : \(String(describing: keyFromChain?.hexDescription)) ")
        
        let jwkDict = keyman.pemToJWK(pemData: keyFromChain!)
        print(jwkDict)
        XCTAssertTrue(jwkDict["n"] != nil && (jwkDict["e"] != nil) && jwkDict["kty"] != nil && jwkDict["kid"] != nil)
    }
    
    func testKeyGenerator(){
        //generate key pair create dictionary with public and private key in it
        let keydict = KeyManager.generateKeyPair(keyTag: "htwchur.keys", keyType: kSecAttrKeyTypeRSA as String)
        XCTAssertNotNil(keydict)
        XCTAssertEqual(keydict?.count, 2)
        
        let keyFromKeychain = KeyChain.loadKey(tagString: "htwchur.keys")
        XCTAssertNotNil(keyFromKeychain)
        XCTAssertNotNil(keydict!["private"]!)
        XCTAssertNotNil(keydict!["public"]!)
        let publicKeyCopy = SecKeyCopyPublicKey(keyFromKeychain!)
        XCTAssertEqual(keydict!["public"], publicKeyCopy)
        print(keyFromKeychain!)
        
        XCTAssertTrue(KeyChain.deleteKey(tagString: "htwchur.keys"))
    }
    
    func testKIDGenerator () {
        let kid  = KeyManager.createKID(jwkDict: dict)
        print("KID : " , kid!)
        XCTAssertNotNil(kid)
        
    }
    
    /*
     //kid is not saved to the key
     func testSaveKIDasAttribute(){
     
     let pubPath = Bundle.main.url(forResource: "eduid_pub", withExtension: "jwks")
     print("Public key Path : \(pubPath?.path ?? " ")")
     let keyman = KeyManager(resourcePath: (pubPath?.relativePath)!)
     let pem = keyman.jwkToPem(key: dict)
     XCTAssertNotNil(pem)
     let kid  = KeyManager.createKID(jwkDict: dict)
     
     let keyData = Data(base64Encoded: pem!)
     let options : [String : Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
     kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
     kSecAttrKeySizeInBits as String : 2048,
     kSecAttrApplicationLabel as String : kid! as CFString,
     kSecAttrLabel as String: kid! as CFString
     ]
     var error : Unmanaged<CFError>?
     let keyVar = SecKeyCreateWithData(keyData! as CFData, options as CFDictionary, &error)
     if(error != nil) {
     print(error.debugDescription)
     return
     }
     
     let  stat = KeyChain.saveKey(tagString: "testKey", key: keyVar!)
     XCTAssertEqual(stat, noErr) //SAVED
     let keyFromChain = KeyChain.loadKey(tagString: "testKey")
     XCTAssertNotNil(keyFromChain)
     let attr  = SecKeyCopyAttributes(keyFromChain!) as! [String : Any]
     print(attr)
     let label = attr[kSecAttrLabel as String] as? Data
     XCTAssertNotNil(label)
     XCTAssertEqual(kid, label?.base64EncodedString())
     print("data kid : \(kid)")
     
     }*/
    
    func testSaveKIDinKeychain(){
        
    }
    
    func testGetPublicAndPrivatefromBundle (){
        //get public key from DER data in bundle
        let urlPath = bundle?.url(forResource: "rsaCert", withExtension: "der") //Bundle.main.url(forResource: "rsaCert", withExtension: ".der")
        print("url path : " , urlPath?.absoluteString as Any)
        
        var keyMan = KeyManager.init(resourcePath: (urlPath?.relativePath)!)
        let publickey = keyMan.getPublicKeyFromBundle()
        XCTAssertNotNil(publickey)
        print(publickey.debugDescription)
        
        //encrypt data with public key
        let algorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA512
        print("SECkeyBlockSize : " , SecKeyGetBlockSize(publickey!))
        let plainText = "I AM LOCKED, PLEASE UNLOCK ME"
        let cipherText = CryptoManager.encryptData(key: publickey!, algorithm: algorithm, plainData: plainText.data(using: String.Encoding.utf8)! as NSData)
        XCTAssertNotNil(cipherText)
        
        print("CIPHER TEXT : " , cipherText?.base64EncodedString() ?? "error by encryption")
        
        //Get private key from pem data in bundle
        //keyMan = KeyManager(resourcePath: (Bundle.main.url(forResource: "ios_priv", withExtension: ".pem")?.relativePath)!) || Not for framework
        keyMan = KeyManager(resourcePath: (bundle?.path(forResource: "ios_priv", ofType: "pem"))!)
        let privateKey = keyMan.getPrivateKeyFromPEM()
        XCTAssertNotNil(privateKey)
        
        //Decrypt with private key
        XCTAssertTrue(SecKeyIsAlgorithmSupported(privateKey!, .decrypt, algorithm) )
        XCTAssertEqual(cipherText?.length, SecKeyGetBlockSize(privateKey!) )
        
        var error : Unmanaged<CFError>?
        let cleartext = SecKeyCreateDecryptedData(privateKey!, algorithm, cipherText! as CFData, &error) as Data?
        XCTAssertNil(error)
        XCTAssertNotNil(cleartext)
        XCTAssertEqual(plainText, String.init(data: cleartext!, encoding: String.Encoding.utf8))
    }
    
    func testSavingAndRetrievingKeyfromKeychain(){
        //get public key from DER data in bundle
        let urlPath = bundle?.url(forResource: "rsaCert", withExtension: "der") //Bundle.main.url(forResource: "rsaCert", withExtension: ".der") || NOT FOR FRAMEWORK
        
        do{
            let str = try String.init(contentsOf: urlPath!)
            print(str)
        } catch {
            print(error)
        }
        
        let keyMan = KeyManager.init(resourcePath: (urlPath?.relativePath)!)
        let publickey = keyMan.getPublicKeyFromBundle()
        XCTAssertNotNil(publickey)
        let status = KeyChain.saveKey(tagString: "eduid.publicKey", key: publickey!)
        XCTAssertEqual(status, noErr)
        print("ITEMNOT FOUND :",errSecItemNotFound)
        let keyFromKC = KeyChain.loadKey(tagString: "eduid.publicKey")
        XCTAssertNotNil(keyFromKC)
        XCTAssertEqual(publickey!, keyFromKC!)
    }
    
}

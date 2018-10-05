//
//  JWTswiftTests.swift
//  JWTswiftTests
//
//  Created by Blended Learning Center on 19.12.17.
//  Copyright © 2017 Blended Learning Center. All rights reserved.
//

import XCTest
import Security
@testable import JWTswift

class JWTswiftTests: XCTestCase {
    let bundle = Bundle(identifier: "ch.htwchur.JWTswift")
    var pubPath : URL!
    var keyman : KeyStore!
    var dict : [String: String]!
    var jwsHeaderDict : [String: Any]!
    var jwsPayloadDict : [String : Any]!
    var dataToHash : String!
    var testJWK : [String:Any]!
    var testCEK : [UInt8]!
    var testAAD : [UInt8]!
    
    
    override func setUp() {
        super.setUp()
        //        pubPath = Bundle.main.url(forResource: "eduid_pub", withExtension: "jwks") || NOT FOR FRAMEWORK
        
        //        pubPath = bundle?.url(forResource: "eduid_pub", withExtension: "jwks")
        keyman = KeyStore()
        //        print("public key path : \(pubPath.path)")
        dict = [
            "e"  : "AQAB",
            "kty" : "RSA",
            "n" : "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"]
        
        jwsHeaderDict = [
            "typ" : "JWT",
            "alg": "HS256"
        ]
        
        jwsPayloadDict = [
            "testdata" : "test1",
            "payloadTest" : "test2",
            "keyToSend" : ["e": "AQAB", "kid": "LolpQpI9lNNqFu-UmAZLQJ3zKOeECBN8YQ4TUf1X86Y", "kty": "RSA", "n": "xHQNRKCzDmkKlxrQHeAwtrpcao0z2s-gvaZAbTt9e18-1F-LMwyLQjDJ681YhSLHIZXaCAStE_KxRf5byBbDbgL5Yx1ngCxKibQ43gFFiWCH6JRsUL-PNEHZdhOPWnSTlzSbszFxYSucYX3PyKVoG-lI03UyZ_60xKabAgciQtEszoFJ53A3ZKh3ddblsSnPPeuj2oIGRY4CmphAuGXl_ff5Co1j2i5ztS3P2oM4XaRB925HIXv2A-SqnBxBK_MRuH93BqGfOs6AVh1mRf1zSNnNAe-Lmku_jkTEk-FKlzSjb4cNgXwEDsSIP3mBMuPZ6zSKFf3FpX1kVRd83ecNfw"]
        ]
        
        dataToHash = "NDk4YmIwN2EtMWZlNy00ZDk4LWEyMTctMDY4OTFkMzVlYmFmAySFHbjPcIT3RCdaMlAO"
        
        testJWK = [
            "kty":"RSA",
            "n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
            "e":"AQAB",
            "d":"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
            "p":"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM",
            "q":"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0",
            "dp":"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs",
            "dq":"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU",
            "qi":"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo"
        ]
        
        testCEK = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207]
        
        testAAD = [101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52,
                   83, 49, 99, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105, 74, 66,
                   77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73,
                   110, 48]
        
    }
    
    
    
    override func tearDown() {
        pubPath = nil
        keyman = nil
        dict = nil
        jwsHeaderDict = nil
        jwsPayloadDict = nil
        dataToHash = nil
        testJWK = nil
        testCEK = nil
        testAAD = nil
        super.tearDown()
    }
    
    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }
    
    
    
    func testTransformingJWKintoPEMandSavingIntoKeychain(){
        pubPath = bundle?.url(forResource: "eduid_pub", withExtension: "jwks")
        //JWK TO PEM PKCS#1 save to keychain, retrieve the pem from keychain and convert it back to JWK
        let keyStr = keyman.jwksToKeyFromBundle(jwksPath: pubPath.path)
        XCTAssertNotNil(keyStr)
        let keyObject = keyStr?.first
        var error : Unmanaged<CFError>?
        let keyData = SecKeyCopyExternalRepresentation((keyObject?.getKeyObject())!, &error)
        XCTAssertNil(error)
        let options : [String : Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA as String,
                                        kSecAttrKeyClass as String: kSecAttrKeyClassPublic as String,
                                        kSecAttrKeySizeInBits as String : 2048,
                                        ]
        let publickey = SecKeyCreateWithData(keyData! as CFData, options as CFDictionary, &error)
        XCTAssertNil(error , "ERROR while creating SecKey")
        let attributes = SecKeyCopyAttributes(publickey!) as NSDictionary?
        print(attributes!)
        
        XCTAssertTrue(SecKeyIsAlgorithmSupported(publickey!, SecKeyOperationType.encrypt, .rsaEncryptionPKCS1))
        print("KEYSTR : \(keyStr!)")
        let keyFromChain = SecKeyCopyExternalRepresentation(publickey!, &error) as Data?
        XCTAssertNotNil(keyFromChain)
        print("key : \(String(describing: keyFromChain?.base64EncodedString() ))")
        print("Key hex : \(String(describing: keyFromChain?.hexDescription)) ")
        
        let jwkDict = KeyStore.pemToJWK(pemData: keyFromChain!)
        print(jwkDict)
        XCTAssertTrue(jwkDict["n"] != nil && (jwkDict["e"] != nil) && jwkDict["kty"] != nil && jwkDict["kid"] != nil)
    }
    
    func testKeyGenerator(){
        //generate key pair create dictionary with public and private key in it
        let keydict = KeyStore.generateKeyPair(keyType: .RSAkeys)
        XCTAssertNotNil(keydict)
        XCTAssertEqual(keydict?.count, 2)
    }
    
    func testKeyPublic(){
        guard var url = bundle?.url(forResource: "ios_priv", withExtension: "jwks") else {
            XCTFail()
            return
        }
        let keyID = keyman.getPrivateKeyIDFromJWKSinBundle(resourcePath: (url.relativePath))
        
        url = (bundle?.url(forResource: "ios_priv", withExtension: "pem"))!
        guard let _ = keyman.getPrivateKeyFromPemInBundle(resourcePath: url.relativePath, identifier: keyID!) else {
            XCTFail()
            return
        }
        
        let keyPrivate = keyman.getKey(withKid: keyID!)
        XCTAssertNotNil(keyPrivate)
        
        let pubkey = KeyStore.getPublicKey(key: keyPrivate!)
        
        //encrypt data with public key
        let algorithm = SecKeyAlgorithm.rsaEncryptionPKCS1
        print("SECkeyBlockSize : " , SecKeyGetBlockSize(pubkey!.getKeyObject()))
        let plainText = "BLC test123"
        
        let cipherText = CryptoManager.encryptData(key: pubkey!, algorithm: algorithm, plainData: plainText.data(using: String.Encoding.utf8)! as NSData)
        XCTAssertNotNil(cipherText)
        
        //Decrypt with private key
        XCTAssertTrue(SecKeyIsAlgorithmSupported(keyPrivate!.getKeyObject(), .decrypt, algorithm) )
        XCTAssertEqual(cipherText?.length, SecKeyGetBlockSize(keyPrivate!.getKeyObject()) )
        
        let cleartext = CryptoManager.decryptData(key: keyPrivate!, algorithm: algorithm, cipherData: cipherText! as CFData)
        XCTAssertNotNil(cleartext)
        print("decrypted Result == \(String(data: cleartext! as Data, encoding: .utf8) ?? "")")
        XCTAssertEqual(plainText, String.init(data: cleartext! as Data, encoding: String.Encoding.utf8))
        
    }
    
    func testKIDGenerator () {
        let kid  = KeyStore.createKIDfromJWK(jwkDict: dict)
        print("KID : " , kid!)
        XCTAssertNotNil(kid)
    }
    
    
    //kid is not saved to the key
    func testSaveKIDandKey(){
        
        let pubPath = bundle?.url(forResource: "eduid_pub", withExtension: "jwks")
        print("Public key Path : \(pubPath?.path ?? " ")")
        
        let keysCollection = keyman.jwksToKeyFromBundle(jwksPath: (pubPath?.path)!)
        XCTAssertTrue(keysCollection?.count == 1)
        
        
        let statKid = KeyChain.saveKey(tagString: "testKey", keyToSave: (keysCollection?.first!)!)
        
        XCTAssertTrue(statKid)
        
        let keyFromChain = KeyChain.loadKey(tagString: "testKey")
        XCTAssertNotNil(keyFromChain)
        XCTAssertEqual(keysCollection?.first?.getKid(), keyFromChain?.getKid())
        
        //deleting the keys on the keychain
        XCTAssertTrue(KeyChain.deleteKey(tagString: "testKey", keyToDelete: (keysCollection?.first)!))
        
    }
    
    func testCreateAndSaveKeyPair() {
        
        
        let keypair = KeyStore.generateKeyPair(keyType: .RSAkeys)
        //        KeyChain.deleteKeyPair(tagString: "test", keyPair: keypair!)
        XCTAssertNotNil(keypair)
        XCTAssertTrue(keypair?.count == 2)
        
        let saved = KeyChain.saveKeyPair(tagString: "test", keyPair: keypair!)
        XCTAssertTrue(saved)
        
        let keyLoaded = KeyChain.loadKeyPair(tagString: "test")
        XCTAssertNotNil(keyLoaded)
        XCTAssertTrue(keyLoaded?.count == 2)
        
        XCTAssertEqual(keypair!["public"]?.getKid(), keyLoaded!["public"]?.getKid())
        XCTAssertEqual(keypair!["private"]?.getKid(), keyLoaded!["private"]?.getKid())
        
        let deleted = KeyChain.deleteKeyPair(tagString: "test", keyPair: keypair!)
        XCTAssertTrue(deleted)
    }
    
    func testRetrievingWithoutSaved(){
        let stat = KeyChain.loadKeyPair(tagString: "test")
        print(stat ?? "")
        XCTAssertNil(stat)
    }
    
    func testGetPublicAndPrivatefromBundle (){
        //get public key from DER data in bundle
        let urlPath = bundle?.url(forResource: "rsaCert", withExtension: "der") //Bundle.main.url(forResource: "rsaCert", withExtension: ".der")
        print("url path : " , urlPath?.absoluteString as Any)
        let publickeyId = keyman.getPublicKeyFromCertificateInBundle(resourcePath: (urlPath?.path)!)
        XCTAssertNotNil(publickeyId)
        print(publickeyId.debugDescription)
        let publicKey = keyman.getKey(withKid: publickeyId!)
        
        //encrypt data with public key
        let algorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA512
        print("SECkeyBlockSize : " , SecKeyGetBlockSize(publicKey!.getKeyObject()))
        let plainText = "I AM LOCKED, PLEASE UNLOCK ME"
        
        let cipherText = CryptoManager.encryptData(key: publicKey!, algorithm: algorithm, plainData: plainText.data(using: String.Encoding.utf8)! as NSData)
        XCTAssertNotNil(cipherText)
        
        print("CIPHER TEXT : " , cipherText?.base64EncodedString() ?? "error by encryption")
        
        //Get private key from pem data in bundle
        //keyMan = KeyManager(resourcePath: (Bundle.main.url(forResource: "ios_priv", withExtension: ".pem")?.relativePath)!) || Not for framework
        let privateKeyPath = bundle?.path(forResource: "ios_priv", ofType: "pem")
        let privateKeyId = keyman.getPrivateKeyFromPemInBundle(resourcePath: privateKeyPath!, identifier: "testPrivate")
        let privateKey = keyman.getKey(withKid: privateKeyId!)
        XCTAssertNotNil(privateKey)
        
        //Decrypt with private key
        XCTAssertTrue(SecKeyIsAlgorithmSupported(privateKey!.getKeyObject(), .decrypt, algorithm) )
        XCTAssertEqual(cipherText?.length, SecKeyGetBlockSize(privateKey!.getKeyObject()) )
        
        let cleartext = CryptoManager.decryptData(key: privateKey!, algorithm: algorithm, cipherData: cipherText! as CFData)
        XCTAssertNotNil(cleartext)
        XCTAssertEqual(plainText, String.init(data: cleartext! as Data, encoding: String.Encoding.utf8))
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
        
        
        let publickeyId = keyman.getPublicKeyFromCertificateInBundle(resourcePath: (urlPath?.path)!)
        XCTAssertNotNil(publickeyId)
        
        let publicKey = keyman.getKey(withKid: publickeyId!)
        XCTAssertNotNil(publicKey)
        
        let status = KeyChain.saveKey(tagString: "eduid.publicKey", keyToSave: publicKey!)
        XCTAssertEqual(status, true)
        print("ITEMNOT FOUND :",errSecItemNotFound)
        let keyFromKC = KeyChain.loadKey(tagString: "eduid.publicKey")
        XCTAssertNotNil(keyFromKC)
        XCTAssertEqual(publicKey!.getKeyObject(), keyFromKC!.getKeyObject())
        XCTAssertEqual(publicKey!.getKid(), keyFromKC!.getKid())
        
        XCTAssertTrue(KeyChain.deleteKey(tagString: "eduid.publicKey", keyToDelete: publicKey!))
    }
    
    func testJWS(){
        let keydict = KeyStore.generateKeyPair(keyType: .RSAkeys)
        XCTAssertNotNil(keydict)
        let jws = JWS(payloadDict: jwsPayloadDict)
        XCTAssertNotNil(jws.sign(key: keydict!["private"]!, alg: .RS256))
        
        XCTAssertTrue(jws.verifyWithDict(header: jws.headerDict, payload: jwsPayloadDict, signature: jws.signatureStr!, key: keydict!["public"]! )  )
        
        XCTAssertTrue(JWS.verify(jwsToVerify: jws.jwsCompactResult!, key: keydict!["public"]!))
    }
    
    func testJWSfromBundle() {
        // Get private key to Sign JWS
        guard let url = bundle?.url(forResource: "privateTest", withExtension: "jwks") else {
            XCTFail()
            return
        }
        let keyID = keyman.getPrivateKeyIDFromJWKSinBundle(resourcePath: url.path)
        
        guard let urlpem = bundle?.url(forResource: "privateTest", withExtension: "pem") else {
            XCTFail()
            return
        }
        let keyIDfrombundle = keyman.getPrivateKeyFromPemInBundle(resourcePath: urlpem.path, identifier: keyID!)
        
        guard let privKey = keyman.getKey(withKid: keyIDfrombundle!) else {
            XCTFail()
            return
        }
        
        let jws = JWS(payloadDict: jwsPayloadDict)
        
        let compactJWS = jws.sign(key: privKey, alg: .RS256)
        XCTAssertNotNil(compactJWS)
        
        print("Compact JWS == \(compactJWS!)")
    }
    
    func testJWSparse(){
        let keydict = KeyStore.generateKeyPair(keyType: .RSAkeys)
        XCTAssertNotNil(keydict)
        let jws = JWS(payloadDict: jwsPayloadDict)
        XCTAssertNotNil(jws.sign(key: keydict!["private"]!, alg: .RS256))
        
        print("jws : " , jws.jwsCompactResult!)
        
        let parsed = JWS.parseJWSpayload(stringJWS: jws.jwsCompactResult!)
        print("PARSED")
        print(parsed!)
        XCTAssertTrue(parsed?.count != 0)
        XCTAssertTrue((parsed!["testdata"] != nil) && (parsed!["payloadTest"] != nil) && (parsed!["keyToSend"] != nil))
        
    }
    
    func testGetKeyIDFromJWKSinBundle() {
        guard var url = bundle?.url(forResource: "ios_priv", withExtension: "jwks") else {
            XCTFail()
            return
        }
        let keyID = keyman.getPrivateKeyIDFromJWKSinBundle(resourcePath: (url.relativePath))
        XCTAssertNotNil(keyID)
        XCTAssertEqual(keyID, "tDVTKwRxlxhccA-yllPwjQdIBXpwbHq0GrYjt1FW8us" )
        
        url = (bundle?.url(forResource: "ios_priv", withExtension: "pem"))!
        let _ = keyman.getPrivateKeyFromPemInBundle(resourcePath: (url.relativePath), identifier: keyID!)
        let privkey = keyman.getKey(withKid: keyID!)
        XCTAssertNotNil(privkey)
        
    }
    
    func testHashfunction() {
        let data = dataToHash.data(using: .ascii)
        XCTAssertNotNil(data!)
        let result = data?.hashSHA256()
        print([UInt8](result!) )
        print(result?.base64EncodedString() as Any)
        XCTAssertEqual(result?.hexDescription, "d39d6be6abc67dee3dae59ba565038e0f2cf6e9b42d42db4f5c4939528cf9a96")
        
    }
    
    //    ---- JWE ----
    
    
    func testJWEHeader(){
        let jwe = JWE(alg: .RSA1_5, kid: "")
        print(jwe.joseHeaderDict!)
        do{
            let jsonheader = try JSONSerialization.data(withJSONObject: jwe.joseHeaderDict!, options: .init(rawValue: 0))
            print(jsonheader.base64EncodedString().base64ToBase64Url().clearPaddding())
        }catch {
            XCTFail()
        }
    }
    
    func testCreateJWE(){
        let keyDict : [String : String] = [
            "kty": "RSA",
            "e": "AQAB",
            "kid": "jujDAZAw2SuzObXophznE7ZqRI9JPwwobUOoYvTW1qs",
            "n": "hZoxEIoPL1RWO2aWv8JYKQBtBEOesP7m_uCUG_PHP1QGazEUTaKhixOb4dqdmLiQps5iDPWdKXUc9os2CMzmFmN9BQFModFV6bKhisPAGyGhKIjoqDklD69yFqkt0meFPyiq5V_h-5C-L-GToZJmT6qPcy3Qrj4UqP0eASLwHXyOBtS0pSD-fvWWRsFnd5dJK0cIQdLJb6thIXSou0S0ObA7pDQ6XXhSi1cJdmRixLFVTy5_Hn-U4Z4ArYmEbA4E2jRC9J_yYsuPmOFhv3JTfqwGG9GdKsj3k0icAoCaGO6dnZxDh_7J4bx0hQPmnwKk1MKlvr8OH1lZ2Z7l1Rl9FQ"
        ]
        guard let key = keyman.jwkToKey(jwkDict: keyDict) else {
            XCTFail()
            return
        }
        let jwe = try! JWE.init(plaintext: ["iat" : "in chur"], alg: .RSA1_5,publicKey: key, kid: key.getKid()!)
        XCTAssertNotNil(jwe.compactJWE)
        print("Compact JWE = ", jwe.compactJWE!)
    }
    
    func testGenerateAAD(){
        let protectedHeader = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0".addPadding().base64UrlToBase64()
        let data = Data.init(base64Encoded: protectedHeader)
        //        data?.base64EncodedData()
        
        //var byteArray = aadString?.asByteArray()
        print("bytes = \([UInt8](data!))")
    }
    
    func testJweGenerateCEK(){
        let jwe = JWE(alg: .RSA1_5, kid: "")
        let cekArray = jwe.generateCEK()
        print(cekArray!)
        XCTAssertNotNil(cekArray)
        XCTAssertEqual(cekArray?.count, 32)
    }
    
    func testEncryptCEK() {
        //encrypt CEK with public JWK from the recipient
        /*
         guard let key = keyman.jwkToKey(jwkDict: testJWK) else {
         XCTFail()
         return
         }*/
        guard let url = bundle?.url(forResource: "privateTest", withExtension: "jwks") else {
            XCTFail()
            return
        }
        let keyfrombundle = keyman.jwksToKeyFromBundle(jwksPath: url.path)
        
        let key = KeyStore.getPublicKey(key: (keyfrombundle?.first)!)
        
        let jwe = JWE(alg: .RSA_OAEP_256, kid: "")
        
        let cekTest = jwe.generateCEK()!
        print("CekTest == \(cekTest)")
        let cipherText = jwe.encryptCEK(encryptKey: key!, alg: .RSA1_5, cek: cekTest)
        print("str =" , cipherText!)
        XCTAssertNotNil(cipherText)
    }
    
    func testDecryptCEK() {
        
        guard let url = bundle?.url(forResource: "privateTest", withExtension: "jwks") else {
            XCTFail()
            return
        }
        let keyID = keyman.getPrivateKeyIDFromJWKSinBundle(resourcePath: url.path)
        
        
        guard let urlpem = bundle?.url(forResource: "privateTest", withExtension: "pem") else {
            XCTFail()
            return
        }
        let keyIDfrombundle = keyman.getPrivateKeyFromPemInBundle(resourcePath: urlpem.path, identifier: keyID!)
        
        let privkey = keyman.getKey(withKid: keyIDfrombundle!)
        //decrypt the following cek string
        
        let cekString = "U2yrenUB5Z2p40b1Imk-TBhl2kpFA83MPJx2oPLg1bFmlaP76o0nQmy4nwwmQyIj5KpunQaSedTXM9djsHtuaBkboKho8gt0Mug7Fc8Lu-9Xld3HhvM37Ulp_jkc_HwvAz46mg-TenZMgsTR4Ni9ORJohmskLzowBGQjZqeEWWEMTHbBEqyEqUa6R4b5lU7IXhoWong4fFFFVq9Y79NyX3vemWxQuqdJvOHCh_wgTUY-b_PJMMGDaBdsm0ZGdsL3KXjWBl4WVHs80udJ13zprqLOoVKcxAdh4lTCwpPkRw3ssdvNvl8WWvGZSLwgsNGLnbiPIu1iyA-Y8XAJjAn7Nw"
        
        let jwe = JWE(alg: .RSA_OAEP_256, kid: "")
        //let decrypted = jwe.decryptCEK(decryptKey: privKey!, alg: .RSA1_5, cipherText: cekString)
        let decryptedCek = jwe.decryptCEK(decryptKey: privkey!, alg: .RSA1_5, cipherText: cekString)
        print("DECRYPTED =  \(String(describing: decryptedCek))")
        
        XCTAssertNotNil(decryptedCek)
    }
    
    
    func testEncryptDecryptCEK(){
        guard let url = bundle?.url(forResource: "ios_priv", withExtension: "jwks") else {
            XCTFail()
            return
        }
        let keyID = keyman.getPrivateKeyIDFromJWKSinBundle(resourcePath: url.path)
        
        
        guard let urlpem = bundle?.url(forResource: "ios_priv", withExtension: "pem") else {
            XCTFail()
            return
        }
        let keyIDfrombundle = keyman.getPrivateKeyFromPemInBundle(resourcePath: urlpem.path, identifier: keyID!)
        
        XCTAssertNotNil(keyIDfrombundle)
        
        let privKey = keyman.getKey(withKid: keyIDfrombundle!)
        let publickey = KeyStore.getPublicKey(key: privKey!)
        
        let jwe = JWE(alg: .RSA1_5, kid: "")
        let cek = jwe.generateCEK()
        
        let encrypted = jwe.encryptCEK(encryptKey: publickey!, alg: .RSA1_5, cek: cek!)
        
        let decrypted = jwe.decryptCEK(decryptKey: privKey!, alg: .RSA1_5, cipherText: encrypted!)
        XCTAssertNotNil(decrypted)
        XCTAssertEqual(decrypted, cek!)
        
    }
    
    func testEncryptDecryptRSA1_5(){
        
        let keypair =  KeyStore.generateKeyPair(keyType: .RSAkeys)
        let plainText = "BLC was here!"
        let dataText = plainText.data(using: .utf8)!
        print("plain before encryption = \([UInt8](dataText))")
        
        let jwe = JWE(alg: .RSA1_5, kid: "")
        let cek = jwe.generateCEK()
        let cipherStr = jwe.encryptCEK(encryptKey: keypair!["public"]!, alg: .RSA1_5, cek: cek!)//[UInt8](dataText))
        print("CEK == \(cek!)")
        print("Cipher text = \(cipherStr ?? "error")")
        
        let plain = jwe.decryptCEK(decryptKey: keypair!["private"]!, alg: .RSA1_5, cipherText: cipherStr!)
        
        print("plain = \(plain ?? [])")
        print("plainText = \(String(describing: String.init(bytes: plain!, encoding: .utf8)))")
        XCTAssertEqual(plain!, cek )// [UInt8](dataText))
        
    }
    
    func testEncryptDecryptRSA_OAEP(){
        
        let keypair = KeyStore.generateKeyPair(keyType: .RSAkeys)
        let jwe = JWE(alg: .RSA_OAEP_256, kid: "")
        let cek = jwe.generateCEK()!
        
        print("Plain before encryption = \(cek)")
        
        let cipher = RSA_OAEP_256.encrypt(encryptKey: keypair!["public"]!, cek: cek)
        XCTAssertNotNil(cipher)
        
        let decrypted = RSA_OAEP_256.decrypt(decryptKey: keypair!["private"]!, cipherText: cipher!)
        print("Decrypted result == \([UInt8](decrypted!))")
        XCTAssertNotNil(decrypted)
        XCTAssertEqual([UInt8](decrypted!), cek)
    }
    
    func testJweGenerateInitVector(){
        let jwe = JWE(alg: .RSA1_5, kid: "")
        let str = jwe.generateInitVec()
        print("init vector = " , str!.count)
        XCTAssertNotNil(str)
    }
    
    func testSHA512(){
        let testString = "blcHTWchur"
        let dataTest = testString.data(using: .utf8)
        let hashdata  = dataTest?.hashSHA512()
        
        
        print("SHA512 result = ", hashdata!.hexDescription, "\n length = ", hashdata!.hexDescription.count)
        
        XCTAssertEqual(hashdata?.hexDescription.uppercased(), "CF37521606600314182DFE80E514393CE45950DC8010E83E639018DF7DD6DC1CD15A6254E334CAB30C1F15F4A7BB0FBE486D991C839818AA74A39DC88B153635")
    }
    
    func testEncryptAES() {
        
        let message = "Don't try to read this text. Top Secret Stuff"
        let messageData = message.data(using: .utf8)!
        let keyData = "12345678901234567890123456789012".data(using: .utf8)!
        let ivData = "abcdefghijklmnop".data(using: .utf8)!
        
        let encryptedData = AES.encryptAes(data: messageData, keyData: keyData, ivData: ivData)
        let decryptedData = AES.decryptAes(data: encryptedData, keyData: keyData, ivData: ivData)
        let decrypted = String(data: decryptedData, encoding: .utf8)!
        print("decrypted Text = " , decrypted)
        XCTAssertEqual(decrypted, message)
    }
    
    func testHmacSha256(){
        let testString = "987654"
        let test : [UInt8] = Array(testString.utf8)
        let dataTest = Data(bytes: test)
        //        let dataTest = testString.data(using: .utf8)
        
        let jwe = JWE(alg: .RSA_OAEP_256, kid: "")
        let key = jwe.generateCEK()!
//        let keyString = "0123"
//        let key : [UInt8] = Array(keyString.utf8)
        let keyData = Data(bytes: key)
        //        let keyData = keyString.data(using: .utf8)
        
        let hmacResult = HmacSha.compute(input: dataTest, key: keyData)
        //        let str  = String(data: hmacResult, encoding: .utf8)
        print("HmacResult = \(hmacResult.hexDescription)")
        
        
    }
    
    
    func testAES128CBC(){
        
        let jwe = JWE(alg: .RSA1_5, kid : "")
        let iV : [UInt8] = [3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101]
        //first extract CEK
        let middleIndex = (testCEK.count / 2)
        let macKey = testCEK[..<middleIndex]
        let encKey = testCEK[middleIndex...]
        print("MAC KEY = \(macKey)")
        print("ENC KEY = \(encKey)")
        
        let encKeyData = Data(bytes: encKey)
        
        let plaintext: [UInt8] = [76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32,
                                  112, 114, 111, 115, 112, 101, 114, 46]
        let dataInput = Data(bytes: plaintext)
        
        let cipher = AES.encryptAes(data: dataInput, keyData: encKeyData, ivData: Data(bytes: iV))
        print([UInt8](cipher))
        
        XCTAssertNotNil(cipher)
        XCTAssertEqual([UInt8](cipher), [40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6,75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143,112, 56, 102])
        
        let al = jwe.generateAL(bitsCount: 408)
        XCTAssertEqual(al, [0, 0, 0, 0, 0, 0, 1, 152])
        
        let hmacInput = (testAAD + iV + [UInt8](cipher) + al)
        XCTAssertEqual(hmacInput, [101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52,
                                   83, 49, 99, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105, 74, 66,
                                   77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73,
                                   110, 48, 3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111,
                                   116, 104, 101, 40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24,
                                   152, 230, 6, 75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215,
                                   104, 143, 112, 56, 102, 0, 0, 0, 0, 0, 0, 1, 152])
        
        let datahmac = Data.init(bytes: hmacInput)
        let macKeydata = Data.init(bytes: macKey)
        print("datahmac = \(datahmac)")
        let hashResult = [UInt8](HmacSha.compute(input: datahmac, key: macKeydata))
        
        
        print("hmac result = \(hashResult)")
        XCTAssertEqual((hashResult), [83, 73, 191, 98, 104, 205, 211, 128, 201, 189, 199, 133, 32, 38, 194, 85, 9, 84, 229, 201, 219, 135, 44, 252, 145, 102, 179, 140, 105, 86, 229, 116])
        
        //take 128 bits from the hash result, this will be used as an Authenticated Tag
        print("splitted = \(hashResult.prefix(upTo: 16))")
        
        let authenticatedTag = Data(bytes: hashResult.prefix(upTo: 16))
        // Authenticated Tag will be sent as base64URL and without padding
        print(authenticatedTag.base64EncodedString().base64ToBase64Url().clearPaddding())
    }
    
    func testCreateJWECompactRSA1_5(){
        guard let url = bundle?.url(forResource: "privateTest", withExtension: "jwks") else {
            XCTFail()
            return
        }
        let keys = keyman.jwksToKeyFromBundle(jwksPath: url.path)
        let pubKey = keys!.first
        XCTAssertNotNil(pubKey)
        
        let payload : [String:Any] = ["julius":"test payload",
                                    "htwchur": "blc"]
        let jwe : JWE
        do{
            jwe = try JWE(plaintext: payload, alg: .RSA1_5, publicKey: pubKey!, kid: pubKey!.getKid()!)
        } catch {
            print(error)
            XCTFail()
            return
        }
        
        let jweCompact = jwe.getCompactJWE()!
        print("Generated JWE Compact == \(jweCompact)")
        XCTAssertNotNil(jweCompact)
    }
    
    func testDecryptJweCompactRSA1_5(){
        guard let url = bundle?.url(forResource: "privateTest", withExtension: "jwks") else {
            XCTFail()
            return
        }
        let keyID = keyman.getPrivateKeyIDFromJWKSinBundle(resourcePath: url.path)
    
        guard let urlpem = bundle?.url(forResource: "privateTest", withExtension: "pem") else {
            XCTFail()
            return
        }
        let keyIDfrombundle = keyman.getPrivateKeyFromPemInBundle(resourcePath: urlpem.path, identifier: keyID!)
        
        guard let privKey = keyman.getKey(withKid: keyIDfrombundle!) else {
            XCTFail()
            return
        }
        
        let compactJwe = "eyJhbGciOiJSU0ExXzUiLCJraWQiOiJCTENodHdjaHVyIiwiY3R5IjoiSldUIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImlzcyI6IkpVTElVUyJ9.m-Rqiz12XFOe9zsmpx7ExP9slP8CC3fxifyH65cIPGOPQzKTX5cSzjeImcBH4e1t-p_70EzYd0p_prbE9Tz4Y2Dyzo7wC14YDSyM8Y1EG1Ml6yzD9EfYK0QsUs9IjBPIlOdtzAqGbP64BqwE3hRA6xAAcich9RwAxbfT7T9KKSLvP84-SwweCmgMETIH5LxZKFfLUvGsYnZKv_wggVUb2eJ1Z1p8iRUaP53W3WhRkuYriBwaxhrVSoUbX2f1EFpg5o93c8xqOpSYaz4n6XxffAZKDmC1FqrwMbkCrK96lVMukb-c6EKB-WGFRGav7TI-QyPBpr4mNHHKD_v91XUXLg.vzJN2uHHBJgNOdspA6kkow.B_HkHFTWU9DMV8R3ul-Og7gmTaIK2NS7dzaVGtDD5Lk1WnBfnKXzGxGU5PS8nhxe.iuGBG8esH53jhU9Nsxkqdw"
        do{
            let jwe = try JWE(compactJWE: compactJwe, privateKey: privKey)
            let header = jwe.getHeaderAsDict()
            let payload  = jwe.getPayloadAsDict()
            
            print("Header from decrypted == \(String(describing: header))")
            print("Payload from decrypted == \(String(describing: payload))")
            XCTAssertNotNil(payload)
            XCTAssertEqual(payload! as! [String:String], ["iss": "JULIUS", "iat": "Hello World"])
        } catch {
            print("Error while decrypting JWE :: \(error)")
            XCTFail()
        }
    }
    
    func testCreateJWECompactRSA_OAEP(){
        guard let url = bundle?.url(forResource: "privateTest", withExtension: "jwks") else {
            XCTFail()
            return
        }
        let keys = keyman.jwksToKeyFromBundle(jwksPath: url.path)
        let pubKey = keys!.first
        XCTAssertNotNil(pubKey)
        
        let payload : [String:Any] = ["julius":"test payload for RSA.OAEP",
                                      "htwchur": "blc"]
        let jwe : JWE
        do{
            jwe = try JWE(plaintext: payload, alg: .RSA_OAEP_256, publicKey: pubKey!, kid: pubKey!.getKid()!)
        } catch {
            print(error)
            XCTFail()
            return
        }
        
        let jweCompact = jwe.getCompactJWE()!
        print("Generated JWE Compact == \(jweCompact)")
        XCTAssertNotNil(jweCompact)
    }
    
    func testDecryptJweCompactRSA_OAEP(){
        guard let url = bundle?.url(forResource: "privateTest", withExtension: "jwks") else {
            XCTFail()
            return
        }
        let keyID = keyman.getPrivateKeyIDFromJWKSinBundle(resourcePath: url.path)
        
        guard let urlpem = bundle?.url(forResource: "privateTest", withExtension: "pem") else {
            XCTFail()
            return
        }
        let keyIDfrombundle = keyman.getPrivateKeyFromPemInBundle(resourcePath: urlpem.path, identifier: keyID!)
        
        guard let privKey = keyman.getKey(withKid: keyIDfrombundle!) else {
            XCTFail()
            return
        }
        
        let compactJwe = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJraWQiOiJCTENodHdjaHVyIiwiY3R5IjoiSldUIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImF1ZCI6InRoaXMgaXMgZW5jcnlwdGVkIHdpdGggUlNBLU9BRVAtMjU2LiIsImlzcyI6IkpVTElVUyJ9.YhQpI6K-XqjdPa9u_Dofb4HjBUthR75qtXbAb8D_1Qbi8lEDdDULl__hv5xrWQAvualZZNfHGyj-E3OOAV21tMJR3UNW5sfaPYOA3MFjn828A9HaxNcgJjBbPUJWu01hBpeweEINTRewZNuo0jcj49EhGees-Txx1TfsJVqO7pJm7RTne8Y_yyxwABuFS2DP5YyAxhScrpJATKdGiuWXBLhblNXcs3XrxlLKw_fPROM3-9nxLhto8onWojqcAADqVgB16ZBNx_Nz6Ti0cZNbIsXqHeCxDvelbZbV0YzWpEewGb2-SouhsxxnsyTZbekYWkN15M5tQMLNaCjg0R4u3Q.yTk_IVRmjL_cZhwuufqOBw.aHmY46TzzE_D2ln3COOSMvDqtCzff-OY2cnmtuBoVJGTZSvGIuzPqUFBBkw8SlNxNdJQQoIBgorfXbhP1_8S76I9Ih5HHLTXAw50iKkMsQ-l0AJs6ddCTC6mbt63r_xb.SINA1q_u3iwdtAmLNi4WSA"
        do{
            let jwe = try JWE(compactJWE: compactJwe, privateKey: privKey)
            let header = jwe.getHeaderAsDict()
            let payload  = jwe.getPayloadAsDict()
            
            print("Header from decrypted == \(String(describing: header))")
            print("Payload from decrypted == \(String(describing: payload))")
            XCTAssertNotNil(payload)
            XCTAssertEqual(payload! as! [String:String], ["iss": "JULIUS", "iat": "Hello World", "aud": "this is encrypted with RSA-OAEP-256."])
        } catch {
            print("Error while decrypting JWE :: \(error)")
            XCTFail()
        }
    }
    
    func testCreateJweCompactAndDecryptRSA1_5(){
        let plaintext = ["abc" : "defghijklmn",
                         "junkfood" : "mcdonalds burger king kfc",
                         "softdrinks" : "cola sprite fanta 7up"]
        guard let keypair = KeyStore.generateKeyPair(keyType: .RSAkeys) else {
            XCTFail()
            return
        }
        
        let jweTest = try! JWE(plaintext: plaintext, alg: .RSA1_5, publicKey: keypair["public"]!, kid: "kid")
        let encodedJWE = jweTest.compactJWE!
        print("Compact JWE = \(encodedJWE)")
        
        let deserializingJwe : JWE
        do{
            deserializingJwe = try JWE(compactJWE: encodedJWE, privateKey: keypair["private"]!)
        } catch {
            print(error)
            XCTFail()
            return
        }
        print("CEK BEFORE = " ,jweTest.cek!)
        
        XCTAssertNotNil(deserializingJwe.compactJWE)
        XCTAssertEqual(plaintext["abc"], deserializingJwe.plaintext!["abc"] as? String)
        XCTAssertEqual(plaintext["junkfood"], deserializingJwe.plaintext!["junkfood"] as? String)
        XCTAssertEqual(plaintext["softdrinks"], deserializingJwe.plaintext!["softdrinks"] as? String)
    }
    
    func testEncryptJWEwithNestedJWS(){
        let keydict = KeyStore.generateKeyPair(keyType: .RSAkeys)
        XCTAssertNotNil(keydict)
        let jws = JWS(payloadDict: jwsPayloadDict)
        XCTAssertNotNil(jws.sign(key: keydict!["private"]!, alg: .RS256))
        
        print("JWS Source == \(jws.jwsCompactResult!)")
        
        guard let url = bundle?.url(forResource: "privateTest", withExtension: "jwks") else {
            XCTFail()
            return
        }
        
        guard let pubkey = keyman.jwksToKeyFromBundle(jwksPath: url.path) else {
            XCTFail()
            return
        }
        
        let jwsSource = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjFMZG1qY0tkQkFnVDk3QWdEd3V5dzJjd3plN1F4NTNLTVpEYlJPT09sa3cifQ.eyJrZXlUb1NlbmQiOnsiZSI6IkFRQUIiLCJraWQiOiJMb2xwUXBJOWxOTnFGdS1VbUFaTFFKM3pLT2VFQ0JOOFlRNFRVZjFYODZZIiwia3R5IjoiUlNBIiwibiI6InhIUU5SS0N6RG1rS2x4clFIZUF3dHJwY2FvMHoycy1ndmFaQWJUdDllMTgtMUYtTE13eUxRakRKNjgxWWhTTEhJWlhhQ0FTdEVfS3hSZjVieUJiRGJnTDVZeDFuZ0N4S2liUTQzZ0ZGaVdDSDZKUnNVTC1QTkVIWmRoT1BXblNUbHpTYnN6RnhZU3VjWVgzUHlLVm9HLWxJMDNVeVpfNjB4S2FiQWdjaVF0RXN6b0ZKNTNBM1pLaDNkZGJsc1NuUFBldWoyb0lHUlk0Q21waEF1R1hsX2ZmNUNvMWoyaTV6dFMzUDJvTTRYYVJCOTI1SElYdjJBLVNxbkJ4QktfTVJ1SDkzQnFHZk9zNkFWaDFtUmYxelNObk5BZS1MbWt1X2prVEVrLUZLbHpTamI0Y05nWHdFRHNTSVAzbUJNdVBaNnpTS0ZmM0ZwWDFrVlJkODNlY05mdyJ9LCJ0ZXN0ZGF0YSI6InRlc3QxIiwicGF5bG9hZFRlc3QiOiJ0ZXN0MiJ9.SOAjlgN3i-f5gKeF3gkoULXBj-GrzkApAOuOQKGRvnvuas1rM_qErCYUjdJ_9a6w3ul8BybZ27Xwrq430m28JPbB4ChR6ohRuw5zOZq0UKY3SZpACjWb1EOAAQyB3xrp_31OfwtYmeuZT63Q8drr_Ykal3mwLUX9ofTTIreY5caHiFNtwd3j1Zda6sRA1HAwHNPURmobLuUZrozjuFf-ggscDQkKhZVH1HQjSCYspfs8DsAJkK4raLv1xxKZhzNEIKHZn8GtrG3amKgMLP0I86CtrdhtAJSqeHXy5peBNnDfFf_sa7rb0sPS-wjDBdrmfeL0uysmxZ4K6-IV35kvLg"
        
        let jwe : JWE
        do {
            jwe = try JWE(plainJWS: jwsSource, alg: .RSA_OAEP_256, publicKey: pubkey.first!, issuer: "eduidApp", subject: "jul", audience: "server", kid: pubkey.first!.getKid()!)
        } catch {
            print(error)
            XCTFail()
            return
        }
        
        XCTAssertNotNil(jwe.getCompactJWE()!)
        print("COMPACT JWE == \(jwe.getCompactJWE()!)")

    }
    
    
    func testDecryptJWEwithNestedJWS(){
        
        let encryptedJwe = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJraWQiOiJCTENodHdjaHVyIiwiY3R5IjoiSldUIiwiZW5jIjoiQTEyOENCQy1IUzI1NiJ9.pMUq4oW1VjB3heMi5oMyT0a4rScOoj7zx6lNERkS1a7HAshGwYuA_cVKCpwYSJdTlC4Eb83QyHuNv_LY_oW_zpD3g6E9HintK8PMapir_9m9Nri65vKxISjRSH026EMh1ztzh5FjotGxnazdEPo8HVZ2Wg6Xj1e3mazwB5UoiN_hilVoMxXx9KVefT2g9FtM3Vp-zOE98Bykf28XQN1FAn_QtZ4iiNWKsv3oZNmil3wgz8fBUNQvNNoLkUwsGQjHRM14fX5Dm00pyoTHugCWuwuBC8NzRLhr5yGWzC1IA8z9Y5-020MMfMPq9FSk39BWY2_qeSXa2do-5zQbmhz4LA.fW9Ul7E03LKf5SsTVqKZSA.v4HeDgv-JRyLVlTqMDTVX2CGIAD7jeocycYOhNqnjEIXlJo6etSykgO62pcPCwYo_VBhHVsZVJ0ox0jNzTrC-s_JfG-3Yz_ljZfxdbLClMwT8gNyQ2KaiWUdqlPj3EoPK0-OAcF8JlYel9BPqOmYYFpVExqMOUqLNX3pmqCgZ8UuAdnSMzuGt-5-eiQi_e92lNlb2uGx-_LevaIEQ0R2pcS46cNgsZg15HdhSRNg4A1HPRtwgMeVGTnQb_7Id57tqkKtoyA8v6BbIQnIZ3I7hk6loARJRgmpfAOQ04K-F8hnE4g4as6yMrLP5rmactrj4Ab6mWFk0UpHX4pGU9z41VJbCQPz_o2ALxoF-Ebu0whjUgeYwP6ThxqqZy2KgeRHVyzHbRtCT-TXjejSNUybn0kKCqrtqkVFoatdSUQUMYqyVcj3JKGfW-V0V03i7skIvo-JsT_GpOQr2MFx478DI8Kpnrbj5OzauFCTlUt9d7zVnwsZFRoDdDXXWBjQTOfpp3YnydP_frn2dh0o-hoIrHgekhR8OwaLP6zti1ghHbEYj2MUPRvJ25zM_5WKTTXq9ps1nAqGkhaIvhoaKo6W81KL9DAZ8Iz03c--Wjd3VdEUsF5xiXUWbtkz8KdbsUWla2Gj3xn4vjtycvFLTTbqd-F6LLoxogv0iAFfyfPIXDAj3WODYTHyE1wp_eHkZ3vBSLbs9LQC2HQ29CNhp6C2eID6hNsAQdlOZV8zTcKeWI6nSgBNVn6iui7hM2G3COWFHYxQIxc6MuBS3FA1pMrO4Wz5rFDMxReMusszDMGbJ681ucZjgS4XGf1WrxKrXP330WFruR7XJ_e6-fZ-9uzGSk9jAvMaVcalVHe48txfpmbqmEG4PPFCHNycgtxLnFZRRWDVpETLgkqh6jj-FrDgMu96UMYOV4tGbT_xPoEXcnqTS4jmAenks_gY11YvSnLJNOJJ4NYS1z08onH0ySXqEtVs-wEvXPZYR-QC-O1BU8qJk4uybxpt21EZfWdgfHA5f4Vy1UVam6pLbDXHbc9DADQvtnz97Xun_A7WGoeH2MmqY6IgLwYYScLvWrp5H76IVWJJMLaUCd8jBr4_6S6QKsfdJQ3-UTWXs_BY9Ir0tgsEnn5N0DdUh6IhZAT7LnFwMX-rwCIJ8lOVb6g57s9WrxZv7Fetm_BTDYFcHsKz2FKon-lQVAycpQ-p4-E8pAlNBhVyMxOq4AKJYBd9XKjidGjljESKgcGxmtnDYj0P2Tugg5t-GdfgpxAo30HBD350YrtqZJaLwlQNFNYEIQKvgTW67nS152DJHZ-kM3Zd4TuwMztCxobHFddKyH4jAflto3lm3YLGLa-N3MbVOv2G7yowNTmJimQQaEq7Gvsr71LJKzawzuGg9jtoLpQDSLtOaahzwE-ndLpBsG3mUCTKHXaC8WXUB3jjBLA8BH_8L9wWmrcxx-36bR0x7pZweYUs.HQfhICyOm75HPpnNNplU1g"
        
        // Get private key to decrypt JWE
        guard let url = bundle?.url(forResource: "privateTest", withExtension: "jwks") else {
            XCTFail()
            return
        }
        let keyID = keyman.getPrivateKeyIDFromJWKSinBundle(resourcePath: url.path)
        
        guard let urlpem = bundle?.url(forResource: "privateTest", withExtension: "pem") else {
            XCTFail()
            return
        }
        let keyIDfrombundle = keyman.getPrivateKeyFromPemInBundle(resourcePath: urlpem.path, identifier: keyID!)
        
        guard let privKey = keyman.getKey(withKid: keyIDfrombundle!) else {
            XCTFail()
            return
        }
        
        let jwe : JWE
        do{
            jwe = try JWE(compactJWE: encryptedJwe, privateKey: privKey)
        } catch {
            print(error)
            XCTFail()
            return
        }
        
        print("PLAIN JWS == \(jwe.plainJWS)")
        
        XCTAssertEqual(jwe.plainJWS!, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImQyM1FZWFVjaTBoUU9hU1dydFhwUzhQU0ktcjhRcDFRd3N5amloUjZ5RjQifQ.eyJrZXlUb1NlbmQiOnsiZSI6IkFRQUIiLCJraWQiOiJMb2xwUXBJOWxOTnFGdS1VbUFaTFFKM3pLT2VFQ0JOOFlRNFRVZjFYODZZIiwia3R5IjoiUlNBIiwibiI6InhIUU5SS0N6RG1rS2x4clFIZUF3dHJwY2FvMHoycy1ndmFaQWJUdDllMTgtMUYtTE13eUxRakRKNjgxWWhTTEhJWlhhQ0FTdEVfS3hSZjVieUJiRGJnTDVZeDFuZ0N4S2liUTQzZ0ZGaVdDSDZKUnNVTC1QTkVIWmRoT1BXblNUbHpTYnN6RnhZU3VjWVgzUHlLVm9HLWxJMDNVeVpfNjB4S2FiQWdjaVF0RXN6b0ZKNTNBM1pLaDNkZGJsc1NuUFBldWoyb0lHUlk0Q21waEF1R1hsX2ZmNUNvMWoyaTV6dFMzUDJvTTRYYVJCOTI1SElYdjJBLVNxbkJ4QktfTVJ1SDkzQnFHZk9zNkFWaDFtUmYxelNObk5BZS1MbWt1X2prVEVrLUZLbHpTamI0Y05nWHdFRHNTSVAzbUJNdVBaNnpTS0ZmM0ZwWDFrVlJkODNlY05mdyJ9LCJ0ZXN0ZGF0YSI6InRlc3QxIiwicGF5bG9hZFRlc3QiOiJ0ZXN0MiJ9.fkMF80PTBa_6cyXlJKpfXJbl2Vb0Y2pzGpZuvIPdm5kCy-RdzvxM6qMOpWUkLVaGnhp2dCzVgcpYj3J51kawMxullcG5ECSbPbjpPK_b5V4FeZWxtfmbWvR_u1fMj0wPNG0cOuFjSSSIEqfg6uFPNTb7gcn4ISBnLbSbDAoxo8ELEpiCCj44z75b0usepTii7dfgjlGLiOHIkxlR_eYIRblrM3Mbl4fxdWPM8ZW6I7lfvIGNpGPiPD1uQv9ltASYu8hmLgtzbg52UjWso-ghqRl3lFiAW5klV8QyNWcvS2WarWbQjhy6VdJHsz0KvslpzISW8-XRqEZfLV_Xz-vWLQ")
    }
    
    func testDebug(){
        /*
        let tagString = "HQfhICyOm75HPpnNNplU1g"
        let headerDict = ["alg":"RSA-OAEP-256", "kid":"BLChtwchur", "cty":"JWT", "enc":"A128CBC-HS256"]
        let cek : [UInt8] = [183, 146, 255, 189, 77, 135, 117, 32, 103, 130, 178, 252, 109, 152, 24, 174, 242, 34, 56, 140, 163, 124, 174, 95, 251, 96, 32, 211, 76, 42, 29, 28]
        let cipherStr = "v4HeDgv-JRyLVlTqMDTVX2CGIAD7jeocycYOhNqnjEIXlJo6etSykgO62pcPCwYo_VBhHVsZVJ0ox0jNzTrC-s_JfG-3Yz_ljZfxdbLClMwT8gNyQ2KaiWUdqlPj3EoPK0-OAcF8JlYel9BPqOmYYFpVExqMOUqLNX3pmqCgZ8UuAdnSMzuGt-5-eiQi_e92lNlb2uGx-_LevaIEQ0R2pcS46cNgsZg15HdhSRNg4A1HPRtwgMeVGTnQb_7Id57tqkKtoyA8v6BbIQnIZ3I7hk6loARJRgmpfAOQ04K-F8hnE4g4as6yMrLP5rmactrj4Ab6mWFk0UpHX4pGU9z41VJbCQPz_o2ALxoF-Ebu0whjUgeYwP6ThxqqZy2KgeRHVyzHbRtCT-TXjejSNUybn0kKCqrtqkVFoatdSUQUMYqyVcj3JKGfW-V0V03i7skIvo-JsT_GpOQr2MFx478DI8Kpnrbj5OzauFCTlUt9d7zVnwsZFRoDdDXXWBjQTOfpp3YnydP_frn2dh0o-hoIrHgekhR8OwaLP6zti1ghHbEYj2MUPRvJ25zM_5WKTTXq9ps1nAqGkhaIvhoaKo6W81KL9DAZ8Iz03c--Wjd3VdEUsF5xiXUWbtkz8KdbsUWla2Gj3xn4vjtycvFLTTbqd-F6LLoxogv0iAFfyfPIXDAj3WODYTHyE1wp_eHkZ3vBSLbs9LQC2HQ29CNhp6C2eID6hNsAQdlOZV8zTcKeWI6nSgBNVn6iui7hM2G3COWFHYxQIxc6MuBS3FA1pMrO4Wz5rFDMxReMusszDMGbJ681ucZjgS4XGf1WrxKrXP330WFruR7XJ_e6-fZ-9uzGSk9jAvMaVcalVHe48txfpmbqmEG4PPFCHNycgtxLnFZRRWDVpETLgkqh6jj-FrDgMu96UMYOV4tGbT_xPoEXcnqTS4jmAenks_gY11YvSnLJNOJJ4NYS1z08onH0ySXqEtVs-wEvXPZYR-QC-O1BU8qJk4uybxpt21EZfWdgfHA5f4Vy1UVam6pLbDXHbc9DADQvtnz97Xun_A7WGoeH2MmqY6IgLwYYScLvWrp5H76IVWJJMLaUCd8jBr4_6S6QKsfdJQ3-UTWXs_BY9Ir0tgsEnn5N0DdUh6IhZAT7LnFwMX-rwCIJ8lOVb6g57s9WrxZv7Fetm_BTDYFcHsKz2FKon-lQVAycpQ-p4-E8pAlNBhVyMxOq4AKJYBd9XKjidGjljESKgcGxmtnDYj0P2Tugg5t-GdfgpxAo30HBD350YrtqZJaLwlQNFNYEIQKvgTW67nS152DJHZ-kM3Zd4TuwMztCxobHFddKyH4jAflto3lm3YLGLa-N3MbVOv2G7yowNTmJimQQaEq7Gvsr71LJKzawzuGg9jtoLpQDSLtOaahzwE-ndLpBsG3mUCTKHXaC8WXUB3jjBLA8BH_8L9wWmrcxx-36bR0x7pZweYUs"
        let ivStr = "fW9Ul7E03LKf5SsTVqKZSA"
        let AL : [UInt8] = [0, 0, 0, 0, 0, 0, 3, 32]
        
        let cipher = Data(base64Encoded: cipherStr.clearPaddding().base64UrlToBase64())
        */
        
    }
    
    
}

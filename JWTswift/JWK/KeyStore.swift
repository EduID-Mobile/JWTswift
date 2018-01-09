//
//  KeyManager.swift
//  eduid-iOS
//
//  Created by Blended Learning Center on 04.12.17.
//  Copyright © 2017 Blended Learning Center. All rights reserved.
//

import Foundation
import CoreFoundation
import Security

public class KeyStore {
    
    private var keysCollection : [Key]?
    
    public init() {
        self.keysCollection = [Key]()
    }
    
    public init(withKey key : Key) {
        self.keysCollection = [Key]()
        self.keysCollection?.append(key)
    }
    
    public init(withKeys keys: [Key]) {
        self.keysCollection = keys
    }
    
    public func addKey(key : Key) -> Bool {
        if key.getKid() == nil {
            print("key should have id!")
            return false
        }
        self.keysCollection?.append(key)
        return true
    }
    
    public func deleteKey( key : Key) -> Bool {
        let length : Int = self.keysCollection?.count as Int!
        for i in 0 ..< length {
            if keysCollection![i] == key {
                self.keysCollection?.remove(at: i)
                return true
            }
        }
        return false
    }
    
    public func deleteAll(){
        keysCollection?.removeAll()
    }
    
    public func getKey(withKid kid: String) -> Key? {
       
        for key in keysCollection! {
            if key.getKid() == kid {
                return key
            }
        }
        
        return nil
    }
    
    //returning kid from the key
    //return nil if no key found
    public func  getPublicKeyFromCertificateInBundle (resourcePath: String) -> String? {
        //DER format
        let certData = NSData(contentsOfFile: resourcePath)
        let cert = SecCertificateCreateWithData(nil, certData! as CFData)
        var publicKey : SecKey? = nil
        var trust : SecTrust? = nil
        var policy : SecPolicy? = nil
        if(cert != nil) {
            policy = SecPolicyCreateBasicX509()
            if policy != nil  {
                if( SecTrustCreateWithCertificates(cert!, policy, &trust) == noErr){
                    var result : SecTrustResultType = SecTrustResultType.unspecified
                    let res = SecTrustEvaluate(trust!, &result)
                    print(res)
                    //recoverableTrustFailure
                    if(result == SecTrustResultType.proceed || result == SecTrustResultType.recoverableTrustFailure){
                        publicKey = SecTrustCopyPublicKey(trust!)
                    }
                }
            }
        }
        if(publicKey == nil){
            return nil
        }
        let keyEmpty = Key(keyObject: publicKey!, kid: nil)
        let keyTmp = KeyStore.createKIDfromKey(key: keyEmpty)
        if self.addKey(key:  keyTmp! ) {
            return keyTmp!.getKid()
        }else {
            return nil
        }
    }
    /*
    public func getCertificateFromBundle(resourcePath: String) -> SecCertificate? {
        if let data = NSData(contentsOfFile: resourcePath) {
            
            //let cfData = CFDataCreate(kCFAllocatorDefault, UnsafePointer<UInt8>(data.bytes), data.length)
            let cert = SecCertificateCreateWithData(kCFAllocatorDefault, data as NSData)
            return cert
        }
        return nil
    }
    */
    
   /*
    //specialize for RSA private key in pem format (#PKCS1)
    func getPrivateKeyFromBundle() -> SecKey? {
        
        let data = NSData(contentsOfFile: resourcePath!)
        
        let options = NSMutableDictionary()
        var privateKey : SecKey? = nil
        options.setObject("password", forKey: kSecImportExportPassphrase as! NSCopying)
        var items = CFArrayCreate(nil, nil, 0, nil)
        var securityError = SecPKCS12Import(data!, options as CFDictionary, &items)
        if ( securityError == noErr && CFArrayGetCount(items) > 0 ) {
            let identityDict : CFDictionary = CFArrayGetValueAtIndex(items, 0) as! CFDictionary
            var keyIdentity = kSecImportItemIdentity
            let identityApp : SecIdentity = CFDictionaryGetValue(identityDict, &keyIdentity) as! SecIdentity
            
            securityError = SecIdentityCopyPrivateKey(identityApp, &privateKey)
            if(securityError != noErr){
                privateKey = nil
            }
        }
        return privateKey
    }*/
    
    private func cutHeaderFooterPem (certString : inout String) {
        //CUT HEADER AND TAIL FROM PEM KEY
        let offset = ("-----BEGIN RSA PRIVATE KEY-----").count
        let index = certString.index(certString.startIndex, offsetBy: offset+1)
        
        let tail = "-----END RSA PRIVATE KEY-----"
        if let lowerBound = certString.range(of: tail)?.lowerBound {
            certString = String(certString[index ..< lowerBound])
            print(certString as Any)
        }
    }
    
    
    /**
     Get RSA private key from pem(#PKCS1) data in bundle
     - parameter resourcePath: Path to the private key data in pem format (PKCS#1)
     - returns : private key in SecKey format or nil when there is an error or no key found in pem data
     */
    public func getPrivateKeyFromPemInBundle(resourcePath : String, identifier : String) -> String? {
        var keyInString : String?
        do{
            keyInString = try String(contentsOfFile: resourcePath)
        } catch { print(error)}
        
        print("PEM BEFORE  : " , keyInString!)
        //Extracting the Header and Footer from the PEM data to get the RSA key
        cutHeaderFooterPem(certString: &keyInString!)
        
        
        let data = NSData(base64Encoded: keyInString!, options: NSData.Base64DecodingOptions.ignoreUnknownCharacters)
        print("BEFORE CUT : " , data!)
        //        let range = NSRange.initcation: 26, length: (data?.length)! - 26)
        //        let subdata = data?.subdata(with: range)
        
        print("DATA :" , data?.length as Any)
        var attributes : [String : String]  = [:]
        attributes[kSecAttrKeyType as String] = kSecAttrKeyTypeRSA as String
        attributes[kSecAttrKeyClass as String] = kSecAttrKeyClassPrivate as String
        attributes[kSecAttrKeySizeInBits as String] = String(2048) //String((data?.length)!) * 8)
        
        var error : Unmanaged<CFError>?
        let privateKey = SecKeyCreateWithData(data! as CFData, attributes as CFDictionary, &error)
        print(error.debugDescription)
        if privateKey != nil {
            let key = Key(keyObject: privateKey!, kid: identifier)
            self.keysCollection?.append(key)
            return identifier
        }
        return nil
    }
    
    /**
     Converting jwks data to pem string
     parameter jwksSourceData: jwks in Data format
     returns : Pem data in string format 
    */
    public func jwksToKeyFromServer(jwksSourceData : Data) -> [Key]?{
        if jwksSourceData.count == 0 {
            return nil
        }
        return jwksToPem(jwksSourceData: jwksSourceData)
    }
    
    /**
     
     */
    public func jwksToKeyFromBundle(jwksPath : String) -> [Key]? {
        if jwksPath.count == 0{
            return nil
        }
        return jwksToPem(jwksPath: jwksPath)
    }
    
    //jwks
    private func jwksToPem(jwksSourceData : Data? = nil, jwksPath : String? = nil) -> [Key]? {
        var result  = [Key]()
        var dataFromPath : Data?
        
        if(jwksSourceData != nil){
            dataFromPath = jwksSourceData
        } else if jwksPath != nil{
            dataFromPath = NSData(contentsOfFile: jwksPath!) as Data?
        } else {
            //BOTH jwksSourceData and jwksPath not nil or both are nil
            return nil
        }
        var jsonData : [String : Any]?
        do{
            jsonData = try JSONSerialization.jsonObject(with: dataFromPath as Data!, options: JSONSerialization.ReadingOptions.mutableContainers) as? [String : Any]
        }catch{
            print(error)
            return nil
        }
        
        let keysJWKS = jsonData!["keys"] as! [[String: String]]
       
        for keyJWKS in keysJWKS{
            let keyResult = jwkToKey(jwkDict: keyJWKS)
            if keyResult != nil {
                result.append(keyResult!)
            }
        }
        return result
    }
    
    
    //TODO : make it private
    //PUBLIC KEY
     public func jwkToKey(jwkDict : [String : String]) -> Key? {
        
        let exponentStr = jwkDict["e"]!.base64UrlToBase64().addPadding()
        let exponentData = Data(base64Encoded: exponentStr)
        
        let modulusStr = jwkDict["n"]!.base64UrlToBase64().addPadding()
        let modulusData = Data(base64Encoded: modulusStr)
        print("exponent : \(exponentStr)")
        print("modulus : \(modulusStr)")
        let pemGen = PemGenerator(modulusHex: (modulusData?.hexDescription)!, exponentHex: (exponentData?.hexDescription)!, lengthModulus: (modulusData?.count)!, lengthExponent: (exponentData?.count)!)
        let pemString = pemGen.generatePublicPem()
        
        let attributes : [String : Any] = [
            kSecAttrKeyType as String : kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String : kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String : 2048]
        
        var error: Unmanaged<CFError>?
        let dataPem = Data.init(base64Encoded: pemString)
        guard let publicKey = SecKeyCreateWithData(dataPem! as  CFData, attributes as CFDictionary, &error) else {
            print("Cannot create key, Error : \(error.debugDescription)")
            return nil
        }
        
        if let kid = jwkDict["kid"] {
            //base64url
            return Key(keyObject: publicKey, kid: kid)
        } else{
            //if there is no Key ID, create a thumbprint for this jwk and use it as Key ID
            let kidTmp = KeyStore.createKIDfromJWK(jwkDict: jwkDict)
            return Key(keyObject: publicKey, kid: kidTmp)
        }
    }
    
    private func  bytesCount (base64str : String) -> Int{
        
        let bitsCount = base64str.count * 6
        if bitsCount % 8 == 0 {
            return bitsCount / 8
        }
        else {
            return (bitsCount / 8) + 1
        }
    }

    
    /**
     pkcs1 // SecKeyData as input parameter
     */
    public class func pemToJWK(pemData : Data , kid: String? = nil) -> [String: String]{
        var jwk : [String : String] = [:]
        print("LAST INDEX : \(pemData.endIndex.hashValue)")
        let rangeModulus : Range<Int> = 9..<265
        let rangeExponent : Range<Int> = Int(267)..<pemData.endIndex.hashValue
        //rangeExponent
        print("DATA SIZE :  \(pemData.count),",pemData.base64EncodedString())
        let subdataMod = pemData.subdata(in: rangeModulus)
        let subdataEx = pemData.subdata(in: rangeExponent)
        print("MOD HEX : \(subdataMod.hexDescription)")
        print("EX HEX : \(subdataEx.hexDescription)")
        jwk["n"] = subdataMod.base64EncodedString().clearPaddding().base64ToBase64Url()
        jwk["e"] = subdataEx.base64EncodedString().clearPaddding().base64ToBase64Url()
        jwk["kty"] = "RSA"
        if kid == nil {
            jwk["kid"] =  KeyStore.createKIDfromJWK(jwkDict: jwk)
        } else {
            jwk["kid"] = kid
        }
        
        return jwk
    }
    
    public class func keyToJwk(key : Key) -> [String: String]? {
        var error : Unmanaged<CFError>?
        guard let dataFromKey : Data = SecKeyCopyExternalRepresentation(key.getKeyObject(), &error)! as Data! else {
            print("error on creating data from key, \(error.debugDescription)")
            return nil
        }
        
        return pemToJWK(pemData: dataFromKey, kid: key.getKid()?.base64ToBase64Url() )
    }
    
    public class func createKIDfromKey(key : Key) -> Key? {
        if key.getKid() != nil {
            print("KID is already exist!")
            return nil
        }
        
        var error : Unmanaged<CFError>?
        guard let dataFromKey : Data = SecKeyCopyExternalRepresentation(key.getKeyObject(), &error)! as Data! else {
            print("error on creating data from key")
            return nil
        }
        print("DATA : " , dataFromKey)
        let jwkDict = pemToJWK(pemData: dataFromKey)
        return Key(keyObject: key.getKeyObject(), kid: jwkDict["kid"])
        
    }
    
    /**
    Generate a key ID from a modulus, exponent and keytype for the JWK
     - parameter jwkDict: String dictionary, containing keys : e, n , and kty , which are required to create a kid (thumbprint)
     - returns : KID in base64encoded string format (without Padding)
     */
    public class func createKIDfromJWK(jwkDict : [String: String]) -> String? {
        
        var jsonString : String?
        if jwkDict.keys.contains("e") && jwkDict.keys.contains("kty") && jwkDict.keys.contains("n") {
            
            jsonString = "{\"e\":\"\(jwkDict["e"]!)\",\"kty\":\"\(jwkDict["kty"]!)\",\"n\":\"\(jwkDict["n"]!)\"}" as String!
            print("string :" , jsonString!)
            var byteArray = [UInt8]()
            for char in jsonString!.utf8 {
                byteArray += [char]
            }
            print(byteArray)
            let kidArray = Data.init(bytes: byteArray)
            print(kidArray.hashSHA256()!)
            let kidData = Data(bytes: kidArray.hashSHA256()!)

            print("kidData : " , kidData.base64EncodedString().clearPaddding() )
            var hashvalue = jsonString?.hashValue as Int!
            print("String hashvalue : " , hashvalue! )
            let dataHashvalue = Data(bytes: &hashvalue, count: MemoryLayout.size(ofValue: hashvalue))
            print("data from string hash : " , dataHashvalue.base64EncodedString())
            print("kid data : " , kidData.base64EncodedString().clearPaddding())
            return kidData.base64EncodedString().clearPaddding()
        }
        return nil
    }
    
    
    /**
     Generate a random key pair
     - parameter keyTag: a unique name tag for the key
     - paramater keyType: kSecAttrKeyType for now is RSA key type
     - returns : A dictionary contains one key pair with keys "public", "private" to access the specific key
     */
    
    public class func generateKeyPair(keyType : String) -> [String : Key]? { // parameter keyTag : String
//        let tag = keyTag.data(using: .utf8)!
        var keysResult : [String : Key] = [:]
        let attributes : [String : Any] = [ kSecAttrKeyType as String : keyType,
                                            kSecAttrKeySizeInBits as String : 2048,
                                            kSecPrivateKeyAttrs as String : [kSecAttrIsPermanent as String : false]//,
                                                                             //kSecAttrApplicationTag as String : tag ]
        ]
        //kSecattrIsPermanent == true -> store the keychain in the default keychain while creating it, use the application tag to retrieve it from keychain later
        var error : Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            print(error.debugDescription)
            return nil
        }
        keysResult["private"] = Key(keyObject: privateKey, kid: nil)
        let publicSecKey = SecKeyCopyPublicKey(privateKey)
        print(publicSecKey!)
        let keyTmp = Key(keyObject: publicSecKey!, kid: nil)
        keysResult["public"] = createKIDfromKey(key: keyTmp)
        
        return keysResult
    }
}

//
//  JWE.swift
//  JWTswift
//
//  Created by Blended Learning Center on 14.09.18.
//  Copyright © 2018 Blended Learning Center. All rights reserved.
//

import Foundation
import Security
import CommonCrypto

public enum CekEncryptionAlgorithm {
    case RSA1_5
    case RSA_OAEP_256
}

public enum EncAlgorithm {
    case A128CBC_HS256
}

enum JweError : Error {
    case wrongJweFormat
    case unsupportedAlgorithm
    case validationError
    case encryptionError
    case decryptionErrror
}

public class JWE {
    var joseHeaderDict : [String : Any]?
    var joseHeaderData : Data?
    var encryptedCEK: String?
    var initVector : [UInt8]?
    var ciphertext : String?
    var authTag : String?
    
    var compactJWE : String?
    var cek : [UInt8]?
    var plaintext : [String : Any]?
    
    internal init(alg: CekEncryptionAlgorithm, issuer: String, subject: String, audience: String, kid : String) {
        //Header will be set with default algorithm, this could be changed in the future
        
        joseHeaderDict = ["kid" : kid,
                          "cty" : "JWT",
                          "enc" : "A128CBC-HS256"]
        
        switch alg {
        case .RSA1_5:
            joseHeaderDict!["alg"] = "RSA1_5"
        case .RSA_OAEP_256:
            joseHeaderDict!["alg"] = "RSA-OAEP-256"
        }
        
        if issuer.count > 0 && subject.count > 0  && audience.count > 0 {
            joseHeaderDict!["iss"] = issuer
            joseHeaderDict!["sub"] = subject
            joseHeaderDict!["aud"] = audience
        }
        
        joseHeaderData = try! JSONSerialization.data(withJSONObject: joseHeaderDict!, options: [])
    }
    
    public init(compactJWE : String, privateKey : Key) throws {
        
        let jweArray = compactJWE.components(separatedBy: ".")
        print("array = ", jweArray)
        
        if jweArray.count != 5 {
            clearAll()
            throw JweError.wrongJweFormat
        }
        
        joseHeaderData = Data.init(base64Encoded: jweArray[0].base64UrlToBase64().addPadding())
        do{
            joseHeaderDict = try JSONSerialization.jsonObject(with: joseHeaderData!, options: []) as? [String : Any]
        } catch {
            clearAll()
            throw error
        }
        
        self.compactJWE = compactJWE
        
        encryptedCEK = jweArray[1]
        
        let initVectorData = Data(base64Encoded: jweArray[2].base64UrlToBase64().addPadding())
        initVector = [UInt8](initVectorData!)
        
        ciphertext = jweArray[3]
        
        authTag = jweArray[4]
        
        do{
            let _ = try deserializeJwe(decryptKey: privateKey)
        }catch {
            clearAll()
            throw error
        }
        
    }
    
    public convenience init(plaintext : [String:Any], alg: CekEncryptionAlgorithm, publicKey : Key, issuer : String, subject : String, audience: String, kid: String) throws {
        self.init(alg: alg, issuer: issuer, subject: subject, audience: audience, kid: kid)
        self.plaintext = plaintext
        do{
            let _ = try generateJWE(encryptKey: publicKey);
        } catch {
            clearAll()
            throw error
        }
    }
    
    
    // MARK: ----  Setter ----
    
    func setInitVector(initVector: [UInt8]){
        self.initVector = initVector
    }
    
    func clearAll(){
        joseHeaderDict = nil
        joseHeaderData = nil
        encryptedCEK = nil
        initVector = nil
        ciphertext = nil
        authTag = nil
        
        compactJWE = nil
        cek = nil
        plaintext = nil
    }
    
    // MARK: --- Getter ----
    /**
     GetHeader function
     - returns: A dictionary of [String: Any] and return nil if empty or /if there is an error
    */
    public func getHeaderAsDict() -> [String : Any]? {
        return joseHeaderDict
    }
    
    /**
     Get payload of JWE in dictionary format
     - returns: A dictionary of [String: Any], return nil if empty
    */
    public func getPayloadAsDict() -> [String : Any]? {
        return plaintext
    }
    
    /**
     Get compact serialization of JWE
     - returns: A String of JWE compact seriaization, return nil if empty
     */
    public func getCompactJWE() -> String? {
        return compactJWE
    }
    
    // MARK: ---- Deserializing ----
    
    func deserializeJwe(decryptKey : Key) throws -> [String : Any]? {
        // Part 1 decrypt encoded key
//        let encryptedCEKdata = Data.init(base64Encoded: encryptedCEK!.base64UrlToBase64().addPadding())
        
        switch joseHeaderDict!["alg"] as! String {
        case "RSA1_5":
            cek = decryptCEK(decryptKey: decryptKey, alg: .RSA1_5, cipherText: encryptedCEK!)
            guard cek != nil else {
                throw JweError.decryptionErrror
            }
        case "RSA-OAEP-256":
            cek = decryptCEK(decryptKey: decryptKey, alg: .RSA_OAEP_256, cipherText: encryptedCEK!)
            guard cek != nil else {
                throw JweError.decryptionErrror
            }
        default:
            throw JweError.unsupportedAlgorithm
        }
    
        
        // Part 2 Get the mac and enc key for validation and decryption
        print("Deserialize cek == \(cek!)")
        
        let middleIndex = cek!.count / 2
        let macKey = cek![..<middleIndex]
        let encKey = cek![middleIndex...]
        
        let cipherData = Data(base64Encoded: ciphertext!.base64UrlToBase64().addPadding())
        
        // Part 3 Validate the authentication Tag
        let aad = generateAAD()
//        print("AAD AFTER :: \(aad)")
        let al = generateAL(bitsCount: aad!.count * 8)
        let hmacInput = aad! + initVector! + [UInt8](cipherData!) + al

//        print("hmacInput AFTER :: \(hmacInput)" )
        
        let hmacOutput = HmacSha.compute(input: Data(bytes: hmacInput), key: Data(bytes: macKey))
//        print("HMAC OUTPUT AFTER == \([UInt8](hmacOutput))")
        let authTagDataSecond = hmacOutput.prefix(upTo: 16)
        let authTagSecond = authTagDataSecond.base64EncodedString().base64ToBase64Url().clearPaddding()
        
        print("authTagSecond == \(authTagSecond)")
        
        // Validation == Compare the createdTag with the received AuthTag
        if authTag != authTagSecond {
            clearAll()
            throw JweError.validationError
        }
        
        // Part 4 Decrypt the cipher text with the encryption key from CEK
        
        let decryptData = AES.decryptAes(data: cipherData!, keyData: Data(bytes: encKey), ivData: Data(bytes: initVector!))
        do{
            plaintext = try JSONSerialization.jsonObject(with: decryptData, options: .init(rawValue: 0)) as? [String : Any]
        } catch {
            print(error)
            clearAll()
            return nil
        }
        
        return plaintext!
    }
    
    
//---- Generator ----
    
    func generateJWE(encryptKey : Key) throws -> String {
        
        // 5 Different components (header, encrypted CEK, initialization Vector, Ciphertext,
        // Authentication Tag).
    
        // Part 1 Header
        let headerEncoded = joseHeaderData!.base64EncodedString().base64ToBase64Url().clearPaddding()
        
        // Part 2 Encrypted Key
        if cek == nil {
            cek = self.generateCEK()
        }
        
        switch joseHeaderDict!["alg"]! as! String {
        case "RSA1_5" :
            encryptedCEK = encryptCEK(encryptKey: encryptKey, alg: .RSA1_5, cek: cek!)
            guard encryptedCEK != nil else {
                throw JweError.encryptionError
            }
        
        case "RSA-OAEP-256":
            encryptedCEK = encryptCEK(encryptKey: encryptKey, alg: .RSA_OAEP_256, cek: cek!)
            guard encryptedCEK != nil else {
                throw JweError.encryptionError
            }
        default:
            throw JweError.unsupportedAlgorithm
        }
        
        // Part 3 Initialization Vector
        if initVector == nil {
            initVector = generateInitVec()
        }
        let ivEncoded = Data.init(bytes: initVector!) .base64EncodedString().base64ToBase64Url().clearPaddding()
        
        // Part 4 Cipher Text
        let middleIndex = cek!.count / 2
        let macKey = cek![..<middleIndex]
        let encKey = cek![middleIndex...]
//        print("MACKEY BEFORE == \(macKey)")
        let plainData : Data
        do{
            plainData = try JSONSerialization.data(withJSONObject: plaintext!, options: [])
        }catch {
            throw error
        }
        let cipher = AES.encryptAes(data: plainData, keyData: Data(bytes: encKey), ivData: Data(bytes: initVector!))
        ciphertext = cipher.base64EncodedString().base64ToBase64Url().clearPaddding()
        
        // Part 5 Authentication Tag
        guard let aad = generateAAD() else {
            print("JWE :: Cannot Generate AAD")
            return ""
        }
        
        let al = generateAL(bitsCount: aad.count * 8) // Bytes to bits
        let hmacInput = aad + initVector! + [UInt8](cipher) + al
//        print("HMAC INPUT BEFORE :: \(hmacInput)")
        
        let hmacOutput = HmacSha.compute(input: Data(bytes: hmacInput) , key: Data(bytes: macKey))
//        print("HMAC OUTPUT BEFORE == \([UInt8](hmacOutput))")
        
        let authenticationTagData = hmacOutput.prefix(upTo: 16) // Take the first 128 bits from the output
        authTag = authenticationTagData.base64EncodedString().base64ToBase64Url().clearPaddding()
        
        compactJWE = "\(headerEncoded).\(encryptedCEK!).\(ivEncoded).\(ciphertext!).\(authTag!)"
        return compactJWE!
    }
    
    
    func generateAAD() -> [UInt8]? {
        guard (joseHeaderData != nil) else {
            return nil
        }
        return [UInt8](joseHeaderData!.base64EncodedData())
    }
    
    public func generateAL(bitsCount : Int) -> [UInt8] {
        var result : [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0]
        
        var bitString = String.init(bitsCount, radix: 2, uppercase: false)
        print("str generateAL = \(bitString)")
        
        var bitsTmp = bitString.count
        var resultIndex = result.count - 1
        
        repeat{
            var indexByte : String.Index
            if bitsTmp - 8 >= 0 {
                indexByte = bitString.index(bitString.endIndex, offsetBy: -8)
                print("byte : ",bitString[indexByte...])
            } else {
                indexByte = bitString.index(bitString.endIndex, offsetBy: -bitsTmp)
                print("byte2 : ", bitString[indexByte...])
            }
            let resultByte = bitString[indexByte...]
            bitString = String(bitString[..<indexByte])
            print("bitString = \(bitString)")
            
            bitsTmp -= 8
            
            print(UInt8(String(resultByte), radix: 2)!)
            result[resultIndex] = UInt8(String(resultByte), radix: 2)!
            resultIndex -= 1
            
        } while (bitsTmp > 0)
        
        print("result = \(result)")
        return result
    }
    
    public func generateCEK() -> [UInt8]? {
        // For A256CBC-HS512 CEK needs to be 64 Bytes : 32 Bytes for MAC Key, and 32 Bytes for ENC
        // A128CBC-HS256 needs to be 32 Bytes : 16 Bytes MAC Key, 16 Bytes ENC KEY
        guard let randombytes = generateRandomBytes(countBytes: 32) else {
            print("Error creating a random bytes for CEK")
            return nil
        }
        return [UInt8](randombytes)
    }
    
    public func generateInitVec() -> [UInt8]? {
        // 16 Bytes init vector for A128CBC-HS256
        guard let randombytes = generateRandomBytes(countBytes: 16) else {
            print("Error creating a random bytes for Initialization Vector")
            return nil
        }
        return [UInt8](randombytes)
    }
    
    private func generateRandomBytes(countBytes: Int) -> Data? {
        var randombytes = [UInt8](repeating: 0, count: countBytes)
        let status = SecRandomCopyBytes(kSecRandomDefault, randombytes.count, &randombytes)
        if status == errSecSuccess {
            return Data(bytes: randombytes)
        } else {
            return nil
        }
    }
    
    public func encryptCEK(encryptKey: Key, alg: CekEncryptionAlgorithm, cek: [UInt8]) -> String? {
        
        let cipherText : Data?
        switch alg {
        case .RSA1_5:
            cipherText = RSA1_5.encrypt(encryptKey: encryptKey, cek: cek)
        case .RSA_OAEP_256:
            cipherText = RSA_OAEP_256.encrypt(encryptKey: encryptKey, cek: cek)
        }
        
        guard cipherText != nil  else {
            return nil
        }
        print("ENCRYPTED = \([UInt8](cipherText!))")
        return cipherText!.base64EncodedString().base64ToBase64Url().clearPaddding()
    }
    
    public func decryptCEK(decryptKey: Key, alg: CekEncryptionAlgorithm, cipherText: String) -> [UInt8]? {

        let strCipher = cipherText.addPadding().base64UrlToBase64()
        let cipher = Data.init(base64Encoded: strCipher)
        
        let plainData : Data?
        switch alg {
        case .RSA1_5:
            plainData = RSA1_5.decrypt(decryptKey: decryptKey, cipherText: cipher!)
        case .RSA_OAEP_256:
            plainData = RSA_OAEP_256.decrypt(decryptKey: decryptKey, cipherText: cipher!)
        }
        
        guard plainData != nil else {
            return nil
        }
        
        return [UInt8](plainData!)
    }
    
}

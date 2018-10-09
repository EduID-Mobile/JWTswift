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
    case unsupportedFormatForPayload
    case serializationError
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
    var plainJWS : String?
    
    /**
     Default init - assigning the header data properly for the JWE instance
    */
    internal init(alg: CekEncryptionAlgorithm, kid : String, aud: String? = nil) {
        //Header will be set with default enc algorithm, this could be changed in the future
        joseHeaderDict = ["kid" : kid,
                          "cty" : "JWT",
                          "enc" : "A128CBC-HS256"]
        if aud != nil {
            joseHeaderDict!["aud"] = aud
        }
        
        switch alg {
        case .RSA1_5:
            joseHeaderDict!["alg"] = "RSA1_5"
        case .RSA_OAEP_256:
            joseHeaderDict!["alg"] = "RSA-OAEP-256"
        }

        joseHeaderData = try! JSONSerialization.data(withJSONObject: joseHeaderDict!, options: [])
    }
    
    /**
     Main function to work with incoming compact serialized JWE from external endpoints. As a parameter a private key would be required to decrypt the incoming JWE.
     - parameter compactJWE : String format of JWE with 5 different parts, separated by '.'
     - parameter privateKey : Key object, that will be used to decrypt the JWE
     - Throws: One of JweError if deserializing process failed
     */
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
    
    /**
    Main function to create JWE instance based from the payload in dictionary format
     - parameter plaintext: A dictionary for the payload
     - parameter alg: CekEncryptionAlgorithm, algorithm that is used to encrypt the CEK data
     - parameter publicKey: public key to encrypt the data using the alg above
     - parameter kid: kid from the public key in String format
     - parameter aud: optional claim for the assertion forwarding(RFC 7521+7523)
     - Throws: One of JweError if serializing process failed
     */
    public convenience init(plaintext : [String:Any], alg: CekEncryptionAlgorithm, publicKey : Key, kid: String, aud: String? = nil) throws {
        self.init(alg: alg, kid: kid, aud: aud)
        self.plaintext = plaintext
        do{
            let _ = try generateJWE(encryptKey: publicKey)
        } catch {
            clearAll()
            throw error
        }
    }
    
    /**
     Main function to create a nested JWE with a compact JWS as payload inside
     - parameter plainJWS: A compact serialization of JWS in String
     - parameter alg: CekEncryptionAlgorithm, algorithm that is used to encrypt the CEK data
     - parameter publicKey: public key to encrypt the data using the alg above
     - parameter kid: kid from the public key in String format
     - parameter aud: optional claim for the assertion forwarding(RFC 7521+7523)
     - Throws: One of JweError if serializing process failed
     */
    public convenience init(plainJWS : String, alg: CekEncryptionAlgorithm, publicKey: Key, kid: String, aud: String? = nil) throws {
        
        self.init(alg: alg, kid: kid, aud: aud)
        self.plainJWS = plainJWS
        
        do{
            let _ = try generateJWE(encryptKey: publicKey)
        } catch {
            clearAll()
            throw error
        }
    }
    
    // MARK: ----  Setter ----
    
    func setInitVector(initVector: [UInt8]) {
        self.initVector = initVector
    }
    
    func addExtraHeader(headerClaim : String, headerValue: Any) {
        if headerClaim == "aud" || headerClaim == "iss" || headerClaim == "sub" {
            joseHeaderDict![headerClaim] = headerValue
        }
    }
    
    /**
     Clearing all the data if any error occured on the initializing process
     */
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
     if return nil, the payload could be a JWS String and could be fetched with getPayloadJWS()
     - returns: A dictionary of [String: Any], return nil if empty
     */
    public func getPayloadAsDict() -> [String : Any]? {
        return plaintext
    }
    
    /**
     Get a payload of Jws nested inside JWE in a compact string format
     if return nil, the payload could be just a normal Dictionary payload and could be fetched with getPayloadAsDict()
     - returns: A compact string of JWS, return nil if empty
     */
    public func getPayloadJWS() -> String? {
        return plainJWS
    }
    
    /**
     Get compact serialization of JWE
     - returns: A String of JWE compact seriaization, return nil if empty
     */
    public func getCompactJWE() -> String? {
        return compactJWE
    }
    
    // MARK: ---- Deserializing ----
    /**
     Function to work (validate & decrypt) with incoming compact JWE from the extern endpoints.
     This function will be executed automatically from init with compact JWE as parameter.
     - parameter decryptKey: Key for decryption
     - Throws: one of JweError from the deserializing process
     */
    func deserializeJwe(decryptKey : Key) throws -> Bool {
        // Part 1 decrypt encoded key
        
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
            
            // Data could be in string = nested JWS inside JWE
            plainJWS = String(data: decryptData, encoding: .utf8)
            guard plainJWS != nil else {
                clearAll()
                throw JweError.unsupportedFormatForPayload
            }
        }
        
        return true
    }

    //---- Generator ----
    /**
     Function to generate a compact JWE based on the payload data and encryption algorithm.
     This function will be executed automaticall from the init() with payload dictionary or JWS as parameter.
     - parameter encryptKey: Key to encrypt the Data
     - Throws: one JweError from the serializing process
     - returns: String of compact serialized JWE
     */
    func generateJWE(encryptKey : Key) throws -> String {
        
        // 5 Different components (header, encrypted CEK, initialization Vector, Ciphertext,
        // Authentication Tag).
        let headerEncoded : String
        // Part 1 Header
        do {
            let headerDataTmp = try JSONSerialization.data(withJSONObject: joseHeaderDict!, options: [])
            headerEncoded = headerDataTmp.base64EncodedString().base64ToBase64Url().clearPaddding()
        } catch {
            print(error)
            throw JweError.serializationError
        }
            
            //joseHeaderData!.base64EncodedString().base64ToBase64Url().clearPaddding()
        
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
        if plaintext != nil {
            do{
                plainData = try JSONSerialization.data(withJSONObject: plaintext!, options: [])
            }catch {
                throw error
            }
        } else if plainJWS != nil {
            plainData = plainJWS!.data(using: .utf8)!
        } else {
            throw JweError.unsupportedFormatForPayload
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
                print("HMAC INPUT BEFORE :: \(hmacInput)")
        
        let hmacOutput = HmacSha.compute(input: Data(bytes: hmacInput) , key: Data(bytes: macKey))
                print("HMAC OUTPUT BEFORE == \([UInt8](hmacOutput))")
        
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
    
    /**
     Random byte generator of a specific byte length.
     This bytes will be used to encrypt the payload and make a signature.
     - returns: Array of (32) unsigned integer
    */
    public func generateCEK() -> [UInt8]? {
        // For A256CBC-HS512 CEK needs to be 64 Bytes : 32 Bytes for MAC Key, and 32 Bytes for ENC
        // A128CBC-HS256 needs to be 32 Bytes : 16 Bytes MAC Key, 16 Bytes ENC KEY
        guard let randombytes = generateRandomBytes(countBytes: 32) else {
            print("Error creating a random bytes for CEK")
            return nil
        }
        return [UInt8](randombytes)
    }
    
    /**
     Random byte generator that will be used as an init vector on encryption/decryption process.
     - returns: Array of (16) unsigned integer
     */
    public func generateInitVec() -> [UInt8]? {
        // 16 Bytes init vector for A128CBC-HS256
        guard let randombytes = generateRandomBytes(countBytes: 16) else {
            print("Error creating a random bytes for Initialization Vector")
            return nil
        }
        return [UInt8](randombytes)
    }
    
    /**
     Main function to generate random bytes, this is used for generateInitVec() and generateCEK()
     - parameter countBytes: number of random bytes that will be generated
     - returns: random bytes in Data format or nil if there is any Error
    */
    private func generateRandomBytes(countBytes: Int) -> Data? {
        var randombytes = [UInt8](repeating: 0, count: countBytes)
        let status = SecRandomCopyBytes(kSecRandomDefault, randombytes.count, &randombytes)
        if status == errSecSuccess {
            return Data(bytes: randombytes)
        } else {
            return nil
        }
    }
    
    /**
     Help function to encrypt the CEK based with the selected algorithm
     - parameter encryptKey: Key to encrypt the cek
     - parameter alg: selected algorithm
     - parameter cek: bytes to encrypt
     - returns: A encrypted cek in string format, that will be sent as a part of JWE serialization
    */
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
    
    /**
     Help function to decrypt the CEK based with the selected algorithm
     - parameter decryptKey: Key to decrypt the cek
     - parameter alg: selected algorithm
     - parameter cipherText: String to decrypt
     - returns: An array of unsigned integer that could be used to validate and decrypt the JWE,or nil if there is any error
     */
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

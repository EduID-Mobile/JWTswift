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

public enum cekEncryptionAlgorithm {
    case RSA1_5
}

public enum encAlgorithm {
    case A256CBC_HS512
}

public class JWE {
    var joseHeaderDict : [String : Any]?
    var joseHeaderData : Data?
    var encryptedCEK: String?
    var initVector : [UInt8]?
    var chiphertext : String?
    var authTag : String?
    
    var compactJWE : String?
    var cek : [UInt8]?
    var plaintext : [String : Any]?
    
    init() {
        //Header will be set with default algorithm, this could be changed in the future
        joseHeaderDict = ["alg" : "RSA1_5" ,
                           "enc" : "A128CBC-HS256"]
        joseHeaderData = try! JSONSerialization.data(withJSONObject: joseHeaderDict!, options: [])
    }
    
    init(jweCompact : String) {
        
        
    }
    
    public convenience init(plaintext : [String:Any], publicKey : Key) {
        self.init()
        self.plaintext = plaintext
        
        generateJWE(encryptKey: publicKey);
    }
    
    
//----  Setter ----
    
    public func setInitVector(initVector: [UInt8]){
        self.initVector = initVector
    }
    
//---- Generator ----
    
    func generateJWE(encryptKey : Key) -> String {
        
        // 5 Different components (header, encrypted CEK, initialization Vector, Ciphertext,
        // Authentication Tag).
    
        // Part 1 Header
        let headerEncoded = joseHeaderData!.base64EncodedString().base64ToBase64Url().clearPaddding()
        
        // Part 2 Encrypted Key
        if cek == nil {
            cek = self.generateCEK()
        }
        let encryptedCekData = RSA1_5.encrypt(encryptKey: encryptKey, cek: cek!)
        encryptedCEK = encryptedCekData?.base64EncodedString().base64ToBase64Url().clearPaddding()
        
        // Part 3 Initialization Vector
        if initVector == nil {
            initVector = generateInitVec() // This already return the base64URL encoded string
        }
        let ivEncoded = Data.init(bytes: initVector!) .base64EncodedString().base64ToBase64Url().clearPaddding()
        
        // Part 4 Cipher Text
        let middleIndex = cek!.count / 2
        let macKey = cek![..<middleIndex]
        let encKey = cek![middleIndex...]
        
        let plainData = try! JSONSerialization.data(withJSONObject: plaintext!, options: [])
        let cipher = AES.encryptAes(data: plainData, keyData: Data(bytes: encKey), ivData: Data(bytes: initVector!))
        chiphertext = cipher.base64EncodedString().base64ToBase64Url().clearPaddding()
        
        // Part 5 Authentication Tag
        guard let aad = generateAAD() else {
            print("JWE :: Cannot Generate AAD")
            return ""
        }
        
        let al = generateAL(bitsCount: aad.count * 8) // Bytes to bits
        let hmacInput = aad + initVector! + [UInt8](cipher) + al
        let hmacOutput = HmacSha.compute(input: Data(bytes: hmacInput) , key: Data(bytes: macKey))
        
        let authenticationTagData = hmacOutput.prefix(upTo: 16) // Take the first 128 bits from the output
        authTag = authenticationTagData.base64EncodedString().base64ToBase64Url().clearPaddding()
        
        compactJWE = "\(headerEncoded).\(encryptedCEK!).\(ivEncoded).\(chiphertext!).\(authTag!)"
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
        guard let randombytes = generateRandomBytes(countBytes: 16) else {
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
    
    public func encryptCEK(encryptKey: Key, alg: cekEncryptionAlgorithm, cek: [UInt8]) -> String? {
        if alg != .RSA1_5{
            return nil
        }
        
        guard let cipherText = RSA1_5.encrypt(encryptKey: encryptKey, cek: cek) else {
            return nil
        }
        
        return cipherText.base64EncodedString().base64ToBase64Url().clearPaddding()
    }
    
    public func decryptCEK(decryptKey: Key, alg: cekEncryptionAlgorithm, cipherText: String) -> [UInt8]? {
        if alg != .RSA1_5{
            return nil
        }
        let cipher = Data.init(base64Encoded: cipherText.base64UrlToBase64().addPadding())
        
        guard let plainData = RSA1_5.decrypt(decryptKey: decryptKey, cipherText: cipher!) else {
            return nil
        }
        
        return [UInt8](plainData)
    }
    
}

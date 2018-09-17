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
    var encryptedKey : String?
    var initVector : String?
    var aad : String?
    var plaintext : String?
    var chiphertext : String?
    var authTag : String?
    
    
    init(){
        //Header will be set with default algorithm, this could be changed in the future
        joseHeaderDict = [ "alg" : "RSA1_5" ,
                           "enc" : "A128CBC-HS256"]
    }
    
    init(plaintext : String) {
        self.plaintext = plaintext
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
    
    public func generateInitVec() -> String? {
        guard let randombytes = generateRandomBytes(countBytes: 16) else {
            print("Error creating a random bytes for Initialization Vector")
            return nil
        }
        return randombytes.base64EncodedString().base64ToBase64Url().clearPaddding()
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
        
        guard SecKeyIsAlgorithmSupported(encryptKey.getKeyObject(), .encrypt, .rsaEncryptionPKCS1) else {
            print("Key doesn't support the encryption algorithm")
            return nil
        }
        print("block size = " , SecKeyGetBlockSize(encryptKey.getKeyObject()))
        
        
        //transform cek to data
        let cekData = Data(bytes: cek)
        print("cekData count = " ,cekData.count)
        guard cekData.count < (SecKeyGetBlockSize(encryptKey.getKeyObject())-130) else {
            print("Cek is too big")
            return nil
        }
        
        
        var error: Unmanaged<CFError>?
        guard let cipherText = SecKeyCreateEncryptedData(encryptKey.getKeyObject(), .rsaEncryptionPKCS1, cekData as! CFData, &error) as Data? else {
            print(error!.takeRetainedValue())
            return nil
        }
        print("Cipher Text = " ,[UInt8](cipherText).count)
        return cipherText.base64EncodedString().base64ToBase64Url().clearPaddding()
    }
    
    public func encryptAes(data: Data, keyData: Data, ivData: Data) -> Data{
        
        return aes(data: data, keyData: keyData, ivData: ivData, operation: kCCEncrypt)
    }
    
    public func decryptAes(data: Data, keyData: Data, ivData: Data) -> Data{
        
        return aes(data: data, keyData: keyData, ivData: ivData, operation: kCCDecrypt)
    }
    
    
    public func aes(data: Data, keyData: Data, ivData: Data, operation: Int) -> Data {
        let cryptLength = size_t(data.count + kCCBlockSizeAES128)
        var cryptData = Data(count: cryptLength)
        
        let keyLength = size_t(kCCKeySizeAES128)
        let options = CCOptions(kCCOptionPKCS7Padding)
        
        var bytesEncrpytedCount : size_t = 0
        
        let cryptStatus = cryptData.withUnsafeMutableBytes { cryptBytes in
            data.withUnsafeBytes { dataBytes in
                ivData.withUnsafeBytes { ivBytes in
                    keyData.withUnsafeBytes { keyBytes in
                        CCCrypt(CCOperation(operation), CCAlgorithm(kCCAlgorithmAES), options, keyBytes, keyLength, ivBytes, dataBytes, data.count, cryptBytes, cryptLength, &bytesEncrpytedCount)
                    }
                }
            }
        }
        
        if UInt32(cryptStatus) == UInt32(kCCSuccess) {
            cryptData.removeSubrange(bytesEncrpytedCount..<cryptData.count)
        } else {
            print("Error : \(cryptStatus)")
            
        }
        return cryptData
    }
    
    
    
}

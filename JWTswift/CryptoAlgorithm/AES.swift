//
//  aes.swift
//  JWTswift
//
//  Created by Blended Learning Center on 24.09.18.
//  Copyright © 2018 Blended Learning Center. All rights reserved.
//

import Foundation
import CommonCrypto

internal struct AES {
    
    static func encryptAes(data: Data, keyData: Data, ivData: Data) -> Data {
        return aes(data: data, keyData: keyData, ivData: ivData, operation: kCCEncrypt)
    }
    
    static func decryptAes(data: Data, keyData: Data, ivData: Data) -> Data {
        return aes(data: data, keyData: keyData, ivData: ivData, operation: kCCDecrypt)
    }
    
    
    /**
     Main function for aes128 algorithm
     - returns: Cipher Data from encryption or PlainText from decryption
     */
    static func aes(data: Data, keyData: Data, ivData: Data, operation: Int) -> Data {
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

//
//  hmacSha.swift
//  JWTswift
//
//  Created by Blended Learning Center on 24.09.18.
//  Copyright © 2018 Blended Learning Center. All rights reserved.
//

import Foundation
import CommonCrypto

struct HmacSha {
    
    static func compute(input : Data, key: Data) -> Data {
        
//        let keyBytes = UnsafePointer<CUnsignedChar>([UInt8](key))
//        let dataBytes = UnsafePointer<CUnsignedChar>([UInt8](input))

        /*
        let keyString = key.base64EncodedString()
        let dataString = input.base64EncodedString()
        
        let inputKey = keyString.cString(using: .utf8)
        let inputData = dataString.cString(using: .utf8)
        print("HMAC key = \(inputKey)")
        print("HMAC data = \(inputData)")
        */
        
        var result = Data(count: 32)
        
//        CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), keyBytes, key.count, dataBytes, input.count, &result)
        
        result.withUnsafeMutableBytes { resultBytes in
            key.withUnsafeBytes { keyBytes in
                input.withUnsafeBytes { inputBytes in
                   CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), keyBytes, key.count, inputBytes, input.count, resultBytes)
                }
            }
        }
        //
        return result
//        let hmacData = Data(bytes: result, count: Int(CC_SHA256_DIGEST_LENGTH))
        
//        return hmacData
    }
    
}

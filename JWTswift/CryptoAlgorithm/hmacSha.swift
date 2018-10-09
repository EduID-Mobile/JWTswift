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
    
    /**
     Main function of HMAC Sha256 algorithm 
     */
    static func compute(input : Data, key: Data) -> Data {
        
        var result = Data(count: 32)
        
        result.withUnsafeMutableBytes { resultBytes in
            key.withUnsafeBytes { keyBytes in
                input.withUnsafeBytes { inputBytes in
                   CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), keyBytes, key.count, inputBytes, input.count, resultBytes)
                }
            }
        }
        
        return result
    }
}

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
        
        let keyBytes = UnsafePointer<CUnsignedChar>([UInt8](key))
        let dataBytes = UnsafePointer<CUnsignedChar>([UInt8](input))
        
        var result = [CUnsignedChar](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        
        CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), keyBytes, Int(CC_SHA256_DIGEST_LENGTH), dataBytes, input.count, &result)
        
        let hmacData = Data(bytes: result, count: Int(CC_SHA256_DIGEST_LENGTH))
        
        return hmacData
    }
    
}
